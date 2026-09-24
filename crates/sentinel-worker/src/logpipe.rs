//! One attempt's log pipe (W05): redact, spool, send within the window,
//! advance on acknowledgement, and close with the end marker.
//!
//! Output from the step's reader threads is redacted and appended to the
//! spool under one lock; frames leave for the controller from the spool's
//! send cursor, never more than `MAX_UNACKED_LOG_FRAMES` in flight, so a
//! controller that is slow or absent costs disk on the worker and nothing
//! else. A frame written while the cursor is caught up is sent straight
//! from memory; only a backlog is read back. An acknowledgement moves the
//! cursor; a lost session — or a lost bulk connection, which may have taken
//! frames with it — rewinds the cursor to the last acknowledgement before
//! anything else is sent. The spool is synced every `SYNC_EVERY` writes and
//! at the end: a power loss can take the unsynced ones, and an acknowledged
//! sequence is never reused, so what the controller holds stays consistent.
//! The end goes out once every stored frame is acknowledged — a refused
//! tail is declared, never waited for — and only after the spool holds it
//! durably, so a restart re-sends the same end. A spool the previous
//! process left without an end ([`LogPipe::recover`]) was cut short by the
//! crash, and its end declares the unknown tail as a gap.
//!
//! The pipe owns the attempt's redactor: values registered for this attempt
//! apply to its output only, from the moment they are registered, and go
//! with it. It counts what the spool refused, by cause, for the worker's
//! diagnostics; the log itself carries the gaps.

use std::{
    path::Path,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use sentinel_core::AttemptId;
use sentinel_link::session::{Reporter, Route};
use sentinel_protocol::{
    limits::{MAX_LOG_FRAME_BYTES, MAX_UNACKED_LOG_FRAMES},
    logs::Stream,
};

use crate::{
    Result,
    attempt::Output,
    redact::Redactor,
    spool::{MAX_SPOOL_BYTES, Refused, Spool, SpoolSpace},
};

/// How long finalization waits for the controller to acknowledge and close
/// the log before the attempt is reported as a publication failure.
pub const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(60);
/// Frames between spool syncs.
pub const SYNC_EVERY: u32 = 32;

struct PipeState {
    spool: Option<Spool>,
    redactor: Redactor,
    reporter: Option<Reporter>,
    /// The route frames in flight took; a detachment since then means they
    /// may be lost with the connection.
    route: Option<Route>,
    /// Highest sequence handed to the current session.
    sent: u64,
    unsynced: u32,
    ended: bool,
    /// `LogEnd` was handed to the current session.
    end_sent: bool,
    /// The controller answered `LogEndAck` (protocol 5): the end marker
    /// is durable there and the spool may be dropped.
    end_acked: bool,
    /// The last attached session's protocol answers `LogEnd`.
    end_acked_protocol: bool,
    refused: bool,
    /// The step whose output came last: held-back bytes are attributed to
    /// it when they are released.
    last_step: Option<u32>,
    /// A leftover spool without an end: its end declares the cut tail.
    cut: bool,
    /// Frames the spool refused, by cause.
    refusals: Refused,
}

impl PipeState {
    /// Send from the last acknowledgement again.
    fn resend_from_ack(&mut self) {
        if let Some(spool) = self.spool.as_mut() {
            let acked = spool.acked();
            self.sent = match spool.rewind(acked) {
                // Resend from the last acknowledgement.
                Ok(()) => acked,
                // The send cursor stayed ahead of `acked`; keeping `sent`
                // there too counts the unread tail as in-flight, so the
                // window cannot overflow. What was skipped reaches the
                // controller as a declared gap, never a silent one.
                Err(_) => spool.last_seq(),
            };
        }
    }

    /// Whether new frames may go out on `reporter`'s current route now. A
    /// detached bulk connection may have swallowed frames: rewind first. A
    /// newly attached one could let a new frame overtake frames still in
    /// flight on control: wait until those are acknowledged.
    fn route_ready(&mut self, reporter: &Reporter) -> bool {
        let now = reporter.route();
        match self.route {
            Some(before) if before.detached != now.detached => {
                self.resend_from_ack();
            }
            Some(before) if before != now => {
                let acked = self.spool.as_ref().map_or(self.sent, Spool::acked);
                if self.sent > acked {
                    return false;
                }
            }
            _ => {}
        }
        self.route = Some(now);
        true
    }

    /// Release the held-back tail of both streams as `step`'s output.
    fn flush_carry(&mut self, step: u32) {
        for stream in [Stream::Stdout, Stream::Stderr] {
            let rest = self.redactor.flush(stream);
            for chunk in rest.chunks(MAX_LOG_FRAME_BYTES) {
                self.store(step, stream, chunk);
            }
        }
    }

    /// Append one chunk; a refusal is counted by cause (the spool has
    /// declared its sequence either way).
    fn store(&mut self, step: u32, stream: Stream, chunk: &[u8]) -> Option<u64> {
        let spool = self.spool.as_mut()?;
        match spool.append(step, stream, chunk) {
            Ok(Some(seq)) => Some(seq),
            _ => {
                if let Some(why) = spool.last_refusal() {
                    self.refusals.count(why);
                }
                None
            }
        }
    }
}

pub struct LogPipe {
    attempt: AttemptId,
    state: Mutex<PipeState>,
    progress: Condvar,
}

impl LogPipe {
    /// A pipe over a spool bounded only by its per-attempt cap.
    pub fn open(
        root: &Path,
        attempt: AttemptId,
        redactor: Redactor,
        reporter: Option<Reporter>,
    ) -> Result<LogPipe> {
        Self::open_in(&SpoolSpace::unbounded(root), attempt, redactor, reporter)
    }

    /// A live attempt's pipe, its spool in the worker's shared spool space.
    pub fn open_in(
        space: &Arc<SpoolSpace>,
        attempt: AttemptId,
        redactor: Redactor,
        reporter: Option<Reporter>,
    ) -> Result<LogPipe> {
        let spool = Spool::open_in(space, attempt, MAX_SPOOL_BYTES)?;
        Ok(Self::with(attempt, spool, redactor, reporter, false))
    }

    /// The pipe of a spool the previous process left: delivered from its
    /// cursor and closed. Without an end record the attempt was cut short
    /// by the crash, and its end says so.
    pub fn recover(
        space: &Arc<SpoolSpace>,
        attempt: AttemptId,
        reporter: Option<Reporter>,
    ) -> Result<LogPipe> {
        let spool = Spool::open_in(space, attempt, MAX_SPOOL_BYTES)?;
        let cut = !spool.ended();
        Ok(Self::with(attempt, spool, Redactor::new(), reporter, cut))
    }

    fn with(
        attempt: AttemptId,
        spool: Spool,
        redactor: Redactor,
        reporter: Option<Reporter>,
        cut: bool,
    ) -> LogPipe {
        let sent = spool.acked();
        // A pipe opened on a live session takes its protocol now, as
        // `attached` would: on protocol 5 the spool must wait for the end
        // marker's acknowledgement, not merely for `LogEnd` to be sent.
        let end_acked_protocol = reporter.as_ref().is_some_and(|r| r.protocol() >= 5);
        LogPipe {
            attempt,
            state: Mutex::new(PipeState {
                spool: Some(spool),
                redactor,
                route: reporter.as_ref().map(Reporter::route),
                reporter,
                sent,
                unsynced: 0,
                ended: false,
                end_sent: false,
                end_acked: false,
                end_acked_protocol,
                refused: false,
                last_step: None,
                cut,
                refusals: Refused::default(),
            }),
            progress: Condvar::new(),
        }
    }

    /// Frames the spool refused so far, by cause.
    pub fn refusals(&self) -> Refused {
        self.lock().refusals
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Redact a registered value from this attempt's output from now on.
    /// Returns whether it was accepted (long enough to be a secret).
    pub fn register_secret(&self, value: &[u8]) -> bool {
        self.lock().redactor.register(value)
    }

    /// Send what the window allows from the spool's cursor, then the end
    /// marker once everything is acknowledged.
    fn pump(&self, st: &mut PipeState) {
        let Some(reporter) = st.reporter.clone() else {
            return;
        };
        if st.refused || st.spool.is_none() || !st.route_ready(&reporter) {
            return;
        }
        let expected = st.route;
        let spool = st.spool.as_mut().expect("checked above");
        let acked = spool.acked();
        let in_flight = st.sent.saturating_sub(acked) as usize;
        let room = MAX_UNACKED_LOG_FRAMES.saturating_sub(in_flight);
        if room > 0 {
            let frames = spool.send_next(room).unwrap_or_default();
            for frame in frames {
                match reporter.log_frame(
                    self.attempt,
                    frame.seq,
                    frame.step,
                    frame.stream,
                    &frame.bytes,
                ) {
                    Ok(route) => {
                        st.sent = frame.seq;
                        if Some(route) != expected {
                            // The route moved under this batch: the next
                            // pump sees it and rewinds or waits.
                            return;
                        }
                    }
                    Err(_) => {
                        // The session is gone; the next attach rewinds and
                        // resends.
                        st.reporter = None;
                        return;
                    }
                }
            }
        }
        let spool = st.spool.as_mut().expect("checked above");
        // Every stored frame acknowledged: the end can go. Declared gaps are
        // never acknowledged, so they are not waited for.
        if st.ended && !st.end_sent && spool.acked() >= spool.last_stored() {
            if !spool.ended() {
                if std::mem::take(&mut st.cut) {
                    // Past everything the controller acknowledged: never a
                    // sequence it holds. A failed write still spent it; the
                    // end record below retries the `declared` file.
                    let _ = spool.declare_cut();
                }
                // Durable before it is declared; retried at the next pump.
                if spool.persist_end().is_err() {
                    return;
                }
            }
            let gaps = spool.gaps().to_vec();
            if reporter
                .log_end(self.attempt, spool.last_seq(), &gaps)
                .is_ok()
            {
                st.end_sent = true;
                self.progress.notify_all();
            } else {
                st.reporter = None;
            }
        }
    }

    /// Frames through `through` are durable on the controller.
    pub fn acked(&self, through: u64) {
        let mut st = self.lock();
        if let Some(spool) = st.spool.as_mut() {
            let _ = spool.acknowledged(through);
        }
        self.pump(&mut st);
        self.progress.notify_all();
    }

    /// The controller stores no more of this attempt's log.
    pub fn refused(&self) {
        let mut st = self.lock();
        st.refused = true;
        self.progress.notify_all();
    }

    /// Protocol 5: the controller's end marker is durable.
    pub fn end_acked(&self) {
        let mut st = self.lock();
        st.end_acked = true;
        self.progress.notify_all();
    }

    /// A session is live: resend from the last acknowledgement. The end
    /// marker goes out again too — it was only ever durable once the
    /// controller said so. A refusal from the last session is not carried
    /// over: a permanent one is simply answered again, and one an older
    /// controller sent for a transient fault gets its retry.
    pub fn attached(&self, reporter: Reporter) {
        let mut st = self.lock();
        st.end_acked_protocol = reporter.protocol() >= 5;
        st.route = Some(reporter.route());
        st.reporter = Some(reporter);
        st.refused = false;
        if !st.end_acked {
            st.end_sent = false;
        }
        st.resend_from_ack();
        self.pump(&mut st);
    }

    pub fn detached(&self) {
        self.lock().reporter = None;
    }

    /// The bulk connection went: resend what it may have swallowed before
    /// anything else goes out on the fallback route.
    pub fn resync(&self) {
        let mut st = self.lock();
        self.pump(&mut st);
    }
}

impl Output for LogPipe {
    fn write(&self, step: u32, stream: Stream, bytes: &[u8]) {
        let mut st = self.lock();
        if st.ended {
            return;
        }
        if let Some(previous) = st.last_step
            && previous != step
        {
            st.flush_carry(previous);
        }
        st.last_step = Some(step);
        let out = st.redactor.apply(stream, bytes);
        if out.is_empty() {
            return;
        }
        let st = &mut *st;
        for chunk in out.chunks(MAX_LOG_FRAME_BYTES) {
            // The frame goes out from memory when nothing older waits and
            // the window has room; otherwise the pump reads it back later.
            let direct = match st.reporter.clone() {
                Some(reporter) if !st.refused => {
                    let window = st.spool.as_ref().is_some_and(|spool| {
                        spool.caught_up()
                            && (st.sent.saturating_sub(spool.acked()) as usize)
                                < MAX_UNACKED_LOG_FRAMES
                    });
                    (window && st.route_ready(&reporter)).then_some(reporter)
                }
                _ => None,
            };
            if st.spool.is_none() {
                return;
            }
            // Every chunk spends its sequence whether the write lands, a
            // bound refuses it, or the disk fails — `append` declares what it
            // could not hold, and the next chunk must still spend its own.
            let Some(seq) = st.store(step, stream, chunk) else {
                continue;
            };
            let spool = st.spool.as_mut().expect("stored above");
            if let Some(reporter) = direct {
                match reporter.log_frame(self.attempt, seq, step, stream, chunk) {
                    // A route that changed under this send is left for the
                    // next pump, which still holds the old one to compare
                    // against and rewinds or waits as it must.
                    Ok(_) => {
                        spool.sent_tail(seq);
                        st.sent = seq;
                    }
                    Err(_) => st.reporter = None,
                }
            }
        }
        st.unsynced += 1;
        if st.unsynced >= SYNC_EVERY
            && let Some(spool) = st.spool.as_mut()
            && spool.sync().is_ok()
        {
            st.unsynced = 0;
        }
        self.pump(st);
    }

    fn step_done(&self, step: u32) {
        let mut st = self.lock();
        if !st.ended {
            st.flush_carry(step);
            self.pump(&mut st);
        }
    }

    fn redact(&self, text: String) -> String {
        let st = self.lock();
        if st.redactor.is_empty() {
            return text;
        }
        String::from_utf8_lossy(&st.redactor.redact_all(text.as_bytes())).into_owned()
    }

    fn complete(&self) -> bool {
        let mut st = self.lock();
        if !st.ended {
            let step = st.last_step.unwrap_or(0);
            st.flush_carry(step);
            let s = &mut *st;
            if let Some(spool) = s.spool.as_mut() {
                let _ = spool.sync();
                // The `last_seq` and gaps `LogEnd` declares must survive a
                // restart unchanged, or a re-sent end would conflict. A
                // recovered spool's end waits for the controller's
                // acknowledgements, which may move it (`pump`).
                if !s.cut {
                    let _ = spool.persist_end();
                }
            }
            s.ended = true;
        }
        self.pump(&mut st);
        let deadline = Instant::now() + LOG_FLUSH_TIMEOUT;
        // Protocol 5 keeps the spool until the controller's end marker is
        // durable (`LogEndAck`); earlier sessions keep the send boundary.
        while !(st.end_acked || (st.end_sent && !st.end_acked_protocol)) && !st.refused {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            st = self
                .progress
                .wait_timeout(st, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
            self.pump(&mut st);
        }
        if (st.end_acked || (st.end_sent && !st.end_acked_protocol))
            && let Some(spool) = st.spool.take()
        {
            let _ = spool.remove();
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything the pipe has spooled, as (step, text).
    fn spooled(pipe: &LogPipe) -> Vec<(u32, String)> {
        let mut st = pipe.lock();
        let spool = st.spool.as_mut().unwrap();
        spool
            .unacked(0, 1_000)
            .unwrap()
            .into_iter()
            .map(|f| (f.step, String::from_utf8(f.bytes).unwrap()))
            .collect()
    }

    fn text(frames: &[(u32, String)]) -> String {
        frames.iter().map(|(_, t)| t.as_str()).collect()
    }

    /// P04-12: a value registered into a live attempt redacts its output
    /// from then on, and only that attempt's.
    #[test]
    fn registration_is_per_attempt_and_takes_effect_while_it_runs() {
        let root = tempfile::tempdir().unwrap();
        let a = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        let b = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        a.write(0, Stream::Stdout, b"before tok-1234567890\n");
        assert!(a.register_secret(b"tok-1234567890"));
        assert!(!a.register_secret(b"short"));
        a.write(0, Stream::Stdout, b"after tok-1234567890\n");
        b.write(0, Stream::Stdout, b"other tok-1234567890\n");
        a.step_done(0);
        b.step_done(0);
        assert_eq!(text(&spooled(&a)), "before tok-1234567890\nafter ***\n");
        assert_eq!(text(&spooled(&b)), "other tok-1234567890\n");
        // Diagnostics that leave the attempt are redacted the same way.
        assert_eq!(
            a.redact("Error: tok-1234567890 refused".into()),
            "Error: *** refused"
        );
        assert_eq!(
            b.redact("Error: tok-1234567890 refused".into()),
            "Error: tok-1234567890 refused"
        );
    }

    /// P04-21: bytes held back as a possible secret prefix are released as
    /// the step that printed them when it ends, never as another step's
    /// (or as no step at all).
    #[test]
    fn held_back_bytes_belong_to_the_step_that_printed_them() {
        let root = tempfile::tempdir().unwrap();
        let pipe = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        pipe.register_secret(b"secret-value-xyz");
        pipe.write(0, Stream::Stdout, b"tail secret-val");
        pipe.step_done(0);
        pipe.write(1, Stream::Stdout, b"next\n");
        pipe.step_done(1);
        let frames = spooled(&pipe);
        assert!(frames.iter().all(|(step, _)| *step != u32::MAX));
        let step0: String = frames
            .iter()
            .filter(|(s, _)| *s == 0)
            .map(|(_, t)| t.as_str())
            .collect();
        assert_eq!(step0, "tail secret-val");
        assert_eq!(text(&frames), "tail secret-valnext\n");
    }
}
