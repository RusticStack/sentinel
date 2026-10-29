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

pub const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(60);
pub const SYNC_EVERY: u32 = 32;

struct PipeState {
    spool: Option<Spool>,
    redactor: Redactor,
    reporter: Option<Reporter>,
    route: Option<Route>,
    sent: u64,
    unsynced: u32,
    ended: bool,
    end_sent: bool,
    end_acked: bool,
    end_acked_protocol: bool,
    refused: bool,
    last_step: Option<u32>,
    cut: bool,
    refusals: Refused,
}

impl PipeState {
    fn resend_from_ack(&mut self) {
        if let Some(spool) = self.spool.as_mut() {
            let acked = spool.acked();
            self.sent = match spool.rewind(acked) {
                Ok(()) => acked,
                // Keeping `sent` at the cursor counts the unread tail as in flight, so the window cannot overflow.
                Err(_) => spool.last_seq(),
            };
        }
    }

    // A newly attached route could let new frames overtake frames still in flight on the old one.
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

    fn flush_carry(&mut self, step: u32) {
        for stream in [Stream::Stdout, Stream::Stderr] {
            let mut rest = self.redactor.flush(stream);
            for chunk in rest.chunks(MAX_LOG_FRAME_BYTES) {
                self.store(step, stream, chunk);
            }
            rest.fill(0);
        }
    }

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
    pub fn open(
        root: &Path,
        attempt: AttemptId,
        redactor: Redactor,
        reporter: Option<Reporter>,
    ) -> Result<LogPipe> {
        Self::open_in(&SpoolSpace::unbounded(root), attempt, redactor, reporter)
    }

    pub fn open_in(
        space: &Arc<SpoolSpace>,
        attempt: AttemptId,
        redactor: Redactor,
        reporter: Option<Reporter>,
    ) -> Result<LogPipe> {
        let spool = Spool::open_in(space, attempt, MAX_SPOOL_BYTES)?;
        Ok(Self::with(attempt, spool, redactor, reporter, false))
    }

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

    pub fn refusals(&self) -> Refused {
        self.lock().refusals
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn register_secret(&self, value: &[u8]) -> bool {
        self.lock().redactor.register(value)
    }

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
                            return;
                        }
                    }
                    Err(_) => {
                        st.reporter = None;
                        return;
                    }
                }
            }
        }
        let spool = st.spool.as_mut().expect("checked above");
        if st.ended && !st.end_sent && spool.acked() >= spool.last_stored() {
            if !spool.ended() {
                if std::mem::take(&mut st.cut) {
                    let _ = spool.declare_cut();
                }
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

    pub fn acked(&self, through: u64) {
        let mut st = self.lock();
        if let Some(spool) = st.spool.as_mut() {
            let _ = spool.acknowledged(through);
        }
        self.pump(&mut st);
        self.progress.notify_all();
    }

    pub fn refused(&self) {
        let mut st = self.lock();
        st.refused = true;
        self.progress.notify_all();
    }

    /// Removes the attempt's spool without ending it, for an attempt that failed before it ran a step: the
    /// controller is told the failure by an event, and nothing was logged that needs a delivered end record.
    pub fn discard(&self) {
        let mut st = self.lock();
        st.ended = true;
        if let Some(spool) = st.spool.take() {
            let _ = spool.remove();
        }
    }

    pub fn end_acked(&self) {
        let mut st = self.lock();
        st.end_acked = true;
        self.progress.notify_all();
    }

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
            let Some(seq) = st.store(step, stream, chunk) else {
                continue;
            };
            let spool = st.spool.as_mut().expect("stored above");
            if let Some(reporter) = direct {
                match reporter.log_frame(self.attempt, seq, step, stream, chunk) {
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
        let mut st = self.lock();
        if st.redactor.is_empty() {
            return text;
        }
        let mut raw = text.into_bytes();
        let mut redacted = st.redactor.redact_all(&raw);
        raw.fill(0);
        let text = String::from_utf8_lossy(&redacted).into_owned();
        redacted.fill(0);
        text
    }

    fn excerpt(&self, stderr: &[u8]) -> String {
        self.lock()
            .redactor
            .excerpt(stderr, stderr.len() >= crate::process::OUTPUT_TAIL_BYTES)
    }

    fn complete(&self) -> bool {
        let mut st = self.lock();
        if !st.ended {
            let step = st.last_step.unwrap_or(0);
            st.flush_carry(step);
            let s = &mut *st;
            if let Some(spool) = s.spool.as_mut() {
                let _ = spool.sync();
                // The end record must survive a restart unchanged, or a re-sent end would conflict.
                if !s.cut {
                    let _ = spool.persist_end();
                }
            }
            s.ended = true;
        }
        self.pump(&mut st);
        let deadline = Instant::now() + LOG_FLUSH_TIMEOUT;
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

    #[test]
    fn registration_is_per_attempt_and_takes_effect_while_it_runs() {
        let root = tempfile::tempdir().unwrap();
        let a = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        let b = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        a.write(0, Stream::Stdout, b"before tok-1234567890\n");
        assert!(a.register_secret(b"tok-1234567890"));
        assert!(a.register_secret(b"short"));
        a.write(0, Stream::Stdout, b"after tok-1234567890\n");
        b.write(0, Stream::Stdout, b"other tok-1234567890\n");
        a.step_done(0);
        b.step_done(0);
        assert_eq!(text(&spooled(&a)), "before tok-1234567890\nafter ***\n");
        assert_eq!(text(&spooled(&b)), "other tok-1234567890\n");
        assert_eq!(
            a.redact("Error: tok-1234567890 refused".into()),
            "Error: *** refused"
        );
        assert_eq!(
            b.redact("Error: tok-1234567890 refused".into()),
            "Error: tok-1234567890 refused"
        );
    }

    #[test]
    fn a_failure_excerpt_is_redacted_before_it_is_cut() {
        let root = tempfile::tempdir().unwrap();
        let pipe = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        pipe.register_secret(b"apiVersion: v1\ntoken: kube-secret-token");
        let excerpt = pipe.excerpt(b"cat config\napiVersion: v1\ntoken: kube-secret-token\n");
        assert!(!excerpt.contains("kube-secret"), "{excerpt}");
        let printed = b"apiVersion: v1\ntoken: kube-secret-token\n".repeat(4_000);
        let wrapped = &printed[printed.len() - crate::process::OUTPUT_TAIL_BYTES..];
        let excerpt = pipe.excerpt(wrapped);
        assert!(!excerpt.contains("secret-token"), "{excerpt}");
        let plain = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
        assert_eq!(plain.excerpt(b"a\nError: nope\n"), "Error: nope");
    }

    #[test]
    fn a_secret_split_across_output_calls_is_redacted() {
        let root = tempfile::tempdir().unwrap();
        let mut redactor = Redactor::new();
        redactor.register(b"split-secret-value");
        let pipe = LogPipe::open(root.path(), AttemptId::new(), redactor, None).unwrap();
        pipe.write(0, Stream::Stdout, b"before split-secret-");
        pipe.write(0, Stream::Stdout, b"value after\n");
        pipe.step_done(0);
        assert_eq!(text(&spooled(&pipe)), "before *** after\n");
    }

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
