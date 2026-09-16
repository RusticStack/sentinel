//! One attempt's log pipe (W05): redact, spool, send within the window,
//! advance on acknowledgement, and close with the end marker.
//!
//! Output from the step's reader threads is redacted and appended to the
//! spool under one lock; frames leave for the controller from the spool's
//! send cursor, never more than `MAX_UNACKED_LOG_FRAMES` in flight, so a
//! controller that is slow or absent costs disk on the worker and nothing
//! else. An acknowledgement moves the cursor; a lost session rewinds the
//! cursor to the last acknowledgement when the next session attaches. The
//! spool is synced every `SYNC_EVERY` frames and at the end, so a worker
//! crash loses at most that many unsynced frames, which the reopened spool
//! then declares as missing rather than pretending they were delivered.

use std::{
    path::Path,
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

use sentinel_core::AttemptId;
use sentinel_link::session::Reporter;
use sentinel_protocol::{
    limits::{MAX_LOG_FRAME_BYTES, MAX_UNACKED_LOG_FRAMES},
    logs::Stream,
};

use crate::{Result, attempt::Output, redact::Redactor, spool::Spool};

/// How long finalization waits for the controller to acknowledge and close
/// the log before the attempt is reported as a publication failure.
pub const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(60);
/// Frames between spool syncs.
pub const SYNC_EVERY: u32 = 32;

struct PipeState {
    spool: Option<Spool>,
    redactor: Redactor,
    reporter: Option<Reporter>,
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
        let spool = Spool::open(root, attempt)?;
        let sent = spool.acked();
        Ok(LogPipe {
            attempt,
            state: Mutex::new(PipeState {
                spool: Some(spool),
                redactor,
                reporter,
                sent,
                unsynced: 0,
                ended: false,
                end_sent: false,
                end_acked: false,
                end_acked_protocol: false,
                refused: false,
            }),
            progress: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Send what the window allows from the spool's cursor, then the end
    /// marker once everything is acknowledged.
    fn pump(&self, st: &mut PipeState) {
        let Some(spool) = st.spool.as_mut() else {
            return;
        };
        let Some(reporter) = st.reporter.clone() else {
            return;
        };
        if st.refused {
            return;
        }
        let acked = spool.acked();
        let in_flight = st.sent.saturating_sub(acked) as usize;
        let room = MAX_UNACKED_LOG_FRAMES.saturating_sub(in_flight);
        if room > 0 {
            let frames = spool.send_next(room).unwrap_or_default();
            for frame in frames {
                if reporter.log(self.attempt, &frame).is_err() {
                    // The session is gone; the next attach rewinds and resends.
                    st.reporter = None;
                    return;
                }
                st.sent = frame.seq;
            }
        }
        if st.ended && !st.end_sent && acked == spool.last_seq() {
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
    /// controller said so.
    pub fn attached(&self, reporter: Reporter) {
        let mut st = self.lock();
        st.end_acked_protocol = reporter.protocol() >= 5;
        st.reporter = Some(reporter);
        if !st.end_acked {
            st.end_sent = false;
        }
        if let Some(spool) = st.spool.as_mut() {
            let acked = spool.acked();
            st.sent = match spool.rewind(acked) {
                // Resend from the last acknowledgement.
                Ok(()) => acked,
                // The send cursor stayed ahead of `acked`; keeping `sent`
                // there too counts the unread tail as in-flight, so the
                // window cannot overflow. What was skipped reaches the
                // controller as a declared gap, never a silent one.
                Err(_) => spool.last_seq(),
            };
        }
        self.pump(&mut st);
    }

    pub fn detached(&self) {
        self.lock().reporter = None;
    }
}

impl Output for LogPipe {
    fn write(&self, step: u32, stream: Stream, bytes: &[u8]) {
        let mut st = self.lock();
        if st.ended {
            return;
        }
        let out = st.redactor.apply(stream, bytes);
        if out.is_empty() {
            return;
        }
        let Some(spool) = st.spool.as_mut() else {
            return;
        };
        for chunk in out.chunks(MAX_LOG_FRAME_BYTES) {
            // Every chunk spends its sequence whether the write lands, the
            // cap refuses it, or the disk fails — `append` declares what it
            // could not hold, and the next chunk must still spend its own.
            let _ = spool.append(step, stream, chunk);
        }
        st.unsynced += 1;
        if st.unsynced >= SYNC_EVERY
            && let Some(spool) = st.spool.as_mut()
            && spool.sync().is_ok()
        {
            st.unsynced = 0;
        }
        self.pump(&mut st);
    }

    fn complete(&self) -> bool {
        let mut st = self.lock();
        if !st.ended {
            for stream in [Stream::Stdout, Stream::Stderr] {
                let rest = st.redactor.flush(stream);
                if !rest.is_empty()
                    && let Some(spool) = st.spool.as_mut()
                {
                    for chunk in rest.chunks(MAX_LOG_FRAME_BYTES) {
                        let _ = spool.append(u32::MAX, stream, chunk);
                    }
                }
            }
            if let Some(spool) = st.spool.as_mut() {
                let _ = spool.sync();
            }
            st.ended = true;
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
