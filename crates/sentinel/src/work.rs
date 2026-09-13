//! Fixed-size execution lanes. Admission never blocks the calling control thread.
//! Captured payload sizes must also be bounded by callers; queue depth is not a byte quota.
use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::timing::elapsed_ns;

type Job = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Copy, Debug)]
pub enum WorkClass {
    BlockingIo,
    Cpu,
}
impl WorkClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockingIo => "blocking_io",
            Self::Cpu => "cpu",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkError {
    Full,
    Closed,
    Panicked,
    Timeout,
}
impl fmt::Display for WorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "work execution: {self:?}")
    }
}
impl std::error::Error for WorkError {}

pub struct Task<T> {
    result: Receiver<Result<T, WorkError>>,
}
impl<T> Task<T> {
    /// Blocking wait, suitable for bootstrap/drain only, not a future async control loop.
    /// Timeout does not interrupt a running closure or free its occupied lane.
    pub fn wait(self, timeout: Duration) -> Result<T, WorkError> {
        self.result
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => WorkError::Timeout,
                mpsc::RecvTimeoutError::Disconnected => WorkError::Closed,
            })?
    }
}

pub struct Executor {
    sender: Option<SyncSender<Job>>,
    stopping: Arc<AtomicBool>,
    done: Receiver<()>,
    thread: Option<JoinHandle<()>>,
    class: WorkClass,
}

impl Executor {
    /// One dedicated thread per lane, plus at most `capacity` waiting tasks.
    /// Separate instances for I/O and CPU prevent either class consuming the other's thread.
    pub fn new(class: WorkClass, capacity: usize) -> std::io::Result<Self> {
        if !(1..=1024).contains(&capacity) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "work queue capacity must be 1..=1024",
            ));
        }
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let (done_sender, done) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let thread = thread::Builder::new()
            .name(format!("sentinel-{}", class.as_str()))
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    job();
                }
                let _ = done_sender.send(());
            })?;
        Ok(Self {
            sender: Some(sender),
            stopping,
            done,
            thread: Some(thread),
            class,
        })
    }

    pub fn try_submit<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Task<T>, WorkError> {
        let sender = self.sender.as_ref().ok_or(WorkError::Closed)?;
        let (result_sender, result) = mpsc::sync_channel(1);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let queued = Instant::now();
        let class = self.class;
        let job = Box::new(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                span.in_scope(|| {
                    let queue_wait_ns = elapsed_ns(queued);
                    let started = Instant::now();
                    // A panic must not permanently remove the lane. The normal panic hook
                    // still runs; callers must not panic with sensitive payloads.
                    let value =
                        catch_unwind(AssertUnwindSafe(work)).map_err(|_| WorkError::Panicked);
                    tracing::debug!(
                        event = "work_completed",
                        work_class = class.as_str(),
                        queue_wait_ns,
                        duration_ns = elapsed_ns(started),
                        panicked = value.is_err()
                    );
                    let _ = result_sender.send(value);
                })
            });
        });
        sender.try_send(job).map_err(|error| {
            let reason = match error {
                TrySendError::Full(_) => WorkError::Full,
                TrySendError::Disconnected(_) => WorkError::Closed,
            };
            tracing::warn!(event = "work_rejected", work_class = class.as_str(), reason = ?reason);
            reason
        })?;
        Ok(Task { result })
    }

    /// Stop admission, drop pending tasks, and wait at most the supplied deadline
    /// for the active task. Rust threads cannot be forcibly cancelled.
    pub fn shutdown(&mut self, timeout: Duration) -> bool {
        self.stopping.store(true, Ordering::Release);
        self.sender.take();
        if self.thread.is_none() {
            return true;
        }
        if self.done.recv_timeout(timeout).is_ok() {
            return self.thread.take().unwrap().join().is_ok();
        }
        false
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        // No unbounded join from Drop. Explicit shutdown reports whether draining finished.
        self.stopping.store(true, Ordering::Release);
        self.sender.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMIT: Duration = Duration::from_secs(2);

    #[test]
    fn saturation_rejects_without_starving_another_lane_and_panic_recovers() {
        let mut io = Executor::new(WorkClass::BlockingIo, 1).unwrap();
        let mut cpu = Executor::new(WorkClass::Cpu, 1).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let first = io
            .try_submit(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(LIMIT).unwrap();
            })
            .unwrap();
        started_rx.recv_timeout(LIMIT).unwrap();
        let second = io.try_submit(|| 42).unwrap();
        assert!(matches!(io.try_submit(|| ()), Err(WorkError::Full)));
        assert_eq!(cpu.try_submit(|| 7).unwrap().wait(LIMIT), Ok(7));
        release_tx.send(()).unwrap();
        first.wait(LIMIT).unwrap();
        assert_eq!(second.wait(LIMIT), Ok(42));
        assert_eq!(
            cpu.try_submit(|| panic!("test panic")).unwrap().wait(LIMIT),
            Err(WorkError::Panicked)
        );
        assert_eq!(cpu.try_submit(|| 8).unwrap().wait(LIMIT), Ok(8));
        assert!(io.shutdown(LIMIT));
        assert!(cpu.shutdown(LIMIT));
        assert!(matches!(io.try_submit(|| ()), Err(WorkError::Closed)));
    }

    #[test]
    fn shutdown_is_bounded_and_discards_waiting_work() {
        let mut executor = Executor::new(WorkClass::BlockingIo, 1).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let active = executor
            .try_submit(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(LIMIT).unwrap();
            })
            .unwrap();
        started_rx.recv_timeout(LIMIT).unwrap();
        let queued = executor
            .try_submit(|| panic!("queued work must not run"))
            .unwrap();
        assert!(!executor.shutdown(Duration::ZERO));
        release_tx.send(()).unwrap();
        active.wait(LIMIT).unwrap();
        assert!(executor.shutdown(LIMIT));
        assert_eq!(queued.wait(LIMIT), Err(WorkError::Closed));
    }

    #[test]
    fn result_timeout_does_not_release_active_capacity() {
        let mut executor = Executor::new(WorkClass::Cpu, 1).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let active = executor
            .try_submit(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(LIMIT).unwrap();
            })
            .unwrap();
        started_rx.recv_timeout(LIMIT).unwrap();
        assert_eq!(active.wait(Duration::ZERO), Err(WorkError::Timeout));
        let queued = executor.try_submit(|| 42).unwrap();
        assert!(matches!(executor.try_submit(|| ()), Err(WorkError::Full)));
        release_tx.send(()).unwrap();
        assert_eq!(queued.wait(LIMIT), Ok(42));
        assert!(executor.shutdown(LIMIT));
    }
}
