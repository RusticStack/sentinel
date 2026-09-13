//! Internal diagnostics, not durable job stdout/stderr. A slow sink may lose events.
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

use crate::{LogFormat, LogLevel};

pub const LOG_QUEUE_CAPACITY: usize = 256;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct Counters {
    full: AtomicU64,
    oversized: AtomicU64,
    closed: AtomicU64,
    io_errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LossSnapshot {
    pub full: u64,
    pub oversized: u64,
    pub closed: u64,
    pub io_errors: u64,
}

#[derive(Clone)]
struct QueueWriter {
    sender: Arc<Mutex<Option<SyncSender<Vec<u8>>>>>,
    counters: Arc<Counters>,
}

impl QueueWriter {
    fn snapshot(&self) -> LossSnapshot {
        LossSnapshot {
            full: self.counters.full.load(Ordering::Relaxed),
            oversized: self.counters.oversized.load(Ordering::Relaxed),
            closed: self.counters.closed.load(Ordering::Relaxed),
            io_errors: self.counters.io_errors.load(Ordering::Relaxed),
        }
    }
}

struct RecordWriter {
    queue: QueueWriter,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Write for RecordWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES.saturating_sub(self.bytes.len()) {
            self.oversized = true;
        }
        if !self.oversized {
            self.bytes.extend_from_slice(bytes);
        }
        // Losing one whole event is preferable to emitting invalid/truncated JSON.
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        let counters = &self.queue.counters;
        if self.oversized {
            counters.oversized.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.bytes.is_empty() {
            return;
        }
        let sender = self
            .queue
            .sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(sender) = sender.as_ref() else {
            counters.closed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match sender.try_send(std::mem::take(&mut self.bytes)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                counters.full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                counters.closed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl<'a> MakeWriter<'a> for QueueWriter {
    type Writer = RecordWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter {
            queue: self.clone(),
            bytes: Vec::with_capacity(MAX_RECORD_BYTES),
            oversized: false,
        }
    }
}

pub struct Diagnostics {
    dispatch: Dispatch,
    writer: QueueWriter,
    done: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl Diagnostics {
    pub fn stderr(format: LogFormat, level: LogLevel) -> io::Result<Self> {
        Self::with_sink(format, level, io::stderr())
    }

    pub fn with_sink(
        format: LogFormat,
        level: LogLevel,
        mut sink: impl Write + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
        let (done_sender, done) = mpsc::sync_channel(1);
        let writer = QueueWriter {
            sender: Arc::new(Mutex::new(Some(sender))),
            counters: Arc::new(Counters::default()),
        };
        let counters = writer.counters.clone();
        let thread = thread::Builder::new()
            .name("sentinel-diagnostics".into())
            .spawn(move || {
                while let Ok(bytes) = receiver.recv() {
                    if sink.write_all(&bytes).is_err() {
                        counters.io_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if sink.flush().is_err() {
                    counters.io_errors.fetch_add(1, Ordering::Relaxed);
                }
                let _ = done_sender.send(());
            })?;
        let level = match level {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_max_level(level)
            .with_ansi(false);
        let dispatch = match format {
            LogFormat::Text => Dispatch::new(subscriber.finish()),
            LogFormat::Json => Dispatch::new(
                subscriber
                    .json()
                    .with_current_span(false)
                    .with_span_list(true)
                    .finish(),
            ),
        };
        Ok(Self {
            dispatch,
            writer,
            done,
            thread: Some(thread),
        })
    }

    pub fn dispatch(&self) -> &Dispatch {
        &self.dispatch
    }
    pub fn losses(&self) -> LossSnapshot {
        self.writer.snapshot()
    }

    /// A stalled stderr/pipe must not indefinitely delay process shutdown.
    /// False means output is incomplete; the caller decides its exit policy.
    pub fn shutdown(&mut self, timeout: Duration) -> bool {
        self.writer
            .sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if self.thread.is_none() {
            return true;
        }
        if self.done.recv_timeout(timeout).is_ok() {
            return self.thread.take().unwrap().join().is_ok();
        }
        false
    }
}

impl Drop for Diagnostics {
    fn drop(&mut self) {
        self.writer
            .sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        correlation::*,
        timing::{Outcome, Phase, PhaseTimer},
        work::{Executor, WorkClass},
    };
    const LIMIT: Duration = Duration::from_secs(2);

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_preserves_all_ids_across_work_threads_and_measures_local_phases() {
        let capture = Capture::default();
        let mut logs =
            Diagnostics::with_sink(LogFormat::Json, LogLevel::Debug, capture.clone()).unwrap();
        let ids = Correlation {
            process_id: ProcessId::new(),
            request_id: Some(RequestId::new()),
            run_id: Some(RunId::new()),
            job_id: Some(JobId::new()),
            attempt_id: Some(AttemptId::new()),
        };
        let mut executor = Executor::new(WorkClass::Cpu, 1).unwrap();
        tracing::dispatcher::with_default(logs.dispatch(), || {
            ids.span().in_scope(|| {
                executor
                    .try_submit(|| {
                        let outer = PhaseTimer::start(Phase::Step);
                        let inner =
                            PhaseTimer::start(Phase::CacheRestore).finish(Outcome::Completed);
                        assert!(outer.finish(Outcome::Failed) >= inner);
                    })
                    .unwrap()
                    .wait(LIMIT)
                    .unwrap();
            })
        });
        assert!(executor.shutdown(LIMIT));
        assert!(logs.shutdown(LIMIT));
        let bytes = capture.0.lock().unwrap();
        let records: Vec<serde_json::Value> = String::from_utf8_lossy(&bytes)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        for record in &records {
            let context = &record["spans"][0];
            assert_eq!(context["request_id"], ids.request_id.unwrap().to_string());
            assert_eq!(context["run_id"], ids.run_id.unwrap().to_string());
            assert_eq!(context["job_id"], ids.job_id.unwrap().to_string());
            assert_eq!(context["attempt_id"], ids.attempt_id.unwrap().to_string());
            assert_eq!(context["process_id"], ids.process_id.to_string());
            assert_eq!(context["schema_version"], 1);
            assert!(record["fields"]["duration_ns"].is_u64());
        }
        assert_eq!(records[1]["fields"]["outcome"], "failed");
        assert!(records[2]["fields"]["queue_wait_ns"].is_u64());
    }

    #[test]
    fn filtered_events_keep_error_context_and_oversized_records_are_dropped_whole() {
        let capture = Capture::default();
        let mut logs =
            Diagnostics::with_sink(LogFormat::Json, LogLevel::Warn, capture.clone()).unwrap();
        let ids = Correlation::process(ProcessId::new());
        tracing::dispatcher::with_default(logs.dispatch(), || {
            ids.span().in_scope(|| {
                tracing::info!("filtered");
                tracing::warn!("retained");
                tracing::error!(payload = "x".repeat(MAX_RECORD_BYTES * 2), "too large");
            })
        });
        assert!(logs.shutdown(LIMIT));
        assert_eq!(logs.losses().oversized, 1);
        let bytes = capture.0.lock().unwrap();
        let lines = String::from_utf8_lossy(&bytes);
        assert_eq!(lines.lines().count(), 1);
        let record: serde_json::Value = serde_json::from_str(lines.trim()).unwrap();
        assert_eq!(record["spans"][0]["process_id"], ids.process_id.to_string());
        assert!(record["spans"][0].get("run_id").is_none());
    }

    struct StalledSink {
        started: SyncSender<()>,
        release: Receiver<()>,
    }
    impl Write for StalledSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.started.try_send(());
            self.release.recv_timeout(LIMIT).unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn slow_sink_has_bounded_queue_and_shutdown_wait() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(LOG_QUEUE_CAPACITY + 1);
        let mut logs = Diagnostics::with_sink(
            LogFormat::Json,
            LogLevel::Info,
            StalledSink {
                started: started_tx,
                release: release_rx,
            },
        )
        .unwrap();
        tracing::dispatcher::with_default(logs.dispatch(), || tracing::info!("first"));
        started_rx.recv_timeout(LIMIT).unwrap();
        tracing::dispatcher::with_default(logs.dispatch(), || {
            for _ in 0..LOG_QUEUE_CAPACITY + 10 {
                tracing::info!("queued");
            }
        });
        assert_eq!(logs.losses().full, 10);
        assert!(!logs.shutdown(Duration::ZERO));
        for _ in 0..LOG_QUEUE_CAPACITY + 1 {
            release_tx.send(()).unwrap();
        }
        assert!(logs.shutdown(LIMIT));
    }

    #[test]
    fn sink_write_failure_is_counted_without_recursive_logging() {
        struct BrokenSink;
        impl Write for BrokenSink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut logs = Diagnostics::with_sink(LogFormat::Json, LogLevel::Info, BrokenSink).unwrap();
        tracing::dispatcher::with_default(logs.dispatch(), || tracing::info!("lost"));
        assert!(logs.shutdown(LIMIT));
        assert_eq!(logs.losses().io_errors, 1);
    }
}
