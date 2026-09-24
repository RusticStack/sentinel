//! A log pipe whose spool refuses output — the worker's spool quota or its
//! free-space reserve (R01/D06) — still closes its log, over a real
//! loopback TLS session into a real `LogStore`: the refused frames are
//! declared as gaps, the end goes out once every *stored* frame is
//! acknowledged, and the refusals are counted by cause.

#![cfg(target_os = "linux")]

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, Fence, JobId, PoolId, RunId, UnixMillis, WorkerId};
use sentinel_link::{
    identity::Identity,
    session::{
        self, Accepted, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict,
        Offer, Rejection, Reporter, SessionHandler,
    },
    tls,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion, negotiate};
use sentinel_store::logs::{Appended, LogStore};
use sentinel_worker::{
    attempt::Output,
    logpipe::LogPipe,
    redact::Redactor,
    spool::{SPOOL_DIR, SpoolSpace},
};

struct AnyAdmission;
impl Admission for AnyAdmission {
    fn admit(
        &self,
        _: &sentinel_auth::secret::Digest,
        worker: WorkerId,
        _: &str,
        hello: &Hello,
        _: Option<&sentinel_auth::secret::Secret>,
        _: Capacity,
    ) -> Result<Admitted, Rejection> {
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated: negotiate(hello).map_err(Rejection::from)?,
        })
    }
}

/// The controller's log handling, reduced to its store: a frame is
/// acknowledged through the stored frontier once durable, and the end once
/// its marker is.
struct Logs {
    store: LogStore,
    run: RunId,
    job: JobId,
}

impl SessionHandler for Logs {
    fn ping(&self, _: WorkerId, _: &[AttemptId]) -> sentinel_link::Result<Beat> {
        Ok(Beat {
            lease_until: UnixMillis(UnixMillis::now().0 + 30_000),
            stop: Vec::new(),
            cancel: Vec::new(),
        })
    }
    fn acknowledged(&self, _: WorkerId, _: AttemptId, _: Fence) {}
    fn declined(&self, _: WorkerId, _: AttemptId, _: Fence) {}
    fn reported(&self, _: WorkerId, _: AttemptId, _: Fence, _: Event, _: Option<Vec<u8>>) {}
    fn spec(&self, _: WorkerId, _: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }
    fn log(&self, _: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict {
        match self.store.append(self.run, self.job, attempt, &frame) {
            Ok(Appended::Stored { through } | Appended::Duplicate { through }) => {
                LogVerdict::Acked(through)
            }
            Err(_) => LogVerdict::Refused,
        }
    }
    fn log_end(
        &self,
        _: WorkerId,
        attempt: AttemptId,
        last_seq: u64,
        gaps: &[(u64, u64)],
    ) -> LogVerdict {
        match self
            .store
            .finish(self.run, self.job, attempt, last_seq, gaps)
        {
            Ok(()) => LogVerdict::Acked(last_seq),
            Err(_) => LogVerdict::Refused,
        }
    }
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

/// Hands acknowledgements to the pipe, as the executor does.
#[derive(Default)]
struct Forward {
    reporter: Mutex<Option<Reporter>>,
    pipe: Mutex<Option<Arc<LogPipe>>>,
}

impl Executor for Forward {
    fn offered(&self, _: &Offer) -> bool {
        false
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, reporter: Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, through: u64) {
        if let Some(pipe) = self.pipe.lock().unwrap().clone() {
            pipe.acked(through);
        }
    }
    fn log_refused(&self, _: AttemptId) {
        if let Some(pipe) = self.pipe.lock().unwrap().clone() {
            pipe.refused();
        }
    }
    fn log_ended(&self, _: AttemptId) {
        if let Some(pipe) = self.pipe.lock().unwrap().clone() {
            pipe.end_acked();
        }
    }
}

/// The quota runs out after three frames: the next two are refused and
/// declared. Before the fix the end waited for an acknowledgement of the
/// refused tail — which never comes, since it was never sent — until the
/// 60 s flush timeout failed the attempt as a publication failure.
#[test]
fn a_spool_refusing_its_tail_still_closes_the_log_with_the_gaps_declared() {
    let temp = tempfile::tempdir().unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let handler = Logs {
        store: LogStore::open(temp.path().join("logs")).unwrap(),
        run,
        job,
    };
    let controller = Identity::generate("controller").unwrap();
    let pin = controller.fingerprint();
    let server = tls::server_config(controller).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    let serving = Arc::clone(&handler);
    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        if let Ok(Accepted::Control(mut control)) = session::accept(socket, server, &AnyAdmission) {
            let _ = control.serve(&*serving);
        }
    });
    let client = tls::client_config(Identity::generate("worker").unwrap(), pin).unwrap();
    let mut link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "worker",
        Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: ProtocolVersion(6),
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "test".into(),
        },
        None,
        Capacity {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
        },
    )
    .unwrap();
    let executor = Arc::new(Forward::default());
    {
        let executor = Arc::clone(&executor);
        thread::spawn(move || {
            let _ = link.run(&*executor, || false);
        });
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while executor.reporter.lock().unwrap().is_none() {
        assert!(Instant::now() < deadline, "no session");
        thread::sleep(Duration::from_millis(5));
    }

    let worker = temp.path().join("worker");
    let space = SpoolSpace::with_probe(&worker, 0, u64::MAX, |_| None);
    let reporter = executor.reporter.lock().unwrap().clone();
    let pipe = Arc::new(LogPipe::open_in(&space, attempt, Redactor::new(), reporter).unwrap());
    *executor.pipe.lock().unwrap() = Some(Arc::clone(&pipe));
    for n in 1..=3 {
        pipe.write(0, Stream::Stdout, format!("line {n}\n").as_bytes());
    }
    // The worker's spools now hold all the quota allows.
    space.set_limits(0, space.used());
    for n in 4..=5 {
        pipe.write(0, Stream::Stdout, format!("line {n}\n").as_bytes());
    }
    let closing = Instant::now();
    assert!(pipe.complete(), "the log did not close");
    assert!(
        closing.elapsed() < Duration::from_secs(10),
        "the end waited {:?}",
        closing.elapsed()
    );
    assert_eq!(pipe.refusals().quota, 2);
    assert_eq!(pipe.refusals().total(), 2);
    // The spool is gone and its bytes left the quota.
    assert!(!worker.join(SPOOL_DIR).join(attempt.to_string()).exists());
    assert_eq!(space.used(), 0);
    let tail = handler.store.tail(run, job, attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.frames.len(), 3);
    assert_eq!(tail.gaps, vec![(4, 5)]);
}
