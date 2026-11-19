//! A bulk connection that swallows a log's frames loses nothing: the pipe rewinds to its last acknowledgement and
//! sends every frame again on the control connection, where the controller stores them once, in sequence.

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
        Offer, Rejection, Reporter, Sender, SessionHandler,
    },
    tls,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion, negotiate};
use sentinel_store::logs::{Appended, LogStore};
use sentinel_worker::{attempt::Output, logpipe::LogPipe, redact::Redactor, spool::SpoolSpace};

const FRAMES: usize = 300;
const PAYLOAD: usize = 2 << 10;

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

#[derive(Default)]
struct Logs {
    store: Option<LogStore>,
    scope: (RunId, JobId),
    /// Every sequence the controller was handed, in the order it arrived, so a replay that duplicates or reorders a
    /// frame is visible rather than hidden by the store's idempotence.
    seen: Mutex<Vec<u64>>,
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
        let (run, job) = self.scope;
        match self
            .store
            .as_ref()
            .expect("store")
            .append(run, job, attempt, &frame)
        {
            Ok(Appended::Stored { through } | Appended::Duplicate { through }) => {
                self.seen.lock().unwrap().push(frame.seq);
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
        let (run, job) = self.scope;
        match self
            .store
            .as_ref()
            .expect("store")
            .finish(run, job, attempt, last_seq, gaps)
        {
            Ok(()) => LogVerdict::Acked(last_seq),
            Err(_) => LogVerdict::Refused,
        }
    }
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

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
    fn bulk_detached(&self) {
        if let Some(pipe) = self.pipe.lock().unwrap().clone() {
            pipe.resync();
        }
    }
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

#[test]
fn a_lost_bulk_connection_replays_the_log_from_the_last_acknowledgement() {
    let temp = tempfile::tempdir().unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let handler = Arc::new(Logs {
        store: Some(LogStore::open(temp.path().join("logs")).unwrap()),
        scope: (run, job),
        seen: Mutex::new(Vec::new()),
    });
    let controller = Identity::generate("controller").unwrap();
    let pin = controller.fingerprint();
    let server = tls::server_config(controller).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    // The bulk connection is served until the test tears it down: the frames stored before the cut are acknowledged
    // on it, and everything the worker handed it afterwards is lost with the socket, as a firewall or a dead helper
    // loses it.
    let bulk: Arc<Mutex<Option<Sender>>> = Arc::default();
    let control_bulk = Arc::clone(&bulk);
    let serving = Arc::clone(&handler);
    let _control = thread::spawn(move || {
        let (control_socket, _) = listener.accept().unwrap();
        let Accepted::Control(mut control) =
            session::accept(control_socket, server.clone(), &AnyAdmission).unwrap()
        else {
            panic!("control hello first");
        };
        let (bulk_socket, _) = listener.accept().unwrap();
        let Accepted::Bulk(bulk) = session::accept(bulk_socket, server, &AnyAdmission).unwrap()
        else {
            panic!("a bulk hello on the second connection");
        };
        *control_bulk.lock().unwrap() = Some(bulk.sender());
        let serving_bulk = Arc::clone(&serving);
        thread::spawn(move || {
            let mut bulk = bulk;
            let _ = bulk.serve(
                &*serving_bulk,
                sentinel_protocol::negotiate::SUPPORTED_MAX.0,
                &|| true,
            );
        });
        let _ = control.serve(&*serving);
    });

    let client = tls::client_config(Identity::generate("worker").unwrap(), pin).unwrap();
    let mut link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "worker",
        Hello {
            protocol_min: ProtocolVersion(7),
            protocol_max: sentinel_protocol::negotiate::SUPPORTED_MAX,
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
    link.send_profile(&sentinel_protocol::negotiate::Profile::default())
        .unwrap();
    let dialer = link.bulk_dialer().expect("protocol 7 dials a bulk route");
    let mut bulk_link = dialer.open().expect("the bulk connection attaches");
    let executor = Arc::new(Forward::default());
    {
        let executor = Arc::clone(&executor);
        thread::spawn(move || {
            let _ = bulk_link.run(&*executor, || false);
        });
    }
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
    let payload = format!("{}\n", "x".repeat(PAYLOAD - 1));
    for _ in 0..FRAMES {
        pipe.write(0, Stream::Stdout, payload.as_bytes());
    }
    // The route dies the moment the controller has stored a frame on it: what it acknowledged is safe, and
    // everything after that acknowledgement is lost with the socket, so the pipe must rewind rather than continue
    // from where it had written.
    let deadline = Instant::now() + Duration::from_secs(10);
    while handler.seen.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "the bulk connection carried no frame"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let dead = bulk
        .lock()
        .unwrap()
        .take()
        .expect("the bulk connection attached");
    dead.close();
    drop(dead);
    assert!(
        pipe.complete(),
        "the log did not close over the fallback route"
    );

    let tail = handler
        .store
        .as_ref()
        .unwrap()
        .tail(run, job, attempt, 0, FRAMES + 1, None)
        .unwrap();
    assert!(tail.complete, "the log must reach its end marker");
    assert_eq!(tail.gaps, Vec::new(), "no frame may be declared lost");
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        (1..=FRAMES as u64).collect::<Vec<_>>(),
        "every frame the bulk swallowed is stored once, in sequence"
    );
    // Frames the dead route had already read past the last acknowledgement arrive as duplicates, in whatever order
    // two connections deliver them. What the pipe owes is that each is sent again from that acknowledgement and that
    // the store ends up holding one copy of it, in sequence.
    let seen = handler.seen.lock().unwrap().clone();
    let count = |seq: u64| seen.iter().filter(|s| **s == seq).count();
    assert!(
        (1..=FRAMES as u64).all(|seq| count(seq) >= 1),
        "every frame reached the controller"
    );
    assert!(
        (1..=FRAMES as u64).all(|seq| count(seq) <= 2),
        "a frame travels once per route, never more"
    );
    assert!(
        !worker
            .join(sentinel_worker::spool::SPOOL_DIR)
            .join(attempt.to_string())
            .exists(),
        "the spool is gone once the end is acknowledged"
    );
}
