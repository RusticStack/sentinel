use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, Fence, PoolId, UnixMillis, WorkerId};
use sentinel_link::{
    Error,
    identity::Identity,
    session::{
        self, Accepted, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict,
        Offer, Rejection, Reporter, SessionHandler,
    },
    tls,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{
    Arch, Capabilities, Hello, Profile, ProtocolVersion, negotiate,
};

/// Socket buffers autotune, so the flood writes until the writer blocks, not a fixed amount.
const FLOOD_BYTES: usize = 16 * 1024;
const STALL_QUIET: Duration = Duration::from_secs(1);
const PONG_WINDOW: Duration = Duration::from_secs(12);

fn wait_until(mut done: impl FnMut() -> bool, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

struct AnyAdmission;

impl Admission for AnyAdmission {
    fn admit(
        &self,
        _fingerprint: &sentinel_auth::secret::Digest,
        worker: WorkerId,
        _name: &str,
        hello: &Hello,
        _enrollment: Option<&sentinel_auth::secret::Secret>,
        _capacity: Capacity,
    ) -> Result<Admitted, Rejection> {
        let negotiated = negotiate(hello).map_err(Rejection::from)?;
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated,
        })
    }
}

#[derive(Default)]
struct Counting {
    pings: AtomicU64,
    logs: AtomicU64,
}

impl SessionHandler for Counting {
    fn ping(&self, _worker: WorkerId, _held: &[AttemptId]) -> sentinel_link::Result<Beat> {
        self.pings.fetch_add(1, Ordering::AcqRel);
        Ok(Beat {
            lease_until: UnixMillis(UnixMillis::now().0 + 30_000),
            stop: Vec::new(),
            cancel: Vec::new(),
        })
    }
    fn acknowledged(&self, _worker: WorkerId, _attempt: AttemptId, _fence: Fence) {}
    fn declined(&self, _worker: WorkerId, _attempt: AttemptId, _fence: Fence) {}
    fn reported(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _fence: Fence,
        _event: Event,
        _summary: Option<Vec<u8>>,
    ) {
    }
    fn spec(&self, _worker: WorkerId, _attempt: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }
    fn log(&self, _worker: WorkerId, _attempt: AttemptId, frame: Frame) -> LogVerdict {
        self.logs.fetch_add(1, Ordering::AcqRel);
        LogVerdict::Acked(frame.seq)
    }
    fn abandoned(&self, _worker: WorkerId, _attempt: AttemptId, _fence: Fence) {}
}

#[derive(Default)]
struct TestExecutor {
    reporter: Mutex<Option<Reporter>>,
    acked: AtomicU64,
    refused: AtomicU64,
}

impl Executor for TestExecutor {
    fn offered(&self, _offer: &Offer) -> bool {
        false
    }
    fn stop(&self, _attempt: AttemptId) {}
    fn cancel(&self, _attempt: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _until: UnixMillis) {}
    fn attached(&self, reporter: Reporter) {
        *self.reporter.lock().unwrap_or_else(|p| p.into_inner()) = Some(reporter);
    }
    fn detached(&self) {
        self.reporter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
    fn spec(&self, _attempt: AttemptId, _context: JobContext, _bytes: Vec<u8>) {}
    fn no_spec(&self, _attempt: AttemptId) {}
    fn log_acked(&self, _attempt: AttemptId, _through: u64) {
        self.acked.fetch_add(1, Ordering::AcqRel);
    }
    fn log_refused(&self, _attempt: AttemptId) {
        self.refused.fetch_add(1, Ordering::AcqRel);
    }
}

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: sentinel_protocol::negotiate::SUPPORTED_MAX,
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "sentinel-link-test".into(),
    }
}

fn capacity() -> Capacity {
    Capacity {
        cpu_millis: 4_000,
        memory_bytes: 8 << 30,
    }
}

fn deployment() -> (
    std::net::TcpListener,
    Arc<rustls::ServerConfig>,
    std::sync::Arc<rustls::ClientConfig>,
) {
    let controller = Identity::generate("controller-priority").unwrap();
    let fingerprint = controller.fingerprint();
    let server = tls::server_config(controller).unwrap();
    let worker = Identity::generate("worker-priority").unwrap();
    let client = tls::client_config(worker, fingerprint).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    (listener, server, client)
}

fn log_frame(seq: u64) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: vec![b'x'; FLOOD_BYTES],
    }
}

#[test]
fn stalled_bulk_never_holds_up_the_control_beat() {
    let (listener, server, client) = deployment();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(Counting::default());
    let drain = Arc::new(AtomicBool::new(false));
    let controller = {
        let handler = Arc::clone(&handler);
        let drain = Arc::clone(&drain);
        thread::spawn(move || {
            let (control_socket, _) = listener.accept().unwrap();
            let Accepted::Control(mut control) =
                session::accept(control_socket, server.clone(), &AnyAdmission).unwrap()
            else {
                panic!("first connection must be the control hello");
            };
            let (bulk_socket, _) = listener.accept().unwrap();
            let Accepted::Bulk(mut bulk) =
                session::accept(bulk_socket, server, &AnyAdmission).unwrap()
            else {
                panic!("second connection must be the bulk hello");
            };
            let control_handler = Arc::clone(&handler);
            let serving = thread::spawn(move || {
                let _ = control.serve(&*control_handler);
            });
            while !drain.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = bulk.serve(
                &*handler,
                sentinel_protocol::negotiate::SUPPORTED_MAX.0,
                &|| !serving.is_finished(),
            );
            let _ = serving.join();
        })
    };

    let executor = Arc::new(TestExecutor::default());
    let stop = Arc::new(AtomicBool::new(false));
    let bulk_stop = Arc::new(AtomicBool::new(false));
    let mut link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "priority",
        hello(),
        None,
        capacity(),
    )
    .unwrap();
    assert_eq!(
        link.negotiated.protocol,
        sentinel_protocol::negotiate::SUPPORTED_MAX
    );
    link.send_profile(&Profile::default()).unwrap();
    let bulk = link
        .bulk_dialer()
        .expect("protocol 7 has a bulk dialer")
        .open()
        .unwrap();
    let bulk_closer = bulk.sender();
    let bulk_reader = {
        let executor = Arc::clone(&executor);
        let stop = Arc::clone(&bulk_stop);
        let mut bulk = bulk;
        thread::spawn(move || {
            let _ = bulk.run(&*executor, || stop.load(Ordering::Acquire));
        })
    };
    let closer = link.sender();
    let runner = {
        let executor = Arc::clone(&executor);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let _ = link.run(&*executor, || stop.load(Ordering::Acquire));
        })
    };
    assert!(
        wait_until(
            || executor
                .reporter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_some(),
            Duration::from_secs(5)
        ),
        "the session must attach its reporter"
    );
    let reporter = executor
        .reporter
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .expect("reporter checked present");

    let sent = Arc::new(AtomicU64::new(0));
    let outcome = Arc::new(AtomicU64::new(0));
    let attempt = AttemptId::new();
    let flood = {
        let sent = Arc::clone(&sent);
        let outcome = Arc::clone(&outcome);
        let drain = Arc::clone(&drain);
        thread::spawn(move || {
            let frame = log_frame(0);
            let mut seq = 0;
            while !drain.load(Ordering::Acquire) {
                seq += 1;
                if reporter
                    .log_frame(attempt, seq, frame.step, frame.stream, &frame.bytes)
                    .is_err()
                {
                    outcome.store(2, Ordering::Release);
                    return;
                }
                sent.store(seq, Ordering::Release);
            }
            outcome.store(1, Ordering::Release);
        })
    };

    let stalled_at = {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = sent.load(Ordering::Acquire);
        let mut since = Instant::now();
        loop {
            assert_eq!(
                outcome.load(Ordering::Acquire),
                0,
                "the flood must still be writing while nothing reads the bulk connection"
            );
            let now = sent.load(Ordering::Acquire);
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= STALL_QUIET {
                break last;
            }
            assert!(
                Instant::now() < deadline,
                "the bulk writer never blocked ({last} frames of {FLOOD_BYTES} bytes sent)"
            );
            thread::sleep(Duration::from_millis(20));
        }
    };
    assert!(stalled_at > 0, "the bulk connection took no frames at all");

    let pings_before = handler.pings.load(Ordering::Acquire);
    assert!(
        wait_until(
            || handler.pings.load(Ordering::Acquire) > pings_before,
            PONG_WINDOW
        ),
        "a pong must arrive while the bulk connection is stalled"
    );
    assert_eq!(
        (
            sent.load(Ordering::Acquire),
            outcome.load(Ordering::Acquire)
        ),
        (stalled_at, 0),
        "the bulk writer must still have been blocked when the pong arrived"
    );

    drain.store(true, Ordering::Release);
    assert!(
        wait_until(
            || outcome.load(Ordering::Acquire) != 0,
            Duration::from_secs(30)
        ),
        "the stalled bulk write must complete once the controller reads"
    );
    assert_eq!(
        outcome.load(Ordering::Acquire),
        1,
        "the stalled bulk write must complete, not fail, once the controller reads"
    );
    let total = sent.load(Ordering::Acquire);
    assert!(
        wait_until(
            || handler.logs.load(Ordering::Acquire) == total,
            Duration::from_secs(30)
        ),
        "every flooded frame must reach the controller after the drain"
    );
    stop.store(true, Ordering::Release);
    bulk_stop.store(true, Ordering::Release);
    closer.close();
    bulk_closer.close();
    flood.join().unwrap();
    let _ = runner.join();
    let _ = bulk_reader.join();
    let _ = controller.join();
}

#[test]
fn bulk_traffic_on_control_is_served_as_fallback() {
    let (listener, server, client) = deployment();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(Counting::default());
    let controller = {
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let Accepted::Control(mut control) =
                session::accept(socket, server, &AnyAdmission).unwrap()
            else {
                panic!("control hello expected");
            };
            let _ = control.serve(&*handler);
        })
    };

    let executor = Arc::new(TestExecutor::default());
    let stop = Arc::new(AtomicBool::new(false));
    let mut link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "fallback",
        hello(),
        None,
        capacity(),
    )
    .unwrap();
    assert_eq!(
        link.negotiated.protocol,
        sentinel_protocol::negotiate::SUPPORTED_MAX
    );
    link.send_profile(&Profile::default()).unwrap();
    let closer = link.sender();
    let runner = {
        let executor = Arc::clone(&executor);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let _ = link.run(&*executor, || stop.load(Ordering::Acquire));
        })
    };
    assert!(
        wait_until(
            || executor
                .reporter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_some(),
            Duration::from_secs(5)
        ),
        "the session must attach its reporter"
    );
    let reporter = executor
        .reporter
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .expect("reporter checked present");
    reporter
        .log(AttemptId::new(), &log_frame(1))
        .expect("control fallback accepts a log frame");
    assert!(
        wait_until(
            || executor.acked.load(Ordering::Acquire) == 1,
            Duration::from_secs(5)
        ),
        "the acknowledged log must come back over control"
    );
    assert_eq!(executor.refused.load(Ordering::Acquire), 0);
    assert!(handler.logs.load(Ordering::Acquire) == 1);

    stop.store(true, Ordering::Release);
    closer.close();
    let _ = runner.join();
    let _ = controller.join();
}

#[test]
fn host_id_is_stable_for_one_host() {
    let first = session::host_id();
    let second = session::host_id();
    assert_eq!(first, second);
}

#[test]
fn session_error_is_printable() {
    let error: Error = Error::Protocol("priority");
    assert!(format!("{error}").contains("priority"));
}

#[test]
fn a_failing_bulk_redial_never_delays_the_control_teardown() {
    let (listener, server, client) = deployment();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(Counting::default());
    let dials = Arc::new(AtomicU64::new(0));
    let (control_tx, control_rx) = std::sync::mpsc::channel();
    let controller = {
        let handler = Arc::clone(&handler);
        let dials = Arc::clone(&dials);
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let Accepted::Control(mut control) =
                session::accept(socket, server.clone(), &AnyAdmission).unwrap()
            else {
                panic!("control hello expected");
            };
            control_tx.send(control.sender()).unwrap();
            thread::spawn(move || {
                let _ = control.serve(&*handler);
            });
            let (socket, _) = listener.accept().unwrap();
            let first = session::accept(socket, server, &AnyAdmission).unwrap();
            dials.fetch_add(1, Ordering::AcqRel);
            drop(first);
            for socket in listener.incoming() {
                let Ok(socket) = socket else { return };
                dials.fetch_add(1, Ordering::AcqRel);
                drop(socket);
            }
        })
    };

    let worker_id = WorkerId::new();
    let config = sentinel_link::worker::Config {
        controller: addr,
        server: sentinel_auth::secret::Digest([0; 32]),
        also_pinned: Vec::new(),
        worker: worker_id,
        name: "bulk-backoff".into(),
        hello: hello(),
        capacity: capacity(),
        profile: Profile::default(),
        transport: Default::default(),
        remote_cache: false,
    };
    let executor = Arc::new(TestExecutor::default());
    let handle = Arc::new(sentinel_link::worker::Handle::new());
    let worker = {
        let executor = Arc::clone(&executor);
        let handle = Arc::clone(&handle);
        thread::spawn(move || {
            let welcomed = AtomicBool::new(false);
            let outcome = sentinel_link::worker::session(
                &config,
                client,
                None,
                &*executor,
                &handle,
                &welcomed,
                &|_| {},
            );
            (outcome, Instant::now())
        })
    };
    let control = control_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        wait_until(
            || dials.load(Ordering::Acquire) >= 3,
            Duration::from_secs(15)
        ),
        "the bulk connection must be redialled after it drops"
    );
    thread::sleep(Duration::from_millis(300));
    let closed = Instant::now();
    control.close();
    let (outcome, returned) = worker.join().unwrap();
    assert!(outcome.is_err(), "a lost control session is an error");
    let teardown = returned.duration_since(closed);
    assert!(
        teardown < Duration::from_millis(1_500),
        "the session returned {teardown:?} after the control connection closed"
    );
    handle.stop();
    let _ = std::net::TcpStream::connect(addr);
    drop(controller);
}
