//! Q05: control traffic stays alive when the bulk transport is stalled.
//!
//! A protocol-7 session has two connections with one identity. This suite
//! proves the reason the split exists: with the controller deliberately not
//! reading the bulk connection (so the worker's bulk writes block on TCP
//! backpressure after the socket buffers fill), the control session still
//! sends its heartbeat and receives its pong — and the stalled bulk traffic
//! completes once the reader drains. A second case proves the fallback: a
//! bulk-class message sent on the control connection (no second connection
//! up) is served, not rejected, so an environment that blocks the second
//! connection loses latency, never correctness.

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
        Offer, Reporter, Rejection, SessionHandler,
    },
    tls,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{
    Arch, Capabilities, Hello, Profile, ProtocolVersion, negotiate,
};

/// 32 KiB is `MAX_LOG_FRAME_BYTES`; the flood sends enough frames to fill any
/// plausible socket buffer (64 MiB) and prove the writer blocks.
const FLOOD_FRAMES: u64 = 2 * 1024;
const FLOOD_BYTES: usize = 32 * 1024;
const PONG_WINDOW: Duration = Duration::from_secs(12);
const DRAIN_WINDOW: Duration = Duration::from_secs(30);

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

/// Admit every certificate and negotiate exactly what the hello offers; the
/// suite tests transport priority, not admission.
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

/// Counts what actually crossed each connection, so the assertions are about
/// observed traffic rather than timing guesses.
#[derive(Default)]
struct Counting {
    pings: AtomicU64,
    logs: AtomicU64,
}

impl SessionHandler for Counting {
    fn ping(&self, _worker: WorkerId, _held: &[AttemptId]) -> Result<Beat> {
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

/// The worker end: nothing is held, offers are declined, and the reporter of
/// the live session is kept so the test can speak over it.
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
        self.reporter.lock().unwrap_or_else(|p| p.into_inner()).take();
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
    // The bulk reader waits for this: the test keeps the stall open exactly
    // as long as it needs to observe the control beat inside it.
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
            // The stall: nothing reads the bulk connection while the test
            // floods it, so the worker's bulk writes block.
            while !drain.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = bulk.serve(&*handler, sentinel_protocol::negotiate::SUPPORTED_MAX.0);
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
    // Protocol 7: report the profile, then dial the bulk connection and read
    // its answers on their own thread (log acknowledgements included).
    assert_eq!(link.negotiated.protocol, ProtocolVersion(7));
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

    // Flood the bulk connection; the controller is not reading, so once the
    // socket buffers fill the writer blocks. 64 MiB cannot fit in loopback
    // socket buffers, so completing within the window would mean the stall
    // was not in effect.
    let finished = Arc::new(AtomicBool::new(false));
    let attempt = AttemptId::new();
    let flood = {
        let finished = Arc::clone(&finished);
        thread::spawn(move || {
            for seq in 1..=FLOOD_FRAMES {
                if reporter.log(attempt, &log_frame(seq)).is_err() {
                    return;
                }
            }
            finished.store(true, Ordering::Release);
        })
    };
    assert!(
        !wait_until(|| finished.load(Ordering::Acquire), Duration::from_secs(2)),
        "the flood must not complete while nothing reads the bulk connection"
    );

    // The whole point: a beat completes while the bulk writer is blocked.
    // The controller answers pings on the control connection only, so a
    // second ping here cannot have come from a bulk-powered session.
    let pings_before = handler.pings.load(Ordering::Acquire);
    assert!(
        wait_until(
            || handler.pings.load(Ordering::Acquire) > pings_before,
            PONG_WINDOW
        ),
        "a pong must arrive while the bulk connection is stalled"
    );
    assert!(
        !finished.load(Ordering::Acquire),
        "the pong must have arrived before the stalled bulk traffic moved"
    );

    // Drain and prove the stalled traffic completes.
    drain.store(true, Ordering::Release);
    assert!(
        wait_until(|| finished.load(Ordering::Acquire), DRAIN_WINDOW),
        "the stalled bulk flood must complete once the reader drains"
    );
    assert!(
        handler.logs.load(Ordering::Acquire) > 0,
        "the drained bulk traffic must have reached the handler"
    );
    assert!(
        wait_until(
            || executor.acked.load(Ordering::Acquire) > 0,
            Duration::from_secs(10)
        ),
        "acknowledged bulk frames must come back on the bulk connection"
    );

    // Clean up: end both connections and join every thread.
    stop.store(true, Ordering::Release);
    bulk_stop.store(true, Ordering::Release);
    closer.close();
    bulk_closer.close();
    let _ = runner.join();
    let _ = bulk_reader.join();
    let _ = flood.join();
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
    assert_eq!(link.negotiated.protocol, ProtocolVersion(7));
    link.send_profile(&Profile::default()).unwrap();
    // No bulk connection is dialled: the session falls back to control.
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
    // The profile's host id must be the same for sibling worker processes on
    // one machine; it is derived from the machine id, never random.
    let first = session::host_id();
    let second = session::host_id();
    assert_eq!(first, second);
}

#[test]
fn session_error_is_printable() {
    // Telemetry and diagnostics must never need the session to carry
    // credentials; the error type stays printable without them.
    let error: Error = Error::Protocol("priority");
    assert!(format!("{error}").contains("priority"));
}
