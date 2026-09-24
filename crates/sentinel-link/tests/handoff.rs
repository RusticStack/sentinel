//! The controller's hand-off close (`Sender::close_notify`), as a worker
//! sees it: the session ends at once with [`Error::Closed`] rather than at
//! the heartbeat deadline, and the reconnect waits only the shortest
//! back-off however often it happens, where a lost session doubles it.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{AttemptId, Event, Fence, PoolId, UnixMillis, WorkerId};
use sentinel_link::{
    Error,
    identity::Identity,
    session::{
        self, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict, Offer,
        Rejection, Reporter, SessionHandler,
    },
    tls, worker,
};
use sentinel_protocol::{
    logs::Frame,
    negotiate::{Arch, Capabilities, Hello, ProtocolVersion},
};

struct Welcoming;

impl Admission for Welcoming {
    fn admit(
        &self,
        _: &Digest,
        worker: WorkerId,
        _: &str,
        hello: &Hello,
        _: Option<&Secret>,
        _: Capacity,
    ) -> Result<Admitted, Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated,
        })
    }
}

impl SessionHandler for Welcoming {
    fn ping(&self, _: WorkerId, _: &[AttemptId]) -> sentinel_link::Result<Beat> {
        Ok(Beat {
            lease_until: UnixMillis(i64::MAX / 2),
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
    fn log(&self, _: WorkerId, _: AttemptId, _: Frame) -> LogVerdict {
        LogVerdict::Refused
    }
    fn log_end(&self, _: WorkerId, _: AttemptId, _: u64, _: &[(u64, u64)]) -> LogVerdict {
        LogVerdict::Refused
    }
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

struct Idle;

impl Executor for Idle {
    fn offered(&self, _: &Offer) -> bool {
        false
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, _: Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

/// Sessions the controller closes, one after another.
const CLOSES: usize = 4;

#[test]
fn a_clean_close_ends_the_session_at_once_and_redials_on_the_shortest_back_off() {
    let identity = Identity::generate("controller").unwrap();
    let fingerprint = identity.fingerprint();
    let config = tls::server_config(identity).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    // Each session is welcomed, closed cleanly 50 ms later, and served
    // until the worker's side is gone too.
    let controller = thread::spawn(move || {
        let mut welcomed = Vec::new();
        loop {
            let (socket, _) = listener.accept().unwrap();
            let session::Accepted::Control(mut session) =
                session::accept(socket, Arc::clone(&config), &Welcoming).unwrap()
            else {
                panic!("a control hello");
            };
            welcomed.push(Instant::now());
            if welcomed.len() > CLOSES {
                // Held open until the worker stops, so the worker's last
                // session ends by its own stop, not by a dropped socket.
                break (welcomed, session);
            }
            let sender = session.sender();
            thread::sleep(Duration::from_millis(50));
            let closed = Instant::now();
            sender.close_notify();
            // The worker's close answers ours: the session ends then, well
            // before any heartbeat deadline.
            let _ = session.serve(&Welcoming);
            assert!(
                closed.elapsed() < Duration::from_secs(2),
                "{:?}",
                closed.elapsed()
            );
        }
    });

    let events = Mutex::new(Vec::new());
    let handle = worker::Handle::new();
    let settings = worker::Config {
        controller: addr,
        server: fingerprint,
        worker: WorkerId::new(),
        name: "w".into(),
        hello: Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: ProtocolVersion(1),
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "test".into(),
        },
        capacity: Capacity {
            cpu_millis: 1000,
            memory_bytes: 1 << 30,
        },
        profile: Default::default(),
        transport: Default::default(),
        remote_cache: false,
    };
    thread::scope(|scope| {
        scope.spawn(|| {
            let _ = worker::run(
                settings,
                Identity::generate("worker").unwrap(),
                None,
                &Idle,
                &handle,
                &|event| {
                    if let worker::Event::Disconnected(error) = event {
                        events.lock().unwrap().push(error.to_string());
                        assert!(matches!(error, Error::Closed), "{error}");
                    }
                },
            );
        });
        let (welcomed, last) = controller.join().unwrap();
        handle.stop();
        drop(last);
        // Doubling would have made the third wait at least 3 s (4 s less its
        // jitter); every wait here is the first back-off, at most 1.25 s,
        // plus a local handshake.
        for pair in welcomed.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap < Duration::from_millis(1_600),
                "redialled after {gap:?}"
            );
        }
    });
    assert_eq!(events.lock().unwrap().len(), CLOSES);
}

/// Connections the controller closes while they are still in their TLS
/// handshake, one after another.
const HANDSHAKE_CLOSES: usize = 3;

/// A hand-off also meets connections that are not sessions yet. Each one
/// here is held in its TLS handshake by a slow link (the controller's
/// flight reaches the worker, the worker's answer never reaches the
/// controller) until the hand-off claims it. The worker must read the claim
/// as the controller's clean close at once, not wait out its own 15 s
/// deadline for the welcome, and redial on its shortest back-off every
/// time, although it was never welcomed.
#[test]
fn a_connection_closed_in_its_handshake_ends_at_once_and_redials_on_the_shortest_back_off() {
    let identity = Identity::generate("controller").unwrap();
    let fingerprint = identity.fingerprint();
    let config = tls::server_config(identity).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let (stalled, stalls) = mpsc::channel::<()>();
    let slow = slow_link(addr, HANDSHAKE_CLOSES, stalled);

    let controller = thread::spawn(move || {
        let mut claimed = Vec::new();
        let mut arrived = Vec::new();
        for _ in 0..HANDSHAKE_CLOSES {
            let (socket, _) = listener.accept().unwrap();
            arrived.push(Instant::now());
            let arrival = session::Arrival::default();
            let outcome = thread::scope(|scope| {
                let (arrival, config) = (&arrival, &config);
                let accepting = scope.spawn(move || {
                    session::accept_arriving(
                        socket,
                        Arc::clone(config),
                        &Welcoming,
                        Duration::from_secs(10),
                        arrival,
                        Duration::from_millis(600),
                    )
                });
                stalls.recv().unwrap();
                assert!(
                    arrival.hand_off(),
                    "a connection in its handshake is claimable"
                );
                claimed.push(Instant::now());
                accepting.join().unwrap()
            });
            assert!(matches!(outcome, Err(Error::Closed)), "{:?}", outcome.err());
            // The worker's end answered the close within the bound.
            assert_eq!(arrival.answered(), Some(true));
        }
        let (socket, _) = listener.accept().unwrap();
        arrived.push(Instant::now());
        let session::Accepted::Control(session) =
            session::accept(socket, Arc::clone(&config), &Welcoming).unwrap()
        else {
            panic!("a control hello");
        };
        (claimed, arrived, session)
    });

    let events = Mutex::new(Vec::new());
    let handle = worker::Handle::new();
    let settings = worker::Config {
        controller: slow,
        server: fingerprint,
        worker: WorkerId::new(),
        name: "w".into(),
        hello: Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: ProtocolVersion(1),
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "test".into(),
        },
        capacity: Capacity {
            cpu_millis: 1000,
            memory_bytes: 1 << 30,
        },
        profile: Default::default(),
        transport: Default::default(),
        remote_cache: false,
    };
    thread::scope(|scope| {
        scope.spawn(|| {
            let _ = worker::run(
                settings,
                Identity::generate("worker").unwrap(),
                None,
                &Idle,
                &handle,
                &|event| match event {
                    worker::Event::Disconnected(error) => {
                        events
                            .lock()
                            .unwrap()
                            .push((Instant::now(), error.to_string()));
                        assert!(matches!(error, Error::Closed), "{error}");
                    }
                    worker::Event::Connected { .. } => handle.stop(),
                    worker::Event::Backoff(_) => {}
                },
            );
        });
        let (claimed, arrived, last) = controller.join().unwrap();
        // The worker stops once welcomed; its last session is held till then.
        drop(last);
        let events = events.lock().unwrap();
        assert_eq!(events.len(), HANDSHAKE_CLOSES, "{events:?}");
        for (index, at) in claimed.iter().enumerate() {
            let seen = events[index].0 - *at;
            assert!(
                seen < Duration::from_millis(500),
                "saw the close after {seen:?}"
            );
            // Doubling would have made the third wait at least 3 s: every
            // wait here is the first back-off, at most 1.25 s.
            let redial = arrived[index + 1] - *at;
            assert!(
                redial < Duration::from_millis(1_600),
                "redialled after {redial:?}"
            );
        }
    });
}

/// A slow link to `upstream`: bytes and ends pass both ways, except that on
/// each of the first `stalls` connections the client's bytes stop getting
/// through once the server's first bytes (its TLS flight) came back, which
/// `stalled` announces. The server is then held in its handshake.
fn slow_link(upstream: SocketAddr, stalls: usize, stalled: mpsc::Sender<()>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = listener.local_addr().unwrap();
    thread::spawn(move || {
        for (index, client) in listener.incoming().enumerate() {
            let Ok(client) = client else { continue };
            let server = TcpStream::connect(upstream).unwrap();
            let held = Arc::new(AtomicBool::new(false));
            let stall = index < stalls;
            let client_rx = client.try_clone().unwrap();
            let server_tx = server.try_clone().unwrap();
            let gate = Arc::clone(&held);
            thread::spawn(move || pump(client_rx, server_tx, || !gate.load(Ordering::Acquire)));
            let stalled = stalled.clone();
            thread::spawn(move || {
                pump(server, client, || {
                    if stall && !held.swap(true, Ordering::AcqRel) {
                        let _ = stalled.send(());
                    }
                    true
                })
            });
        }
    });
    local
}

/// Copy `from` to `to` until `from` ends, passing a FIN on as a FIN and an
/// error as a reset; `pass` decides per read whether bytes are delivered.
fn pump(mut from: TcpStream, mut to: TcpStream, mut pass: impl FnMut() -> bool) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if pass() && to.write_all(&buf[..n]).is_err() {
                    let _ = from.shutdown(Shutdown::Both);
                    return;
                }
            }
            Err(_) => {
                let _ = to.shutdown(Shutdown::Both);
                let _ = from.shutdown(Shutdown::Both);
                return;
            }
        }
    }
}
