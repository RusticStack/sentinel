//! The controller's hand-off close (`Sender::close_notify`), as a worker
//! sees it: the session ends at once with [`Error::Closed`] rather than at
//! the heartbeat deadline, and the reconnect waits only the shortest
//! back-off however often it happens, where a lost session doubles it.

use std::{
    sync::{Arc, Mutex},
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
