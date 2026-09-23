//! Part 04 audit hardening of the link: a retryable refusal is retried, a
//! reconnect renegotiates and is recorded, a welcome outside the hello's
//! range is refused, a transient log fault is never a permanent refusal,
//! an idle bulk connection lives as long as its session, and peers that
//! never finish a handshake cannot hold the session slots.

use std::{
    io::Write,
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, Fence, PoolId, RepoId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    Error,
    controller::Controller,
    identity::Identity,
    session::{
        self, Accepted, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict,
        Offer, Rejection, Reporter, SessionHandler,
    },
    tls, worker,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{
    Arch, Capabilities, Hello, Negotiated, Profile, ProtocolVersion, negotiate,
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch,
    logs::LogStore,
    tenancy::{self, PoolKind},
    workers,
};

fn hello(max: u16) -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(max),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "hardening".into(),
    }
}

fn capacity() -> Capacity {
    Capacity {
        cpu_millis: 4_000,
        memory_bytes: 8 << 30,
    }
}

fn eventually(what: &str, within: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// A handler that accepts everything and answers log frames with a
/// scripted verdict sequence.
#[derive(Default)]
struct Scripted {
    verdicts: Mutex<Vec<LogVerdict>>,
    logs: AtomicU64,
}

impl SessionHandler for Scripted {
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
    fn log(&self, _: WorkerId, _: AttemptId, frame: Frame) -> LogVerdict {
        self.logs.fetch_add(1, Ordering::SeqCst);
        let mut script = self.verdicts.lock().unwrap();
        if script.is_empty() {
            LogVerdict::Acked(frame.seq)
        } else {
            script.remove(0)
        }
    }
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

/// Admits with a scripted list of answers, then negotiates normally.
struct ScriptedAdmission {
    answers: Mutex<Vec<Result<Option<Negotiated>, Rejection>>>,
    asked: AtomicUsize,
}

impl Admission for ScriptedAdmission {
    fn admit(
        &self,
        _: &sentinel_auth::secret::Digest,
        worker: WorkerId,
        _: &str,
        hello: &Hello,
        _: Option<&Secret>,
        _: Capacity,
    ) -> Result<Admitted, Rejection> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let next = {
            let mut answers = self.answers.lock().unwrap();
            if answers.is_empty() {
                Ok(None)
            } else {
                answers.remove(0)
            }
        };
        let negotiated = match next? {
            Some(forced) => forced,
            None => negotiate(hello).map_err(Rejection::from)?,
        };
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated,
        })
    }
}

#[derive(Default)]
struct Quiet {
    reporter: Mutex<Option<Reporter>>,
    refused: AtomicU64,
}

impl Executor for Quiet {
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
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, _: AttemptId, _: JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {
        self.refused.fetch_add(1, Ordering::SeqCst);
    }
}

/// A controller stand-in: accepts connections under `admission`, serves
/// control sessions with `handler` and bulk connections for as long as
/// `alive` holds.
fn stand_in(
    admission: Arc<ScriptedAdmission>,
    handler: Arc<Scripted>,
    alive: Arc<AtomicBool>,
) -> (
    std::net::SocketAddr,
    sentinel_auth::secret::Digest,
    Arc<AtomicUsize>,
) {
    let identity = Identity::generate("stand-in").unwrap();
    let fingerprint = identity.fingerprint();
    let server = tls::server_config(identity).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let bulk_ended = Arc::new(AtomicUsize::new(0));
    let ended = Arc::clone(&bulk_ended);
    thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { continue };
            let (server, admission, handler, alive, ended) = (
                Arc::clone(&server),
                Arc::clone(&admission),
                Arc::clone(&handler),
                Arc::clone(&alive),
                Arc::clone(&ended),
            );
            thread::spawn(move || match session::accept(socket, server, &*admission) {
                Ok(Accepted::Control(mut control)) => {
                    let _ = control.serve(&*handler);
                    control.sender().close();
                }
                Ok(Accepted::Bulk(mut bulk)) => {
                    let _ = bulk.serve(&*handler, 7, &|| alive.load(Ordering::SeqCst));
                    ended.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {}
            });
        }
    });
    (addr, fingerprint, bulk_ended)
}

/// P04-1: `Unavailable` is the controller's "try again later". The worker
/// backs off and retries it; it does not stop for good.
#[test]
fn an_unavailable_refusal_is_retried_and_the_worker_connects() {
    let admission = Arc::new(ScriptedAdmission {
        answers: Mutex::new(vec![
            Err(Rejection::Unavailable),
            Err(Rejection::Unavailable),
        ]),
        asked: AtomicUsize::new(0),
    });
    let (addr, fingerprint, _) = stand_in(
        Arc::clone(&admission),
        Arc::new(Scripted::default()),
        Arc::new(AtomicBool::new(true)),
    );
    let handle = Arc::new(worker::Handle::new());
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let (grip, log) = (Arc::clone(&handle), Arc::clone(&events));
    let config = worker::Config {
        controller: addr,
        server: fingerprint,
        worker: WorkerId::new(),
        name: "retrying".into(),
        hello: hello(6),
        capacity: capacity(),
        profile: Profile::default(),
        transport: session::TransportStats::default(),
        remote_cache: false,
    };
    let running = thread::spawn(move || {
        worker::run(
            config,
            Identity::generate("worker").unwrap(),
            None,
            &Quiet::default(),
            &grip,
            &|event| log.lock().unwrap().push(format!("{event:?}")),
        )
    });
    eventually(
        "a session after two refusals",
        Duration::from_secs(20),
        || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("Connected"))
        },
    );
    assert_eq!(admission.asked.load(Ordering::SeqCst), 3);
    let seen = events.lock().unwrap().clone();
    assert_eq!(
        seen.iter().filter(|e| e.contains("Unavailable")).count(),
        2,
        "{seen:?}"
    );
    assert_eq!(seen.iter().filter(|e| e.starts_with("Backoff")).count(), 2);
    handle.stop();
    assert!(running.join().unwrap().is_ok());

    // Any other rejection is still final: the loop returns it.
    let admission = Arc::new(ScriptedAdmission {
        answers: Mutex::new(vec![Err(Rejection::NotEnrolled)]),
        asked: AtomicUsize::new(0),
    });
    let (addr, fingerprint, _) = stand_in(
        admission,
        Arc::new(Scripted::default()),
        Arc::new(AtomicBool::new(true)),
    );
    let outcome = worker::run(
        worker::Config {
            controller: addr,
            server: fingerprint,
            worker: WorkerId::new(),
            name: "final".into(),
            hello: hello(6),
            capacity: capacity(),
            profile: Profile::default(),
            transport: session::TransportStats::default(),
            remote_cache: false,
        },
        Identity::generate("worker").unwrap(),
        None,
        &Quiet::default(),
        &worker::Handle::new(),
        &|_| {},
    );
    assert!(matches!(
        outcome,
        Err(Error::Rejected(Rejection::NotEnrolled))
    ));
}

/// P04-2: a welcome at a version the hello did not offer is refused by the
/// worker instead of failing on its first frame.
#[test]
fn a_welcome_outside_the_hellos_range_is_refused() {
    let forced = Negotiated {
        protocol: ProtocolVersion(7),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
    };
    let (addr, fingerprint, _) = stand_in(
        Arc::new(ScriptedAdmission {
            answers: Mutex::new(vec![Ok(Some(forced))]),
            asked: AtomicUsize::new(0),
        }),
        Arc::new(Scripted::default()),
        Arc::new(AtomicBool::new(true)),
    );
    let refused = session::connect(
        addr,
        tls::client_config(Identity::generate("w").unwrap(), fingerprint).unwrap(),
        WorkerId::new(),
        "w",
        hello(6),
        None,
        capacity(),
    )
    .unwrap_err();
    assert!(matches!(refused, Error::Protocol(_)), "{refused}");
}

/// P04-11: a transient controller fault on a log frame closes the
/// connection so the worker resends; it is never answered `LogRefused`,
/// which would end the attempt's log for good.
#[test]
fn a_transient_log_fault_closes_the_connection_instead_of_refusing() {
    let handler = Arc::new(Scripted {
        verdicts: Mutex::new(vec![LogVerdict::Retry]),
        logs: AtomicU64::new(0),
    });
    let (addr, fingerprint, _) = stand_in(
        Arc::new(ScriptedAdmission {
            answers: Mutex::new(Vec::new()),
            asked: AtomicUsize::new(0),
        }),
        Arc::clone(&handler),
        Arc::new(AtomicBool::new(true)),
    );
    let client = tls::client_config(Identity::generate("w").unwrap(), fingerprint).unwrap();
    let mut link = session::connect(
        addr,
        Arc::clone(&client),
        WorkerId::new(),
        "w",
        hello(6),
        None,
        capacity(),
    )
    .unwrap();
    let executor = Quiet::default();
    let attempt = AttemptId::new();
    let outcome = thread::scope(|scope| {
        let running = scope.spawn(|| link.run(&executor, || false));
        eventually("the session's reporter", Duration::from_secs(5), || {
            executor.reporter.lock().unwrap().is_some()
        });
        let reporter = executor.reporter.lock().unwrap().clone().unwrap();
        reporter
            .log(
                attempt,
                &Frame {
                    seq: 1,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes: b"hello\n".to_vec(),
                },
            )
            .unwrap();
        running.join().unwrap()
    });
    assert!(outcome.is_err(), "the connection must close");
    assert_eq!(executor.refused.load(Ordering::SeqCst), 0);
    assert_eq!(handler.logs.load(Ordering::SeqCst), 1);
}

/// P04-13: bulk has no heartbeat of its own; while its control session is
/// alive an idle bulk connection is kept past the heartbeat deadline, and
/// it ends once the control session does.
#[test]
fn an_idle_bulk_connection_lives_as_long_as_its_session() {
    let alive = Arc::new(AtomicBool::new(true));
    let (addr, fingerprint, bulk_ended) = stand_in(
        Arc::new(ScriptedAdmission {
            answers: Mutex::new(Vec::new()),
            asked: AtomicUsize::new(0),
        }),
        Arc::new(Scripted::default()),
        Arc::clone(&alive),
    );
    let client = tls::client_config(Identity::generate("w").unwrap(), fingerprint).unwrap();
    let link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "w",
        hello(7),
        None,
        capacity(),
    )
    .unwrap();
    let bulk = link.bulk_dialer().unwrap().open().unwrap();
    // Idle past the heartbeat deadline: still attached.
    thread::sleep(session::HEARTBEAT_DEADLINE + Duration::from_secs(2));
    assert_eq!(bulk_ended.load(Ordering::SeqCst), 0);
    // The session goes: so does the bulk connection, within one deadline.
    alive.store(false, Ordering::SeqCst);
    eventually(
        "the bulk connection to end",
        session::HEARTBEAT_DEADLINE * 2 + Duration::from_secs(2),
        || bulk_ended.load(Ordering::SeqCst) == 1,
    );
    drop((link, bulk));
}

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    pool: PoolId,
    controller: Controller,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )?;
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis(1),
            )
        })
        .unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        logs,
        objects,
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Deployment {
        _dir: dir,
        store,
        pool,
        controller,
    }
}

impl Deployment {
    fn enrollment(&self) -> Secret {
        let pool = self.pool;
        self.store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
            })
            .unwrap()
            .secret
    }

    fn connect(
        &self,
        identity: Identity,
        worker: WorkerId,
        enrollment: Option<&Secret>,
        max: u16,
    ) -> Result<session::Link, Error> {
        session::connect(
            self.controller.local_addr(),
            tls::client_config(identity, self.controller.fingerprint()).unwrap(),
            worker,
            "w",
            hello(max),
            enrollment,
            capacity(),
        )
    }
}

/// P04-2: every hello renegotiates. A worker enrolled at protocol 6 that
/// reconnects offering 7 is welcomed at 7 and records it (so its profile —
/// and with it its disk — reaches placement); rolled back to 5 it is
/// welcomed at 5, never at a version it cannot speak.
#[test]
fn a_reconnecting_worker_is_renegotiated_and_recorded() {
    let d = deployment();
    let (worker, identity) = (WorkerId::new(), Identity::generate("w").unwrap());
    let (cert, key) = (d._dir.path().join("w.crt"), d._dir.path().join("w.key"));
    identity.save(&cert, &key).unwrap();
    let load = || Identity::load(&cert, &key).unwrap();
    let secret = d.enrollment();
    let stored = |d: &Deployment| {
        d.store
            .read(|c| workers::authenticate(c, &load().fingerprint()))
            .unwrap()
            .negotiated
            .protocol
    };
    let link = d.connect(load(), worker, Some(&secret), 6).unwrap();
    assert_eq!(link.negotiated.protocol, ProtocolVersion(6));
    drop(link);

    let mut link = d.connect(load(), worker, None, 7).unwrap();
    assert_eq!(link.negotiated.protocol, ProtocolVersion(7));
    assert_eq!(stored(&d), ProtocolVersion(7));
    link.send_profile(&Profile {
        disk_bytes: 64 << 30,
        ..Profile::default()
    })
    .unwrap();
    let executor = Quiet::default();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let running = scope.spawn(|| link.run(&executor, || stop.load(Ordering::SeqCst)));
        eventually("the profile's disk", Duration::from_secs(10), || {
            d.store
                .read(|c| dispatch::free_capacity(c, worker))
                .is_ok_and(|free| free.disk_bytes == 64 << 30)
        });
        stop.store(true, Ordering::SeqCst);
        let _ = running.join();
    });

    let link = d.connect(load(), worker, None, 5).unwrap();
    assert_eq!(link.negotiated.protocol, ProtocolVersion(5));
    assert_eq!(stored(&d), ProtocolVersion(5));
}

/// P04-9: connections that never finish their handshake hold a slot of the
/// small pre-admission cap for at most the handshake deadline — a byte
/// dripped now and then does not extend it — and an enrolled worker gets
/// in once they are cut.
#[test]
fn stalled_handshakes_are_cut_at_their_deadline_and_cannot_lock_workers_out() {
    let d = deployment();
    d.controller
        .set_admission_limits(2, Duration::from_millis(500));
    let secret = d.enrollment();
    let addr = d.controller.local_addr();
    let idle = TcpStream::connect(addr).unwrap();
    let mut drip = TcpStream::connect(addr).unwrap();
    let dripping = thread::spawn(move || {
        let started = Instant::now();
        // One byte every 150 ms: each read wait is well inside any per-read
        // timeout, so only an absolute deadline ends this connection.
        while drip.write_all(&[0x16]).is_ok() && started.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(150));
        }
        started.elapsed()
    });
    thread::sleep(Duration::from_millis(100));
    // Both pre-admission slots are taken: a new connection is shed.
    assert!(
        d.connect(
            Identity::generate("w").unwrap(),
            WorkerId::new(),
            Some(&secret),
            6
        )
        .is_err()
    );
    assert!(d.controller.stats().shed.load(Ordering::SeqCst) >= 1);
    // Cut at the deadline (at most twice it, by construction), after which
    // an enrolled worker is admitted.
    let cut = dripping.join().unwrap();
    assert!(cut < Duration::from_secs(3), "drip survived {cut:?}");
    drop(idle);
    eventually("a worker admitted", Duration::from_secs(5), || {
        d.connect(
            Identity::generate("w").unwrap(),
            WorkerId::new(),
            Some(&secret),
            6,
        )
        .is_ok()
    });
}
