//! W01 end to end over real TLS on loopback: a worker generates its identity,
//! redeems a one-time enrollment on its first session, heartbeats, is
//! revoked, and is refused thereafter. Wrong server fingerprints, unknown
//! certificates, spent enrollments and unsupported protocol versions are each
//! refused at the point the design says they should be.

use std::{
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{PoolId, TenantId, UnixMillis, UserId, WorkerId};
use sentinel_link::{
    Error,
    identity::Identity,
    session::{self, Admission, Rejection},
    tls,
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    tenancy::{self, PoolKind},
    workers,
};

/// The controller's admission policy, backed by the real store.
struct StoreAdmission {
    store: Arc<Store>,
    beats: AtomicUsize,
}

impl Admission for StoreAdmission {
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
    ) -> Result<(WorkerId, Negotiated), Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        if let Ok(known) = self.store.read(|c| workers::authenticate(c, fingerprint)) {
            return Ok((known.id, known.negotiated));
        }
        let Some(secret) = enrollment else {
            return Err(Rejection::NotEnrolled);
        };
        let (secret, fingerprint, name) = (
            Secret::parse(&{
                let mut t = String::new();
                secret.expose(&mut t);
                t
            })
            .unwrap(),
            *fingerprint,
            name.to_owned(),
        );
        self.store
            .writer()
            .write(move |tx| {
                workers::enroll(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint,
                        name: &name,
                        negotiated,
                    },
                    UnixMillis::now(),
                )
            })
            .map(|w| (w.id, w.negotiated))
            .map_err(|e| match e {
                sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_) => {
                    Rejection::Identity
                }
                _ => Rejection::Enrollment,
            })
    }

    fn seen(&self, worker: WorkerId) {
        self.beats.fetch_add(1, Ordering::SeqCst);
        let _ = self
            .store
            .writer()
            .write(move |tx| workers::seen(tx, worker, UnixMillis::now()));
    }
}

struct Controller {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    admission: Arc<StoreAdmission>,
    addr: SocketAddr,
    fingerprint: Digest,
    pool: PoolId,
    outcomes: Arc<Mutex<Vec<Result<(), String>>>>,
    stop: Arc<AtomicBool>,
}

fn controller() -> Controller {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let root = UserId::new();
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            let tenant = TenantId::new();
            auth::create_namespace(
                tx,
                sentinel_core::auth::Principal::new(
                    root,
                    sentinel_core::auth::Permissions::ALL,
                    None,
                    None,
                ),
                tenant,
                sentinel_core::auth::Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )?;
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
    let identity = Identity::generate("controller").unwrap();
    let fingerprint = identity.fingerprint();
    let config = tls::server_config(identity).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let admission = Arc::new(StoreAdmission {
        store: Arc::clone(&store),
        beats: AtomicUsize::new(0),
    });
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (admission, outcomes, stop) = (
            Arc::clone(&admission),
            Arc::clone(&outcomes),
            Arc::clone(&stop),
        );
        thread::spawn(move || {
            for socket in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(socket) = socket else { break };
                let (config, admission, outcomes) = (
                    Arc::clone(&config),
                    Arc::clone(&admission),
                    Arc::clone(&outcomes),
                );
                thread::spawn(move || {
                    let outcome = session::accept(socket, config, &*admission)
                        .and_then(|mut s| s.serve(&*admission))
                        .map_err(|e| e.to_string());
                    outcomes.lock().unwrap().push(outcome);
                });
            }
        });
    }
    Controller {
        _dir: dir,
        store,
        admission,
        addr,
        fingerprint,
        pool,
        outcomes,
        stop,
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(1),
        capabilities: Capabilities::REQUIRED.union(Capabilities::REFLINK),
        arch: Arch::X86_64,
        software: "test".into(),
    }
}

fn enrollment(c: &Controller, lifetime_ms: i64) -> Secret {
    let pool = c.pool;
    c.store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(
                tx,
                Authority::HostLocal,
                pool,
                lifetime_ms,
                UnixMillis::now(),
            )
        })
        .unwrap()
        .secret
}

fn connect(
    c: &Controller,
    identity: Identity,
    worker: WorkerId,
    enrollment: Option<&Secret>,
) -> Result<session::Link, Error> {
    let config = tls::client_config(identity, c.fingerprint).unwrap();
    session::connect(c.addr, config, worker, "worker-1", hello(), enrollment)
}

#[test]
fn a_worker_enrolls_once_heartbeats_reconnects_and_is_refused_after_revocation() {
    let c = controller();
    let secret = enrollment(&c, 60_000);
    let (worker, identity) = (WorkerId::new(), Identity::generate("worker-1").unwrap());
    let (cert, key) = {
        let dir = c._dir.path();
        (dir.join("w.crt"), dir.join("w.key"))
    };
    identity.save(&cert, &key).unwrap();

    // Without the enrollment, an unknown certificate is refused.
    let refused = connect(&c, Identity::load(&cert, &key).unwrap(), worker, None).unwrap_err();
    assert!(
        matches!(refused, Error::Rejected(Rejection::NotEnrolled)),
        "{refused}"
    );

    // With it: welcomed, negotiated, and the beats are recorded.
    let mut link = connect(
        &c,
        Identity::load(&cert, &key).unwrap(),
        worker,
        Some(&secret),
    )
    .unwrap();
    assert_eq!(link.worker, worker);
    assert_eq!(link.negotiated.protocol, ProtocolVersion(1));
    assert!(
        link.negotiated
            .capabilities
            .contains(Capabilities::REQUIRED)
    );
    for _ in 0..3 {
        link.beat().unwrap();
    }
    assert_eq!(c.admission.beats.load(Ordering::SeqCst), 3);
    let stored = c
        .store
        .read(|conn| {
            workers::authenticate(conn, &Identity::load(&cert, &key).unwrap().fingerprint())
        })
        .unwrap();
    assert_eq!(stored.pool, c.pool);
    assert!(stored.last_seen.is_some());
    drop(link);

    // The enrollment is spent: presenting it again from another machine fails.
    let impostor = connect(
        &c,
        Identity::generate("impostor").unwrap(),
        WorkerId::new(),
        Some(&secret),
    )
    .unwrap_err();
    assert!(
        matches!(impostor, Error::Rejected(Rejection::Enrollment)),
        "{impostor}"
    );
    // The enrolled identity reconnects with no enrollment at all.
    let mut again = connect(&c, Identity::load(&cert, &key).unwrap(), worker, None).unwrap();
    again.beat().unwrap();
    drop(again);

    // Revoked: the same certificate is refused from now on.
    c.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, UnixMillis::now()))
        .unwrap();
    let refused = connect(&c, Identity::load(&cert, &key).unwrap(), worker, None).unwrap_err();
    assert!(matches!(refused, Error::Rejected(Rejection::NotEnrolled)));
    // And it cannot enroll again under the same identity with a fresh secret.
    let fresh = enrollment(&c, 60_000);
    let refused = connect(
        &c,
        Identity::load(&cert, &key).unwrap(),
        worker,
        Some(&fresh),
    )
    .unwrap_err();
    assert!(matches!(refused, Error::Rejected(Rejection::Identity)));
}

#[test]
fn a_wrong_server_fingerprint_never_reaches_the_hello() {
    let c = controller();
    let secret = enrollment(&c, 60_000);
    let wrong = Identity::generate("not-the-controller")
        .unwrap()
        .fingerprint();
    let config = tls::client_config(Identity::generate("w").unwrap(), wrong).unwrap();
    let failure =
        session::connect(c.addr, config, WorkerId::new(), "w", hello(), Some(&secret)).unwrap_err();
    assert!(matches!(failure, Error::Tls(_) | Error::Io(_)), "{failure}");
    // The enrollment was never presented, so it is still unspent.
    assert!(
        connect(
            &c,
            Identity::generate("w2").unwrap(),
            WorkerId::new(),
            Some(&secret)
        )
        .is_ok()
    );
}

#[test]
fn an_unsupported_protocol_and_an_expired_enrollment_are_typed_refusals() {
    let c = controller();
    let secret = enrollment(&c, 60_000);
    let config = tls::client_config(Identity::generate("old").unwrap(), c.fingerprint).unwrap();
    let old = Hello {
        protocol_min: ProtocolVersion(0),
        protocol_max: ProtocolVersion(0),
        ..hello()
    };
    let failure =
        session::connect(c.addr, config, WorkerId::new(), "old", old, Some(&secret)).unwrap_err();
    assert!(
        matches!(
            failure,
            Error::Rejected(Rejection::UnsupportedVersion {
                upgrade_worker: true,
                ..
            })
        ),
        "{failure}"
    );

    let short = enrollment(&c, 1);
    thread::sleep(Duration::from_millis(20));
    let failure = connect(
        &c,
        Identity::generate("late").unwrap(),
        WorkerId::new(),
        Some(&short),
    )
    .unwrap_err();
    assert!(matches!(failure, Error::Rejected(Rejection::Enrollment)));

    // Nothing above left a live session behind; every server-side outcome is
    // a clean refusal or a goodbye.
    thread::sleep(Duration::from_millis(100));
    let outcomes = c.outcomes.lock().unwrap();
    assert!(outcomes.iter().all(|o| o.is_err()), "{outcomes:?}");
}
