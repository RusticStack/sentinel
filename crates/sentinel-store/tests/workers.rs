//! W01 store behavior: enrollment is one-time, expiring, pool-bound and
//! platform-issued; a worker's identity and pool are fixed; liveness is
//! recorded at a bounded cadence; revocation is final.

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    PoolId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn negotiated() -> Negotiated {
    Negotiated {
        protocol: ProtocolVersion(1),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
    }
}

fn fingerprint() -> Digest {
    Secret::generate().digest()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    tenant: TenantId,
    pool: PoolId,
    shared: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, pool, shared) =
        (UserId::new(), TenantId::new(), PoolId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                shared,
                "shared",
                PoolKind::Shared,
                NOW,
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        root,
        tenant,
        pool,
        shared,
    }
}

fn enroll(
    f: &Fixture,
    secret: &Secret,
    worker: WorkerId,
    fp: Digest,
    now: UnixMillis,
) -> Result<workers::Worker, Error> {
    let secret = Secret::parse(&{
        let mut t = String::new();
        secret.expose(&mut t);
        t
    })
    .unwrap();
    f.store.writer().write(move |tx| {
        workers::enroll(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder-1",
                negotiated: negotiated(),
            },
            now,
        )
    })
}

#[test]
fn enrollment_is_platform_issued_pool_bound_single_use_and_expiring() {
    let f = fixture();
    let pool = f.pool;
    // Issuing needs platform administration and an active pool with a bounded lifetime.
    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let refused = f.store.writer().write(move |tx| {
        workers::issue_enrollment(tx, Authority::credential(member), pool, 60_000, NOW).map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    for lifetime in [0, workers::MAX_ENROLLMENT_MS + 1] {
        let refused = f.store.writer().write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, lifetime, NOW).map(|_| ())
        });
        assert!(matches!(
            refused,
            Err(Error::InvalidInput("enrollment lifetime"))
        ));
    }
    let refused = f.store.writer().write(move |tx| {
        workers::issue_enrollment(tx, Authority::HostLocal, PoolId::new(), 60_000, NOW).map(|_| ())
    });
    assert!(matches!(refused, Err(Error::NotFound)));

    let issued = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    assert_eq!(issued.pool, pool);
    assert_eq!(issued.expires.0, 61_000);

    let (worker, fp) = (WorkerId::new(), fingerprint());
    let enrolled = enroll(&f, &issued.secret, worker, fp, at(2_000)).unwrap();
    assert_eq!((enrolled.id, enrolled.pool), (worker, pool));
    // Spent: a second machine gets nothing, and neither does the same one.
    assert!(matches!(
        enroll(
            &f,
            &issued.secret,
            WorkerId::new(),
            fingerprint(),
            at(2_100)
        ),
        Err(Error::NotFound)
    ));
    // A reused identity or fingerprint with a fresh enrollment is a conflict,
    // and the fresh enrollment stays unspent for the real machine.
    let fresh = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(2_200))
        })
        .unwrap();
    assert!(matches!(
        enroll(&f, &fresh.secret, worker, fingerprint(), at(2_300)),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        enroll(&f, &fresh.secret, WorkerId::new(), fp, at(2_300)),
        Err(Error::Conflict)
    ));
    enroll(&f, &fresh.secret, WorkerId::new(), fingerprint(), at(2_400)).unwrap();
    // Expired and revoked enrollments are the same "no".
    let short = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 10, at(3_000)))
        .unwrap();
    assert!(matches!(
        enroll(&f, &short.secret, WorkerId::new(), fingerprint(), at(3_010)),
        Err(Error::NotFound)
    ));
    let revoked = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(3_100))
        })
        .unwrap();
    let id = revoked.id;
    f.store
        .writer()
        .write(move |tx| workers::revoke_enrollment(tx, Authority::HostLocal, id, at(3_200)))
        .unwrap();
    assert!(matches!(
        enroll(
            &f,
            &revoked.secret,
            WorkerId::new(),
            fingerprint(),
            at(3_300)
        ),
        Err(Error::NotFound)
    ));
    let unspend = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE worker_enrollments SET redeemed_ms = NULL, redeemed_worker = NULL",
            [],
        )?;
        Ok(())
    });
    assert!(matches!(unspend, Err(Error::Sqlite(_))));
}

#[test]
fn a_worker_is_known_by_fingerprint_bound_to_its_pool_and_revocable() {
    let f = fixture();
    let pool = f.pool;
    let issued = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    let (worker, fp) = (WorkerId::new(), fingerprint());
    enroll(&f, &issued.secret, worker, fp, at(2_000)).unwrap();

    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(known.id, worker);
    assert!(known.last_seen.is_none());
    assert!(workers::seen_due(&known, at(2_000)));
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fingerprint())),
        Err(Error::NotFound)
    ));

    // Liveness moves forward at a bounded cadence and never backwards.
    f.store
        .writer()
        .write(move |tx| workers::seen(tx, worker, at(5_000)))
        .unwrap();
    f.store
        .writer()
        .write(move |tx| workers::seen(tx, worker, at(4_000)))
        .unwrap();
    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(known.last_seen, Some(at(5_000)));
    assert!(!workers::seen_due(
        &known,
        at(5_000 + workers::SEEN_RECORD_INTERVAL_MS - 1)
    ));
    assert!(workers::seen_due(
        &known,
        at(5_000 + workers::SEEN_RECORD_INTERVAL_MS)
    ));

    // The pool cannot be moved or the fingerprint swapped by raw SQL.
    let shared = f.shared;
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE workers SET pool_id = ?1", [shared.as_bytes()])?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));

    // Listing: the platform, and members of a tenant the pool admits.
    let live = f
        .store
        .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
        .unwrap();
    assert_eq!(live.len(), 1);
    let outsider = Principal::new(UserId::new(), P::ALL, None, None);
    assert!(matches!(
        f.store
            .read(|c| workers::in_pool(c, Authority::credential(outsider), pool)),
        Err(Error::NotFound)
    ));

    // Revocation: refused from now on, not repeatable, and a suspended pool's
    // tenant hides its workers too.
    let refused = f
        .store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::credential(outsider), worker, at(6_000)));
    assert!(matches!(refused, Err(Error::Forbidden)));
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, at(6_000)))
        .unwrap();
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fp)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store.writer().write(move |tx| workers::revoke(
            tx,
            Authority::HostLocal,
            worker,
            at(6_100)
        )),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
            .unwrap()
            .is_empty()
    );
    let root = f.root;
    let tenant = f.tenant;
    let issued = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(7_000))
        })
        .unwrap();
    let fp2 = fingerprint();
    enroll(&f, &issued.secret, WorkerId::new(), fp2, at(7_100)).unwrap();
    f.store
        .writer()
        .write(move |tx| {
            tenancy::suspend(
                tx,
                Authority::Credential {
                    principal: Principal::new(root, P::ALL, None, None),
                    stepped_up: true,
                },
                tenant,
                at(7_200),
            )
        })
        .unwrap();
    // The pool itself is still active, so the worker still authenticates; it
    // is placement that the suspended tenant loses (A07). That is deliberate:
    // a dedicated pool's machines stay enrolled through a suspension.
    assert!(f.store.read(|c| workers::authenticate(c, &fp2)).is_ok());
}
