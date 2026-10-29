//! Controller-owned enrollment policy (Q11): ceilings, priority, the bound node key and uninstall.

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, EnrollmentTerms, HostPolicy, NodeKey, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

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

fn key(byte: u8) -> NodeKey {
    [byte; 32]
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
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
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        repo,
        pool,
    }
}

fn terms(f: &Fixture, policy: HostPolicy, tailcat: bool) -> EnrollmentTerms {
    EnrollmentTerms {
        pool: f.pool,
        lifetime_ms: 60_000,
        policy,
        tailcat,
    }
}

fn issue(f: &Fixture, policy: HostPolicy, tailcat: bool) -> workers::Enrollment {
    let terms = terms(f, policy, tailcat);
    f.store
        .writer()
        .write(move |tx| workers::issue_enrollment_with(tx, Authority::HostLocal, terms, NOW))
        .unwrap()
}

fn redeem(
    f: &Fixture,
    enrollment: &workers::Enrollment,
    worker: WorkerId,
    fp: Digest,
    node_key: Option<NodeKey>,
) -> Result<Option<workers::Worker>, Error> {
    let mut text = String::new();
    enrollment.secret.expose(&mut text);
    let secret = Secret::parse(&text).unwrap();
    f.store.writer().write(move |tx| {
        workers::redeem_bound(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder",
                negotiated: negotiated(),
            },
            node_key,
            at(2_000),
        )
    })
}

fn policy() -> HostPolicy {
    HostPolicy {
        cpu_millis: Some(4_000),
        memory_bytes: Some(8 << 30),
        disk_bytes: Some(50 << 30),
        priority: 25,
    }
}

fn report(f: &Fixture, worker: WorkerId, cpu: i64, memory: i64, disk: i64) {
    f.store
        .writer()
        .write(move |tx| {
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: cpu,
                    memory_bytes: memory,
                    disk_bytes: disk,
                },
            )
        })
        .unwrap();
}

fn capacity(f: &Fixture, worker: WorkerId) -> Capacity {
    f.store
        .read(|c| dispatch::free_capacity(c, worker))
        .unwrap()
}

#[test]
fn an_enrollment_carries_its_ceilings_and_priority_onto_the_worker() {
    let f = fixture();
    let enrollment = issue(&f, policy(), false);
    assert_eq!(enrollment.policy, policy());
    let (worker, fp) = (WorkerId::new(), fingerprint());
    let enrolled = redeem(&f, &enrollment, worker, fp, None).unwrap().unwrap();
    assert_eq!(enrolled.policy, policy());
    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(known.policy, policy());
    assert_eq!(known.node_key, None);

    // The legacy issue call is the neutral policy: no ceilings, priority zero, no node key.
    let pool = f.pool;
    let legacy = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    assert_eq!(legacy.policy, HostPolicy::default());
    assert!(!legacy.tailcat);
}

#[test]
fn ceilings_and_priority_are_validated_and_platform_only() {
    let f = fixture();
    for bad in [
        HostPolicy {
            cpu_millis: Some(0),
            ..HostPolicy::default()
        },
        HostPolicy {
            memory_bytes: Some(-1),
            ..HostPolicy::default()
        },
        HostPolicy {
            disk_bytes: Some(0),
            ..HostPolicy::default()
        },
        HostPolicy {
            priority: workers::PRIORITY_MAX + 1,
            ..HostPolicy::default()
        },
        HostPolicy {
            priority: workers::PRIORITY_MIN - 1,
            ..HostPolicy::default()
        },
    ] {
        let terms = terms(&f, bad, false);
        let refused = f
            .store
            .writer()
            .write(move |tx| workers::issue_enrollment_with(tx, Authority::HostLocal, terms, NOW))
            .map(|_| ());
        assert!(matches!(
            refused,
            Err(Error::InvalidInput("host ceiling" | "host priority"))
        ));
    }
    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let terms = terms(&f, policy(), false);
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment_with(tx, Authority::credential(member), terms, NOW)
        })
        .map(|_| ());
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn a_tailcat_enrollment_binds_the_fingerprint_and_the_node_key_together() {
    let f = fixture();
    let enrollment = issue(&f, HostPolicy::default(), true);
    let (worker, fp) = (WorkerId::new(), fingerprint());

    // Without the node key the enrollment is refused and stays redeemable by the real machine.
    assert!(redeem(&f, &enrollment, worker, fp, None).unwrap().is_none());
    let enrolled = redeem(&f, &enrollment, worker, fp, Some(key(7)))
        .unwrap()
        .unwrap();
    assert_eq!(enrolled.node_key, Some(key(7)));

    let known = f
        .store
        .read(|c| workers::authenticate_bound(c, &fp, &key(7)))
        .unwrap();
    assert_eq!(known.id, worker);
    // The right fingerprint with another worker's key, and the reverse, is no worker at all.
    assert!(matches!(
        f.store
            .read(|c| workers::authenticate_bound(c, &fp, &key(8))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .read(|c| workers::authenticate_bound(c, &fingerprint(), &key(7))),
        Err(Error::NotFound)
    ));
    assert_eq!(
        f.store.read(workers::admitted_node_keys).unwrap(),
        vec![(worker, key(7))]
    );

    // Single use: a spent enrollment admits nothing else.
    assert!(
        redeem(
            &f,
            &enrollment,
            WorkerId::new(),
            fingerprint(),
            Some(key(9))
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn a_direct_tls_enrollment_refuses_a_node_key_and_the_reverse() {
    let f = fixture();
    let direct = issue(&f, HostPolicy::default(), false);
    assert!(
        redeem(&f, &direct, WorkerId::new(), fingerprint(), Some(key(1)))
            .unwrap()
            .is_none()
    );
    let fp = fingerprint();
    let enrolled = redeem(&f, &direct, WorkerId::new(), fp, None)
        .unwrap()
        .unwrap();
    assert_eq!(enrolled.node_key, None);
    // No key was bound, so the bound lookup never matches this worker.
    assert!(matches!(
        f.store
            .read(|c| workers::authenticate_bound(c, &fp, &key(1))),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(workers::admitted_node_keys)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_node_key_belongs_to_one_identity_for_good() {
    let f = fixture();
    let first = issue(&f, HostPolicy::default(), true);
    let worker = WorkerId::new();
    redeem(&f, &first, worker, fingerprint(), Some(key(3)))
        .unwrap()
        .unwrap();

    // A second enrollment cannot claim the key; it stays unspent for the real machine.
    let second = issue(&f, HostPolicy::default(), true);
    assert!(matches!(
        redeem(&f, &second, WorkerId::new(), fingerprint(), Some(key(3))),
        Err(Error::Conflict)
    ));
    // Not even after the first worker is revoked: a retired key is never admitted again.
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, at(3_000)))
        .unwrap();
    assert!(
        f.store
            .read(workers::admitted_node_keys)
            .unwrap()
            .is_empty(),
        "a revoked worker's key leaves the allow list"
    );
    assert!(matches!(
        redeem(&f, &second, WorkerId::new(), fingerprint(), Some(key(3))),
        Err(Error::Conflict)
    ));
    redeem(&f, &second, WorkerId::new(), fingerprint(), Some(key(4)))
        .unwrap()
        .unwrap();

    // The key and the enrollment terms cannot be rewritten through raw SQL either.
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE workers SET node_key = X'00'", [])?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE worker_enrollments SET priority = 100", [])?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
}

#[test]
fn reported_capacity_never_exceeds_the_approved_ceilings() {
    let f = fixture();
    let enrollment = issue(&f, policy(), false);
    let worker = WorkerId::new();
    redeem(&f, &enrollment, worker, fingerprint(), None)
        .unwrap()
        .unwrap();

    // A host larger than its approval is held to the approval.
    report(&f, worker, 16_000, 64 << 30, 500 << 30);
    assert_eq!(
        capacity(&f, worker),
        Capacity {
            cpu_millis: 4_000,
            memory_bytes: 8 << 30,
            disk_bytes: 50 << 30
        }
    );
    // A smaller host keeps its own size; an unreported disk takes the approved limit.
    report(&f, worker, 2_000, 4 << 30, 0);
    assert_eq!(
        capacity(&f, worker),
        Capacity {
            cpu_millis: 2_000,
            memory_bytes: 4 << 30,
            disk_bytes: 50 << 30
        }
    );
}

#[test]
fn a_ceiling_reduction_applies_at_once_and_never_to_accepted_work() {
    let f = fixture();
    let enrollment = issue(&f, HostPolicy::default(), false);
    let worker = WorkerId::new();
    redeem(&f, &enrollment, worker, fingerprint(), None)
        .unwrap()
        .unwrap();
    report(&f, worker, 8_000, 16 << 30, 100 << 30);

    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(
            "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 2, memory: 2GiB }
    steps: [{ id: s, run: 'true' }]
",
        )
        .unwrap(),
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, at(2_000))?;
            for job in ids {
                runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64")?;
            }
            Ok(())
        })
        .unwrap();
    let offer = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, at(2_100)))
        .unwrap()
        .expect("the job fits before the reduction");

    let disk_before = capacity(&f, worker).disk_bytes;
    // Halving the CPU ceiling below the held 2 cores' share: the accepted attempt stays, and the
    // free room goes negative instead of killing it.
    f.store
        .writer()
        .write(move |tx| {
            workers::set_policy(
                tx,
                Authority::HostLocal,
                worker,
                HostPolicy {
                    cpu_millis: Some(1_000),
                    memory_bytes: Some(1 << 30),
                    disk_bytes: None,
                    priority: -5,
                },
            )
        })
        .unwrap();
    let free = capacity(&f, worker);
    assert_eq!(free.cpu_millis, 1_000 - 2_000);
    assert_eq!(free.memory_bytes, (1 << 30) - (2 << 30));
    assert_eq!(
        free.disk_bytes, disk_before,
        "a policy without a disk ceiling leaves the disk room alone"
    );
    let held = f
        .store
        .read(|c| dispatch::is_held(c, worker, offer.attempt))
        .unwrap();
    assert!(held, "accepted work is not touched by a ceiling change");
    let known = f
        .store
        .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
        .unwrap();
    assert_eq!(known[0].policy.priority, -5);

    // Nothing more is placed over the reduced ceiling.
    let again = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, at(2_200)))
        .unwrap();
    assert!(again.is_none());

    // Only the platform changes policy.
    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let refused = f.store.writer().write(move |tx| {
        workers::set_policy(
            tx,
            Authority::credential(member),
            worker,
            HostPolicy::default(),
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn an_uninstall_drains_now_and_revokes_once_accepted_work_has_settled() {
    let f = fixture();
    let enrollment = issue(&f, HostPolicy::default(), true);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    redeem(&f, &enrollment, worker, fp, Some(key(5)))
        .unwrap()
        .unwrap();
    report(&f, worker, 4_000, 8 << 30, 10 << 30);

    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(
            "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
",
        )
        .unwrap(),
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, at(2_000))?;
            for job in ids {
                runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64")?;
            }
            Ok(())
        })
        .unwrap();
    let offer = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, at(2_100)))
        .unwrap()
        .unwrap();

    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let refused = f.store.writer().write(move |tx| {
        workers::request_uninstall(tx, Authority::credential(member), worker, at(3_000))
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    for requested_at in [3_000, 3_500] {
        f.store
            .writer()
            .write(move |tx| {
                workers::request_uninstall(tx, Authority::HostLocal, worker, at(requested_at))
            })
            .unwrap();
    }
    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(
        known.uninstall_requested,
        Some(at(3_000)),
        "the first request's time stands"
    );
    assert!(f.store.read(workers::uninstalling).unwrap());

    // The worker keeps its accepted attempt, so it is not revoked yet, and it takes nothing new.
    let settled = f
        .store
        .writer()
        .write(move |tx| workers::settle_uninstalls(tx, at(3_100)))
        .unwrap();
    assert!(settled.is_empty());
    assert!(f.store.read(|c| workers::authenticate(c, &fp)).is_ok());
    let (tenant2, repo2) = (f.tenant, f.repo);
    let spec2 = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(
            "schema: 1
on: [push]
jobs:
  next:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
",
        )
        .unwrap(),
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant2, repo2, RunId::new(), &spec2, at(3_200))?;
            for job in ids {
                runs::resolve_image(tx, tenant2, job, DIGEST, "linux/amd64")?;
            }
            Ok(())
        })
        .unwrap();
    let none = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, at(3_300)))
        .unwrap();
    assert!(none.is_none(), "an uninstalling worker is drained");

    // Once the attempt is released the next pass revokes the identity and its node key.
    let attempt = offer.attempt;
    f.store
        .writer()
        .write(move |tx| dispatch::lapse(tx, attempt, at(4_000)))
        .unwrap();
    let settled = f
        .store
        .writer()
        .write(move |tx| workers::settle_uninstalls(tx, at(4_100)))
        .unwrap();
    assert_eq!(settled, vec![worker]);
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fp)),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(workers::admitted_node_keys)
            .unwrap()
            .is_empty()
    );
    assert!(!f.store.read(workers::uninstalling).unwrap());
    assert!(f.store.read(|c| workers::revoked(c, worker)).unwrap());
    // An uninstall request cannot be withdrawn, even through raw SQL.
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE workers SET uninstall_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
}

#[test]
fn node_keys_parse_from_the_helper_spelling_only() {
    let hex = "ab".repeat(32);
    assert_eq!(
        workers::parse_node_key(&format!("nodekey:{hex}")),
        Some([0xab; 32])
    );
    assert_eq!(
        workers::parse_node_key(&format!(" nodekey:{} \n", hex.to_uppercase())),
        Some([0xab; 32])
    );
    for bad in [
        "",
        "nodekey:",
        &format!("nodekey:{}", "ab".repeat(31)),
        &format!("nodekey:{}z", "ab".repeat(31)),
        &format!("key:{hex}"),
        &format!("nodekey:{}é", "ab".repeat(31)),
    ] {
        assert_eq!(workers::parse_node_key(bad), None, "{bad}");
    }
}
