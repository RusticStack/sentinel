//! Authoritative host policy (Q12) and the Tailcat node key authorized through an enrollment (Q11):
//! what a worker reports about itself never exceeds what the controller approved, a policy change
//! recomputes the offered size in both directions at once, and the key an administrator authorizes
//! for a pending enrollment is admitted until the enrollment is spent, withdrawn or expired.

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    PoolId, UnixMillis, UserId, WorkerId,
    auth::{Permissions as P, Principal},
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::Authority,
    dispatch::{self, Capacity},
    local_auth::{self, Event},
    tenancy::{self, PoolKind},
    workers::{self, EnrollmentTerms, HostPolicy, NodeKey, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const GIB: i64 = 1 << 30;

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn key(byte: u8) -> NodeKey {
    [byte; 32]
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Shared,
                NOW,
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        pool,
    }
}

fn policy() -> HostPolicy {
    HostPolicy {
        cpu_millis: Some(4_000),
        memory_bytes: Some(8 * GIB),
        disk_bytes: Some(50 * GIB),
        priority: 25,
    }
}

fn issue(f: &Fixture, policy: HostPolicy, tailcat: bool, lifetime_ms: i64) -> workers::Enrollment {
    let terms = EnrollmentTerms {
        pool: f.pool,
        lifetime_ms,
        policy,
        tailcat,
    };
    f.store
        .writer()
        .write(move |tx| workers::issue_enrollment_with(tx, Authority::HostLocal, terms, NOW))
        .unwrap()
}

fn secret_of(enrollment: &workers::Enrollment) -> Secret {
    let mut text = String::new();
    enrollment.secret.expose(&mut text);
    Secret::parse(&text).unwrap()
}

fn redeem_authorized(
    f: &Fixture,
    enrollment: &workers::Enrollment,
    worker: WorkerId,
    fp: Digest,
    now: i64,
) -> Result<Option<workers::Worker>, Error> {
    let secret = secret_of(enrollment);
    f.store.writer().write(move |tx| {
        workers::redeem_authorized(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder",
                negotiated: Negotiated {
                    protocol: ProtocolVersion(1),
                    capabilities: Capabilities::REQUIRED,
                    arch: Arch::X86_64,
                },
            },
            at(now),
        )
    })
}

fn enroll(f: &Fixture, policy: HostPolicy) -> WorkerId {
    let enrollment = issue(f, policy, false, 60_000);
    let worker = WorkerId::new();
    redeem_authorized(f, &enrollment, worker, Secret::generate().digest(), 2_000)
        .unwrap()
        .unwrap();
    worker
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

fn set(f: &Fixture, worker: WorkerId, policy: HostPolicy) {
    f.store
        .writer()
        .write(move |tx| workers::set_policy(tx, Authority::HostLocal, worker, policy))
        .unwrap();
}

fn view(f: &Fixture, worker: WorkerId) -> workers::HostView {
    f.store
        .read(|c| workers::host_view(c, Authority::HostLocal, worker))
        .unwrap()
}

fn offered(f: &Fixture, worker: WorkerId) -> Capacity {
    f.store
        .read(|c| dispatch::free_capacity(c, worker))
        .unwrap()
}

#[test]
fn a_worker_that_reports_more_than_approved_is_capped_however_often_it_says_so() {
    let f = fixture();
    let worker = enroll(&f, policy());

    // The first hello and every later one claim a far larger host than the controller approved.
    for claim in [16_000, 64_000, 256_000] {
        report(&f, worker, claim, 512 * GIB, 4_000 * GIB);
        assert_eq!(
            offered(&f, worker),
            Capacity {
                cpu_millis: 4_000,
                memory_bytes: 8 * GIB,
                disk_bytes: 50 * GIB
            }
        );
    }
    let v = view(&f, worker);
    assert_eq!(v.policy, policy(), "a report never rewrites the approval");
    assert_eq!(v.reported_cpu_millis, 256_000, "the report is kept apart");
    assert_eq!(v.effective_cpu_millis, 4_000);

    // A host smaller than its approval keeps its own size, and an unreported disk takes the ceiling.
    report(&f, worker, 2_000, 4 * GIB, 0);
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 2_000,
            memory_bytes: 4 * GIB,
            disk_bytes: 50 * GIB
        }
    );
}

#[test]
fn approved_ceilings_and_priority_survive_a_controller_restart() {
    let f = fixture();
    let worker = enroll(&f, policy());
    report(&f, worker, 16_000, 64 * GIB, 500 * GIB);
    let lowered = HostPolicy {
        cpu_millis: Some(3_000),
        memory_bytes: Some(6 * GIB),
        disk_bytes: Some(40 * GIB),
        priority: -7,
    };
    set(&f, worker, lowered);
    let before = view(&f, worker);
    assert_eq!(before.policy, lowered);

    // Close the database and open the same file again, as a restarted controller does.
    let Fixture { _dir, store, pool } = f;
    drop(store);
    let store = Store::open(_dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let f = Fixture { _dir, store, pool };

    let after = view(&f, worker);
    assert_eq!(
        after.policy, lowered,
        "the approval is stored, not remembered by a session"
    );
    assert_eq!(after.effective_cpu_millis, 3_000);
    assert_eq!(after.reported_cpu_millis, 16_000);
    let approved = f.store.read(dispatch::approved_by_worker).unwrap();
    assert_eq!(approved[&worker].priority, -7);
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 3_000,
            memory_bytes: 6 * GIB,
            disk_bytes: 40 * GIB
        }
    );

    // The reconnecting worker states its whole machine again: still capped by the stored approval.
    report(&f, worker, 64_000, 512 * GIB, 4_000 * GIB);
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 3_000,
            memory_bytes: 6 * GIB,
            disk_bytes: 40 * GIB
        }
    );
    assert_eq!(view(&f, worker).policy, lowered);
}

#[test]
fn a_policy_change_recomputes_the_offered_size_both_ways_without_a_new_report() {
    let f = fixture();
    let worker = enroll(&f, policy());
    report(&f, worker, 16_000, 64 * GIB, 500 * GIB);

    // Raising the ceilings takes effect at once, up to the host's own report.
    set(
        &f,
        worker,
        HostPolicy {
            cpu_millis: Some(8_000),
            memory_bytes: Some(128 * GIB),
            disk_bytes: Some(200 * GIB),
            priority: 25,
        },
    );
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 8_000,
            memory_bytes: 64 * GIB,
            disk_bytes: 200 * GIB
        },
        "never above what the host itself reported"
    );

    // Removing the ceilings offers the whole report, and no more.
    set(&f, worker, HostPolicy::default());
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 16_000,
            memory_bytes: 64 * GIB,
            disk_bytes: 500 * GIB
        }
    );

    // Reducing them again stops new oversubscription at once.
    set(
        &f,
        worker,
        HostPolicy {
            cpu_millis: Some(1_000),
            memory_bytes: Some(GIB),
            disk_bytes: Some(10 * GIB),
            priority: 0,
        },
    );
    assert_eq!(
        offered(&f, worker),
        Capacity {
            cpu_millis: 1_000,
            memory_bytes: GIB,
            disk_bytes: 10 * GIB
        }
    );
}

#[test]
fn a_size_the_worker_never_stated_is_reduced_but_never_invented() {
    let f = fixture();
    let worker = enroll(&f, HostPolicy::default());
    // No capacity report yet: the controller offers nothing, whatever the policy says.
    set(&f, worker, policy());
    let v = view(&f, worker);
    assert_eq!((v.reported_cpu_millis, v.reported_memory_bytes), (0, 0));
    assert_eq!((v.effective_cpu_millis, v.effective_memory_bytes), (0, 0));
    set(
        &f,
        worker,
        HostPolicy {
            cpu_millis: Some(64_000),
            ..policy()
        },
    );
    assert_eq!(
        view(&f, worker).effective_cpu_millis,
        0,
        "a ceiling is a limit, not a grant"
    );

    // A disk that was never reported is not enforced once its ceiling goes away.
    assert_eq!(view(&f, worker).effective_disk_bytes, 50 * GIB);
    set(&f, worker, HostPolicy::default());
    assert_eq!(view(&f, worker).effective_disk_bytes, 0);
}

#[test]
fn priority_is_the_controllers_alone_and_every_change_is_audited() {
    let f = fixture();
    let worker = enroll(&f, policy());
    assert_eq!(view(&f, worker).policy.priority, 25);

    // Nothing the worker sends reaches the priority or the ceilings.
    report(&f, worker, 99_000, 999 * GIB, 9_999 * GIB);
    assert_eq!(view(&f, worker).policy, policy());

    // Only platform administration sets policy, and the range is checked.
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
    let shown = f
        .store
        .read(move |c| workers::host_view(c, Authority::credential(member), worker));
    assert!(matches!(shown, Err(Error::Forbidden)));
    for bad in [
        HostPolicy {
            priority: 101,
            ..policy()
        },
        HostPolicy {
            cpu_millis: Some(0),
            ..policy()
        },
        HostPolicy {
            memory_bytes: Some(-1),
            ..policy()
        },
    ] {
        let rejected = f
            .store
            .writer()
            .write(move |tx| workers::set_policy(tx, Authority::HostLocal, worker, bad));
        assert!(matches!(rejected, Err(Error::InvalidInput(_))), "{bad:?}");
    }
    assert_eq!(view(&f, worker).policy, policy());

    set(
        &f,
        worker,
        HostPolicy {
            priority: -40,
            ..policy()
        },
    );
    assert_eq!(view(&f, worker).policy.priority, -40);
    let changes: Vec<_> = f
        .store
        .read(|c| local_auth::recent_audit(c, 50))
        .unwrap()
        .into_iter()
        .filter(|row| row.event == Event::WorkerPolicyChanged)
        .collect();
    assert_eq!(changes.len(), 1);
    assert!(changes[0].host_local);
    let detail = changes[0].detail.as_deref().unwrap();
    assert!(detail.contains("priority=-40") && detail.contains(&worker.to_string()));

    // A revoked worker has no policy to read or change.
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, at(9_000)))
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| workers::host_view(c, Authority::HostLocal, worker)),
        Err(Error::NotFound)
    ));
}

fn authorize(
    f: &Fixture,
    enrollment: &workers::Enrollment,
    worker: WorkerId,
    k: NodeKey,
    now: i64,
) -> Result<(), Error> {
    let id = enrollment.id;
    f.store.writer().write(move |tx| {
        workers::authorize_node_key(tx, Authority::HostLocal, id, worker, k, at(now))
    })
}

fn pending(f: &Fixture, now: i64) -> Vec<(WorkerId, NodeKey)> {
    f.store
        .read(|c| workers::pending_node_keys(c, at(now)))
        .unwrap()
}

#[test]
fn an_authorized_key_is_admitted_until_the_enrollment_is_spent_and_then_the_worker_owns_it() {
    let f = fixture();
    let enrollment = issue(&f, policy(), true, 60_000);
    let worker = WorkerId::new();

    // A Tailcat enrollment with no authorized key cannot be redeemed: the controller has no key to bind.
    let none =
        redeem_authorized(&f, &enrollment, worker, Secret::generate().digest(), 1_500).unwrap();
    assert!(none.is_none());
    assert!(
        pending(&f, 1_500).is_empty(),
        "nothing is admitted before an administrator says so"
    );

    authorize(&f, &enrollment, worker, key(7), 1_100).unwrap();
    authorize(&f, &enrollment, worker, key(7), 1_200).unwrap();
    assert_eq!(pending(&f, 1_300), vec![(worker, key(7))]);

    // The pair is fixed: another key or another identifier on the same enrollment is refused.
    assert!(matches!(
        authorize(&f, &enrollment, worker, key(8), 1_300),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        authorize(&f, &enrollment, WorkerId::new(), key(7), 1_300),
        Err(Error::Conflict)
    ));
    assert_eq!(pending(&f, 1_300), vec![(worker, key(7))]);

    // Another identifier presenting the secret is refused, and the enrollment stays redeemable.
    let impostor = redeem_authorized(
        &f,
        &enrollment,
        WorkerId::new(),
        Secret::generate().digest(),
        1_400,
    )
    .unwrap();
    assert!(impostor.is_none());
    assert_eq!(pending(&f, 1_450), vec![(worker, key(7))]);

    let fp = Secret::generate().digest();
    let enrolled = redeem_authorized(&f, &enrollment, worker, fp, 1_500)
        .unwrap()
        .unwrap();
    assert_eq!(enrolled.node_key, Some(key(7)));
    assert_eq!(enrolled.policy, policy());
    assert!(
        pending(&f, 1_600).is_empty(),
        "spent: the worker's own key takes over"
    );
    assert_eq!(
        f.store.read(workers::admitted_node_keys).unwrap(),
        vec![(worker, key(7))]
    );
    assert!(
        f.store
            .read(|c| workers::authenticate_bound(c, &fp, &key(7)))
            .is_ok()
    );

    // The authorization is on the audit trail without the key.
    let rows = f.store.read(|c| local_auth::recent_audit(c, 50)).unwrap();
    let authorized: Vec<_> = rows
        .iter()
        .filter(|row| row.event == Event::WorkerNodeKeyAuthorized)
        .collect();
    assert_eq!(authorized.len(), 1);
    assert!(!authorized[0].detail.as_deref().unwrap().contains("nodekey"));

    // An uninstall takes the key away once the worker has nothing left to finish.
    f.store
        .writer()
        .write(move |tx| workers::request_uninstall(tx, Authority::HostLocal, worker, at(2_000)))
        .unwrap();
    let settled = f
        .store
        .writer()
        .write(move |tx| workers::settle_uninstalls(tx, at(2_100)))
        .unwrap();
    assert_eq!(settled, vec![worker]);
    assert!(
        f.store
            .read(workers::admitted_node_keys)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_withdrawn_or_expired_enrollment_stops_admitting_its_key_and_a_bound_key_is_never_reused() {
    let f = fixture();
    let withdrawn = issue(&f, HostPolicy::default(), true, 60_000);
    let worker = WorkerId::new();
    authorize(&f, &withdrawn, worker, key(1), 1_100).unwrap();
    assert_eq!(pending(&f, 1_200).len(), 1);
    let id = withdrawn.id;
    f.store
        .writer()
        .write(move |tx| workers::revoke_enrollment(tx, Authority::HostLocal, id, at(1_300)))
        .unwrap();
    assert!(
        pending(&f, 1_400).is_empty(),
        "withdrawing the enrollment withdraws the key"
    );
    assert!(matches!(
        authorize(&f, &withdrawn, worker, key(1), 1_500),
        Err(Error::Conflict)
    ));

    // The released key can be authorized again on a fresh enrollment (same machine, new secret).
    let again = issue(&f, HostPolicy::default(), true, 1_000);
    authorize(&f, &again, worker, key(1), 1_600).unwrap();
    assert_eq!(pending(&f, 1_700), vec![(worker, key(1))]);
    // Expiry (the issue time plus one second) removes it without any write.
    assert!(pending(&f, 2_500).is_empty());
    assert!(matches!(
        authorize(&f, &again, worker, key(1), 2_500),
        Err(Error::Conflict)
    ));

    // A key already bound to a worker, and a worker identifier already enrolled, are refused.
    let enrollment = issue(&f, HostPolicy::default(), true, 60_000);
    let first = WorkerId::new();
    authorize(&f, &enrollment, first, key(2), 3_000).unwrap();
    redeem_authorized(&f, &enrollment, first, Secret::generate().digest(), 3_100)
        .unwrap()
        .unwrap();
    let other = issue(&f, HostPolicy::default(), true, 60_000);
    assert!(matches!(
        authorize(&f, &other, WorkerId::new(), key(2), 3_200),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        authorize(&f, &other, first, key(3), 3_200),
        Err(Error::Conflict)
    ));
    // Two pending enrollments cannot hold one key.
    let third = issue(&f, HostPolicy::default(), true, 60_000);
    let fourth = issue(&f, HostPolicy::default(), true, 60_000);
    authorize(&f, &third, WorkerId::new(), key(4), 3_300).unwrap();
    assert!(matches!(
        authorize(&f, &fourth, WorkerId::new(), key(4), 3_300),
        Err(Error::Conflict)
    ));
}

#[test]
fn a_direct_enrollment_takes_no_key_and_redeems_without_one() {
    let f = fixture();
    let direct = issue(&f, policy(), false, 60_000);
    assert!(matches!(
        authorize(&f, &direct, WorkerId::new(), key(9), 1_100),
        Err(Error::InvalidInput(_))
    ));
    let worker = WorkerId::new();
    let enrolled = redeem_authorized(&f, &direct, worker, Secret::generate().digest(), 1_200)
        .unwrap()
        .unwrap();
    assert_eq!(enrolled.node_key, None);
    assert_eq!(enrolled.policy.priority, 25);

    // Only the platform authorizes a key, and the authorization is immutable through raw SQL.
    let tailcat = issue(&f, HostPolicy::default(), true, 60_000);
    let id = tailcat.id;
    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let refused = f.store.writer().write(move |tx| {
        workers::authorize_node_key(
            tx,
            Authority::credential(member),
            id,
            WorkerId::new(),
            key(5),
            at(1_300),
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    authorize(&f, &tailcat, WorkerId::new(), key(5), 1_300).unwrap();
    let raw = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE worker_enrollments SET authorized_node_key = zeroblob(32)",
            [],
        )?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
}
