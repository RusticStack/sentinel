//! Redeeming an enrollment over HTTPS (Q11): the secret authorizes the TLS fingerprint and the Tailcat
//! node key the machine presents, both bound to the pool in the one transaction that spends it.

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{PoolId, UnixMillis, WorkerId};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::Authority,
    local_auth,
    tenancy::{self, PoolKind},
    workers::{self, EnrollmentTerms, HostPolicy, NodeKey, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const LIFETIME_MS: i64 = 60_000;

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
    dir: tempfile::TempDir,
    store: Store,
    pool: PoolId,
}

fn create_pool(store: &Store, name: &'static str) -> PoolId {
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(tx, Authority::HostLocal, pool, name, PoolKind::Shared, NOW)
        })
        .unwrap();
    pool
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let pool = create_pool(&store, "builders");
    Fixture { dir, store, pool }
}

fn issue(store: &Store, pool: PoolId, tailcat: bool) -> workers::Enrollment {
    let terms = EnrollmentTerms {
        pool,
        lifetime_ms: LIFETIME_MS,
        policy: HostPolicy {
            cpu_millis: Some(4_000),
            memory_bytes: None,
            disk_bytes: None,
            priority: 3,
        },
        tailcat,
    };
    store
        .writer()
        .write(move |tx| workers::issue_enrollment_with(tx, Authority::HostLocal, terms, NOW))
        .unwrap()
}

fn secret_of(enrollment: &workers::Enrollment) -> Secret {
    let mut text = String::new();
    enrollment.secret.expose(&mut text);
    Secret::parse(&text).unwrap()
}

fn present(
    store: &Store,
    secret: Secret,
    worker: WorkerId,
    fp: Digest,
    node_key: Option<NodeKey>,
    now: i64,
) -> Result<Option<workers::Worker>, Error> {
    store.writer().write(move |tx| {
        workers::redeem_presented(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder",
                negotiated: negotiated(),
            },
            node_key,
            at(now),
        )
    })
}

fn refusals(store: &Store) -> usize {
    store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .iter()
        .filter(|row| row.event == local_auth::Event::WorkerEnrollmentRefused)
        .count()
}

fn status(f: &Fixture, enrollment: &workers::Enrollment) -> workers::EnrollmentState {
    let id = enrollment.id;
    f.store
        .read(|c| workers::enrollment_status(c, Authority::HostLocal, id, at(2_000)))
        .unwrap()
        .state
}

#[test]
fn one_redemption_binds_the_fingerprint_and_the_node_key_to_the_enrollments_pool() {
    let f = fixture();
    let other = create_pool(&f.store, "elsewhere");
    let enrollment = issue(&f.store, f.pool, true);
    let (worker, fp) = (WorkerId::new(), fingerprint());

    let enrolled = present(
        &f.store,
        secret_of(&enrollment),
        worker,
        fp,
        Some(key(7)),
        2_000,
    )
    .unwrap()
    .unwrap();
    assert_eq!((enrolled.id, enrolled.pool), (worker, f.pool));
    assert_eq!(enrolled.policy.cpu_millis, Some(4_000));
    assert_eq!(enrolled.policy.priority, 3);

    let known = f
        .store
        .read(|c| workers::authenticate_bound(c, &fp, &key(7)))
        .unwrap();
    assert_eq!((known.id, known.pool), (worker, f.pool));
    assert_eq!(
        f.store.read(workers::admitted_node_keys).unwrap(),
        vec![(worker, key(7))]
    );
    assert!(
        f.store
            .read(|c| workers::pending_node_keys(c, at(2_000)))
            .unwrap()
            .is_empty(),
        "a spent enrollment no longer holds a key"
    );
    assert_eq!(status(&f, &enrollment), workers::EnrollmentState::Redeemed);
    // The worker belongs to the enrollment's pool only.
    let in_pool = |pool| {
        f.store
            .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
            .unwrap()
    };
    assert_eq!(in_pool(f.pool).len(), 1);
    assert!(in_pool(other).is_empty());
}

#[test]
fn a_secret_is_single_use_for_every_other_machine() {
    let f = fixture();
    let enrollment = issue(&f.store, f.pool, true);
    let secret = || secret_of(&enrollment);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    present(&f.store, secret(), worker, fp, Some(key(1)), 2_000)
        .unwrap()
        .unwrap();

    // A second machine, a second key on the same identity, and a second identity on the same key.
    for (id, print, node) in [
        (WorkerId::new(), fingerprint(), key(2)),
        (worker, fp, key(2)),
        (worker, fingerprint(), key(1)),
        (WorkerId::new(), fp, key(1)),
    ] {
        assert!(
            present(&f.store, secret(), id, print, Some(node), 2_500)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        f.store
            .read(|c| workers::in_pool(c, Authority::HostLocal, f.pool))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn the_same_machine_may_repeat_the_call_whose_answer_was_lost_but_only_for_a_while() {
    let f = fixture();
    let enrollment = issue(&f.store, f.pool, true);
    let secret = || secret_of(&enrollment);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    let first = present(&f.store, secret(), worker, fp, Some(key(5)), 2_000)
        .unwrap()
        .unwrap();

    let again = present(&f.store, secret(), worker, fp, Some(key(5)), 3_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        (again.id, again.pool, again.node_key),
        (first.id, first.pool, first.node_key)
    );
    assert_eq!(
        f.store
            .read(|c| workers::in_pool(c, Authority::HostLocal, f.pool))
            .unwrap()
            .len(),
        1,
        "a replay creates nothing"
    );

    let late = 2_000 + workers::REPLAY_WINDOW_MS + 1;
    assert!(
        present(&f.store, secret(), worker, fp, Some(key(5)), late)
            .unwrap()
            .is_none()
    );

    // A revoked machine is not answered either.
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, at(3_500)))
        .unwrap();
    assert!(
        present(&f.store, secret(), worker, fp, Some(key(5)), 4_000)
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_expired_withdrawn_or_wrong_secret_is_refused_and_leaves_nothing_behind() {
    let f = fixture();
    let expired = issue(&f.store, f.pool, false);
    let withdrawn = issue(&f.store, f.pool, false);
    let id = withdrawn.id;
    f.store
        .writer()
        .write(move |tx| workers::revoke_enrollment(tx, Authority::HostLocal, id, at(1_500)))
        .unwrap();

    let after_expiry = NOW.0 + LIFETIME_MS;
    for (secret, when) in [
        (secret_of(&expired), after_expiry),
        (secret_of(&withdrawn), 2_000),
        (Secret::generate(), 2_000),
    ] {
        assert!(
            present(&f.store, secret, WorkerId::new(), fingerprint(), None, when)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        present(
            &f.store,
            secret_of(&expired),
            WorkerId::new(),
            fingerprint(),
            None,
            after_expiry - 1
        )
        .unwrap()
        .is_some(),
        "the last millisecond still redeems"
    );
    assert_eq!(status(&f, &withdrawn), workers::EnrollmentState::Revoked);
}

#[test]
fn an_enrollment_of_a_deactivated_pool_is_refused() {
    let f = fixture();
    let enrollment = issue(&f.store, f.pool, false);
    let pool = f.pool;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE pools SET active = 0 WHERE id = ?1",
                [pool.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(
        present(
            &f.store,
            secret_of(&enrollment),
            WorkerId::new(),
            fingerprint(),
            None,
            2_000
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(status(&f, &enrollment), workers::EnrollmentState::Pending);
}

#[test]
fn the_transport_must_match_what_the_enrollment_was_issued_for() {
    let f = fixture();
    let tailcat = issue(&f.store, f.pool, true);
    let direct = issue(&f.store, f.pool, false);
    assert!(
        present(
            &f.store,
            secret_of(&tailcat),
            WorkerId::new(),
            fingerprint(),
            None,
            2_000
        )
        .unwrap()
        .is_none(),
        "a Tailcat enrollment needs the node key"
    );
    assert!(
        present(
            &f.store,
            secret_of(&direct),
            WorkerId::new(),
            fingerprint(),
            Some(key(1)),
            2_000
        )
        .unwrap()
        .is_none(),
        "a direct enrollment takes none"
    );
    assert_eq!(status(&f, &tailcat), workers::EnrollmentState::Pending);
    assert_eq!(status(&f, &direct), workers::EnrollmentState::Pending);
}

#[test]
fn a_taken_identity_or_key_leaves_the_enrollment_for_the_real_machine() {
    let f = fixture();
    let first = issue(&f.store, f.pool, true);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    present(&f.store, secret_of(&first), worker, fp, Some(key(1)), 2_000)
        .unwrap()
        .unwrap();

    let second = issue(&f.store, f.pool, true);
    // The fingerprint, the worker identifier and the node key of a bound machine are each taken.
    for (id, print, node) in [
        (WorkerId::new(), fp, key(2)),
        (worker, fingerprint(), key(2)),
        (WorkerId::new(), fingerprint(), key(1)),
    ] {
        assert!(matches!(
            present(&f.store, secret_of(&second), id, print, Some(node), 2_500),
            Err(Error::Conflict)
        ));
        assert_eq!(status(&f, &second), workers::EnrollmentState::Pending);
    }
    assert!(
        present(
            &f.store,
            secret_of(&second),
            WorkerId::new(),
            fingerprint(),
            Some(key(2)),
            2_600
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn a_key_an_administrator_authorized_is_redeemed_by_that_identifier_and_key_only() {
    let f = fixture();
    let enrollment = issue(&f.store, f.pool, true);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    let id = enrollment.id;
    f.store
        .writer()
        .write(move |tx| {
            workers::authorize_node_key(tx, Authority::HostLocal, id, worker, key(4), at(1_500))
        })
        .unwrap();

    for (who, node) in [(WorkerId::new(), key(4)), (worker, key(5))] {
        assert!(
            present(
                &f.store,
                secret_of(&enrollment),
                who,
                fingerprint(),
                Some(node),
                2_000
            )
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(status(&f, &enrollment), workers::EnrollmentState::Pending);
    present(
        &f.store,
        secret_of(&enrollment),
        worker,
        fp,
        Some(key(4)),
        2_100,
    )
    .unwrap()
    .unwrap();

    // A key reserved for another pending enrollment is not claimable through this one.
    let reserved = issue(&f.store, f.pool, true);
    let free = issue(&f.store, f.pool, true);
    let (holder, rid) = (WorkerId::new(), reserved.id);
    f.store
        .writer()
        .write(move |tx| {
            workers::authorize_node_key(tx, Authority::HostLocal, rid, holder, key(6), at(2_200))
        })
        .unwrap();
    assert!(matches!(
        present(
            &f.store,
            secret_of(&free),
            WorkerId::new(),
            fingerprint(),
            Some(key(6)),
            2_300
        ),
        Err(Error::Conflict)
    ));
}

#[test]
fn a_failure_between_the_steps_spends_nothing_and_survives_a_restart() {
    let f = fixture();
    let enrollment = issue(&f.store, f.pool, true);
    let (worker, fp) = (WorkerId::new(), fingerprint());
    let secret = secret_of(&enrollment);

    // The redemption is applied and then the transaction fails before it commits, as a crash would.
    let attempt = f.store.writer().write(move |tx| {
        let enrolled = workers::redeem_presented(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder",
                negotiated: negotiated(),
            },
            Some(key(1)),
            at(2_000),
        )?;
        assert!(enrolled.is_some());
        Err::<(), _>(Error::Conflict)
    });
    assert!(attempt.is_err());
    assert_eq!(status(&f, &enrollment), workers::EnrollmentState::Pending);
    assert!(
        f.store
            .read(workers::admitted_node_keys)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fp)),
        Err(Error::NotFound)
    ));

    // The same state after the controller restarts: the enrollment is still redeemable, exactly once.
    let Fixture { dir, store, pool } = f;
    drop(store);
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    assert!(
        present(
            &store,
            secret_of(&enrollment),
            worker,
            fp,
            Some(key(1)),
            3_000
        )
        .unwrap()
        .is_some()
    );
    drop(store);
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    assert_eq!(
        store
            .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.read(workers::admitted_node_keys).unwrap(),
        vec![(worker, key(1))]
    );
    assert!(
        present(
            &store,
            secret_of(&enrollment),
            WorkerId::new(),
            fingerprint(),
            Some(key(2)),
            3_100
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn refused_secrets_write_a_bounded_number_of_audit_rows() {
    let f = fixture();
    for _ in 0..(workers::REFUSAL_ROWS_PER_PEER * 5) {
        assert!(
            present(
                &f.store,
                Secret::generate(),
                WorkerId::new(),
                fingerprint(),
                None,
                2_000
            )
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(refusals(&f.store), workers::REFUSAL_ROWS_PER_PEER as usize);

    // A legitimate redemption still audits itself after the flood.
    let enrollment = issue(&f.store, f.pool, false);
    present(
        &f.store,
        secret_of(&enrollment),
        WorkerId::new(),
        fingerprint(),
        None,
        2_100,
    )
    .unwrap()
    .unwrap();
    let rows = f.store.read(|c| local_auth::recent_audit(c, 5)).unwrap();
    assert_eq!(rows[0].event, local_auth::Event::WorkerEnrolled);
}
