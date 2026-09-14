//! G02 store behavior: acceptance is deduplicated and bounded, hook secrets
//! are digest-only and rotatable, GitHub targets resolve only through a bound
//! installation, and resolution settles every case with an explicit reason
//! under a bounded retry budget.
use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, Accepted, NewDelivery, Resolution, State},
    registration::{self, Authority},
    sources::{self, Update},
    sources_forge,
};

const NOW: UnixMillis = UnixMillis(1_000);
const REF: &str = "refs/heads/main";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_ZERO: &str = "0000000000000000000000000000000000000000";

struct Fixture {
    conn: Connection,
    key: Key,
    _dir: tempfile::TempDir,
    alice: Principal,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        alice,
        tenant,
        Namespace::parse("alice").unwrap(),
        NamespaceKind::Personal(alice.user),
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, alice, tenant, repo, "app", NOW).unwrap();
    tx.commit().unwrap();
    let mut f = Fixture {
        conn,
        key,
        _dir: dir,
        alice,
        tenant,
        repo,
    };
    bind(&mut f, 0);
    f
}

fn binding(remote: &str) -> Binding {
    Binding {
        remote: remote.into(),
        allowed_refs: vec![REF.into(), "refs/tags/v*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    }
}

fn bind(f: &mut Fixture, expected: u64) -> u64 {
    let tx = f.conn.transaction().unwrap();
    let version = sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        Update {
            repo: f.repo,
            expected,
            binding: &binding("https://git.example:8443/team/repo.git"),
            credential: &Credential::Https {
                username: "deploy".into(),
                secret: "deploy-token".into(),
            },
            forge: None,
        },
        &["https://git.example:8443".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    version
}

fn accept_with(
    f: &mut Fixture,
    external_id: &str,
    ref_name: &str,
    old: &str,
    new: &str,
) -> Result<Accepted, Error> {
    let tx = f.conn.transaction().unwrap();
    match intake::accept(
        &tx,
        f.repo,
        &NewDelivery {
            provider: "generic",
            external_id,
            event: "ref_update",
            ref_name,
            old_sha: old,
            new_sha: new,
        },
        NOW,
    ) {
        Ok(accepted) => {
            tx.commit().unwrap();
            Ok(accepted)
        }
        Err(error) => {
            tx.rollback().unwrap();
            Err(error)
        }
    }
}

fn accept(f: &mut Fixture, external_id: &str, ref_name: &str, old: &str, new: &str) -> Accepted {
    accept_with(f, external_id, ref_name, old, new).unwrap()
}

fn accept_err(f: &mut Fixture, external_id: &str, ref_name: &str, new: &str) -> Error {
    accept_with(f, external_id, ref_name, SHA_A, new).unwrap_err()
}

fn fetch(f: &Fixture, id: DeliveryId) -> intake::Delivery {
    intake::get(&f.conn, id).unwrap()
}

fn count(f: &Fixture) -> i64 {
    f.conn
        .query_row("SELECT count(*) FROM webhook_deliveries", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn acceptance_is_deduplicated_and_redelivery_is_an_acknowledgement() {
    let mut f = fixture();
    let Accepted::Fresh(id) = accept(&mut f, "push-1", REF, SHA_A, SHA_B) else {
        panic!("first acceptance must be fresh");
    };
    assert_eq!(fetch(&f, id).state, State::Pending);
    // Redelivery with identical terms: acknowledged, nothing new stored.
    assert_eq!(
        accept(&mut f, "push-1", REF, SHA_A, SHA_B),
        Accepted::Duplicate(id)
    );
    assert_eq!(count(&f), 1);
    assert_eq!(fetch(&f, id).state, State::Pending);
    // The same identity with different content is a sender bug, not a replay.
    assert!(matches!(
        accept_err(&mut f, "push-1", "refs/heads/other", SHA_B),
        Error::Conflict
    ));
    // The same content under a new identity is a distinct transition: a ref
    // returning to an earlier commit is reported, not deduplicated away.
    let Accepted::Fresh(second) = accept(&mut f, "push-2", REF, SHA_B, SHA_A) else {
        panic!("distinct delivery must be fresh");
    };
    assert_ne!(second, id);

    // A revoked binding refuses events and loses its hook secret in the same
    // transaction.
    let tx = f.conn.transaction().unwrap();
    intake::issue_token(&tx, Authority::HostLocal, f.repo, NOW).unwrap();
    sources::revoke(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        f.repo,
        1,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(intake::token_issued(&f.conn, f.repo).unwrap().is_none());
    assert!(matches!(
        accept_err(&mut f, "push-3", REF, SHA_B),
        Error::Forbidden
    ));
}

#[test]
fn malformed_terms_are_refused_before_anything_is_stored() {
    let mut f = fixture();
    let uppercase = SHA_A.to_uppercase();
    for (id, ref_name, new) in [
        ("", REF, SHA_A),
        ("has space", REF, SHA_A),
        ("ok", "not-a-ref", SHA_A),
        ("ok", REF, "zzzz"),
        ("ok", REF, uppercase.as_str()),
    ] {
        let error = accept_err(&mut f, id, ref_name, new);
        assert!(
            matches!(error, Error::InvalidInput(_)),
            "{id:?} {ref_name:?} {new:?}: {error:?}"
        );
    }
    assert_eq!(count(&f), 0);
}

#[test]
fn the_admission_bound_refuses_new_events_but_still_acknowledges_duplicates() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    for index in 0..intake::MAX_PENDING_PER_REPO {
        tx.execute(
            "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
                event, ref_name, old_sha, new_sha, state, received_ms)
             VALUES (?1, ?2, ?3, 'generic', ?4, 'ref_update', ?5, ?6, ?7, 0, ?8)",
            rusqlite::params![
                DeliveryId::new().as_bytes(),
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                format!("filler-{index}"),
                REF,
                SHA_A,
                SHA_B,
                NOW.0
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    assert!(matches!(
        accept_err(&mut f, "one-too-many", REF, SHA_B),
        Error::Overloaded
    ));
    // A duplicate of a pending delivery is not new work: it stays an
    // acknowledgement even at the bound.
    let existing: DeliveryId = f
        .conn
        .query_row(
            "SELECT id FROM webhook_deliveries WHERE external_id = 'filler-0'",
            [],
            |r| r.get::<_, [u8; 16]>(0),
        )
        .map(|bytes| DeliveryId::from_bytes(bytes).unwrap())
        .unwrap();
    assert_eq!(
        accept(&mut f, "filler-0", REF, SHA_A, SHA_B),
        Accepted::Duplicate(existing)
    );
}

#[test]
fn hook_secrets_are_digest_only_rotatable_and_revocable() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    let first = intake::issue_token(&tx, Authority::credential(f.alice), f.repo, NOW).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        intake::authenticate(&f.conn, &first).unwrap(),
        Some((f.tenant, f.repo))
    );
    assert_eq!(intake::token_issued(&f.conn, f.repo).unwrap(), Some(NOW));
    // Digest only: the stored blob is not the secret's text form.
    let stored: Vec<u8> = f
        .conn
        .query_row("SELECT token_digest FROM source_intake_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(stored.len(), 32);
    let mut text = String::new();
    first.expose(&mut text);
    assert_ne!(stored, text.as_bytes());
    // An unrelated secret authenticates nothing.
    assert_eq!(
        intake::authenticate(&f.conn, &sentinel_auth::secret::Secret::generate()).unwrap(),
        None
    );

    // Rotation: the previous secret stops working the moment it commits.
    let tx = f.conn.transaction().unwrap();
    let second = intake::issue_token(&tx, Authority::HostLocal, f.repo, NOW).unwrap();
    tx.commit().unwrap();
    assert_eq!(intake::authenticate(&f.conn, &first).unwrap(), None);
    assert_eq!(
        intake::authenticate(&f.conn, &second).unwrap(),
        Some((f.tenant, f.repo))
    );

    // Revocation is final, and revoking nothing is NotFound.
    let tx = f.conn.transaction().unwrap();
    intake::revoke_token(&tx, Authority::HostLocal, f.repo, NOW).unwrap();
    tx.commit().unwrap();
    assert_eq!(intake::authenticate(&f.conn, &second).unwrap(), None);
    assert!(intake::token_issued(&f.conn, f.repo).unwrap().is_none());
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        intake::revoke_token(&tx, Authority::HostLocal, f.repo, NOW),
        Err(Error::NotFound)
    ));
    tx.rollback().unwrap();

    // Attribution is audited: the credentialed issue names the account, the
    // host-local ones name nobody.
    let (action, actor): (String, Option<[u8; 16]>) = f
        .conn
        .query_row(
            "SELECT action, actor FROM source_audit WHERE action = 'hook-token' ORDER BY seq LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(action, "hook-token");
    assert_eq!(actor, Some(*f.alice.user.as_bytes()));

    // A suspended tenant's secret authenticates nothing.
    let tx = f.conn.transaction().unwrap();
    let third = intake::issue_token(&tx, Authority::HostLocal, f.repo, NOW).unwrap();
    tx.commit().unwrap();
    f.conn
        .execute(
            "UPDATE tenants SET active = 0 WHERE id = ?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();
    assert_eq!(intake::authenticate(&f.conn, &third).unwrap(), None);
}

#[test]
fn github_targets_resolve_only_through_a_bound_installation() {
    let mut f = fixture();
    let snapshot = |expected, suspended| sources_forge::Snapshot {
        external_id: 42,
        account_id: 73,
        login: "account",
        personal: false,
        suspended,
        permissions_valid: true,
        expected,
    };
    // A known installation, before any binding: authorizes nothing.
    let tx = f.conn.transaction().unwrap();
    let installation = sources_forge::refresh(&tx, snapshot(0, false), NOW).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        intake::github_target(&f.conn, "42", 91),
        Err(Error::NotFound)
    ));
    let tx = f.conn.transaction().unwrap();
    registration::bind_installation_trusted(&tx, installation, f.tenant, NOW).unwrap();
    let forge = binding("https://github.com/account/repo.git");
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        Update {
            repo: f.repo,
            expected: 1,
            binding: &forge,
            credential: &Credential::Public,
            forge: Some((installation, 91)),
        },
        &["https://github.com".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        intake::github_target(&f.conn, "42", 91).unwrap(),
        (f.tenant, f.repo)
    );
    // A different repository or installation resolves nothing.
    assert!(matches!(
        intake::github_target(&f.conn, "42", 92),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        intake::github_target(&f.conn, "43", 91),
        Err(Error::NotFound)
    ));
    // A suspended installation authorizes nothing.
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(1, true), NOW).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        intake::github_target(&f.conn, "42", 91),
        Err(Error::NotFound)
    ));
    // A revoked binding authorizes nothing.
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(2, false), NOW).unwrap();
    sources::revoke(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        f.repo,
        2,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        intake::github_target(&f.conn, "42", 91),
        Err(Error::NotFound)
    ));
    // A suspended tenant authorizes nothing either.
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(3, false), NOW).unwrap();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        Update {
            repo: f.repo,
            expected: 3,
            binding: &forge,
            credential: &Credential::Public,
            forge: Some((installation, 91)),
        },
        &["https://github.com".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    f.conn
        .execute(
            "UPDATE tenants SET active = 0 WHERE id = ?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        intake::github_target(&f.conn, "42", 91),
        Err(Error::NotFound)
    ));
}

#[test]
fn resolution_settles_every_case_with_an_explicit_reason() {
    let mut f = fixture();
    let _ = accept(&mut f, "suspended-1", REF, SHA_A, SHA_B);
    let _ = accept(&mut f, "suspended-2", REF, SHA_B, SHA_ZERO);
    let _ = accept(&mut f, "suspended-3", "refs/heads/other", SHA_A, SHA_B);

    // Suspended tenant first: everything due fails with that reason.
    f.conn
        .execute(
            "UPDATE tenants SET active = 0 WHERE id = ?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    let settled = intake::resolve_due(&tx, NOW, 10).unwrap();
    tx.commit().unwrap();
    assert_eq!(settled.len(), 3);
    assert!(
        settled
            .iter()
            .all(|(_, r)| *r == Resolution::Failed("tenant_suspended")),
        "{settled:?}"
    );
    f.conn
        .execute(
            "UPDATE tenants SET active = 1 WHERE id = ?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();

    // A fresh batch: an allowed ref is ready, a deletion is ignored, and a
    // ref the binding never allowed is an explicit failure.
    let ready = accept(&mut f, "ready", REF, SHA_A, SHA_B).id();
    let deleted = accept(&mut f, "deleted", REF, SHA_B, SHA_ZERO).id();
    let other = accept(&mut f, "other", "refs/heads/other", SHA_A, SHA_B).id();
    let tx = f.conn.transaction().unwrap();
    let settled = intake::resolve_due(&tx, NOW, 10).unwrap();
    tx.commit().unwrap();
    let reason = |id: DeliveryId| {
        settled
            .iter()
            .find(|(delivery, _)| *delivery == id)
            .map(|(_, r)| *r)
            .unwrap()
    };
    assert_eq!(reason(ready), Resolution::Ready);
    assert_eq!(reason(deleted), Resolution::Ignored("ref_deleted"));
    assert_eq!(reason(other), Resolution::Failed("ref_not_allowed"));
    assert_eq!(fetch(&f, ready).state, State::Ready);
    assert_eq!(fetch(&f, ready).settled, Some(NOW));
    assert_eq!(fetch(&f, ready).reason, None);
    assert_eq!(fetch(&f, deleted).state, State::Ignored);
    assert_eq!(fetch(&f, other).reason.as_deref(), Some("ref_not_allowed"));

    // Settling a settled delivery is a conflict, not a rewrite.
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        intake::settle(&tx, ready, Resolution::Ready, NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();

    // A binding revoked after acceptance fails on the next resolution.
    let revoked = accept(&mut f, "revoked", REF, SHA_A, SHA_B).id();
    let tx = f.conn.transaction().unwrap();
    sources::revoke(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        f.repo,
        1,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    let tx = f.conn.transaction().unwrap();
    let settled = intake::resolve_due(&tx, NOW, 10).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        settled
            .iter()
            .find(|(id, _)| *id == revoked)
            .map(|(_, r)| *r),
        Some(Resolution::Failed("binding_revoked"))
    );
}

#[test]
fn retries_back_off_doubling_and_stop_at_the_attempt_budget() {
    let mut f = fixture();
    let accepted = accept(&mut f, "retry", REF, SHA_A, SHA_B).id();
    // A retry is invisible to `due` until its next attempt is reached.
    let tx = f.conn.transaction().unwrap();
    intake::retry(&tx, accepted, NOW).unwrap();
    tx.commit().unwrap();
    assert_eq!(fetch(&f, accepted).attempts, 1);
    assert!(intake::due(&f.conn, NOW, 10).unwrap().is_empty());
    let later = UnixMillis(NOW.0 + intake::backoff_ms(1));
    assert_eq!(intake::due(&f.conn, later, 10).unwrap().len(), 1);

    for attempt in 2..intake::MAX_ATTEMPTS {
        let tx = f.conn.transaction().unwrap();
        intake::retry(&tx, accepted, NOW).unwrap();
        tx.commit().unwrap();
        assert_eq!(fetch(&f, accepted).attempts, attempt);
    }
    // At the budget the delivery fails with an explicit reason instead of
    // being retried forever.
    let tx = f.conn.transaction().unwrap();
    intake::retry(&tx, accepted, NOW).unwrap();
    tx.commit().unwrap();
    let delivery = fetch(&f, accepted);
    assert_eq!(delivery.state, State::Failed);
    assert_eq!(delivery.reason.as_deref(), Some("resolution_attempts"));
    assert_eq!(delivery.settled, Some(NOW));
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        intake::retry(&tx, accepted, NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
    assert_eq!(intake::backoff_ms(1), 2_000);
    assert_eq!(intake::backoff_ms(20), 5 * 60 * 1000);
}

#[test]
fn retention_purges_settled_rows_only_and_terms_cannot_be_rewritten() {
    let mut f = fixture();
    let settled = accept(&mut f, "settled", REF, SHA_A, SHA_B).id();
    let pending = accept(&mut f, "pending", REF, SHA_A, SHA_B).id();
    let tx = f.conn.transaction().unwrap();
    intake::settle(&tx, settled, Resolution::Ready, NOW).unwrap();
    tx.commit().unwrap();
    // Nothing is old enough yet.
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(NOW.0 - 1), 10).unwrap(),
        0
    );
    tx.rollback().unwrap();
    // A sweep past the retention removes only the settled row.
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(NOW.0 + 1), 10).unwrap(),
        1
    );
    tx.commit().unwrap();
    assert!(matches!(
        intake::get(&f.conn, settled),
        Err(Error::NotFound)
    ));
    assert_eq!(fetch(&f, pending).state, State::Pending);
    // The terms of a stored delivery are immutable, through raw SQL too.
    for sql in [
        "UPDATE webhook_deliveries SET ref_name = 'refs/heads/rewritten'",
        "UPDATE webhook_deliveries SET external_id = 'rewritten'",
        "UPDATE webhook_deliveries SET received_ms = received_ms + 1",
    ] {
        assert!(
            f.conn.execute(sql, []).is_err(),
            "raw SQL rewrote delivery terms: {sql}"
        );
    }
}
