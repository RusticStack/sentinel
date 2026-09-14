//! G02/G03 store behavior: acceptance is deduplicated and bounded, hook
//! secrets are digest-only and rotatable, GitHub targets resolve only through
//! a bound installation, resolution settles every case with an explicit reason
//! under a bounded retry budget, and a ready delivery dispatches one immutable
//! run with its provenance.
use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, Accepted, NewDelivery, Resolution, State},
    provenance,
    registration::{self, Authority},
    runs,
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
    /// A second repository of the same tenant: ownership mismatch cases.
    other: RepoId,
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
    let (tenant, repo, other) = (TenantId::new(), RepoId::new(), RepoId::new());
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
    auth::create_repo(&tx, alice, tenant, other, "other", NOW).unwrap();
    tx.commit().unwrap();
    let mut f = Fixture {
        conn,
        key,
        _dir: dir,
        alice,
        tenant,
        repo,
        other,
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
        None,
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

    // A ready delivery is still open: the dispatch lane may settle it as
    // ignored or failed, and once terminal it cannot be settled again.
    let tx = f.conn.transaction().unwrap();
    intake::settle(&tx, ready, Resolution::Ignored("dispatch_skipped"), NOW).unwrap();
    tx.commit().unwrap();
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
    assert!(
        intake::due(&f.conn, State::Pending, NOW, 10)
            .unwrap()
            .is_empty()
    );
    let later = UnixMillis(NOW.0 + intake::backoff_ms(1));
    assert_eq!(
        intake::due(&f.conn, State::Pending, later, 10)
            .unwrap()
            .len(),
        1
    );

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
    let ready = accept(&mut f, "ready", REF, SHA_A, SHA_B).id();
    let tx = f.conn.transaction().unwrap();
    // One terminal row, one open row awaiting dispatch: retention must keep
    // the open one, because an unresolved event is work, not history.
    intake::settle(&tx, settled, Resolution::Ignored("expired"), NOW).unwrap();
    intake::settle(&tx, ready, Resolution::Ready, NOW).unwrap();
    tx.commit().unwrap();
    // Nothing is old enough yet.
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(NOW.0 - 1), 10).unwrap(),
        0
    );
    tx.rollback().unwrap();
    // A sweep past the retention removes only the terminal row.
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
    assert_eq!(fetch(&f, ready).state, State::Ready);
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

const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccc";
const GITHUB_REPO_ID: u64 = 91;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn spec(pinned: bool) -> RunSpec {
    let image = if pinned {
        IMAGE
    } else {
        "docker.io/library/busybox:latest"
    };
    let yaml = format!(
        "schema: 1\non: [push, tag, pull_request, manual]\njobs:\n  build:\n    image: {image}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new("https://git.example:8443/team/repo.git", SHA_B, Some(REF)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

/// Accept, validate and dispatch one delivery, as the lane would.
fn dispatch_ready(
    f: &mut Fixture,
    id: &str,
    old: &str,
    new: &str,
    pipeline_sha: &str,
    at: UnixMillis,
) -> DeliveryId {
    let accepted = accept(f, id, REF, old, new).id();
    let tx = f.conn.transaction().unwrap();
    intake::resolve_due(&tx, at, 10).unwrap();
    tx.commit().unwrap();
    let delivery = fetch(f, accepted);
    assert_eq!(delivery.state, State::Ready, "{delivery:?}");
    let run_spec = spec(true);
    let images = runs::pinned_images(&run_spec).unwrap();
    let provenance = provenance::Provenance {
        tenant: f.tenant,
        repo: f.repo,
        trigger: "push".into(),
        delivery: Some(accepted),
        provider: Some("generic".into()),
        ref_name: Some(REF.into()),
        old_sha: Some(old.into()),
        new_sha: Some(new.into()),
        head_sha: None,
        base_sha: None,
        merge_sha: None,
        pipeline_sha: pipeline_sha.into(),
        pipeline_path: Some(".sentinel.yml".into()),
        pipeline_digest: run_spec.pipeline.digest.to_le_bytes(),
        pr_number: None,
    };
    let tx = f.conn.transaction().unwrap();
    intake::dispatch(&tx, &delivery, &run_spec, &images, &provenance, at).unwrap();
    tx.commit().unwrap();
    accepted
}

fn accept_pr(f: &mut Fixture, id: &str, terms: &intake::PrTerms<'_>) -> Result<Accepted, Error> {
    let tx = f.conn.transaction().unwrap();
    let base_ref = format!("refs/heads/{}", terms.base_ref);
    let outcome = intake::accept(
        &tx,
        f.repo,
        &NewDelivery {
            provider: "github",
            external_id: id,
            event: "pull_request",
            ref_name: &base_ref,
            old_sha: terms.base_sha,
            new_sha: terms.merge_sha.unwrap_or(terms.head_sha),
        },
        Some(terms),
        NOW,
    );
    match outcome {
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

fn pr_terms<'a>(head_repo: u64, merge: Option<&'a str>) -> intake::PrTerms<'a> {
    intake::PrTerms {
        number: 7,
        action: "opened",
        draft: false,
        head_ref: "feature",
        head_sha: SHA_A,
        head_repo,
        base_ref: "main",
        base_sha: SHA_B,
        merge_sha: merge,
    }
}

#[test]
fn a_ready_delivery_dispatches_one_immutable_run_with_its_provenance() {
    let mut f = fixture();
    let accepted = accept(&mut f, "run-1", REF, SHA_A, SHA_B).id();
    let tx = f.conn.transaction().unwrap();
    intake::resolve_due(&tx, NOW, 10).unwrap();
    tx.commit().unwrap();
    let delivery = fetch(&f, accepted);
    assert_eq!(delivery.state, State::Ready);

    let run_spec = spec(true);
    let images = runs::pinned_images(&run_spec).unwrap();
    let provenance = provenance::Provenance {
        tenant: f.tenant,
        repo: f.repo,
        trigger: "push".into(),
        delivery: Some(accepted),
        provider: Some("generic".into()),
        ref_name: Some(REF.into()),
        old_sha: Some(SHA_A.into()),
        new_sha: Some(SHA_B.into()),
        head_sha: None,
        base_sha: None,
        merge_sha: None,
        pipeline_sha: SHA_B.into(),
        pipeline_path: Some(".sentinel.yml".into()),
        pipeline_digest: run_spec.pipeline.digest.to_le_bytes(),
        pr_number: None,
    };
    let tx = f.conn.transaction().unwrap();
    let run = intake::dispatch(&tx, &delivery, &run_spec, &images, &provenance, NOW).unwrap();
    tx.commit().unwrap();

    // The delivery is terminal and names its run.
    let delivery = fetch(&f, accepted);
    assert_eq!(delivery.state, State::Dispatched);
    assert_eq!(delivery.run, Some(run));
    // The run holds the immutable spec and a resolved image per job.
    let stored = runs::get_run_spec(&f.conn, f.tenant, run).unwrap();
    assert_eq!(stored.source.sha, SHA_B);
    assert_eq!(stored.pipeline.digest, run_spec.pipeline.digest);
    let job: [u8; 16] = f
        .conn
        .query_row(
            "SELECT id FROM jobs WHERE run_id = ?1",
            [run.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    let job = sentinel_core::JobId::from_bytes(job).unwrap();
    let resolved = runs::resolved_image(&f.conn, f.tenant, job).unwrap();
    assert_eq!(resolved.platform, "linux/amd64");
    assert!(resolved.digest.starts_with("sha256:"));
    // Provenance is written once and cannot be rewritten or deleted.
    let recorded = provenance::of_run(&f.conn, run).unwrap().unwrap();
    assert_eq!(recorded.trigger, "push");
    assert_eq!(recorded.delivery, Some(accepted));
    assert_eq!(recorded.new_sha.as_deref(), Some(SHA_B));
    assert_eq!(recorded.pipeline_sha, SHA_B);
    assert_eq!(recorded.pipeline_path.as_deref(), Some(".sentinel.yml"));
    assert_eq!(recorded.tenant, f.tenant);
    for sql in [
        "UPDATE run_provenance SET trigger = 'tag'",
        "DELETE FROM run_provenance",
    ] {
        assert!(
            f.conn.execute(sql, []).is_err(),
            "raw SQL rewrote provenance: {sql}"
        );
    }
    // Provenance must belong to the run it names — the run's repository, not
    // just its tenant — and a delivery's run binding is part of its terms.
    let foreign = RunId::new();
    f.conn
        .execute(
            "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                foreign.as_bytes(),
                f.tenant.as_bytes(),
                f.other.as_bytes(),
                SHA_B,
                NOW.0
            ],
        )
        .unwrap();
    assert!(
        f.conn
            .execute(
                "INSERT INTO run_provenance(run_id, tenant_id, repo_id, trigger, pipeline_sha,
                    pipeline_digest, created_ms)
                 VALUES (?1, ?2, ?3, 'push', ?4, ?5, ?6)",
                rusqlite::params![
                    foreign.as_bytes(),
                    f.tenant.as_bytes(),
                    f.repo.as_bytes(),
                    SHA_B,
                    vec![0u8; 16],
                    NOW.0
                ],
            )
            .is_err(),
        "provenance must name the run's own repository"
    );
    assert!(
        f.conn
            .execute(
                "UPDATE webhook_deliveries SET run_id = ?2 WHERE id = ?1",
                rusqlite::params![accepted.as_bytes(), foreign.as_bytes()],
            )
            .is_err(),
        "a delivery's run binding is part of its terms"
    );
    // The worker context reads the event facts: a push names its branch.
    let facts = provenance::event_facts(&f.conn, run).unwrap();
    assert_eq!(facts.name, "push");
    assert_eq!(facts.ref_name, REF);
    assert_eq!(facts.key, "main");
    assert!(facts.base_ref.is_none() && facts.pr_number.is_none());
    // A run with no provenance is the manual mode, not an invented event.
    let orphan = RunId::new();
    f.conn
        .execute(
            "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![orphan.as_bytes(), f.tenant.as_bytes(), f.repo.as_bytes(), SHA_B, NOW.0],
        )
        .unwrap();
    let facts = provenance::event_facts(&f.conn, orphan).unwrap();
    assert_eq!(facts.name, "manual");
    assert_eq!(facts.key, "manual");

    // Dispatching the same delivery twice cannot create a second run.
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        intake::dispatch(&tx, &delivery, &run_spec, &images, &provenance, NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
    // Retention keeps a delivery a run's provenance depends on.
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(NOW.0 + 1), 10).unwrap(),
        0
    );
    tx.rollback().unwrap();
    let runs: i64 = f
        .conn
        .query_row("SELECT count(*) FROM runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        runs, 3,
        "the dispatched run, the manual-mode orphan and the ownership fixture"
    );
}

#[test]
fn the_duplicate_and_reordered_policy_compares_within_one_stream() {
    let mut f = fixture();
    let first = dispatch_ready(&mut f, "a", SHA_A, SHA_B, SHA_B, NOW);
    let second = dispatch_ready(&mut f, "b", SHA_B, SHA_C, SHA_C, UnixMillis(NOW.0 + 10));
    // The newest dispatched transition of the branch is the second one.
    assert_eq!(
        intake::last_dispatched(&f.conn, f.tenant, f.repo, REF, false)
            .unwrap()
            .unwrap()
            .id,
        second
    );
    assert_ne!(first, second);
    // A pull request targeting the same branch is a separate stream: its
    // transition never compares against the push stream.
    let pr = accept_pr(&mut f, "pr-1", &pr_terms(GITHUB_REPO_ID, Some(SHA_A))).unwrap();
    assert_eq!(
        intake::last_dispatched(&f.conn, f.tenant, f.repo, REF, true)
            .unwrap()
            .map(|d| d.id),
        None
    );
    let tx = f.conn.transaction().unwrap();
    intake::settle(&tx, pr.id(), Resolution::Ready, NOW).unwrap();
    tx.commit().unwrap();
    let run_spec = spec(true);
    let images = runs::pinned_images(&run_spec).unwrap();
    let delivery = fetch(&f, pr.id());
    let provenance = provenance::Provenance {
        tenant: f.tenant,
        repo: f.repo,
        trigger: "pull_request".into(),
        delivery: Some(pr.id()),
        provider: Some("github".into()),
        ref_name: Some(REF.into()),
        old_sha: Some(SHA_B.into()),
        new_sha: Some(SHA_A.into()),
        head_sha: Some(SHA_A.into()),
        base_sha: Some(SHA_B.into()),
        merge_sha: Some(SHA_A.into()),
        pipeline_sha: SHA_A.into(),
        pipeline_path: Some(".sentinel.yml".into()),
        pipeline_digest: run_spec.pipeline.digest.to_le_bytes(),
        pr_number: Some(7),
    };
    let tx = f.conn.transaction().unwrap();
    intake::dispatch(&tx, &delivery, &run_spec, &images, &provenance, NOW).unwrap();
    tx.commit().unwrap();
    // The PR stream now has its own newest transition, and the push stream is
    // untouched.
    assert_eq!(
        intake::last_dispatched(&f.conn, f.tenant, f.repo, REF, true)
            .unwrap()
            .unwrap()
            .id,
        pr.id()
    );
    assert_eq!(
        intake::last_dispatched(&f.conn, f.tenant, f.repo, REF, false)
            .unwrap()
            .unwrap()
            .id,
        second
    );
    // Its event facts are the pull-request ones: merge ref, base branch, number.
    let run = fetch(&f, pr.id()).run.unwrap();
    let facts = provenance::event_facts(&f.conn, run).unwrap();
    assert_eq!(facts.name, "pull_request");
    assert_eq!(facts.ref_name, "refs/pull/7/merge");
    assert_eq!(facts.base_ref.as_deref(), Some("main"));
    assert_eq!(facts.pr_number, Some(7));
    assert_eq!(facts.key, "pr-7");
    let recorded = provenance::of_run(&f.conn, run).unwrap().unwrap();
    assert_eq!(recorded.head_sha.as_deref(), Some(SHA_A));
    assert_eq!(recorded.base_sha.as_deref(), Some(SHA_B));
    assert_eq!(recorded.merge_sha.as_deref(), Some(SHA_A));
    assert_eq!(recorded.pr_number, Some(7));
}

#[test]
fn pull_request_terms_are_stored_and_bounded() {
    let mut f = fixture();
    let accepted = accept_pr(&mut f, "pr-1", &pr_terms(999, Some(SHA_C))).unwrap();
    let pr = intake::pr_for(&f.conn, accepted.id()).unwrap().unwrap();
    assert_eq!(pr.number, 7);
    assert_eq!(pr.action, "opened");
    assert!(!pr.draft);
    assert_eq!(pr.head_ref, "feature");
    assert_eq!(pr.head_sha, SHA_A);
    // A fork head is recorded as a fact, never flattened into the base repo.
    assert_eq!(pr.head_repo, 999);
    assert_eq!(pr.base_ref, "main");
    assert_eq!(pr.merge_sha.as_deref(), Some(SHA_C));
    // The delivery's own terms stand for the tested merge.
    let delivery = fetch(&f, accepted.id());
    assert_eq!(delivery.event, "pull_request");
    assert_eq!(delivery.ref_name.as_deref(), Some(REF));
    assert_eq!(delivery.new_sha.as_deref(), Some(SHA_C));
    assert!(
        intake::pr_for(&f.conn, DeliveryId::new())
            .unwrap()
            .is_none()
    );

    // Malformed terms are refused before anything is stored.
    let mut cases = 0;
    let mut check = |terms: &intake::PrTerms<'_>| {
        cases += 1;
        let outcome = accept_pr(&mut f, "bad", terms);
        assert!(
            matches!(outcome, Err(Error::InvalidInput(_))),
            "{terms:?} -> {outcome:?}"
        );
    };
    check(&intake::PrTerms {
        number: 0,
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        action: "",
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        head_ref: "a b",
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        base_ref: "with..dots",
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        head_sha: "nope",
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        head_repo: 0,
        ..pr_terms(999, Some(SHA_C))
    });
    check(&intake::PrTerms {
        merge_sha: Some("zz"),
        ..pr_terms(999, Some(SHA_C))
    });
    assert_eq!(cases, 7);
    assert_eq!(count(&f), 1, "only the first delivery exists");
    // The terms prove trust, so they cannot be rewritten, and raw SQL cannot
    // attach them to a delivery that does not exist.
    for sql in [
        "UPDATE pr_deliveries SET head_repo_id = 1",
        "UPDATE pr_deliveries SET merge_sha = NULL",
    ] {
        assert!(
            f.conn.execute(sql, []).is_err(),
            "raw SQL rewrote pull request terms: {sql}"
        );
    }
    let detached = DeliveryId::new();
    assert!(
        f.conn
            .execute(
                "INSERT INTO pr_deliveries(delivery_id, tenant_id, repo_id, number, action, draft,
                    head_ref, head_sha, head_repo_id, base_ref, base_sha, merge_sha)
                 VALUES (?1, ?2, ?3, 1, 'opened', 0, 'feature', ?4, 1, 'main', ?5, NULL)",
                rusqlite::params![
                    detached.as_bytes(),
                    f.tenant.as_bytes(),
                    f.repo.as_bytes(),
                    SHA_A,
                    SHA_B
                ],
            )
            .is_err(),
        "pull request terms must belong to a stored delivery"
    );
}
