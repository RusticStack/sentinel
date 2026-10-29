use std::sync::Arc;

use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{
    SessionId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    github_app::{self, Bound, Observed, Purpose, Refusal, STATE_TTL_MS},
    local_auth::{self, Event},
};

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    root: UserId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    Fixture { dir, store, root }
}

fn key(dir: &std::path::Path) -> Key {
    let path = dir.join("master.key");
    if !path.exists() {
        Key::create(&path).unwrap();
    }
    Key::load(&path).unwrap()
}

fn mint(f: &Fixture, purpose: Purpose, user: UserId, session: SessionId) -> Secret {
    mint_at(f, purpose, user, session, 1_000)
}

fn mint_at(f: &Fixture, purpose: Purpose, user: UserId, session: SessionId, ms: i64) -> Secret {
    let tenant = (purpose == Purpose::Install).then(|| {
        f.store
            .read(|c| {
                Ok(TenantId::from_bytes(c.query_row(
                    "SELECT id FROM tenants ORDER BY created_ms LIMIT 1",
                    [],
                    |r| r.get(0),
                )?)
                .unwrap())
            })
            .unwrap()
    });
    f.store
        .writer()
        .write(move |tx| github_app::mint(tx, purpose, user, session, tenant, at(ms)))
        .unwrap()
        .0
}

fn spend(
    f: &Fixture,
    purpose: Purpose,
    secret: &Secret,
    user: UserId,
    session: SessionId,
    now: i64,
) -> Result<Option<TenantId>, Refusal> {
    let presented = Secret::parse(&{
        let mut text = String::new();
        secret.expose(&mut text);
        text
    })
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            let outcome = github_app::spend(tx, purpose, &presented, user, session, at(now))?;
            if let Err(refusal) = outcome {
                github_app::audit_refusal(tx, purpose, refusal, user, at(now))?;
            }
            Ok(outcome)
        })
        .unwrap()
        .map(|spent| spent.tenant)
}

#[test]
fn a_state_is_single_use_expiring_and_bound_to_its_account_session_and_purpose() {
    let f = fixture();
    let other = UserId::new();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, other, "Other", false, at(1)))
        .unwrap();
    let session = SessionId::new();
    let state = mint(&f, Purpose::Manifest, f.root, session);

    for (user, session_used, purpose) in [
        (other, session, Purpose::Manifest),
        (f.root, SessionId::new(), Purpose::Manifest),
        (f.root, session, Purpose::Install),
    ] {
        assert_eq!(
            spend(&f, purpose, &state, user, session_used, 2_000),
            Err(Refusal::Foreign)
        );
    }
    assert_eq!(
        spend(&f, Purpose::Manifest, &state, f.root, session, 2_000),
        Ok(None),
        "the foreign attempts spent nothing"
    );
    assert_eq!(
        spend(&f, Purpose::Manifest, &state, f.root, session, 2_001),
        Err(Refusal::Replayed)
    );
    assert_eq!(
        spend(
            &f,
            Purpose::Manifest,
            &Secret::generate(),
            f.root,
            session,
            2_002
        ),
        Err(Refusal::Unknown)
    );
    let late = mint(&f, Purpose::Manifest, f.root, session);
    assert_eq!(
        spend(
            &f,
            Purpose::Manifest,
            &late,
            f.root,
            session,
            1_000 + STATE_TTL_MS
        ),
        Err(Refusal::Expired)
    );

    // Only the digest is stored, and a spent state cannot be made usable again.
    let raw = f.dir.path().join("metadata.sqlite");
    drop(f.store);
    let conn = rusqlite::Connection::open(&raw).unwrap();
    let mut text = String::new();
    state.expose(&mut text);
    let found: i64 = conn
        .query_row(
            "SELECT count(*) FROM github_app_states WHERE digest = ?1",
            [state.digest().0],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(found, 1);
    assert!(
        conn.execute("UPDATE github_app_states SET used_ms = NULL", [])
            .is_err(),
        "a spent state is never unspent"
    );
    assert!(
        conn.execute(
            "UPDATE github_app_states SET expires_ms = expires_ms + 1",
            []
        )
        .is_err()
    );
}

#[test]
fn refusals_are_audited_without_the_state_and_bounded_per_account() {
    let f = fixture();
    let session = SessionId::new();
    for n in 0..20 {
        let _ = spend(
            &f,
            Purpose::Manifest,
            &Secret::generate(),
            f.root,
            session,
            5_000 + n,
        );
    }
    let rows: Vec<_> = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .filter(|r| r.event == Event::GithubAppStateRefused)
        .collect();
    assert_eq!(rows.len(), 5, "five per account in ten seconds");
    assert!(
        rows.iter()
            .all(|r| r.detail.as_deref() == Some("manifest unknown"))
    );
    assert!(rows.iter().all(|r| r.actor == Some(f.root)));
}

#[test]
fn one_account_holds_a_bounded_number_of_states_and_purging_removes_expired_ones() {
    let f = fixture();
    let session = SessionId::new();
    // A millisecond apart: states minted in the same millisecond have no defined oldest.
    let first = mint_at(&f, Purpose::Manifest, f.root, session, 1_000);
    for i in 1..=github_app::MAX_STATES_PER_USER {
        mint_at(&f, Purpose::Manifest, f.root, session, 1_000 + i);
    }
    assert_eq!(
        spend(&f, Purpose::Manifest, &first, f.root, session, 2_000),
        Err(Refusal::Unknown),
        "the oldest state was dropped"
    );
    let count = |store: &Store| -> i64 {
        store
            .read(|c| Ok(c.query_row("SELECT count(*) FROM github_app_states", [], |r| r.get(0))?))
            .unwrap()
    };
    assert_eq!(count(&f.store), github_app::MAX_STATES_PER_USER);
    assert_eq!(
        github_app::purge(&f.store, at(1_000 + STATE_TTL_MS), 1_000).unwrap(),
        github_app::MAX_STATES_PER_USER as usize
    );
    assert_eq!(count(&f.store), 0);
}

const PEM: &str = "pem-canary-0123456789";
const CLIENT_SECRET: &str = "client-secret-canary-0123456789";
const WEBHOOK_SECRET: &str = "webhook-secret-canary-0123456789";

fn public(app_id: u64) -> github_app::Public {
    github_app::Public {
        app_id,
        slug: "acme-ci".into(),
        name: "Acme CI".into(),
        owner: "acme".into(),
        owner_id: 99,
        html_url: "https://github.com/apps/acme-ci".into(),
        client_id: "Iv1.acme".into(),
    }
}

#[test]
fn the_app_is_stored_once_sealed_and_opens_only_under_its_own_context() {
    let f = fixture();
    let key = Arc::new(key(f.dir.path()));
    let root = f.root;
    let store_app = |key: &Key| {
        let sealed = github_app::seal(key, 7, PEM, CLIENT_SECRET, Some(WEBHOOK_SECRET));
        f.store
            .writer()
            .write(move |tx| github_app::store(tx, &public(7), &sealed, root, at(10)))
    };
    store_app(&key).unwrap();
    assert!(matches!(store_app(&key), Err(Error::Conflict)));
    let loaded = f
        .store
        .read(|c| github_app::load(c, &key))
        .unwrap()
        .unwrap();
    assert_eq!(
        (loaded.pem.as_str(), loaded.client_secret.as_str()),
        (PEM, CLIENT_SECRET)
    );
    assert_eq!(loaded.webhook_secret.as_deref(), Some(WEBHOOK_SECRET));
    assert!(!format!("{loaded:?}").contains("canary"));
    let audit = f.store.read(|c| local_auth::recent_audit(c, 10)).unwrap();
    let created = audit
        .iter()
        .find(|r| r.event == Event::GithubAppCreated)
        .unwrap();
    assert_eq!(created.detail.as_deref(), Some("app 7 acme-ci"));
    f.store
        .read(|c| sentinel_store::reseal::verify_key(c, &key))
        .unwrap();
    assert!(
        f.store
            .read(sentinel_store::reseal::sealed_rows_exist)
            .unwrap()
    );

    let path = f.dir.path().join("metadata.sqlite");
    drop(f.store);
    let bytes = std::fs::read(&path).unwrap();
    for canary in [PEM, CLIENT_SECRET, WEBHOOK_SECRET] {
        assert!(
            !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "{canary} is in the database file"
        );
    }
    let conn = rusqlite::Connection::open(&path).unwrap();
    // A value moved into another column does not open there.
    conn.execute_batch("DROP TRIGGER github_app_update")
        .unwrap();
    conn.execute(
        "UPDATE github_app SET sealed_client_secret = sealed_key",
        [],
    )
    .unwrap();
    let store = Store::open(&path, Durability::Normal).unwrap();
    assert!(store.read(|c| github_app::load(c, &key)).is_err());
    assert!(
        store
            .read(|c| sentinel_store::reseal::verify_key(c, &key))
            .is_err()
    );
}

#[test]
fn the_app_identity_is_immutable_and_reseal_moves_it_to_the_active_key() {
    let f = fixture();
    let key_path = f.dir.path().join("master.key");
    let first = key(f.dir.path());
    let sealed = github_app::seal(&first, 7, PEM, CLIENT_SECRET, None);
    let root = f.root;
    f.store
        .writer()
        .write(move |tx| github_app::store(tx, &public(7), &sealed, root, at(10)))
        .unwrap();
    Key::rotate(&key_path, &f.dir.path().join("old.key")).unwrap();
    let rotated = Arc::new(Key::load(&key_path).unwrap());
    assert_eq!(
        f.store
            .read(|c| sentinel_store::reseal::stale(c, &rotated))
            .unwrap(),
        2
    );
    let progress = sentinel_store::reseal::reseal_all(&f.store, Arc::clone(&rotated)).unwrap();
    assert_eq!(progress.resealed, 2);
    assert_eq!(
        f.store
            .read(|c| sentinel_store::reseal::stale(c, &rotated))
            .unwrap(),
        0
    );
    let loaded = f
        .store
        .read(|c| github_app::load(c, &rotated))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.client_secret, CLIENT_SECRET);
    assert!(loaded.webhook_secret.is_none());
    let ids = f.store.read(sentinel_store::reseal::key_ids).unwrap();
    assert_eq!(
        ids.into_iter().collect::<Vec<_>>(),
        vec![rotated.active_id()]
    );
    for statement in [
        "UPDATE github_app SET slug = 'other'",
        "UPDATE github_app SET app_id = 8",
        "UPDATE github_app SET sealed_key = x'0100'",
    ] {
        assert!(
            f.store
                .writer()
                .write(move |tx| Ok(tx.execute(statement, [])?))
                .is_err(),
            "{statement}"
        );
    }
}

fn tenant(f: &Fixture, slug: &'static str, kind: NamespaceKind) -> TenantId {
    let (root, id) = (f.root, TenantId::new());
    f.store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(tx, admin, id, Namespace::parse(slug).unwrap(), kind, at(1))?;
            if matches!(kind, NamespaceKind::Organization) {
                auth::set_membership(tx, admin, id, root, Role::TenantAdmin)?;
            }
            Ok(())
        })
        .unwrap();
    id
}

fn observed(id: u64, personal: bool) -> Observed<'static> {
    Observed {
        external_id: id,
        account_id: 500 + id,
        login: "acme",
        personal,
        suspended: false,
        permissions_valid: true,
    }
}

#[test]
fn an_installation_binds_once_to_a_matching_tenant() {
    let f = fixture();
    let acme = tenant(&f, "acme", NamespaceKind::Organization);
    let other = tenant(&f, "other", NamespaceKind::Organization);
    let mine = tenant(&f, "root-home", NamespaceKind::Personal(f.root));
    let admin = Principal::new(f.root, P::ALL, None, None);
    let bind = |tenant: TenantId, installation: Observed<'static>| {
        f.store
            .writer()
            .write(move |tx| github_app::bind(tx, admin, tenant, &installation, at(50)))
    };
    assert!(
        matches!(bind(mine, observed(1, false)), Err(Error::Forbidden)),
        "an organization's installation never binds to a personal namespace"
    );
    assert!(matches!(
        bind(acme, observed(1, false)),
        Ok(Bound::Bound(_))
    ));
    assert!(
        matches!(bind(acme, observed(1, false)), Ok(Bound::Already(_))),
        "GitHub's setup_action=update returns to the same tenant"
    );
    assert!(
        matches!(bind(other, observed(1, false)), Err(Error::Conflict)),
        "bound elsewhere stays where it is"
    );
    assert!(matches!(bind(mine, observed(2, true)), Ok(Bound::Bound(_))));
    let (tenant_of, account): (Vec<u8>, i64) = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT tenant_id, account_id FROM installations WHERE external_id = '1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(tenant_of, acme.as_bytes().to_vec());
    assert_eq!(account, 501);
    let audit = f.store.read(|c| local_auth::recent_audit(c, 20)).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|r| r.event == Event::InstallationBound)
            .count(),
        2
    );

    let outsider = UserId::new();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, outsider, "Outsider", false, at(1)))
        .unwrap();
    let stranger = Principal::new(outsider, P::REPOSITORY.union(P::TENANT_ADMIN), None, None);
    assert!(matches!(
        f.store.writer().write(move |tx| github_app::bind(
            tx,
            stranger,
            other,
            &observed(3, false),
            at(60)
        )),
        Err(Error::Forbidden)
    ));
}
