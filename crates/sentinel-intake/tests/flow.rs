//! G02 end to end, without HTTP: the two authenticated ingest paths store
//! deduplicated, tenant-owned deliveries, and the bounded lane resolves them
//! on a wake or on its idle tick.
use std::{
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Batch, Github, Lane,
    ingest::{self, Error as IngestError},
    lane::Config,
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, State},
    registration::{self, Authority},
    sources::{self, Update},
    sources_forge,
};

const REF: &str = "refs/heads/main";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const WEBHOOK_SECRET: &[u8] = b"a-webhook-secret-value";
const GITHUB_REPO_ID: i64 = 91;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    repo: RepoId,
    github_repo: RepoId,
    token: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let root = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo, github_repo) = (TenantId::new(), RepoId::new(), RepoId::new());
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root.user, "root", true, now)?;
            auth::create_namespace(
                tx,
                root,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, root, tenant, repo, "app", now)?;
            auth::create_repo(tx, root, tenant, github_repo, "widget", now)?;
            let generic = Binding {
                remote: "https://git.example:8443/team/repo.git".into(),
                allowed_refs: vec![REF.into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root.user),
                Update {
                    repo,
                    expected: 0,
                    binding: &generic,
                    credential: &Credential::Https {
                        username: "deploy".into(),
                        secret: "deploy-token".into(),
                    },
                    forge: None,
                },
                &["https://git.example:8443".into()],
                &key,
                now,
            )?;
            // A GitHub App installation bound to the same tenant and one repo.
            let installation = sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: 42,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            let forge = Binding {
                remote: "https://github.com/account/widget.git".into(),
                allowed_refs: vec![REF.into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root.user),
                Update {
                    repo: github_repo,
                    expected: 0,
                    binding: &forge,
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID as u64)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            Ok(())
        })
        .unwrap();
    let token = {
        let secret = store
            .writer()
            .write(move |tx| intake::issue_token(tx, Authority::HostLocal, repo, now))
            .unwrap();
        intake::hook_token_text(&secret)
    };
    Fixture {
        _dir: dir,
        store,
        repo,
        github_repo,
        token,
    }
}

fn body(delivery: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "delivery_id": delivery,
        "ref": REF,
        "old_sha": SHA_A,
        "new_sha": SHA_B,
    }))
    .unwrap()
}

fn state(f: &Fixture, repo: RepoId) -> Vec<State> {
    f.store
        .read(move |c| {
            let tenant = sentinel_store::lookup::repo_tenant(c, repo)?;
            let deliveries = intake::list(c, tenant, repo, None, 100)?;
            Ok(deliveries.into_iter().map(|d| d.state).collect())
        })
        .unwrap()
}

fn signed_push(repository: i64, delivery: Option<&str>) -> (Vec<u8>, String, Option<String>) {
    let payload = serde_json::json!({
        "ref": REF,
        "before": SHA_A,
        "after": SHA_B,
        "created": false,
        "deleted": false,
        "forced": false,
        "installation": {"id": 42},
        "repository": {"id": repository, "full_name": "account/widget"},
    });
    sign(payload, delivery)
}

/// A `pull_request` payload for the bound repository, same-repository head.
fn signed_pr(action: &str, delivery: &str) -> (Vec<u8>, String) {
    let payload = serde_json::json!({
        "action": action,
        "number": 7,
        "installation": {"id": 42},
        "repository": {"id": GITHUB_REPO_ID, "full_name": "account/widget"},
        "pull_request": {
            "draft": false,
            "head": {"ref": "feature", "sha": "c".repeat(40), "repo": {"id": GITHUB_REPO_ID}},
            "base": {"ref": "main", "sha": "d".repeat(40)},
            "merge_commit_sha": "e".repeat(40),
        },
    });
    let (body, signature, _) = sign(payload, Some(delivery));
    (body, signature)
}

fn sign(payload: serde_json::Value, delivery: Option<&str>) -> (Vec<u8>, String, Option<String>) {
    let body = serde_json::to_vec(&payload).unwrap();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, WEBHOOK_SECRET);
    let tag = ring::hmac::sign(&key, &body);
    let mut signature = String::from("sha256=");
    for byte in tag.as_ref() {
        signature.push_str(&format!("{byte:02x}"));
    }
    (body, signature, delivery.map(str::to_owned))
}

#[test]
fn the_generic_path_authenticates_scopes_and_deduplicates() {
    let f = fixture();
    let now = UnixMillis::now();
    let first = ingest::generic(&f.store, &f.token, f.repo, &body("hook-1"), now).unwrap();
    assert!(!first.duplicate);
    let again = ingest::generic(&f.store, &f.token, f.repo, &body("hook-1"), now).unwrap();
    assert!(again.duplicate && again.id == first.id);
    assert_eq!(state(&f, f.repo), vec![State::Pending]);

    // A malformed body, an unparseable secret and a valid secret for a
    // different repository are all refusals that store nothing.
    assert_eq!(
        ingest::generic(&f.store, &f.token, f.repo, b"not json", now),
        Err(IngestError::InvalidRequest("body"))
    );
    assert_eq!(
        ingest::generic(
            &f.store,
            "sentinel_hook_not-a-secret",
            f.repo,
            &body("hook-2"),
            now
        ),
        Err(IngestError::Unauthenticated)
    );
    let unknown = RepoId::new();
    assert!(matches!(
        ingest::generic(&f.store, &f.token, unknown, &body("hook-3"), now),
        Err(IngestError::Unauthenticated)
    ));
    // The GitHub repository's token does not exist, so its own path
    // authenticates nothing here; the generic one is scoped to its repository.
    assert_eq!(state(&f, f.repo).len(), 1);
}

#[test]
fn the_github_path_verifies_the_raw_body_and_maps_the_installation() {
    let f = fixture();
    let now = UnixMillis::now();
    let (body, signature, delivery) = signed_push(GITHUB_REPO_ID, Some("gh-1"));
    // Ping: verified, nothing stored.
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "ping",
            None,
            Some(&signature),
            &body,
            now
        )
        .unwrap(),
        Github::Pong
    );
    // A tampered body is a failed signature, never a stored delivery.
    let mut tampered = body.clone();
    tampered[10] ^= 1;
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "push",
            delivery.as_deref(),
            Some(&signature),
            &tampered,
            now
        ),
        Err(IngestError::Unauthenticated)
    );
    // A missing signature is unauthenticated; a missing delivery header is
    // rejected before any store work.
    assert_eq!(
        ingest::github(&f.store, WEBHOOK_SECRET, "push", None, None, &body, now),
        Err(IngestError::Unauthenticated)
    );
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "push",
            None,
            Some(&signature),
            &body,
            now
        ),
        Err(IngestError::InvalidRequest("delivery header"))
    );
    // A valid delivery for a repository this deployment has not bound is
    // accepted and ignored: GitHub must not retry it.
    let (other_body, other_signature, other_delivery) = signed_push(92, Some("gh-2"));
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "push",
            other_delivery.as_deref(),
            Some(&other_signature),
            &other_body,
            now
        )
        .unwrap(),
        Github::Ignored("unbound_repository")
    );
    // An event this deployment does not handle yet is acknowledged and
    // ignored, not retried.
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "workflow_run",
            Some("gh-3"),
            Some(&signature),
            &body,
            now
        )
        .unwrap(),
        Github::Ignored("unsupported_event")
    );
    // A pull request for the bound repository is intake: only the actions that
    // mean new work are stored, and the others are acknowledged and ignored.
    let pr = signed_pr("opened", "gh-4");
    assert!(matches!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "pull_request",
            Some("gh-4"),
            Some(&pr.1),
            &pr.0,
            now
        )
        .unwrap(),
        Github::Ingested(_)
    ));
    let labeled = signed_pr("labeled", "gh-5");
    assert_eq!(
        ingest::github(
            &f.store,
            WEBHOOK_SECRET,
            "pull_request",
            Some("gh-5"),
            Some(&labeled.1),
            &labeled.0,
            now
        )
        .unwrap(),
        Github::Ignored("pr_action")
    );
    // The stored terms are the base branch and the tested merge, with the head
    // repository recorded rather than inferred.
    let delivery_id = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT id FROM webhook_deliveries WHERE external_id = 'gh-4'",
                [],
                |r| r.get::<_, [u8; 16]>(0),
            )?)
        })
        .map(|bytes| sentinel_core::DeliveryId::from_bytes(bytes).unwrap())
        .unwrap();
    let row = f.store.read(move |c| intake::get(c, delivery_id)).unwrap();
    assert_eq!(row.event, "pull_request");
    assert_eq!(row.ref_name.as_deref(), Some("refs/heads/main"));
    assert_eq!(row.new_sha.as_deref(), Some("e".repeat(40).as_str()));
    let terms = f
        .store
        .read(move |c| intake::pr_for(c, delivery_id))
        .unwrap()
        .unwrap();
    assert_eq!(terms.number, 7);
    assert_eq!(terms.head_repo, GITHUB_REPO_ID as u64);
    assert_eq!(terms.base_ref, "main");
    assert_eq!(terms.merge_sha.as_deref(), Some("e".repeat(40).as_str()));
    // The bound repository accepts the push and deduplicates a redelivery.
    let accepted = ingest::github(
        &f.store,
        WEBHOOK_SECRET,
        "push",
        delivery.as_deref(),
        Some(&signature),
        &body,
        now,
    )
    .unwrap();
    let Github::Ingested(accepted) = accepted else {
        panic!("bound push must be ingested");
    };
    assert!(!accepted.duplicate);
    let again = ingest::github(
        &f.store,
        WEBHOOK_SECRET,
        "push",
        delivery.as_deref(),
        Some(&signature),
        &body,
        now,
    )
    .unwrap();
    assert_eq!(
        again,
        Github::Ingested(sentinel_intake::Ingested {
            duplicate: true,
            ..accepted
        })
    );
    // The push and the pull request are both durable and pending; the
    // redelivery and the ignored action added nothing.
    assert_eq!(
        state(&f, f.github_repo),
        vec![State::Pending, State::Pending]
    );
    // A wrong secret never reaches the payload.
    assert_eq!(
        ingest::github(
            &f.store,
            b"another-webhook-secret",
            "push",
            delivery.as_deref(),
            Some(&signature),
            &body,
            now
        ),
        Err(IngestError::Unauthenticated)
    );
}

#[test]
fn the_lane_resolves_on_a_wake_and_on_its_tick() {
    let f = fixture();
    let (tx, rx) = mpsc::channel::<Batch>();
    let lane = Lane::start(
        Arc::clone(&f.store),
        None,
        None,
        Config {
            idle: Duration::from_millis(25),
            ..Config::default()
        },
        move |batch| {
            let _ = tx.send(batch.clone());
        },
    );

    // One delivery resolved by an explicit wake.
    let now = UnixMillis::now();
    let woken = ingest::generic(&f.store, &f.token, f.repo, &body("wake-1"), now).unwrap();
    lane.waker().wake();
    let batch = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("wake resolved");
    assert!(batch.settled.iter().any(|s| s.id == woken.id));
    // One resolved by the idle tick alone: no wake call.
    let ticked = ingest::generic(&f.store, &f.token, f.repo, &body("tick-1"), now).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_ticked = false;
    while Instant::now() < deadline && !saw_ticked {
        if let Ok(batch) = rx.recv_timeout(Duration::from_millis(250)) {
            saw_ticked |= batch.settled.iter().any(|s| s.id == ticked.id);
        }
    }
    assert!(saw_ticked, "the idle tick resolves without a wake");
    assert_eq!(
        state(&f, f.repo),
        vec![State::Ready, State::Ready],
        "both deliveries settled ready"
    );

    // Dropping the lane stops and joins its thread; a new delivery would now
    // wait for the next process.
    drop(lane);
    ingest::generic(&f.store, &f.token, f.repo, &body("after-stop"), now).unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(
        state(&f, f.repo).contains(&State::Pending),
        "nothing resolves after the lane stopped"
    );
}
