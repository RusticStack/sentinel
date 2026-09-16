//! Lane outcome accounting: a retry that spends the last attempt is a
//! durable refusal — counted and reported as refused on the `Retry` and
//! `Throttled` arms alike, never as "retried"/"throttled" while the row is
//! durably dead.

use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_checks::{
    Lane,
    lane::{Batch, Config, Publish, Publisher},
};
use sentinel_core::{
    RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    checks::{self, State},
    provenance::{self, Provenance},
    registration::{self, Authority},
    runs, sources,
    sources_forge::{self, Snapshot},
};

const REF: &str = "refs/heads/main";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GITHUB_REPO_ID: u64 = 91;
const INSTALLATION: u64 = 42;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    tenant: TenantId,
    repo: RepoId,
}

/// The tenant/repo/binding chain `record_run` needs to create outbox rows:
/// an event-driven run on a forge-bound repository.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (alice, tenant, repo) = (
        Principal::new(UserId::new(), Permissions::ALL, None, None),
        TenantId::new(),
        RepoId::new(),
    );
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice.user, "alice", true, now)?;
            auth::create_namespace(
                tx,
                alice,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Personal(alice.user),
                now,
            )?;
            auth::create_repo(tx, alice, tenant, repo, "app", now)?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: INSTALLATION,
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
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(alice.user),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: "https://github.com/account/app.git".into(),
                        allowed_refs: vec![REF.into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            Ok(())
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        repo,
    }
}

/// One event-driven run with a single job: the outbox gets its check and
/// the aggregate.
fn event_run(f: &Fixture) -> RunId {
    let (tenant, repo) = (f.tenant, f.repo);
    let run = RunId::new();
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/account/app.git", SHA_B, Some(REF)).unwrap(),
        compile_str(&format!(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ))
        .unwrap(),
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
            provenance::insert(
                tx,
                &Provenance {
                    tenant,
                    repo,
                    trigger: "push".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some(REF.into()),
                    old_sha: None,
                    new_sha: Some(SHA_B.into()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: SHA_B.into(),
                    pipeline_path: Some(".sentinel.yml".into()),
                    pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                    pr_number: None,
                },
                run,
                UnixMillis::now(),
            )?;
            checks::record_run(tx, tenant, run, UnixMillis::now())?;
            Ok(())
        })
        .unwrap();
    run
}

/// Spend every due row's retry budget down to the last attempt.
fn spend_budget(f: &Fixture) {
    f.store
        .writer()
        .write(|tx| {
            tx.execute(
                "UPDATE check_publications SET attempts = ?1",
                [checks::MAX_ATTEMPTS - 1],
            )?;
            Ok(())
        })
        .unwrap();
}

/// One scripted outcome for every publication the lane hands over.
struct Stub {
    outcome: Publish,
}

impl Publisher for Stub {
    fn publish(&mut self, _publication: &checks::Publication) -> Publish {
        self.outcome.clone()
    }
}

fn start(f: &Fixture, outcome: Publish) -> (Lane, mpsc::Receiver<Batch>) {
    let (tx, rx) = mpsc::channel();
    let lane = Lane::start(
        Arc::clone(&f.store),
        Box::new(Stub { outcome }),
        Config {
            idle: Duration::from_millis(20),
            max_pause: Duration::from_millis(100),
            ..Config::default()
        },
        move |batch| {
            let _ = tx.send(batch.clone());
        },
    );
    (lane, rx)
}

/// Wait until every outbox row of the run is durably refused.
fn wait_refused(f: &Fixture, run: RunId) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
        if !rows.is_empty() && rows.iter().all(|r| r.state == State::Refused) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for refusals: {rows:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_retry_that_spends_the_budget_is_counted_and_reported_as_refused() {
    let f = fixture();
    let run = event_run(&f);
    spend_budget(&f);
    let (lane, batches) = start(
        &f,
        Publish::Retry {
            after_ms: 0,
            detail: "upstream 502".into(),
        },
    );

    wait_refused(&f, run);
    let batch = batches
        .recv_timeout(Duration::from_secs(10))
        .expect("the settling batch");
    assert_eq!(batch.retried, 0, "nothing was scheduled: {batch:?}");
    assert_eq!(batch.refused, 2, "{batch:?}");
    for entry in &batch.entries {
        assert!(
            entry.outcome.starts_with("refused:"),
            "a durable refusal must not read as a retry: {}",
            entry.outcome
        );
    }
    drop(lane);
}

#[test]
fn a_throttle_that_spends_the_budget_reports_the_refusal_not_the_pause() {
    let f = fixture();
    let run = event_run(&f);
    spend_budget(&f);
    let (lane, batches) = start(
        &f,
        Publish::Throttled {
            until_ms: UnixMillis::now().0 + 150,
        },
    );

    // The first row's park spends its last attempt: refused, not throttled.
    let first = batches
        .recv_timeout(Duration::from_secs(10))
        .expect("the throttled batch");
    assert_eq!(first.refused, 1, "{first:?}");
    assert!(
        first.entries.iter().all(|e| e.outcome.contains("refused")),
        "an exhausted park is a refusal: {first:?}"
    );
    assert!(first.paused_until_ms.is_some(), "{first:?}");

    // The row the pause skipped settles refused on the next pass.
    wait_refused(&f, run);
    drop(lane);
}
