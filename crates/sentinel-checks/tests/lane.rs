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
            min_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
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

/// Publishes the aggregate through a rate-limited scope and everything else
/// through an open one.
struct Scoped {
    throttle_until_ms: i64,
}

fn is_aggregate(publication: &checks::Publication) -> bool {
    publication.scope == checks::AGGREGATE_SCOPE
}

impl Publisher for Scoped {
    fn publish(&mut self, publication: &checks::Publication) -> Publish {
        if is_aggregate(publication) {
            Publish::Throttled {
                until_ms: self.throttle_until_ms,
                scope: 1,
            }
        } else {
            Publish::Published {
                check_run_id: 5,
                check_suite_id: None,
            }
        }
    }

    fn scope(&self, publication: &checks::Publication) -> u64 {
        u64::from(is_aggregate(publication))
    }
}

fn start_with(f: &Fixture, publisher: impl Publisher + 'static) -> Lane {
    Lane::start(
        Arc::clone(&f.store),
        Box::new(publisher),
        Config {
            idle: Duration::from_millis(20),
            min_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
            ..Config::default()
        },
        |_| {},
    )
}

fn wait_for(f: &Fixture, run: RunId, what: &str, done: impl Fn(&[checks::Publication]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
        if done(&rows) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out ({what}): {rows:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_throttle_parks_the_row_without_spending_its_budget() {
    let f = fixture();
    let run = event_run(&f);
    spend_budget(&f);
    let until = UnixMillis::now().0 + 600_000;
    let (lane, batches) = start(
        &f,
        Publish::Throttled {
            until_ms: until,
            scope: 0,
        },
    );

    let first = batches
        .recv_timeout(Duration::from_secs(10))
        .expect("the throttled batch");
    assert_eq!(first.refused, 0, "a limit never refuses a row: {first:?}");
    assert_eq!(first.paused_until_ms, Some(until), "{first:?}");
    drop(lane);
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    assert!(!rows.is_empty());
    for row in rows {
        assert_eq!(row.state, State::Pending, "{row:?}");
    }
    // Every row, the one that hit the limit and the ones it skipped, kept its
    // last attempt and waits for the reset.
    let sql = format!(
        "SELECT COUNT(*) FROM check_publications
         WHERE attempts = {} AND next_attempt_ms >= {}",
        checks::MAX_ATTEMPTS - 1,
        until - 1_000
    );
    let parked: i64 = f
        .store
        .read(move |c| Ok(c.query_row(&sql, (), |r| r.get(0))?))
        .unwrap();
    assert_eq!(parked, 2);
}

#[test]
fn one_scope_being_throttled_does_not_stop_the_others() {
    let f = fixture();
    let run = event_run(&f);
    let until = UnixMillis::now().0 + 600_000;
    let lane = start_with(
        &f,
        Scoped {
            throttle_until_ms: until,
        },
    );
    wait_for(&f, run, "the open scope publishes", |rows| {
        rows.iter()
            .filter(|r| !is_aggregate(r))
            .all(|r| r.state == State::Published)
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let parked = loop {
        if let Some(parked) = aggregate_parked_until(&f) {
            break parked;
        }
        assert!(
            Instant::now() < deadline,
            "the throttled row was never parked"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(lane);
    assert!(parked >= until - 1_000, "parked until the reset: {parked}");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    let aggregate = rows.iter().find(|r| is_aggregate(r)).unwrap();
    assert_eq!(aggregate.state, State::Pending);
}

fn aggregate_parked_until(f: &Fixture) -> Option<i64> {
    f.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT next_attempt_ms FROM check_publications WHERE scope = 'aggregate'",
                (),
                |r| r.get::<_, Option<i64>>(0),
            )?)
        })
        .unwrap()
}

/// Makes every delivery write for the aggregate fail inside SQLite, the way a
/// row the store cannot update would.
fn poison_aggregate(f: &Fixture) {
    f.store
        .writer()
        .write(|tx| {
            tx.execute_batch(
                "CREATE TRIGGER poison BEFORE UPDATE ON check_publications
                 WHEN OLD.scope = 'aggregate' AND (NEW.state != OLD.state
                    OR NEW.published_seq != OLD.published_seq)
                 BEGIN SELECT RAISE(ABORT, 'poison'); END;",
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_row_whose_store_writes_keep_failing_cannot_block_the_lane() {
    let f = fixture();
    let run = event_run(&f);
    poison_aggregate(&f);
    let lane = start_with(&f, Deliver);
    wait_for(&f, run, "the healthy rows deliver", |rows| {
        rows.iter()
            .filter(|r| !is_aggregate(r))
            .all(|r| r.state == State::Published)
    });
    // The poison row is quarantined for an hour, not retried in a tight loop.
    let deadline = Instant::now() + Duration::from_secs(20);
    let parked = loop {
        if let Some(parked) = aggregate_parked_until(&f) {
            break parked;
        }
        assert!(Instant::now() < deadline, "the poison row was never parked");
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(lane);
    assert!(parked > UnixMillis::now().0 + 30 * 60 * 1000, "{parked}");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    let aggregate = rows.iter().find(|r| is_aggregate(r)).unwrap();
    assert_eq!(aggregate.state, State::Pending, "the poison row waits");
}

struct Deliver;

impl Publisher for Deliver {
    fn publish(&mut self, _publication: &checks::Publication) -> Publish {
        Publish::Published {
            check_run_id: 9,
            check_suite_id: None,
        }
    }
}

/// A lane whose safety re-read is far away: only the commit notifier and the
/// retry deadline can wake it in time.
fn start_unpolled(f: &Fixture) -> Lane {
    Lane::start(
        Arc::clone(&f.store),
        Box::new(Deliver),
        Config {
            idle: Duration::from_secs(120),
            ..Config::default()
        },
        |_| {},
    )
}

fn all_published(rows: &[checks::Publication]) -> bool {
    !rows.is_empty() && rows.iter().all(|r| r.state == State::Published)
}

#[test]
fn a_publication_committed_to_an_idle_lane_is_delivered_without_polling() {
    let f = fixture();
    let lane = start_unpolled(&f);
    // Let the lane find nothing and go to sleep.
    std::thread::sleep(Duration::from_millis(300));
    let run = event_run(&f);
    // Far inside the lane's two-minute safety re-read.
    wait_for(&f, run, "the commit wakes the lane", all_published);
    drop(lane);
}

#[test]
fn a_backed_off_row_is_read_when_its_deadline_arrives_not_when_something_commits() {
    let f = fixture();
    let run = event_run(&f);
    let due = UnixMillis::now().0 + 400;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute("UPDATE check_publications SET next_attempt_ms = ?1", [due])?;
            Ok(())
        })
        .unwrap();
    let lane = start_unpolled(&f);
    std::thread::sleep(Duration::from_millis(100));
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    assert!(
        rows.iter().all(|r| r.state == State::Pending),
        "not due yet: {rows:?}"
    );
    // No commit follows: only the deadline can wake the lane.
    wait_for(&f, run, "the deadline wakes the lane", all_published);
    drop(lane);
}

#[test]
fn dropping_an_idle_lane_stops_it_at_once() {
    let f = fixture();
    let lane = start_unpolled(&f);
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    drop(lane);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the lane slept through its shutdown"
    );
}
