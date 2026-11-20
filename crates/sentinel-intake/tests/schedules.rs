//! The schedule lane end to end: an occurrence resolves the ref it names, pins that commit, and the
//! run it creates carries its own revision. A refusal is recorded on the occurrence, never dropped.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Fetch, ListRequest, Lister, Resolver,
    poll::TipRequest,
    resolve,
    schedules::{self, Config, Notice},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    registration::Authority,
    schedule::{self, Claim, Overlap, Spec, State},
    sources::{self, Update},
};

const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const REMOTE: &str = "https://git.example:8443/team/repo.git";
const MAIN: &str = "refs/heads/main";
const MINUTE: i64 = 60_000;
/// Two occurrences a minute apart, both in the past so a pass with that clock finds them due.
const A: i64 = 1_800_000;
const B: i64 = A + MINUTE;

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    key: Arc<Key>,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let bind_key = Key::load(&key_path).unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let binding = Binding {
        remote: REMOTE.into(),
        allowed_refs: vec!["refs/heads/*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice.user, "alice", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                alice,
                tenant,
                Namespace::parse("alice").unwrap(),
                NamespaceKind::Personal(alice.user),
                UnixMillis(1),
            )?;
            auth::create_repo(tx, alice, tenant, repo, "project", UnixMillis(1))?;
            sources::bind(
                tx,
                Authority::HostLocal,
                None,
                Update {
                    repo,
                    expected: 0,
                    binding: &binding,
                    credential: &Credential::Public,
                    forge: None,
                },
                &["https://git.example:8443".into()],
                &bind_key,
                UnixMillis(1),
            )?;
            Ok(())
        })
        .unwrap();
    Fixture {
        dir,
        store,
        key,
        tenant,
        repo,
    }
}

/// The remote's ref tip, which the test moves between occurrences.
struct Tips(Mutex<String>);

impl Tips {
    fn set(&self, sha: &str) {
        *self.0.lock().unwrap() = sha.to_owned();
    }
}

impl Lister for Tips {
    fn refs(&self, _: &ListRequest<'_>) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error> {
        panic!("a schedule asks for one ref, never a listing")
    }

    fn tip(
        &self,
        request: &TipRequest<'_>,
    ) -> Result<Option<sentinel_git::RefTip>, sentinel_git::Error> {
        assert_eq!(request.ref_name, MAIN);
        Ok(Some(sentinel_git::RefTip {
            name: request.ref_name.to_owned(),
            oid: self.0.lock().unwrap().clone(),
            peeled: None,
        }))
    }
}

/// The pipeline each commit carries: the test states which commits have one and what it declares.
struct Pipelines(Mutex<HashMap<String, String>>);

impl Pipelines {
    fn set(&self, sha: &str, on: &str) {
        let text = format!(
            "schema: 1\non: {on}\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
        );
        self.0.lock().unwrap().insert(sha.to_owned(), text);
    }
}

impl Fetch for Pipelines {
    fn file_at(
        &self,
        request: resolve::FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        match self.0.lock().unwrap().get(request.sha) {
            Some(text) => Ok(sentinel_git::FetchedFile {
                commit: request.sha.to_owned(),
                bytes: text.clone().into_bytes(),
            }),
            None => Err(sentinel_git::Error::Missing),
        }
    }

    fn merge_at(
        &self,
        _: resolve::MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        panic!("a schedule resolves a commit, never a merge")
    }

    fn is_ancestor(&self, _: resolve::AncestryRequest<'_>) -> Result<bool, sentinel_git::Error> {
        panic!("a schedule proves no ancestry")
    }
}

/// Configure so the cursor sits on `A`, the first occurrence the tests fire.
fn configure(f: &Fixture) -> i64 {
    let spec = Spec {
        cron: "* * * * *".into(),
        ref_name: MAIN.into(),
        overlap: Overlap::Skip,
    };
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| {
            schedule::configure(
                tx,
                Authority::HostLocal,
                None,
                repo,
                &spec,
                UnixMillis(A - 1),
            )
        })
        .unwrap()
}

fn claim(f: &Fixture, now: i64) -> Vec<Claim> {
    f.store
        .writer()
        .write(move |tx| schedule::claim(tx, UnixMillis(now), schedule::MAX_PER_PASS))
        .unwrap()
}

fn resolver(f: &Fixture, fetch: Arc<Pipelines>, lister: Arc<Tips>) -> Resolver {
    Resolver::new(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        vec![
            REMOTE
                .trim_end_matches("/team/repo.git")
                .split_once("https://")
                .map(|_| "https://git.example:8443".to_owned())
                .unwrap(),
        ]
        .into(),
        Arc::from(Vec::new()),
        fetch,
        lister,
        f.dir.path().join("schedule-work"),
        resolve::Config::default(),
    )
    .unwrap()
}

fn occurrences(f: &Fixture) -> Vec<(i64, i64, Option<String>)> {
    f.store
        .read(|c| {
            let mut query =
                c.prepare("SELECT at_ms, state, reason FROM schedule_occurrences ORDER BY at_ms")?;
            let rows = query
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

/// Settle a run's jobs so it is no longer live.
fn cancel(f: &Fixture, run: sentinel_core::RunId) {
    let jobs: Vec<[u8; 16]> = f
        .store
        .read(move |c| {
            let mut query = c.prepare("SELECT id FROM jobs WHERE run_id = ?1")?;
            let rows = query
                .query_map([run.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap();
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            for job in jobs {
                let job = sentinel_core::JobId::from_bytes(job)
                    .map_err(|_| sentinel_store::Error::Corrupt("job_id"))?;
                sentinel_store::jobs::transition(
                    tx,
                    tenant,
                    job,
                    sentinel_core::Actor::Controller,
                    sentinel_core::Event::CancelBeforeStart,
                    UnixMillis(A),
                )?;
            }
            Ok(())
        })
        .unwrap();
}

fn runs(f: &Fixture) -> Vec<(String, String)> {
    f.store
        .read(|c| {
            let mut query = c.prepare(
                "SELECT r.source_sha, p.pipeline_sha FROM runs r
                 JOIN run_provenance p ON p.run_id = r.id ORDER BY r.created_ms, r.source_sha",
            )?;
            let rows = query
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

#[test]
fn each_occurrence_pins_the_commit_its_ref_held_then() {
    let f = fixture();
    configure(&f);
    let tips = Arc::new(Tips(Mutex::new("a".repeat(40))));
    let pipelines = Arc::new(Pipelines(Mutex::new(HashMap::new())));
    let first = "a".repeat(40);
    let second = "b".repeat(40);
    pipelines.set(&first, "[schedule]");
    pipelines.set(&second, "[schedule]");
    let resolver = resolver(&f, Arc::clone(&pipelines), Arc::clone(&tips));

    let claims = claim(&f, A);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].at_ms, A);
    let sentinel_intake::Outcome::Dispatched { run } = resolver
        .resolve_scheduled(&claims[0], UnixMillis(A))
        .unwrap()
    else {
        panic!("the first occurrence dispatches");
    };
    // The first run finishes, so the schedule's default skip policy has nothing to stand aside for.
    cancel(&f, run);

    // The ref moves; the next occurrence reads what it holds now, not what the first one read.
    tips.set(&second);
    let claims = claim(&f, B);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].at_ms, B);
    assert!(matches!(
        resolver
            .resolve_scheduled(&claims[0], UnixMillis(B))
            .unwrap(),
        sentinel_intake::Outcome::Dispatched { .. }
    ));

    assert_eq!(
        runs(&f),
        vec![
            (first.clone(), first.clone()),
            (second.clone(), second.clone())
        ]
    );
    assert_eq!(
        occurrences(&f),
        vec![
            (A, State::Dispatched as i64, None),
            (B, State::Dispatched as i64, None)
        ]
    );
}

#[test]
fn a_pipeline_that_does_not_accept_a_scheduled_run_is_recorded_as_such() {
    let f = fixture();
    configure(&f);
    let sha = "c".repeat(40);
    let tips = Arc::new(Tips(Mutex::new(sha.clone())));
    let pipelines = Arc::new(Pipelines(Mutex::new(HashMap::new())));
    pipelines.set(&sha, "[push]");
    let resolver = resolver(&f, pipelines, tips);
    let claims = claim(&f, A);
    assert!(matches!(
        resolver
            .resolve_scheduled(&claims[0], UnixMillis(A))
            .unwrap(),
        sentinel_intake::Outcome::Failed {
            reason: "no_trigger",
            ..
        }
    ));
    assert_eq!(
        occurrences(&f),
        vec![(A, State::Failed as i64, Some("no_trigger".into()))]
    );
    assert!(runs(&f).is_empty());
    // The schedule keeps going: the cursor is past the refused occurrence.
    let next = f
        .store
        .read(|c| Ok(schedule::of_repo(c, f.repo)?.map(|s| s.next_at_ms)))
        .unwrap();
    assert_eq!(next, Some(A + MINUTE));
}

#[test]
fn a_missing_pipeline_or_ref_is_recorded_against_the_occurrence() {
    let f = fixture();
    configure(&f);
    let sha = "d".repeat(40);
    let tips = Arc::new(Tips(Mutex::new(sha.clone())));
    let pipelines = Arc::new(Pipelines(Mutex::new(HashMap::new())));
    let resolver = resolver(&f, pipelines, tips);
    let claims = claim(&f, A);
    assert!(matches!(
        resolver
            .resolve_scheduled(&claims[0], UnixMillis(A))
            .unwrap(),
        sentinel_intake::Outcome::Failed {
            reason: "no_pipeline",
            ..
        }
    ));
    assert_eq!(
        occurrences(&f),
        vec![(A, State::Failed as i64, Some("no_pipeline".into()))]
    );
}

#[test]
fn the_lane_dispatches_a_due_occurrence_and_reports_it() {
    let f = fixture();
    configure(&f);
    let sha = "e".repeat(40);
    let tips = Arc::new(Tips(Mutex::new(sha.clone())));
    let pipelines = Arc::new(Pipelines(Mutex::new(HashMap::new())));
    pipelines.set(&sha, "[schedule]");
    let resolver = Arc::new(resolver(&f, pipelines, tips));
    // Due now: configuring one millisecond before the current minute puts the cursor on it.
    let boundary = UnixMillis::now().0.div_euclid(MINUTE) * MINUTE;
    let spec = Spec {
        cron: "* * * * *".into(),
        ref_name: MAIN.into(),
        overlap: Overlap::Skip,
    };
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| {
            schedule::configure(
                tx,
                Authority::HostLocal,
                None,
                repo,
                &spec,
                UnixMillis(boundary - 1),
            )
        })
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Notice>::new()));
    let collector = Arc::clone(&seen);
    let lane = schedules::Lane::start(
        Arc::clone(&f.store),
        resolver,
        Config {
            idle: Duration::from_millis(10),
            ..Config::default()
        },
        move |notice| collector.lock().unwrap().push(notice.clone()),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if !runs(&f).is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(lane);
    assert_eq!(
        runs(&f),
        vec![(sha.clone(), sha)],
        "one run for the occurrence"
    );
    let notices = seen.lock().unwrap();
    assert!(
        notices.iter().any(|n| n.outcome.starts_with("dispatched:")),
        "{notices:?}"
    );
}
