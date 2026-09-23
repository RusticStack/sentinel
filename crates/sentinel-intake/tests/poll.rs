//! G07 end-to-end: a remote advertisement becomes a durable `poll` delivery
//! that the unchanged G02–G03 path validates, resolves and dispatches, while
//! remote failures back the schedule off and a revoked binding retires the
//! configuration entirely.
//!
//! The lister is injected so the lane's scheduling, selection, cursor and
//! admission behavior are tested deterministically; `sentinel-git`'s own
//! tests cover the real `git ls-remote` exchange.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Resolver, lane,
    poll::{self, Lister},
    resolve::{self, Fetch},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    intake,
    poll::{self as store_poll, Spec},
    registration::Authority,
    sources::{self, Update},
};

const NOW: UnixMillis = UnixMillis(1_000);
const MAIN: &str = "refs/heads/main";
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

/// A lister whose answer the test controls between polls.
struct FakeLister {
    answer: Mutex<Result<Vec<sentinel_git::RefTip>, String>>,
}

impl FakeLister {
    fn set(&self, tips: Vec<sentinel_git::RefTip>) {
        *self.answer.lock().unwrap() = Ok(tips);
    }
}

impl Lister for FakeLister {
    fn refs(
        &self,
        _: &sentinel_intake::ListRequest<'_>,
    ) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error> {
        match &*self.answer.lock().unwrap() {
            Ok(tips) => Ok(tips.clone()),
            Err(why) => Err(sentinel_git::Error::Preparation(why.clone())),
        }
    }
}

fn tip(name: &str, oid: &str) -> sentinel_git::RefTip {
    sentinel_git::RefTip {
        name: name.into(),
        oid: oid.into(),
        peeled: None,
    }
}

/// The injected fetcher: every push event reads the same valid pipeline.
struct FakeFetch;

impl Fetch for FakeFetch {
    fn file_at(
        &self,
        request: resolve::FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        Ok(sentinel_git::FetchedFile {
            commit: request.sha.to_owned(),
            bytes: format!(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
            )
            .into_bytes(),
        })
    }
    fn merge_at(
        &self,
        _: resolve::MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        panic!("poll deliveries are pushes, not pull requests")
    }
    fn is_ancestor(&self, _: resolve::AncestryRequest<'_>) -> Result<bool, sentinel_git::Error> {
        // No history is modelled: nothing is proven stale.
        Ok(false)
    }
}

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
        remote: "https://git.example:8443/team/repo.git".into(),
        allowed_refs: vec!["refs/heads/*".into(), "refs/tags/*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice.user, "alice", true, NOW)?;
            auth::create_namespace(
                tx,
                alice,
                tenant,
                Namespace::parse("alice").unwrap(),
                NamespaceKind::Personal(alice.user),
                NOW,
            )?;
            auth::create_repo(tx, alice, tenant, repo, "project", NOW)?;
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
                NOW,
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

fn configure(f: &Fixture, refs: &[&str]) {
    let spec = Spec {
        interval_ms: 10_000,
        refs: refs.iter().map(|r| r.to_string()).collect(),
    };
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| store_poll::configure(tx, Authority::HostLocal, None, repo, &spec, NOW))
        .unwrap();
}

/// Make the repository's next poll due immediately rather than waiting out
/// the configured interval.
fn due_now(f: &Fixture) {
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| store_poll::schedule(tx, repo, 0, 0, None, UnixMillis::now()))
        .unwrap();
}

fn wait_for(deadline_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(deadline_ms);
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn deliveries(f: &Fixture) -> Vec<intake::Delivery> {
    f.store
        .read(|c| intake::list(c, f.tenant, f.repo, None, 50))
        .unwrap()
}

fn config(f: &Fixture) -> Option<store_poll::Config> {
    f.store.read(|c| store_poll::of_repo(c, f.repo)).unwrap()
}

/// The deployment's approved authorities: exactly the fixture binding's.
fn destinations() -> Arc<[String]> {
    vec!["https://git.example:8443".to_owned()].into()
}

fn lane_config() -> poll::Config {
    poll::Config {
        idle: Duration::from_millis(10),
        ..poll::Config::default()
    }
}

#[test]
fn an_observed_push_becomes_a_delivery_and_dispatches_a_run() {
    let f = fixture();
    let lister = Arc::new(FakeLister {
        answer: Mutex::new(Ok(vec![tip(MAIN, &"a".repeat(40))])),
    });
    let work = f.dir.path().join("poll-work");
    let poller = sentinel_intake::Poll::start(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        destinations(),
        Arc::clone(&lister) as Arc<dyn Lister>,
        work,
        lane_config(),
        |_| {},
    )
    .unwrap();
    configure(&f, &[MAIN]);
    // First poll: baseline only — no delivery, no run.
    assert!(wait_for(5_000, || config(&f).is_some_and(|c| c.baselined)));
    assert!(deliveries(&f).is_empty());
    // The remote moves: the next poll admits a transition.
    lister.set(vec![tip(MAIN, &"b".repeat(40))]);
    due_now(&f);
    assert!(wait_for(5_000, || !deliveries(&f).is_empty()));
    let d = &deliveries(&f)[0];
    assert_eq!(d.provider, "poll");
    assert!(d.external_id.starts_with("poll:"));
    assert_eq!(d.ref_name.as_deref(), Some(MAIN));
    assert_eq!(
        (d.old_sha.as_deref(), d.new_sha.as_deref()),
        (Some("a".repeat(40).as_str()), Some("b".repeat(40).as_str()))
    );
    // That delivery resolves and dispatches through the unchanged G03 path.
    let resolver = Resolver::new(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        destinations(),
        Arc::new(FakeFetch),
        f.dir.path().join("intake-work"),
        resolve::Config::default(),
    )
    .unwrap();
    let intake_lane = lane::Lane::start(
        Arc::clone(&f.store),
        Some(Arc::new(resolver)),
        None,
        lane::Config {
            idle: Duration::from_millis(10),
            ..lane::Config::default()
        },
        |_| {},
    );
    assert!(wait_for(5_000, || {
        deliveries(&f)
            .first()
            .is_some_and(|d| d.state == intake::State::Dispatched && d.run.is_some())
    }));
    drop(intake_lane);
    drop(poller);
}

#[test]
fn remote_failures_back_the_schedule_off_and_revocation_retires_it() {
    let f = fixture();
    let lister = Arc::new(FakeLister {
        answer: Mutex::new(Err("git ls-remote failed: unreachable".to_owned())),
    });
    let poller = sentinel_intake::Poll::start(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        destinations(),
        Arc::clone(&lister) as Arc<dyn Lister>,
        f.dir.path().join("poll-work"),
        lane_config(),
        |_| {},
    )
    .unwrap();
    configure(&f, &[MAIN]);
    assert!(wait_for(5_000, || {
        config(&f).is_some_and(|c| c.failures > 0 && c.last_error.is_some())
    }));
    let first = config(&f).unwrap();
    assert!(first.next_poll_ms > 0);
    // A healthy remote clears the failure state on its next pass.
    lister.set(vec![tip(MAIN, &"a".repeat(40))]);
    due_now(&f);
    assert!(wait_for(5_000, || {
        config(&f).is_some_and(|c| c.failures == 0 && c.baselined)
    }));
    // Revoking the binding retires the configuration instead of polling a
    // remote the tenant no longer authorizes.
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| sources::revoke(tx, Authority::HostLocal, None, repo, 1, NOW))
        .unwrap();
    assert!(
        config(&f).is_none(),
        "revoke removes the poll configuration"
    );
    due_now(&f); // in case a stale row survived, a pass must not resurrect it
    std::thread::sleep(Duration::from_millis(50));
    assert!(deliveries(&f).is_empty());
    drop(poller);
}

#[test]
fn a_binding_that_vanished_mid_schedule_drops_the_configuration() {
    let f = fixture();
    let lister = Arc::new(FakeLister {
        answer: Mutex::new(Ok(vec![tip(MAIN, &"a".repeat(40))])),
    });
    let poller = sentinel_intake::Poll::start(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        destinations(),
        Arc::clone(&lister) as Arc<dyn Lister>,
        f.dir.path().join("poll-work"),
        lane_config(),
        |_| {},
    )
    .unwrap();
    configure(&f, &[MAIN]);
    // Simulate a config whose binding disappeared without revoke's cleanup:
    // the lane notices and drops it rather than polling forever.
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM source_bindings WHERE repo_id=?1",
                [repo.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    due_now(&f);
    assert!(wait_for(5_000, || config(&f).is_none()));
    assert!(deliveries(&f).is_empty());
    drop(poller);
}
