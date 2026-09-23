//! Fault isolation and live policy in the intake and poll lanes (P05 audit):
//! a delivery or poll configuration whose binding authorizes nothing any more
//! settles or backs off on its own and never holds another tenant's work
//! behind it; the deployment's destination policy is rechecked before any
//! controller-side fetch; a rotation that races issuance is retried, not
//! failed; and an idle lane costs no writes.
//!
//! Fetching and listing are injected (and counted), so these run everywhere.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, InstallationId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Lane, Resolver,
    lane::Config as LaneConfig,
    poll::{self, Lister},
    resolve::{self, Fetch},
    source,
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, NewDelivery, State},
    poll::{self as store_poll, Spec},
    registration::{self, Authority},
    sources::{self, Update},
    sources_forge,
};

const MAIN: &str = "refs/heads/main";
const AUTHORITY: &str = "https://git.example:8443";
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

/// A fetcher that serves one valid push pipeline and counts every call.
#[derive(Default)]
struct CountingFetch {
    calls: AtomicUsize,
}

impl Fetch for CountingFetch {
    fn file_at(
        &self,
        request: resolve::FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        panic!("no pull requests here")
    }

    fn is_ancestor(&self, _: resolve::AncestryRequest<'_>) -> Result<bool, sentinel_git::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(false)
    }
}

/// A lister answering per remote, counting every call.
#[derive(Default)]
struct RoutedLister {
    answers: Mutex<HashMap<String, Result<Vec<sentinel_git::RefTip>, String>>>,
    calls: AtomicUsize,
}

impl RoutedLister {
    fn set(&self, remote: &str, answer: Result<Vec<sentinel_git::RefTip>, String>) {
        self.answers
            .lock()
            .unwrap()
            .insert(remote.to_owned(), answer);
    }
}

impl Lister for RoutedLister {
    fn refs(
        &self,
        request: &sentinel_intake::ListRequest<'_>,
    ) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.lock().unwrap().get(request.remote) {
            Some(Ok(tips)) => Ok(tips.clone()),
            Some(Err(why)) => Err(sentinel_git::Error::Preparation(why.clone())),
            None => Ok(Vec::new()),
        }
    }
}

fn tip(oid: char) -> sentinel_git::RefTip {
    sentinel_git::RefTip {
        name: MAIN.into(),
        oid: oid.to_string().repeat(40),
        peeled: None,
    }
}

struct Repo {
    owner: Principal,
    tenant: TenantId,
    id: RepoId,
    remote: String,
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    key: Arc<Key>,
    /// Two tenants' generic repositories.
    one: Repo,
    two: Repo,
    /// Tenant one's GitHub-App-bound repository.
    app: Repo,
    installation: InstallationId,
}

fn tenant_with_repo(
    tx: &sentinel_store::Transaction<'_>,
    key: &Key,
    slug: &str,
    name: &str,
) -> sentinel_store::Result<Repo> {
    let owner = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, id) = (TenantId::new(), RepoId::new());
    let now = UnixMillis::now();
    provisioning::insert_human(tx, owner.user, slug, true, now)?;
    auth::create_namespace(
        tx,
        owner,
        tenant,
        Namespace::parse(slug).unwrap(),
        NamespaceKind::Organization,
        now,
    )?;
    auth::create_repo(tx, owner, tenant, id, name, now)?;
    let remote = format!("{AUTHORITY}/{slug}/{name}.git");
    sources::bind(
        tx,
        Authority::HostLocal,
        None,
        Update {
            repo: id,
            expected: 0,
            binding: &Binding {
                remote: remote.clone(),
                allowed_refs: vec!["refs/heads/*".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            },
            credential: &Credential::Public,
            forge: None,
        },
        &[AUTHORITY.into()],
        key,
        now,
    )?;
    Ok(Repo {
        owner,
        tenant,
        id,
        remote,
    })
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let sealing = Arc::clone(&key);
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (one, two, app, installation) = store
        .writer()
        .write(move |tx| {
            let one = tenant_with_repo(tx, &sealing, "one", "app")?;
            let two = tenant_with_repo(tx, &sealing, "two", "app")?;
            let now = UnixMillis::now();
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
            registration::bind_installation_trusted(tx, installation, one.tenant, now)?;
            let owner = one.owner;
            let app_repo = RepoId::new();
            auth::create_repo(tx, owner, one.tenant, app_repo, "widget", now)?;
            let remote = "https://github.com/account/widget.git".to_owned();
            sources::bind(
                tx,
                Authority::HostLocal,
                None,
                Update {
                    repo: app_repo,
                    expected: 0,
                    binding: &Binding {
                        remote: remote.clone(),
                        allowed_refs: vec!["refs/heads/*".into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, 91)),
                },
                &["https://github.com".into()],
                &sealing,
                now,
            )?;
            let app = Repo {
                owner,
                tenant: one.tenant,
                id: app_repo,
                remote,
            };
            Ok((one, two, app, installation))
        })
        .unwrap();
    Fixture {
        dir,
        store,
        key,
        one,
        two,
        app,
        installation,
    }
}

fn everything() -> Arc<[String]> {
    vec![AUTHORITY.to_owned(), "https://github.com".to_owned()].into()
}

impl Fixture {
    fn resolver(&self, destinations: Arc<[String]>, fetch: Arc<CountingFetch>) -> Resolver {
        Resolver::new(
            Arc::clone(&self.store),
            Some(Arc::clone(&self.key)),
            None,
            destinations,
            fetch,
            self.dir.path().join(format!("work-{}", DeliveryId::new())),
            resolve::Config::default(),
        )
        .unwrap()
    }

    fn accept(&self, repo: &Repo, id: &str, old: char, new: char) -> DeliveryId {
        let (repo, id) = (repo.id, id.to_owned());
        let (old, new) = (old.to_string().repeat(40), new.to_string().repeat(40));
        self.store
            .writer()
            .write(move |tx| {
                intake::accept(
                    tx,
                    repo,
                    &NewDelivery {
                        provider: "generic",
                        external_id: &id,
                        event: "ref_update",
                        ref_name: MAIN,
                        old_sha: &old,
                        new_sha: &new,
                    },
                    None,
                    UnixMillis::now(),
                )
                .map(|accepted| accepted.id())
            })
            .unwrap()
    }

    /// Lane phase one, by hand: every due pending delivery becomes ready.
    fn validate_all(&self) {
        self.store
            .writer()
            .write(|tx| intake::resolve_due(tx, UnixMillis::now(), 64))
            .unwrap();
    }

    fn delivery(&self, id: DeliveryId) -> intake::Delivery {
        self.store.read(move |c| intake::get(c, id)).unwrap()
    }

    fn sql(&self, statement: &'static str, id: [u8; 16]) {
        self.store
            .writer()
            .write(move |tx| {
                tx.execute(statement, [id])?;
                Ok(())
            })
            .unwrap();
    }
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn start_lane(f: &Fixture, resolver: Resolver) -> Lane {
    Lane::start(
        Arc::clone(&f.store),
        Some(Arc::new(resolver)),
        None,
        LaneConfig {
            idle: Duration::from_millis(10),
            min_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            ..LaneConfig::default()
        },
        |_| {},
    )
}

/// Ready deliveries whose binding stopped authorizing anything — a suspended
/// tenant, a suspended installation, a revoked App binding — settle with
/// their reason, and another tenant's later delivery still dispatches.
#[test]
fn an_unusable_binding_settles_its_delivery_and_never_stalls_another_tenant() {
    let f = fixture();
    let suspended = f.accept(&f.one, "one-1", 'a', 'b');
    let uninstalled = f.accept(&f.app, "app-1", 'a', 'b');
    f.validate_all();
    assert_eq!(f.delivery(suspended).state, State::Ready);
    assert_eq!(f.delivery(uninstalled).state, State::Ready);
    // The installation is suspended by its owner, then the tenant is.
    f.sql(
        "UPDATE installations SET suspended = 1 WHERE id = ?1",
        *f.installation.as_bytes(),
    );
    f.sql(
        "UPDATE tenants SET active = 0 WHERE id = ?1",
        *f.one.tenant.as_bytes(),
    );
    let other = f.accept(&f.two, "two-1", 'a', 'b');
    let lane = start_lane(&f, f.resolver(everything(), Arc::default()));
    wait_for("the other tenant's dispatch", || {
        f.delivery(other).state == State::Dispatched
    });
    wait_for("the suspended deliveries to settle", || {
        !f.delivery(suspended).state.is_open() && !f.delivery(uninstalled).state.is_open()
    });
    drop(lane);
    for id in [suspended, uninstalled] {
        let row = f.delivery(id);
        assert_eq!(row.state, State::Failed, "{row:?}");
        assert_eq!(row.reason.as_deref(), Some("tenant_suspended"), "{row:?}");
    }
}

#[test]
fn a_suspended_installation_and_a_revoked_app_binding_settle_with_their_reasons() {
    let f = fixture();
    let first = f.accept(&f.app, "app-1", 'a', 'b');
    f.validate_all();
    f.sql(
        "UPDATE installations SET suspended = 1 WHERE id = ?1",
        *f.installation.as_bytes(),
    );
    let resolver = f.resolver(everything(), Arc::default());
    let outcome = resolver
        .resolve(&f.delivery(first), UnixMillis::now())
        .unwrap();
    assert_eq!(
        outcome,
        sentinel_intake::Outcome::Failed {
            reason: "access_removed",
            detail: None
        }
    );
    // A `repository renamed` revocation keeps the installation association
    // on the row; it must still read as revoked, not as a store fault.
    f.sql(
        "UPDATE installations SET suspended = 0 WHERE id = ?1",
        *f.installation.as_bytes(),
    );
    let second = f.accept(&f.app, "app-2", 'b', 'c');
    f.validate_all();
    f.sql(
        "UPDATE source_bindings SET revoked = 1, credential = x'', version = version + 1
         WHERE repo_id = ?1",
        *f.app.id.as_bytes(),
    );
    let outcome = resolver
        .resolve(&f.delivery(second), UnixMillis::now())
        .unwrap();
    assert_eq!(
        outcome,
        sentinel_intake::Outcome::Failed {
            reason: "binding_revoked",
            detail: None
        }
    );
}

/// A delivery whose resolution hits a store fault is parked under its own
/// retry schedule; the pass carries on with the rest.
#[test]
fn a_store_fault_on_one_delivery_parks_it_and_the_pass_continues() {
    let f = fixture();
    let broken = f.accept(&f.one, "one-1", 'a', 'b');
    f.validate_all();
    // An undecodable binding: reading it is a store fault, not a verdict.
    f.sql(
        "UPDATE source_bindings SET binding = x'00' WHERE repo_id = ?1",
        *f.one.id.as_bytes(),
    );
    let other = f.accept(&f.two, "two-1", 'a', 'b');
    let lane = start_lane(&f, f.resolver(everything(), Arc::default()));
    wait_for("the other tenant's dispatch", || {
        f.delivery(other).state == State::Dispatched
    });
    wait_for("the broken delivery to be parked", || {
        f.delivery(broken).attempts > 0
    });
    drop(lane);
    let row = f.delivery(broken);
    assert!(row.state.is_open(), "a fault is not a verdict: {row:?}");
    let next: Option<i64> = f
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT next_attempt_ms FROM webhook_deliveries WHERE id = ?1",
                [broken.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(next.is_some_and(|at| at > UnixMillis::now().0 - 60_000));
}

/// Narrowing `source-destinations.json` stops controller-side fetches for a
/// binding outside it, with an explicit reason, before any remote work.
#[test]
fn a_binding_outside_the_destination_policy_is_refused_before_any_fetch() {
    let f = fixture();
    let delivery = f.accept(&f.one, "one-1", 'a', 'b');
    f.validate_all();
    let fetch = Arc::new(CountingFetch::default());
    let only_github: Arc<[String]> = vec!["https://github.com".to_owned()].into();
    let resolver = f.resolver(only_github, Arc::clone(&fetch));
    let outcome = resolver
        .resolve(&f.delivery(delivery), UnixMillis::now())
        .unwrap();
    assert_eq!(
        outcome,
        sentinel_intake::Outcome::Failed {
            reason: "destination_refused",
            detail: None
        }
    );
    assert_eq!(
        f.delivery(delivery).reason.as_deref(),
        Some("destination_refused")
    );
    assert_eq!(fetch.calls.load(Ordering::SeqCst), 0, "nothing was fetched");
}

/// A binding rotated between the lookup and the issuance is retried under a
/// fresh lookup instead of failing the delivery for good.
#[test]
fn a_rotation_racing_issuance_is_transient() {
    let f = fixture();
    let source::Lookup::Bound(stale) = source::classify(&f.store, f.one.id).unwrap() else {
        panic!("a live binding");
    };
    let (repo, remote, key) = (f.one.id, f.one.remote.clone(), Arc::clone(&f.key));
    f.store
        .writer()
        .write(move |tx| {
            sources::bind(
                tx,
                Authority::HostLocal,
                None,
                Update {
                    repo,
                    expected: 1,
                    binding: &Binding {
                        remote,
                        allowed_refs: vec!["refs/heads/*".into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Https {
                        username: "deploy".into(),
                        secret: "rotated".into(),
                    },
                    forge: None,
                },
                &[AUTHORITY.into()],
                &key,
                UnixMillis::now(),
            )
        })
        .unwrap();
    assert_eq!(
        source::issue(&f.store, Some(&f.key), None, &stale, UnixMillis::now()).err(),
        Some(source::Error::Unavailable("source_changed"))
    );
    let source::Lookup::Bound(fresh) = source::classify(&f.store, f.one.id).unwrap() else {
        panic!("a live binding");
    };
    let access = source::issue(&f.store, Some(&f.key), None, &fresh, UnixMillis::now()).unwrap();
    assert_eq!(access.version, 2);
    assert_eq!(
        access.credential,
        Credential::Https {
            username: "deploy".into(),
            secret: "rotated".into()
        }
    );
}

/// An idle lane reads; it does not write. Every commit wakes each run-watch
/// long poll, so an empty validation pass must not be one.
#[test]
fn an_idle_lane_takes_no_writes() {
    let f = fixture();
    let lane = start_lane(&f, f.resolver(everything(), Arc::default()));
    // Let the lane settle into its idle loop.
    std::thread::sleep(Duration::from_millis(100));
    let before = f.store.changes().generation();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        f.store.changes().generation(),
        before,
        "an idle tick committed"
    );
    // And it still wakes for work.
    let delivery = f.accept(&f.two, "two-1", 'a', 'b');
    lane.waker().wake();
    wait_for("the dispatch", || {
        f.delivery(delivery).state == State::Dispatched
    });
    drop(lane);
}

fn configure(f: &Fixture, repo: &Repo) {
    let id = repo.id;
    f.store
        .writer()
        .write(move |tx| {
            store_poll::configure(
                tx,
                Authority::HostLocal,
                None,
                id,
                &Spec {
                    interval_ms: 10_000,
                    refs: vec![MAIN.into()],
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

fn poll_config(f: &Fixture, repo: &Repo) -> Option<store_poll::Config> {
    let id = repo.id;
    f.store.read(move |c| store_poll::of_repo(c, id)).unwrap()
}

fn due_now(f: &Fixture, repo: &Repo) {
    let id = repo.id;
    f.store
        .writer()
        .write(move |tx| store_poll::schedule(tx, id, 0, 0, None, UnixMillis::now()))
        .unwrap();
}

fn start_poll(f: &Fixture, destinations: Arc<[String]>, lister: &Arc<RoutedLister>) -> poll::Poll {
    sentinel_intake::Poll::start(
        Arc::clone(&f.store),
        Some(Arc::clone(&f.key)),
        None,
        destinations,
        Arc::clone(lister) as Arc<dyn Lister>,
        f.dir.path().join(format!("poll-{}", DeliveryId::new())),
        poll::Config {
            idle: Duration::from_millis(10),
            min_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            ..poll::Config::default()
        },
        |_| {},
    )
    .unwrap()
}

/// A suspended tenant's poll configuration backs off (and is kept for when
/// the tenant returns); another repository's poll is never blocked by it.
#[test]
fn a_suspended_tenants_poll_backs_off_without_blocking_others() {
    let f = fixture();
    let lister = Arc::new(RoutedLister::default());
    lister.set(&f.one.remote, Ok(vec![tip('a')]));
    lister.set(&f.two.remote, Ok(vec![tip('a')]));
    configure(&f, &f.one);
    f.sql(
        "UPDATE tenants SET active = 0 WHERE id = ?1",
        *f.one.tenant.as_bytes(),
    );
    configure(&f, &f.two);
    let poller = start_poll(&f, everything(), &lister);
    wait_for("the other repository's baseline", || {
        poll_config(&f, &f.two).is_some_and(|c| c.baselined)
    });
    wait_for("the suspended repository's back-off", || {
        poll_config(&f, &f.one).is_some_and(|c| c.failures > 0)
    });
    drop(poller);
    let suspended = poll_config(&f, &f.one).expect("the configuration is kept");
    assert_eq!(suspended.last_error.as_deref(), Some("tenant_suspended"));
    assert!(!suspended.baselined);
}

/// The poller rechecks the destination policy before listing a remote.
#[test]
fn a_poll_outside_the_destination_policy_is_refused_without_listing() {
    let f = fixture();
    let lister = Arc::new(RoutedLister::default());
    configure(&f, &f.one);
    let poller = start_poll(&f, vec!["https://github.com".to_owned()].into(), &lister);
    wait_for("the refusal", || {
        poll_config(&f, &f.one).is_some_and(|c| c.failures > 0)
    });
    drop(poller);
    assert_eq!(
        poll_config(&f, &f.one).unwrap().last_error.as_deref(),
        Some("destination_refused")
    );
    assert_eq!(lister.calls.load(Ordering::SeqCst), 0);
}

/// A remote's multibyte diagnostic longer than the stored bound is cut on a
/// character boundary, and the poll lane keeps polling afterwards.
#[test]
fn a_multibyte_failure_reason_is_bounded_and_the_lane_survives() {
    let f = fixture();
    let lister = Arc::new(RoutedLister::default());
    // As recorded, the reason reads `git: git ls-remote failed: é…`: 27
    // bytes of prefix plus two-byte characters, so byte 256 falls inside one.
    let reason = format!("git ls-remote failed: {}", "é".repeat(200));
    let shown = sentinel_git::Error::Preparation(reason.clone()).to_string();
    assert!(!shown.is_char_boundary(256));
    lister.set(&f.one.remote, Err(reason));
    lister.set(&f.two.remote, Ok(vec![tip('a')]));
    configure(&f, &f.one);
    let poller = start_poll(&f, everything(), &lister);
    wait_for("the failure to be recorded", || {
        poll_config(&f, &f.one).is_some_and(|c| c.failures > 0)
    });
    let stored = poll_config(&f, &f.one).unwrap().last_error.unwrap();
    assert!(stored.len() <= 256, "{}", stored.len());
    // The lane is alive: a repository configured afterwards is polled.
    configure(&f, &f.two);
    wait_for("the next repository's baseline", || {
        poll_config(&f, &f.two).is_some_and(|c| c.baselined)
    });
    lister.set(&f.two.remote, Ok(vec![tip('b')]));
    due_now(&f, &f.two);
    let (tenant, repo) = (f.two.tenant, f.two.id);
    wait_for("the next repository's delivery", || {
        !f.store
            .read(move |c| intake::list(c, tenant, repo, None, 10))
            .unwrap()
            .is_empty()
    });
    drop(poller);
}
