//! A job's additional repository checkouts: each one is authorized exactly as the run's own is, and every
//! one of them is delivered with the revision the run's source manifest records.

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    AttemptId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    negotiate::{Arch, Capabilities, Hello, ProtocolVersion},
    source::{Binding, Credential},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    logs::LogStore,
    registration::Authority,
    runs, sources,
    sources::Update,
    tenancy,
    tenancy::PoolKind,
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REMOTE: &str = "https://git.example:8443/team/repo.git";
const SHARED_REMOTE: &str = "https://git.example:8443/team/shared.git";
const SHARED_SECRET: &str = "private-shared-token";
const CAPACITY: Capacity = Capacity {
    cpu_millis: 4_000,
    memory_bytes: 8 << 30,
};

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    checkout:
      repositories: [{repo: shared, path: vendor/shared, ref: refs/heads/main}]
    steps: [{ id: s, run: 'true' }]
";

/// How the additional checkout's repository is bound, when it exists at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shared {
    MainOnly,
    Unbound,
    Absent,
    OutsideDestinations,
}

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    controller: Option<Controller>,
    pool: PoolId,
    tenant: TenantId,
    run: RunId,
    shared: RepoId,
}

impl Deployment {
    fn controller(&self) -> &Controller {
        self.controller.as_ref().unwrap()
    }
}

fn deployment(shared: Shared, pipeline: &str, recorded: Option<&str>) -> Deployment {
    let recorded = recorded.map(str::to_owned);
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let sealing = Key::load(&key_path).unwrap();
    let (owner, tenant, repo, pool, run, other) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        RunId::new(),
        RepoId::new(),
    );
    let principal = Principal::new(owner, P::ALL, None, None);
    let binding = |remote: &str, refs: &[&str]| Binding {
        remote: remote.into(),
        allowed_refs: refs.iter().map(|r| (*r).into()).collect(),
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let spec = RunSpec::new(
        PinnedSource::new(REMOTE, SHA, Some("refs/heads/main")).unwrap(),
        compile_str(pipeline).unwrap(),
    )
    .unwrap();
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, owner, "root", true, now)?;
            auth::create_namespace(
                tx,
                principal,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, principal, tenant, repo, "app", now)?;
            auth::create_repo(tx, principal, tenant, other, "shared", now)?;
            auth::set_membership(
                tx,
                principal,
                tenant,
                owner,
                sentinel_core::auth::Role::TenantAdmin,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                now,
            )?;
            sources::bind(
                tx,
                sentinel_store::registration::Authority::credential(principal),
                None,
                Update {
                    repo,
                    expected: 0,
                    binding: &binding(REMOTE, &["refs/heads/main"]),
                    credential: &Credential::Https {
                        username: "deploy".into(),
                        secret: "private-source-token".into(),
                    },
                    forge: None,
                },
                &["https://git.example:8443".into()],
                &key,
                now,
            )?;
            if shared != Shared::Unbound && shared != Shared::Absent {
                let remote = if shared == Shared::OutsideDestinations {
                    "https://elsewhere.example/team/shared.git"
                } else {
                    SHARED_REMOTE
                };
                sources::bind(
                    tx,
                    sentinel_store::registration::Authority::credential(principal),
                    None,
                    Update {
                        repo: other,
                        expected: 0,
                        binding: &binding(remote, &["refs/heads/main"]),
                        credential: &Credential::Https {
                            username: "deploy".into(),
                            secret: SHARED_SECRET.into(),
                        },
                        forge: None,
                    },
                    &[
                        "https://git.example:8443".into(),
                        "https://elsewhere.example".into(),
                    ],
                    &key,
                    now,
                )?;
            }
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            if let Some(revision) = recorded {
                sources::record_resolution(
                    tx,
                    tenant,
                    run,
                    &sources::ResolvedSource {
                        job_index: 0,
                        checkout_index: 1,
                        repo: other,
                        name: "shared".into(),
                        path: "vendor/shared".into(),
                        ref_name: Some("refs/heads/main".into()),
                        revision,
                        history: "shallow".into(),
                        resolved: now,
                    },
                )?;
            }
            Ok(())
        })
        .unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        logs,
        objects,
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    controller.set_source_key(Arc::new(sealing));
    controller.set_source_destinations(vec![
        "https://git.example:8443".into(),
        "https://elsewhere.example".into(),
    ]);
    Deployment {
        _dir: dir,
        store,
        controller: Some(controller),
        pool,
        tenant,
        run,
        shared: other,
    }
}

fn hello(protocol_max: u16) -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(protocol_max),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "test".into(),
    }
}

type SpecRecord = (AttemptId, Option<session::JobContext>, Vec<u8>);

#[derive(Default)]
struct Captured {
    specs: Mutex<Vec<SpecRecord>>,
    reporter: Mutex<Option<session::Reporter>>,
    held: Mutex<Vec<AttemptId>>,
}

impl Executor for Captured {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        true
    }
    fn accepted(&self, attempt: AttemptId) {
        if let Some(reporter) = self.reporter.lock().unwrap().clone() {
            reporter.need_spec(attempt).unwrap();
        }
    }
    fn stop(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, reporter: session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, attempt: AttemptId, context: session::JobContext, bytes: Vec<u8>) {
        self.specs
            .lock()
            .unwrap()
            .push((attempt, Some(context), bytes));
    }
    fn no_spec(&self, attempt: AttemptId) {
        self.specs.lock().unwrap().push((attempt, None, Vec::new()));
    }
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

struct WorkerProcess {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<sentinel_link::Result<()>>>,
}

impl WorkerProcess {
    fn start(d: &Deployment, protocol: u16, executor: Arc<Captured>) -> WorkerProcess {
        let identity = Identity::generate("worker").unwrap();
        let id = WorkerId::new();
        let enrollment = {
            let pool = d.pool;
            d.store
                .writer()
                .write(move |tx| {
                    workers::issue_enrollment(
                        tx,
                        Authority::HostLocal,
                        pool,
                        60_000,
                        UnixMillis::now(),
                    )
                })
                .unwrap()
                .secret
        };
        let handle = Arc::new(worker::Handle::new());
        let config = worker::Config {
            controller: d.controller().local_addr(),
            server: d.controller().fingerprint(),
            also_pinned: Vec::new(),
            worker: id,
            name: "builder-1".into(),
            hello: hello(protocol),
            capacity: CAPACITY,
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: session::TransportStats::default(),
            remote_cache: false,
        };
        let grip = Arc::clone(&handle);
        let running = Arc::clone(&executor);
        let thread = thread::spawn(move || {
            worker::run(
                config,
                identity,
                Some(enrollment),
                &*running,
                &grip,
                &|_| {},
            )
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while executor.reporter.lock().unwrap().is_none() {
            assert!(Instant::now() < deadline, "worker did not attach");
            thread::sleep(Duration::from_millis(20));
        }
        WorkerProcess {
            handle,
            thread: Some(thread),
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The first spec answer the worker receives, or `None` when the controller refused the attempt.
fn first_spec(d: &Deployment, protocol: u16) -> (Option<session::JobContext>, Vec<u8>) {
    d.controller().wake();
    let attempts = Arc::new(Captured::default());
    let worker = WorkerProcess::start(d, protocol, Arc::clone(&attempts));
    thread::sleep(Duration::from_millis(100));
    let deadline = Instant::now() + Duration::from_secs(15);
    let answer = loop {
        if let Some((_, context, bytes)) = attempts.specs.lock().unwrap().first().cloned() {
            break (context, bytes);
        }
        if let Some(reporter) = attempts.reporter.lock().unwrap().clone()
            && let Some(attempt) = attempts.held.lock().unwrap().first().copied()
        {
            let _ = reporter.need_spec(attempt);
        }
        assert!(
            Instant::now() < deadline,
            "no spec answer arrived: {:?}",
            d.controller().stats()
        );
        thread::sleep(Duration::from_millis(50));
    };
    drop(worker);
    answer
}

#[test]
fn an_unauthorized_additional_repository_is_refused_rather_than_fetched() {
    // A repository this tenant does not hold, one with no binding, one bound outside the deployment's
    // destinations and one whose ref its binding excludes: every one is refused at once, in the same
    // transaction as the run's own grant.
    for (shared, pipeline) in [
        (Shared::Absent, PIPELINE),
        (Shared::Unbound, PIPELINE),
        (Shared::OutsideDestinations, PIPELINE),
        (
            Shared::MainOnly,
            PIPELINE
                .replace("refs/heads/main", "refs/heads/other")
                .as_str(),
        ),
    ] {
        let d = deployment(shared, pipeline, None);
        let (context, bytes) = first_spec(&d, 14);
        assert!(context.is_none(), "{shared:?}: a spec was delivered");
        assert!(bytes.is_empty());
        // Nothing was recorded for a job that never started: the manifest stays answerable and empty.
        let tenant = d.tenant;
        let run = d.run;
        assert!(
            d.store
                .read(move |c| sources::manifest(c, tenant, run))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn a_job_with_additional_checkouts_is_told_the_recorded_revision_and_its_manifest_is_complete() {
    let recorded = "2".repeat(40);
    let d = deployment(Shared::MainOnly, PIPELINE, Some(&recorded));
    let (context, bytes) = first_spec(&d, 15);
    let context = context.expect("protocol 15 must receive the spec");
    // The spec itself still states the declaration, and names the format that carries it.
    let spec = RunSpec::decode(&bytes).unwrap();
    assert_eq!(bytes[0], 13);
    assert_eq!(spec.pipeline.jobs[0].spec.checkouts[0].repo, "shared");
    assert_eq!(context.checkouts.len(), 1);
    let checkout = &context.checkouts[0];
    assert_eq!(checkout.index, 1, "index 0 is the run's own checkout");
    assert_eq!(checkout.repo, d.shared);
    assert_eq!(
        checkout.revision, recorded,
        "the rerun resolves the run's recorded revision, not the branch's tip"
    );
    assert!(checkout.recorded);
    assert_eq!(checkout.access.binding.remote, SHARED_REMOTE);
    assert_eq!(
        checkout.access.credential,
        Credential::Https {
            username: "deploy".into(),
            secret: SHARED_SECRET.into()
        }
    );
    assert_eq!(context.source.as_ref().unwrap().binding.remote, REMOTE);

    // The manifest answers what the run built: the run's own checkout first, then every declared one.
    let tenant = d.tenant;
    let run = d.run;
    let manifest = d
        .store
        .read(move |c| sources::manifest(c, tenant, run))
        .unwrap();
    assert_eq!(
        manifest
            .iter()
            .map(|s| (s.checkout_index, s.revision.as_str(), s.path.as_str()))
            .collect::<Vec<_>>(),
        [(0, SHA, ""), (1, recorded.as_str(), "vendor/shared")]
    );
    assert_eq!(manifest[1].repo, d.shared);
}

#[test]
fn a_worker_below_the_additional_checkout_protocol_is_refused() {
    let d = deployment(Shared::MainOnly, PIPELINE, Some(&"2".repeat(40)));
    let (context, bytes) = first_spec(&d, 14);
    assert!(
        context.is_none(),
        "protocol 14 cannot be told about an additional checkout"
    );
    assert!(bytes.is_empty());
}
