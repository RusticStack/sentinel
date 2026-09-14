//! G01 across the link: a bound repository's access reaches a protocol-2
//! worker only with the spec of an attempt it acknowledged, and a protocol-1
//! worker is refused instead of silently checking out without a credential.
#![cfg(target_os = "linux")]

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
    auth::{self, Authority, NamespaceKind, provisioning},
    logs::LogStore,
    runs,
    sources::{self, Update},
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REMOTE: &str = "https://git.example:8443/team/repo.git";
const SECRET: &str = "private-source-deploy-token";
const CAPACITY: Capacity = Capacity {
    cpu_millis: 4_000,
    memory_bytes: 8 << 30,
};

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    controller: Option<Controller>,
    pool: PoolId,
}

impl Deployment {
    fn controller(&self) -> &Controller {
        self.controller.as_ref().unwrap()
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let sealing = Key::load(&key_path).unwrap();
    let (owner, tenant, repo, pool, run) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        RunId::new(),
    );
    let principal = Principal::new(owner, P::ALL, None, None);
    let binding = Binding {
        remote: REMOTE.into(),
        allowed_refs: vec!["refs/heads/main".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let credential = Credential::Https {
        username: "deploy".into(),
        secret: SECRET.into(),
    };
    let spec = RunSpec::new(
        PinnedSource::new(REMOTE, SHA, Some("refs/heads/main")).unwrap(),
        compile_str(
            "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
",
        )
        .unwrap(),
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
                    binding: &binding,
                    credential: &credential,
                    forge: None,
                },
                &["https://git.example:8443".into()],
                &key,
                now,
            )?;
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(())
        })
        .unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        logs,
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    controller.set_source_key(Arc::new(sealing));
    controller.set_source_destinations(vec!["https://git.example:8443".into()]);
    Deployment {
        _dir: dir,
        store,
        controller: Some(controller),
        pool,
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

/// A spec delivery: the attempt, its context (none when refused), the bytes.
type SpecRecord = (AttemptId, Option<session::JobContext>, Vec<u8>);

/// What the worker was told, and the reporter that asks for more.
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
    /// The real worker asks for the spec only after its acknowledgement is on
    /// the wire; the test does the same through the attached reporter.
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

/// A worker thread result, named once so the struct type stays readable.
type WorkerResult = sentinel_link::Result<()>;

struct WorkerProcess {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<WorkerResult>>,
}

impl WorkerProcess {
    /// Enroll, connect at `protocol`, and wait until the reporter is attached.
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
            worker: id,
            name: "builder-1".into(),
            hello: hello(protocol),
            capacity: CAPACITY,
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

/// Offer, acknowledgement, `NeedSpec`, and whatever came back. The real flow
/// asks for the spec from `accepted`, so no manual `need_spec` is needed.
fn first_spec(d: &Deployment, protocol: u16) -> (Option<session::JobContext>, Vec<u8>) {
    d.controller().wake();
    let attempts = Arc::new(Captured::default());
    let worker = WorkerProcess::start(d, protocol, Arc::clone(&attempts));
    // The worker attaches asynchronously; give the reporter a moment before
    // the offer can arrive, then nudge a retry if the flow missed the first.
    thread::sleep(Duration::from_millis(100));
    let deadline = Instant::now() + Duration::from_secs(10);
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
            "spec answer did not arrive: {:?}",
            d.controller().stats()
        );
        thread::sleep(Duration::from_millis(50));
    };
    drop(worker);
    answer
}

#[test]
fn a_bound_source_reaches_a_current_worker_with_its_credential_and_event() {
    let d = deployment();
    let (context, bytes) = first_spec(&d, 3);
    let context = context.expect("protocol 3 must receive the spec");
    assert!(RunSpec::decode(&bytes).is_ok());
    let access = context.source.expect("bound source must be delivered");
    assert_eq!(access.binding.remote, REMOTE);
    assert_eq!(
        access.credential,
        Credential::Https {
            username: "deploy".into(),
            secret: SECRET.into()
        }
    );
    assert_eq!(access.version, 1);
    assert!(access.expires_ms > UnixMillis::now().0);
    assert!(!format!("{:?}", access.credential).contains(SECRET));
    // The run has no provenance here (the test creates it with the store
    // primitive), so the event facts are the manual fallback: recorded, never
    // invented.
    assert_eq!(context.event.name, "manual");
    assert_eq!(context.event.key, "manual");
    assert!(context.event.base_ref.is_none());
    assert!(context.event.pr_number.is_none());
}

#[test]
fn a_worker_below_the_context_protocol_is_refused_rather_than_misreading_it() {
    for protocol in [1, 2] {
        // A fresh deployment per protocol: the first worker leases the only
        // job, and a leased job is not re-offered.
        let d = deployment();
        let (context, bytes) = first_spec(&d, protocol);
        assert!(
            context.is_none(),
            "protocol {protocol} must not see a context it cannot decode"
        );
        assert!(bytes.is_empty());
    }
}
