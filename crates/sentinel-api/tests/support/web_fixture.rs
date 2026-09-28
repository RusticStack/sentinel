//! A controller seeded the way a person finds one: two organizations with
//! repositories, three members with different roles and a pending
//! applicant, a worker with capacity and labels, a diamond run with a
//! passed, a failed (with a gap in its log), a running and a blocked job,
//! filterable push and pull-request runs, a run with a large log, a job the
//! fleet cannot place, and a pending GitHub check. Shared by the web API
//! tests and the real-browser test (U02–U06).

#![allow(dead_code)]

use std::sync::Arc;

use sentinel_core::{
    AttemptId, Event, FailureClass, Fence, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    logs::{Frame, Stream},
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
    summary::{AttemptSummary, CacheRecord, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store,
    auth::{self as authz, Authority, NamespaceKind},
    checks, dispatch, jobs, local_auth,
    logs::LogStore,
    lookup,
    objects::Objects,
    provenance,
    registration::{self, Applicant, DeploymentPolicy, Terms},
    runs,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

pub const PASSWORD: &str = "correct horse battery staple";
const BUSYBOX: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub controller: Controller,
    pub objects: Arc<Objects>,
    server: Option<sentinel_api::Server>,
    pub base: String,
    pub root: UserId,
    /// `Bearer sntl_…` for root with every permission.
    pub auth: String,
    pub acme: TenantId,
    pub beta: TenantId,
    pub app: RepoId,
    pub web: RepoId,
    pub dana: UserId,
    pub rui: UserId,
    pub pat: UserId,
    pub pool: PoolId,
    pub worker: WorkerId,
    pub diamond: RunId,
    pub jobs: std::collections::HashMap<&'static str, JobId>,
    pub attempts: std::collections::HashMap<&'static str, (AttemptId, Fence)>,
    /// The running job's attempt, whose log a test may keep appending to.
    pub live: (RunId, JobId, AttemptId, Fence),
    /// Next sequence of the live log.
    pub live_seq: std::sync::atomic::AtomicU64,
    pub bulk: RunId,
    pub bulk_attempt: AttemptId,
    pub bulk_lines: u64,
    pub pr_run: RunId,
    pub push_run: RunId,
    pub stuck_run: RunId,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

const DIAMOND: &str = "schema: 1
on: [push]
jobs:
  alpha:
    image: IMAGE
    steps:
      - { id: deps, run: 'true' }
      - { id: build, run: 'true' }
    cache:
      - { name: cargo, key: 'v1', paths: [target] }
  beta:
    needs: [alpha]
    image: IMAGE
    steps:
      - { id: prepare, run: 'true' }
      - { id: unit, run: 'go test ./...' }
      - { id: report, run: 'true' }
  gamma:
    needs: [alpha]
    image: IMAGE
    steps:
      - { id: integration, run: 'true' }
      - { id: smoke, run: 'true' }
  zeta:
    needs: [beta, gamma]
    image: IMAGE
    steps: [{ id: publish, run: 'true' }]
";

const BULK: &str = "schema: 1
on: [push]
jobs:
  huge:
    image: IMAGE
    steps:
      - { id: prepare, run: 'true' }
      - { id: flood, run: 'true' }
";

const STUCK: &str = "schema: 1
on: [push]
jobs:
  enormous:
    image: IMAGE
    resources: {cpu: 64, memory: 1GiB}
    steps: [{ id: never, run: 'true' }]
";

fn pipeline(text: &str) -> String {
    text.replace("IMAGE", BUSYBOX)
}

/// A pipeline compiled and pinned the way dispatch does it.
fn spec(pipeline_text: &str, sha: &str, ref_name: &str) -> RunSpec {
    let compiled = compile_str(&pipeline(pipeline_text)).expect("fixture pipeline compiles");
    let source = PinnedSource::new("https://github.com/acme/app.git", sha, Some(ref_name)).unwrap();
    RunSpec::new(source, compiled).unwrap()
}

/// Create a run the way `POST …/runs` does, with explicit provenance.
#[allow(clippy::too_many_arguments)]
fn create_run(
    store: &Store,
    root: UserId,
    tenant: TenantId,
    repo: RepoId,
    pipeline_text: &str,
    sha: &str,
    ref_name: &str,
    trigger: &str,
    pr: Option<u64>,
) -> (RunId, Vec<JobId>) {
    let spec = spec(pipeline_text, sha, ref_name);
    let images = runs::pinned_images(&spec).unwrap();
    let (sha, ref_name, trigger) = (sha.to_owned(), ref_name.to_owned(), trigger.to_owned());
    store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            let run = RunId::new();
            let jobs = authz::create_run(
                tx,
                Principal::new(root, P::ALL, None, None),
                repo,
                run,
                &spec,
                now,
            )?;
            for (job, (digest, platform)) in jobs.iter().zip(&images) {
                runs::resolve_image(tx, tenant, *job, digest, platform)?;
            }
            provenance::insert(
                tx,
                &provenance::Provenance {
                    tenant,
                    repo,
                    trigger,
                    delivery: None,
                    provider: None,
                    ref_name: Some(ref_name),
                    old_sha: None,
                    new_sha: Some(sha.clone()),
                    head_sha: pr.map(|_| sha.clone()),
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: sha,
                    pipeline_path: None,
                    pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                    pr_number: pr,
                },
                run,
                now,
            )?;
            checks::record_run(tx, tenant, run, now)?;
            Ok((run, jobs))
        })
        .unwrap()
}

fn job_named(store: &Store, tenant: TenantId, run: RunId, name: &str) -> JobId {
    let view = store
        .read(|c| sentinel_store::status::run(c, tenant, run))
        .unwrap();
    view.jobs.iter().find(|j| j.name == name).unwrap().id
}

fn lease(store: &Store, tenant: TenantId, job: JobId, worker: WorkerId) -> (AttemptId, Fence) {
    store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            let leased = jobs::lease(tx, tenant, job, worker, UnixMillis(i64::MAX / 2), now)?;
            dispatch::acknowledge(tx, worker, leased.0, leased.1, now)?;
            for event in [Event::PreparationStarted, Event::StepsStarted] {
                dispatch::report(tx, worker, leased.0, leased.1, event, None, now, None)?;
            }
            Ok(leased)
        })
        .unwrap()
}

fn settle(
    store: &Store,
    worker: WorkerId,
    leased: (AttemptId, Fence),
    event: Event,
    summary: AttemptSummary,
) {
    let bytes = summary.encode().unwrap();
    store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            dispatch::report(
                tx,
                worker,
                leased.0,
                leased.1,
                Event::FinalizationStarted,
                None,
                now,
                None,
            )?;
            dispatch::report(
                tx,
                worker,
                leased.0,
                leased.1,
                event,
                Some(&bytes),
                now,
                None,
            )?;
            dispatch::log_ended(tx, leased.0)
        })
        .unwrap();
}

fn step(index: u32, id: &str, outcome: StepOutcome, ms: u64) -> StepRecord {
    StepRecord {
        index,
        id: id.into(),
        outcome,
        duration_ns: Some(ms * 1_000_000),
    }
}

/// Append `text` to a log as frames of at most one frame's bytes.
fn write_log(
    logs: &LogStore,
    (run, job, attempt): (RunId, JobId, AttemptId),
    seq: &mut u64,
    step: u32,
    stream: Stream,
    text: &[u8],
) {
    for chunk in text.chunks(sentinel_protocol::limits::MAX_LOG_FRAME_BYTES) {
        *seq += 1;
        logs.append(
            run,
            job,
            attempt,
            &Frame {
                seq: *seq,
                step,
                stream,
                bytes: chunk.to_vec(),
            },
        )
        .unwrap();
    }
}

impl Fixture {
    /// Seed everything. `bulk_mib` sizes the large log's big step.
    pub fn new(bulk_mib: usize) -> Fixture {
        Fixture::serving(bulk_mib, None)
    }

    /// As [`Fixture::new`], with the deployment's public URL: the origin
    /// browsers use (the web interface's), which sign-in checks `Origin`
    /// against.
    pub fn serving(bulk_mib: usize, public_url: Option<String>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
        let objects = Arc::new(Objects::open(dir.path()).unwrap());
        let key_path = dir.path().join("master.key");
        sentinel_auth::sealed::Key::create(&key_path).unwrap();
        let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
        let now = UnixMillis::now();
        let root =
            local_auth::bootstrap(&store, "root", "Root Admin", PASSWORD.as_bytes(), now).unwrap();
        let (acme, beta, app, web, site) = (
            TenantId::new(),
            TenantId::new(),
            RepoId::new(),
            RepoId::new(),
            RepoId::new(),
        );
        let (pool, worker) = (PoolId::new(), WorkerId::new());
        store
            .writer()
            .write(move |tx| {
                let admin = Principal::new(root, P::ALL, None, None);
                for (tenant, slug) in [(acme, "acme"), (beta, "beta")] {
                    authz::create_namespace(
                        tx,
                        admin,
                        tenant,
                        Namespace::parse(slug).unwrap(),
                        NamespaceKind::Organization,
                        now,
                    )?;
                    authz::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
                }
                authz::create_repo(tx, admin, acme, app, "app", now)?;
                authz::create_repo(tx, admin, acme, web, "web", now)?;
                authz::create_repo(tx, admin, beta, site, "site", now)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    PoolKind::Dedicated(acme),
                    now,
                )?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &sentinel_auth::secret::Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                        name: "builder-1",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(4),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    now,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    dispatch::Capacity {
                        cpu_millis: 8_000,
                        memory_bytes: 16 << 30,
                        disk_bytes: 100 << 30,
                    },
                )?;
                dispatch::report_profile(
                    tx,
                    worker,
                    &dispatch::ReportedProfile {
                        labels: &["linux".to_owned(), "ssd".to_owned()],
                        host_id: Some([7; 16]),
                        avail_images: &[],
                        cache_bytes: Some(5 << 30),
                        load_ns: None,
                    },
                )
            })
            .unwrap();
        // People: an operator and a reader of acme with passwords, and an
        // applicant waiting for approval.
        let invite = |role: Role| {
            store
                .writer()
                .write(move |tx| {
                    registration::invite(
                        tx,
                        Authority::HostLocal,
                        Terms {
                            tenant: Some(acme),
                            role: Some(role),
                            identity: None,
                            lifetime_ms: 3_600_000,
                        },
                        UnixMillis::now(),
                    )
                })
                .unwrap()
                .secret
        };
        let admitted = |name: &str, role: Role| {
            let secret = invite(role);
            match registration::register(
                &store,
                Applicant::Local {
                    display_name: name,
                    username: &name.to_ascii_lowercase(),
                    password: PASSWORD.as_bytes(),
                },
                Some(&secret),
                UnixMillis::now(),
            )
            .unwrap()
            {
                registration::Admission::Admitted(user) => user,
                other => panic!("{other:?}"),
            }
        };
        let dana = admitted("Dana", Role::Operator);
        let rui = admitted("Rui", Role::Reader);
        store
            .writer()
            .write(|tx| {
                registration::set_policy(
                    tx,
                    Authority::HostLocal,
                    DeploymentPolicy {
                        registration: registration::Registration::ApprovalRequired,
                        ..registration::policy(tx)?
                    },
                    UnixMillis::now(),
                )
            })
            .unwrap();
        let pat = match registration::register(
            &store,
            Applicant::Local {
                display_name: "Pat",
                username: "pat",
                password: PASSWORD.as_bytes(),
            },
            None,
            UnixMillis::now(),
        )
        .unwrap()
        {
            registration::Admission::Pending(user) => user,
            other => panic!("{other:?}"),
        };
        let granted = tokens::provision(
            &store,
            Grant::new(root, "fixture", P::ALL),
            UnixMillis::now(),
        )
        .unwrap();
        let controller = Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            Arc::clone(&objects),
            Identity::generate("controller").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server = sentinel_api::Server::start(sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs: Arc::clone(&logs),
            objects: Arc::clone(&objects),
            controller: controller.handle(),
            secret_key: Some(key),
            sessions: local_auth::Policy::default(),
            github_webhook_secret: None,
            intake: None,
            public_url,
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        })
        .unwrap();
        let base = format!("http://{}", server.local_addr());

        // The diamond: alpha passed, beta failed, gamma running, zeta blocked.
        let (diamond, _) = create_run(
            &store,
            root,
            acme,
            app,
            DIAMOND,
            "1111111111111111111111111111111111111111",
            "refs/heads/main",
            "push",
            None,
        );
        let mut jobs = std::collections::HashMap::new();
        let mut attempts = std::collections::HashMap::new();
        for name in ["alpha", "beta", "gamma", "zeta"] {
            jobs.insert(name, job_named(&store, acme, diamond, name));
        }
        let alpha = lease(&store, acme, jobs["alpha"], worker);
        let mut seq = 0;
        write_log(
            &logs,
            (diamond, jobs["alpha"], alpha.0),
            &mut seq,
            0,
            Stream::Stdout,
            b"fetching 42 crates\nfetched\n",
        );
        write_log(
            &logs,
            (diamond, jobs["alpha"], alpha.0),
            &mut seq,
            1,
            Stream::Stdout,
            b"   Compiling app v0.1.0\n    Finished release in 12.3s\n",
        );
        logs.finish(diamond, jobs["alpha"], alpha.0, seq, &[])
            .unwrap();
        settle(
            &store,
            worker,
            alpha,
            Event::Passed,
            AttemptSummary {
                checkout_ns: Some(420_000_000),
                image_pull_ns: Some(80_000_000),
                image_present: Some(true),
                container_start_ns: Some(150_000_000),
                steps_ns: Some(12_600_000_000),
                finalize_ns: Some(300_000_000),
                steps: vec![
                    step(0, "deps", StepOutcome::Passed, 300),
                    step(1, "build", StepOutcome::Passed, 12_300),
                ],
                caches: vec![CacheRecord {
                    name: "cargo".into(),
                    class: 1,
                    outcome: "hit".into(),
                    lookup_ns: Some(2_000_000),
                    lock_wait_ns: None,
                    clone_ns: Some(40_000_000),
                    first_touch_ns: None,
                    files: 1200,
                    bytes: 900 << 20,
                    copied_bytes: 0,
                    reflink: true,
                    commit_ns: None,
                    staged_bytes: None,
                    reused_bytes: None,
                    dirty_bytes: None,
                    publish: None,
                    costly_hit: false,
                }],
                ..AttemptSummary::default()
            },
        );
        attempts.insert("alpha", alpha);

        let beta_lease = lease(&store, acme, jobs["beta"], worker);
        let mut seq = 0;
        write_log(
            &logs,
            (diamond, jobs["beta"], beta_lease.0),
            &mut seq,
            0,
            Stream::Stdout,
            b"go: downloading modules\n",
        );
        // A hole: frame 2 was never stored.
        seq += 1;
        let hole = seq;
        let mut unit = Vec::new();
        for i in 0..200 {
            unit.extend_from_slice(
                format!("=== RUN   TestNoise{i}\n--- PASS: TestNoise{i} (0.00s)\n").as_bytes(),
            );
        }
        for event in [
            json!({"Action":"run","Package":"example/api","Test":"TestCheckout"}),
            json!({"Action":"output","Package":"example/api","Test":"TestCheckout","Output":"    api_test.go:42: expected 200, got 500\n"}),
            json!({"Action":"fail","Package":"example/api","Test":"TestCheckout"}),
        ] {
            unit.extend_from_slice(&serde_json::to_vec(&event).unwrap());
            unit.push(b'\n');
        }
        write_log(
            &logs,
            (diamond, jobs["beta"], beta_lease.0),
            &mut seq,
            1,
            Stream::Stdout,
            &unit,
        );
        write_log(
            &logs,
            (diamond, jobs["beta"], beta_lease.0),
            &mut seq,
            1,
            Stream::Stderr,
            b"FAIL\texample/api\t0.412s\n",
        );
        write_log(
            &logs,
            (diamond, jobs["beta"], beta_lease.0),
            &mut seq,
            2,
            Stream::Stdout,
            b"report written\n",
        );
        logs.finish(diamond, jobs["beta"], beta_lease.0, seq, &[(hole, hole)])
            .unwrap();
        settle(
            &store,
            worker,
            beta_lease,
            Event::Failed(FailureClass::CommandFailed),
            AttemptSummary {
                checkout_ns: Some(390_000_000),
                steps_ns: Some(4_100_000_000),
                steps: vec![
                    step(0, "prepare", StepOutcome::Passed, 90),
                    step(1, "unit", StepOutcome::Failed { code: 1 }, 4_000),
                    step(2, "report", StepOutcome::Passed, 10),
                ],
                detail: "step unit exited 1".into(),
                ..AttemptSummary::default()
            },
        );
        attempts.insert("beta", beta_lease);

        let gamma_job = jobs["gamma"];
        let gamma = lease(&store, acme, gamma_job, worker);
        let mut live_seq = 0;
        write_log(
            &logs,
            (diamond, jobs["gamma"], gamma.0),
            &mut live_seq,
            0,
            Stream::Stdout,
            b"starting integration suite\n",
        );
        attempts.insert("gamma", gamma);

        // A large log: a short first step, then `bulk_mib` MiB of numbered
        // 128-byte lines, then a needle near the end.
        let (bulk, bulk_jobs) = create_run(
            &store,
            root,
            acme,
            app,
            BULK,
            "2222222222222222222222222222222222222222",
            "refs/heads/main",
            "push",
            None,
        );
        let bulk_attempt = lease(&store, acme, bulk_jobs[0], worker);
        let mut seq = 0;
        write_log(
            &logs,
            (bulk, bulk_jobs[0], bulk_attempt.0),
            &mut seq,
            0,
            Stream::Stdout,
            b"preparing\n",
        );
        let mut lines = 0u64;
        let mut chunk = Vec::with_capacity(sentinel_protocol::limits::MAX_LOG_FRAME_BYTES);
        let total = bulk_mib << 20;
        let mut written = 0;
        while written < total {
            chunk.clear();
            while chunk.len() + 128 <= sentinel_protocol::limits::MAX_LOG_FRAME_BYTES
                && written + chunk.len() < total
            {
                lines += 1;
                let line = format!(
                    "line {lines:>9} of the flood: the quick brown fox jumps over the lazy dog"
                );
                chunk.extend_from_slice(line.as_bytes());
                chunk.extend(std::iter::repeat_n(b'.', 127 - line.len()));
                chunk.push(b'\n');
            }
            written += chunk.len();
            seq += 1;
            logs.append(
                bulk,
                bulk_jobs[0],
                bulk_attempt.0,
                &Frame {
                    seq,
                    step: 1,
                    stream: Stream::Stdout,
                    bytes: chunk.clone(),
                },
            )
            .unwrap();
        }
        lines += 1;
        write_log(
            &logs,
            (bulk, bulk_jobs[0], bulk_attempt.0),
            &mut seq,
            1,
            Stream::Stderr,
            b"needle-7f3a: the one line worth finding\n",
        );
        logs.finish(bulk, bulk_jobs[0], bulk_attempt.0, seq, &[])
            .unwrap();
        settle(
            &store,
            worker,
            bulk_attempt,
            Event::Passed,
            AttemptSummary {
                steps: vec![
                    step(0, "prepare", StepOutcome::Passed, 5),
                    step(1, "flood", StepOutcome::Passed, 9_000),
                ],
                ..AttemptSummary::default()
            },
        );

        // Runs to filter by: a pull request and a feature branch in `app`.
        let (pr_run, _) = create_run(
            &store,
            root,
            acme,
            app,
            BULK,
            "3333333333333333333333333333333333333333",
            "refs/heads/main",
            "pull_request",
            Some(42),
        );
        let (push_run, _) = create_run(
            &store,
            root,
            acme,
            app,
            BULK,
            "4444444444444444444444444444444444444444",
            "refs/heads/feature-x",
            "push",
            None,
        );
        // A job no worker can take.
        let (stuck_run, _) = create_run(
            &store,
            root,
            acme,
            web,
            STUCK,
            "5555555555555555555555555555555555555555",
            "refs/heads/main",
            "push",
            None,
        );

        // A check GitHub has not accepted yet, two minutes old.
        let (tenant_bytes, repo_bytes, run_bytes) =
            (*acme.as_bytes(), *app.as_bytes(), *diamond.as_bytes());
        store
            .writer()
            .write(move |tx| {
                let then = UnixMillis::now().0 - 120_000;
                let id = [1u8; 16];
                tx.execute(
                    "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, scope, name, head_sha,
                        external_id, status, title, summary, seq, created_ms, updated_ms)
                     VALUES (?1, ?2, ?3, ?4, 'aggregate', 'sentinel', ?5, 'ext-1', 'in_progress',
                        'Running', 'Jobs are running', 1, ?6, ?6)",
                    (&id[..], &tenant_bytes[..], &repo_bytes[..], &run_bytes[..],
                        "1111111111111111111111111111111111111111", then),
                )?;
                Ok(())
            })
            .unwrap();

        Fixture {
            dir,
            store,
            logs,
            controller,
            objects,
            server: Some(server),
            base,
            root,
            auth: format!("Bearer {}", sentinel_auth::token::format(&granted.secret)),
            acme,
            beta,
            app,
            web,
            dana,
            rui,
            pat,
            pool,
            worker,
            diamond,
            jobs,
            attempts,
            live: (diamond, gamma_job, gamma.0, gamma.1),
            live_seq: std::sync::atomic::AtomicU64::new(live_seq),
            bulk,
            bulk_attempt: bulk_attempt.0,
            bulk_lines: lines,
            pr_run,
            push_run,
            stuck_run,
        }
    }

    /// Append one line to the running job's log (step `step`).
    pub fn live_line(&self, step: u32, text: &str) {
        let seq = self
            .live_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let (run, job, attempt, _) = self.live;
        self.logs
            .append(
                run,
                job,
                attempt,
                &Frame {
                    seq,
                    step,
                    stream: Stream::Stdout,
                    bytes: format!("{text}\n").into_bytes(),
                },
            )
            .unwrap();
    }

    /// A `Bearer sntl_…` for `user` with `permissions`.
    pub fn bearer(&self, user: UserId, permissions: P) -> String {
        let granted = tokens::provision(
            &self.store,
            Grant::new(user, "fixture", permissions),
            UnixMillis::now(),
        )
        .unwrap();
        format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
    }

    /// A `Bearer sntl_…` for a member who is no platform administrator:
    /// every tenant and repository permission its memberships allow.
    pub fn member(&self, user: UserId) -> String {
        self.bearer(user, P::REPOSITORY.union(P::TENANT_ADMIN))
    }

    pub fn tenant_id(&self, slug: &str) -> TenantId {
        self.store
            .read(|c| lookup::tenant_by_slug_any(c, slug))
            .unwrap()
    }
}

/// One HTTP request: status, headers and JSON (or text) body.
pub fn call(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> (u16, Vec<(String, String)>, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let url = format!("{base}{path}");
    let bytes = body.map(|b| b.to_string().into_bytes());
    let response = match method {
        "GET" => {
            let mut r = agent.get(&url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        }
        "DELETE" => {
            let mut r = agent.delete(&url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        }
        _ => {
            let mut r = match method {
                "PUT" => agent.put(&url),
                _ => agent.post(&url),
            };
            r = r.header("content-type", "application/json");
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(bytes.as_deref().unwrap_or(b"{}"))
        }
    }
    .unwrap();
    let status = response.status().as_u16();
    let out_headers = response
        .headers()
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (
        status,
        out_headers,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}
