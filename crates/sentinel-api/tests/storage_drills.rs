//! The storage Part's failure drills: a policy changed on a running controller, a tenant at its hard
//! threshold, retention lowered to recover space, and one tenant's storage touching nobody else's.
//!
//! Each drives the real controller — its maintenance thread, its writer transactions and its own HTTP
//! routes — and asserts the numbers an operator reads back. What is simulated is named where it is used.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use fixture::call;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{
    controller::{Controller, StoragePolicy},
    identity::Identity,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self as authz, Authority, NamespaceKind},
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{Expect, Objects},
    retention::Deployment,
    runs, space,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
/// The tenant quota every drill starts from: small enough that a few hundred bytes are a fraction of it.
const QUOTA: u64 = 1_000;
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// How often the controller's maintenance and notice threads look in a drill.
const EVERY: Duration = Duration::from_millis(25);
/// A drill waits this long for a pass before it fails.
const PATIENCE: Duration = Duration::from_secs(30);

struct Api {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    acme: TenantId,
    beta: TenantId,
    acme_repo: RepoId,
    pool: PoolId,
    /// The session cookie and the CSRF token every write carries.
    session: (String, String),
}

fn start() -> Api {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    objects.set_deployment(Deployment {
        tenant_quota_bytes: QUOTA,
        ..Deployment::default()
    });
    objects.set_admission(Arc::new(
        space::Admission::with_probe(
            space::Watermarks {
                reserve: 1 << 30,
                low: 2 << 30,
                high: 4 << 30,
                floor: 1 << 27,
            },
            || Ok(1 << 50),
        )
        .unwrap(),
    ));
    let now = UnixMillis::now();
    let root =
        sentinel_store::local_auth::bootstrap(&store, "root", "Root", PASSWORD.as_bytes(), now)
            .unwrap();
    let (acme, beta) = (TenantId::new(), TenantId::new());
    let (acme_repo, beta_repo) = (RepoId::new(), RepoId::new());
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            let platform = Principal::new(root, P::ALL, None, None);
            for (tenant, slug) in [(acme, "acme"), (beta, "beta")] {
                authz::create_namespace(
                    tx,
                    platform,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    now,
                )?;
                authz::set_membership(tx, platform, tenant, root, Role::TenantAdmin)?;
            }
            jobs::insert_repo(tx, acme, acme_repo, "app", now)?;
            jobs::insert_repo(tx, beta, beta_repo, "site", now)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(acme),
                now,
            )
        })
        .unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    // The maintenance pass runs on its own thread; a drill shortens its interval so a pass lands inside
    // the test instead of after a minute.
    controller.set_storage_policy(StoragePolicy { interval_ms: 25 });
    let mut api = Api {
        _dir: dir,
        store,
        objects,
        logs,
        controller,
        server: None,
        base: String::new(),
        acme,
        beta,
        acme_repo,
        pool,
        session: (String::new(), String::new()),
    };
    api.serve();
    let (status, headers, body) = call(
        &api.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": "root", "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let cookie = headers
        .iter()
        .find(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.split(';').next().unwrap().to_owned())
        .expect("the sign-in sets a session cookie");
    let csrf = body["csrf"]
        .as_str()
        .expect("the sign-in answers the CSRF token")
        .to_owned();
    api.session = (cookie, csrf);
    api
}

impl Api {
    fn serve(&mut self) {
        let server = sentinel_api::Server::start_with(
            sentinel_api::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                store: Arc::clone(&self.store),
                logs: Arc::clone(&self.logs),
                objects: Arc::clone(&self.objects),
                controller: self.controller.handle(),
                secret_key: None,
                sessions: sentinel_store::local_auth::Policy::default(),
                github_webhook_secret: None,
                intake: None,
                public_url: None,
                github_sign_in: None,
                trusted_proxies: sentinel_api::TrustedProxy::loopback(),
            },
            sentinel_api::Options {
                notices_every: Some(EVERY),
                ..sentinel_api::Options::default()
            },
        )
        .unwrap();
        self.base = format!("http://{}", server.local_addr());
        self.server = Some(server);
    }

    fn headers(&self) -> Vec<(&str, &str)> {
        vec![
            ("cookie", self.session.0.as_str()),
            ("x-sentinel-csrf", self.session.1.as_str()),
        ]
    }

    fn get(&self, path: &str) -> (u16, Value) {
        let (status, _, body) = call(&self.base, "GET", path, None, &self.headers());
        (status, body)
    }

    fn put(&self, path: &str, body: &Value) -> (u16, Value) {
        let (status, _, body) = call(&self.base, "PUT", path, Some(body), &self.headers());
        (status, body)
    }

    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let (status, _, body) = call(&self.base, "POST", path, Some(body), &self.headers());
        (status, body)
    }

    fn storage(&self, slug: &str) -> Value {
        let (status, body) = self.get(&format!("/api/v1/tenants/{slug}/storage"));
        assert_eq!(status, 200, "{body}");
        body
    }

    fn platform_storage(&self) -> Value {
        let (status, body) = self.get("/api/v1/admin/storage");
        assert_eq!(status, 200, "{body}");
        body
    }

    fn count(&self, sql: &str) -> i64 {
        self.store
            .read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?))
            .unwrap()
    }

    /// Commits one object of `bytes` distinct bytes to `tenant`, the accounting a staged upload's commit
    /// makes, and answers what the tenant now stores.
    fn object(&self, tenant: TenantId, bytes: u64) -> u64 {
        let content: Vec<u8> = (0..bytes)
            .map(|i| (i.wrapping_mul(31).wrapping_add(bytes) % 251) as u8)
            .collect();
        let staged = self
            .objects
            .stage(tenant, content.as_slice(), u64::MAX, Expect::default())
            .unwrap();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        self.used(tenant)
    }

    fn used(&self, tenant: TenantId) -> u64 {
        self.store
            .read(move |c| Ok(sentinel_store::retention::tenant_usage(c, tenant)?.total()))
            .unwrap()
    }

    /// An attempt of this tenant's repository that was released at `released`.
    fn attempt(
        &self,
        tenant: TenantId,
        repo: RepoId,
        released: UnixMillis,
    ) -> (RunId, JobId, AttemptId) {
        let (run, pool) = (RunId::new(), self.pool);
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let worker = WorkerId::new();
        let attempt = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
                runs::resolve_image(tx, tenant, ids[0], IMAGE, "linux/amd64")?;
                let issued = workers::issue_enrollment(
                    tx,
                    Authority::HostLocal,
                    pool,
                    60_000,
                    UnixMillis::now(),
                )?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(4),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    UnixMillis::now(),
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    Capacity {
                        cpu_millis: 4_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 0,
                    },
                )?;
                let offer = dispatch::place(
                    tx,
                    worker,
                    pool,
                    dispatch::DEFAULT_LEASE_MS,
                    UnixMillis::now(),
                )?
                .expect("the queued job was placed");
                // The lease is released at a stated instant so the drill chooses what retention sees,
                // rather than waiting an hour for a log to become due.
                tx.execute(
                    &format!(
                        "UPDATE attempts SET released_ms = {} WHERE id = ?1",
                        released.0
                    ),
                    [offer.attempt.as_bytes().as_slice()],
                )?;
                Ok(offer.attempt)
            })
            .unwrap();
        let (run, job) = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT j.run_id, a.job_id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE a.id = ?1",
                    [attempt.as_bytes().as_slice()],
                    |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?)),
                )?)
            })
            .map(|(run, job)| {
                (
                    RunId::from_bytes(run).unwrap(),
                    JobId::from_bytes(job).unwrap(),
                )
            })
            .unwrap();
        (run, job, attempt)
    }

    /// An attempt of this tenant's repository released at `released` with one line in its log, so the
    /// controller's own pass stamps it.
    fn released(
        &self,
        tenant: TenantId,
        repo: RepoId,
        released: UnixMillis,
    ) -> (RunId, JobId, AttemptId) {
        let (run, job, attempt) = self.attempt(tenant, repo, released);
        let frame = sentinel_protocol::logs::Frame {
            seq: 1,
            step: 0,
            stream: sentinel_protocol::logs::Stream::Stdout,
            bytes: b"built the archive\n".to_vec(),
        };
        self.logs.append(run, job, attempt, &frame).unwrap();
        self.logs.finish(run, job, attempt, 1, &[]).unwrap();
        self.logs.forget(attempt);
        (run, job, attempt)
    }

    /// One captured artifact of the tenant's repository: `bytes` of content committed, the manifest that
    /// names an entry, and the row that points at that manifest — the three a worker's publication writes in
    /// one transaction.
    fn artifact(
        &self,
        tenant: TenantId,
        repo: RepoId,
        name: &str,
        bytes: u64,
        created: UnixMillis,
    ) {
        let (run, job, attempt) = self.attempt(tenant, repo, created);
        let body: Vec<u8> = (0..bytes)
            .map(|i| (i.wrapping_mul(17).wrapping_add(bytes) % 251) as u8)
            .collect();
        let staged = self
            .objects
            .stage(tenant, body.as_slice(), u64::MAX, Expect::default())
            .unwrap();
        let (digest, len) = (staged.digest(), staged.len());
        let manifest = artifact_manifest(job, name);
        let name = name.to_owned();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| {
                objects.commit(tx, &staged)?;
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    sentinel_store::objects::Kind::Artifact,
                    &manifest,
                    &[sentinel_store::objects::Entry {
                        path: "out/dist.tar".into(),
                        digest,
                        len,
                        mode: 0o644,
                    }],
                )?;
                artifacts::record_class(
                    tx,
                    tenant,
                    run,
                    job,
                    attempt,
                    &name,
                    None,
                    artifacts::State::Captured,
                    Some(version),
                    1,
                    len,
                    UnixMillis(created.0 + 90 * 86_400_000),
                    created,
                )
            })
            .unwrap();
    }

    /// Waits until `check` holds, failing the drill with `what` if a pass never gets there.
    fn until(&self, what: &str, mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + PATIENCE;
        while !check() {
            assert!(Instant::now() < deadline, "never happened: {what}");
            std::thread::sleep(EVERY);
        }
    }
}

/// The manifest a job's artifact lives under, the name the sweep retires it by.
fn artifact_manifest(job: JobId, name: &str) -> String {
    artifacts::manifest_name(job, name)
}

/// The hard threshold is reached: uploads are refused and nothing is stored.
fn refused(api: &Api, slug: &str, len: u64) {
    let (status, body) = api.post(
        &format!("/api/v1/tenants/{slug}/uploads"),
        &json!({ "len": len }),
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"].as_str(), Some("quota_exceeded"), "{body}");
}

#[test]
fn an_override_changes_what_the_next_check_enforces_and_the_next_pass_removes_without_a_restart() {
    let api = start();
    // Below every threshold, and inside the deployment's two-week log retention.
    assert_eq!(api.object(api.acme, 500), 500);
    assert_eq!(
        api.storage("acme")["thresholds"]["state"].as_str(),
        Some("ok")
    );
    let (status, body) = api.post("/api/v1/tenants/acme/uploads", &json!({ "len": 100 }));
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        api.used(api.acme),
        600,
        "the open upload's declared length counts"
    );

    // The tenant's own override, through the platform's admin route: a hard line at 40 %, which is 400
    // bytes of this 1,000 byte quota. Nothing restarts between the write and the checks below.
    let (status, body) = api.put(
        "/api/v1/admin/tenants/acme/storage",
        &json!({ "hard_percent": 40, "soft_percent": 30 }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["effective"]["hard_percent"].as_u64(), Some(40));

    // The next check enforces it: the page reads `hard` at 600 bytes and the next upload is refused.
    let report = api.storage("acme");
    assert_eq!(
        report["thresholds"]["state"].as_str(),
        Some("hard"),
        "{report}"
    );
    assert_eq!(
        report["thresholds"]["hard_limit_bytes"].as_u64(),
        Some(400),
        "{report}"
    );
    assert_eq!(
        report["usage"]["object_bytes"].as_u64(),
        Some(600),
        "{report}"
    );
    refused(&api, "acme", 1);

    // A retention lowered through the same route reaches the next pass: the log was released an hour ago,
    // so a one-hour retention is already due and the pass that follows frees its bytes.
    let released = UnixMillis(UnixMillis::now().0 - 3_600_000);
    let (run, job, attempt) = api.released(api.acme, api.acme_repo, released);
    let dir = api.logs.attempt_dir(run, job, attempt);
    api.until("the pass stamps the released log", || {
        api.count("SELECT COUNT(*) FROM attempts WHERE log_bytes > 0") == 1
    });
    assert!(dir.exists(), "the log is still on disk");
    assert!(
        api.used(api.acme) > 600,
        "the log's bytes joined the usage: {}",
        api.used(api.acme)
    );
    let (status, body) = api.put(
        "/api/v1/admin/tenants/acme/storage",
        &json!({ "log_retention_secs": 3_600 }),
    );
    assert_eq!(status, 200, "{body}");
    api.until("the pass expires the log", || {
        api.count("SELECT COUNT(*) FROM attempts WHERE log_expired_ms IS NOT NULL") == 1
    });
    assert_eq!(api.used(api.acme), 600, "the log's bytes came back");
    assert!(!dir.exists(), "the expired log's directory is gone");

    // Raising the hard line through the route admits work again on the next check, with no restart either.
    let (status, body) = api.put(
        "/api/v1/admin/tenants/acme/storage",
        &json!({ "hard_percent": 90 }),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = api.post("/api/v1/tenants/acme/uploads", &json!({ "len": 100 }));
    assert_eq!(status, 201, "{body}");
}

#[test]
fn a_tenant_at_its_hard_threshold_stops_admitting_work_and_the_reason_is_where_an_operator_reads_it()
 {
    let api = start();
    assert_eq!(api.object(api.acme, QUOTA), QUOTA);
    let report = api.storage("acme");
    assert_eq!(
        report["thresholds"]["state"].as_str(),
        Some("hard"),
        "{report}"
    );
    assert_eq!(
        report["thresholds"]["hard_limit_bytes"].as_u64(),
        Some(QUOTA),
        "{report}"
    );
    assert_eq!(
        report["usage"]["object_bytes"].as_u64(),
        Some(QUOTA),
        "{report}"
    );

    // Nothing more is admitted: an upload of one byte would pass the line, so it is refused and the store
    // holds what it held before.
    refused(&api, "acme", 1);
    assert_eq!(api.used(api.acme), QUOTA);
    assert_eq!(api.count("SELECT COUNT(*) FROM uploads"), 0);

    // A platform operator sees the same tenant at its limit from the deployment's own list and its storage
    // report, without opening the tenant's page.
    let list = api.platform_storage();
    assert_eq!(list["stored_bytes"].as_u64(), Some(QUOTA), "{list}");
    let (status, tenants) = api.get("/api/v1/admin/tenants");
    assert_eq!(status, 200, "{tenants}");
    let acme = tenants["tenants"]
        .as_array()
        .expect("the platform's tenant list")
        .iter()
        .find(|t| t["slug"] == "acme")
        .expect("acme is listed");
    assert_eq!(acme["state"].as_str(), Some("hard"), "{acme}");
    assert_eq!(acme["used_percent"].as_u64(), Some(100), "{acme}");

    // The reason is on the page the tenant's administrator opens: the hard line in bytes, the state, and the
    // notice the controller's own pass told, with one audit row naming the crossing.
    api.until("the crossing is told", || {
        api.storage("acme")["notice"].as_object().is_some()
    });
    let report = api.storage("acme");
    assert_eq!(
        report["notice"]["delivery"].as_str(),
        Some("in_app"),
        "{report}"
    );
    assert_eq!(report["notice"]["threshold_percent"].as_u64(), Some(80));
    assert_eq!(report["notice"]["limit_bytes"].as_u64(), Some(QUOTA));
    assert_eq!(
        api.count("SELECT COUNT(*) FROM auth_audit WHERE event = 99"),
        1,
        "one audit row names the crossing"
    );

    // A log at the limit is counted and never refused, so the tenant keeps the evidence of what it ran.
    let (run, job, attempt) = api.released(api.acme, api.acme_repo, UnixMillis::now());
    api.until("the log at the limit is stamped", || {
        api.count("SELECT COUNT(*) FROM attempts WHERE log_bytes > 0") == 1
    });
    assert!(api.logs.attempt_dir(run, job, attempt).exists());
    assert!(api.used(api.acme) > QUOTA, "the log's bytes are counted");
    assert!(
        api.count("SELECT COUNT(*) FROM attempts WHERE log_expired_ms IS NOT NULL") == 0,
        "and nothing expired it"
    );
}

#[test]
fn a_lowered_retention_frees_the_space_in_the_next_pass_and_the_pass_reports_what_it_removed() {
    let api = start();
    let created = UnixMillis(UnixMillis::now().0 - 3_600_000);
    api.artifact(api.acme, api.acme_repo, "dist", 200, created);
    assert_eq!(api.object(api.acme, 300), 500);
    assert_eq!(api.count("SELECT COUNT(*) FROM artifacts"), 1);
    // The pass indexes the manifest, which is what moves the artifact's bytes from the uploads class into
    // the artifacts class.
    api.until("the pass indexes the manifest", || {
        api.storage("acme")["classes"]["artifacts"].as_u64() == Some(200)
    });

    // Lowered through the admin route: an hour of artifacts, so the row created an hour ago is due at the
    // very next pass. No restart and no resealed database.
    let (status, body) = api.put(
        "/api/v1/admin/tenants/acme/storage",
        &json!({ "artifact_retention_secs": 3_600 }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["effective"]["artifact_retention_ms"].as_u64(),
        Some(3_600_000)
    );

    api.until("the pass sweeps the artifact", || {
        api.count("SELECT COUNT(*) FROM artifacts") == 0
    });
    // The pass names what it removed, on the platform's storage report.
    let removed = api.platform_storage()["removed"].clone();
    assert!(
        removed["artifacts"].as_u64().unwrap_or(0) >= 1,
        "the sweep is reported: {removed}"
    );
    // The artifact's class bytes came back and its charge left the repository.
    assert_eq!(
        api.storage("acme")["classes"]["artifacts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        api.count("SELECT COUNT(*) FROM repo_usage WHERE artifact_bytes > 0"),
        0
    );

    // The object the artifact held is reclaimed by the pass once its unreferenced grace has passed: the
    // grace is a day, so the drill ages the row rather than waiting one out.
    api.store
        .writer()
        .write(|tx| {
            tx.execute(
                "UPDATE object_unreferenced SET created_ms = created_ms - ?1",
                [25 * 3_600_000i64],
            )?;
            Ok(())
        })
        .unwrap();
    api.until("the pass reclaims the object", || api.used(api.acme) == 0);
    let removed = api.platform_storage()["removed"].clone();
    assert!(
        removed["objects"].as_u64().unwrap_or(0) >= 1,
        "the reclamation is reported: {removed}"
    );
    assert!(
        removed["bytes"].as_u64().unwrap_or(0) >= 300,
        "the bytes it freed are reported: {removed}"
    );
}

#[test]
fn one_tenants_usage_notice_and_thresholds_move_nothing_of_anothers() {
    let api = start();
    // The same bytes in both tenants, then acme is capped by an override and beta is not.
    assert_eq!(api.object(api.acme, 500), 500);
    assert_eq!(api.object(api.beta, 500), 500);
    let (status, body) = api.put(
        "/api/v1/admin/tenants/acme/storage",
        &json!({ "hard_percent": 40, "soft_percent": 30 }),
    );
    assert_eq!(status, 200, "{body}");

    // The override is acme's alone: beta still stands `ok` at its own 50 % and admits one more byte.
    assert_eq!(
        api.storage("acme")["thresholds"]["state"].as_str(),
        Some("hard")
    );
    let beta = api.storage("beta");
    assert_eq!(beta["thresholds"]["state"].as_str(), Some("ok"), "{beta}");
    assert_eq!(beta["thresholds"]["hard_limit_bytes"].as_u64(), Some(QUOTA));
    assert_eq!(beta["usage"]["object_bytes"].as_u64(), Some(500));
    let (status, body) = api.post("/api/v1/tenants/beta/uploads", &json!({ "len": 1 }));
    assert_eq!(status, 201, "{body}");
    refused(&api, "acme", 1);

    // acme crossing its soft threshold tells acme's administrators and leaves beta's page with no notice.
    api.until("acme's crossing is told", || {
        api.storage("acme")["notice"].as_object().is_some()
    });
    assert!(
        api.storage("beta")["notice"].is_null(),
        "beta was told nothing"
    );
    assert_eq!(
        api.count("SELECT COUNT(*) FROM storage_notices"),
        1,
        "one tenant over the line, one row"
    );

    // Beta's usage is its own: acme's bytes never appear in it, and beta's own commit moves only beta.
    assert_eq!(api.used(api.beta), 501);
    assert_eq!(api.used(api.acme), 500);
    assert_eq!(api.object(api.beta, 100), 601);
    assert_eq!(api.used(api.acme), 500);
    let acme = api.storage("acme");
    assert_eq!(acme["usage"]["object_bytes"].as_u64(), Some(500), "{acme}");
    assert_eq!(
        acme["classes"]["uploads"].as_u64(),
        Some(500),
        "acme's classes count acme's objects alone: {acme}"
    );
    assert_eq!(
        api.storage("beta")["classes"]["uploads"].as_u64(),
        Some(601),
        "beta's 600 object bytes and its open upload's declared length"
    );

    // A repository policy of beta's leaves acme's line where it is.
    let (status, body) = api.put(
        "/api/v1/tenants/beta/repos/site/storage",
        &json!({ "quota_bytes": 600 }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        api.storage("acme")["thresholds"]["hard_limit_bytes"].as_u64(),
        Some(400)
    );
}
