//! The O05 commands end to end, portable: the real `sentinel` binary with a
//! static credential against an in-process controller API on loopback.
//! Listing pages stream as NDJSON, `wait` exits 0/8/7, an artifact entry
//! downloads with its digest checked, `not_found` and `conflict` keep their
//! exits, and JSON-mode failures touch stderr only.

use std::{
    collections::HashSet,
    process::{Command, Output},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, Event, Fence, JobId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self, NamespaceKind},
    dispatch, jobs, local_auth,
    logs::LogStore,
    objects::{Entry, Expect, Kind, Objects},
    tokens::{self, Grant},
};
use serde_json::{Value, json};

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    root: UserId,
    tenant: TenantId,
    repo: RepoId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let now = UnixMillis::now();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"correct horse battery", now).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let granted =
        tokens::provision(&store, Grant::new(root, "cli", P::ALL), UnixMillis::now()).unwrap();
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
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        secret_key: None,
    })
    .unwrap();
    Deployment {
        base: format!("http://{}", server.local_addr()),
        dir,
        store,
        objects,
        logs,
        _controller: controller,
        server: Some(server),
        token: sentinel_auth::token::format(&granted.secret),
        root,
        tenant,
        repo,
    }
}

/// Run the CLI with the deployment's static credential; nothing from the
/// caller's environment or profiles leaks in.
fn cli(d: &Deployment, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env("SENTINEL_TOKEN", &d.token)
        .env("SENTINEL_SERVER", &d.base)
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", d.dir.path().join("no-profiles"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps: [{ id: s, run: 'true' }]
";

/// Dispatch a one-job run through the CLI itself.
fn dispatch_run(d: &Deployment) -> (RunId, JobId) {
    let file = d.dir.path().join("pipeline.yml");
    std::fs::write(&file, PIPELINE).unwrap();
    let out = cli(
        d,
        &[
            "run",
            "dispatch",
            "--tenant",
            "acme",
            "--repo",
            "app",
            "--pipeline",
            file.to_str().unwrap(),
            "--source",
            "https://github.com/o/r.git",
            "--sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--output",
            "json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let run: Value = serde_json::from_str(&stdout(&out)).unwrap();
    (
        run["id"].as_str().unwrap().parse().unwrap(),
        run["jobs"][0]["id"].as_str().unwrap().parse().unwrap(),
    )
}

fn lease(d: &Deployment, job: JobId) -> (WorkerId, AttemptId, Fence) {
    let tenant = d.tenant;
    d.store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            let worker = enrolled_worker(tx, tenant, now)?;
            let (attempt, fence) =
                jobs::lease(tx, tenant, job, worker, UnixMillis(i64::MAX / 2), now)?;
            Ok((worker, attempt, fence))
        })
        .unwrap()
}

/// A worker the store knows: its own dedicated pool of the tenant and a
/// host-local enrollment. Acknowledgements and reports come only from a
/// registered, unrevoked worker (P08-7).
fn enrolled_worker(
    tx: &sentinel_store::Transaction<'_>,
    tenant: TenantId,
    now: UnixMillis,
) -> sentinel_store::Result<WorkerId> {
    use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
    use sentinel_store::{
        auth::Authority,
        tenancy::{self, PoolKind},
        workers::{self, Presentation},
    };
    let (pool, worker) = (sentinel_core::PoolId::new(), WorkerId::new());
    tenancy::create_pool(
        tx,
        Authority::HostLocal,
        pool,
        "test",
        PoolKind::Dedicated(tenant),
        now,
    )?;
    let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
    let mut text = String::new();
    issued.secret.expose(&mut text);
    workers::enroll(
        tx,
        &sentinel_auth::secret::Secret::parse(&text).unwrap(),
        Presentation {
            worker,
            fingerprint: sentinel_auth::secret::Secret::generate().digest(),
            name: "w",
            negotiated: Negotiated {
                protocol: ProtocolVersion(4),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
            },
        },
        now,
    )?;
    Ok(worker)
}

fn pass(store: &Store, (worker, attempt, fence): (WorkerId, AttemptId, Fence)) {
    store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            dispatch::acknowledge(tx, worker, attempt, fence, now)?;
            for event in [
                Event::StepsStarted,
                Event::FinalizationStarted,
                Event::Passed,
            ] {
                dispatch::report(tx, worker, attempt, fence, event, None, now, None)?;
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn run_list_streams_every_page_as_ndjson_and_json_carries_the_cursor() {
    let d = deployment();
    // 520 runs: more than one 500-run page.
    let (tenant, repo) = (d.tenant, d.repo);
    let ids: Vec<RunId> = (0..520).map(|_| RunId::new()).collect();
    let seeded = ids.clone();
    d.store
        .writer()
        .write(move |tx| {
            for (i, run) in seeded.iter().enumerate() {
                jobs::insert_run(
                    tx,
                    tenant,
                    repo,
                    *run,
                    "sha",
                    UnixMillis(1_000 + i as i64 / 3),
                )?;
            }
            Ok(())
        })
        .unwrap();
    let out = cli(
        &d,
        &[
            "run", "list", "--tenant", "acme", "--repo", "app", "--all", "--output", "ndjson",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let lines: Vec<Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 520, "one line per run");
    let listed: HashSet<&str> = lines.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(listed.len(), 520);
    let created: Vec<i64> = lines
        .iter()
        .map(|r| r["created_ms"].as_i64().unwrap())
        .collect();
    assert!(created.windows(2).all(|w| w[0] >= w[1]), "newest first");
    // JSON: one document, bounded by --limit, with the cursor to continue.
    let out = cli(
        &d,
        &[
            "run", "list", "--tenant", "acme", "--repo", "app", "--limit", "3", "--json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let page: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(page["runs"].as_array().unwrap().len(), 3);
    let next = page["next"].as_str().unwrap().to_owned();
    assert_eq!(page["runs"][2]["id"], next.as_str());
    let out = cli(
        &d,
        &[
            "run", "list", "--tenant", "acme", "--repo", "app", "--before", &next, "--limit",
            "1000", "--output", "ndjson",
        ],
    );
    assert_eq!(stdout(&out).lines().count(), 517);
    // Text names the cursor on stderr when more remain; stdout is the list.
    let out = cli(
        &d,
        &[
            "run", "list", "--tenant", "acme", "--repo", "app", "--limit", "2",
        ],
    );
    assert_eq!(stdout(&out).lines().count(), 2);
    assert!(stderr(&out).contains("--before run_"), "{}", stderr(&out));
    // A tenant is required when no profile context supplies one.
    let out = cli(&d, &["run", "list", "--repo", "app"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("--tenant"), "{}", stderr(&out));
}

#[test]
fn wait_exits_zero_when_the_run_passes_eight_when_it_does_not_and_seven_at_the_deadline() {
    let d = deployment();
    // Passes while the CLI is parked on the wait route.
    let (run, job) = dispatch_run(&d);
    let leased = lease(&d, job);
    let store = Arc::clone(&d.store);
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(600));
        pass(&store, leased);
    });
    let started = Instant::now();
    // Bounded, so a run that never passes fails the test instead of hanging it.
    let out = cli(
        &d,
        &[
            "wait",
            &run.to_string(),
            "--output",
            "ndjson",
            "--timeout",
            "20s",
        ],
    );
    worker.join().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert!(started.elapsed() < Duration::from_secs(20));
    let changes: Vec<Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(changes.len() >= 2, "the first answer and the finish");
    assert_eq!(changes.last().unwrap()["run"]["state"], "passed");
    assert!(stderr(&out).is_empty());

    // Finished without passing: exit 8, the run on stdout, the reason on stderr.
    let (run, job) = dispatch_run(&d);
    let out = cli(&d, &["job", "cancel", &job.to_string()]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = cli(&d, &["run", "wait", &run.to_string(), "--json"]);
    assert_eq!(code(&out), 8, "{}", stderr(&out));
    let view: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(view["state"], "canceled");
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "client_run_failed");

    // Still queued at the deadline: exit 7.
    let (run, _) = dispatch_run(&d);
    let started = Instant::now();
    let out = cli(&d, &["wait", &run.to_string(), "--timeout", "1500ms"]);
    assert_eq!(code(&out), 7, "{}", stderr(&out));
    assert!(started.elapsed() >= Duration::from_millis(1400));
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(stderr(&out).contains("deadline"), "{}", stderr(&out));
    let out = cli(&d, &["wait", &run.to_string(), "--timeout", "soon"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn an_artifact_entry_downloads_with_its_length_and_digest_checked() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let staged = d
        .objects
        .stage(d.tenant, &payload[..], u64::MAX, Expect::default())
        .unwrap();
    let digest = staged.digest().to_string();
    let (tenant, objects) = (d.tenant, Arc::clone(&d.objects));
    let artifact = d
        .store
        .writer()
        .write(move |tx| {
            objects.commit(tx, &staged)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, "report"),
                &[Entry {
                    path: "out/report.bin".into(),
                    digest: staged.digest(),
                    len: staged.len(),
                    mode: 0o644,
                }],
            )?;
            let now = UnixMillis::now();
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "report",
                artifacts::State::Captured,
                Some(version),
                1,
                staged.len(),
                UnixMillis(now.0 + 86_400_000),
                now,
            )
        })
        .unwrap();
    let out = cli(
        &d,
        &["artifact", "list", &run.to_string(), "--output", "ndjson"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let rows: Vec<Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], artifact.to_string());
    // The answers name the owning tenant, so a download needs no --tenant
    // (this CLI has neither the flag nor a profile context below).
    let out = cli(&d, &["artifact", "list", &run.to_string(), "--json"]);
    let listed: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(listed["tenant"], "acme");
    let out = cli(
        &d,
        &[
            "artifact",
            "show",
            &run.to_string(),
            &artifact.to_string(),
            "--json",
        ],
    );
    let shown: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(shown["tenant"], "acme");
    let target = d.dir.path().join("report.bin");
    let out = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--path",
            "out/report.bin",
            "--out",
            target.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&target).unwrap(), payload);
    let result: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(result["digest"], digest.as_str());
    assert_eq!(result["len"], 300_000);
    assert!(!d.dir.path().join("report.bin.sentinel-part").exists());
    // An entry the manifest does not list is not found, and nothing is written.
    let missing = d.dir.path().join("missing.bin");
    let out = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--path",
            "out/other.bin",
            "--out",
            missing.to_str().unwrap(),
            "--tenant",
            "acme",
        ],
    );
    assert_eq!(code(&out), 4, "{}", stderr(&out));
    assert!(!missing.exists());
    // The cache summary of an attempt without one says so.
    let out = cli(&d, &["cache", "show", &attempt.to_string(), "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let summary: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        summary,
        json!({ "attempt": attempt.to_string(), "present": false })
    );
}

#[test]
fn not_found_and_conflict_keep_their_exits_and_json_failures_touch_stderr_only() {
    let d = deployment();
    let missing = RunId::new().to_string();
    let out = cli(&d, &["status", &missing]);
    assert_eq!(code(&out), 4);
    assert!(stdout(&out).is_empty());
    assert!(
        stderr(&out).starts_with("error: not_found"),
        "{}",
        stderr(&out)
    );
    let out = cli(&d, &["run", "status", &missing, "--output", "json"]);
    assert_eq!(code(&out), 4);
    assert!(stdout(&out).is_empty(), "stdout stays clean");
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 1, "one error document");
    let error: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        (error["schema"].as_str(), error["code"].as_str()),
        (Some("sentinel.error/1"), Some("not_found"))
    );
    // Rerunning a cancelled job is a conflict: exit 5.
    let (_, job) = dispatch_run(&d);
    assert_eq!(code(&cli(&d, &["job", "cancel", &job.to_string()])), 0);
    let out = cli(
        &d,
        &["job", "rerun", &job.to_string(), "--output", "ndjson"],
    );
    assert_eq!(code(&out), 5, "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "conflict");
    // A value that would change the request path is refused locally.
    let out = cli(&d, &["status", "run_x/../../me", "--json"]);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).is_empty());
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "client_usage");
    // Log search over an attempt with no log yet is not found.
    let out = cli(
        &d,
        &[
            "log",
            "search",
            &AttemptId::new().to_string(),
            "--text",
            "x",
        ],
    );
    assert_eq!(code(&out), 4, "{}", stderr(&out));
}

#[test]
fn pipeline_explain_json_failures_are_one_error_document_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yml");
    std::fs::write(&bad, "schema: 1\njobs: []\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(["pipeline", "explain", "--json", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).is_empty());
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "invalid_pipeline");
    let good = dir.path().join("good.yml");
    std::fs::write(&good, PIPELINE).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(["pipeline", "explain", "--json", good.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let _: Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    // `--output json` is the same mode, for validate as well as explain.
    let pipeline = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .arg("pipeline")
            .args(args)
            .output()
            .unwrap()
    };
    let out = pipeline(&["explain", "--output", "json", good.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let explained: Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(explained["schema"], "sentinel.explain/1");
    let out = pipeline(&["validate", "--output", "json", good.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let valid: Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(
        (valid["valid"].as_bool(), valid["jobs"].as_u64()),
        (Some(true), Some(1))
    );
    let out = pipeline(&["validate", "--output", "json", bad.to_str().unwrap()]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).is_empty());
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "invalid_pipeline");
    // Text validate prints nothing on success; ndjson is not an offline mode.
    let out = pipeline(&["validate", good.to_str().unwrap()]);
    assert_eq!((code(&out), stdout(&out).as_str()), (0, ""));
    assert_eq!(
        code(&pipeline(&[
            "validate",
            "--output",
            "ndjson",
            good.to_str().unwrap()
        ])),
        2
    );
}

fn plain_get(url: &str, token: &str) -> (u16, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .get(url)
        .header("authorization", format!("Bearer {token}"))
        .call()
        .unwrap();
    let status = response.status().as_u16();
    let body = serde_json::from_str(&response.into_body().read_to_string().unwrap())
        .unwrap_or(Value::Null);
    (status, body)
}

/// Another person administering `acme` (so every repository is visible),
/// with their own read credential (the raw `sntl_…` text).
fn other_user(d: &Deployment, name: &'static str) -> String {
    let (root, tenant) = (d.root, d.tenant);
    let user = UserId::new();
    let now = UnixMillis::now();
    d.store
        .writer()
        .write(move |tx| {
            auth::provisioning::insert_human(tx, user, name, false, now)?;
            let admin = Principal::new(root, P::ALL, None, None);
            auth::set_membership(tx, admin, tenant, user, Role::TenantAdmin)
        })
        .unwrap();
    let granted = tokens::provision(&d.store, Grant::new(user, name, P::READ), now).unwrap();
    sentinel_auth::token::format(&granted.secret)
}

#[test]
fn wait_rides_out_rate_limited_answers_instead_of_failing() {
    let d = deployment();
    let (busy, _) = dispatch_run(&d);
    let (run, job) = dispatch_run(&d);
    // Other long polls hold every subscriber slot for about 2 s.
    let (_, answer) = plain_get(&format!("{}/api/v1/runs/{busy}/wait", d.base), &d.token);
    let version = answer["version"].as_str().unwrap().to_owned();
    // Two other users hold them, each within its per-user share (P09-12).
    let others = [other_user(&d, "other-a"), other_user(&d, "other-b")];
    let holders: Vec<_> = (0..sentinel_api::SUBSCRIBERS)
        .map(|i| {
            let url = format!(
                "{}/api/v1/runs/{busy}/wait?since={version}&timeout_ms=2000",
                d.base
            );
            let token = others[i / sentinel_api::SUBSCRIBERS_PER_USER].clone();
            thread::spawn(move || plain_get(&url, &token).0)
        })
        .collect();
    thread::sleep(Duration::from_millis(300));
    // Every slot is taken: a parking poll now is refused, so the CLI below
    // really meets `rate_limited` (P09-18) rather than parking at once.
    let (_, now) = plain_get(&format!("{}/api/v1/runs/{run}/wait", d.base), &d.token);
    let (status, refused) = plain_get(
        &format!(
            "{}/api/v1/runs/{run}/wait?since={}&timeout_ms=2000",
            d.base,
            now["version"].as_str().unwrap()
        ),
        &d.token,
    );
    assert_eq!(status, 429, "{refused}");
    assert_eq!(refused["code"], "rate_limited");
    assert!(refused["details"]["retry_after_ms"].as_u64().is_some());
    // The job is cancelled while the CLI's parking polls are being refused.
    let (store, tenant) = (Arc::clone(&d.store), d.tenant);
    let canceller = thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        store
            .writer()
            .write(move |tx| dispatch::cancel(tx, tenant, job, UnixMillis::now()).map(|_| ()))
            .unwrap();
    });
    // The first poll answers at once (no `since`); the next must park and
    // is refused while the holders last, past the client's own three
    // attempts — `wait` backs off with jitter and polls again.
    let out = cli(&d, &["wait", &run.to_string(), "--timeout", "20s"]);
    canceller.join().unwrap();
    for holder in holders {
        assert_eq!(holder.join().unwrap(), 200);
    }
    assert_eq!(code(&out), 8, "finished, not busy: {}", stderr(&out));
}

/// P09-11: `log show` over a log far larger than the client's 10 MiB body
/// limit — full 32 KiB frames — prints every frame: the server bounds each
/// page in bytes and the CLI follows `next_after`.
#[test]
fn log_show_reads_a_log_of_full_frames_past_the_client_body_limit() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let frames = 400u64; // 12.5 MiB of payload
    for seq in 1..=frames {
        let mut bytes = vec![b'q'; 32 * 1024];
        bytes[..8].copy_from_slice(format!("{seq:07}\n").as_bytes());
        d.logs
            .append(
                run,
                job,
                attempt,
                &sentinel_protocol::logs::Frame {
                    seq,
                    step: 0,
                    stream: sentinel_protocol::logs::Stream::Stdout,
                    bytes,
                },
            )
            .unwrap();
    }
    let out = cli(
        &d,
        &["log", "show", &attempt.to_string(), "--output", "ndjson"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let seqs: Vec<u64> = stdout(&out)
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(seqs, (1..=frames).collect::<Vec<_>>());
}

/// P09-16: when the match cap falls inside one frame's matches, the resume
/// point is before that frame, so its remaining matches are not skipped.
#[test]
fn log_search_cut_inside_a_frame_resumes_before_it() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    for (seq, text) in [(1u64, "needle a\n"), (2, "needle b\nneedle c\nneedle d\n")] {
        d.logs
            .append(
                run,
                job,
                attempt,
                &sentinel_protocol::logs::Frame {
                    seq,
                    step: 0,
                    stream: sentinel_protocol::logs::Stream::Stdout,
                    bytes: text.as_bytes().to_vec(),
                },
            )
            .unwrap();
    }
    d.logs.finish(run, job, attempt, 2, &[]).unwrap();
    let out = cli(
        &d,
        &[
            "log",
            "search",
            &attempt.to_string(),
            "--text",
            "needle",
            "--limit",
            "2",
            "--output",
            "json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let answer: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(answer["matches"].as_array().unwrap().len(), 2);
    assert_eq!(answer["complete"], false, "{answer}");
    assert_eq!(answer["next_after"], 1, "{answer}");
}
