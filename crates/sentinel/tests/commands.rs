use std::{
    collections::HashSet,
    io::{Read, Write},
    process::{Command, Output, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
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
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
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
        secret_key: Some(Arc::clone(&key)),
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
    let out = cli(
        &d,
        &[
            "run", "list", "--tenant", "acme", "--repo", "app", "--limit", "2",
        ],
    );
    assert_eq!(stdout(&out).lines().count(), 2);
    assert!(stderr(&out).contains("--before run_"), "{}", stderr(&out));
    let out = cli(&d, &["run", "list", "--repo", "app"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("--tenant"), "{}", stderr(&out));
}

#[test]
fn wait_exits_zero_when_the_run_passes_eight_when_it_does_not_and_seven_at_the_deadline() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let leased = lease(&d, job);
    let store = Arc::clone(&d.store);
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(600));
        pass(&store, leased);
    });
    let started = Instant::now();
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

    let (run, job) = dispatch_run(&d);
    let out = cli(&d, &["job", "cancel", &job.to_string()]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = cli(&d, &["run", "wait", &run.to_string(), "--json"]);
    assert_eq!(code(&out), 8, "{}", stderr(&out));
    let view: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(view["state"], "canceled");
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "client_run_failed");

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
    let out = cli(&d, &["cache", "show", &attempt.to_string(), "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let summary: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        summary,
        json!({ "attempt": attempt.to_string(), "present": false })
    );
}

#[test]
fn every_artifact_entry_downloads_into_a_directory_and_a_link_mints_a_working_url() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let bodies: [(&str, &[u8]); 3] = [
        ("out/report.txt", b"report-bytes"),
        ("out/nested/coverage.json", b"{\"covered\":true}"),
        ("top.bin", &[0u8, 159, 146, 150]),
    ];
    let (tenant, dir_path) = (d.tenant, d.dir.path().to_path_buf());
    let artifact = d
        .store
        .writer()
        .write(move |tx| {
            let objects = Objects::open(&dir_path).unwrap();
            let mut entries = Vec::with_capacity(bodies.len());
            let mut bytes = 0u64;
            for (path, body) in bodies {
                let staged = objects
                    .stage(tenant, body, u64::MAX, Expect::default())
                    .unwrap();
                objects.commit(tx, &staged)?;
                bytes += staged.len();
                entries.push(Entry {
                    path: path.to_owned(),
                    digest: staged.digest(),
                    len: staged.len(),
                    mode: 0o644,
                });
            }
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, "report"),
                &entries,
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
                entries.len() as u64,
                bytes,
                UnixMillis(now.0 + 86_400_000),
                now,
            )
        })
        .unwrap();
    let dir = d.dir.path().join("tree");
    let out = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--all",
            "--out",
            dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    for (path, body) in bodies {
        assert_eq!(std::fs::read(dir.join(path)).unwrap(), body, "{path}");
    }
    let printed = stdout(&out);
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines.len(), 3, "{printed}");
    assert!(
        lines[0].contains("out/report.txt: 12 bytes"),
        "{}",
        lines[0]
    );
    let json_dir = d.dir.path().join("tree-json");
    let out = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--all",
            "--out",
            json_dir.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let listed: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(listed["artifact"], artifact.to_string());
    assert_eq!(listed["entries"].as_array().unwrap().len(), 3);
    assert_eq!(listed["entries"][2]["path"], "top.bin");
    assert_eq!(
        listed["entries"][2]["out"],
        json_dir.join("top.bin").display().to_string()
    );

    let neither = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--out",
            json_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&neither), 2, "{}", stderr(&neither));
    let both = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &artifact.to_string(),
            "--all",
            "--path",
            "top.bin",
            "--out",
            json_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&both), 2, "{}", stderr(&both));

    let absent = cli(
        &d,
        &[
            "artifact",
            "download",
            &run.to_string(),
            &sentinel_core::ArtifactId::new().to_string(),
            "--all",
            "--out",
            json_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&absent), 4, "{}", stderr(&absent));

    let link = cli(
        &d,
        &[
            "artifact",
            "link",
            &run.to_string(),
            &artifact.to_string(),
            "--entry",
            "out/report.txt",
            "--expires",
            "60",
            "--json",
        ],
    );
    assert_eq!(code(&link), 0, "{}", stderr(&link));
    let minted: Value = serde_json::from_str(&stdout(&link)).unwrap();
    let url = minted["url"].as_str().unwrap();
    assert!(url.contains("/dl/"), "{url}");
    let expires = minted["expires_ms"].as_i64().unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert!(expires > now_ms && expires <= now_ms + 61_000, "{expires}");
    let response = ureq::get(url).call().unwrap();
    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body, b"report-bytes");
    let text = cli(
        &d,
        &[
            "artifact",
            "link",
            &run.to_string(),
            &artifact.to_string(),
            "--format",
            "zip",
        ],
    );
    assert_eq!(code(&text), 0, "{}", stderr(&text));
    let printed = stdout(&text);
    assert!(printed.starts_with("http"), "{printed}");
    assert!(
        printed.contains("anyone holding this URL can download"),
        "{printed}"
    );
    for args in [
        &["--format", "rar"][..],
        &["--expires", "0"],
        &["--expires", "3601"],
        &["--entry", "top.bin", "--format", "tar"],
    ] {
        let mut argv = vec!["artifact", "link", "run_x", "arf_x"];
        argv.extend_from_slice(args);
        let out = cli(&d, &argv);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
    }
}

#[test]
fn mcp_reads_artifacts_through_the_shared_tools_and_refuses_an_entry_over_the_text_bound() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let (tenant, dir_path) = (d.tenant, d.dir.path().to_path_buf());
    let big = vec![b'x'; sentinel_protocol::limits::MAX_ARTIFACT_TEXT_BYTES + 1];
    let (report, large) = d
        .store
        .writer()
        .write(move |tx| {
            let objects = Objects::open(&dir_path).unwrap();
            let publish = |name: &str, files: &[(&str, &[u8])]| {
                let mut entries = Vec::with_capacity(files.len());
                let mut bytes = 0u64;
                for (path, body) in files {
                    let staged = objects
                        .stage(tenant, *body, u64::MAX, Expect::default())
                        .unwrap();
                    objects.commit(tx, &staged)?;
                    bytes += staged.len();
                    entries.push(Entry {
                        path: (*path).to_owned(),
                        digest: staged.digest(),
                        len: staged.len(),
                        mode: 0o644,
                    });
                }
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    &artifacts::manifest_name(job, name),
                    &entries,
                )?;
                let now = UnixMillis::now();
                artifacts::record(
                    tx,
                    tenant,
                    run,
                    job,
                    attempt,
                    name,
                    artifacts::State::Captured,
                    Some(version),
                    entries.len() as u64,
                    bytes,
                    UnixMillis(now.0 + 86_400_000),
                    now,
                )
            };
            let report = publish(
                "report",
                &[
                    ("out/report.txt", &b"report-bytes"[..]),
                    ("out/notes/nested.md", &b"# notes\n"[..]),
                ],
            )?;
            let large = publish("large", &[("dump/full.log", &big[..])])?;
            Ok::<_, sentinel_store::Error>((report, large))
        })
        .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env("SENTINEL_TOKEN", &d.token)
        .env("SENTINEL_SERVER", &d.base)
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", d.dir.path().join("no-profiles"))
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let call = |id: u32, name: &str, arguments: Value| {
        json!({
            "jsonrpc":"2.0", "id":id, "method":"tools/call",
            "params":{"name":name,"arguments":arguments}
        })
    };
    {
        let mut input = child.stdin.take().unwrap();
        for request in [
            json!({
                "jsonrpc":"2.0", "id":1, "method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
            }),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            call(3, "list_artifacts", json!({"run": run.to_string()})),
            call(
                4,
                "get_artifact",
                json!({"run": run.to_string(), "artifact": report.to_string()}),
            ),
            call(
                5,
                "read_artifact_file",
                json!({"run": run.to_string(), "artifact": report.to_string(), "path": "out/report.txt"}),
            ),
            call(
                6,
                "read_artifact_file",
                json!({"run": run.to_string(), "artifact": large.to_string(), "path": "dump/full.log"}),
            ),
            call(
                7,
                "get_artifact_link",
                json!({"run": run.to_string(), "artifact": report.to_string(), "entry": "out/notes/nested.md"}),
            ),
        ] {
            writeln!(input, "{request}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let replies: Vec<Value> = stdout(&output)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 7, "one reply per request");
    let tools = replies[1]["result"]["tools"].as_array().unwrap();
    for name in [
        "list_artifacts",
        "get_artifact",
        "read_artifact_file",
        "get_artifact_link",
    ] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "{name} is not offered"
        );
    }
    let listed = &replies[2]["result"]["structuredContent"];
    assert_eq!(listed["artifacts"].as_array().unwrap().len(), 2, "{listed}");
    let detail = &replies[3]["result"]["structuredContent"];
    assert_eq!(detail["manifest"]["entries"].as_array().unwrap().len(), 2);
    let read = &replies[4]["result"]["structuredContent"];
    assert_eq!(read["text"], "report-bytes");
    assert_eq!(read["untrusted"], true);
    assert_eq!(read["media"], "text");
    let refused = &replies[5]["result"];
    assert_eq!(refused["isError"], true, "{refused}");
    let message = refused["structuredContent"]["message"].as_str().unwrap();
    assert!(
        message.contains(&format!(
            "{}",
            sentinel_protocol::limits::MAX_ARTIFACT_TEXT_BYTES + 1
        )) && message.contains("text bound"),
        "{message}"
    );
    let url = replies[6]["result"]["structuredContent"]["url"]
        .as_str()
        .unwrap();
    let response = ureq::get(url).call().unwrap();
    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body, b"# notes\n");
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
    let out = cli(&d, &["status", "run_x/../../me", "--json"]);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).is_empty());
    let error: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(error["code"], "client_usage");
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
    let (_, answer) = plain_get(&format!("{}/api/v1/runs/{busy}/wait", d.base), &d.token);
    let version = answer["version"].as_str().unwrap().to_owned();
    const NAMES: [&str; 8] = [
        "holder-0", "holder-1", "holder-2", "holder-3", "holder-4", "holder-5", "holder-6",
        "holder-7",
    ];
    let users = sentinel_api::SUBSCRIBERS.div_ceil(sentinel_api::SUBSCRIBERS_PER_USER);
    let others: Vec<String> = NAMES[..users].iter().map(|n| other_user(&d, n)).collect();
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
    let (store, tenant) = (Arc::clone(&d.store), d.tenant);
    let canceller = thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        store
            .writer()
            .write(move |tx| dispatch::cancel(tx, tenant, job, UnixMillis::now()).map(|_| ()))
            .unwrap();
    });
    let out = cli(&d, &["wait", &run.to_string(), "--timeout", "20s"]);
    canceller.join().unwrap();
    for holder in holders {
        assert_eq!(holder.join().unwrap(), 200);
    }
    assert_eq!(code(&out), 8, "finished, not busy: {}", stderr(&out));
}

#[test]
fn log_show_reads_a_log_of_full_frames_past_the_client_body_limit() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let frames = 400u64;
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

#[test]
fn log_show_json_stops_at_its_byte_budget_with_a_continuation() {
    let d = deployment();
    let (run, job) = dispatch_run(&d);
    let (_, attempt, _) = lease(&d, job);
    let frames = 520u64;
    for seq in 1..=frames {
        d.logs
            .append(
                run,
                job,
                attempt,
                &sentinel_protocol::logs::Frame {
                    seq,
                    step: 0,
                    stream: sentinel_protocol::logs::Stream::Stdout,
                    bytes: vec![b'j'; 32 * 1024],
                },
            )
            .unwrap();
    }
    d.logs.finish(run, job, attempt, frames, &[]).unwrap();
    let out = cli(&d, &["log", "show", &attempt.to_string(), "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    let shown = doc["frames"].as_array().unwrap();
    assert_eq!(shown.len(), 512, "16 MiB of 32 KiB frames");
    assert_eq!(doc["complete"], false);
    assert_eq!(doc["next_after"], 512);
    let out = cli(
        &d,
        &["log", "show", &attempt.to_string(), "--output", "ndjson"],
    );
    assert_eq!(stdout(&out).lines().count(), frames as usize);
}

/// A cut inside a frame resumes before it, so that frame's later matches are not skipped.
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
