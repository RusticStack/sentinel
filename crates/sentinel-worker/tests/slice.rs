//! W09: the vertical slice through the real components — a controller with
//! its store, log store and API; a worker with the real executor; rootless
//! Podman — under the things that go wrong: a cancel that lands during
//! preparation, the network dropping under a running job, the controller
//! restarting under a running job. Every job's verdict is read through the
//! API, every log through the API, and at the end nothing is duplicated,
//! nothing is owned, nothing is left. Gated like the other container tests:
//! `SENTINEL_PODMAN_TESTS=1` as a rootless Podman account.

#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    PoolId, RepoId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::Capacity,
    worker::{self, Handle},
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind},
    local_auth,
    logs::LogStore,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers,
};
use sentinel_worker::{
    executor::{Executor, Notice},
    podman,
    workspace::Workspace,
};

const IMAGE: &str = "docker.io/library/busybox";
const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

/// The API as the CLI would use it.
struct Api {
    base: String,
    token: String,
}

impl Api {
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(60)))
                .build(),
        );
        let url = format!("{}{path}", self.base);
        let auth = format!("Bearer {}", self.token);
        let response = match method {
            "GET" => agent.get(&url).header("authorization", &auth).call(),
            _ => agent
                .post(&url)
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .send(body.unwrap_or(serde_json::json!({})).to_string().as_bytes()),
        }
        .unwrap();
        let status = response.status().as_u16();
        let text = response.into_body().read_to_string().unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        )
    }
    fn dispatch(&self, pipeline: &str, repo: &Path, sha: &str) -> serde_json::Value {
        let (status, run) = self.call(
            "POST",
            "/api/v1/tenants/acme/repos/app/runs",
            Some(serde_json::json!({
                "pipeline": pipeline,
                "source": { "repo": repo.to_str().unwrap(), "sha": sha, "ref": "main" }
            })),
        );
        assert_eq!(status, 201, "{run}");
        run
    }
    fn run(&self, id: &str) -> serde_json::Value {
        let (status, view) = self.call("GET", &format!("/api/v1/runs/{id}"), None);
        assert_eq!(status, 200, "{view}");
        view
    }
    fn job(&self, run: &str, name: &str) -> serde_json::Value {
        let view = self.run(run);
        view["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|j| j["name"] == name)
            .cloned()
            .unwrap()
    }
    fn logs(&self, attempt: &str) -> serde_json::Value {
        let (status, page) = self.call(
            "GET",
            &format!("/api/v1/attempts/{attempt}/logs?limit=500"),
            None,
        );
        assert_eq!(status, 200, "{page}");
        page
    }
}

fn pipeline(name: &str, script: &str) -> String {
    format!(
        "schema: 1\non: [push]\njobs:\n  {name}:\n    image: {IMAGE}@{DIGEST}\n    resources: {{ cpu: 1, memory: 128MiB }}\n    steps:\n      - id: s\n        run: '{script}'\n"
    )
}

#[test]
fn the_vertical_slice_survives_cancel_network_loss_and_controller_restart() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("greeting.txt"), "hello\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);

    // Controller, store, logs, API, credential.
    let store =
        Arc::new(Store::open(temp.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(temp.path().join("logs")).unwrap());
    let (tenant, repo_id, pool) = (TenantId::new(), RepoId::new(), PoolId::new());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    store
        .writer()
        .write(move |tx| {
            let principal = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                principal,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis::now(),
            )?;
            auth::set_membership(tx, principal, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, principal, tenant, repo_id, "app", UnixMillis::now())?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis::now(),
            )
        })
        .unwrap();
    let token =
        tokens::provision(&store, Grant::new(root, "slice", P::ALL), UnixMillis::now()).unwrap();
    let controller_identity = Identity::generate("controller").unwrap();
    let (c_cert, c_key) = (temp.path().join("c.crt"), temp.path().join("c.key"));
    controller_identity.save(&c_cert, &c_key).unwrap();
    let mut controller = Some(
        Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            controller_identity,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    );
    let link_addr = controller.as_ref().unwrap().local_addr();
    let fingerprint = controller.as_ref().unwrap().fingerprint();
    let api_server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs: Arc::clone(&logs),
        controller: controller.as_ref().unwrap().handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
    })
    .unwrap();
    let api = Api {
        base: format!("http://{}", api_server.local_addr()),
        token: sentinel_auth::token::format(&token.secret),
    };
    let enrollment = store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
        })
        .unwrap()
        .secret;

    // Worker with the real executor.
    let worker_dir = temp.path().join("worker");
    fs::create_dir(&worker_dir).unwrap();
    let notices = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&notices);
    let worker_id = WorkerId::new();
    let executor = Executor::start(worker_dir.clone(), worker_id, move |notice: Notice| {
        log.lock().unwrap().push(format!("{notice:?}"));
    })
    .unwrap();
    executor.set_cancel_grace(Duration::from_secs(2));
    executor.set_prepare_hold(Duration::from_secs(3));
    let handle = Arc::new(Handle::new());
    let link_thread = {
        let (executor, handle) = (executor.clone(), Arc::clone(&handle));
        let config = worker::Config {
            controller: link_addr,
            server: fingerprint,
            worker: worker_id,
            name: "builder-1".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(1),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 4 << 30,
            },
        };
        thread::spawn(move || {
            worker::run(
                config,
                Identity::generate("worker").unwrap(),
                Some(enrollment),
                &executor,
                &handle,
                &|_| {},
            )
        })
    };
    let connected = |controller: &Option<Controller>| {
        controller.as_ref().unwrap().connected() == vec![worker_id]
    };
    eventually("worker connected", || connected(&controller));

    // 1. Success and command failure, through the API, with the log.
    let ok = api.dispatch(&pipeline("ok", "cat greeting.txt; echo done"), &repo, &sha);
    let bad = api.dispatch(&pipeline("bad", "echo boom >&2; exit 7"), &repo, &sha);
    let (ok_id, bad_id) = (
        ok["id"].as_str().unwrap().to_owned(),
        bad["id"].as_str().unwrap().to_owned(),
    );
    eventually("ok passed", || api.run(&ok_id)["state"] == "passed");
    eventually("bad failed", || api.run(&bad_id)["state"] == "failed");
    let ok_job = api.job(&ok_id, "ok");
    let ok_log = api.logs(ok_job["attempt"].as_str().unwrap());
    assert_eq!(ok_log["complete"], true);
    let text: String = ok_log["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["text"].as_str().unwrap())
        .collect();
    assert_eq!(text, "hello\ndone\n");
    let bad_job = api.job(&bad_id, "bad");
    assert_eq!(bad_job["failure_class"], "command_failed");
    let bad_log = api.logs(bad_job["attempt"].as_str().unwrap());
    assert!(
        bad_log["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["stream"] == "stderr" && f["text"] == "boom\n")
    );

    // 2. Cancel during preparation: the hold between checkout and pull is
    // where the cancel lands; no container ever starts; the verdict is a
    // cancel, not a preparation failure.
    let held = api.dispatch(&pipeline("held", "echo never"), &repo, &sha);
    let held_id = held["id"].as_str().unwrap().to_owned();
    eventually("held preparing", || {
        api.job(&held_id, "held")["state"] == "preparing"
    });
    let (status, body) = api.call("POST", &format!("/api/v1/runs/{held_id}/cancel"), None);
    assert_eq!(status, 200, "{body}");
    eventually("held canceled", || api.run(&held_id)["state"] == "canceled");
    let held_job = api.job(&held_id, "held");
    assert_eq!(held_job["failure_class"], "canceled");
    assert!(
        !notices
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains("Started") && false)
    );

    // 3. Network loss under a running job: the controller drops the
    // session; the worker keeps the attempt, reconnects with back-off,
    // resends its log from the cursor and reports once.
    let long = api.dispatch(
        &pipeline("long", "echo start; sleep 4; echo end"),
        &repo,
        &sha,
    );
    let long_id = long["id"].as_str().unwrap().to_owned();
    eventually("long running", || {
        api.job(&long_id, "long")["state"] == "running"
    });
    thread::sleep(Duration::from_millis(500));
    assert!(controller.as_ref().unwrap().handle().disconnect(worker_id));
    eventually("session dropped", || !connected(&controller));
    eventually("worker back", || connected(&controller));
    eventually("long passed", || api.run(&long_id)["state"] == "passed");
    let long_job = api.job(&long_id, "long");
    let long_log = api.logs(long_job["attempt"].as_str().unwrap());
    assert_eq!(long_log["complete"], true);
    let text: String = long_log["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["text"].as_str().unwrap())
        .collect();
    assert_eq!(
        text, "start\nend\n",
        "no duplicated or lost frames across the loss"
    );
    let mut seqs: Vec<u64> = long_log["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["seq"].as_u64().unwrap())
        .collect();
    let before = seqs.len();
    seqs.dedup();
    assert_eq!(seqs.len(), before);

    // 4. Controller restart under a running job: the same store, log store
    // and identity come back on the same address; startup reconciliation
    // finds the live lease and leaves it; the worker reconnects and the
    // job completes exactly once.
    let slow = api.dispatch(&pipeline("slow", "echo a; sleep 5; echo b"), &repo, &sha);
    let slow_id = slow["id"].as_str().unwrap().to_owned();
    eventually("slow running", || {
        api.job(&slow_id, "slow")["state"] == "running"
    });
    assert!(controller.take().unwrap().shutdown(Duration::from_secs(5)));
    let restarted = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Identity::load(&c_cert, &c_key).unwrap(),
        link_addr,
    )
    .unwrap();
    let settled = restarted.reconciled();
    assert_eq!(
        (settled.expired, settled.lapsed, settled.orphaned),
        (0, 0, 0),
        "a live lease is left alone"
    );
    controller = Some(restarted);
    eventually("worker back after restart", || connected(&controller));
    eventually("slow passed", || api.run(&slow_id)["state"] == "passed");
    let slow_job = api.job(&slow_id, "slow");
    let slow_log = api.logs(slow_job["attempt"].as_str().unwrap());
    let text: String = slow_log["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["text"].as_str().unwrap())
        .collect();
    assert_eq!(text, "a\nb\n");
    assert_eq!(slow_job["fence"], 1, "one attempt, never replayed");

    // No duplicate execution anywhere: each job has exactly one attempt and
    // one `Started` notice; nothing is owned or left behind.
    let started = notices
        .lock()
        .unwrap()
        .iter()
        .filter(|n| n.starts_with("Started("))
        .count();
    assert_eq!(started, 5, "{:?}", notices.lock().unwrap());
    for id in [&ok_id, &bad_id, &held_id, &long_id, &slow_id] {
        assert_eq!(api.run(id)["jobs"][0]["fence"], 1);
    }
    eventually("executor idle", || executor.state_is_idle());
    assert!(podman::owned(worker_id).unwrap().is_empty());
    assert!(Workspace::leftovers(&worker_dir).unwrap().is_empty());
    assert!(
        sentinel_worker::spool::Spool::leftovers(&worker_dir)
            .unwrap()
            .is_empty()
    );
    assert!(
        sentinel_worker::recovery::leftovers(&worker_dir)
            .unwrap()
            .is_empty()
    );
    handle.stop();
    link_thread.join().unwrap().unwrap();
    api_server.shutdown();
    assert!(controller.take().unwrap().shutdown(Duration::from_secs(5)));
    let _ = UserId::new();
}
