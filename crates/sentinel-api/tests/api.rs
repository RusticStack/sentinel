//! W08 over real HTTP on loopback: authentication by bearer credential and
//! by session cookie (with CSRF on mutations), structured errors, dispatch
//! with idempotency, status, cancel, rerun, log tail/follow through the
//! same files the controller writes, and worker status.

use std::{sync::Arc, thread, time::Duration};

use sentinel_core::{
    AttemptId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    logs::{Frame, Stream},
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
    source::{Binding, Credential},
};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    intake, local_auth,
    logs::LogStore,
    objects::{Entry, Expect, Kind, Objects},
    registration, runs,
    sources::{self, Update},
    sources_forge,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers::{self, Presentation},
};

const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const WEBHOOK_SECRET: &[u8] = b"a-webhook-secret-value";
const GITHUB_REPO_ID: u64 = 91;

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    hook_token: String,
    tenant: TenantId,
    repo: RepoId,
    github_repo: RepoId,
    intake_repo: RepoId,
    root: UserId,
}

fn deployment() -> Deployment {
    deployment_with(local_auth::Policy::default())
}

fn deployment_with(sessions: local_auth::Policy) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = sentinel_auth::sealed::Key::load(&key_path).unwrap();
    let (tenant, repo, github_repo, intake_repo, pool) = (
        TenantId::new(),
        RepoId::new(),
        RepoId::new(),
        RepoId::new(),
        PoolId::new(),
    );
    // A bootstrapped super admin with a password, a namespace, two bound
    // repositories (one generic, one through a GitHub App installation) and a
    // pool.
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            // The super admin created the namespace; membership is what
            // repository access is judged by, so root joins it explicitly.
            auth::set_membership(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                root,
                sentinel_core::auth::Role::TenantAdmin,
            )?;
            auth::create_repo(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                repo,
                "app",
                now,
            )?;
            auth::create_repo(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                github_repo,
                "widget",
                now,
            )?;
            auth::create_repo(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                intake_repo,
                "hooked",
                now,
            )?;
            let generic = Binding {
                remote: "https://git.example:8443/team/repo.git".into(),
                allowed_refs: vec!["refs/heads/main".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root),
                Update {
                    repo: intake_repo,
                    expected: 0,
                    binding: &generic,
                    credential: &Credential::Https {
                        username: "deploy".into(),
                        secret: "deploy-token".into(),
                    },
                    forge: None,
                },
                &["https://git.example:8443".into()],
                &key,
                now,
            )?;
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
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            let forge = Binding {
                remote: "https://github.com/account/widget.git".into(),
                allowed_refs: vec!["refs/heads/main".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root),
                Update {
                    repo: github_repo,
                    expected: 0,
                    binding: &forge,
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                now,
            )
        })
        .unwrap();
    let hook_token = {
        let secret = store
            .writer()
            .write(move |tx| intake::issue_token(tx, Authority::HostLocal, intake_repo, now))
            .unwrap();
        intake::hook_token_text(&secret)
    };
    let granted = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "test",
            permissions: P::ALL,
            tenant: None,
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
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
        objects,
        controller: controller.handle(),
        sessions,
        github_webhook_secret: Some(Arc::from(WEBHOOK_SECRET)),
        intake: None,
        public_url: None,
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let _ = provisioning::insert_human;
    Deployment {
        _dir: dir,
        store,
        logs,
        _controller: controller,
        server: Some(server),
        base,
        token: sentinel_auth::token::format(&granted.secret),
        hook_token,
        tenant,
        repo,
        github_repo,
        intake_repo,
        root,
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

/// A minimal HTTP client: ureq with errors turned into (status, body).
fn call(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    auth: Option<&str>,
    extra: &[(&str, &str)],
) -> (u16, serde_json::Value) {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "POST" => agent.post(&url),
        _ => unreachable!(),
    };
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    for (k, v) in extra {
        request = request.header(*k, *v);
    }
    let response = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .send(body.to_string().as_bytes())
            .unwrap(),
        None => request.send_empty().unwrap(),
    };
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    let json = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    (status, json)
}

fn bearer(d: &Deployment) -> String {
    format!("Bearer {}", d.token)
}

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps: [{ id: s, run: 'true' }]
  test:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    needs: [build]
    steps: [{ id: s, run: 'true' }]
";

fn dispatch_body() -> serde_json::Value {
    serde_json::json!({
        "pipeline": PIPELINE,
        "source": { "repo": "https://github.com/o/r.git", "sha": "0123456789abcdef0123456789abcdef01234567", "ref": "main" }
    })
}

#[test]
fn credentials_are_required_and_errors_are_structured() {
    let d = deployment();
    let (status, body) = call(&d, "GET", "/api/v1/me", None, None, &[]);
    assert_eq!(status, 401);
    assert_eq!(body["schema"], "sentinel.error/1");
    assert_eq!(body["code"], "unauthenticated");
    assert_eq!(body["retryable"], false);
    let (status, body) = call(&d, "GET", "/api/v1/me", None, Some("Bearer sntl_nope"), &[]);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    let (status, body) = call(&d, "GET", "/api/v1/me", None, Some(&bearer(&d)), &[]);
    assert_eq!(status, 200);
    assert_eq!(body["user"], d.root.to_string());
    assert_eq!(body["via"], "bearer");
    assert_eq!(body["super_admin"], true);
    let (status, body) = call(&d, "GET", "/api/v1/nope", None, Some(&bearer(&d)), &[]);
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let (status, _) = call(&d, "GET", "/api/v1/health", None, None, &[]);
    assert_eq!(status, 200);
    // The page itself needs no credential; everything it does goes through the API.
    let (status, page) = call(&d, "GET", "/", None, None, &[]);
    assert_eq!(status, 200);
    assert!(page.as_str().unwrap().contains("/api/v1/login"));
}

/// Manual dispatch on a repository with no binding: the worker fetches the
/// named remote with its own identity, so only an unauthenticated `https://`
/// remote is admissible — never a path or `file://` URL on the worker host,
/// never `ssh://` with the worker account's keys, never `git://` or plain
/// `http://`.
#[test]
fn manual_dispatch_refuses_local_and_ambient_credential_remotes() {
    let d = deployment();
    let auth = bearer(&d);
    for remote in [
        "file:///var/lib/sentinel/worker/mirrors/rep_x",
        "/var/lib/sentinel/worker/mirrors/rep_x",
        "../other-attempt",
        "ssh://git@github.com/o/r.git",
        "git@github.com:o/r.git",
        "git://github.com/o/r.git",
        "http://169.254.169.254/latest",
        "https://user:pass@github.com/o/r.git",
        "ext::sh -c touch% /tmp/pwned",
    ] {
        let body = serde_json::json!({
            "pipeline": PIPELINE,
            "source": { "repo": remote, "sha": "0123456789abcdef0123456789abcdef01234567" }
        });
        let (status, answer) = call(
            &d,
            "POST",
            "/api/v1/tenants/acme/repos/app/runs",
            Some(&body),
            Some(&auth),
            &[],
        );
        assert_eq!(
            (status, answer["code"].as_str()),
            (400, Some("invalid_request")),
            "{remote}: {answer}"
        );
    }
    // Nothing was created by any refusal; an https remote still dispatches.
    let (status, _) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let (status, page) = call(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos/app/runs",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(page["runs"].as_array().unwrap().len(), 1, "{page}");
}

#[test]
fn dispatch_status_cancel_rerun_and_logs_work_through_the_api() {
    let d = deployment();
    let auth = bearer(&d);
    // Unpinned images are refused before anything is written.
    let unpinned = serde_json::json!({
        "pipeline": PIPELINE.replace("@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", ":latest"),
        "source": { "repo": "https://github.com/o/r.git", "sha": "0123456789abcdef0123456789abcdef01234567" }
    });
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&unpinned),
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("pinned by digest")
    );
    // A malformed pipeline is a structured refusal that does not echo it.
    let broken = serde_json::json!({ "pipeline": "schema: 1\njobs: []", "source": { "repo": "x", "sha": "0123456789abcdef0123456789abcdef01234567" } });
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&broken),
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    // The repository and its (empty) run list are visible first.
    let (status, repos) = call(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200, "{repos}");
    let names: Vec<&str> = repos["repos"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert!(names.contains(&"app"), "{names:?}");
    let (status, list) = call(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos/app/runs",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200, "{list}");
    assert!(list["runs"].as_array().unwrap().is_empty());
    // Dispatch, idempotently.
    let key = [("idempotency-key", "run-1")];
    let (status, run) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &key,
    );
    assert_eq!(status, 201, "{run}");
    let run_id = run["id"].as_str().unwrap().to_owned();
    assert_eq!(run["state"], "pending");
    assert_eq!(run["jobs"].as_array().unwrap().len(), 2);
    assert_eq!(run["jobs"][0]["name"], "build");
    assert_eq!(run["jobs"][0]["state"], "queued");
    assert_eq!(run["jobs"][1]["state"], "blocked");
    let (status, again) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &key,
    );
    assert_eq!((status, again["id"].as_str()), (200, Some(run_id.as_str())));
    let mut other = dispatch_body();
    other["source"]["ref"] = serde_json::json!("develop");
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&other),
        Some(&auth),
        &key,
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (422, Some("idempotency_mismatch"))
    );
    // Listed for the repository, readable by id, not readable through a
    // credential scoped to another tenant.
    let (status, list) = call(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos/app/runs?limit=10",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(list["runs"][0]["id"], run_id);
    let (status, view) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run_id}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, view["state"].as_str()), (200, Some("pending")));
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{}", sentinel_core::RunId::new()),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let (status, body) = call(&d, "GET", "/api/v1/runs/not-an-id", None, Some(&auth), &[]);
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    let outsider = tokens::provision(
        &d.store,
        Grant {
            user: d.root,
            name: "narrow",
            permissions: P::READ,
            tenant: Some(TenantId::new()),
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    );
    if let Ok(outsider) = outsider {
        let narrow = format!("Bearer {}", sentinel_auth::token::format(&outsider.secret));
        let (status, body) = call(
            &d,
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            None,
            Some(&narrow),
            &[],
        );
        assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    }

    // Cancel the job that is running-to-be; the blocked one is skipped by
    // the dependency decision; a rerun is refused for a cancelled job.
    let build = run["jobs"][0]["id"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &d,
        "POST",
        &format!("/api/v1/jobs/{build}/cancel"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["outcome"].as_str()), (200, Some("terminal")));
    let (status, view) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run_id}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(view["jobs"][0]["state"], "canceled");
    assert_eq!(view["jobs"][0]["failure_class"], "canceled");
    // Never attempted: no log state exists to report.
    assert!(view["jobs"][0]["log_state"].is_null());
    let (status, body) = call(
        &d,
        "POST",
        &format!("/api/v1/jobs/{build}/rerun"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    let (status, body) = call(
        &d,
        "POST",
        &format!("/api/v1/runs/{run_id}/cancel"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert!(body["canceled"].as_u64().unwrap() <= 1);
    let (status, view) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run_id}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(view["state"], "canceled");

    // Logs: a lease, frames written the way the controller writes them, a
    // tail by sequence, a follow that returns as soon as more arrives, and
    // completion.
    let (status, run2) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let (tenant, repo) = (d.tenant, d.repo);
    let _ = repo;
    let worker = sentinel_core::WorkerId::new();
    let run_id: RunId = run2["id"].as_str().unwrap().parse().unwrap();
    let job_id: sentinel_core::JobId = run2["jobs"][0]["id"].as_str().unwrap().parse().unwrap();
    let attempt = d
        .store
        .writer()
        .write(move |tx| {
            let (attempt, _) = sentinel_store::jobs::lease(
                tx,
                tenant,
                job_id,
                worker,
                UnixMillis(i64::MAX / 2),
                UnixMillis::now(),
            )?;
            Ok(attempt)
        })
        .unwrap();
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/logs"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let frame = |seq, text: &str, stream| Frame {
        seq,
        step: 0,
        stream,
        bytes: text.as_bytes().to_vec(),
    };
    d.logs
        .append(
            run_id,
            job_id,
            attempt,
            &frame(1, "hello\n", Stream::Stdout),
        )
        .unwrap();
    d.logs
        .append(run_id, job_id, attempt, &frame(2, "warn\n", Stream::Stderr))
        .unwrap();
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/logs?after=1"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(body["complete"], false);
    assert_eq!(body["frames"].as_array().unwrap().len(), 1);
    assert_eq!(body["frames"][0]["stream"], "stderr");
    assert_eq!(body["frames"][0]["text"], "warn\n");
    // Follow: the request parks until a frame arrives.
    let logs = Arc::clone(&d.logs);
    let store = Arc::clone(&d.store);
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(400));
        logs.append(
            run_id,
            job_id,
            attempt,
            &Frame {
                seq: 3,
                step: 1,
                stream: Stream::Stdout,
                bytes: b"late\n".to_vec(),
            },
        )
        .unwrap();
        logs.finish(run_id, job_id, attempt, 3, &[]).unwrap();
        // What the controller's `log_end` does: the row lands with the marker.
        store
            .writer()
            .write(move |tx| sentinel_store::dispatch::log_ended(tx, attempt))
            .unwrap();
    });
    let started = std::time::Instant::now();
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/logs?after=2&wait=1"),
        None,
        Some(&auth),
        &[],
    );
    writer.join().unwrap();
    assert_eq!(status, 200);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(body["frames"][0]["text"], "late\n");
    assert_eq!(body["frames"][0]["step"], 1);
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/logs?after=3&wait=1"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["complete"].as_bool()), (200, Some(true)));
    // The durable end is also visible on the run: `log_state` says the
    // attempt's end marker is on disk, not merely that frames stopped.
    let (status, view) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run_id}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, view["jobs"][0]["log_state"].as_str()),
        (200, Some("complete"))
    );
    // The step filter serves only that step's frames.
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/logs?step=1"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(
        body["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![3]
    );
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/logs", AttemptId::new()),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));

    // Worker status: the pools the tenant may use, with nothing connected.
    let (status, body) = call(
        &d,
        "GET",
        "/api/v1/workers?tenant=acme",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pools"][0]["name"], "builders");
    assert_eq!(body["pools"][0]["workers"].as_array().unwrap().len(), 0);
    let (status, body) = call(&d, "GET", "/api/v1/workers", None, Some(&auth), &[]);
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[test]
fn a_password_session_needs_the_csrf_header_for_mutations() {
    let d = deployment();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/login",
        Some(&serde_json::json!({ "username": "root", "password": "wrong password here" })),
        None,
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    let url = format!("{}/api/v1/login", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&url)
        .header("content-type", "application/json")
        .send(
            serde_json::json!({ "username": "root", "password": "correct horse battery staple" })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("__Host-sentinel_session="));
    assert!(cookie.contains("HttpOnly"));
    let cookie_value = cookie.split(';').next().unwrap().to_owned();
    let body: serde_json::Value =
        serde_json::from_str(&response.into_body().read_to_string().unwrap()).unwrap();
    let csrf = body["csrf"].as_str().unwrap().to_owned();
    assert_eq!(body["user"], d.root.to_string());
    // Reads with the cookie alone.
    let (status, me) = call(
        &d,
        "GET",
        "/api/v1/me",
        None,
        None,
        &[("cookie", &cookie_value)],
    );
    assert_eq!((status, me["via"].as_str()), (200, Some("session")));
    // A mutation with the cookie but no CSRF header is refused; with the
    // header it goes through.
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        None,
        &[("cookie", &cookie_value)],
    );
    assert_eq!((status, body["code"].as_str()), (403, Some("forbidden")));
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        None,
        &[("cookie", &cookie_value), ("x-sentinel-csrf", &csrf)],
    );
    assert_eq!(status, 201, "{body}");
    // Logout clears the session; the cookie is dead afterwards.
    let (status, _) = call(
        &d,
        "POST",
        "/api/v1/logout",
        Some(&serde_json::json!({})),
        None,
        &[("cookie", &cookie_value), ("x-sentinel-csrf", &csrf)],
    );
    assert_eq!(status, 200);
    let (status, body) = call(
        &d,
        "GET",
        "/api/v1/me",
        None,
        None,
        &[("cookie", &cookie_value)],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    let _ = DIGEST;
}

/// A GitHub `push` payload for one immutable repository ID.
fn push_payload(repository: u64) -> serde_json::Value {
    serde_json::json!({
        "ref": "refs/heads/main",
        "before": "a".repeat(40),
        "after": "b".repeat(40),
        "created": false,
        "deleted": false,
        "forced": false,
        "installation": {"id": 42},
        "repository": {"id": repository, "full_name": "account/widget"},
    })
}

/// A GitHub `pull_request` payload for one repository and head repository.
fn pr_payload(action: &str, head_repo: u64, merge: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "action": action,
        "number": 7,
        "installation": {"id": 42},
        "repository": {"id": GITHUB_REPO_ID, "full_name": "account/widget"},
        "pull_request": {
            "draft": false,
            "head": {"ref": "feature", "sha": "c".repeat(40), "repo": {"id": head_repo}},
            "base": {"ref": "main", "sha": "d".repeat(40)},
            "merge_commit_sha": merge,
        },
    })
}

/// The App webhook signature over exactly the bytes the request carries.
fn webhook_signature(body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, WEBHOOK_SECRET);
    let tag = ring::hmac::sign(&key, body);
    let mut out = String::from("sha256=");
    for byte in tag.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hook_bearer(d: &Deployment) -> String {
    format!("Bearer {}", d.hook_token)
}

fn delivery_state(d: &Deployment, id: &str) -> intake::State {
    let id: sentinel_core::DeliveryId = id.parse().unwrap();
    d.store.read(move |c| intake::get(c, id)).unwrap().state
}

#[test]
fn intake_routes_authenticate_deduplicate_and_report_explicitly() {
    let d = deployment();

    // Generic intake: no secret, a malformed secret, an unknown repository and
    // another repository's secret are one indistinguishable refusal.
    let update = |delivery: &str| {
        serde_json::json!({
            "delivery_id": delivery,
            "ref": "refs/heads/main",
            "old_sha": "a".repeat(40),
            "new_sha": "b".repeat(40),
        })
    };
    let intake_path = format!("/api/v1/intake/{}", d.intake_repo);
    let (status, body) = call(&d, "POST", &intake_path, Some(&update("hook-1")), None, &[]);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    let (status, _) = call(
        &d,
        "POST",
        &intake_path,
        Some(&update("hook-1")),
        Some("Bearer sentinel_hook_0000"),
        &[],
    );
    assert_eq!(status, 401);
    let (status, _) = call(
        &d,
        "POST",
        &format!("/api/v1/intake/{}", RepoId::new()),
        Some(&update("hook-1")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(status, 401, "a repository is never enumerable by intake");

    // A malformed body is invalid_request; a body over the route's limit is
    // refused before it is parsed.
    let (status, body) = call(
        &d,
        "POST",
        &intake_path,
        Some(&serde_json::json!({ "delivery_id": "hook-2" })),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    let oversize = serde_json::json!({
        "delivery_id": "hook-3",
        "ref": "refs/heads/main",
        "old_sha": "a".repeat(40),
        "new_sha": "b".repeat(40),
        "padding": "x".repeat(70_000),
    });
    let (status, body) = call(
        &d,
        "POST",
        &intake_path,
        Some(&oversize),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (413, Some("payload_too_large"))
    );

    // A valid delivery is acknowledged with its record id, durable before the
    // response; the redelivery is a duplicate of the same record.
    let (status, first) = call(
        &d,
        "POST",
        &intake_path,
        Some(&update("hook-4")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(
        (status, first["duplicate"].as_bool()),
        (202, Some(false)),
        "{first}"
    );
    let id = first["delivery"].as_str().unwrap().to_owned();
    assert_eq!(delivery_state(&d, &id), intake::State::Pending);
    let (status, again) = call(
        &d,
        "POST",
        &intake_path,
        Some(&update("hook-4")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(
        (
            status,
            again["duplicate"].as_bool(),
            again["delivery"].as_str()
        ),
        (202, Some(true), Some(id.as_str()))
    );
    // The same identity with different content is a conflict, not a replay.
    let (status, body) = call(
        &d,
        "POST",
        &intake_path,
        Some(&serde_json::json!({
            "delivery_id": "hook-4",
            "ref": "refs/heads/other",
            "old_sha": "a".repeat(40),
            "new_sha": "b".repeat(40),
        })),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));

    // GitHub intake: the signature covers the raw body, and a ping is a probe
    // that stores nothing.
    let payload = push_payload(GITHUB_REPO_ID);
    let raw = payload.to_string();
    let signed = webhook_signature(raw.as_bytes());
    let (status, _) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[],
    );
    assert_eq!(status, 401, "no signature");
    let (status, _) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[
            ("x-hub-signature-256", "sha256=00"),
            ("x-github-event", "push"),
            ("x-github-delivery", "gh-1"),
        ],
    );
    assert_eq!(status, 401, "wrong signature length");
    let ping = serde_json::json!({ "zen": "Keep it logically awesome." });
    let ping_raw = ping.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&ping),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(ping_raw.as_bytes()),
            ),
            ("x-github-event", "ping"),
        ],
    );
    assert_eq!((status, body["pong"].as_bool()), (200, Some(true)));

    // A valid push for an unbound repository is accepted and ignored: GitHub
    // must not retry it, and no delivery is stored.
    let unbound = push_payload(92);
    let unbound_raw = unbound.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&unbound),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(unbound_raw.as_bytes()),
            ),
            ("x-github-event", "push"),
            ("x-github-delivery", "gh-2"),
        ],
    );
    assert_eq!(
        (status, body["ignored"].as_str()),
        (200, Some("unbound_repository"))
    );
    // A delivery without its identity header is refused before the store.
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[("x-hub-signature-256", &signed), ("x-github-event", "push")],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    // The bound repository accepts, stores and deduplicates.
    let (status, first) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[
            ("x-hub-signature-256", &signed),
            ("x-github-event", "push"),
            ("x-github-delivery", "gh-3"),
        ],
    );
    assert_eq!(
        (status, first["duplicate"].as_bool()),
        (202, Some(false)),
        "{first}"
    );
    let id = first["delivery"].as_str().unwrap().to_owned();
    assert_eq!(delivery_state(&d, &id), intake::State::Pending);
    let (status, again) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[
            ("x-hub-signature-256", &signed),
            ("x-github-event", "push"),
            ("x-github-delivery", "gh-3"),
        ],
    );
    assert_eq!((status, again["duplicate"].as_bool()), (202, Some(true)));
    assert_eq!(again["delivery"].as_str(), Some(id.as_str()));
    // An event this deployment does not handle is acknowledged and ignored,
    // not retried.
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&payload),
        None,
        &[
            ("x-hub-signature-256", &signed),
            ("x-github-event", "workflow_run"),
            ("x-github-delivery", "gh-4"),
        ],
    );
    assert_eq!(
        (status, body["ignored"].as_str()),
        (200, Some("unsupported_event"))
    );
    // A pull request is intake now: the base branch is the policy ref and the
    // tested merge is what it stands for. Only the actions that mean new work
    // are stored; others are acknowledged and ignored.
    let pr = pr_payload("opened", GITHUB_REPO_ID, Some(&"e".repeat(40)));
    let pr_raw = pr.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&pr),
        None,
        &[
            ("x-hub-signature-256", &webhook_signature(pr_raw.as_bytes())),
            ("x-github-event", "pull_request"),
            ("x-github-delivery", "gh-5"),
        ],
    );
    assert_eq!(
        (status, body["duplicate"].as_bool()),
        (202, Some(false)),
        "{body}"
    );
    let pr_id = body["delivery"].as_str().unwrap().to_owned();
    assert_eq!(delivery_state(&d, &pr_id), intake::State::Pending);
    let labeled = pr_payload("labeled", GITHUB_REPO_ID, Some(&"e".repeat(40)));
    let labeled_raw = labeled.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&labeled),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(labeled_raw.as_bytes()),
            ),
            ("x-github-event", "pull_request"),
            ("x-github-delivery", "gh-6"),
        ],
    );
    assert_eq!((status, body["ignored"].as_str()), (200, Some("pr_action")));
    // A malformed pull-request body is a request error, not a crash.
    let broken = serde_json::json!({ "action": "opened", "number": 7 });
    let broken_raw = broken.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&broken),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(broken_raw.as_bytes()),
            ),
            ("x-github-event", "pull_request"),
            ("x-github-delivery", "gh-7"),
        ],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    // Control events are acknowledged with their outcome, never retried: a
    // check-suite rerequest for a check we never published resolves to
    // nothing, and the receipt deduplicates the replay.
    let suite = serde_json::json!({
        "action": "rerequested",
        "installation": {"id": 42},
        "repository": {"id": GITHUB_REPO_ID},
        "check_suite": {"id": 777, "head_sha": "e".repeat(40)},
    });
    let suite_raw = suite.to_string();
    let suite_headers = |raw: &str, delivery: &str| {
        [
            ("x-hub-signature-256", webhook_signature(raw.as_bytes())),
            ("x-github-event", "check_suite".to_owned()),
            ("x-github-delivery", delivery.to_owned()),
        ]
    };
    let suite_headers = suite_headers(&suite_raw, "gh-8");
    let suite_headers: Vec<(&str, &str)> = suite_headers
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&suite),
        None,
        &suite_headers,
    );
    assert_eq!(
        (
            status,
            body["controlled"].as_str(),
            body["duplicate"].as_bool()
        ),
        (200, Some("unknown_check"), Some(false)),
        "{body}"
    );
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&suite),
        None,
        &suite_headers,
    );
    assert_eq!(
        (
            status,
            body["controlled"].as_str(),
            body["duplicate"].as_bool()
        ),
        (200, Some("unknown_check"), Some(true)),
        "a replayed receipt answers what the first attempt did"
    );
    // The same delivery id under a different event is a conflict.
    let renamed = serde_json::json!({
        "action": "renamed",
        "installation": {"id": 42},
        "repository": {"id": GITHUB_REPO_ID},
    });
    let renamed_raw = renamed.to_string();
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&renamed),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(renamed_raw.as_bytes()),
            ),
            ("x-github-event", "repository"),
            ("x-github-delivery", "gh-8"),
        ],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("conflict")),
        "{body}"
    );
    // A rename under a fresh delivery revokes the binding; an approved remote
    // never follows a repository's new name.
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/hooks/github",
        Some(&renamed),
        None,
        &[
            (
                "x-hub-signature-256",
                &webhook_signature(renamed_raw.as_bytes()),
            ),
            ("x-github-event", "repository"),
            ("x-github-delivery", "gh-9"),
        ],
    );
    assert_eq!(
        (status, body["controlled"].as_str()),
        (200, Some("repository_rebind_required")),
        "{body}"
    );
    let revoked: bool = d
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT revoked FROM source_bindings WHERE repo_id=?1",
                [d.github_repo.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(revoked, "the rename revoked the binding");
    // The repository owned by the token is what the delivery belongs to: the
    // generic secret is scoped to its repository.
    let (status, _) = call(
        &d,
        "POST",
        &format!("/api/v1/intake/{}", d.github_repo),
        Some(&update("hook-5")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(status, 401);

    // The admission bound is reported as rate_limited, and a duplicate of an
    // already-stored delivery is still acknowledged at the bound.
    let repo = d.intake_repo;
    let tenant = d.tenant;
    let received = UnixMillis::now().0;
    d.store
        .writer()
        .write(move |tx| {
            for index in 0..sentinel_store::intake::MAX_PENDING_PER_REPO {
                let id = sentinel_core::DeliveryId::new();
                let filler = format!("filler-{index}");
                let (old, new) = ("a".repeat(40), "b".repeat(40));
                tx.execute(
                    "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
                        event, ref_name, old_sha, new_sha, state, received_ms)
                     VALUES (?1, ?2, ?3, 'generic', ?4, 'ref_update', ?5, ?6, ?7, 0, ?8)",
                    (
                        id.as_bytes().as_slice(),
                        tenant.as_bytes().as_slice(),
                        repo.as_bytes().as_slice(),
                        filler.as_str(),
                        "refs/heads/main",
                        old.as_str(),
                        new.as_str(),
                        received,
                    ),
                )?;
            }
            Ok(())
        })
        .unwrap();
    let (status, body) = call(
        &d,
        "POST",
        &intake_path,
        Some(&update("hook-6")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (429, Some("rate_limited")),
        "{body}"
    );
    let (status, again) = call(
        &d,
        "POST",
        &intake_path,
        Some(&update("hook-4")),
        Some(&hook_bearer(&d)),
        &[],
    );
    assert_eq!((status, again["duplicate"].as_bool()), (202, Some(true)));
}

// ---- D02: resumable uploads and authorized range downloads ----

/// Raw bytes in and out plus Content-Range, for the transfer routes.
fn raw(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    auth: Option<&str>,
    extra: &[(&str, &str)],
) -> (u16, Vec<u8>, Option<String>) {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "PUT" => agent.put(&url),
        "POST" => agent.post(&url),
        "DELETE" => agent.delete(&url).force_send_body(),
        _ => unreachable!(),
    };
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    for (k, v) in extra {
        request = request.header(*k, *v);
    }
    let response = match body {
        Some(bytes) => request.send(bytes).unwrap(),
        None => request.send_empty().unwrap(),
    };
    let status = response.status().as_u16();
    let range = response
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = response.into_body().read_to_vec().unwrap();
    (status, bytes, range)
}

/// An upload request that sends its headers and one byte, then stalls: the
/// server's body read blocks, holding a transfer slot until the socket dies.
fn held_upload(d: &Deployment, path: &str, auth: &str, len: usize) -> std::net::TcpStream {
    use std::io::Write as _;
    let addr = d.base.strip_prefix("http://").unwrap().to_owned();
    let mut socket = std::net::TcpStream::connect(addr).unwrap();
    write!(
        socket,
        "PUT {path} HTTP/1.1\r\nhost: sentinel\r\nauthorization: {auth}\r\ncontent-length: {len}\r\n\r\nx"
    )
    .unwrap();
    socket
}

#[test]
fn uploads_resume_commit_and_downloads_range_through_the_api() {
    let d = deployment();
    let auth = bearer(&d);
    let content: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let digest = blake3::hash(&content).to_hex().to_string();

    // Begin the session under the tenant's slug.
    let (status, begin) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": content.len(), "digest": digest })),
        Some(&auth),
        &[],
    );
    assert_eq!((status, begin["state"].as_str()), (201, Some("open")));
    assert_eq!(begin["received"], 0);
    let upload = begin["upload"].as_str().unwrap().to_owned();

    // Send the tail first, retry it identically, then fill the gap.
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset=30000"),
        Some(&content[30_000..]),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    let (status, ack, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset=30000"),
        Some(&content[30_000..]),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ack).unwrap()["received"],
        10_000
    );
    let (status, st) = call(
        &d,
        "GET",
        &format!("/api/v1/uploads/{upload}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    assert_eq!(st["received"], 10_000);
    assert_eq!(st["ranges"][0][0], 30_000);

    // Sealing before the ranges tile is refused; nothing is committed yet.
    let (status, body) = call(
        &d,
        "POST",
        &format!("/api/v1/uploads/{upload}/commit"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );
    let (status, _body, _) = raw(
        &d,
        "GET",
        &format!("/api/v1/tenants/acme/objects/{digest}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 404);

    // Out-of-bounds and missing-offset chunks are refused.
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}"),
        Some(&content[..1]),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 400);
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset={}", content.len() - 1),
        Some(&content[..2]),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 400);

    // Fill the head and commit; the digest comes back and the object serves.
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset=0"),
        Some(&content[..30_000]),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    let (status, sealed) = call(
        &d,
        "POST",
        &format!("/api/v1/uploads/{upload}/commit"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, sealed["digest"].as_str()),
        (200, Some(digest.as_str()))
    );
    // Committing again answers the same digest (idempotent close).
    let (status, sealed) = call(
        &d,
        "POST",
        &format!("/api/v1/uploads/{upload}/commit"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, sealed["digest"].as_str()),
        (200, Some(digest.as_str()))
    );

    let object = format!("/api/v1/tenants/acme/objects/{digest}");
    let (status, bytes, range) = raw(&d, "GET", &object, None, Some(&auth), &[]);
    assert_eq!(status, 200);
    assert_eq!(bytes, content);
    assert!(range.is_none());

    let (status, bytes, range) = raw(
        &d,
        "GET",
        &object,
        None,
        Some(&auth),
        &[("range", "bytes=10-19")],
    );
    assert_eq!(status, 206);
    assert_eq!(bytes, content[10..20]);
    assert_eq!(range.as_deref(), Some("bytes 10-19/40000"));

    let (status, bytes, _) = raw(
        &d,
        "GET",
        &object,
        None,
        Some(&auth),
        &[("range", "bytes=-7")],
    );
    assert_eq!(status, 206);
    assert_eq!(bytes, content[39_993..]);

    for spec in ["bytes=99-4", "bytes=40000-", "items=0-1", "bytes=0-1,4-5"] {
        let (status, _, _) = raw(&d, "GET", &object, None, Some(&auth), &[("range", spec)]);
        assert_eq!(status, 400, "{spec} must be refused");
    }

    // Without credentials every transfer route refuses.
    for (method, path) in [
        ("POST", "/api/v1/tenants/acme/uploads"),
        ("GET", &format!("/api/v1/uploads/{upload}")),
        ("PUT", &format!("/api/v1/uploads/{upload}?offset=0")),
        ("DELETE", &format!("/api/v1/uploads/{upload}")),
        ("GET", &object),
    ] {
        let (status, _, _) = raw(&d, method, path, None, None, &[]);
        assert_eq!(status, 401, "{method} {path}");
    }

    // A credential scoped to another tenant cannot see the upload or object.
    let other_tenant = TenantId::new();
    let root = d.root;
    d.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                other_tenant,
                Namespace::parse("other").unwrap(),
                NamespaceKind::Organization,
                UnixMillis::now(),
            )
        })
        .unwrap();
    let outsider = tokens::provision(
        &d.store,
        Grant {
            user: d.root,
            name: "foreign",
            permissions: P::ALL,
            tenant: Some(other_tenant),
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let foreign = format!("Bearer {}", sentinel_auth::token::format(&outsider.secret));
    let (status, body) = call(
        &d,
        "GET",
        &format!("/api/v1/uploads/{upload}"),
        None,
        Some(&foreign),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let (status, _, _) = raw(&d, "GET", &object, None, Some(&foreign), &[]);
    assert_eq!(status, 404);
    let (status, body) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": 4 })),
        Some(&foreign),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));

    // Aborting a second open upload drops it; writes after abort conflict.
    let (status, begin) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": 4 })),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let doomed = begin["upload"].as_str().unwrap().to_owned();
    let (status, _, _) = raw(
        &d,
        "DELETE",
        &format!("/api/v1/uploads/{doomed}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    let (status, body, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{doomed}?offset=0"),
        Some(b"ab"),
        Some(&auth),
        &[],
    );
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
}

#[test]
fn transfer_slots_are_bounded() {
    let d = deployment();
    let auth = bearer(&d);
    // A small committed object to download once slots are free again.
    let content = b"downloadable".repeat(64);
    let digest = blake3::hash(&content).to_hex().to_string();
    let (status, begin) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": content.len(), "digest": digest })),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let upload = begin["upload"].as_str().unwrap().to_owned();
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset=0"),
        Some(&content),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    let (status, _) = call(
        &d,
        "POST",
        &format!("/api/v1/uploads/{upload}/commit"),
        Some(&serde_json::json!({})),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);

    // Pin every slot with an upload whose body never finishes arriving.
    let (status, begin) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": 4 << 20 })),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let pending = begin["upload"].as_str().unwrap().to_owned();
    let held: Vec<std::net::TcpStream> = (0..sentinel_api::TRANSFERS)
        .map(|_| {
            held_upload(
                &d,
                &format!("/api/v1/uploads/{pending}?offset=0"),
                &auth,
                4 << 20,
            )
        })
        .collect();
    // Give the workers a moment to reach their blocked body reads.
    thread::sleep(Duration::from_millis(300));
    let object = format!("/api/v1/tenants/acme/objects/{digest}");
    let (status, body, _) = raw(&d, "GET", &object, None, Some(&auth), &[]);
    assert_eq!(status, 429);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        "rate_limited"
    );
    drop(held);
    // The dead sockets release their slots as their blocked reads fail;
    // retry briefly rather than assume an instant release.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (status, bytes) = loop {
        let (status, bytes, _) = raw(&d, "GET", &object, None, Some(&auth), &[]);
        if status == 200 || std::time::Instant::now() > deadline {
            break (status, bytes);
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status, 200);
    assert_eq!(bytes.len(), content.len());
}

#[test]
fn artifact_routes_are_authorized_and_scoped() {
    let d = deployment();
    let (tenant, repo) = (d.tenant, d.intake_repo);
    let now = UnixMillis::now();
    // A run over the bound intake repository: one queued job, one placed
    // attempt, one captured artifact with a manifest and one absent row.
    let run = RunId::new();
    let spec = RunSpec::new(
        PinnedSource::new(
            "https://git.example:8443/team/repo.git",
            "0123456789abcdef0123456789abcdef01234567",
            Some("refs/heads/main"),
        )
        .unwrap(),
        compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
        )
        .unwrap(),
    )
    .unwrap();
    let job = d
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids[0])
        })
        .unwrap();
    let (pool, worker) = (PoolId::new(), WorkerId::new());
    d.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "artifacts",
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
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 8 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    let offer = d
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("the queued job was placed");
    assert_eq!((offer.run, offer.job), (run, job));
    // The captured row carries a committed manifest; the absent one does not.
    let objects = Objects::open(d._dir.path()).unwrap();
    let staged = objects
        .stage(tenant, &b"report-bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    let (captured, absent) = {
        let objects = Objects::open(d._dir.path()).unwrap();
        d.store
            .writer()
            .write(move |tx| {
                objects.commit(tx, &staged)?;
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    &artifacts::manifest_name(job, "report"),
                    &[Entry {
                        path: "out/report.txt".into(),
                        digest: staged.digest(),
                        len: staged.len(),
                        mode: 0o644,
                    }],
                )?;
                let captured = artifacts::record(
                    tx,
                    tenant,
                    run,
                    job,
                    offer.attempt,
                    "report",
                    artifacts::State::Captured,
                    Some(version),
                    1,
                    staged.len(),
                    UnixMillis(now.0 + 7 * 86_400_000),
                    now,
                )?;
                let absent = artifacts::record(
                    tx,
                    tenant,
                    run,
                    job,
                    offer.attempt,
                    "coverage",
                    artifacts::State::Absent,
                    None,
                    0,
                    0,
                    UnixMillis(now.0 + 7 * 86_400_000),
                    now,
                )?;
                Ok((captured, absent))
            })
            .unwrap()
    };
    let auth = bearer(&d);
    // The listing answers both rows, newest states included.
    let (status, rows) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200);
    let rows = rows["artifacts"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    // Detail returns the manifest's entry list for the captured row.
    let (status, detail) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts/{captured}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["state"], "captured");
    assert_eq!(detail["name"], "report");
    let manifest = &detail["manifest"];
    assert_eq!(manifest["version"], 1);
    let entries = manifest["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["path"], "out/report.txt");
    assert_eq!(entries[0]["len"], 12);
    // The absent row has no manifest.
    let (status, detail) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts/{absent}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, detail["state"].as_str()), (200, Some("absent")));
    assert!(detail.get("manifest").is_none() || detail["manifest"].is_null());
    // Anonymous calls refuse; a foreign run or artifact id is invisible.
    for path in [
        format!("/api/v1/runs/{run}/artifacts"),
        format!("/api/v1/runs/{run}/artifacts/{captured}"),
    ] {
        let (status, _) = call(&d, "GET", &path, None, None, &[]);
        assert_eq!(status, 401, "{path}");
    }
    let (status, body) = call(
        &d,
        "GET",
        &format!(
            "/api/v1/runs/{run}/artifacts/{}",
            sentinel_core::ArtifactId::new()
        ),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));

    // P06-6: the bytes follow repository authorization. The admin reads
    // them; a tenant reader without a grant on the repository cannot — the
    // digest answers exactly as an unknown one would — until granted.
    let digest = entries[0]["digest"].as_str().unwrap().to_owned();
    let object = format!("/api/v1/tenants/acme/objects/{digest}");
    let (status, bytes, _) = raw(&d, "GET", &object, None, Some(&auth), &[]);
    assert_eq!((status, bytes.as_slice()), (200, &b"report-bytes"[..]));
    let reader = UserId::new();
    let root = d.root;
    d.store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, reader, "Rita", false, now)?;
            auth::set_membership(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                reader,
                sentinel_core::auth::Role::Reader,
            )
        })
        .unwrap();
    let reader_auth = format!(
        "Bearer {}",
        sentinel_auth::token::format(
            &tokens::provision(
                &d.store,
                Grant {
                    user: reader,
                    name: "rita",
                    permissions: P::READ,
                    tenant: None,
                    repo: None,
                    lifetime_ms: 60_000,
                },
                now,
            )
            .unwrap()
            .secret
        )
    );
    let unknown = format!("/api/v1/tenants/acme/objects/{}", "0".repeat(64));
    let (status, missing, _) = raw(&d, "GET", &unknown, None, Some(&reader_auth), &[]);
    assert_eq!(status, 404);
    let (status, refused, _) = raw(&d, "GET", &object, None, Some(&reader_auth), &[]);
    assert_eq!(
        status, 404,
        "a reader without a grant read another repo's bytes"
    );
    let code =
        |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap()["code"].clone();
    assert_eq!(code(&refused), code(&missing), "an existence oracle");
    d.store
        .writer()
        .write(move |tx| {
            auth::set_repo_grant(
                tx,
                Principal::new(root, P::ALL, None, None),
                repo,
                reader,
                P::READ,
            )
        })
        .unwrap();
    let (status, _, _) = raw(&d, "GET", &object, None, Some(&reader_auth), &[]);
    assert_eq!(status, 200);
    // A super admin holding platform scope is no member of another tenant:
    // its bytes are not the admin's to read.
    let beta = TenantId::new();
    let foreign = {
        let objects = Objects::open(d._dir.path()).unwrap();
        let staged = objects
            .stage(beta, &b"beta bytes"[..], u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        d.store
            .writer()
            .write(move |tx| {
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    beta,
                    Namespace::parse("beta").unwrap(),
                    NamespaceKind::Organization,
                    now,
                )?;
                objects.commit(tx, &staged).map(|_| ())
            })
            .unwrap();
        digest
    };
    let (status, _, _) = raw(
        &d,
        "GET",
        &format!("/api/v1/tenants/beta/objects/{foreign}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(status, 404, "platform scope read a tenant's bytes");
}

/// Upload `content` as root and return its digest.
fn upload_object(d: &Deployment, auth: &str, content: &[u8]) -> String {
    let digest = blake3::hash(content).to_hex().to_string();
    let (status, begin) = call(
        d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": content.len(), "digest": digest })),
        Some(auth),
        &[],
    );
    assert_eq!(status, 201, "{begin}");
    let upload = begin["upload"].as_str().unwrap().to_owned();
    for (i, chunk) in content.chunks(sentinel_api::MAX_UPLOAD_CHUNK).enumerate() {
        let offset = i * sentinel_api::MAX_UPLOAD_CHUNK;
        let (status, _, _) = raw(
            d,
            "PUT",
            &format!("/api/v1/uploads/{upload}?offset={offset}"),
            Some(chunk),
            Some(auth),
            &[],
        );
        assert_eq!(status, 200);
    }
    let (status, sealed) = call(
        d,
        "POST",
        &format!("/api/v1/uploads/{upload}/commit"),
        Some(&serde_json::json!({})),
        Some(auth),
        &[],
    );
    assert_eq!(status, 200, "{sealed}");
    digest
}

/// A GET whose response is never read: once the socket buffers fill, the
/// server's body write stalls with the request's permits held.
fn stalled_get(d: &Deployment, path: &str, auth: &str) -> std::net::TcpStream {
    use std::io::Write as _;
    let addr = d.base.strip_prefix("http://").unwrap().to_owned();
    let mut socket = std::net::TcpStream::connect(addr).unwrap();
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nhost: sentinel\r\nauthorization: {auth}\r\n\r\n"
    )
    .unwrap();
    socket
}

/// P06-2 and P09-12: a download holds its transfer slot until its body is
/// written, and with every transfer slot held by stalled downloads and every
/// subscriber slot by parked waits, control requests still find a handler.
#[test]
fn downloads_hold_their_slot_and_control_requests_keep_handlers() {
    let d = deployment();
    let auth = bearer(&d);
    let content: Vec<u8> = (0..(24u32 << 20)).map(|i| (i % 253) as u8).collect();
    let digest = upload_object(&d, &auth, &content);
    let object = format!("/api/v1/tenants/acme/objects/{digest}");
    let stalled: Vec<_> = (0..sentinel_api::TRANSFERS)
        .map(|_| stalled_get(&d, &object, &auth))
        .collect();
    thread::sleep(Duration::from_millis(500));
    let (status, body, _) = raw(&d, "GET", &object, None, Some(&auth), &[]);
    assert_eq!(status, 429, "downloads are not bounded while they stream");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        "rate_limited"
    );
    // Park every subscriber slot too.
    let (status, run) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201, "{run}");
    let run = run["id"].as_str().unwrap().to_owned();
    let (_, first) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/wait"),
        None,
        Some(&auth),
        &[],
    );
    let version = first["version"].as_str().unwrap().to_owned();
    let waits: Vec<_> = (0..sentinel_api::SUBSCRIBERS)
        .map(|_| {
            let (base, auth, run, version) =
                (d.base.clone(), auth.clone(), run.clone(), version.clone());
            thread::spawn(move || {
                let agent = ureq::Agent::new_with_config(
                    ureq::Agent::config_builder()
                        .http_status_as_error(false)
                        .build(),
                );
                agent
                    .get(format!(
                        "{base}/api/v1/runs/{run}/wait?since={version}&timeout_ms=3000"
                    ))
                    .header("authorization", &auth)
                    .call()
                    .unwrap()
                    .status()
                    .as_u16()
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(500));
    // Transfers and long polls hold six of eight permits; the reserved two
    // still answer at once.
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let (status, _) = call(&d, "GET", "/api/v1/health", None, None, &[]);
        assert_eq!(status, 200);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "health waited {:?} behind long-held permits",
            started.elapsed()
        );
    }
    for wait in waits {
        assert_eq!(wait.join().unwrap(), 200);
    }
    drop(stalled);
    // The dead sockets fail their stalled writes and release the slots.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        let (status, bytes, _) = raw(
            &d,
            "GET",
            &object,
            None,
            Some(&auth),
            &[("range", "bytes=0-9")],
        );
        if status == 206 || std::time::Instant::now() > deadline {
            assert!(status != 206 || bytes == content[..10]);
            break status;
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status, 206);
}

/// P06-13: a whole-object download is rehashed while it streams; bytes that
/// rotted on disk end the body short instead of arriving complete.
#[test]
fn a_rotted_object_is_never_served_whole() {
    use std::io::Read as _;
    let d = deployment();
    let auth = bearer(&d);
    let content = b"bytes that will rot on disk".repeat(1000);
    let digest = upload_object(&d, &auth, &content);
    let path = d
        ._dir
        .path()
        .join("objects")
        .join(d.tenant.to_string())
        .join(&digest[..2])
        .join(&digest);
    let mut rotten = content.clone();
    rotten[5000] ^= 0xff;
    std::fs::write(&path, &rotten).unwrap();
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .get(format!("{}/api/v1/tenants/acme/objects/{digest}", d.base))
        .header("authorization", &auth)
        .call()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let mut got = Vec::new();
    let read = response.into_body().into_reader().read_to_end(&mut got);
    assert!(
        read.is_err() || got.len() < content.len(),
        "a corrupt object arrived whole ({} bytes)",
        got.len()
    );
    // A range read is not verified (documented); the route still serves it.
    let (status, _, _) = raw(
        &d,
        "GET",
        &format!("/api/v1/tenants/acme/objects/{digest}"),
        None,
        Some(&auth),
        &[("range", "bytes=0-9")],
    );
    assert_eq!(status, 206);
}

/// P06-12: touching an expired upload retires it — durably, not inside the
/// refused request's rolled-back transaction.
#[test]
fn touching_an_expired_upload_retires_it() {
    let d = deployment();
    let auth = bearer(&d);
    let (status, begin) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/uploads",
        Some(&serde_json::json!({ "len": 8, "ttl_ms": 1 })),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201);
    let upload = begin["upload"].as_str().unwrap().to_owned();
    thread::sleep(Duration::from_millis(20));
    let (status, _, _) = raw(
        &d,
        "PUT",
        &format!("/api/v1/uploads/{upload}?offset=0"),
        Some(b"abcdefgh"),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 400);
    let (status, state) = call(
        &d,
        "GET",
        &format!("/api/v1/uploads/{upload}"),
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(
        (status, state["state"].as_str()),
        (200, Some("aborted")),
        "{state}"
    );
    assert!(
        !d._dir.path().join("incoming").join(&upload).exists(),
        "the staging file outlived the retirement"
    );
}

/// P02-3 and P09-11: the log route refuses a malformed position instead of
/// restarting at zero, pages carry the versioned `c1` cursor bound to the
/// tenant and attempt, and a page of full frames is bounded in bytes.
#[test]
fn log_pages_are_bounded_and_positions_are_validated() {
    let d = deployment();
    let auth = bearer(&d);
    let (status, run) = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&dispatch_body()),
        Some(&auth),
        &[],
    );
    assert_eq!(status, 201, "{run}");
    let run_id: RunId = run["id"].as_str().unwrap().parse().unwrap();
    let job_id: sentinel_core::JobId = run["jobs"][0]["id"].as_str().unwrap().parse().unwrap();
    let attempt = attempt_for(&d, job_id);
    let full = vec![b'z'; 32 * 1024];
    for seq in 1..=100u64 {
        d.logs
            .append(
                run_id,
                job_id,
                attempt,
                &Frame {
                    seq,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes: full.clone(),
                },
            )
            .unwrap();
    }
    let logs = format!("/api/v1/attempts/{attempt}");
    for bad in ["after=abc", "after=-1", "limit=many", "step=x"] {
        let (status, body) = call(
            &d,
            "GET",
            &format!("{logs}/logs?{bad}"),
            None,
            Some(&auth),
            &[],
        );
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{bad}: {body}"
        );
    }
    for bad in [
        "c1zz".to_owned(),
        sentinel_protocol::cursor::Cursor {
            tenant: TenantId::new(),
            kind: sentinel_protocol::cursor::StreamKind::AttemptLog,
            stream: *attempt.as_bytes(),
            seq: sentinel_protocol::cursor::Seq(0),
        }
        .to_string(),
        sentinel_protocol::cursor::Cursor {
            tenant: d.tenant,
            kind: sentinel_protocol::cursor::StreamKind::AttemptLog,
            stream: *AttemptId::new().as_bytes(),
            seq: sentinel_protocol::cursor::Seq(0),
        }
        .to_string(),
    ] {
        let (status, body) = call(
            &d,
            "GET",
            &format!("{logs}/logs?cursor={bad}"),
            None,
            Some(&auth),
            &[],
        );
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_cursor")),
            "{body}"
        );
    }
    // Paging by the numeric position and by the cursor sees every frame,
    // each page within the byte bound.
    let mut seen = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let query = match &next {
            None => "after=0".to_owned(),
            Some(cursor) => format!("cursor={cursor}"),
        };
        let (status, page) = call(
            &d,
            "GET",
            &format!("{logs}/logs?{query}&limit=500"),
            None,
            Some(&auth),
            &[],
        );
        assert_eq!(status, 200, "{page}");
        let frames = page["frames"].as_array().unwrap();
        let bytes: usize = frames
            .iter()
            .map(|f| f["text"].as_str().unwrap().len())
            .sum();
        assert!(
            bytes <= sentinel_store::logs::PAGE_BYTES as usize,
            "{bytes}"
        );
        seen.extend(frames.iter().map(|f| f["seq"].as_u64().unwrap()));
        assert!(page["next"].as_str().unwrap().starts_with("c1"));
        if page["next_after"].is_null() {
            break;
        }
        next = Some(page["next"].as_str().unwrap().to_owned());
    }
    assert_eq!(seen, (1..=100).collect::<Vec<_>>());
}

/// Place the job's attempt through the dispatcher's own path.
fn attempt_for(d: &Deployment, job: sentinel_core::JobId) -> AttemptId {
    let (tenant, now) = (d.tenant, UnixMillis::now());
    let (pool, worker) = (PoolId::new(), WorkerId::new());
    d.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "logs",
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
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 8 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    let offer = d
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("the queued job was placed");
    assert_eq!(offer.job, job);
    offer.attempt
}

/// A raw `POST /api/v1/login`: (status, set-cookie, body).
fn raw_login(
    d: &Deployment,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, Option<String>, String) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut request = agent.post(&format!("{}/api/v1/login", d.base));
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let response = request.send(body.as_bytes()).unwrap();
    let status = response.status().as_u16();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_owned());
    (
        status,
        cookie,
        response.into_body().read_to_string().unwrap(),
    )
}

/// Login CSRF: the body a cross-site `enctype="text/plain"` form produces
/// (`name=value`, shaped to parse as JSON) mints no session.
#[test]
fn login_refuses_a_text_plain_body() {
    let d = deployment();
    let forged = r#"{"username":"root","password":"correct horse battery=staple"}"#;
    let (status, cookie, body) = raw_login(&d, forged, &[("content-type", "text/plain")]);
    assert_eq!(status, 400, "{body}");
    assert!(cookie.is_none());
    // Without any content type, too.
    let (status, cookie, _) = raw_login(&d, forged, &[]);
    assert_eq!(status, 400);
    assert!(cookie.is_none());
}

#[test]
fn login_refuses_a_foreign_origin() {
    let d = deployment();
    let good = r#"{"username":"root","password":"correct horse battery staple"}"#;
    let (status, cookie, _) = raw_login(
        &d,
        good,
        &[
            ("content-type", "application/json"),
            ("origin", "https://attacker.example"),
        ],
    );
    assert_eq!(status, 403);
    assert!(cookie.is_none());
    // The deployment's own origin, or none (a non-browser client), signs in.
    let own = d.base.clone();
    let (status, cookie, _) = raw_login(
        &d,
        good,
        &[
            ("content-type", "application/json; charset=utf-8"),
            ("origin", &own),
        ],
    );
    assert_eq!(status, 200);
    assert!(cookie.is_some());
    let (status, _, _) = raw_login(&d, good, &[("content-type", "application/json")]);
    assert_eq!(status, 200);
}

/// P03-7 / P02-9: an existing tenant the caller has no part in lists as the
/// same `not_found` as a tenant that does not exist, never as an empty page.
#[test]
fn a_foreign_tenant_slug_lists_as_not_found() {
    let d = deployment();
    let (member, globex) = (UserId::new(), TenantId::new());
    let root = d.root;
    let now = UnixMillis::now();
    let tenant = d.tenant;
    d.store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            provisioning::insert_human(tx, member, "Member", false, now)?;
            auth::create_namespace(
                tx,
                admin,
                globex,
                Namespace::parse("globex").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, member, sentinel_core::auth::Role::Reader)
        })
        .unwrap();
    let granted = tokens::provision(
        &d.store,
        Grant {
            user: member,
            name: "member",
            permissions: P::REPOSITORY,
            tenant: None,
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let auth = format!("Bearer {}", sentinel_auth::token::format(&granted.secret));
    let (own, _) = call(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(own, 200);
    let foreign = call(
        &d,
        "GET",
        "/api/v1/tenants/globex/repos",
        None,
        Some(&auth),
        &[],
    );
    let missing = call(
        &d,
        "GET",
        "/api/v1/tenants/nowhere/repos",
        None,
        Some(&auth),
        &[],
    );
    assert_eq!(foreign.0, 404, "{}", foreign.1);
    assert_eq!(foreign, missing);
}

/// P03-5: using a session slides its idle deadline, so an active session
/// outlives the idle window it started with; the cookie lives as long as
/// the session's absolute bound.
#[test]
fn an_active_session_outlives_its_first_idle_deadline() {
    let policy = local_auth::Policy {
        idle_ms: 6_000,
        refresh_after_ms: 1_000,
        ..local_auth::Policy::default()
    };
    let d = deployment_with(policy);
    // The session's clock starts when the login request arrives, before the
    // (slow, in a debug build) password hash: time everything from here.
    let start = std::time::Instant::now();
    let at = |ms: u64| {
        let due = start + Duration::from_millis(ms);
        thread::sleep(due.saturating_duration_since(std::time::Instant::now()));
    };
    let (status, cookie, _) = raw_login(
        &d,
        r#"{"username":"root","password":"correct horse battery staple"}"#,
        &[("content-type", "application/json")],
    );
    assert_eq!(status, 200);
    let cookie = cookie.unwrap();
    let max_age = format!("Max-Age={}", policy.absolute_ms / 1000);
    assert!(cookie.contains(&max_age), "{cookie}");
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let me = || call(&d, "GET", "/api/v1/me", None, None, &[("cookie", &cookie)]).0;
    // Used at 4 s: the idle deadline slides to about 10 s.
    at(4_000);
    assert_eq!(me(), 200);
    // Past the first idle deadline (6 s after sign-in), still signed in;
    // this use slides it to about 14 s.
    at(8_000);
    assert_eq!(me(), 200);
    // Idle for a whole window: gone.
    at(14_700);
    assert_eq!(me(), 401);
}
