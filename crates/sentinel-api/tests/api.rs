//! W08 over real HTTP on loopback: authentication by bearer credential and
//! by session cookie (with CSRF on mutations), structured errors, dispatch
//! with idempotency, status, cancel, rerun, log tail/follow through the
//! same files the controller writes, and worker status.

use std::{sync::Arc, thread, time::Duration};

use sentinel_core::{
    AttemptId, PoolId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    source::{Binding, Credential},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    intake, local_auth,
    logs::LogStore,
    registration,
    sources::{self, Update},
    sources_forge,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
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
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs: Arc::clone(&logs),
        controller: controller.handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: Some(Arc::from(WEBHOOK_SECRET)),
        intake: None,
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
    let attempt = {
        let job: sentinel_core::JobId = run2["jobs"][0]["id"].as_str().unwrap().parse().unwrap();
        d.store
            .writer()
            .write(move |tx| {
                let (attempt, _) = sentinel_store::jobs::lease(
                    tx,
                    tenant,
                    job,
                    worker,
                    UnixMillis(i64::MAX / 2),
                    UnixMillis::now(),
                )?;
                Ok(attempt)
            })
            .unwrap()
    };
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
        .append(attempt, &frame(1, "hello\n", Stream::Stdout))
        .unwrap();
    d.logs
        .append(attempt, &frame(2, "warn\n", Stream::Stderr))
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
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(400));
        logs.append(
            attempt,
            &Frame {
                seq: 3,
                step: 1,
                stream: Stream::Stdout,
                bytes: b"late\n".to_vec(),
            },
        )
        .unwrap();
        logs.finish(attempt, 3, &[]).unwrap();
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
