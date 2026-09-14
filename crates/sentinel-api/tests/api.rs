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
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
};

const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    tenant: TenantId,
    repo: RepoId,
    root: UserId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let (tenant, repo, pool) = (TenantId::new(), RepoId::new(), PoolId::new());
    // A bootstrapped super admin with a password, a namespace, a repository
    // and a pool.
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
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis::now(),
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
                UnixMillis::now(),
            )?;
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
        tenant,
        repo,
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
    assert_eq!(repos["repos"][0]["name"], "app");
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
