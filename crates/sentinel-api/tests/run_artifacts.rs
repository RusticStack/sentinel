//! Run-level and runner-mode artifacts over the API (E04): attaching files to a run through the
//! existing upload sessions records them with their uploader, a runner-mode job records what
//! `upload-artifact` produced under its GitHub run and job, and both are refused by scope, by the
//! repository permission, by the tenant quota and by the run budget.

use std::sync::Arc;

use sentinel_core::{
    RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    jobs, local_auth,
    logs::LogStore,
    objects::Objects,
    retention::{self, Deployment as Limits},
    runs,
    tokens::{self, Grant},
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Api {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    server: Option<sentinel_api::Server>,
    base: String,
    admin: String,
    runner: String,
    reader: String,
    foreign: String,
    tenant: TenantId,
    repo: RepoId,
    root: UserId,
}

impl Drop for Api {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment() -> Api {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let now = UnixMillis::now();
    let operator = UserId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, operator, "Operator", true, now)?;
            auth::create_namespace(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                root,
                Role::TenantAdmin,
            )?;
            // A reader of the tenant: it can see the repository but not operate on it.
            auth::set_membership(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                operator,
                Role::Reader,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", now)
        })
        .unwrap();
    let mint = |user: UserId, permissions: Permissions, name: &'static str| {
        let granted = tokens::provision(
            &store,
            Grant {
                user,
                name,
                permissions,
                tenant: Some(tenant),
                repo: None,
                lifetime_ms: 3_600_000,
            },
            UnixMillis::now(),
        )
        .unwrap();
        format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
    };
    let admin = mint(root, Permissions::ALL, "admin");
    let foreign = {
        let (user, tenant, repo) = (UserId::new(), TenantId::new(), RepoId::new());
        store
            .writer()
            .write(move |tx| {
                provisioning::insert_human(tx, user, "Outsider", true, now)?;
                let admin = Principal::new(user, Permissions::ALL, None, None);
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse("other").unwrap(),
                    NamespaceKind::Organization,
                    now,
                )?;
                auth::set_membership(tx, admin, tenant, user, Role::TenantAdmin)?;
                auth::create_repo(tx, admin, tenant, repo, "other", now)
            })
            .unwrap();
        let granted = tokens::provision(
            &store,
            Grant {
                user,
                name: "outsider",
                permissions: Permissions::ALL,
                tenant: None,
                repo: None,
                lifetime_ms: 3_600_000,
            },
            UnixMillis::now(),
        )
        .unwrap();
        format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
    };
    // `run` implies every scope `runs:write` does, `artifacts:write` included; the live membership
    // is what decides whether the repository may be operated on.
    let runner = mint(operator, Permissions::RUN, "runner");
    let reader = mint(root, Permissions::READ, "reader");
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
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
        logs,
        objects: Arc::clone(&objects),
        controller: controller.handle(),
        secret_key: Some(Arc::new(
            sentinel_auth::sealed::Key::load(&key_path).unwrap(),
        )),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Api {
        _dir: dir,
        store,
        objects,
        server: Some(server),
        base,
        admin,
        runner,
        reader,
        foreign,
        tenant,
        repo,
        root,
    }
}

impl Api {
    fn run(&self) -> RunId {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let now = UnixMillis::now();
        self.store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, IMAGE, "linux/amd64")?;
                }
                Ok(())
            })
            .unwrap();
        run
    }

    /// One object through the existing upload sessions, answering the digest to name it by.
    fn upload(&self, body: &[u8]) -> String {
        let (status, begun) = call(
            self,
            "POST",
            "/api/v1/tenants/acme/uploads",
            Some(&serde_json::json!({ "len": body.len() })),
            &self.admin,
        );
        assert_eq!(status, 201, "{begun}");
        let upload = begun["upload"].as_str().unwrap().to_owned();
        let (status, _, _) = send(
            self,
            "PUT",
            &format!("/api/v1/uploads/{upload}?offset=0"),
            Some(body),
            &self.admin,
            &[("content-type", "application/octet-stream")],
        );
        assert_eq!(status, 200);
        let (status, committed) = call(
            self,
            "POST",
            &format!("/api/v1/uploads/{upload}/commit"),
            Some(&serde_json::json!({})),
            &self.admin,
        );
        assert_eq!(status, 200, "{committed}");
        committed["digest"].as_str().unwrap().to_owned()
    }

    fn attach_body(&self, name: &str, digest: &str, len: usize) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "entries": [{ "path": "reports/out.txt", "digest": digest, "len": len }],
        })
    }
}

fn call(
    d: &Api,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    auth: &str,
) -> (u16, serde_json::Value) {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "POST" => agent.post(&url),
        "PUT" => agent.put(&url),
        _ => unreachable!(),
    }
    .header("authorization", auth);
    let response = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .send(body.to_string().as_bytes())
            .unwrap(),
        None => request.send_empty().unwrap(),
    };
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

fn send(
    d: &Api,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    auth: &str,
    extra: &[(&str, &str)],
) -> (u16, Vec<u8>, String) {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "POST" => agent.post(&url),
        "PUT" => agent.put(&url),
        _ => unreachable!(),
    }
    .header("authorization", auth);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = match body {
        Some(body) => request.send(body).unwrap(),
        None => request.send_empty().unwrap(),
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response.into_body().read_to_vec().unwrap();
    (status, bytes, content_type)
}

#[test]
fn attaching_needs_the_scope_and_the_repository_permission() {
    let d = deployment();
    let run = d.run();
    let digest = d.upload(b"report bytes");
    let body = d.attach_body("reports", &digest, 12);
    let path = format!("/api/v1/runs/{run}/artifacts");

    let (status, refused) = call(&d, "POST", &path, Some(&body), &d.reader);
    assert_eq!(status, 403, "{refused}");
    assert_eq!(
        refused["code"], "forbidden",
        "a credential without the scope is refused before anything else"
    );
    assert_eq!(refused["details"]["scope"], "artifacts:write");

    // The scope alone is not authority: this credential sees the run but its live membership is a
    // reader's, so the repository permission refuses the attachment, as every run route does —
    // `not_found`, never something that reveals what it may not touch.
    let (status, seen) = call(&d, "GET", &format!("/api/v1/runs/{run}"), None, &d.reader);
    assert_eq!(
        status, 200,
        "a reader can see the run it cannot attach to: {seen}"
    );
    let (status, refused) = call(&d, "POST", &path, Some(&body), &d.runner);
    assert_eq!(status, 404, "{refused}");
    assert_eq!(refused["code"], "not_found");

    let (status, created) = call(&d, "POST", &path, Some(&body), &d.admin);
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["origin"], "run");
    assert_eq!(created["name"], "reports");
    assert_eq!(created["state"], "captured");
    assert_eq!(created["job"], serde_json::Value::Null);
    assert_eq!(created["attempt"], serde_json::Value::Null);
    assert_eq!(created["run"], run.to_string());
    assert_eq!(created["uploader"]["user_id"], d.root.to_string());
    assert_eq!(created["uploader"]["display_name"], "Root");

    let repeat = call(&d, "POST", &path, Some(&body), &d.admin);
    assert_eq!(
        repeat.0, 409,
        "the same name twice is a conflict: {repeat:?}"
    );

    let elsewhere = call(
        &d,
        "POST",
        &format!("/api/v1/runs/{}/artifacts", RunId::new()),
        Some(&body),
        &d.admin,
    );
    assert_eq!(
        elsewhere.0, 404,
        "another run is not this caller's: {elsewhere:?}"
    );
}

#[test]
fn a_run_level_artifact_lists_with_its_uploader_and_downloads_like_a_jobs() {
    let d = deployment();
    let run = d.run();
    let bytes = b"run-level artifact bytes";
    let digest = d.upload(bytes);
    let body = d.attach_body("reports", &digest, bytes.len());
    let (status, created) = call(
        &d,
        "POST",
        &format!("/api/v1/runs/{run}/artifacts"),
        Some(&body),
        &d.admin,
    );
    assert_eq!(status, 201, "{created}");
    let art = created["id"].as_str().unwrap().to_owned();

    let (status, listed) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts"),
        None,
        &d.admin,
    );
    assert_eq!(status, 200);
    let rows = listed["artifacts"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "run");
    assert_eq!(rows[0]["uploader"]["display_name"], "Root");
    assert_eq!(rows[0]["bytes"], bytes.len() as u64);
    assert_eq!(
        rows[0]["charged_bytes"],
        bytes.len() as u64,
        "the default class weighs its bytes once"
    );

    let (status, detail) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts/{art}"),
        None,
        &d.admin,
    );
    assert_eq!(status, 200);
    assert_eq!(detail["manifest"]["entries"][0]["path"], "reports/out.txt");
    assert_eq!(detail["manifest"]["entries"][0]["digest"], digest);

    // The archive route resolves through the row's own manifest, so a run-level artifact
    // downloads exactly as a job's does.
    let (status, archive, content_type) = send(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts/{art}/archive?format=tar"),
        None,
        &d.admin,
        &[],
    );
    assert_eq!(status, 200, "{content_type}");
    assert_eq!(content_type, "application/x-tar");
    assert!(
        archive.windows(bytes.len()).any(|window| window == bytes),
        "the archived body carries the attached bytes"
    );
}

#[test]
fn the_quota_and_the_run_budget_refuse_an_attachment() {
    let d = deployment();
    let run = d.run();
    let bytes = vec![7u8; 4096];
    let digest = d.upload(&bytes);
    let body = d.attach_body("reports", &digest, bytes.len());
    let path = format!("/api/v1/runs/{run}/artifacts");

    let (status, refused) = call(
        &d,
        "PUT",
        "/api/v1/tenants/acme/repos/app/storage",
        Some(&serde_json::json!({ "quota_bytes": 1024 })),
        &d.admin,
    );
    assert_eq!(status, 200, "the repository's quota is set: {refused}");
    let (status, refused) = call(&d, "POST", &path, Some(&body), &d.admin);
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["code"], "quota_exceeded");
    let (tenant, repo, limits) = (d.tenant, d.repo, d.objects.deployment());
    d.store
        .writer()
        .write(move |tx| {
            retention::set(
                tx,
                &auth::Authority::HostLocal,
                &limits,
                tenant,
                Some(repo),
                retention::Policy::default(),
                UnixMillis::now(),
            )
            .map(|_| ())
        })
        .unwrap();

    // The run budget is the run's artifact bytes whoever produced them: a lowered budget refuses a
    // run-level attachment exactly as it refuses a job's.
    d.objects.set_deployment(Limits {
        run_artifact_bytes: bytes.len() as u64 - 1,
        ..d.objects.deployment()
    });
    let (status, refused) = call(&d, "POST", &path, Some(&body), &d.admin);
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["code"], "quota_exceeded");
    d.objects.set_deployment(Limits::default());
    let (status, created) = call(&d, "POST", &path, Some(&body), &d.admin);
    assert_eq!(status, 201, "{created}");
}

#[test]
fn an_attachment_the_manifest_could_not_hold_is_refused_before_it_is_written() {
    let d = deployment();
    let run = d.run();
    let digest = d.upload(b"bytes");
    let path = format!("/api/v1/runs/{run}/artifacts");
    let cases = [
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{ "path": "", "digest": digest, "len": 5 }],
            }),
            "an empty entry path",
        ),
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{ "path": "out.txt", "digest": "sha256:zz", "len": 5 }],
            }),
            "a malformed digest",
        ),
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{
                    "path": "out.txt",
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "len": 5,
                }],
            }),
            "an object the tenant does not hold",
        ),
        (
            serde_json::json!({ "name": "reports", "entries": [] }),
            "no entries",
        ),
        (
            serde_json::json!({
                "name": "",
                "entries": [{ "path": "out.txt", "digest": digest, "len": 5 }],
            }),
            "an empty name",
        ),
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{ "path": "out.txt", "digest": digest, "len": 5 }],
                "class": "nonexistent",
            }),
            "a class the deployment does not define",
        ),
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{ "path": "out.txt", "digest": digest, "len": 5 }],
                "retain_secs": 0,
            }),
            "a retention below the floor",
        ),
        (
            serde_json::json!({
                "name": "reports",
                "entries": [{ "path": "out.txt", "digest": digest, "len": 5 }],
                "retain_secs": 400 * 86_400,
            }),
            "a retention past the ceiling",
        ),
    ];
    for (body, why) in cases {
        let (status, refused) = call(&d, "POST", &path, Some(&body), &d.admin);
        assert_eq!(status, 400, "{why}: {refused}");
        assert_eq!(refused["code"], "invalid_request", "{why}");
    }
    let (status, listed) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts"),
        None,
        &d.admin,
    );
    assert_eq!(status, 200);
    assert!(
        listed["artifacts"].as_array().unwrap().is_empty(),
        "nothing was recorded: {listed}"
    );
}

#[test]
fn a_runner_mode_artifact_is_recorded_under_its_github_run_and_job() {
    let d = deployment();
    let digest = d.upload(b"junit xml");
    let (github_run, first, second) = (9001, 11, 12);
    let record = |job: u64, name: &str| {
        call(
            &d,
            "POST",
            &format!(
                "/api/v1/tenants/acme/repos/app/runner-runs/{github_run}/jobs/{job}/artifacts"
            ),
            Some(&d.attach_body(name, &digest, 9)),
            &d.admin,
        )
    };
    let (status, created) = record(first, "coverage");
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["origin"], "runner");
    assert_eq!(created["github_run"], github_run);
    assert_eq!(created["github_job"], first);
    assert_eq!(created["job"], serde_json::Value::Null);
    assert_eq!(created["run"], serde_json::Value::Null);
    assert_eq!(created["repo"], d.repo.to_string());
    assert!(
        created["uploader"].is_null(),
        "a GitHub job attaches nothing"
    );
    let (status, second_row) = record(second, "results");
    assert_eq!(status, 201, "{second_row}");

    let list = format!("/api/v1/tenants/acme/repos/app/runner-runs/{github_run}/artifacts");
    let (status, listed) = call(&d, "GET", &list, None, &d.admin);
    assert_eq!(status, 200, "{listed}");
    let rows = listed["artifacts"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row["github_job"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![first, second],
        "a later job of the run reads them in job order"
    );
    assert_eq!(rows[0]["name"], "coverage");

    let art = second_row["id"].as_str().unwrap();
    let (status, detail) = call(
        &d,
        "GET",
        &format!("/api/v1/tenants/acme/repos/app/runner-runs/{github_run}/artifacts/{art}"),
        None,
        &d.admin,
    );
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["manifest"]["entries"][0]["path"], "reports/out.txt");

    // Another GitHub run, another repository and a reader without the scope see nothing of it.
    let (status, other_run) = call(
        &d,
        "GET",
        &format!(
            "/api/v1/tenants/acme/repos/app/runner-runs/{}/artifacts",
            github_run + 1
        ),
        None,
        &d.admin,
    );
    assert_eq!(status, 200);
    assert!(other_run["artifacts"].as_array().unwrap().is_empty());
    let (status, _) = call(
        &d,
        "GET",
        &format!(
            "/api/v1/tenants/acme/repos/app/runner-runs/{}/artifacts/{art}",
            github_run + 1
        ),
        None,
        &d.admin,
    );
    assert_eq!(status, 404, "an artifact of another GitHub run");
    let (status, _) = call(
        &d,
        "GET",
        &format!("/api/v1/tenants/acme/repos/none/runner-runs/{github_run}/artifacts"),
        None,
        &d.admin,
    );
    assert_eq!(status, 404, "an unbound repository");
    let (status, refused) = call(&d, "GET", &list, None, &d.runner);
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["details"]["scope"], "artifacts:read");
    let (status, refused) = call(
        &d,
        "POST",
        &format!("/api/v1/tenants/acme/repos/app/runner-runs/{github_run}/jobs/13/artifacts"),
        Some(&d.attach_body("later", &digest, 9)),
        &d.runner,
    );
    assert_eq!(
        status, 404,
        "a reader of the repository cannot record its runner-mode artifacts: {refused}"
    );
}

/// A run-level artifact belongs to the run and tenant it names: another organization's member, who holds
/// everything its own tenant grants, gets `not_found` for it, and so does its own tenant naming another run.
#[test]
fn a_run_level_artifact_is_scoped_by_its_run_and_its_tenant() {
    let d = deployment();
    let run = d.run();
    let other_run = d.run();
    let bytes = b"attached once, scoped to one run";
    let digest = d.upload(bytes);
    let body = d.attach_body("reports", &digest, bytes.len());
    let (status, created) = call(
        &d,
        "POST",
        &format!("/api/v1/runs/{run}/artifacts"),
        Some(&body),
        &d.admin,
    );
    assert_eq!(status, 201, "{created}");
    let art = created["id"].as_str().unwrap().to_owned();

    for (who, credential) in [("another tenant", &d.foreign), ("another run", &d.admin)] {
        let named = if who == "another run" { other_run } else { run };
        for path in [
            format!("/api/v1/runs/{named}/artifacts/{art}"),
            format!("/api/v1/runs/{named}/artifacts/{art}/archive?format=tar"),
        ] {
            let (status, refused) = call(&d, "GET", &path, None, credential);
            assert_eq!(status, 404, "{who} on {path}: {refused}");
            assert_eq!(refused["code"], "not_found", "{who} on {path}");
        }
    }
    // And the attachment is not reachable through an upload session's object route either.
    let (status, refused) = call(
        &d,
        "GET",
        &format!("/api/v1/tenants/acme/objects/{digest}"),
        None,
        &d.foreign,
    );
    assert_eq!(status, 404, "{refused}");

    let (status, detail) = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{run}/artifacts/{art}"),
        None,
        &d.admin,
    );
    assert_eq!(status, 200, "its own run still reads it: {detail}");
}
