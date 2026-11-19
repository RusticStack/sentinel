//! The migration preview route: a repository's `runs-on:` diff at a pinned commit, the native
//! plan on request, and the read path's own authorization.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use sentinel_core::{
    PoolId, RepoId, TenantId, UnixMillis, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind},
    local_auth,
    logs::LogStore,
    objects::Objects,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

const COMMIT: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";
const IMAGE: &str = "docker.io/library/ubuntu:24.04@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const PASSWORD: &str = "correct horse battery staple";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    server: Option<sentinel_api::Server>,
    _controller: Controller,
    base: String,
    token: String,
    outsider: String,
    unprivileged: String,
    tenant: TenantId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let (tenant, repo, other) = (TenantId::new(), RepoId::new(), TenantId::new());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        PASSWORD.as_bytes(),
        UnixMillis::now(),
    )
    .unwrap();
    let now = UnixMillis::now();
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
            auth::create_namespace(
                tx,
                admin,
                other,
                Namespace::parse("beta").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let token = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "preview",
            permissions: P::ALL,
            tenant: None,
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let outsider = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "outsider",
            permissions: P::ALL,
            tenant: Some(other),
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let unprivileged = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "unprivileged",
            permissions: P::RUN,
            tenant: None,
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let api_key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
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
        objects,
        controller: controller.handle(),
        secret_key: Some(api_key),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Deployment {
        _dir: dir,
        store,
        server: Some(server),
        _controller: controller,
        base,
        token: sentinel_auth::token::format(&token.secret),
        outsider: sentinel_auth::token::format(&outsider.secret),
        unprivileged: sentinel_auth::token::format(&unprivileged.secret),
        tenant,
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn fixture(name: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/workflows")
        .join(if name.starts_with("ci") || name.starts_with("mixed") {
            "native"
        } else {
            "valid"
        })
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn workflows(name: &str) -> Value {
    json!([{ "path": format!(".github/workflows/{name}"), "text": fixture(name) }])
}

fn body(name: &str, native: Option<Value>) -> Value {
    let mut body = json!({ "commit": COMMIT, "workflows": workflows(name) });
    if let Some(native) = native {
        body["native"] = native;
    }
    body
}

struct Answer {
    status: u16,
    body: Value,
}

fn post(d: &Deployment, slug: &str, repo: &str, body: &Value, auth: Option<&str>) -> Answer {
    let url = format!(
        "{}/api/v1/tenants/{slug}/repos/{repo}/migration/preview",
        d.base
    );
    let mut request = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
    .post(&url);
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = request
        .header("content-type", "application/json")
        .send(body.to_string())
        .unwrap();
    let status = response.status().as_u16();
    let mut response = response;
    let text = response.body_mut().read_to_string().unwrap();
    Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

fn call(d: &Deployment, body: &Value) -> Answer {
    post(d, "acme", "app", body, Some(&format!("Bearer {}", d.token)))
}

/// The workflow's body that differs, as `added` lines.
fn added_lines(diff: &str) -> Vec<&str> {
    diff.lines()
        .filter_map(|line| line.strip_prefix('+'))
        .filter(|line| !line.starts_with("++"))
        .collect()
}

#[test]
fn the_preview_answers_with_the_label_diff() {
    let d = deployment();
    let answer = call(&d, &body("ci.yml", None));
    assert_eq!(answer.status, 200, "{}", answer.body);
    let body = &answer.body;
    assert_eq!(body["schema"], "sentinel.migration-preview/1");
    assert_eq!(body["revision"], COMMIT);
    assert_eq!(body["label_table"], 1);
    assert_eq!(body["rule_table"], 1);
    // No worker is enrolled, so no class of this deployment can carry a Docker daemon.
    assert_eq!(body["docker"], "container_only");
    let workflow = &body["workflows"][0];
    assert_eq!(workflow["path"], ".github/workflows/ci.yml");
    assert_eq!(
        added_lines(workflow["diff"].as_str().unwrap()),
        vec![
            "    runs-on: sentinel-4vcpu-ubuntu-2404",
            "    runs-on: sentinel-4vcpu-ubuntu-2404"
        ]
    );
    assert_eq!(workflow["native"], Value::Null);
    assert_eq!(workflow["native_refused"], Value::Null);
    let change = &workflow["changes"][0];
    assert_eq!(change["job"], "build");
    assert_eq!(change["before"], "    runs-on: ubuntu-latest\n");
    assert_eq!(change["after"], "    runs-on: sentinel-4vcpu-ubuntu-2404\n");
}

#[test]
fn the_native_plan_is_answered_only_when_asked() {
    let d = deployment();
    let answer = call(
        &d,
        &body("ci.yml", Some(json!({ "images": { "linux": IMAGE } }))),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    let native = &answer.body["workflows"][0]["native"];
    assert!(!native.is_null(), "{}", answer.body);
    // One workflow is posted, so the pipeline belongs at the repository root.
    assert_eq!(native["path"], ".sentinel.yml");
    let text = native["text"].as_str().unwrap();
    sentinel_pipeline::compile_str(text).expect("a generated pipeline the compiler accepts");
    assert!(text.contains(IMAGE));
    assert_eq!(native["secrets"], json!(["CRATES_IO_TOKEN"]));
    let jobs = native["jobs"].as_array().unwrap();
    let build = jobs.iter().find(|job| job["github"] == "build").unwrap();
    assert_eq!(build["jobs"], json!(["build-stable", "build-1-99"]));
    assert_eq!(build["env"], json!(["CARGO_TERM_COLOR"]));
    assert_eq!(build["steps"][1]["kind"], "cache");
    assert_eq!(build["steps"][2]["kind"], "script");
    assert_eq!(build["steps"][2]["script"], "scripts/ci/ci/build/03.sh");
    assert!(text.contains("sh scripts/ci/ci/build/03.sh"));
    // A job whose platform has no image this preview was given stays on GitHub.
    let answer = call(
        &d,
        &body("mixed.yml", Some(json!({ "images": { "linux": IMAGE } }))),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    let native = &answer.body["workflows"][0]["native"];
    let jobs = native["jobs"].as_array().unwrap();
    let windows = jobs.iter().find(|job| job["github"] == "windows").unwrap();
    assert_eq!(windows["jobs"], json!([]));
    assert_eq!(windows["kept"].as_array().unwrap().len(), 1);
}

#[test]
fn a_job_needing_docker_follows_the_deployments_own_fleet() {
    let d = deployment();
    let answer = call(&d, &body("blacksmith-migrated.yml", None));
    assert_eq!(answer.status, 200, "{}", answer.body);
    let kept = answer.body["workflows"][0]["kept"].as_array().unwrap();
    let docker = kept.iter().find(|job| job["job"] == "docker").unwrap();
    assert!(
        docker["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("docker"))
    );

    // A worker that serves micro-VM guests changes the same preview: the class carries the
    // daemon, so the job moves instead of staying.
    let (store, tenant) = (Arc::clone(&d.store), d.tenant);
    let (pool, worker) = (PoolId::new(), WorkerId::new());
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(tx, Authority::HostLocal, pool, "kvm", PoolKind::Shared, now)?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &sentinel_auth::secret::Secret::parse(&text).unwrap(),
                Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "kvm",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED.union(Capabilities::ISOLATION_MICROVM),
                        arch: Arch::X86_64,
                    },
                },
                now,
            )
        })
        .unwrap();
    let answer = post(
        &d,
        "acme",
        "app",
        &body("blacksmith-migrated.yml", None),
        Some(&format!("Bearer {}", d.token)),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["docker"], "microvm_guests");
    let kept = answer.body["workflows"][0]["kept"].as_array().unwrap();
    assert!(kept.iter().all(|job| job["job"] != "docker"));
    let _ = tenant;
}

#[test]
fn the_read_path_authorizes_every_preview() {
    let d = deployment();
    let unauthenticated = post(&d, "acme", "app", &body("ci.yml", None), None);
    assert_eq!(unauthenticated.status, 401);
    // A credential that may dispatch runs but not read them cannot read the preview.
    let unprivileged = post(
        &d,
        "acme",
        "app",
        &body("ci.yml", None),
        Some(&format!("Bearer {}", d.unprivileged)),
    );
    assert_eq!(unprivileged.status, 403);
    // A principal bound to another tenant is answered as if the repository were not there.
    let outsider = post(
        &d,
        "acme",
        "app",
        &body("ci.yml", None),
        Some(&format!("Bearer {}", d.outsider)),
    );
    assert_eq!(outsider.status, 404, "{}", outsider.body);
    // The repository name is the one in this tenant.
    let missing = post(
        &d,
        "acme",
        "absent",
        &body("ci.yml", None),
        Some(&format!("Bearer {}", d.token)),
    );
    assert_eq!(missing.status, 404, "{}", missing.body);
}

#[test]
fn the_preview_refuses_inputs_it_cannot_read() {
    let d = deployment();
    let mut bad_commit = body("ci.yml", None);
    bad_commit["commit"] = json!("main");
    let answer = call(&d, &bad_commit);
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(
        answer.body["message"].as_str().unwrap().contains("commit"),
        "{}",
        answer.body
    );

    let mut outside = body("ci.yml", None);
    outside["workflows"][0]["path"] = json!("ci.yml");
    let answer = call(&d, &outside);
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(
        answer.body["message"]
            .as_str()
            .unwrap()
            .contains(".github/workflows"),
        "{}",
        answer.body
    );

    let huge = "x".repeat(sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES + 1);
    let oversized = json!({
        "commit": COMMIT,
        "workflows": [{ "path": ".github/workflows/big.yml", "text": huge }],
    });
    let answer = call(&d, &oversized);
    assert_eq!(answer.status, 413, "{}", answer.body);
    assert_eq!(
        answer.body["details"]["limit_bytes"],
        sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES
    );

    let mut unknown = body("ci.yml", None);
    unknown["workflows"][0]["script"] = json!("echo");
    let answer = call(&d, &unknown);
    assert_eq!(answer.status, 400, "{}", answer.body);
}
