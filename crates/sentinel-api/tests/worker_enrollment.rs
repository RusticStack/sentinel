//! Q11: platform administrators issue worker enrollments and download the worker-only bootstrap script.

use std::sync::Arc;

use sentinel_api::{Pin, TailcatRelease, WorkerBootstrap, WorkerBootstrapSettings};
use sentinel_core::{
    PoolId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    objects::Objects,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const X86: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARM: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HELPER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const FINGERPRINT: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const TAILCAT_ADDRESS: &str = "tcQ2w3E4r5T6y7U8i9O0p1A2s3D4f5G6h7J8";
const NODE_KEY: [u8; 32] = [7; 32];

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    pool: PoolId,
    root: UserId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn bootstrap(dir: &std::path::Path, with_tailcat: bool) -> Arc<WorkerBootstrap> {
    let address_file = dir.join("address");
    std::fs::write(&address_file, format!("{TAILCAT_ADDRESS}\n")).unwrap();
    Arc::new(
        WorkerBootstrap::new(WorkerBootstrapSettings {
            controller: "10.0.0.5:7443".parse().unwrap(),
            fingerprint: FINGERPRINT.into(),
            release_url: "https://releases.example.test/sentinel/0.1.0".into(),
            release_sums: format!(
                "{X86}  sentinel-0.1.0-x86_64-linux-worker.tar.gz\n\
                 {ARM}  sentinel-0.1.0-aarch64-linux-worker.tar.gz\n"
            ),
            tailcat: with_tailcat.then(|| TailcatRelease {
                version: "0.6.0".into(),
                x86_64: Some(Pin {
                    url: "https://releases.example.test/tailcat/0.6.0/tailcat-linux-amd64".into(),
                    sha256: HELPER.into(),
                }),
                aarch64: None,
                derpmap_url: None,
                region: None,
            }),
            tailcat_address_file: with_tailcat.then_some(address_file),
        })
        .unwrap(),
    )
}

fn deployment(configured: Option<bool>) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        PASSWORD.as_bytes(),
        UnixMillis::now(),
    )
    .unwrap();
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Shared,
                UnixMillis::now(),
            )
        })
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
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: Some(key),
            sessions: local_auth::Policy::default(),
            github_webhook_secret: None,
            intake: None,
            public_url: None,
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        },
        sentinel_api::Options {
            worker_bootstrap: configured.map(|tailcat| bootstrap(dir.path(), tailcat)),
            ..sentinel_api::Options::default()
        },
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Deployment {
        _dir: dir,
        store,
        _controller: controller,
        server: Some(server),
        base,
        pool,
        root,
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn send(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> Reply {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let url = format!("{}{path}", d.base);
    let response = match method {
        "GET" | "DELETE" => {
            let mut request = if method == "GET" {
                agent.get(&url).force_send_body()
            } else {
                agent.delete(&url).force_send_body()
            };
            for (k, v) in headers {
                request = request.header(*k, *v);
            }
            request.send_empty()
        }
        _ => {
            let mut request = if method == "PUT" {
                agent.put(&url)
            } else {
                agent.post(&url)
            }
            .header("content-type", "application/json");
            for (k, v) in headers {
                request = request.header(*k, *v);
            }
            request.send(
                body.map_or_else(|| "{}".to_owned(), Value::to_string)
                    .as_bytes(),
            )
        }
    }
    .unwrap();
    let status = response.status().as_u16();
    let headers = response
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
    Reply {
        status,
        headers,
        text,
    }
}

struct Session {
    cookie: String,
    csrf: String,
}

impl Session {
    fn headers(&self) -> [(&str, &str); 2] {
        [("cookie", &self.cookie), ("x-sentinel-csrf", &self.csrf)]
    }
}

fn sign_in(d: &Deployment) -> Session {
    let reply = send(
        d,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": "root", "password": PASSWORD })),
        &[],
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    Session {
        cookie: reply
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        csrf: reply.json()["csrf"].as_str().unwrap().to_owned(),
    }
}

fn step_up(d: &Deployment, session: &Session) {
    let reply = send(
        d,
        "POST",
        "/api/v1/step-up",
        Some(&json!({ "method": "password", "code": PASSWORD })),
        &session.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
}

fn administrator(d: &Deployment) -> Session {
    let session = sign_in(d);
    step_up(d, &session);
    session
}

fn issue(d: &Deployment, session: &Session, body: Value) -> Reply {
    send(
        d,
        "POST",
        "/api/v1/admin/worker-enrollments",
        Some(&body),
        &session.headers(),
    )
}

fn audit_events(d: &Deployment, session: &Session) -> Vec<String> {
    let reply = send(
        d,
        "GET",
        "/api/v1/admin/audit?limit=100",
        None,
        &session.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    reply.json()["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap().to_owned())
        .collect()
}

fn negotiated() -> Negotiated {
    Negotiated {
        protocol: ProtocolVersion(1),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
    }
}

fn redeem(d: &Deployment, secret: &str, node_key: Option<[u8; 32]>) -> bool {
    let secret = sentinel_auth::token::parse(secret).expect("a well-formed secret");
    d.store
        .writer()
        .write(move |tx| {
            workers::redeem_bound(
                tx,
                &secret,
                Presentation {
                    worker: sentinel_core::WorkerId::new(),
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "builder-1",
                    negotiated: negotiated(),
                },
                node_key,
                UnixMillis::now(),
            )
            .map(|w| w.is_some())
        })
        .unwrap()
}

#[test]
fn issuing_needs_a_fresh_step_up_and_the_secret_is_returned_once() {
    let d = deployment(Some(true));
    let body = json!({
        "pool": d.pool.to_string(),
        "cpu_millis": 4000,
        "memory_bytes": 8_589_934_592u64,
        "priority": 5,
    });
    assert_eq!(
        send(
            &d,
            "POST",
            "/api/v1/admin/worker-enrollments",
            Some(&body),
            &[]
        )
        .status,
        401
    );

    let session = sign_in(&d);
    let refused = issue(&d, &session, body.clone());
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["details"]["step_up"], true);

    // A bearer token never steps up: only a browser session can issue a machine's way into the fleet.
    let granted = tokens::provision(
        &d.store,
        Grant::new(d.root, "ops", sentinel_core::auth::Permissions::ALL),
        UnixMillis::now(),
    )
    .unwrap();
    let bearer = format!("Bearer {}", sentinel_auth::token::format(&granted.secret));
    let by_token = send(
        &d,
        "POST",
        "/api/v1/admin/worker-enrollments",
        Some(&body),
        &[("authorization", &bearer)],
    );
    assert_eq!(by_token.status, 403, "{}", by_token.text);

    step_up(&d, &session);
    let issued = issue(&d, &session, body);
    assert_eq!(issued.status, 201, "{}", issued.text);
    assert_eq!(issued.header("cache-control"), Some("no-store"));
    let issued = issued.json();
    let secret = issued["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("sntl_") && secret.len() == "sntl_".len() + 64);
    assert_eq!(issued["transport"], "tailcat");
    assert_eq!(issued["tailcat_address"], TAILCAT_ADDRESS);
    assert_eq!(issued["release_version"], "0.1.0");
    assert_eq!(issued["host"]["cpu_millis"], 4000);
    assert_eq!(issued["host"]["priority"], 5);
    assert_eq!(issued["host"]["disk_bytes"], Value::Null);
    let id = issued["id"].as_str().unwrap();
    assert_eq!(
        issued["bootstrap_path"],
        format!("/api/v1/admin/worker-enrollments/{id}/bootstrap.sh")
    );

    // Nothing the controller serves afterwards repeats the secret or the Tailcat address.
    let state = send(
        &d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}"),
        None,
        &session.headers(),
    );
    assert_eq!(state.status, 200, "{}", state.text);
    assert_eq!(state.json()["state"], "pending");
    assert_eq!(state.json()["transport"], "tailcat");
    assert_eq!(state.json()["host"]["memory_bytes"], 8_589_934_592u64);
    let audit = send(
        &d,
        "GET",
        "/api/v1/admin/audit?limit=100",
        None,
        &session.headers(),
    );
    for served in [&state.text, &audit.text] {
        assert!(!served.contains(&secret[5..]) && !served.contains(TAILCAT_ADDRESS));
    }
    assert!(audit_events(&d, &session).contains(&"worker-enrollment-issued".to_owned()));

    // The issued secret is exactly the pool-bound, single-use enrollment of the store layer: a Tailcat one
    // refuses a worker that presents no node key, then binds both halves of the identity at once.
    assert!(!redeem(&d, &secret, None));
    assert!(redeem(&d, &secret, Some(NODE_KEY)));
    assert!(!redeem(&d, &secret, Some([8; 32])));
    let spent = send(
        &d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}"),
        None,
        &session.headers(),
    );
    assert_eq!(spent.json()["state"], "redeemed");
}

#[test]
fn a_direct_enrollment_has_no_address_and_refuses_a_node_key() {
    let d = deployment(Some(false));
    let session = administrator(&d);
    let issued = issue(
        &d,
        &session,
        json!({ "pool": d.pool.to_string(), "transport": "direct", "lifetime_ms": 600_000 }),
    );
    assert_eq!(issued.status, 201, "{}", issued.text);
    let issued = issued.json();
    assert_eq!(issued["transport"], "direct");
    assert_eq!(issued["tailcat_address"], Value::Null);
    let secret = issued["secret"].as_str().unwrap();
    assert!(!redeem(&d, secret, Some(NODE_KEY)));
    assert!(redeem(&d, secret, None));
}

#[test]
fn issuing_refuses_what_cannot_work_with_a_stated_reason() {
    let d = deployment(Some(false));
    let session = administrator(&d);
    let pool = d.pool.to_string();
    let tailcat = issue(&d, &session, json!({ "pool": pool }));
    assert_eq!(tailcat.status, 409, "{}", tailcat.text);
    assert!(tailcat.text.contains("no Tailcat helper"));
    for (body, status) in [
        (json!({ "pool": pool, "transport": "wireguard" }), 400),
        (
            json!({ "pool": pool, "transport": "direct", "lifetime_ms": 0 }),
            400,
        ),
        (
            json!({ "pool": pool, "transport": "direct", "lifetime_ms": 90_000_000 }),
            400,
        ),
        (
            json!({ "pool": pool, "transport": "direct", "cpu_millis": 0 }),
            400,
        ),
        (
            json!({ "pool": pool, "transport": "direct", "priority": 101 }),
            400,
        ),
        (
            json!({ "pool": pool, "transport": "direct", "secret": "x" }),
            400,
        ),
        (json!({ "pool": "not-a-pool", "transport": "direct" }), 400),
        (
            json!({ "pool": PoolId::new().to_string(), "transport": "direct" }),
            404,
        ),
    ] {
        let reply = issue(&d, &session, body.clone());
        assert_eq!(reply.status, status, "{body}: {}", reply.text);
    }

    // A Tailcat enrollment waits for the controller's own address instead of handing out a script that cannot connect.
    let d = deployment(Some(true));
    let session = administrator(&d);
    std::fs::remove_file(d._dir.path().join("address")).unwrap();
    let reply = issue(&d, &session, json!({ "pool": d.pool.to_string() }));
    assert_eq!(reply.status, 409, "{}", reply.text);
    assert!(reply.text.contains("Tailcat address"));

    let d = deployment(None);
    let session = administrator(&d);
    let reply = issue(&d, &session, json!({ "pool": d.pool.to_string() }));
    assert_eq!(reply.status, 409, "{}", reply.text);
    assert!(reply.text.contains("[worker_bootstrap]"));
    let path = format!("/api/v1/admin/worker-enrollments/{}/bootstrap.sh", "tok_x");
    assert_eq!(send(&d, "GET", &path, None, &session.headers()).status, 409);
}

fn script_of(d: &Deployment, session: &Session, id: &str) -> Reply {
    send(
        d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}/bootstrap.sh"),
        None,
        &session.headers(),
    )
}

#[test]
fn the_script_is_a_secret_free_attachment_served_only_for_a_pending_enrollment() {
    let d = deployment(Some(true));
    let session = administrator(&d);
    let issued = issue(&d, &session, json!({ "pool": d.pool.to_string() })).json();
    let (id, secret) = (
        issued["id"].as_str().unwrap().to_owned(),
        issued["secret"].as_str().unwrap().to_owned(),
    );

    let anonymous = send(
        &d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}/bootstrap.sh"),
        None,
        &[],
    );
    assert_eq!(anonymous.status, 401);

    let script = script_of(&d, &session, &id);
    assert_eq!(script.status, 200, "{}", script.text);
    assert_eq!(
        script.header("content-type"),
        Some("text/x-shellscript; charset=utf-8")
    );
    assert!(
        script
            .header("content-disposition")
            .is_some_and(|v| v.starts_with("attachment;"))
    );
    assert_eq!(script.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(script.header("cache-control"), Some("no-store"));
    let text = &script.text;
    assert!(text.starts_with("#!/bin/sh\n"));
    for pinned in [
        "TRANSPORT='tailcat'",
        &format!("CONTROLLER_FINGERPRINT='{FINGERPRINT}'"),
        &format!("WORKER_SHA256_X86_64='{X86}'"),
        &format!("WORKER_SHA256_AARCH64='{ARM}'"),
        &format!("TAILCAT_SHA256_X86_64='{HELPER}'"),
        "WORKER_URL_X86_64='https://releases.example.test/sentinel/0.1.0/sentinel-0.1.0-x86_64-linux-worker.tar.gz'",
    ] {
        assert!(text.contains(pinned), "missing {pinned}");
    }
    // No credential reaches the script: not the enrollment secret, not the controller's Tailcat address.
    assert!(!text.contains(&secret[5..]) && !text.contains(TAILCAT_ADDRESS));
    // Nothing in it hands a download to a shell through a pipe.
    assert!(
        !text.lines().any(|l| l
            .split('|')
            .skip(1)
            .any(|seg| matches!(seg.split_whitespace().next(), Some("sh" | "bash" | "dash")))),
        "a line pipes into a shell"
    );

    script_of(&d, &session, &id);
    let downloads = audit_events(&d, &session)
        .iter()
        .filter(|e| *e == "worker-bootstrap-downloaded")
        .count();
    assert_eq!(downloads, 2);

    // Once spent, the enrollment gets no further script and no audit row for the refusal's request.
    assert!(redeem(&d, &secret, Some(NODE_KEY)));
    let spent = script_of(&d, &session, &id);
    assert_eq!(spent.status, 409, "{}", spent.text);
    let after = audit_events(&d, &session)
        .iter()
        .filter(|e| *e == "worker-bootstrap-downloaded")
        .count();
    assert_eq!(after, 2);
}

#[test]
fn withdrawing_closes_an_unspent_enrollment_and_its_script() {
    let d = deployment(Some(false));
    let session = administrator(&d);
    let issued = issue(
        &d,
        &session,
        json!({ "pool": d.pool.to_string(), "transport": "direct" }),
    )
    .json();
    let (id, secret) = (
        issued["id"].as_str().unwrap().to_owned(),
        issued["secret"].as_str().unwrap().to_owned(),
    );
    let path = format!("/api/v1/admin/worker-enrollments/{id}");
    assert_eq!(send(&d, "DELETE", &path, None, &[]).status, 401);
    assert_eq!(
        send(&d, "DELETE", &path, None, &session.headers()).status,
        204
    );
    assert_eq!(
        send(&d, "DELETE", &path, None, &session.headers()).status,
        404
    );
    let state = send(&d, "GET", &path, None, &session.headers());
    assert_eq!(state.json()["state"], "revoked");
    assert_eq!(script_of(&d, &session, &id).status, 409);
    assert!(!redeem(&d, &secret, None));
    assert!(audit_events(&d, &session).contains(&"worker-enrollment-revoked".to_owned()));
    assert_eq!(
        send(
            &d,
            "GET",
            "/api/v1/admin/worker-enrollments/tok_00000000-0000-4000-8000-000000000000",
            None,
            &session.headers()
        )
        .status,
        404
    );
}

#[test]
fn issuing_and_downloading_are_rate_limited_per_administrator() {
    let d = deployment(Some(false));
    let session = administrator(&d);
    let body = json!({ "pool": d.pool.to_string(), "transport": "direct" });
    let mut first = None;
    let mut statuses = Vec::new();
    for _ in 0..8 {
        let reply = issue(&d, &session, body.clone());
        if first.is_none() {
            first = Some(reply.json()["id"].as_str().unwrap().to_owned());
        }
        statuses.push(reply.status);
    }
    assert_eq!(&statuses[..5], &[201; 5], "{statuses:?}");
    assert!(statuses[5..].iter().all(|s| *s == 429), "{statuses:?}");
    let limited = issue(&d, &session, body);
    assert_eq!(limited.json()["details"]["retry_after_ms"], 6_000);

    let id = first.unwrap();
    let mut codes = Vec::new();
    for _ in 0..14 {
        codes.push(script_of(&d, &session, &id).status);
    }
    assert_eq!(&codes[..10], &[200; 10], "{codes:?}");
    assert!(codes[10..].iter().all(|c| *c == 429), "{codes:?}");
}

fn enroll_worker(d: &Deployment, secret: &str) -> sentinel_core::WorkerId {
    let secret = sentinel_auth::token::parse(secret).expect("a well-formed secret");
    let worker = sentinel_core::WorkerId::new();
    d.store
        .writer()
        .write(move |tx| {
            workers::redeem_bound(
                tx,
                &secret,
                Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "builder-1",
                    negotiated: negotiated(),
                },
                None,
                UnixMillis::now(),
            )
            .map(|_| ())
        })
        .unwrap();
    d.store
        .writer()
        .write(move |tx| {
            sentinel_store::dispatch::report_capacity(
                tx,
                worker,
                sentinel_store::dispatch::Capacity {
                    cpu_millis: 16_000,
                    memory_bytes: 64 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    worker
}

#[test]
fn an_administrator_reads_and_replaces_a_workers_host_policy_and_requests_its_uninstall() {
    let d = deployment(Some(false));
    let session = administrator(&d);
    let issued = issue(
        &d,
        &session,
        json!({ "pool": d.pool.to_string(), "transport": "direct", "cpu_millis": 4000, "priority": 5 }),
    );
    assert_eq!(issued.status, 201, "{}", issued.text);
    let worker = enroll_worker(&d, issued.json()["secret"].as_str().unwrap());
    let path = format!("/api/v1/admin/workers/{worker}/policy");

    // Approved, reported and effective are three different facts: the host claims 16 cores, the
    // controller approved 4, and 4 is what it offers.
    let shown = send(&d, "GET", &path, None, &session.headers());
    assert_eq!(shown.status, 200, "{}", shown.text);
    let body = shown.json();
    assert_eq!(body["approved"]["cpu_millis"], 4000);
    assert_eq!(body["approved"]["priority"], 5);
    assert_eq!(body["reported"]["cpu_millis"], 16_000);
    assert_eq!(body["effective"]["cpu_millis"], 4000);
    assert_eq!(body["effective"]["memory_bytes"], 64u64 << 30);
    // Nothing is running, so nothing is reserved and the host is within its cap.
    assert_eq!(body["reserved"]["cpu_millis"], 0);
    assert_eq!(body["over_cap"]["over"], false);
    assert_eq!(body["over_cap"]["cpu_millis"], 0);

    // The placement order is readable by platform administrators only.
    let order = send(
        &d,
        "GET",
        "/api/v1/admin/placement",
        None,
        &session.headers(),
    );
    assert_eq!(order.status, 200, "{}", order.text);
    assert_eq!(order.json()["order"], "fastest");
    assert_eq!(order.json()["workers"], json!([]));
    assert_eq!(
        send(&d, "GET", "/api/v1/admin/placement", None, &[]).status,
        401
    );

    // Replacing the policy needs a fresh step-up and platform administration.
    let unsure = sign_in(&d);
    let refused = send(
        &d,
        "PUT",
        &path,
        Some(&json!({ "cpu_millis": 8000 })),
        &unsure.headers(),
    );
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["details"]["step_up"], true);
    assert_eq!(
        send(&d, "PUT", &path, Some(&json!({ "cpu_millis": 8000 })), &[]).status,
        401
    );
    assert_eq!(
        send(&d, "GET", &path, None, &unsure.headers()).json()["approved"]["cpu_millis"],
        4000,
        "a refused change changes nothing"
    );

    let replaced = send(
        &d,
        "PUT",
        &path,
        Some(&json!({ "cpu_millis": 8000, "memory_bytes": 1u64 << 30, "priority": -20 })),
        &session.headers(),
    );
    assert_eq!(replaced.status, 200, "{}", replaced.text);
    let body = replaced.json();
    assert_eq!(body["approved"]["cpu_millis"], 8000);
    assert_eq!(body["approved"]["disk_bytes"], Value::Null);
    assert_eq!(body["approved"]["priority"], -20);
    assert_eq!(
        body["effective"]["cpu_millis"], 8000,
        "a raise applies at once"
    );
    assert_eq!(
        body["effective"]["memory_bytes"],
        1u64 << 30,
        "a reduction too"
    );
    assert!(audit_events(&d, &session).contains(&"worker-policy-changed".to_owned()));

    for bad in [
        json!({ "priority": 101 }),
        json!({ "cpu_millis": 0 }),
        json!({ "cpu_millis": 1, "tenant_priority": 3 }),
    ] {
        let rejected = send(&d, "PUT", &path, Some(&bad), &session.headers());
        assert_eq!(rejected.status, 400, "{bad}: {}", rejected.text);
    }
    let unknown = format!(
        "/api/v1/admin/workers/{}/policy",
        sentinel_core::WorkerId::new()
    );
    assert_eq!(
        send(&d, "GET", &unknown, None, &session.headers()).status,
        404
    );
    assert_eq!(
        send(&d, "PUT", &unknown, Some(&json!({})), &session.headers()).status,
        404
    );

    // An uninstall request is accepted and audited; the controller settles it once the work has drained.
    let uninstall = format!("/api/v1/admin/workers/{worker}/uninstall");
    assert_eq!(
        send(&d, "POST", &uninstall, None, &unsure.headers()).status,
        403
    );
    let accepted = send(&d, "POST", &uninstall, None, &session.headers());
    assert_eq!(accepted.status, 202, "{}", accepted.text);
    assert_eq!(accepted.json()["uninstall"], "requested");
    assert!(audit_events(&d, &session).contains(&"worker-uninstall-requested".to_owned()));
    assert_eq!(
        send(
            &d,
            "POST",
            &format!(
                "/api/v1/admin/workers/{}/uninstall",
                sentinel_core::WorkerId::new()
            ),
            None,
            &session.headers()
        )
        .status,
        404
    );
}

/// A tenant administrator with the strongest token the store allows it.
fn tenant_administrator(d: &Deployment) -> String {
    let (root, tenant, user) = (d.root, TenantId::new(), UserId::new());
    let now = UnixMillis::now();
    d.store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, Permissions::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            provisioning::insert_human(tx, user, "tenant-admin", false, now)?;
            auth::set_membership(
                tx,
                admin,
                tenant,
                user,
                sentinel_core::auth::Role::TenantAdmin,
            )
        })
        .unwrap();
    // The store refuses a platform-scoped token for anyone but a super administrator, so the
    // strongest credential a tenant administrator can hold is every other permission.
    let strongest = Permissions::REPOSITORY.union(Permissions::TENANT_ADMIN);
    let granted = tokens::provision(&d.store, Grant::new(user, "tenant", strongest), now).unwrap();
    format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
}

#[test]
fn only_a_platform_administrator_reaches_any_enrollment_or_host_route() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let issued = issue(&d, &admin, json!({ "pool": d.pool.to_string() }));
    assert_eq!(issued.status, 201, "{}", issued.text);
    let issued = issued.json();
    let id = issued["id"].as_str().unwrap().to_owned();
    let worker = {
        let direct = issue(
            &d,
            &admin,
            json!({ "pool": d.pool.to_string(), "transport": "direct" }),
        );
        enroll_worker(&d, direct.json()["secret"].as_str().unwrap())
    };
    let tenant = tenant_administrator(&d);
    let bearer = [("authorization", tenant.as_str())];

    let routes = [
        ("POST", "/api/v1/admin/worker-enrollments".to_owned()),
        ("GET", "/api/v1/admin/worker-enrollments".to_owned()),
        ("GET", format!("/api/v1/admin/worker-enrollments/{id}")),
        ("DELETE", format!("/api/v1/admin/worker-enrollments/{id}")),
        (
            "GET",
            format!("/api/v1/admin/worker-enrollments/{id}/bootstrap.sh"),
        ),
        ("GET", "/api/v1/admin/workers".to_owned()),
        ("GET", format!("/api/v1/admin/workers/{worker}/policy")),
        ("PUT", format!("/api/v1/admin/workers/{worker}/policy")),
        ("POST", format!("/api/v1/admin/workers/{worker}/uninstall")),
        ("GET", "/api/v1/admin/placement".to_owned()),
    ];
    let body = json!({ "pool": d.pool.to_string() });
    for (method, path) in &routes {
        let anonymous = send(&d, method, path, Some(&body), &[]);
        assert_eq!(anonymous.status, 401, "{method} {path}: {}", anonymous.text);
        let refused = send(&d, method, path, Some(&body), &bearer);
        assert!(
            matches!(refused.status, 403 | 404),
            "{method} {path} reached a tenant administrator: {} {}",
            refused.status,
            refused.text
        );
        assert!(!refused.text.contains(&id));
    }

    // Nothing the refused calls attempted took effect.
    let after = send(
        &d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}"),
        None,
        &admin.headers(),
    );
    assert_eq!(after.json()["state"], "pending");
    let events = audit_events(&d, &admin);
    for forbidden in [
        "worker-enrollment-revoked",
        "worker-uninstall-requested",
        "worker-policy-changed",
        "worker-bootstrap-downloaded",
    ] {
        assert!(!events.contains(&forbidden.to_owned()), "{forbidden}");
    }
}

#[test]
fn listings_show_terms_and_host_policy_and_never_a_secret() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let first = issue(
        &d,
        &admin,
        json!({ "pool": d.pool.to_string(), "transport": "direct", "cpu_millis": 2000, "priority": 3 }),
    )
    .json();
    let second = issue(
        &d,
        &admin,
        json!({ "pool": d.pool.to_string(), "memory_bytes": 4_294_967_296u64 }),
    )
    .json();
    let (secret_a, secret_b) = (
        first["secret"].as_str().unwrap().to_owned(),
        second["secret"].as_str().unwrap().to_owned(),
    );
    let other = PoolId::new();
    d.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                other,
                "elsewhere",
                PoolKind::Shared,
                UnixMillis::now(),
            )
        })
        .unwrap();
    let third = issue(
        &d,
        &admin,
        json!({ "pool": other.to_string(), "transport": "direct" }),
    );
    assert_eq!(third.status, 201, "{}", third.text);

    let all = send(
        &d,
        "GET",
        "/api/v1/admin/worker-enrollments",
        None,
        &admin.headers(),
    );
    assert_eq!(all.status, 200, "{}", all.text);
    assert_eq!(all.json()["enrollments"].as_array().unwrap().len(), 3);
    let narrowed = send(
        &d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments?pool={}", d.pool),
        None,
        &admin.headers(),
    );
    let listed = narrowed.json();
    let rows = listed["enrollments"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["pool"] == d.pool.to_string()));
    assert!(rows.iter().all(|r| r["state"] == "pending"));
    let direct = rows.iter().find(|r| r["transport"] == "direct").unwrap();
    assert_eq!(direct["host"]["cpu_millis"], 2000);
    assert_eq!(direct["host"]["priority"], 3);
    for served in [&all.text, &narrowed.text] {
        assert!(!served.contains(&secret_a[5..]) && !served.contains(&secret_b[5..]));
        assert!(!served.contains(TAILCAT_ADDRESS));
    }

    // Paging: one at a time, newest first, with a cursor.
    let page = send(
        &d,
        "GET",
        "/api/v1/admin/worker-enrollments?limit=1",
        None,
        &admin.headers(),
    )
    .json();
    assert_eq!(page["enrollments"].as_array().unwrap().len(), 1);
    assert!(page["next_before"].is_i64() || page["next_before"].is_u64());
    for bad in ["pool=not-an-id", "before=-1", "before=x"] {
        let rejected = send(
            &d,
            "GET",
            &format!("/api/v1/admin/worker-enrollments?{bad}"),
            None,
            &admin.headers(),
        );
        assert_eq!(rejected.status, 400, "{bad}: {}", rejected.text);
    }

    // A redeemed enrollment is listed as such, and its worker is listed with its host policy.
    let worker = enroll_worker(&d, &secret_a);
    let states: Vec<String> = send(
        &d,
        "GET",
        "/api/v1/admin/worker-enrollments",
        None,
        &admin.headers(),
    )
    .json()["enrollments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["state"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(states.iter().filter(|s| *s == "redeemed").count(), 1);

    let hosts = send(&d, "GET", "/api/v1/admin/workers", None, &admin.headers());
    assert_eq!(hosts.status, 200, "{}", hosts.text);
    let hosts = hosts.json();
    let listed = hosts["workers"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    let host = &listed[0];
    assert_eq!(host["id"], worker.to_string());
    assert_eq!(host["pool"], d.pool.to_string());
    assert_eq!(host["transport"], "direct");
    assert_eq!(host["connected"], false);
    assert_eq!(host["uninstall_requested_ms"], Value::Null);
    assert_eq!(host["host"]["approved"]["cpu_millis"], 2000);
    assert_eq!(host["host"]["approved"]["priority"], 3);
    assert_eq!(host["host"]["reported"]["cpu_millis"], 16_000);
    assert_eq!(host["host"]["effective"]["cpu_millis"], 2000);
    let text = hosts.to_string();
    assert!(!text.contains(&secret_a[5..]));
    assert!(!text.contains("fingerprint") && !text.contains("node_key"));
    let elsewhere = send(
        &d,
        "GET",
        &format!("/api/v1/admin/workers?pool={other}"),
        None,
        &admin.headers(),
    );
    assert_eq!(elsewhere.json()["workers"], json!([]));

    // An uninstall request is visible on the listing.
    let uninstall = send(
        &d,
        "POST",
        &format!("/api/v1/admin/workers/{worker}/uninstall"),
        None,
        &admin.headers(),
    );
    assert_eq!(uninstall.status, 202, "{}", uninstall.text);
    let marked = send(&d, "GET", "/api/v1/admin/workers", None, &admin.headers()).json();
    assert!(marked["workers"][0]["uninstall_requested_ms"].is_number());
}
