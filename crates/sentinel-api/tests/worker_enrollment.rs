//! Q11: platform administrators issue worker enrollments and download the worker-only bootstrap script.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use sentinel_api::{Pin, TailcatRelease, WorkerBootstrap, WorkerBootstrapSettings};
use sentinel_core::{
    PoolId, TenantId, UnixMillis, UserId, WorkerId,
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
    enrolled_calls: Arc<AtomicUsize>,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn bootstrap(dir: &std::path::Path, with_tailcat: bool, https: bool) -> Arc<WorkerBootstrap> {
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
            api_url: https.then(|| "http://127.0.0.1:8080".into()),
        })
        .unwrap(),
    )
}

fn deployment(configured: Option<bool>) -> Deployment {
    deployment_with(configured, true)
}

/// `https` false leaves out `api_url`: workers then present the secret with the first link hello.
fn deployment_with(configured: Option<bool>, https: bool) -> Deployment {
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
    let enrolled_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&enrolled_calls);
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
            worker_bootstrap: configured.map(|tailcat| bootstrap(dir.path(), tailcat, https)),
            on_worker_enrolled: Some(sentinel_api::Notify(Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }))),
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
        enrolled_calls,
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
        ("GET", "/api/v1/admin/worker-bootstrap".to_owned()),
        (
            "POST",
            format!("/api/v1/admin/worker-enrollments/{id}/node-key"),
        ),
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
        "worker-node-key-authorized",
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
    // The deployment runs a real link controller, whose uninstall pass revokes a worker that holds no work
    // as soon as it ticks, and the listing shows live workers only: either the request is visible or it
    // has already settled and the worker is gone.
    match marked["workers"].as_array().and_then(|hosts| hosts.first()) {
        Some(host) => assert!(host["uninstall_requested_ms"].is_number(), "{marked}"),
        None => assert_eq!(marked["workers"], json!([]), "{marked}"),
    }
}

fn node_key_text(byte: u8) -> String {
    format!("nodekey:{}", format!("{byte:02x}").repeat(32))
}

fn redeem_body(secret: &str, worker: WorkerId, fingerprint: &str, node_key: Option<u8>) -> Value {
    let mut body = json!({
        "secret": secret,
        "worker": worker.to_string(),
        "name": "build-1",
        "fingerprint": fingerprint,
        "arch": "x86_64",
    });
    if let Some(byte) = node_key {
        body["node_key"] = json!(node_key_text(byte));
    }
    body
}

fn post_redeem(d: &Deployment, body: &Value) -> Reply {
    send(
        d,
        "POST",
        "/api/v1/worker-enrollments/redeem",
        Some(body),
        &[],
    )
}

fn issue_secret(d: &Deployment, admin: &Session, transport: &str) -> (String, String) {
    let issued = issue(
        d,
        admin,
        json!({
            "pool": d.pool.to_string(),
            "transport": transport,
            "cpu_millis": 2000,
            "priority": 3,
        }),
    );
    assert_eq!(issued.status, 201, "{}", issued.text);
    let body = issued.json();
    (
        body["secret"].as_str().unwrap().to_owned(),
        body["id"].as_str().unwrap().to_owned(),
    )
}

fn enrollment_state(d: &Deployment, admin: &Session, id: &str) -> String {
    let shown = send(
        d,
        "GET",
        &format!("/api/v1/admin/worker-enrollments/{id}"),
        None,
        &admin.headers(),
    );
    shown.json()["state"].as_str().unwrap().to_owned()
}

const PRINT_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PRINT_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn a_tailcat_machine_redeems_over_https_and_gets_the_controllers_trust_data() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (secret, id) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();

    let reply = post_redeem(&d, &redeem_body(&secret, worker, PRINT_A, Some(7)));
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let body = reply.json();
    assert_eq!(body["worker"], worker.to_string());
    assert_eq!(body["pool"], d.pool.to_string());
    assert_eq!(body["transport"], "tailcat");
    assert_eq!(body["controller"], "10.0.0.5:7443");
    assert_eq!(body["controller_fingerprint"], FINGERPRINT);
    assert_eq!(body["tailcat_address"], TAILCAT_ADDRESS);
    assert_eq!(body["host"]["cpu_millis"], 2000);
    assert_eq!(body["host"]["priority"], 3);
    assert_eq!(d.enrolled_calls.load(Ordering::SeqCst), 1);

    // One transaction bound both identities, and the secret is spent.
    let print = sentinel_auth::secret::Digest([0x11; 32]);
    let bound = d
        .store
        .read(|c| workers::authenticate_bound(c, &print, &[7u8; 32]))
        .unwrap();
    assert_eq!((bound.id, bound.pool), (worker, d.pool));
    assert!(
        d.store
            .read(|c| workers::pending_node_keys(c, UnixMillis::now()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(enrollment_state(&d, &admin, &id), "redeemed");
    let hosts = send(&d, "GET", "/api/v1/admin/workers", None, &admin.headers()).json();
    assert_eq!(hosts["workers"][0]["id"], worker.to_string());
    assert!(!hosts.to_string().contains(&secret[5..]));

    // The same machine repeating the call (its answer was lost) gets the same answer and no second worker.
    let again = post_redeem(&d, &redeem_body(&secret, worker, PRINT_A, Some(7)));
    assert_eq!(again.status, 200, "{}", again.text);
    assert_eq!(again.json()["worker"], worker.to_string());
    let hosts = send(&d, "GET", "/api/v1/admin/workers", None, &admin.headers()).json();
    assert_eq!(hosts["workers"].as_array().unwrap().len(), 1);
}

#[test]
fn a_direct_machine_gets_no_tailcat_address_and_the_transports_do_not_mix() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (direct, _) = issue_secret(&d, &admin, "direct");
    let refused = post_redeem(&d, &redeem_body(&direct, WorkerId::new(), PRINT_A, Some(7)));
    assert_eq!(refused.status, 403, "{}", refused.text);
    let reply = post_redeem(&d, &redeem_body(&direct, WorkerId::new(), PRINT_A, None));
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.json()["transport"], "direct");
    assert_eq!(reply.json()["tailcat_address"], Value::Null);
    assert_eq!(reply.json()["controller_fingerprint"], FINGERPRINT);

    let (tailcat, _) = issue_secret(&d, &admin, "tailcat");
    let missing = post_redeem(&d, &redeem_body(&tailcat, WorkerId::new(), PRINT_B, None));
    assert_eq!(missing.status, 403, "{}", missing.text);
}

#[test]
fn every_way_a_secret_can_fail_is_one_answer_that_names_no_case() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (spent, _) = issue_secret(&d, &admin, "direct");
    let first = post_redeem(&d, &redeem_body(&spent, WorkerId::new(), PRINT_A, None));
    assert_eq!(first.status, 200);
    let (withdrawn, id) = issue_secret(&d, &admin, "direct");
    let gone = send(
        &d,
        "DELETE",
        &format!("/api/v1/admin/worker-enrollments/{id}"),
        None,
        &admin.headers(),
    );
    assert_eq!(gone.status, 204);

    // Spent (by another machine), withdrawn and never issued: indistinguishable.
    let wrong = format!("sntl_{}", "ab".repeat(32));
    let answers: Vec<Reply> = [spent.as_str(), withdrawn.as_str(), wrong.as_str()]
        .into_iter()
        .map(|secret| post_redeem(&d, &redeem_body(secret, WorkerId::new(), PRINT_B, None)))
        .collect();
    for answer in &answers {
        assert_eq!(answer.status, 403, "{}", answer.text);
    }
    let messages: Vec<String> = answers
        .iter()
        .map(|a| a.json()["message"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        messages.windows(2).all(|pair| pair[0] == pair[1]),
        "{messages:?}"
    );
    assert_eq!(
        d.enrolled_calls.load(Ordering::SeqCst),
        1,
        "only the real redemption notified"
    );
}

#[test]
fn a_taken_identity_is_a_conflict_that_leaves_the_secret_for_the_real_machine() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (first, _) = issue_secret(&d, &admin, "direct");
    assert_eq!(
        post_redeem(&d, &redeem_body(&first, WorkerId::new(), PRINT_A, None)).status,
        200
    );
    let (second, id) = issue_secret(&d, &admin, "direct");
    let clash = post_redeem(&d, &redeem_body(&second, WorkerId::new(), PRINT_A, None));
    assert_eq!(clash.status, 409, "{}", clash.text);
    assert_eq!(enrollment_state(&d, &admin, &id), "pending");
    let real = post_redeem(&d, &redeem_body(&second, WorkerId::new(), PRINT_B, None));
    assert_eq!(real.status, 200, "{}", real.text);
}

#[test]
fn a_tailcat_redemption_waits_for_the_controllers_address_and_spends_nothing() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (secret, id) = issue_secret(&d, &admin, "tailcat");
    let address = d._dir.path().join("address");
    let saved = std::fs::read(&address).unwrap();
    std::fs::remove_file(&address).unwrap();
    let early = post_redeem(&d, &redeem_body(&secret, WorkerId::new(), PRINT_A, Some(7)));
    assert_eq!(early.status, 429, "{}", early.text);
    assert_eq!(enrollment_state(&d, &admin, &id), "pending");
    std::fs::write(&address, saved).unwrap();
    let ready = post_redeem(&d, &redeem_body(&secret, WorkerId::new(), PRINT_A, Some(7)));
    assert_eq!(ready.status, 200, "{}", ready.text);
}

#[test]
fn the_endpoint_is_off_without_an_api_url_and_takes_no_browser_or_oversized_requests() {
    let off = deployment(None);
    let reply = post_redeem(&off, &redeem_body("sntl_x", WorkerId::new(), PRINT_A, None));
    assert_eq!(reply.status, 404);

    let d = deployment(Some(false));
    let valid = redeem_body(
        &format!("sntl_{}", "cd".repeat(32)),
        WorkerId::new(),
        PRINT_A,
        None,
    );
    let browser = send(
        &d,
        "POST",
        "/api/v1/worker-enrollments/redeem",
        Some(&valid),
        &[("origin", "https://evil.example")],
    );
    assert_eq!(browser.status, 403, "{}", browser.text);
    let huge = json!({ "secret": "x".repeat(4096) });
    let oversized = post_redeem(&d, &huge);
    assert_eq!(oversized.status, 413, "{}", oversized.text);
    // A secret in the URL is never read: the body is the only place for it.
    let in_url = send(
        &d,
        "POST",
        &format!(
            "/api/v1/worker-enrollments/redeem?secret=sntl_{}",
            "ab".repeat(32)
        ),
        Some(&json!({ "worker": WorkerId::new().to_string() })),
        &[],
    );
    assert_eq!(in_url.status, 400, "{}", in_url.text);
}

#[test]
fn guessing_is_rate_limited_per_address_and_the_audit_trail_stays_small() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let mut statuses = Vec::new();
    // Each request is a new connection from the trusted loopback proxy, so the client address is the forwarded
    // one; without it every connection would be keyed alone.
    for _ in 0..8 {
        let secret = format!("sntl_{}", "ef".repeat(32));
        let body = redeem_body(&secret, WorkerId::new(), PRINT_A, None);
        statuses.push(
            send(
                &d,
                "POST",
                "/api/v1/worker-enrollments/redeem",
                Some(&body),
                &[("x-forwarded-for", "198.51.100.7")],
            )
            .status,
        );
    }
    assert!(statuses.iter().take(5).all(|s| *s == 403), "{statuses:?}");
    assert!(statuses.iter().skip(5).all(|s| *s == 429), "{statuses:?}");
    let refused = audit_events(&d, &admin)
        .iter()
        .filter(|e| *e == "worker-enrollment-refused")
        .count();
    assert_eq!(refused, 5);
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn options(d: &Deployment, session: &Session) -> Reply {
    send(
        d,
        "GET",
        "/api/v1/admin/worker-bootstrap",
        None,
        &session.headers(),
    )
}

#[test]
fn the_options_route_states_what_can_be_issued_and_the_digest_of_the_script_served() {
    let d = deployment(Some(true));
    assert_eq!(
        send(&d, "GET", "/api/v1/admin/worker-bootstrap", None, &[]).status,
        401
    );
    let tenant = tenant_administrator(&d);
    let refused = send(
        &d,
        "GET",
        "/api/v1/admin/worker-bootstrap",
        None,
        &[("authorization", tenant.as_str())],
    );
    assert!(matches!(refused.status, 403 | 404), "{}", refused.text);

    let admin = administrator(&d);
    let listed = options(&d, &admin);
    assert_eq!(listed.status, 200, "{}", listed.text);
    assert_eq!(listed.header("cache-control"), Some("no-store"));
    let o = listed.json();
    assert_eq!(o["configured"], true);
    assert_eq!(o["release_version"], "0.1.0");
    assert_eq!(o["redeem"], "https");
    assert_eq!(o["archs"], json!(["x86_64", "aarch64"]));
    assert_eq!(o["transports"]["direct"]["available"], true);
    assert_eq!(o["transports"]["tailcat"]["available"], true);
    assert_eq!(o["transports"]["tailcat"]["address_ready"], true);
    assert_eq!(o["transports"]["tailcat"]["helper_version"], "0.6.0");

    // The digest names the exact bytes the download serves, and the issue answer repeats it.
    for (transport, tailcat) in [("tailcat", true), ("direct", false)] {
        let issued = issue(
            &d,
            &admin,
            json!({ "pool": d.pool.to_string(), "transport": transport }),
        );
        assert_eq!(issued.status, 201, "{}", issued.text);
        let issued = issued.json();
        let served = script_of(&d, &admin, issued["id"].as_str().unwrap());
        assert_eq!(served.status, 200, "{}", served.text);
        let digest = sha256_hex(served.text.as_bytes());
        assert_eq!(o["transports"][transport]["bootstrap_sha256"], digest);
        assert_eq!(issued["bootstrap_sha256"], digest);
        assert_eq!(issued["redeem"], "https");
        assert_eq!(tailcat, issued["tailcat_address"].is_string());
        // Nothing the options carry is a credential, before or after an issue.
        let after = options(&d, &admin);
        assert_eq!(after.json(), o);
        let secret = issued["secret"].as_str().unwrap();
        assert!(!after.text.contains(&secret[5..]) && !after.text.contains(TAILCAT_ADDRESS));
    }
    assert_ne!(
        o["transports"]["direct"]["bootstrap_sha256"],
        o["transports"]["tailcat"]["bootstrap_sha256"]
    );

    // A controller that has not written its Tailcat address yet says so, before an administrator tries.
    std::fs::remove_file(d._dir.path().join("address")).unwrap();
    let waiting = options(&d, &admin).json();
    assert_eq!(waiting["transports"]["tailcat"]["available"], true);
    assert_eq!(waiting["transports"]["tailcat"]["address_ready"], false);
}

#[test]
fn the_options_say_when_enrollment_is_unconfigured_or_direct_only_or_redeems_over_the_link() {
    let off = deployment(None);
    let admin = administrator(&off);
    let answer = options(&off, &admin);
    assert_eq!(answer.status, 200, "{}", answer.text);
    assert_eq!(answer.json(), json!({ "configured": false }));

    let direct = deployment(Some(false));
    let admin = administrator(&direct);
    let o = options(&direct, &admin).json();
    assert_eq!(o["configured"], true);
    assert_eq!(o["transports"]["direct"]["available"], true);
    assert_eq!(o["transports"]["tailcat"]["available"], false);
    assert_eq!(o["transports"]["tailcat"]["address_ready"], false);
    assert_eq!(o["transports"]["tailcat"]["helper_version"], Value::Null);
    assert_eq!(o["transports"]["tailcat"]["bootstrap_sha256"], Value::Null);

    let link = deployment_with(Some(true), false);
    let admin = administrator(&link);
    assert_eq!(options(&link, &admin).json()["redeem"], "link");
    let issued = issue(&link, &admin, json!({ "pool": link.pool.to_string() }));
    assert_eq!(issued.json()["redeem"], "link");
}

fn node_key_path(enrollment: &str) -> String {
    format!("/api/v1/admin/worker-enrollments/{enrollment}/node-key")
}

fn post_node_key(
    d: &Deployment,
    headers: &[(&str, &str)],
    enrollment: &str,
    worker: WorkerId,
    key: u8,
) -> Reply {
    send(
        d,
        "POST",
        &node_key_path(enrollment),
        Some(&json!({ "worker": worker.to_string(), "node_key": node_key_text(key) })),
        headers,
    )
}

fn pending_keys(d: &Deployment) -> Vec<(WorkerId, [u8; 32])> {
    d.store
        .read(|c| workers::pending_node_keys(c, UnixMillis::now()))
        .unwrap()
}

#[test]
fn authorizing_a_node_key_needs_a_fresh_step_up_and_wakes_the_allow_list_pass() {
    let d = deployment_with(Some(true), false);
    let admin = administrator(&d);
    let (_, id) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();

    assert_eq!(post_node_key(&d, &[], &id, worker, 7).status, 401);
    // A browser session without a recent second factor is told to step up, and nothing is admitted.
    let cold = sign_in(&d);
    let asked = post_node_key(&d, &cold.headers(), &id, worker, 7);
    assert_eq!(asked.status, 403, "{}", asked.text);
    assert_eq!(asked.json()["details"]["step_up"], true);
    // A bearer token never steps up: admitting a key to the Tailcat network stays a browser or host-local act.
    let granted = tokens::provision(
        &d.store,
        Grant::new(d.root, "ops", Permissions::ALL),
        UnixMillis::now(),
    )
    .unwrap();
    let bearer = format!("Bearer {}", sentinel_auth::token::format(&granted.secret));
    let by_token = post_node_key(&d, &[("authorization", &bearer)], &id, worker, 7);
    assert_eq!(by_token.status, 403, "{}", by_token.text);
    assert!(pending_keys(&d).is_empty());
    assert_eq!(d.enrolled_calls.load(Ordering::SeqCst), 0);

    let done = post_node_key(&d, &admin.headers(), &id, worker, 7);
    assert_eq!(done.status, 204, "{}", done.text);
    assert_eq!(pending_keys(&d), vec![(worker, [7; 32])]);
    assert_eq!(d.enrolled_calls.load(Ordering::SeqCst), 1);
    let audit = send(
        &d,
        "GET",
        "/api/v1/admin/audit?limit=100",
        None,
        &admin.headers(),
    );
    assert!(audit_events(&d, &admin).contains(&"worker-node-key-authorized".to_owned()));
    assert!(!audit.text.contains(&"07".repeat(32)) && !audit.text.contains(&worker.to_string()));

    // The same pair again is the same answer.
    let again = post_node_key(&d, &admin.headers(), &id, worker, 7);
    assert_eq!(again.status, 204, "{}", again.text);
    assert_eq!(pending_keys(&d).len(), 1);
}

#[test]
fn a_node_key_conflict_is_a_plain_409_that_changes_nothing() {
    let d = deployment_with(Some(true), false);
    let admin = administrator(&d);
    let (_, first) = issue_secret(&d, &admin, "tailcat");
    let (_, second) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();
    assert_eq!(
        post_node_key(&d, &admin.headers(), &first, worker, 7).status,
        204
    );

    // A second, different pair for the same enrollment.
    let other = post_node_key(&d, &admin.headers(), &first, worker, 8);
    assert_eq!(other.status, 409, "{}", other.text);
    // A key another pending enrollment already holds.
    let taken = post_node_key(&d, &admin.headers(), &second, WorkerId::new(), 7);
    assert_eq!(taken.status, 409, "{}", taken.text);
    assert_eq!(pending_keys(&d), vec![(worker, [7; 32])]);
}

#[test]
fn a_node_key_is_refused_for_what_cannot_take_one() {
    let d = deployment_with(Some(true), false);
    let admin = administrator(&d);
    let (_, direct) = issue_secret(&d, &admin, "direct");
    let (_, spent) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();

    let on_direct = post_node_key(&d, &admin.headers(), &direct, worker, 7);
    assert_eq!(on_direct.status, 400, "{}", on_direct.text);
    let unknown = post_node_key(
        &d,
        &admin.headers(),
        "tok_00000000-0000-4000-8000-000000000000",
        worker,
        7,
    );
    assert_eq!(unknown.status, 404, "{}", unknown.text);
    // Withdrawn: a spent or expired enrollment takes the same path.
    let revoked: sentinel_core::TokenId = spent.parse().unwrap();
    d.store
        .writer()
        .write(move |tx| {
            workers::revoke_enrollment(tx, Authority::HostLocal, revoked, UnixMillis::now())
        })
        .unwrap();
    let late = post_node_key(&d, &admin.headers(), &spent, worker, 7);
    assert_eq!(late.status, 409, "{}", late.text);
    assert!(pending_keys(&d).is_empty());
    assert_eq!(d.enrolled_calls.load(Ordering::SeqCst), 0);

    // Malformed input is refused before anything is charged or written.
    let path = node_key_path(&spent);
    for body in [
        json!({ "worker": worker.to_string(), "node_key": "nodekey:abc" }),
        json!({ "worker": worker.to_string(), "node_key": "7".repeat(64) }),
        json!({ "worker": worker.to_string(), "node_key": node_key_text(7).to_uppercase() }),
        json!({ "worker": "not-a-worker", "node_key": node_key_text(7) }),
        json!({ "worker": worker.to_string() }),
        json!({ "worker": worker.to_string(), "node_key": node_key_text(7), "extra": 1 }),
    ] {
        let refused = send(&d, "POST", &path, Some(&body), &admin.headers());
        assert_eq!(refused.status, 400, "{body}: {}", refused.text);
    }
    assert!(pending_keys(&d).is_empty());
}

#[test]
fn node_key_authorizations_share_the_issuing_rate_limit() {
    let d = deployment_with(Some(true), false);
    let admin = administrator(&d);
    let (_, id) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();
    let statuses: Vec<u16> = (0..7)
        .map(|_| post_node_key(&d, &admin.headers(), &id, worker, 7).status)
        .collect();
    assert_eq!(&statuses[..4], &[204; 4], "{statuses:?}");
    assert!(statuses[4..].iter().all(|s| *s == 429), "{statuses:?}");
    let limited = post_node_key(&d, &admin.headers(), &id, worker, 7);
    assert_eq!(limited.json()["details"]["retry_after_ms"], 6_000);
}

#[test]
fn a_redemption_over_https_binds_only_the_authorized_worker_and_key() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let (secret, id) = issue_secret(&d, &admin, "tailcat");
    let worker = WorkerId::new();
    assert_eq!(
        post_node_key(&d, &admin.headers(), &id, worker, 7).status,
        204
    );

    // Another identifier, or another key, cannot spend a secret that was authorized for this pair.
    let stranger = post_redeem(&d, &redeem_body(&secret, WorkerId::new(), PRINT_A, Some(7)));
    assert_eq!(stranger.status, 403, "{}", stranger.text);
    let wrong_key = post_redeem(&d, &redeem_body(&secret, worker, PRINT_A, Some(8)));
    assert_eq!(wrong_key.status, 403, "{}", wrong_key.text);
    assert_eq!(enrollment_state(&d, &admin, &id), "pending");

    let reply = post_redeem(&d, &redeem_body(&secret, worker, PRINT_A, Some(7)));
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.json()["worker"], worker.to_string());
    assert_eq!(enrollment_state(&d, &admin, &id), "redeemed");
    // Spent: no further authorization, and the key leaves the pending list for the worker's own.
    let spent = post_node_key(&d, &admin.headers(), &id, worker, 7);
    assert_eq!(spent.status, 409, "{}", spent.text);
    assert!(pending_keys(&d).is_empty());
}

#[test]
fn no_credential_outlives_the_issuing_response() {
    let d = deployment(Some(true));
    let admin = administrator(&d);
    let issued = issue(
        &d,
        &admin,
        json!({ "pool": d.pool.to_string(), "transport": "tailcat" }),
    );
    assert_eq!(issued.status, 201, "{}", issued.text);
    let issued = issued.json();
    let (id, secret) = (
        issued["id"].as_str().unwrap().to_owned(),
        issued["secret"].as_str().unwrap().to_owned(),
    );
    let canaries = [&secret[5..], TAILCAT_ADDRESS];

    // Every read an administrator has, before the machine redeems.
    let reads = [
        "/api/v1/admin/worker-enrollments".to_owned(),
        format!("/api/v1/admin/worker-enrollments/{id}"),
        format!("/api/v1/admin/worker-enrollments/{id}/bootstrap.sh"),
        "/api/v1/admin/worker-bootstrap".to_owned(),
        "/api/v1/admin/workers".to_owned(),
        "/api/v1/admin/placement".to_owned(),
        "/api/v1/admin/pools".to_owned(),
        "/api/v1/admin/audit?limit=100".to_owned(),
    ];
    let mut served = Vec::new();
    for path in &reads {
        let reply = send(&d, "GET", path, None, &admin.headers());
        assert_eq!(reply.status, 200, "{path}: {}", reply.text);
        served.push(format!("{path}\n{:?}\n{}", reply.headers, reply.text));
    }

    // The machine redeems: its answer is the one place the address is meant to reach, and it never repeats the secret.
    let reply = post_redeem(&d, &redeem_body(&secret, WorkerId::new(), PRINT_A, Some(7)));
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert!(reply.text.contains(TAILCAT_ADDRESS));
    assert!(!reply.text.contains(&secret[5..]));
    // Another enrollment is withdrawn, and a direct one issued and redeemed.
    let (direct_secret, direct_id) = issue_secret(&d, &admin, "direct");
    let (_, withdrawn) = issue_secret(&d, &admin, "tailcat");
    let gone = send(
        &d,
        "DELETE",
        &format!("/api/v1/admin/worker-enrollments/{withdrawn}"),
        None,
        &admin.headers(),
    );
    assert_eq!(gone.status, 204);
    let direct = post_redeem(
        &d,
        &redeem_body(&direct_secret, WorkerId::new(), PRINT_B, None),
    );
    assert_eq!(direct.status, 200, "{}", direct.text);
    assert!(!direct.text.contains(&direct_secret[5..]));

    // And every read again, after.
    for path in &reads {
        let reply = send(&d, "GET", path, None, &admin.headers());
        served.push(format!("{path}\n{:?}\n{}", reply.headers, reply.text));
    }
    served.push(
        send(
            &d,
            "GET",
            &format!("/api/v1/admin/worker-enrollments/{direct_id}"),
            None,
            &admin.headers(),
        )
        .text,
    );
    let served = served.join("\n");
    for canary in canaries {
        assert!(!served.contains(canary), "{canary} in an answer");
    }

    // Only the digest of the secret is stored; the address is never stored by the API at all.
    let mut files = 0;
    for entry in std::fs::read_dir(d._dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("metadata.sqlite") {
            continue;
        }
        files += 1;
        let bytes = std::fs::read(&path).unwrap();
        for canary in canaries.iter().chain(&[&direct_secret[5..]]) {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
                "{canary} in {name}"
            );
        }
    }
    assert!(files >= 1);
}
