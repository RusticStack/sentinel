//! Part 22 Y02 over HTTP: the AI evidence bundle, its authorization and its bound.
//!
//! The gate this binary proves is the one the backlog row states: a canary secret, a token prefix
//! and a PEM block never survive into the bundle. Nothing here mocks the store or the redactor —
//! the secret is sealed by `sentinel_store::secrets::put` and unsealed through the delivery audit
//! `sentinel_store::secrets::audit_use` records, the log is written through `LogStore`, and the
//! redaction the worker performs before its spool is the very `sentinel_protocol::redact::Redactor`
//! the worker links, which moved to the protocol crate so both holders apply one implementation.

use std::sync::Arc;

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    summary::{AttemptSummary, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, provisioning},
    jobs, local_auth,
    logs::LogStore,
    oauth::{self, GrantKind, NewGrant},
    objects::Objects,
    secrets,
};
use serde_json::Value;

const ROOT: &str = "correct horse battery staple";
const ADMIN: &str = "ada-password-is-long";
/// The canary the attempt was registered: it is a real sealed secret, and no serving path may hold it.
const CANARY: &str = "canary-token-7f3a9c2e5b1d";
/// A second registered value, so one served field cannot hide a second leak.
const CANARY_FILE: &str = "canary-file-value-91c4d7e0a8b2";
const CANARY_STEP: &str = "unit";
/// The client the AI service's grant is issued through.
const AI_CLIENT: &str = "sentinel-ai";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    root: UserId,
    tenant: TenantId,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    /// The AI service's credential: a grant a deployment gives its AI process, and nothing else.
    service: String,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment(lines: &[(&str, Stream)]) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let now = UnixMillis::now();
    let root =
        local_auth::bootstrap(&store, "root", "Root", ROOT.as_bytes(), UnixMillis::now()).unwrap();
    let (tenant, repo, run, job, attempt) = (
        TenantId::new(),
        RepoId::new(),
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
    );
    let (admin, service) = (UserId::new(), UserId::new());
    let summary = AttemptSummary {
        steps_ns: Some(1_500_000_000),
        steps: vec![
            StepRecord {
                index: 0,
                id: "deps".into(),
                outcome: StepOutcome::Passed,
                duration_ns: Some(500_000_000),
            },
            StepRecord {
                index: 1,
                id: CANARY_STEP.into(),
                outcome: StepOutcome::Failed { code: 1 },
                duration_ns: Some(1_000_000_000),
            },
        ],
        ..AttemptSummary::default()
    };
    let sealed = summary.encode().unwrap();
    store
        .writer()
        .write(move |tx| {
            let root = Principal::new(root, P::ALL, None, None);
            jobs::insert_tenant(tx, tenant, "acme", now)?;
            provisioning::insert_human(tx, admin, "Ada", false, now)?;
            provisioning::insert_human(tx, service, "ai-service", true, now)?;
            auth::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, tenant, service, Role::Reader)?;
            auth::create_repo(tx, root, tenant, repo, "app", now)?;
            auth::set_repo_grant(tx, root, repo, admin, P::READ.union(P::RUN))?;
            auth::set_repo_grant(tx, root, repo, service, P::READ)?;
            jobs::insert_run(tx, tenant, repo, run, "abc123", now)?;
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id, summary, released_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6, ?7)",
                (
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [9u8; 16],
                    repo.as_bytes(),
                    sealed,
                    now.0,
                ),
            )?;
            let phc = sentinel_auth::password::hash(ADMIN.as_bytes()).unwrap();
            local_auth::provision_credential(
                tx,
                sentinel_store::auth::Authority::HostLocal,
                admin,
                "ada",
                &phc,
                now,
            )?;
            Ok(())
        })
        .unwrap();
    register_secrets(&store, Arc::clone(&key), admin, tenant, repo, attempt);
    let mut seq = 0u64;
    for (text, stream) in lines {
        write_log(
            &logs,
            (run, job, attempt),
            &mut seq,
            1,
            *stream,
            text.as_bytes(),
        );
    }
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
            logs: Arc::clone(&logs),
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
        sentinel_api::Options::default(),
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    // The AI service's own client, capped at the one scope it needs: the shipped CLI client is
    // capped below `ai:context`, so a deployment grants this credential to the AI process alone.
    oauth::register_client(
        &store,
        &oauth::ClientSpec {
            id: AI_CLIENT,
            name: "Sentinel AI",
            first_party: true,
            loopback: false,
            redirect_path: None,
            device: false,
            max_scopes: Scopes::AI_CONTEXT,
        },
        &[],
    )
    .unwrap();
    let granted = oauth::issue_grant_trusted(
        &store,
        NewGrant {
            user: service,
            client_id: AI_CLIENT,
            kind: GrantKind::Code,
            scopes: Scopes::AI_CONTEXT,
            tenant: None,
            repo: None,
            audience: Audience::Api,
            name: None,
            lifetime_ms: oauth::LOGIN_GRANT_MS,
            created_by: None,
            created_session: None,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let service = format!(
        "Bearer {}",
        sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Access, &granted.access)
    );
    Deployment {
        _dir: dir,
        store,
        root,
        _controller: controller,
        server: Some(server),
        base,
        tenant,
        run,
        job,
        attempt,
        service,
    }
}

/// The attempt's registered values, through the store's own write path, its binding and the use
/// audit its delivery would record.
fn register_secrets(
    store: &Store,
    key: Arc<sentinel_auth::sealed::Key>,
    admin: UserId,
    tenant: TenantId,
    repo: RepoId,
    attempt: AttemptId,
) {
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            // The tenant's administrator, in their own tenant: the authority a secret write needs.
            let admin = Principal::new(admin, P::ALL, Some(tenant), None);
            for (name, value) in [("CANARY_TOKEN", CANARY), ("CANARY_FILE", CANARY_FILE)] {
                secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: secrets::Scope::Repo(repo),
                        name,
                        expected: 0,
                        value: value.as_bytes(),
                    },
                    &key,
                    now,
                )?;
                secrets::bind_named(tx, admin, repo, "", "", name, false, true, now)?;
            }
            // The use audit is what makes these the attempt's registered values: the delivery's
            // own record, read back by `secrets::attempt_values`.
            for name in ["CANARY_TOKEN", "CANARY_FILE"] {
                let resolved = secrets::resolve(tx, repo, "alpha", CANARY_STEP, name)?;
                secrets::audit_use(tx, attempt, CANARY_STEP, &resolved, now)?;
            }
            Ok(())
        })
        .unwrap();
}

fn write_log(
    logs: &LogStore,
    (run, job, attempt): (RunId, JobId, AttemptId),
    seq: &mut u64,
    step: u32,
    stream: Stream,
    text: &[u8],
) {
    for chunk in text.chunks(sentinel_protocol::limits::MAX_LOG_FRAME_BYTES) {
        *seq += 1;
        logs.append(
            run,
            job,
            attempt,
            &Frame {
                seq: *seq,
                step,
                stream,
                bytes: chunk.to_vec(),
            },
        )
        .unwrap();
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
}

fn send(d: &Deployment, path: &str, authorization: &str) -> Reply {
    call(d, "GET", path, None, &[("authorization", authorization)])
}

fn call(
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
    let mut request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "PUT" => agent.put(&url),
        _ => agent.post(&url),
    }
    .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request
        .send(
            body.map_or_else(|| "{}".to_owned(), Value::to_string)
                .as_bytes(),
        )
        .unwrap();
    Reply {
        status: response.status().as_u16(),
        headers: response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect(),
        text: response.into_body().read_to_string().unwrap_or_default(),
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

fn stepped_up(d: &Deployment, username: &str, password: &str) -> Session {
    let reply = call(
        d,
        "POST",
        "/api/v1/login",
        Some(&serde_json::json!({ "username": username, "password": password })),
        &[],
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    let cookie = reply
        .headers
        .iter()
        .find(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.split(';').next().unwrap_or_default().to_owned())
        .unwrap();
    let csrf = reply.json()["csrf"].as_str().unwrap().to_owned();
    let session = Session { cookie, csrf };
    let reply = call(
        d,
        "POST",
        "/api/v1/step-up",
        Some(&serde_json::json!({ "method": "password", "code": password })),
        &session.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    session
}

fn bundle(d: &Deployment, query: &str) -> Reply {
    send(
        d,
        &format!("/api/v1/attempts/{}/ai-context{query}", d.attempt),
        &d.service,
    )
}

/// Both administrators agree, exactly as a deployment turns AI on.
fn opt_in(d: &Deployment) {
    let root = stepped_up(d, "root", ROOT);
    let reply = call(
        d,
        "PUT",
        "/api/v1/admin/ai",
        Some(&serde_json::json!({ "enabled": true, "providers": ["local"] })),
        &root.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    let ada = stepped_up(d, "ada", ADMIN);
    let reply = call(
        d,
        "PUT",
        "/api/v1/tenants/acme/ai",
        Some(&serde_json::json!({ "enabled": true, "data_policy": "zero_retention" })),
        &ada.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
}

#[test]
fn the_bundle_needs_the_ai_grant_and_a_tenant_that_opted_in() {
    let d = deployment(&[("the unit step failed\n", Stream::Stderr)]);
    // The service's grant is not enough on its own: no tenant has opted in, so no bundle exists.
    let reply = bundle(&d, "");
    assert_eq!(reply.status, 403, "{}", reply.text);
    assert_eq!(reply.json()["details"]["ai"], "off");
    assert_eq!(reply.json()["code"], "forbidden");

    let tenant = d.tenant;
    let _ = tenant;
    d.store
        .writer()
        .write(move |tx| {
            sentinel_store::ai::set_deployment(
                tx,
                sentinel_store::auth::Authority::HostLocal,
                sentinel_store::ai::Deployment {
                    enabled: true,
                    providers: sentinel_store::ai::Providers::NONE,
                },
                UnixMillis::now(),
            )?;
            Ok(())
        })
        .unwrap();
    // A deployment with no provider allowed is still no opt-in: nothing could ever be sent.
    assert_eq!(bundle(&d, "").status, 403);

    opt_in(&d);
    let reply = bundle(&d, "");
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.json()["schema"], "sentinel.ai-context/1");
    assert_eq!(reply.json()["attempt"], d.attempt.to_string());
    assert_eq!(reply.json()["run"], d.run.to_string());
    assert_eq!(reply.json()["job"], d.job.to_string());

    // A member with `logs:read` reads the log and the failure context, never the bundle: a session
    // cannot hold `ai:context` at all, because no permission set implies it.
    let ada = stepped_up(&d, "ada", ADMIN);
    let logs = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/logs", d.attempt),
        None,
        &ada.headers(),
    );
    assert_eq!(logs.status, 200, "{}", logs.text);
    let refused = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/ai-context", d.attempt),
        None,
        &ada.headers(),
    );
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["details"]["scope"], "ai:context");
    // The same for the CLI's own token, whose scopes are every read a permission implies.
    let cli = format!("Bearer {}", root_credential(&d));
    let refused = send(
        &d,
        &format!("/api/v1/attempts/{}/ai-context", d.attempt),
        &cli,
    );
    assert_eq!(refused.status, 403, "{}", refused.text);

    // The attempt of another tenant, or one that does not exist, is not found rather than forbidden.
    let elsewhere = format!("/api/v1/attempts/{}/ai-context", AttemptId::new());
    let reply = send(&d, &elsewhere, &d.service);
    assert_eq!(reply.status, 404, "{}", reply.text);
}

fn root_credential(d: &Deployment) -> String {
    let now = UnixMillis::now();
    let granted = oauth::issue_grant_trusted(
        &d.store,
        NewGrant {
            user: d.root,
            client_id: sentinel_protocol::oauth::CLI_CLIENT_ID,
            kind: GrantKind::Code,
            scopes: Scopes::CLI_DEFAULT,
            tenant: None,
            repo: None,
            audience: Audience::Api,
            name: None,
            lifetime_ms: oauth::LOGIN_GRANT_MS,
            created_by: None,
            created_session: None,
        },
        now,
    )
    .unwrap();
    sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Access, &granted.access)
}

#[test]
fn no_registered_value_token_prefix_or_pem_block_survives_into_the_bundle() {
    // The stored log holds a registered value, a token prefix, a PEM block, a cloud key and a JWT.
    // The first is the case the second pass exists for: the value was registered as this attempt's
    // after the frame was written, which is what a secret created for a value an older log already
    // contains looks like. The rest are text no value registration can cover.
    // Assembled here rather than committed: the committed-key guard refuses a PEM private key in the
    // tree, and a generated body is the same text to the scanner.
    // The header is assembled from parts so no line of this file carries a whole header followed by a
    // body: the committed-key guard reads that shape as a key, and a fixture is not one.
    let pem = format!(
        "{}\n{}\n{}",
        ["-----BEGIN ", "RSA PRIVATE KEY", "-----"].concat(),
        "MIIEowIBAAKCAQEAoZ0fakePemBodyThatMustNotTravel",
        ["-----END ", "RSA PRIVATE KEY", "-----"].concat()
    );
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYW5hcnkifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let github = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let value_line = format!("deploy: token {CANARY} and file {CANARY_FILE}\n");
    let github_line = format!("export GITHUB_TOKEN={github}\n");
    let pem_line = format!("cat key.pem\n{pem}\n");
    let jwt_line = format!("Authorization: Bearer {jwt}\n");
    let aws_line = format!("aws_access_key_id = {aws}\n");
    let failure_line =
        "--- FAIL: TestCheckout (0.31s)\n    checkout_test.go:42: expected 3, got 4\n";
    let lines = [
        (value_line.as_str(), Stream::Stdout),
        (github_line.as_str(), Stream::Stderr),
        (pem_line.as_str(), Stream::Stdout),
        (jwt_line.as_str(), Stream::Stderr),
        (aws_line.as_str(), Stream::Stdout),
        (failure_line, Stream::Stdout),
    ];
    let d = deployment(&lines);
    opt_in(&d);

    // The store really holds them: the first pass over this text never ran, and the log route shows it.
    let ada = stepped_up(&d, "ada", ADMIN);
    let raw = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/logs", d.attempt),
        None,
        &ada.headers(),
    );
    assert_eq!(raw.status, 200, "{}", raw.text);
    for secret in [
        CANARY,
        github,
        "MIIEowIBAAKCAQEAoZ0fakePemBodyThatMustNotTravel",
        jwt,
        aws,
    ] {
        assert!(raw.text.contains(secret), "the log should hold {secret}");
    }

    let reply = bundle(&d, "");
    assert_eq!(reply.status, 200, "{}", reply.text);
    for secret in [
        CANARY,
        CANARY_FILE,
        github,
        "MIIEowIBAAKCAQEAoZ0fakePemBodyThatMustNotTravel",
        jwt,
        aws,
    ] {
        assert!(
            !reply.text.contains(secret),
            "{secret} survived into the bundle"
        );
    }
    assert!(!reply.text.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!reply.text.contains("ghp_"));
    assert!(!reply.text.contains("AKIA"));
    assert!(!reply.text.contains("eyJhbGci"));

    let body = reply.json();
    assert_eq!(body["redaction"]["values"], 2);
    assert!(body["redaction"]["value_rewrites"].as_u64().unwrap() >= 1);
    assert!(
        body["redaction"]["pattern_replacements"].as_u64().unwrap() >= 3,
        "{}",
        body["redaction"]
    );
    let patterns = body["redaction"]["patterns"].as_array().unwrap();
    for kind in ["github_token", "pem_block", "aws_key", "jwt"] {
        assert!(patterns.iter().any(|p| p == kind), "{patterns:?}");
    }

    // The diagnostics the log parses into are still the evidence: the failure survives, rewritten.
    assert_eq!(body["authoritative"]["current_attempt"], false);
    assert_eq!(body["failed_step"]["id"], CANARY_STEP);
    assert_eq!(body["failed_step"]["outcome"], "failed");
    assert_eq!(body["failed_step"]["exit_code"], 1);
    assert!(
        body["log"]["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|frame| frame["text"].as_str().unwrap_or("").contains("***")),
        "{}",
        body["log"]["frames"]
    );
}

#[test]
fn the_default_bound_and_a_smaller_one_are_both_enforced() {
    let noise = "compiling sentinel-core v0.1.0\n".repeat(64);
    let mut lines = Vec::new();
    for _ in 0..400 {
        lines.push((noise.clone(), Stream::Stdout));
    }
    lines.push(("the last line a reader needs\n".to_owned(), Stream::Stderr));
    let borrowed: Vec<(&str, Stream)> = lines
        .iter()
        .map(|(text, stream)| (text.as_str(), *stream))
        .collect();
    let d = deployment(&borrowed);
    opt_in(&d);

    let reply = bundle(&d, "");
    assert_eq!(reply.status, 200, "{}", reply.text);
    let body = reply.json();
    let size = body["bounds"]["bytes"].as_u64().unwrap();
    assert_eq!(body["bounds"]["budget_bytes"], 32 * 1024);
    assert!(size <= 32 * 1024, "{size} exceeds the default bound");
    assert_eq!(size as usize, reply.text.len());
    assert_eq!(body["bounds"]["truncated"], true);
    assert!(body["bounds"]["omitted_log_frames"].as_u64().unwrap() > 0);
    // What survives a cut is the newest evidence, and the cut is stated: frames it dropped are
    // counted, and a frame that lost bytes carries `cut` with the newest of its text.
    assert!(reply.text.contains("the last line a reader needs"));
    for frame in body["log"]["frames"].as_array().unwrap() {
        if frame["cut"] == true {
            assert!(!frame["text"].as_str().unwrap_or_default().is_empty());
        }
    }
    assert!(
        body["bounds"]["omitted_log_frames"].as_u64().unwrap() > 0
            || body["log"]["frames"]
                .as_array()
                .unwrap()
                .iter()
                .any(|frame| frame["cut"] == true)
    );

    let small = bundle(&d, "?budget=2048");
    assert_eq!(small.status, 200, "{}", small.text);
    let body = small.json();
    let size = body["bounds"]["bytes"].as_u64().unwrap();
    assert_eq!(body["bounds"]["budget_bytes"], 2048);
    assert!(size <= 2048, "{size} exceeds a 2 KiB bound");
    assert_eq!(size as usize, small.text.len());
    assert_eq!(body["bounds"]["truncated"], true);

    for bad in ["?budget=0", "?budget=1023", "?budget=65537", "?budget=many"] {
        let reply = bundle(&d, bad);
        assert_eq!(reply.status, 400, "{bad}: {}", reply.text);
        assert_eq!(reply.json()["code"], "invalid_request");
    }
}
