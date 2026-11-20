//! Part 22 Y03 over HTTP: durable AI requests, their consumption by the AI service, and the
//! request-scoped delegation.
//!
//! The gate this binary proves is the row's: a delegated token cannot read past the requester.
//! The delegation is the requester's own identity capped to read-only scopes, minted at claim
//! time, bound to one request and one attempt, and dead the moment the request settles or its
//! deadline passes. No provider is contacted: the controller never calls one, and the AI process
//! is represented here by the credential it presents.

use std::sync::Arc;

use sentinel_core::{
    AiRequestId, AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    summary::{AttemptSummary, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, provisioning},
    jobs, local_auth,
    logs::LogStore,
    oauth::{self, GrantKind, NewGrant},
    objects::Objects,
};
use serde_json::{Value, json};

const ADMIN: &str = "ada-password-is-long";
const MEMBER: &str = "mia-password-is-long";
const AI_CLIENT: &str = "sentinel-ai";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    run: RunId,
    attempt: AttemptId,
    /// An attempt of the same repository the requester can read too. The delegation is bound to
    /// one request, so it may not read this one.
    other_attempt: AttemptId,
    /// An attempt of a repository in the same tenant the requester has no grant on: the delegation
    /// must be refused here exactly as the requester is.
    hidden_attempt: AttemptId,
    /// The tenant's reader: the person a request is made on behalf of.
    member: UserId,
    /// The AI service's grant: `ai:context` and nothing else.
    service: String,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment(opted_in: bool) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let now = UnixMillis::now();
    let root = local_auth::bootstrap(&store, "root", "Root", b"correct horse battery staple", now)
        .unwrap();
    let (tenant, repo, hidden_repo) = (TenantId::new(), RepoId::new(), RepoId::new());
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let (other_job, other_attempt) = (JobId::new(), AttemptId::new());
    let hidden_attempt = AttemptId::new();
    let (admin, member, service) = (UserId::new(), UserId::new(), UserId::new());
    let summary = AttemptSummary {
        steps_ns: Some(1_500_000_000),
        steps: vec![StepRecord {
            index: 0,
            id: "unit".into(),
            outcome: StepOutcome::Failed { code: 1 },
            duration_ns: Some(1_000_000_000),
        }],
        ..AttemptSummary::default()
    };
    let sealed = summary.encode().unwrap();
    store
        .writer()
        .write(move |tx| {
            let root = Principal::new(root, P::ALL, None, None);
            jobs::insert_tenant(tx, tenant, "acme", now)?;
            provisioning::insert_human(tx, admin, "Ada", false, now)?;
            provisioning::insert_human(tx, member, "Mia", false, now)?;
            provisioning::insert_human(tx, service, "ai-service", true, now)?;
            auth::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, tenant, member, Role::Reader)?;
            auth::set_membership(tx, root, tenant, service, Role::Reader)?;
            auth::create_repo(tx, root, tenant, repo, "app", now)?;
            auth::create_repo(tx, root, tenant, hidden_repo, "internal", now)?;
            auth::set_repo_grant(tx, root, repo, admin, P::REPOSITORY)?;
            auth::set_repo_grant(tx, root, repo, member, P::READ)?;
            // The AI service reads the bundles it is asked about, with its own grant and the
            // repository membership a deployment gives it.
            auth::set_repo_grant(tx, root, repo, service, P::READ)?;
            auth::set_repo_grant(tx, root, hidden_repo, admin, P::REPOSITORY)?;
            jobs::insert_run(tx, tenant, repo, run, "abc123", now)?;
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)?;
            jobs::insert_job(tx, tenant, run, other_job, "beta", 5, 1)?;
            for (id, job) in [(attempt, job), (other_attempt, other_job)] {
                tx.execute(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                        repo_id, summary, released_ms)
                     VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6, ?7)",
                    (
                        id.as_bytes(),
                        tenant.as_bytes(),
                        job.as_bytes(),
                        [9u8; 16],
                        repo.as_bytes(),
                        sealed.as_slice(),
                        now.0,
                    ),
                )?;
            }
            let hidden_run = RunId::new();
            let hidden_job = JobId::new();
            jobs::insert_run(tx, tenant, hidden_repo, hidden_run, "def456", now)?;
            jobs::insert_job(tx, tenant, hidden_run, hidden_job, "unit", 5, 0)?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                    repo_id, released_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6)",
                (
                    hidden_attempt.as_bytes(),
                    tenant.as_bytes(),
                    hidden_job.as_bytes(),
                    [8u8; 16],
                    hidden_repo.as_bytes(),
                    now.0,
                ),
            )?;
            for (user, name, password) in [(admin, "ada", ADMIN), (member, "mia", MEMBER)] {
                let phc = sentinel_auth::password::hash(password.as_bytes()).unwrap();
                local_auth::provision_credential(tx, Authority::HostLocal, user, name, &phc, now)?;
            }
            Ok(())
        })
        .unwrap();
    logs.append(
        run,
        job,
        attempt,
        &Frame {
            seq: 1,
            step: 0,
            stream: Stream::Stdout,
            bytes: b"assertion failed: left != right at src/lib.rs:41".to_vec(),
        },
    )
    .unwrap();

    // The deployment allows the local endpoint and OpenRouter; the tenant may opt in with a data
    // policy of its own choosing.
    let platform = Principal::new(root, P::ALL, None, None);
    let administrator = Principal::new(
        admin,
        P::REPOSITORY.union(P::TENANT_ADMIN),
        Some(tenant),
        None,
    );
    store
        .writer()
        .write(move |tx| {
            let mut providers = sentinel_store::ai::Providers::NONE;
            providers.insert(sentinel_store::ai::Provider::Local);
            providers.insert(sentinel_store::ai::Provider::OpenRouter);
            sentinel_store::ai::set_deployment(
                tx,
                Authority::Credential {
                    principal: platform,
                    stepped_up: true,
                },
                sentinel_store::ai::Deployment {
                    enabled: true,
                    providers,
                },
                now,
            )?;
            if opted_in {
                sentinel_store::ai::set_tenant(
                    tx,
                    Authority::Credential {
                        principal: administrator,
                        stepped_up: true,
                    },
                    tenant,
                    sentinel_store::ai::Tenant {
                        enabled: true,
                        data_policy: sentinel_store::ai::DataPolicy::LocalOnly,
                    },
                    now,
                )?;
            }
            Ok(())
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
        _controller: controller,
        server: Some(server),
        base,
        run,
        attempt,
        other_attempt,
        hidden_attempt,
        member,
        service,
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

fn sign_in(d: &Deployment, username: &str, password: &str) -> Session {
    let reply = call(
        d,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": password })),
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
    Session { cookie, csrf }
}

fn stepped_up(d: &Deployment, username: &str, password: &str) -> Session {
    let session = sign_in(d, username, password);
    let reply = call(
        d,
        "POST",
        "/api/v1/step-up",
        Some(&json!({ "method": "password", "code": password })),
        &session.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    session
}

fn ask(d: &Deployment, session: &Session, attempt: AttemptId, provider: &str) -> Reply {
    call(
        d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": attempt.to_string(), "provider": provider })),
        &session.headers(),
    )
}

/// The one queued request's id, as the AI service lists it.
fn queued(d: &Deployment) -> Reply {
    call(
        d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    )
}

/// Claims the one queued request as the AI service, which mints its delegation.
fn claim_next(d: &Deployment) -> (String, String) {
    let queue = queued(d);
    assert_eq!(queue.status, 200, "{}", queue.text);
    let id = queue.json()["requests"][0]["id"]
        .as_str()
        .expect("a queued request")
        .to_owned();
    let claimed = call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(claimed.status, 200, "{}", claimed.text);
    let access = claimed.json()["token"]["access"]
        .as_str()
        .unwrap()
        .to_owned();
    (id, format!("Bearer {access}"))
}

fn evidence(d: &Deployment, attempt: AttemptId, authorization: &str) -> Reply {
    call(
        d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/ai-context?budget=8192"),
        None,
        &[("authorization", authorization)],
    )
}

#[test]
fn a_member_asks_and_the_service_answers_through_the_delegation() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    let asked = ask(&d, &mia, d.attempt, "local");
    assert_eq!(asked.status, 201, "{}", asked.text);
    let row = asked.json();
    assert_eq!(row["state"], "queued");
    assert_eq!(row["provider"], "local");
    assert_eq!(row["data_policy"], "local_only");
    assert!(row["outcome"].is_null());
    let id = row["id"].as_str().unwrap().to_owned();

    let (claimed_id, delegation) = claim_next(&d);
    assert_eq!(claimed_id, id);
    // The delegation holds the read-only half of the requester's scopes and nothing else.
    let claim = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(
        claim.status, 409,
        "a claimed request cannot be claimed twice"
    );

    let bundle = evidence(&d, d.attempt, &delegation);
    assert_eq!(bundle.status, 200, "{}", bundle.text);
    assert_eq!(bundle.json()["schema"], "sentinel.ai-context/1");

    // The service's own grant reads the same bundle, and is what settles the request.
    assert_eq!(evidence(&d, d.attempt, &d.service).status, 200);
    let settled = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({ "outcome": "completed", "text": "the unit step failed on an assertion" })),
        &[("authorization", &d.service)],
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    assert_eq!(settled.json()["state"], "settled");
    assert_eq!(settled.json()["outcome"], "completed");

    // The requester reads the answer from the durable row.
    let read = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(read.status, 200, "{}", read.text);
    assert_eq!(read.json()["state"], "settled");
    assert_eq!(
        read.json()["result"],
        "the unit step failed on an assertion"
    );

    // And the delegation is dead: it was minted for that request, and the settlement revoked it in
    // the same write, so it no longer authenticates at all.
    let after = evidence(&d, d.attempt, &delegation);
    assert!(after.status == 401 || after.status == 403, "{}", after.text);
    // The attempt itself is still readable by the service grant, so nothing else was taken away.
    assert_eq!(evidence(&d, d.attempt, &d.service).status, 200);
}

#[test]
fn a_delegation_reads_nothing_the_requester_could_not_and_cannot_write() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    assert_eq!(ask(&d, &mia, d.attempt, "local").status, 201);
    let (_, delegation) = claim_next(&d);

    // Its own request's attempt, which the requester can read.
    assert_eq!(evidence(&d, d.attempt, &delegation).status, 200);
    // Another attempt of the same repository: the binding is one request, one attempt.
    let other = evidence(&d, d.other_attempt, &delegation);
    assert_eq!(other.status, 403, "{}", other.text);
    // A repository the requester has no grant on: the delegation is refused exactly as they are.
    let hidden = evidence(&d, d.hidden_attempt, &delegation);
    assert!(
        hidden.status == 403 || hidden.status == 404,
        "{}",
        hidden.text
    );

    // It is the requester's own identity, capped to reads: what they can read, it can read.
    let run = call(
        &d,
        "GET",
        &format!("/api/v1/runs/{}", d.run),
        None,
        &[("authorization", &delegation)],
    );
    assert_eq!(run.status, 200, "{}", run.text);

    // And it carries no write authority at all.
    let write = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/repos/app/runs",
        Some(&json!({ "pipeline": "x", "source": { "repo": "r", "sha": "abc", "ref": "main" } })),
        &[("authorization", &delegation)],
    );
    assert_eq!(write.status, 403, "{}", write.text);
    assert!(write.json()["details"]["scope"].as_str().is_some());
}

#[test]
fn a_request_is_refused_while_the_tenant_has_not_opted_in() {
    let d = deployment(false);
    let mia = sign_in(&d, "mia", MEMBER);
    let refused = ask(&d, &mia, d.attempt, "local");
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["details"]["ai"], "off");
    // Nothing was queued, so the service has nothing to consume.
    assert!(queued(&d).json()["requests"].as_array().unwrap().is_empty());
}

#[test]
fn a_provider_the_data_policy_cannot_use_is_refused_at_the_request() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    // The deployment allows OpenRouter, but this tenant is `local_only`.
    let refused = ask(&d, &mia, d.attempt, "openrouter");
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["details"]["ai"], "off");
}

#[test]
fn disabling_the_tenant_drops_its_requests_and_revokes_the_delegation() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    assert_eq!(ask(&d, &mia, d.attempt, "local").status, 201);
    let (id, delegation) = claim_next(&d);
    assert_eq!(evidence(&d, d.attempt, &delegation).status, 200);

    let ada = stepped_up(&d, "ada", ADMIN);
    let disabled = call(
        &d,
        "PUT",
        "/api/v1/tenants/acme/ai",
        Some(&json!({ "enabled": false, "data_policy": "local_only" })),
        &ada.headers(),
    );
    assert_eq!(disabled.status, 200, "{}", disabled.text);

    // The queue is gone in the same write that turned the tenant off.
    assert!(queued(&d).json()["requests"].as_array().unwrap().is_empty());
    let gone = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(gone.status, 404, "{}", gone.text);
    // And the delegation it minted cannot read evidence any more: revoked, so it does not even
    // authenticate.
    let after = evidence(&d, d.attempt, &delegation);
    assert!(after.status == 401 || after.status == 403, "{}", after.text);
}

#[test]
fn a_request_past_its_deadline_ends_unavailable_and_its_delegation_dies() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    assert_eq!(ask(&d, &mia, d.attempt, "local").status, 201);
    let (id, delegation) = claim_next(&d);
    let request_id: AiRequestId = id.parse().unwrap();
    let now = UnixMillis::now();
    let store = Arc::clone(&d.store);
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE ai_requests SET deadline_ms = ?2 WHERE id = ?1",
                (request_id.as_bytes(), now.0.saturating_sub(1)),
            )?;
            Ok(())
        })
        .unwrap();

    // The service's next poll settles what nobody answered in time.
    assert!(queued(&d).json()["requests"].as_array().unwrap().is_empty());
    let read = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(read.status, 200, "{}", read.text);
    assert_eq!(read.json()["state"], "settled");
    assert_eq!(read.json()["outcome"], "unavailable");
    assert_eq!(read.json()["reason"], "the request deadline passed");
    let after = evidence(&d, d.attempt, &delegation);
    assert!(after.status == 401 || after.status == 403, "{}", after.text);
}

#[test]
fn a_requester_holding_less_than_the_read_set_is_refused_rather_than_delegated_wider() {
    let d = deployment(true);
    // A credential narrower than the read set: runs and logs, but not artifacts, cache or the
    // metadata of secrets. Its delegation would be wider than its holder, so there is none.
    let client = "sentinel-narrow";
    oauth::register_client(
        &d.store,
        &oauth::ClientSpec {
            id: client,
            name: "Narrow",
            first_party: true,
            loopback: true,
            redirect_path: Some("/cb"),
            device: true,
            max_scopes: Scopes::RUNS_READ.union(Scopes::LOGS_READ),
        },
        &[],
    )
    .unwrap();
    let narrow = oauth::issue_grant_trusted(
        &d.store,
        NewGrant {
            user: d.member,
            client_id: client,
            kind: GrantKind::Code,
            scopes: Scopes::RUNS_READ.union(Scopes::LOGS_READ),
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
    let access = sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Access, &narrow.access);
    let refused = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": d.attempt.to_string(), "provider": "local" })),
        &[("authorization", &format!("Bearer {access}"))],
    );
    assert_eq!(refused.status, 403, "{}", refused.text);
    let missing = refused.json()["details"]["scope"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(missing.contains("artifacts:read"), "{missing}");
    assert!(missing.contains("cache:read"), "{missing}");
    assert!(missing.contains("secrets:metadata"), "{missing}");
    assert!(queued(&d).json()["requests"].as_array().unwrap().is_empty());
}

#[test]
fn another_tenants_member_cannot_read_a_request() {
    let d = deployment(true);
    let mia = sign_in(&d, "mia", MEMBER);
    let asked = ask(&d, &mia, d.attempt, "local");
    assert_eq!(asked.status, 201, "{}", asked.text);
    let id = asked.json()["id"].as_str().unwrap().to_owned();
    // The service grant holds `ai:context` and nothing else, so it cannot read a member's row.
    let service = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(service.status, 403, "{}", service.text);
    // A request id that does not exist is not found, never a leak of another tenant's rows.
    let absent = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{}", AiRequestId::new()),
        None,
        &mia.headers(),
    );
    assert_eq!(absent.status, 404, "{}", absent.text);
}
