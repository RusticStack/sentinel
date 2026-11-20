//! Part 22 Y04 over HTTP: the tenant's budget, the pre-call reservation and the analysis cache.
//!
//! The gate this binary proves is the refusal's: a request that does not fit its tenant's month is
//! refused by the reserve call and settled in that same write, so it never waits in the queue and no
//! provider is ever contacted for it. The second half is the cache's: a repeat of the same evidence
//! is answered by the reserve call itself, marked reused, with no provider call at all.

use std::sync::Arc;

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::summary::{AttemptSummary, StepOutcome, StepRecord};
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
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    attempt: AttemptId,
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

fn deployment() -> Deployment {
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
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
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
            auth::set_repo_grant(tx, root, repo, admin, P::REPOSITORY)?;
            auth::set_repo_grant(tx, root, repo, member, P::READ)?;
            auth::set_repo_grant(tx, root, repo, service, P::READ)?;
            jobs::insert_run(tx, tenant, repo, run, "abc123", now)?;
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                    repo_id, summary, released_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6, ?7)",
                (
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [9u8; 16],
                    repo.as_bytes(),
                    sealed.as_slice(),
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
                    budgets: sentinel_store::ai::Budgets::default(),
                    auto_analysis: false,
                },
                now,
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
        _controller: controller,
        server: Some(server),
        base,
        attempt,
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

/// The administrator states the tenant's budget.
fn set_budgets(d: &Deployment, budgets: Value) -> Reply {
    let ada = stepped_up(d, "ada", ADMIN);
    call(
        d,
        "PUT",
        "/api/v1/tenants/acme/ai",
        Some(&json!({
            "enabled": true,
            "data_policy": "local_only",
            "budgets": budgets,
        })),
        &ada.headers(),
    )
}

fn usage(d: &Deployment) -> Reply {
    let ada = sign_in(d, "ada", ADMIN);
    call(
        d,
        "GET",
        "/api/v1/tenants/acme/ai/usage",
        None,
        &ada.headers(),
    )
}

/// A member asks one question about the one attempt.
fn ask(d: &Deployment) -> String {
    let mia = sign_in(d, "mia", MEMBER);
    let reply = call(
        d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": d.attempt.to_string(), "provider": "local" })),
        &mia.headers(),
    );
    assert_eq!(reply.status, 201, "{}", reply.text);
    reply.json()["id"].as_str().unwrap().to_owned()
}

fn claim(d: &Deployment, id: &str) {
    let claimed = call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(claimed.status, 200, "{}", claimed.text);
}

fn reserve(
    d: &Deployment,
    id: &str,
    input: u64,
    output: u64,
    cost: u64,
    digest: &str,
    print: &str,
) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/reserve"),
        Some(&json!({
            "input_tokens": input,
            "output_tokens": output,
            "cost_micros": cost,
            "digest": digest,
            "fingerprint": print,
            "prompt_version": "analysis-1",
            "model": "fake/model",
        })),
        &[("authorization", &d.service)],
    )
}

/// The service settles a request with one `sentinel.ai-analysis/1` claim citing the fixture's log.
fn complete(d: &Deployment, id: &str, claim: &str, usage: Value) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({
            "outcome": "completed",
            "analysis": {
                "schema": "sentinel.ai-analysis/1",
                "summary": "the unit step failed",
                "claims": [{
                    "text": claim,
                    "citations": [{ "attempt": d.attempt.to_string(), "evidence": "log-1" }],
                }],
            },
            "usage": usage,
        })),
        &[("authorization", &d.service)],
    )
}

fn request(d: &Deployment, id: &str) -> Value {
    let mia = sign_in(d, "mia", MEMBER);
    call(
        d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    )
    .json()
}

const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRINT: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// The gate: a request past the tenant's month is refused by the reserve call, which settles it, so
/// it never waits in the queue — and the refusal names the budget.
#[test]
fn a_request_past_the_month_is_refused_immediately_and_never_queued() {
    let d = deployment();
    let reply = set_budgets(
        &d,
        json!({ "monthly_tokens": 1_500, "max_input_tokens": 32_000, "concurrency": 4 }),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);

    let first = ask(&d);
    claim(&d, &first);
    let held = reserve(&d, &first, 1_000, 500, 9_000, DIGEST, PRINT);
    assert_eq!(held.status, 200, "{}", held.text);
    assert_eq!(held.json()["state"], "reserved");
    assert!(held.json()["expires_ms"].as_i64().unwrap() > 0);

    let second = ask(&d);
    claim(&d, &second);
    let refused = reserve(&d, &second, 1_000, 500, 9_000, OTHER, PRINT);
    assert_eq!(refused.status, 200, "{}", refused.text);
    let body = refused.json();
    assert_eq!(body["state"], "refused");
    assert!(
        body["reason"].as_str().unwrap().starts_with("budget: "),
        "{}",
        body["reason"]
    );
    // Refused means ended: the row is settled `unavailable` with that reason, and nothing is queued.
    assert_eq!(body["request"]["state"], "settled");
    assert_eq!(body["request"]["outcome"], "unavailable");
    assert_eq!(request(&d, &second)["reason"], body["reason"]);
    let queued = call(
        &d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(
        queued.json()["requests"].as_array().unwrap().len(),
        0,
        "a refused request stayed in the queue: {}",
        queued.text
    );

    let month = usage(&d);
    assert_eq!(month.status, 200, "{}", month.text);
    assert_eq!(month.json()["reserved"]["input_tokens"], 1_000);
    assert_eq!(month.json()["in_flight"], 1);
}

/// A repeat of the same evidence is answered by the reserve call itself: marked reused, charged
/// nothing, and with no provider call to make.
#[test]
fn a_repeated_evidence_digest_is_served_without_a_provider_call() {
    let d = deployment();
    let first = ask(&d);
    claim(&d, &first);
    assert_eq!(
        reserve(&d, &first, 1_000, 500, 9_000, DIGEST, PRINT).json()["state"],
        "reserved"
    );
    let done = complete(
        &d,
        &first,
        "the unit step failed: left != right",
        json!({ "input_tokens": 800, "output_tokens": 300, "cost_micros": 4_000 }),
    );
    assert_eq!(done.status, 200, "{}", done.text);
    assert_eq!(done.json()["outcome"], "completed");
    assert_eq!(done.json()["reused"], false);

    let again = ask(&d);
    claim(&d, &again);
    let reused = reserve(&d, &again, 1_000, 500, 9_000, DIGEST, PRINT);
    assert_eq!(reused.status, 200, "{}", reused.text);
    let body = reused.json();
    assert_eq!(body["state"], "reused");
    assert_eq!(body["by"], "evidence");
    assert_eq!(body["text"], "the unit step failed: left != right");
    assert_eq!(body["request"]["state"], "settled");
    let row = request(&d, &again);
    assert_eq!(row["reused"], true, "a reused answer is marked as one");
    assert_eq!(row["result"], "the unit step failed: left != right");

    // The month was charged once, by the request that actually asked the provider.
    let month = usage(&d);
    assert_eq!(month.json()["settled"]["input_tokens"], 800);
    assert_eq!(month.json()["settled"]["cost_micros"], 4_000);
    assert_eq!(month.json()["reserved"]["input_tokens"], 0);
}

/// The policy route states the budget, keeps the fields it is not given, and refuses what the schema
/// cannot hold.
#[test]
fn the_budget_policy_route_states_the_budget_and_refuses_what_it_cannot_hold() {
    let d = deployment();
    let stated = set_budgets(
        &d,
        json!({ "monthly_tokens": 5_000, "monthly_cost_micros": 250_000, "concurrency": 3 }),
    );
    assert_eq!(stated.status, 200, "{}", stated.text);
    assert_eq!(stated.json()["budgets"]["monthly_tokens"], 5_000);
    assert_eq!(stated.json()["budgets"]["concurrency"], 3);
    // The fields it did not state keep the defaults.
    assert_eq!(
        stated.json()["budgets"]["max_output_tokens"],
        sentinel_store::ai::Budgets::DEFAULT.max_output_tokens
    );

    // A second change without a budget keeps what the tenant stated before.
    let kept = set_budgets(&d, json!({ "max_output_tokens": 2_048 }));
    assert_eq!(kept.status, 200, "{}", kept.text);
    assert_eq!(
        kept.json()["budgets"]["monthly_tokens"],
        5_000,
        "a budget was reset by omission"
    );
    assert_eq!(kept.json()["budgets"]["max_output_tokens"], 2_048);

    for (budgets, field) in [
        (json!({ "concurrency": 0 }), "concurrency"),
        (json!({ "concurrency": 65 }), "concurrency"),
        (json!({ "max_input_tokens": 0 }), "max_input_tokens"),
        (json!({ "max_cost_micros": 0 }), "max_cost_micros"),
    ] {
        let refused = set_budgets(&d, budgets);
        assert_eq!(refused.status, 400, "{}: {}", field, refused.text);
        assert_eq!(
            refused.json()["details"]["budget"],
            field,
            "{}",
            refused.text
        );
    }
}

/// A reserve call names what it cannot read, and a request nobody claimed has nothing to reserve.
#[test]
fn a_reservation_of_a_queued_request_and_a_malformed_digest_are_refused() {
    let d = deployment();
    let queued = ask(&d);
    let early = reserve(&d, &queued, 100, 100, 100, DIGEST, PRINT);
    assert_eq!(early.status, 409, "{}", early.text);

    claim(&d, &queued);
    let malformed = reserve(&d, &queued, 100, 100, 100, "not-a-digest", PRINT);
    assert_eq!(malformed.status, 400, "{}", malformed.text);
    assert_eq!(malformed.json()["details"]["field"], "digest");
    let upper = reserve(
        &d,
        &queued,
        100,
        100,
        100,
        "ABCDEF111111111111111111111111111111111111111111111111111111111111",
        PRINT,
    );
    assert_eq!(upper.status, 400, "{}", upper.text);
}

/// The usage route reports the month's charged and held totals, and the budget they are held against.
#[test]
fn the_usage_route_reports_the_month_it_is_charged_against() {
    let d = deployment();
    set_budgets(
        &d,
        json!({ "monthly_tokens": 4_000, "monthly_cost_micros": 100_000 }),
    );
    let id = ask(&d);
    claim(&d, &id);
    reserve(&d, &id, 1_200, 300, 7_000, DIGEST, PRINT);
    let month = usage(&d).json();
    assert_eq!(
        month["month"].as_str().unwrap().len(),
        7,
        "the month is YYYY-MM: {}",
        month["month"]
    );
    assert_eq!(month["budget"]["monthly_tokens"], 4_000);
    assert_eq!(month["reserved"]["input_tokens"], 1_200);
    assert_eq!(month["reserved"]["output_tokens"], 300);
    assert_eq!(month["reserved"]["cost_micros"], 7_000);
    assert_eq!(month["settled"]["cost_micros"], 0);
    assert_eq!(month["in_flight"], 1);

    complete(
        &d,
        &id,
        "an answer",
        json!({ "input_tokens": 900, "output_tokens": 200, "cost_micros": 5_000 }),
    );
    let after = usage(&d).json();
    assert_eq!(after["settled"]["input_tokens"], 900);
    assert_eq!(after["settled"]["output_tokens"], 200);
    assert_eq!(after["reserved"]["cost_micros"], 0);
    assert_eq!(after["in_flight"], 0);
}
