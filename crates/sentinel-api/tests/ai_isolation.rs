//! Part 22 Y10: the failure drills for AI assistance, in the shape
//! [resilience](../docs/resilience.md) uses — one test per failure, each driving the real
//! controller and asserting what survives.
//!
//! A provider is never contacted here, because the controller never calls one: the AI process is
//! represented by the credential it presents, and its four calls (queue, claim, reserve, settle)
//! are the real routes. What that leaves simulated is named in each drill: the provider's answer,
//! and the death of the process that was holding a request.
//!
//! The last drill is the invariant that ties the rest together: with AI on and its provider
//! failing, every deterministic surface — each job's state and failure class, each attempt's
//! outcome, the checks published and the run's conclusion — is identical to the same scenario with
//! AI off, driven twice through a real worker session.

#![cfg(target_os = "linux")]

use std::sync::Arc;

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AiRequestId, AttemptId, Event, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId,
    WorkerId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    negotiate::{Arch, Capabilities, Hello, ProtocolVersion},
    summary::{AttemptSummary, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store, ai,
    auth::{self, Authority, provisioning},
    checks, jobs, local_auth,
    logs::LogStore,
    oauth::{self, GrantKind, NewGrant},
    objects::Objects,
    runs,
};
use serde_json::{Value, json};

const ADMIN: &str = "ada-password-is-long";
const MEMBER: &str = "mia-password-is-long";
const AI_CLIENT: &str = "sentinel-ai";
/// A digest and a fingerprint that name one question, so a reuse cannot happen by accident.
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PRINT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    tenant: TenantId,
    run: RunId,
    job: JobId,
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

/// A tenant with one committed attempt, AI enabled for the deployment and opted in for the tenant
/// with `budgets` and automatic analysis on — so a failed job would be asked about by itself.
fn deployment(budgets: ai::Budgets) -> Deployment {
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
            let mut providers = ai::Providers::NONE;
            providers.insert(ai::Provider::Local);
            ai::set_deployment(
                tx,
                Authority::Credential {
                    principal: platform,
                    stepped_up: true,
                },
                ai::Deployment {
                    enabled: true,
                    providers,
                },
                now,
            )?;
            ai::set_tenant(
                tx,
                Authority::Credential {
                    principal: administrator,
                    stepped_up: true,
                },
                tenant,
                ai::Tenant {
                    enabled: true,
                    data_policy: ai::DataPolicy::LocalOnly,
                    budgets,
                    auto_analysis: true,
                },
                now,
            )?;
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
        tenant,
        run,
        job,
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

/// A member asks one question about the one attempt.
fn ask(d: &Deployment) -> String {
    ask_as(d, "mia", MEMBER)
}

fn ask_as(d: &Deployment, username: &str, password: &str) -> String {
    let session = sign_in(d, username, password);
    let reply = call(
        d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": d.attempt.to_string(), "provider": "local" })),
        &session.headers(),
    );
    assert_eq!(reply.status, 201, "{}", reply.text);
    reply.json()["id"].as_str().unwrap().to_owned()
}

/// The AI service's poll, which is also the sweep: `(queued ids, everything the poll answered)`.
fn poll(d: &Deployment) -> Vec<String> {
    let reply = call(
        d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    reply.json()["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect()
}

/// Claims `id` as the AI service, which mints its delegation.
fn claim(d: &Deployment, id: &str) -> String {
    let claimed = call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(claimed.status, 200, "{}", claimed.text);
    format!(
        "Bearer {}",
        claimed.json()["token"]["access"].as_str().unwrap()
    )
}

fn reserve(d: &Deployment, id: &str, input: u64, output: u64) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/reserve"),
        Some(&json!({
            "input_tokens": input,
            "output_tokens": output,
            "cost_micros": 9_000,
            "digest": DIGEST,
            "fingerprint": PRINT,
            "prompt_version": "analysis-1",
            "model": "fake/model",
        })),
        &[("authorization", &d.service)],
    )
}

/// What the AI process sends when its provider fails: no answer, and the reason there is none.
fn settle_unavailable(d: &Deployment, id: &str, reason: &str) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({ "outcome": "unavailable", "reason": reason })),
        &[("authorization", &d.service)],
    )
}

fn request(d: &Deployment, id: &str) -> Reply {
    let mia = sign_in(d, "mia", MEMBER);
    call(
        d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    )
}

fn usage(d: &Deployment) -> Value {
    let ada = sign_in(d, "ada", ADMIN);
    let reply = call(
        d,
        "GET",
        "/api/v1/tenants/acme/ai/usage",
        None,
        &ada.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    reply.json()
}

fn evidence(d: &Deployment, authorization: &str) -> Reply {
    call(
        d,
        "GET",
        &format!("/api/v1/attempts/{}/ai-context?budget=8192", d.attempt),
        None,
        &[("authorization", authorization)],
    )
}

/// How many reservations the ledger is holding, read from the table rather than the route: the
/// drill has to see the release itself, not only what a report says about it.
fn held(d: &Deployment) -> i64 {
    d.store
        .read(|c| {
            Ok(
                c.query_row("SELECT COUNT(*) FROM ai_reservations", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .unwrap()
}

/// Every deterministic surface of the run, as one value two scenarios can be compared by: the
/// jobs' states and failure classes in pipeline order, every attempt's outcome as the summary bytes
/// the controller stored, the checks published for the run, and the run's own conclusion.
#[derive(Debug, PartialEq, Eq)]
struct Surfaces {
    jobs: Vec<(String, Option<String>)>,
    attempts: Vec<(i64, String)>,
    conclusion: Option<String>,
    checks: Vec<(String, String, Option<String>, String, String)>,
}

fn surfaces(d: &Deployment) -> Surfaces {
    let (tenant, run) = (d.tenant, d.run);
    d.store
        .read(move |c| {
            let mut jobs = Vec::new();
            for (job, _) in runs::run_jobs(c, tenant, run)? {
                let row = jobs::get_job(c, tenant, job)?;
                jobs.push((
                    format!("{:?}", row.state),
                    row.failure_class.map(|class| class.as_str().to_owned()),
                ));
            }
            let mut attempts = Vec::new();
            let mut statement = c.prepare_cached(
                "SELECT fence, summary FROM attempts WHERE job_id = ?1 ORDER BY fence",
            )?;
            let mut rows = statement.query([d.job.as_bytes()])?;
            while let Some(row) = rows.next()? {
                let fence: i64 = row.get(0)?;
                let summary: Option<Vec<u8>> = row.get(1)?;
                attempts.push((
                    fence,
                    summary.map_or_else(String::new, |bytes| {
                        bytes.iter().map(|b| format!("{b:02x}")).collect()
                    }),
                ));
            }
            drop(rows);
            drop(statement);
            let mut checks = checks::of_run(c, tenant, run)?
                .into_iter()
                .map(|published| {
                    (
                        published.name,
                        published.status.as_str().to_owned(),
                        published.conclusion.map(|c| c.as_str().to_owned()),
                        published.title,
                        published.summary,
                    )
                })
                .collect::<Vec<_>>();
            checks.sort();
            let conclusion = checks
                .iter()
                .find(|(name, ..)| name == checks::AGGREGATE_NAME)
                .and_then(|(_, _, conclusion, ..)| conclusion.clone());
            Ok(Surfaces {
                jobs,
                attempts,
                conclusion,
                checks,
            })
        })
        .unwrap()
}

/// The surfaces before any AI activity, to prove the drills change none of them.
fn unchanged(d: &Deployment, before: &Surfaces) {
    assert_eq!(&surfaces(d), before, "a deterministic surface changed");
}

/// The clock passing a request's deadline. A reservation expires at exactly that instant — it is
/// written as the row's own deadline when the maximum is held — so a drill simulating time moves
/// both; moving only the row would be simulating a policy the controller never writes.
fn expire(d: &Deployment, id: &str) {
    let id: AiRequestId = id.parse().unwrap();
    let now = UnixMillis::now().0;
    // The row and the reservation are moved together, and both are dated an hour ago, because the
    // store keeps `created_ms < expires_ms`: this is the clock having passed the deadline, not a
    // request that was never admitted.
    let (created, past) = (now.saturating_sub(3_600_000), now.saturating_sub(1));
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE ai_requests SET created_ms = ?2, deadline_ms = ?3 WHERE id = ?1",
                (id.as_bytes(), created, past),
            )?;
            tx.execute(
                "UPDATE ai_reservations SET created_ms = ?2, expires_ms = ?3 WHERE request_id = ?1",
                (id.as_bytes(), created, past),
            )?;
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Drill 1: a provider outage.
// ---------------------------------------------------------------------------------------------

/// Every request settles `unavailable` with the provider's reason, the delegation each one minted
/// dies with it, and no run, job, attempt or check moves.
///
/// Simulated leg: the provider's failure. What the provider said is the reason the process writes;
/// the row, the delegation, the settlement and the queue are the controller's own.
#[test]
fn a_provider_outage_ends_every_request_and_moves_nothing_else() {
    let d = deployment(ai::Budgets::default());
    let before = surfaces(&d);

    let first = ask(&d);
    let delegation = claim(&d, &first);
    assert_eq!(evidence(&d, &delegation).status, 200);
    assert_eq!(reserve(&d, &first, 1_000, 500).json()["state"], "reserved");
    let second = ask(&d);
    let second_delegation = claim(&d, &second);
    assert_eq!(reserve(&d, &second, 1_000, 500).json()["state"], "reserved");

    let reason = "provider: the provider answered 503";
    assert_eq!(settle_unavailable(&d, &first, reason).status, 200);
    assert_eq!(settle_unavailable(&d, &second, reason).status, 200);

    for id in [&first, &second] {
        let row = request(&d, id);
        assert_eq!(row.status, 200, "{}", row.text);
        assert_eq!(row.json()["state"], "settled");
        assert_eq!(row.json()["outcome"], "unavailable");
        assert_eq!(row.json()["reason"], reason);
    }
    // Settled is settled: the same settlement again is refused, never a second ending.
    assert_eq!(settle_unavailable(&d, &first, reason).status, 409);
    // Both delegations are dead, and the queue has nothing left for the process to pick up.
    for authorization in [&delegation, &second_delegation] {
        let after = evidence(&d, authorization);
        assert!(after.status == 401 || after.status == 403, "{}", after.text);
    }
    assert!(poll(&d).is_empty(), "a settled request stayed queued");
    assert_eq!(held(&d), 0, "a settled request still holds its reservation");
    unchanged(&d, &before);
}

// ---------------------------------------------------------------------------------------------
// Drill 2: a slow provider.
// ---------------------------------------------------------------------------------------------

/// The request's deadline ends it, the reservation is released, and the budget is usable again.
///
/// The drill does not wait ten minutes: it moves the request's deadline into the past, which is
/// what the clock does to it, and then drives the poll whose sweep is the one that ends it. The
/// proof of the release is two-fold: the reservation row is gone, and a later request of exactly
/// the same size is admitted against the same month.
#[test]
fn a_slow_provider_is_ended_by_the_deadline_and_releases_its_budget() {
    let d = deployment(ai::Budgets {
        monthly_tokens: 1_500,
        ..ai::Budgets::default()
    });
    let before = surfaces(&d);

    let first = ask(&d);
    claim(&d, &first);
    let reserved = reserve(&d, &first, 1_000, 500);
    assert_eq!(reserved.json()["state"], "reserved", "{}", reserved.text);
    assert_eq!(usage(&d)["reserved"]["input_tokens"], 1_000);
    assert_eq!(held(&d), 1);

    // The provider never answers and the deadline passes with the request still claimed.
    expire(&d, &first);
    // Before the sweep runs, the month is already free: a hold is counted only while it is live.
    assert_eq!(
        usage(&d)["reserved"]["input_tokens"],
        0,
        "an expired hold still counts against the month"
    );
    assert_eq!(usage(&d)["in_flight"], 0);

    assert!(poll(&d).is_empty(), "the expired request stayed queued");
    let row = request(&d, &first);
    assert_eq!(row.json()["state"], "settled");
    assert_eq!(row.json()["outcome"], "unavailable");
    assert_eq!(row.json()["reason"], "the request deadline passed");
    assert_eq!(held(&d), 0, "the sweep left the reservation behind");

    // The budget is usable again for exactly the request that could not get it before.
    let again = ask(&d);
    claim(&d, &again);
    let admitted = reserve(&d, &again, 1_000, 500);
    assert_eq!(admitted.json()["state"], "reserved", "{}", admitted.text);
    unchanged(&d, &before);
}

// ---------------------------------------------------------------------------------------------
// Drill 3: budget exhaustion.
// ---------------------------------------------------------------------------------------------

/// The refusal is immediate — the reserve call itself ends the request — the row settles
/// `unavailable` with the budget's reason, nothing is held, and nothing waits in the queue behind
/// it.
#[test]
fn an_exhausted_budget_refuses_at_once_and_queues_nothing() {
    let d = deployment(ai::Budgets {
        monthly_tokens: 1_200,
        ..ai::Budgets::default()
    });
    let before = surfaces(&d);

    let first = ask(&d);
    claim(&d, &first);
    assert_eq!(reserve(&d, &first, 800, 300).json()["state"], "reserved");

    // 1,100 of 1,200 tokens are held, and this one asks for 1,500 more.
    let second = ask(&d);
    let delegation = claim(&d, &second);
    let refused = reserve(&d, &second, 1_000, 500);
    assert_eq!(refused.status, 200, "{}", refused.text);
    let body = refused.json();
    assert_eq!(body["state"], "refused");
    assert!(
        body["reason"].as_str().unwrap().starts_with("budget: "),
        "{}",
        body["reason"]
    );
    // Refused in the write that refused it: the row is already settled, and nothing is held.
    assert_eq!(body["request"]["state"], "settled");
    assert_eq!(body["request"]["outcome"], "unavailable");
    assert_eq!(held(&d), 1, "a refusal held a second reservation");
    assert_eq!(request(&d, &second).json()["reason"], body["reason"]);
    // Its delegation died with the settlement, so the refused request can read no evidence either.
    let after = evidence(&d, &delegation);
    assert!(after.status == 401 || after.status == 403, "{}", after.text);

    // Nothing waits behind it: the only request in flight is the one that was reserved, and the
    // queue the next poll reads is empty, so no later request is left waiting for a decision.
    assert!(poll(&d).is_empty(), "a refusal left something queued");
    assert_eq!(usage(&d)["in_flight"], 1);
    assert_eq!(held(&d), 1);
    unchanged(&d, &before);
}

// ---------------------------------------------------------------------------------------------
// Drill 4: the tenant disabled while a request is being processed.
// ---------------------------------------------------------------------------------------------

/// The request ends, the delegation is revoked in the same write that turned the tenant off, and
/// the AI process cannot read the evidence afterwards — nor reserve, nor settle.
#[test]
fn a_disable_mid_processing_ends_the_request_and_revokes_its_delegation() {
    let d = deployment(ai::Budgets::default());
    let before = surfaces(&d);

    let id = ask(&d);
    let delegation = claim(&d, &id);
    assert_eq!(evidence(&d, &delegation).status, 200);
    assert_eq!(reserve(&d, &id, 1_000, 500).json()["state"], "reserved");
    assert_eq!(held(&d), 1);

    let ada = stepped_up(&d, "ada", ADMIN);
    let disabled = call(
        &d,
        "PUT",
        "/api/v1/tenants/acme/ai",
        Some(&json!({ "enabled": false, "data_policy": "local_only" })),
        &ada.headers(),
    );
    assert_eq!(disabled.status, 200, "{}", disabled.text);

    // The row is gone, its hold is gone, and the delegation it minted does not authenticate.
    let mia = sign_in(&d, "mia", MEMBER);
    let gone = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(gone.status, 404, "{}", gone.text);
    assert!(poll(&d).is_empty());
    assert_eq!(held(&d), 0, "the disable left the request's hold behind");
    assert_eq!(usage(&d)["reserved"]["input_tokens"], 0);
    let after = evidence(&d, &delegation);
    assert!(after.status == 401 || after.status == 403, "{}", after.text);

    // And the process's own calls end the request as unavailable rather than half-finishing it.
    assert_eq!(reserve(&d, &id, 1_000, 500).status, 404);
    assert_eq!(settle_unavailable(&d, &id, "provider: x").status, 404);
    unchanged(&d, &before);
}

// ---------------------------------------------------------------------------------------------
// Drill 5: `sentinel-ai` killed mid-request.
// ---------------------------------------------------------------------------------------------

/// The killed process's row ends `unavailable` at its deadline instead of staying claimed, its
/// reservation expires with that deadline, and a later request can use the budget.
///
/// Simulated leg: the kill. The process is represented by the claim it took and no settlement, which
/// is exactly what a `SIGKILL` leaves: a claimed row, a live hold, and nobody to end it.
#[test]
fn a_killed_ai_process_leaves_a_row_its_deadline_ends_and_a_free_budget() {
    let d = deployment(ai::Budgets {
        monthly_tokens: 1_500,
        ..ai::Budgets::default()
    });
    let before = surfaces(&d);

    let killed = ask(&d);
    claim(&d, &killed);
    assert_eq!(reserve(&d, &killed, 1_000, 500).json()["state"], "reserved");

    // The process dies here: nothing settles this request, and time passes its deadline.
    expire(&d, &killed);
    // What the kill leaves behind is still claimed — the row is not silently forgotten — and its
    // hold has already stopped counting against the month, so the queue can move on before anyone
    // sweeps it.
    let claimed = request(&d, &killed);
    assert_eq!(claimed.json()["state"], "claimed");
    assert_eq!(usage(&d)["reserved"]["input_tokens"], 0);

    // The next process to poll sweeps it: settled unavailable at its deadline, never claimed forever.
    assert!(poll(&d).is_empty());
    let row = request(&d, &killed);
    assert_eq!(row.json()["state"], "settled");
    assert_eq!(row.json()["outcome"], "unavailable");
    assert_eq!(row.json()["reason"], "the request deadline passed");
    assert_eq!(held(&d), 0);

    // And the budget it held is spendable by the next request, of the same size.
    let later = ask(&d);
    claim(&d, &later);
    let admitted = reserve(&d, &later, 1_000, 500);
    assert_eq!(admitted.json()["state"], "reserved", "{}", admitted.text);
    unchanged(&d, &before);
}

// ---------------------------------------------------------------------------------------------
// Drill 6: the invariant. With AI on and its provider failing, no deterministic surface moves.
// ---------------------------------------------------------------------------------------------

/// How this drill's AI is set: `Off` is a deployment that never opted in, `On` is a tenant that
/// opted in with automatic analysis, whose provider is down for every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ai {
    Off,
    On,
}

const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REF: &str = "refs/heads/main";
const INSTALLATION: u64 = 42;
const FORGE_REPO: u64 = 91;

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(3),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "drill".into(),
    }
}

const ONE_JOB: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

struct Seeded {
    tenant: TenantId,
    run: RunId,
    job: JobId,
    worker: WorkerId,
    enrollment: Secret,
    worker_identity: (std::path::PathBuf, std::path::PathBuf),
}

/// A tenant with a bound forge source, one run of one job whose checks are published, and a pool
/// with an enrollment for the worker that will carry the attempt.
fn seed(dir: &std::path::Path, key: &Arc<sentinel_auth::sealed::Key>, ai: Ai) -> Seeded {
    let key = Arc::clone(key);
    let store = Store::open(dir.join("metadata.sqlite"), Durability::Normal).unwrap();
    let now = UnixMillis::now();
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    let (run, worker) = (RunId::new(), WorkerId::new());
    let spec = sentinel_pipeline::RunSpec::new(
        sentinel_pipeline::PinnedSource::new("https://github.com/account/app.git", SHA, Some(REF))
            .unwrap(),
        sentinel_pipeline::compile_str(ONE_JOB).unwrap(),
    )
    .unwrap();
    let (job, enrollment) = store
        .writer()
        .write(move |tx| {
            let principal = Principal::new(root, P::ALL, None, None);
            provisioning::insert_human(tx, root, "root", true, now)?;
            let phc = sentinel_auth::password::hash(b"correct horse battery staple").unwrap();
            local_auth::provision_credential(tx, Authority::HostLocal, root, "root", &phc, now)?;
            auth::create_namespace(
                tx,
                principal,
                tenant,
                sentinel_core::auth::Namespace::parse("acme").unwrap(),
                sentinel_store::auth::NamespaceKind::Personal(root),
                now,
            )?;
            auth::set_membership(tx, principal, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, principal, tenant, repo, "app", now)?;
            auth::set_repo_grant(tx, principal, repo, root, P::REPOSITORY)?;
            let installation = sentinel_store::sources_forge::refresh(
                tx,
                sentinel_store::sources_forge::Snapshot {
                    external_id: INSTALLATION,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: sentinel_core::RunnerPermissions::ALL,
                    migration: sentinel_core::MigrationPermissions::ALL,
                    expected: 0,
                },
                now,
            )?;
            sentinel_store::registration::bind_installation_trusted(tx, installation, tenant, now)?;
            sentinel_store::sources::bind(
                tx,
                Authority::HostLocal,
                Some(root),
                sentinel_store::sources::Update {
                    repo,
                    expected: 0,
                    binding: &sentinel_protocol::source::Binding {
                        remote: "https://github.com/account/app.git".into(),
                        allowed_refs: vec![REF.into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &sentinel_protocol::source::Credential::Public,
                    forge: Some((installation, FORGE_REPO)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            runs::resolve_image(tx, tenant, ids[0], IMAGE, "linux/amd64")?;
            sentinel_store::provenance::insert(
                tx,
                &sentinel_store::provenance::Provenance {
                    tenant,
                    repo,
                    trigger: "push".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some(REF.into()),
                    old_sha: Some("0".repeat(40)),
                    new_sha: Some(SHA.into()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: SHA.into(),
                    pipeline_path: Some(".sentinel.yml".into()),
                    pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                    pr_number: None,
                    group_ref: None,
                },
                run,
                now,
            )?;
            sentinel_store::tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                sentinel_store::tenancy::PoolKind::Dedicated(tenant),
                now,
            )?;
            if ai == Ai::On {
                let mut providers = ai::Providers::NONE;
                providers.insert(ai::Provider::Local);
                ai::set_deployment(
                    tx,
                    Authority::Credential {
                        principal,
                        stepped_up: true,
                    },
                    ai::Deployment {
                        enabled: true,
                        providers,
                    },
                    now,
                )?;
                ai::set_tenant(
                    tx,
                    Authority::Credential {
                        principal,
                        stepped_up: true,
                    },
                    tenant,
                    ai::Tenant {
                        enabled: true,
                        data_policy: ai::DataPolicy::LocalOnly,
                        budgets: ai::Budgets::default(),
                        auto_analysis: true,
                    },
                    now,
                )?;
            }
            Ok((
                ids[0],
                sentinel_store::workers::issue_enrollment(
                    tx,
                    Authority::HostLocal,
                    pool,
                    3_600_000,
                    now,
                )?
                .secret,
            ))
        })
        .unwrap();
    let worker_identity = Identity::generate("worker").unwrap();
    let files = (dir.join("worker.crt"), dir.join("worker.key"));
    worker_identity.save(&files.0, &files.1).unwrap();
    Seeded {
        tenant,
        run,
        job,
        worker,
        enrollment,
        worker_identity: files,
    }
}

/// The executor for the drill: it takes the one offer and keeps the reporter the session hands it.
struct Rig {
    offers: std::sync::Mutex<Vec<sentinel_link::session::Offer>>,
    reporter: std::sync::Mutex<Option<sentinel_link::session::Reporter>>,
    acks: std::sync::Mutex<Vec<u64>>,
}

impl Rig {
    fn new() -> Arc<Rig> {
        Arc::new(Rig {
            offers: std::sync::Mutex::new(Vec::new()),
            reporter: std::sync::Mutex::new(None),
            acks: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl sentinel_link::session::Executor for Rig {
    fn offered(&self, offer: &sentinel_link::session::Offer) -> bool {
        self.offers.lock().unwrap().push(offer.clone());
        true
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.offers
            .lock()
            .unwrap()
            .iter()
            .map(|o| o.attempt)
            .collect()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, reporter: sentinel_link::session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, _: AttemptId, _: sentinel_link::session::JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, through: u64) {
        self.acks.lock().unwrap().push(through);
    }
    fn log_refused(&self, _: AttemptId) {}
    fn log_ended(&self, _: AttemptId) {}
}

struct Runner {
    handle: Arc<sentinel_link::worker::Handle>,
    thread: Option<std::thread::JoinHandle<sentinel_link::Result<()>>>,
    events: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Runner {
    fn start(
        addr: std::net::SocketAddr,
        seed: &Seeded,
        dir: &std::path::Path,
        rig: Arc<Rig>,
    ) -> Runner {
        let handle = Arc::new(sentinel_link::worker::Handle::new());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut secret = String::new();
        seed.enrollment.expose(&mut secret);
        let identity = Identity::load(&seed.worker_identity.0, &seed.worker_identity.1).unwrap();
        let server = Identity::load(&dir.join("controller.crt"), &dir.join("controller.key"))
            .unwrap()
            .fingerprint();
        let (worker, name) = (seed.worker, "builder-1".to_owned());
        let enrollment = Secret::parse(&secret).unwrap();
        let config = sentinel_link::worker::Config {
            controller: addr,
            server,
            also_pinned: Vec::new(),
            worker,
            name,
            hello: hello(),
            capacity: sentinel_link::session::Capacity {
                cpu_millis: 4_000,
                memory_bytes: 8 << 30,
            },
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: sentinel_link::session::TransportStats::default(),
            remote_cache: false,
        };
        let (grip, log) = (Arc::clone(&handle), Arc::clone(&events));
        let thread = std::thread::spawn(move || {
            sentinel_link::worker::run(config, identity, Some(enrollment), &*rig, &grip, &|event| {
                log.lock().unwrap().push(format!("{event:?}"));
            })
        });
        Runner {
            handle,
            thread: Some(thread),
            events,
        }
    }

    fn wait_for(&self, needle: &str, count: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.contains(needle))
            .count()
            < count
        {
            assert!(
                std::time::Instant::now() < deadline,
                "no {count}th {needle}: {:?}",
                self.events.lock().unwrap()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn stop(mut self) {
        self.handle.stop();
        let outcome = self.thread.take().unwrap().join().unwrap();
        assert!(outcome.is_ok(), "the worker loop ended: {outcome:?}");
    }
}

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !predicate() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// One scenario: a real worker carries a real attempt to its end, and with AI on a member asks
/// about it while it runs and again after it ends, the poll sweeps and queues the automatic
/// request, and every request settles `unavailable` because the provider is down.
fn scenario(passing: bool, ai: Ai) -> Surfaces {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let seed = seed(dir.path(), &key, ai);
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path().join("data")).unwrap());
    let identity = Identity::generate("controller").unwrap();
    let (crt, key_file) = (
        dir.path().join("controller.crt"),
        dir.path().join("controller.key"),
    );
    identity.save(&crt, &key_file).unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::load(&crt, &key_file).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = controller.local_addr();
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs: Arc::clone(&logs),
            objects,
            controller: controller.handle(),
            secret_key: Some(Arc::clone(&key)),
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
    let path = dir.path().to_path_buf();
    let mut deployment = Deployment {
        _dir: dir,
        store: Arc::clone(&store),
        _controller: controller,
        server: Some(server),
        base,
        tenant: seed.tenant,
        run: seed.run,
        job: seed.job,
        attempt: AttemptId::new(),
        service: String::new(),
    };
    if ai == Ai::On {
        deployment.service = service_grant(&store);
    }

    let rig = Rig::new();
    let runner = Runner::start(addr, &seed, &path, Arc::clone(&rig));
    runner.wait_for("Connected", 1);
    eventually("an offer", || !rig.offers.lock().unwrap().is_empty());
    let offer = rig.offers.lock().unwrap()[0].clone();
    let (attempt, fence) = (offer.attempt, offer.fence);
    deployment.attempt = attempt;
    eventually("an attached reporter", || {
        rig.reporter.lock().unwrap().is_some()
    });
    let reporter = rig.reporter.lock().unwrap().clone().unwrap();
    reporter.need_spec(attempt).unwrap();
    for seq in 1..=3 {
        reporter
            .log(
                attempt,
                &Frame {
                    seq,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes: format!("line {seq}\n").into_bytes(),
                },
            )
            .unwrap();
    }
    eventually("three acknowledged frames", || {
        rig.acks.lock().unwrap().last() == Some(&3)
    });
    reporter
        .report(attempt, fence, Event::StepsStarted)
        .unwrap();

    let mut asked = Vec::new();
    if ai == Ai::On {
        // The member asks while the attempt is still running: the request, its delegation, the
        // evidence read and the hold are the real routes, taken in the middle of the run.
        let id = ask_as(&deployment, "root", "correct horse battery staple");
        let delegation = claim(&deployment, &id);
        assert_eq!(evidence(&deployment, &delegation).status, 200);
        assert_eq!(
            reserve(&deployment, &id, 1_000, 500).json()["state"],
            "reserved"
        );
        asked.push(id);
    }

    for event in [
        Event::FinalizationStarted,
        if passing {
            Event::Passed
        } else {
            Event::Failed(sentinel_core::FailureClass::CommandFailed)
        },
    ] {
        reporter.report(attempt, fence, event).unwrap();
    }
    eventually("the terminal job", || {
        store
            .read(|c| jobs::get_job(c, seed.tenant, seed.job))
            .unwrap()
            .state
            .is_terminal()
    });
    runner.stop();

    if ai == Ai::On {
        // The poll the process runs: it sweeps and writes the automatic request a tenant asked for
        // about its failed job. Then the provider is down, so every request ends unavailable — and
        // the run's own surfaces, which were written before any of this, are what the drill compares.
        let queued = poll(&deployment);
        let expected = if passing { 1 } else { 2 };
        assert_eq!(
            rows(&store),
            expected,
            "the AI path did not run: {queued:?} queued"
        );
        asked.extend(queued);
        for id in &asked {
            let settled =
                settle_unavailable(&deployment, id, "provider: the provider answered 503");
            assert_eq!(settled.status, 200, "{}", settled.text);
        }
        assert!(poll(&deployment).is_empty(), "a request stayed queued");
        assert!(charged(&store), "the AI path charged nothing");
    }
    let surfaces = surfaces(&deployment);
    if let Some(server) = deployment.server.take() {
        server.shutdown();
    }
    surfaces
}

fn rows(store: &Arc<Store>) -> i64 {
    store
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM ai_requests", [], |r| {
                r.get::<_, i64>(0)
            })?)
        })
        .unwrap()
}

fn charged(store: &Arc<Store>) -> bool {
    store
        .read(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM ai_ledger", [], |r| r.get::<_, i64>(0))? > 0)
        })
        .unwrap()
}

/// The AI service's grant for the drill's deployment: `ai:context` and nothing else.
fn service_grant(store: &Arc<Store>) -> String {
    let service = UserId::new();
    let (store, service_copy) = (Arc::clone(store), service);
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, service_copy, "ai-service", true, UnixMillis::now())?;
            Ok(())
        })
        .unwrap();
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
    format!(
        "Bearer {}",
        sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Access, &granted.access)
    )
}

/// The gate: with AI on and its provider failing, every deterministic surface of a passing run and
/// of a failing run is identical to the same run with AI off. Both scenarios are driven twice, each
/// through a real controller, a real worker session and a real attempt.
#[test]
fn ai_on_and_failing_changes_no_deterministic_surface() {
    let off_failing = scenario(false, Ai::Off);
    let on_failing = scenario(false, Ai::On);
    assert_eq!(
        on_failing, off_failing,
        "AI changed a surface of a failing run"
    );
    assert_eq!(
        off_failing.jobs[0].0, "Terminal(Failed)",
        "the drill's own fixture did not fail"
    );
    assert_eq!(off_failing.conclusion.as_deref(), Some("failure"));
    // The surfaces the drill compares are not empty: a failing run publishes its job's check and
    // the run's own, and it has one attempt.
    assert_eq!(off_failing.checks.len(), 2, "{off_failing:?}");
    assert_eq!(off_failing.attempts.len(), 1, "{off_failing:?}");

    let off_passing = scenario(true, Ai::Off);
    let on_passing = scenario(true, Ai::On);
    assert_eq!(
        on_passing, off_passing,
        "AI changed a surface of a passing run"
    );
    assert_eq!(off_passing.jobs[0].0, "Terminal(Passed)");
    assert_eq!(off_passing.conclusion.as_deref(), Some("success"));
    assert_eq!(off_passing.checks.len(), 2, "{off_passing:?}");
}
