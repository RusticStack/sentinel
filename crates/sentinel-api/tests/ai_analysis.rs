//! Part 22 Y05 over HTTP: the failure analysis a request settles with, decoded against
//! `sentinel.ai-analysis/1`, its citations checked against the evidence the controller stored, and
//! shown under the deterministic failure summary as inference.
//!
//! The gate this binary proves is the citation's: an answer that does not decode is refused and
//! stored nowhere, a citation that names evidence the controller did not serve is dropped before
//! anyone sees it, and an answer whose every citation was dropped is not shown at all. The third
//! claim is the invariant: an analysis changes no run's state, no job's failure class and no
//! published check — the routes that compute those read nothing from here, and the test compares
//! them byte for byte before and after one is served.
//!
//! No provider is contacted: the AI process is represented by the credential it presents.

use std::sync::Arc;

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    analysis::{ANALYSIS_SCHEMA, Analysis},
    logs::{Frame, Stream},
    summary::{AttemptSummary, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store, ai,
    auth::{self, Authority, provisioning},
    checks, jobs, local_auth,
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
    tenant: TenantId,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    /// A job of another repository of the same tenant, which the requester cannot read.
    hidden_attempt: AttemptId,
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

/// A deployment whose one job ended `failed` with one attempt, one log frame and one Go test
/// diagnostic. `SCENARIOS` chooses what the two administrators decided.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// AI on for the deployment and the tenant, automatic analysis off.
    OptedIn,
    /// The same, with automatic analysis on: a failed job gets its own request.
    Automatic,
    /// The deployment allows AI and the tenant has not opted in.
    Off,
}

fn deployment(scenario: Scenario) -> Deployment {
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
            auth::set_repo_grant(tx, root, repo, service, P::READ)?;
            auth::set_repo_grant(tx, root, hidden_repo, admin, P::REPOSITORY)?;
            jobs::insert_run(tx, tenant, repo, run, "abc123", now)?;
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)?;
            // The job ended failed: what the sweep that writes an automatic request reads.
            tx.execute(
                "UPDATE jobs SET state_code = 20, failure_class = 0, terminal_ms = ?2
                  WHERE id = ?1",
                (job.as_bytes(), now.0),
            )?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                    repo_id, summary, released_ms, log_expires_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6, ?7, ?8)",
                (
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [9u8; 16],
                    repo.as_bytes(),
                    sealed.as_slice(),
                    now.0,
                    now.0 + 14 * 24 * 60 * 60 * 1000,
                ),
            )?;
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
            // The checks Sentinel publishes for this run, published before any analysis exists:
            // the job's own and the run's aggregate, as `checks::record_job` writes them.
            for (scope, name, conclusion, title, summary) in [
                (
                    job.to_string(),
                    checks::qualified_name("alpha"),
                    "failure",
                    "job failed",
                    "alpha failed",
                ),
                (
                    "aggregate".to_owned(),
                    checks::qualified_name("sentinel"),
                    "failure",
                    "run failed",
                    "the run failed",
                ),
            ] {
                tx.execute(
                    "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, scope, name,
                        head_sha, external_id, status, conclusion, title, summary, seq,
                        created_ms, updated_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'completed', ?9, ?10, ?11, 1,
                        ?12, ?12)",
                    (
                        sentinel_core::CheckId::new().as_bytes().as_slice(),
                        tenant.as_bytes(),
                        repo.as_bytes(),
                        run.as_bytes(),
                        scope.as_str(),
                        name.as_str(),
                        "abc123abc123abc123abc123abc123abc123abc1",
                        format!("sentinel:{scope}"),
                        conclusion,
                        title,
                        summary,
                        now.0,
                    ),
                )?;
            }
            for (user, name, password) in [(admin, "ada", ADMIN), (member, "mia", MEMBER)] {
                let phc = sentinel_auth::password::hash(password.as_bytes()).unwrap();
                local_auth::provision_credential(tx, Authority::HostLocal, user, name, &phc, now)?;
            }
            Ok(())
        })
        .unwrap();
    for (seq, text) in [
        (
            1,
            r#"{"Action":"run","Package":"example/pkg","Test":"TestCreate"}"#,
        ),
        (
            2,
            r#"{"Action":"output","Package":"example/pkg","Test":"TestCreate","Output":"create_test.go:42: wanted 201, got 500\n"}"#,
        ),
        (
            3,
            r#"{"Action":"fail","Package":"example/pkg","Test":"TestCreate"}"#,
        ),
    ] {
        logs.append(
            run,
            job,
            attempt,
            &Frame {
                seq,
                step: 0,
                stream: Stream::Stdout,
                // Go test JSON is one event per line: the parser and the detector both read lines.
                bytes: [text.as_bytes(), b"\n"].concat(),
            },
        )
        .unwrap();
    }

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
            if scenario != Scenario::Off {
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
                        budgets: ai::Budgets::default(),
                        auto_analysis: scenario == Scenario::Automatic,
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
        hidden_attempt,
        member,
        service,
    }
}

#[derive(Debug)]
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

/// One analysis, as a model's answer: every claim cites evidence of `attempt`.
fn answer(attempt: AttemptId, claims: &[(&str, &str)]) -> Value {
    json!({
        "schema": ANALYSIS_SCHEMA,
        "summary": "the unit step failed on an assertion",
        "claims": claims
            .iter()
            .map(|(text, evidence)| json!({
                "text": text,
                "citations": [{ "attempt": attempt.to_string(), "evidence": evidence }],
            }))
            .collect::<Vec<_>>(),
    })
}

/// A member asks about the attempt and the AI service claims it.
fn claimed(d: &Deployment, session: &Session, attempt: AttemptId) -> String {
    let asked = call(
        d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": attempt.to_string(), "provider": "local" })),
        &session.headers(),
    );
    assert_eq!(asked.status, 201, "{}", asked.text);
    let id = asked.json()["id"].as_str().unwrap().to_owned();
    let claimed = call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(claimed.status, 200, "{}", claimed.text);
    id
}

/// The AI service settles `id` with `analysis`.
fn settle(d: &Deployment, id: &str, analysis: &Value) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({ "outcome": "completed", "analysis": analysis })),
        &[("authorization", &d.service)],
    )
}

/// One analysis served for `attempt`, as a member who can read it reads it.
fn served(d: &Deployment, session: &Session, attempt: AttemptId) -> Reply {
    call(
        d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/ai-analysis"),
        None,
        &session.headers(),
    )
}

#[test]
fn an_analysis_is_shown_with_its_citations_resolved_and_labelled_inference() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    assert_eq!(served(&d, &mia, d.attempt).json()["reason"], "none");

    let id = claimed(&d, &mia, d.attempt);
    let settled = settle(
        &d,
        &id,
        &answer(
            d.attempt,
            &[
                ("the failing assertion wants 201 and got 500", "log-2"),
                ("the failure is the Create test", "diag-1"),
            ],
        ),
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    assert_eq!(settled.json()["analysis"]["schema"], ANALYSIS_SCHEMA);

    let body = served(&d, &mia, d.attempt);
    assert_eq!(body.status, 200, "{}", body.text);
    let body = body.json();
    assert_eq!(body["present"], true);
    assert_eq!(body["schema"], ANALYSIS_SCHEMA);
    assert_eq!(
        body["inference"], true,
        "an analysis is inference wherever it is shown"
    );
    assert_eq!(body["origin"], "member");
    assert_eq!(body["reused"], false);
    assert_eq!(body["summary"], "the unit step failed on an assertion");
    assert_eq!(body["dropped_citations"], 0);
    assert!(body["expires_ms"].as_i64().is_some());
    let claims = body["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 2);
    let log = &claims[0]["citations"][0];
    assert_eq!(log["evidence"], "log-2");
    assert_eq!(log["attempt"], d.attempt.to_string());
    assert_eq!(log["run"], d.run.to_string());
    assert_eq!(
        log["step"], 0,
        "the frame's own step, which is where the UI links"
    );
    assert_eq!(log["sequence"], 2);
    let diagnostic = &claims[1]["citations"][0];
    assert_eq!(diagnostic["evidence"], "diag-1");
    assert!(
        (1..=3).contains(&diagnostic["sequence"].as_u64().unwrap()),
        "a diagnostic points at the frame it was found in: {diagnostic:?}"
    );
    assert_eq!(
        diagnostic["step"], 0,
        "in the failed step, where the log page opens"
    );
}

#[test]
fn a_citation_that_does_not_resolve_is_dropped_before_the_answer_is_shown() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    let id = claimed(&d, &mia, d.attempt);
    let settled = settle(
        &d,
        &id,
        &answer(
            d.attempt,
            &[
                ("a frame the bundle never had", "log-900"),
                ("a diagnostic past the bundle's cap", "diag-9"),
                ("the assertion in the output", "log-2"),
            ],
        ),
    );
    assert_eq!(settled.status, 200, "{}", settled.text);

    let body = served(&d, &mia, d.attempt).json();
    assert_eq!(body["present"], true);
    assert_eq!(
        body["dropped_citations"], 2,
        "the two citations that name no stored evidence"
    );
    let claims = body["claims"].as_array().unwrap();
    assert_eq!(
        claims.len(),
        1,
        "a claim with nothing left to cite is dropped"
    );
    assert_eq!(claims[0]["citations"][0]["evidence"], "log-2");
}

#[test]
fn an_analysis_whose_every_citation_was_dropped_is_not_shown_at_all() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    let id = claimed(&d, &mia, d.attempt);
    settle(
        &d,
        &id,
        &answer(d.attempt, &[("a frame that does not exist", "log-900")]),
    );
    let body = served(&d, &mia, d.attempt);
    assert_eq!(body.status, 200, "{}", body.text);
    let body = body.json();
    assert_eq!(body["present"], false);
    assert_eq!(body["reason"], "dropped");
    assert_eq!(body["dropped_citations"], 1);
    assert!(
        body.get("claims").is_none(),
        "a claim nobody can check is not a finding"
    );
}

#[test]
fn a_citation_into_another_repository_never_resolves() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    // A stored answer about this attempt whose only citation names the hidden attempt: the same
    // tenant, another repository. It is not the reader's to follow, so it is dropped.
    let (tenant, repo, attempt, member) = (
        d.tenant,
        jobs_repo(&d, d.hidden_attempt),
        d.attempt,
        d.member,
    );
    let document = valid_document(d.hidden_attempt);
    let (row, now) = (sentinel_core::AiRequestId::new(), UnixMillis::now().0);
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO ai_requests(id, tenant_id, repo_id, attempt_id, requester_id,
                    requester_scopes, provider, data_policy, state_code, outcome, result,
                    origin, created_ms, deadline_ms, settled_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 3, 2, ?7, 1, ?8, ?9, ?8)",
                (
                    row.as_bytes().as_slice(),
                    tenant.as_bytes(),
                    repo.as_slice(),
                    attempt.as_bytes(),
                    member.as_bytes(),
                    Scopes::READ_ONLY.bits(),
                    document.as_str(),
                    now - 10,
                    now + 60_000,
                ),
            )?;
            Ok(())
        })
        .unwrap();
    let body = served(&d, &mia, d.attempt).json();
    assert_eq!(
        body["present"], false,
        "a claim about a log the reader cannot open is not shown"
    );
    assert_eq!(body["reason"], "dropped");
}

/// The repository of one attempt, for a row inserted directly.
fn jobs_repo(d: &Deployment, attempt: AttemptId) -> Vec<u8> {
    d.store
        .read(move |c| {
            let repo = sentinel_store::lookup::run_repo(
                c,
                sentinel_store::lookup::job_run(
                    c,
                    sentinel_store::lookup::attempt_job(c, attempt)?,
                )?,
            )?;
            Ok(repo.as_bytes().to_vec())
        })
        .unwrap()
}

/// A stored analysis document citing one frame of `attempt`.
fn valid_document(attempt: AttemptId) -> String {
    Analysis {
        summary: "the unit step failed".into(),
        claims: vec![sentinel_protocol::analysis::Claim {
            text: "the log says so".into(),
            citations: vec![sentinel_protocol::analysis::Citation {
                attempt,
                evidence: sentinel_protocol::analysis::Evidence::Log { sequence: 1 },
            }],
        }],
    }
    .encode()
}

#[test]
fn an_answer_that_does_not_decode_is_refused_and_stored_nowhere() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    let id = claimed(&d, &mia, d.attempt);

    // A claim with no citation, an unknown field, and a citation that names no bundle id: each is
    // refused with the field it failed on, and the row keeps its claim so the service can try again.
    let mut uncited = answer(d.attempt, &[("no evidence", "log-1")]);
    uncited["claims"][0]["citations"] = json!([]);
    let mut unknown = answer(d.attempt, &[("with a confidence", "log-1")]);
    unknown["claims"][0]["confidence"] = json!(0.9);
    let not_a_document = json!("the unit step failed");
    for (body, field) in [
        (uncited, "claims[].citations"),
        (unknown, "analysis"),
        (not_a_document, "analysis"),
    ] {
        let refused = settle(&d, &id, &body);
        assert_eq!(refused.status, 400, "{}", refused.text);
        assert_eq!(refused.json()["code"], "invalid_request");
        assert_eq!(
            refused.json()["details"]["field"],
            field,
            "{}",
            refused.text
        );
    }
    let row = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    let row = row.json();
    assert_eq!(row["state"], "claimed", "a refused answer settles nothing");
    assert!(row["analysis"].is_null());

    // The same request, answered properly, is what is stored.
    let settled = settle(
        &d,
        &id,
        &answer(d.attempt, &[("the assertion failed", "log-2")]),
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    let row = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(row.json()["analysis"]["schema"], ANALYSIS_SCHEMA);
    assert_eq!(
        row.json()["analysis"]["claims"][0]["citations"][0]["evidence"],
        "log-2"
    );
}

#[test]
fn an_analysis_changes_no_run_no_job_and_no_check() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    let before = conclusions(&d);
    assert_eq!(before.run_state, "Terminal(Failed)");
    assert_eq!(before.job_state, "failed");
    assert_eq!(before.failure_class.as_deref(), Some("command_failed"));
    assert_eq!(
        before.checks.len(),
        2,
        "the job's check and the run's aggregate"
    );

    let id = claimed(&d, &mia, d.attempt);
    settle(
        &d,
        &id,
        &answer(
            d.attempt,
            &[
                ("the assertion wants 201 and got 500", "log-2"),
                ("the Create test is what failed", "diag-1"),
            ],
        ),
    );
    let shown = served(&d, &mia, d.attempt).json();
    assert_eq!(shown["present"], true, "an analysis was served");
    assert_eq!(
        conclusions(&d),
        before,
        "nothing it says reached a conclusion"
    );
}

/// Everything a conclusion is computed from, as one comparable value.
#[derive(Debug, PartialEq, Eq)]
struct Conclusions {
    run_state: String,
    job_state: String,
    failure_class: Option<String>,
    checks: Vec<(String, Option<String>, String, String)>,
}

fn conclusions(d: &Deployment) -> Conclusions {
    let (tenant, run, job) = (d.tenant, d.run, d.job);
    d.store
        .read(move |c| {
            let run_state = jobs::run_state(c, tenant, run)?;
            let job = jobs::get_job(c, tenant, job)?;
            let checks = checks::of_run(c, tenant, run)?
                .into_iter()
                .map(|publication| {
                    (
                        publication.name.clone(),
                        publication.conclusion.map(|c| c.as_str().to_owned()),
                        format!("{:?}", publication.status),
                        publication.summary.clone(),
                    )
                })
                .collect();
            Ok(Conclusions {
                run_state: format!("{run_state:?}"),
                job_state: job.state.as_str().to_owned(),
                failure_class: job.failure_class.map(|class| class.as_str().to_owned()),
                checks,
            })
        })
        .unwrap()
}

#[test]
fn an_analysis_expires_with_the_logs_it_cites() {
    let d = deployment(Scenario::OptedIn);
    let mia = sign_in(&d, "mia", MEMBER);
    let id = claimed(&d, &mia, d.attempt);
    settle(
        &d,
        &id,
        &answer(d.attempt, &[("the assertion failed", "log-2")]),
    );
    // The attempt's log is kept for an hour: the analysis may not outlive it.
    let retention = UnixMillis::now().0 + 60 * 60 * 1000;
    let attempt = d.attempt;
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expires_ms = ?2 WHERE id = ?1",
                (attempt.as_bytes(), retention),
            )?;
            Ok(())
        })
        .unwrap();
    let body = served(&d, &mia, d.attempt).json();
    assert_eq!(body["present"], true);
    assert_eq!(body["expires_ms"], retention);

    // Retention removes the log: the citation it named resolves to nothing, so nothing is shown.
    let attempt = d.attempt;
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expired_ms = ?2 WHERE id = ?1",
                (attempt.as_bytes(), retention),
            )?;
            Ok(())
        })
        .unwrap();
    let body = served(&d, &mia, d.attempt).json();
    assert_eq!(body["present"], false);
    assert_eq!(body["reason"], "dropped");
}

#[test]
fn ai_off_shows_no_analysis_and_asks_nothing() {
    let d = deployment(Scenario::Off);
    let mia = sign_in(&d, "mia", MEMBER);
    let body = served(&d, &mia, d.attempt);
    assert_eq!(body.status, 200, "{}", body.text);
    assert_eq!(body.json()["present"], false);
    assert_eq!(body.json()["reason"], "off");
    // The evidence bundle Y05 reads is refused too, so no answer could have been computed anyway.
    let bundle = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/ai-context", d.attempt),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(bundle.status, 403, "{}", bundle.text);
    assert_eq!(bundle.json()["details"]["ai"], "off");
}

#[test]
fn another_tenants_analysis_is_not_found_and_a_reader_without_the_repository_is_refused() {
    let d = deployment(Scenario::OptedIn);
    // The hidden attempt is in a repository Mia cannot read: its analysis is not hers to see either.
    assert_eq!(
        served(&d, &sign_in(&d, "mia", MEMBER), d.hidden_attempt).status,
        404
    );
    // And an attempt that does not exist is the same answer.
    assert_eq!(
        served(&d, &sign_in(&d, "mia", MEMBER), AttemptId::new()).status,
        404
    );
}

#[test]
fn the_services_poll_writes_the_automatic_request_for_a_failed_job() {
    let d = deployment(Scenario::Automatic);
    // The member asks nothing. The poll is the sweep, and it is what writes the row.
    let queue = call(
        &d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(queue.status, 200, "{}", queue.text);
    let rows = queue.json()["requests"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 1, "{queue:?}");
    assert_eq!(rows[0]["attempt"], d.attempt.to_string());
    assert_eq!(rows[0]["origin"], "automatic");
    assert_eq!(rows[0]["provider"], "local");
    // One failure is one request however often the poll runs.
    call(
        &d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    let again = call(
        &d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(again.json()["requests"].as_array().unwrap().len(), 1);
    // A member's own request is a second row, because it is a second question with its own origin.
    let mia = sign_in(&d, "mia", MEMBER);
    let asked = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": d.attempt.to_string(), "provider": "local" })),
        &mia.headers(),
    );
    assert_eq!(asked.status, 201, "{}", asked.text);
    assert_eq!(asked.json()["origin"], "member");
    let rows = call(
        &d,
        "GET",
        "/api/v1/ai/requests?limit=8",
        None,
        &[("authorization", &d.service)],
    );
    let origins: Vec<String> = rows.json()["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["origin"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(origins, ["automatic", "member"]);
}
