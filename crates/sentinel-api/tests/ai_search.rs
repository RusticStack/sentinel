//! Part 22 Y07 over HTTP: a log-search question becomes a bounded plan of the reads the controller
//! already serves, executed under the requester's own delegation, and an answer is shown only when
//! it cites a line this repository's logs hold.
//!
//! The gate this binary proves is fourfold. A plan is executed as the requester, so a read naming
//! another repository's attempt is refused and a search never leaves the request's repository. A
//! plan past its reads, its needle, its run window, its match count or its result bytes is refused
//! with a reason — refused, never truncated — and the request ends `unavailable` in the same write.
//! An answer whose every citation resolves to nothing is refused at the moment it is stored, so no
//! reader can be shown one. And the cost bound stays where Y04 put it: a question whose reservation
//! does not fit its tenant's cap is refused before any provider could be contacted.
//!
//! No provider is contacted: the AI process is represented by the credentials it presents, and the
//! model's two answers — the plan and the analysis — are documents this test writes itself.

use std::sync::Arc;

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    analysis::ANALYSIS_SCHEMA,
    logs::{Frame, Stream},
    plan::PLAN_SCHEMA,
    summary::{AttemptSummary, StepOutcome, StepRecord},
};
use sentinel_store::{
    Durability, Store, ai,
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

/// A frame the fixture's visible attempt holds, and the literal one search is asked for.
const NEEDLE: &str = "wanted 201";

struct Deployment {
    _dir: tempfile::TempDir,
    _store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    attempt: AttemptId,
    /// An attempt of another repository of the same tenant, which the requester cannot read.
    hidden_attempt: AttemptId,
    service: String,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

/// How many log frames the visible attempt holds beyond its Go test diagnostic, and what the one
/// tenant may spend. `burst` is what makes a plan's results exceed their own byte bound.
#[derive(Default)]
struct Burden {
    burst: usize,
    budgets: ai::Budgets,
}

fn deployment(burden: Burden) -> Deployment {
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
    let budgets = burden.budgets;
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
                bytes: [text.as_bytes(), b"\n"].concat(),
            },
        )
        .unwrap();
    }
    // Frames the search finds in bulk, each carrying the needle: a plan of six reads over them
    // asks for more result bytes than one plan may hold.
    for at in 0..burden.burst {
        logs.append(
            run,
            job,
            attempt,
            &Frame {
                seq: 4 + at as u64,
                step: 0,
                stream: Stream::Stdout,
                bytes: [format!("{NEEDLE}: burst line {at} {}\n", "x".repeat(512)).as_bytes()]
                    .concat(),
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
                    auto_analysis: false,
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
        _store: store,
        _controller: controller,
        server: Some(server),
        base,
        attempt,
        hidden_attempt,
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

/// A question as the plan that answers it: one literal search over the repository's one run.
fn plan(reads: Value) -> Value {
    json!({ "schema": PLAN_SCHEMA, "reads": reads })
}

fn search(needle: &str, runs: u16, limit: u16) -> Value {
    json!({ "kind": "search", "q": needle, "runs": runs, "limit": limit })
}

fn context(attempt: AttemptId) -> Value {
    json!({ "kind": "context", "attempt": attempt.to_string() })
}

/// One analysis, as a model's answer: every claim cites `attempt`'s evidence `evidence`.
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

/// A member asks `question` about the fixture's attempt and the AI service claims it.
fn asked(d: &Deployment, session: &Session, question: &str) -> (String, String) {
    let asked = call(
        d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({
            "attempt": d.attempt.to_string(),
            "provider": "local",
            "question": question,
        })),
        &session.headers(),
    );
    assert_eq!(asked.status, 201, "{}", asked.text);
    assert_eq!(asked.json()["kind"], "search");
    assert_eq!(asked.json()["question"], question);
    let id = asked.json()["id"].as_str().unwrap().to_owned();
    let claimed = call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    assert_eq!(claimed.status, 200, "{}", claimed.text);
    let token = claimed.json()["token"]["access"]
        .as_str()
        .unwrap()
        .to_owned();
    (id, token)
}

/// Executes `plan` for `id` under the request's delegation, as the AI process does.
fn execute(d: &Deployment, id: &str, delegation: &str, plan: &Value) -> Reply {
    call(
        d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/plan"),
        Some(plan),
        &[("authorization", &format!("Bearer {delegation}"))],
    )
}

#[test]
fn a_question_is_answered_from_lines_the_plan_read_and_its_citation_resolves_to_one() {
    let d = deployment(Burden::default());
    let mia = sign_in(&d, "mia", MEMBER);
    let (id, delegation) = asked(&d, &mia, "Why did the create test fail with a 500?");

    let executed = execute(
        &d,
        &id,
        &delegation,
        &plan(json!([search(NEEDLE, 1, 10), context(d.attempt)])),
    );
    assert_eq!(executed.status, 200, "{}", executed.text);
    let body = executed.json();
    assert_eq!(body["state"], "ready");
    let results = &body["results"];
    assert_eq!(results["schema"], "sentinel.ai-search/1");
    assert_eq!(
        results["question"],
        "Why did the create test fail with a 500?"
    );
    let search_read = &results["reads"][0];
    assert_eq!(search_read["kind"], "search");
    assert_eq!(search_read["runs"], 1);
    assert_eq!(search_read["truncated"], false);
    let lines = search_read["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 1, "{}", executed.text);
    assert_eq!(lines[0]["attempt"], d.attempt.to_string());
    assert_eq!(lines[0]["evidence"], "log-2");
    assert_eq!(lines[0]["sequence"], 2);
    assert_eq!(lines[0]["step"], 0);
    assert_eq!(lines[0]["stream"], "stdout");
    assert!(lines[0]["text"].as_str().unwrap().contains(NEEDLE));
    // The context read is the same bundle the evidence route would serve, at the plan's own bound.
    let read = &results["reads"][1];
    assert_eq!(read["kind"], "context");
    assert_eq!(read["bundle"]["schema"], "sentinel.ai-context/1");
    assert_eq!(read["bundle"]["attempt"], d.attempt.to_string());
    assert!(
        read["bundle"]["bounds"]["budget_bytes"]
            .as_u64()
            .unwrap()
            .le(&8192)
    );
    assert_eq!(results["bounds"]["reads"], 2);
    assert!(results["bounds"]["bytes"].as_u64().unwrap() > 0);

    // The answer cites the line the search returned; the controller resolves it and serves it.
    let settled = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({
            "outcome": "completed",
            "analysis": answer(d.attempt, &[("the assertion wanted 201 and got 500", "log-2")]),
        })),
        &[("authorization", &d.service)],
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    assert_eq!(settled.json()["outcome"], "completed");
    let served = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(served.status, 200, "{}", served.text);
    let served = served.json();
    assert_eq!(served["present"], true);
    assert_eq!(served["inference"], true);
    assert_eq!(served["dropped_citations"], 0);
    let citation = &served["claims"][0]["citations"][0];
    assert_eq!(citation["evidence"], "log-2");
    assert_eq!(citation["attempt"], d.attempt.to_string());
    assert_eq!(citation["sequence"], 2);
    assert!(
        citation["run"].as_str().is_some(),
        "a citation links its run"
    );
    assert!(citation["step"].as_u64().is_some(), "and the step it is in");
}

#[test]
fn an_answer_whose_citations_resolve_to_nothing_is_refused_rather_than_shown() {
    let d = deployment(Burden::default());
    let mia = sign_in(&d, "mia", MEMBER);
    let (id, delegation) = asked(&d, &mia, "Which line failed?");
    let executed = execute(&d, &id, &delegation, &plan(json!([search(NEEDLE, 1, 10)])));
    assert_eq!(executed.status, 200, "{}", executed.text);

    // A model that invents its evidence: a frame past the log's end, and a diagnostic the bundle
    // never numbered. Neither resolves, so the answer is refused and the request ends unavailable.
    let settled = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/complete"),
        Some(&json!({
            "outcome": "completed",
            "analysis": answer(d.attempt, &[
                ("the log says the test passed", "log-999"),
                ("the assertion is reported twice", "diag-9"),
            ]),
        })),
        &[("authorization", &d.service)],
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    let settled = settled.json();
    assert_eq!(settled["outcome"], "unavailable");
    assert_eq!(
        settled["reason"],
        "citation: no claim cites evidence this repository's logs hold"
    );
    assert_eq!(settled["analysis"], Value::Null);

    let served = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    let served = served.json();
    assert_eq!(served["present"], false);
    assert_eq!(
        served["analysis"],
        Value::Null,
        "an uncited answer is stored nowhere"
    );

    // The same answer about an attempt of another repository resolves to nothing either: a search
    // answer is checked against the repository it was asked about.
    let (other, delegation) = asked(&d, &mia, "Which line failed?");
    let executed = execute(
        &d,
        &other,
        &delegation,
        &plan(json!([search(NEEDLE, 1, 10)])),
    );
    assert_eq!(executed.status, 200, "{}", executed.text);
    let settled = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{other}/complete"),
        Some(&json!({
            "outcome": "completed",
            "analysis": answer(d.hidden_attempt, &[("the other repository failed", "log-1")]),
        })),
        &[("authorization", &d.service)],
    );
    assert_eq!(settled.status, 200, "{}", settled.text);
    assert_eq!(settled.json()["outcome"], "unavailable");
}

#[test]
fn a_plan_past_its_reads_needle_window_matches_or_bytes_is_refused_with_its_reason() {
    let d = deployment(Burden {
        burst: 200,
        budgets: ai::Budgets::default(),
    });
    let mia = sign_in(&d, "mia", MEMBER);

    // Six reads is the bound; a seventh is refused before any of them runs.
    let (id, delegation) = asked(&d, &mia, "How many times did this fail?");
    let mut reads = vec![context(d.attempt); 7];
    reads[0] = search(NEEDLE, 1, 5);
    let executed = execute(&d, &id, &delegation, &plan(json!(reads)));
    assert_eq!(executed.status, 200, "{}", executed.text);
    let body = executed.json();
    assert_eq!(body["state"], "refused");
    assert_eq!(body["field"], "reads");
    assert_eq!(
        body["reason"],
        "plan: the plan names a read this build cannot execute"
    );
    assert_eq!(body["request"]["state"], "settled");
    assert_eq!(body["request"]["outcome"], "unavailable");

    // A read past its needle, its run window or its match count, and a document with a field this
    // build does not execute: each is refused whole, with the field named.
    for (bad, field) in [
        (json!([search(&"n".repeat(257), 1, 5)]), "reads[].q"),
        (json!([search(NEEDLE, 0, 5)]), "reads[].runs"),
        (json!([search(NEEDLE, 101, 5)]), "reads[].runs"),
        (json!([search(NEEDLE, 1, 26)]), "reads[].limit"),
        (json!([search(NEEDLE, 1, 0)]), "reads[].limit"),
        (
            json!([{ "kind": "search", "q": NEEDLE, "runs": 1, "limit": 5, "grep": "-i" }]),
            "plan",
        ),
        (json!([{ "kind": "artifact", "id": "a" }]), "plan"),
    ] {
        let (id, delegation) = asked(&d, &mia, "Did this happen before?");
        let executed = execute(&d, &id, &delegation, &plan(bad.clone()));
        assert_eq!(executed.status, 200, "{} :: {executed:?}", executed.text);
        let body = executed.json();
        assert_eq!(body["state"], "refused", "{bad}");
        assert_eq!(body["field"], field, "{bad}");
        assert_eq!(body["request"]["outcome"], "unavailable", "{bad}");
    }

    // Six reads that each find 25 long lines exceed the document the plan may serve; the plan is
    // refused rather than served shortened, and the request ends with that reason.
    let (id, delegation) = asked(&d, &mia, "Show me every burst line.");
    let reads: Vec<Value> = (0..6).map(|_| search(NEEDLE, 1, 25)).collect();
    let executed = execute(&d, &id, &delegation, &plan(json!(reads)));
    assert_eq!(executed.status, 200, "{}", executed.text);
    let body = executed.json();
    assert_eq!(body["state"], "refused", "{}", executed.text);
    assert_eq!(
        body["reason"],
        "bounds: the plan's results exceed 65536 bytes"
    );
    assert_eq!(body["request"]["outcome"], "unavailable");
}

#[test]
fn a_plan_naming_a_read_the_requester_cannot_perform_is_refused() {
    let d = deployment(Burden::default());
    let mia = sign_in(&d, "mia", MEMBER);
    let (id, delegation) = asked(&d, &mia, "What did the other repository's job do?");

    // The delegation is the member's own identity: another repository's attempt is not a read it can
    // perform, and the refusal names the read rather than skipping it.
    let executed = execute(
        &d,
        &id,
        &delegation,
        &plan(json!([context(d.hidden_attempt)])),
    );
    assert_eq!(executed.status, 200, "{}", executed.text);
    let body = executed.json();
    assert_eq!(body["state"], "refused");
    assert_eq!(body["field"], "plan[1]");
    assert_eq!(
        body["reason"],
        "plan: a read names an attempt this repository does not hold"
    );
    assert_eq!(body["request"]["outcome"], "unavailable");
    assert!(
        !executed.text.contains("internal"),
        "the refusal names no repository: {}",
        executed.text
    );

    // The same attempt is refused to the delegation on the evidence route, which is what makes the
    // plan's refusal a property of the credential and not of the plan route alone.
    let direct = call(
        &d,
        "GET",
        &format!("/api/v1/attempts/{}/ai-context", d.hidden_attempt),
        None,
        &[("authorization", &format!("Bearer {delegation}"))],
    );
    assert_ne!(direct.status, 200, "{}", direct.text);

    // The refusal settled the request, and settling revokes its delegation in the same write: the
    // credential the refusal was answered to no longer authenticates at all, and the service grant
    // is told the request is no longer live.
    let again = execute(&d, &id, &delegation, &plan(json!([search(NEEDLE, 1, 5)])));
    assert_eq!(again.status, 401, "{}", again.text);
    let again = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/plan"),
        Some(&plan(json!([search(NEEDLE, 1, 5)]))),
        &[("authorization", &d.service)],
    );
    assert_eq!(again.status, 409, "{}", again.text);

    // The service grant may still execute a live plan, and another tenant's request is not found.
    let (id, delegation) = asked(&d, &mia, "Which line failed?");
    let by_grant = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/plan"),
        Some(&plan(json!([search(NEEDLE, 1, 5)]))),
        &[("authorization", &d.service)],
    );
    assert_eq!(by_grant.status, 200, "{}", by_grant.text);
    assert_eq!(by_grant.json()["state"], "ready");
    let _ = delegation;

    // An analysis request is not a log search: the plan route refuses the wrong kind outright.
    let analysis = call(
        &d,
        "POST",
        "/api/v1/tenants/acme/ai/requests",
        Some(&json!({ "attempt": d.attempt.to_string(), "provider": "local" })),
        &mia.headers(),
    );
    assert_eq!(analysis.status, 201, "{}", analysis.text);
    assert_eq!(analysis.json()["kind"], "analysis");
    assert_eq!(analysis.json()["question"], Value::Null);
    let id = analysis.json()["id"].as_str().unwrap().to_owned();
    let claimed = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/claim"),
        None,
        &[("authorization", &d.service)],
    );
    let delegation = claimed.json()["token"]["access"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = execute(&d, &id, &delegation, &plan(json!([search(NEEDLE, 1, 5)])));
    assert_eq!(refused.status, 400, "{}", refused.text);
}

#[test]
fn the_cost_bound_refuses_a_question_before_any_provider_could_be_contacted() {
    let d = deployment(Burden {
        burst: 0,
        budgets: ai::Budgets {
            max_input_tokens: 1,
            ..ai::Budgets::default()
        },
    });
    let mia = sign_in(&d, "mia", MEMBER);
    let (id, _delegation) = asked(&d, &mia, "Which line failed?");
    // What the AI process holds for a question and its plan: both prompts and the model's cap.
    let reserved = call(
        &d,
        "POST",
        &format!("/api/v1/ai/requests/{id}/reserve"),
        Some(&json!({
            "input_tokens": 4096,
            "output_tokens": 1024,
            "cost_micros": 100,
            "digest": "a".repeat(64),
            "fingerprint": "b".repeat(64),
            "prompt_version": "search-1",
            "model": "local/test",
        })),
        &[("authorization", &d.service)],
    );
    assert_eq!(reserved.status, 200, "{}", reserved.text);
    let body = reserved.json();
    let reserved = body;
    assert_eq!(reserved["state"], "refused");
    assert!(
        reserved["reason"]
            .as_str()
            .unwrap()
            .starts_with("per_request:"),
        "{reserved:?}"
    );
    assert_eq!(reserved["request"]["outcome"], "unavailable");
    // The refusal settled the row, so the question is never queued for a deadline to notice.
    let served = call(
        &d,
        "GET",
        &format!("/api/v1/ai/requests/{id}"),
        None,
        &mia.headers(),
    );
    assert_eq!(served.json()["state"], "settled");
    assert_eq!(served.json()["outcome"], "unavailable");
}
