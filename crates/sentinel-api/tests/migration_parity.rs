//! The migration parity route: each job pair of a migration compared over the commits it ran on,
//! with what Sentinel recorded beside what the Actions pages stated — and the read path's own
//! authorization and bounds.

use std::sync::Arc;

use sentinel_core::{
    CheckId, JobId, RepoId, RunId, TenantId, UnixMillis,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind},
    checks, local_auth,
    logs::LogStore,
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    repo: RepoId,
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
    let (tenant, repo, other) = (TenantId::new(), RepoId::new(), TenantId::new());
    let bound_repo = repo;
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
            name: "parity",
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
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::new(Objects::open(dir.path()).unwrap()),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let api_key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs,
        objects: Arc::new(Objects::open(dir.path()).unwrap()),
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
        repo: bound_repo,
    }
}

/// One commit the migration shadowed: a run whose job took `duration_ms` from its lease, and the
/// check Sentinel published for it. `conclusion` is what the copy concluded.
fn shadow(d: &Deployment, sha: &str, duration_ms: i64, conclusion: &str) -> (RunId, JobId) {
    let (run, job) = (RunId::new(), JobId::new());
    let (tenant, repo) = (d.tenant, d.repo);
    let (scope, name) = (job.to_string(), checks::qualified_name("build"));
    let external = format!("{run}:{scope}");
    let (source, sha) = (sha.to_owned(), sha.to_owned());
    let conclusion = conclusion.to_owned();
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms)
                 VALUES(?1, ?2, ?3, ?4, 1000)",
                (run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), source.as_str()),
            )?;
            tx.execute(
                "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq,
                                  repo_id, spec_index, leased_ms, terminal_ms)
                 VALUES(?1, ?2, ?3, 'build', 6, 0, 0, ?4, 0, 1000, ?5)",
                (
                    job.as_bytes(),
                    tenant.as_bytes(),
                    run.as_bytes(),
                    repo.as_bytes(),
                    1000 + duration_ms,
                ),
            )?;
            tx.execute(
                "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, scope, name, head_sha,
                                                external_id, status, conclusion, title, summary, seq,
                                                published_seq, attempts, state, created_ms,
                                                updated_ms, settled_ms)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'completed', ?9, 'Passed', 'job passed',
                        1, 1, 0, 1, 1000, 1000, 1000)",
                (
                    CheckId::new().as_bytes(),
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    run.as_bytes(),
                    scope.as_str(),
                    name.as_str(),
                    sha.as_str(),
                    external.as_str(),
                    conclusion.as_str(),
                ),
            )?;
            Ok(())
        })
        .unwrap();
    (run, job)
}

/// The Actions jobs page a run's jobs came from: the original the GitHub runner ran.
fn page(jobs: Value) -> Value {
    json!({ "total_count": jobs.as_array().map_or(0, Vec::len), "jobs": jobs })
}

fn original(id: u64, sha: &str, conclusion: &str, duration_ms: u64) -> Value {
    json!({
        "id": id,
        "run_id": 9000,
        "name": "build",
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "labels": ["ubuntu-latest"],
        "started_at": "2026-11-02T10:00:00Z",
        "completed_at": format!("2026-11-02T10:{:02}:{:02}Z", duration_ms / 60_000, (duration_ms / 1_000) % 60),
        "steps": [{"name": "Run tests", "status": "completed", "conclusion": "success", "number": 2}]
    })
}

fn pairs(shas: &[&str]) -> Value {
    json!(
        shas.iter()
            .map(|sha| json!({"sha": sha, "original": "build", "shadow": "sentinel / build"}))
            .collect::<Vec<_>>()
    )
}

fn junit(failures: usize) -> String {
    let mut cases = String::new();
    for index in 0..3 {
        if index < failures {
            cases.push_str(&format!(
                "<testcase name=\"Test{index}\"><failure message=\"broken\"/></testcase>"
            ));
        } else {
            cases.push_str(&format!("<testcase name=\"Test{index}\"/>"));
        }
    }
    format!("<testsuite>{cases}</testsuite>")
}

fn side_tests(sha: &str, job: &str, failures: usize) -> Value {
    json!({ "sha": sha, "job": job, "format": "junit_xml", "report": junit(failures) })
}

struct Answer {
    status: u16,
    body: Value,
}

fn post(d: &Deployment, body: &Value, auth: Option<&str>) -> Answer {
    let url = format!("{}/api/v1/tenants/acme/repos/app/migration/parity", d.base);
    let mut request = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
    .post(&url);
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let mut response = request
        .header("content-type", "application/json")
        .send(body.to_string())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap();
    Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

fn call(d: &Deployment, body: &Value) -> Answer {
    post(d, body, Some(&format!("Bearer {}", d.token)))
}

#[test]
fn a_matching_pair_and_a_differing_one_are_both_reported() {
    let d = deployment();
    shadow(&d, SHA_A, 60_000, "success");
    shadow(&d, SHA_B, 150_000, "success");
    let body = json!({
        "pairs": pairs(&[SHA_A, SHA_B]),
        "actions": [page(json!([
            original(11, SHA_A, "success", 60_000),
            original(12, SHA_B, "success", 60_000),
        ]))],
        "tests": [
            side_tests(SHA_A, "build", 0),
            side_tests(SHA_A, "sentinel / build", 0),
            side_tests(SHA_B, "build", 0),
            side_tests(SHA_B, "sentinel / build", 0),
        ],
    });
    let answer = call(&d, &body);
    assert_eq!(answer.status, 200, "{}", answer.body);
    let body = &answer.body;
    assert_eq!(body["schema"], "sentinel.migration-parity/1");
    assert_eq!(body["shadow_prefix"], "sentinel / ");
    let pairs = body["pairs"].as_array().unwrap();
    assert_eq!(pairs.len(), 2);

    // The copy took the same time as the original and concluded the same way: a match.
    assert_eq!(pairs[0]["sha"], SHA_A);
    assert_eq!(pairs[0]["mode"], "native");
    assert_eq!(pairs[0]["verdict"], "match");
    assert_eq!(pairs[0]["mismatches"], json!([]));
    assert_eq!(pairs[0]["original"]["conclusion"], "success");
    assert_eq!(pairs[0]["original"]["duration_ms"], 60_000);
    assert_eq!(pairs[0]["shadow_side"]["duration_ms"], 60_000);
    assert_eq!(
        pairs[0]["original"]["tests"],
        json!({"format": "junit_xml", "total": 3, "failed": 0, "skipped": 0})
    );

    // The same copy took twice the original's time: the pair is a mismatch and says what differs.
    assert_eq!(pairs[1]["sha"], SHA_B);
    assert_eq!(pairs[1]["verdict"], "mismatch");
    assert_eq!(pairs[1]["mismatches"], json!(["duration"]));
    assert_eq!(pairs[1]["shadow_side"]["duration_ms"], 150_000);

    let jobs = body["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["job"], "build");
    assert_eq!(jobs[0]["samples"], 2);
    assert_eq!(
        (jobs[0]["matched"].clone(), jobs[0]["mismatched"].clone()),
        (json!(1), json!(1))
    );
    assert_eq!(jobs[0]["original"]["p50_ms"], 60_000);
    assert_eq!(jobs[0]["shadow"]["p50_ms"], 60_000);
    assert_eq!(jobs[0]["shadow"]["p95_ms"], 150_000);
    assert_eq!(body["unpaired"], json!([]));
}

#[test]
fn a_job_with_no_test_reports_says_so_instead_of_matching_zero() {
    let d = deployment();
    shadow(&d, SHA_A, 60_000, "failure");
    let body = json!({
        "pairs": pairs(&[SHA_A]),
        "actions": [page(json!([original(11, SHA_A, "failure", 60_000)]))],
    });
    let answer = call(&d, &body);
    assert_eq!(answer.status, 200, "{}", answer.body);
    let pair = &answer.body["pairs"][0];
    assert_eq!(pair["verdict"], "mismatch");
    assert_eq!(pair["mismatches"], json!(["tests_unreported"]));
    assert_eq!(pair["original"]["tests"], Value::Null);
    assert_eq!(pair["shadow_side"]["tests"], Value::Null);
    assert_eq!(answer.body["jobs"][0]["mismatched"], 1);
}

#[test]
fn a_copy_no_pair_names_is_listed_and_a_malformed_page_is_refused() {
    let d = deployment();
    shadow(&d, SHA_A, 60_000, "success");
    // The report names no pair at all, so the copy Sentinel ran is listed rather than dropped.
    let answer = call(
        &d,
        &json!({
            "pairs": [],
            "actions": [page(json!([original(11, SHA_A, "success", 60_000)]))],
        }),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(
        answer.body["unpaired"],
        json!([{"sha": SHA_A, "shadow": "sentinel / build"}])
    );

    // A body that is not the Actions jobs response is refused, naming the page.
    let answer = call(&d, &json!({ "pairs": [], "actions": [{ "jobs": "no" }] }));
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(
        answer.body["message"]
            .as_str()
            .unwrap()
            .contains("actions jobs page")
    );

    // A report format that states no test counts is refused with the format named.
    let answer = call(
        &d,
        &json!({
            "pairs": [],
            "tests": [{ "sha": SHA_A, "job": "build", "format": "rust_compiler_json", "report": "" }],
        }),
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert_eq!(answer.body["details"]["format"], "rust_compiler_json");

    // A commit id the report cannot key on is the store's refusal, not a report of nothing.
    let answer = call(
        &d,
        &json!({
            "pairs": [{ "sha": "main", "original": "build", "shadow": "sentinel / build" }],
        }),
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(answer.body["message"].as_str().unwrap().contains("commit"));

    // One request compares one report's worth of pairs.
    let many = json!({
        "pairs": (0..=sentinel_store::parity::MAX_PAIRS)
            .map(|_| json!({"sha": SHA_A, "original": "build", "shadow": "sentinel / build"}))
            .collect::<Vec<_>>(),
    });
    let answer = call(&d, &many);
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert_eq!(
        answer.body["details"]["limit"],
        sentinel_store::parity::MAX_PAIRS
    );
}

#[test]
fn the_report_reads_only_repositories_the_caller_may_read() {
    let d = deployment();
    shadow(&d, SHA_A, 60_000, "success");
    let body = json!({ "pairs": pairs(&[SHA_A]), "actions": [page(json!([original(11, SHA_A, "success", 60_000)]))] });
    // Another tenant does not learn that this repository exists.
    let answer = post(&d, &body, Some(&format!("Bearer {}", d.outsider)));
    assert_eq!(answer.status, 404, "{}", answer.body);
    // A credential without the read scope is refused before anything is read.
    let answer = post(&d, &body, Some(&format!("Bearer {}", d.unprivileged)));
    assert_eq!(answer.status, 403, "{}", answer.body);
    // And no credential at all is not a read.
    let answer = post(&d, &body, None);
    assert_eq!(answer.status, 401, "{}", answer.body);
}
