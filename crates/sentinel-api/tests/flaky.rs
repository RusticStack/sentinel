//! The flaky-test surface: outcomes read from a finished attempt's own JUnit and Go JSON reports, the
//! fail-then-pass rule against a same-commit rerun, and the same list over MCP.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self, NamespaceKind},
    local_auth,
    logs::LogStore,
    objects::{Entry, Expect, Kind, Objects},
    outcomes,
    tokens::{self, Grant},
};
use serde_json::{Value, json};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccc";

struct Api {
    _dir: tempfile::TempDir,
    _server: sentinel_api::Server,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    base: String,
    auth: String,
    tenant: TenantId,
    other_repo: RepoId,
    repo: RepoId,
    root: UserId,
}

impl Api {
    fn start() -> Api {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
        let objects = Arc::new(Objects::open(dir.path()).unwrap());
        let controller = Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            Arc::clone(&objects),
            Identity::generate("controller").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let root = local_auth::bootstrap(
            &store,
            "root",
            "Root",
            b"correct horse battery staple",
            UnixMillis::now(),
        )
        .unwrap();
        let (tenant, other, repo, other_repo) = (
            TenantId::new(),
            TenantId::new(),
            RepoId::new(),
            RepoId::new(),
        );
        let now = UnixMillis::now();
        let admin = Principal::new(root, P::ALL, None, None);
        store
            .writer()
            .write(move |tx| {
                for (id, slug) in [(tenant, "acme"), (other, "beta")] {
                    auth::create_namespace(
                        tx,
                        admin,
                        id,
                        Namespace::parse(slug).unwrap(),
                        NamespaceKind::Organization,
                        now,
                    )?;
                    auth::set_membership(tx, admin, id, root, Role::TenantAdmin)?;
                }
                auth::create_repo(tx, admin, tenant, repo, "app", now)?;
                auth::create_repo(tx, admin, other, other_repo, "app", now)
            })
            .unwrap();
        let server = sentinel_api::Server::start_with(
            sentinel_api::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                store: Arc::clone(&store),
                logs: Arc::clone(&logs),
                objects: Arc::clone(&objects),
                controller: controller.handle(),
                secret_key: None,
                sessions: local_auth::Policy::default(),
                github_webhook_secret: None,
                intake: None,
                public_url: None,
                github_sign_in: None,
                trusted_proxies: sentinel_api::TrustedProxy::loopback(),
            },
            sentinel_api::Options {
                outcomes_every: Some(Duration::from_millis(25)),
                ..sentinel_api::Options::default()
            },
        )
        .unwrap();
        let base = format!("http://{}", server.local_addr());
        let granted =
            tokens::provision(&store, Grant::new(root, "flaky", P::ALL), UnixMillis::now())
                .unwrap();
        Api {
            _dir: dir,
            _server: server,
            store,
            logs,
            objects,
            base,
            auth: format!("Bearer {}", sentinel_auth::token::format(&granted.secret)),
            tenant,
            other_repo,
            repo,
            root,
        }
    }

    /// A finished attempt of one commit: its run, job, attempt and the row that queues it for the pass.
    fn attempt(&self, sha: &str, at_ms: i64) -> (RunId, JobId, AttemptId) {
        let (tenant, repo) = (self.tenant, self.repo);
        let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
        let sha = sha.to_owned();
        self.store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), sha, at_ms),
                )?;
                tx.execute(
                    "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, spec_index)
                     VALUES (?1, ?2, ?3, 'test', 3, 5, 0, 0)",
                    (job.as_bytes(), tenant.as_bytes(), run.as_bytes()),
                )?;
                tx.execute(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id)
                     VALUES (?1, ?2, ?3, 1, ?4, 0, ?5)",
                    (
                        attempt.as_bytes(),
                        tenant.as_bytes(),
                        job.as_bytes(),
                        [7u8; 16],
                        repo.as_bytes(),
                    ),
                )?;
                outcomes::enqueue(tx, attempt)
            })
            .unwrap();
        (run, job, attempt)
    }

    /// The attempt's own JUnit report, published as a captured artifact exactly as a job's `junit.xml` is.
    fn junit(&self, run: RunId, job: JobId, attempt: AttemptId, xml: &str) {
        let bytes = xml.len() as u64;
        let one = self
            .objects
            .stage(self.tenant, xml.as_bytes(), u64::MAX, Expect::default())
            .unwrap();
        let entry = Entry {
            path: "junit.xml".into(),
            digest: one.digest(),
            len: one.len(),
            mode: 0o644,
        };
        let (store, objects, tenant) = (
            Arc::clone(&self.store),
            Arc::clone(&self.objects),
            self.tenant,
        );
        store
            .writer()
            .write(move |tx| {
                objects.commit(tx, &one)?;
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    &artifacts::manifest_name(job, "reports"),
                    &[entry],
                )?;
                artifacts::record_class(
                    tx,
                    tenant,
                    run,
                    job,
                    attempt,
                    "reports",
                    None,
                    artifacts::State::Captured,
                    Some(version),
                    1,
                    bytes,
                    UnixMillis(UnixMillis::now().0 + 86_400_000),
                    UnixMillis::now(),
                )
                .map(|_| ())
            })
            .unwrap();
    }

    /// The attempt's stdout as `go test -json` states it, which is what a job that runs Go tests writes.
    fn go_json(&self, run: RunId, job: JobId, attempt: AttemptId, lines: &[&str]) {
        for (index, line) in lines.iter().enumerate() {
            self.logs
                .append(
                    run,
                    job,
                    attempt,
                    &Frame {
                        seq: index as u64 + 1,
                        step: 0,
                        stream: Stream::Stdout,
                        bytes: format!("{line}\n").into_bytes(),
                    },
                )
                .unwrap();
        }
    }

    fn flakes(&self, query: &str) -> (u16, Value) {
        let (status, _, body) = fixture::call(
            &self.base,
            "GET",
            &format!("/api/v1/tenants/acme/repos/app/flakes{query}"),
            None,
            &[("authorization", &self.auth)],
        );
        (status, body)
    }

    /// Until the pass has read `rows` rows of the queue: the pass sleeps between rounds, so the answer is
    /// polled, never assumed.
    fn settled(&self, rows: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let (status, body) = self.flakes("?limit=20");
            assert_eq!(status, 200, "{body}");
            if body["window"]["rows"].as_u64().unwrap_or(0) >= rows || Instant::now() > deadline {
                return body;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn junit_case(class: &str, name: &str, failure: bool) -> String {
    if failure {
        format!(
            r#"<testcase name="{name}" classname="{class}"><failure message="broken"/></testcase>"#
        )
    } else {
        format!(r#"<testcase name="{name}" classname="{class}"/>"#)
    }
}

fn report(cases: &[String]) -> String {
    format!("<testsuite>{}</testsuite>", cases.concat())
}

fn go(action: &str, package: &str, test: &str) -> String {
    format!(
        r#"{{"Time":"2026-01-01T00:00:00Z","Action":"{action}","Package":"{package}","Test":"{test}"}}"#
    )
}

#[test]
fn a_same_commit_rerun_that_passed_is_the_flake_and_another_commits_pass_proves_nothing() {
    let api = Api::start();
    let now = UnixMillis::now().0;
    // Commit A: adds fails, then a rerun of the same commit passes it: one flake.
    let (run, job, attempt) = api.attempt(SHA_A, now - 3_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds[case-1]", true)]),
    );
    // The Go job of the same commit fails too, then passes on its own rerun.
    let (run, job, attempt) = api.attempt(SHA_A, now - 2_900);
    let failing = [
        go("run", "example/pkg", "TestGo"),
        go("fail", "example/pkg", "TestGo"),
    ];
    let lines: Vec<&str> = failing.iter().map(String::as_str).collect();
    api.go_json(run, job, attempt, &lines);
    let (run, job, attempt) = api.attempt(SHA_A, now - 2_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds[case-1]", false)]),
    );
    let (run, job, attempt) = api.attempt(SHA_A, now - 1_900);
    let passing = [
        go("run", "example/pkg", "TestGo"),
        go("pass", "example/pkg", "TestGo"),
    ];
    let lines: Vec<&str> = passing.iter().map(String::as_str).collect();
    api.go_json(run, job, attempt, &lines);
    // Commit B: adds fails there, and commit C passes it. Neither is a rerun of the other.
    let (run, job, attempt) = api.attempt(SHA_B, now - 1_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds[case-1]", true)]),
    );
    let (run, job, attempt) = api.attempt(SHA_C, now - 500);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds[case-1]", false)]),
    );

    let body = api.settled(6);
    let tests = body["tests"].as_array().unwrap();
    let by_identity = |identity: &str| {
        tests
            .iter()
            .find(|test| test["identity"] == identity)
            .unwrap_or_else(|| panic!("{identity} is missing from {body}"))
    };
    let calc = by_identity("com.acme.Calc::adds");
    assert_eq!(calc["suite"], "com.acme.Calc");
    assert_eq!(calc["name"], "adds");
    assert_eq!(
        (
            calc["attempts"].as_u64(),
            calc["failed"].as_u64(),
            calc["passed"].as_u64()
        ),
        (Some(4), Some(2), Some(2))
    );
    assert_eq!(calc["commits"], 3);
    assert_eq!(calc["flakes"], 1);
    assert_eq!(calc["rate_bps"], 3_333);
    assert!(calc["last_failed_ms"].as_i64().unwrap() >= now - 1_000);

    let go_test = by_identity("example/pkg::TestGo");
    assert_eq!(go_test["commits"], 1);
    assert_eq!(go_test["flakes"], 1);
    assert_eq!(go_test["rate_bps"], 10_000);
    assert_eq!(body["window"]["rows"], 6);
    assert_eq!(body["broken"], 0);
    assert_eq!(
        body["window"]["days"], 14,
        "the window defaults to log retention"
    );
}

#[test]
fn a_test_that_never_passed_is_counted_as_broken_and_never_listed() {
    let api = Api::start();
    let now = UnixMillis::now().0;
    for at in 0..2 {
        let (run, job, attempt) = api.attempt(SHA_A, now - 2_000 + at);
        api.junit(
            run,
            job,
            attempt,
            &report(&[junit_case("com.acme.Calc", "divides", true)]),
        );
    }
    let body = api.settled(2);
    assert_eq!(body["broken"], 1);
    assert!(
        body["tests"].as_array().unwrap().is_empty(),
        "two failures of one commit are a broken test, not a flake: {body}"
    );
}

#[test]
fn the_report_is_bounded_and_scoped_like_the_runs_it_is_read_from() {
    let api = Api::start();
    let now = UnixMillis::now().0;
    let (run, job, attempt) = api.attempt(SHA_A, now - 2_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds", true)]),
    );
    let (run, job, attempt) = api.attempt(SHA_A, now - 1_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds", false)]),
    );
    api.settled(2);

    // Another tenant's repository of the same name holds none of this repository's rows, and a repository
    // it does not have answers as if it did not exist.
    let (status, _, body) = fixture::call(
        &api.base,
        "GET",
        "/api/v1/tenants/beta/repos/app/flakes",
        None,
        &[("authorization", &api.auth)],
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["tests"].as_array().unwrap().is_empty(), "{body}");
    assert_eq!(body["window"]["rows"], 0, "{body}");
    let (status, _, body) = fixture::call(
        &api.base,
        "GET",
        "/api/v1/tenants/beta/repos/missing/flakes",
        None,
        &[("authorization", &api.auth)],
    );
    assert_eq!(status, 404, "{body}");
    let _ = api.other_repo;
    let (status, body) = api.flakes("?limit=1");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tests"].as_array().unwrap().len(), 1);
    // A day is long enough for rows written a second ago.
    let (status, body) = api.flakes("?days=1&limit=200");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["window"]["days"], 1);
    assert_eq!(body["tests"].as_array().unwrap().len(), 1);
    // A window or limit outside its range is served at the default, and only a malformed value is refused,
    // exactly as the durations route reads its own window.
    let (status, body) = api.flakes("?days=0&limit=201");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["window"]["days"], 14);
    let (status, body) = api.flakes("?limit=abc");
    assert_eq!(status, 400, "{body}");
    let (status, body) = api.flakes("?days=abc");
    assert_eq!(status, 400, "{body}");
}

fn mcp_post(
    base: &str,
    body: &Value,
    authorization: &str,
    extra: &[(&str, &str)],
) -> (u16, Vec<(String, String)>, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let mut request = agent
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("authorization", authorization)
        .header("content-type", "application/json");
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = request.send(body.to_string().as_bytes()).unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let text = response.into_body().read_to_string().unwrap();
    (
        status,
        headers,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn mcp_session(api: &Api, client: &'static str, scopes: Scopes) -> (String, String) {
    use sentinel_auth::oauth::{self as auth_oauth, Kind, pkce};
    use sentinel_core::auth::Audience;
    sentinel_store::oauth::register_mcp_client(
        &api.store,
        &sentinel_store::oauth::McpClientSpec {
            id: client,
            name: "Flaky reader",
            max_scopes: Scopes::MCP,
            kind: sentinel_store::oauth::McpRegistrationKind::Dynamic,
            metadata_url: None,
        },
        &["http://127.0.0.1:49152/callback"],
    )
    .unwrap();
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let code = sentinel_store::oauth::code::approve(
        &api.store,
        &sentinel_store::oauth::code::Approval {
            client_id: client,
            redirect_uri: "http://127.0.0.1:49152/callback",
            code_challenge: &challenge,
            user: api.root,
            scopes,
            tenant: None,
            repo: None,
            audience: Audience::Mcp,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let grant = sentinel_store::oauth::code::exchange(
        &api.store,
        client,
        &code,
        "http://127.0.0.1:49152/callback",
        &verifier,
        Some(Audience::Mcp),
        UnixMillis::now(),
    )
    .unwrap();
    let authorization = format!("Bearer {}", auth_oauth::format(Kind::Access, &grant.access));
    let (status, headers, body) = mcp_post(
        &api.base,
        &json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"flaky-test","version":"1"}}
        }),
        &authorization,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let session = headers
        .into_iter()
        .find(|(key, _)| key == "mcp-session-id")
        .unwrap()
        .1;
    let (status, _, body) = mcp_post(
        &api.base,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        &authorization,
        &[
            ("mcp-protocol-version", "2025-11-25"),
            ("mcp-session-id", session.as_str()),
        ],
    );
    assert_eq!(status, 202, "{body}");
    (authorization, session)
}

#[test]
fn mcp_reads_the_same_list_as_untrusted_deterministic_counts() {
    let api = Api::start();
    let now = UnixMillis::now().0;
    let (run, job, attempt) = api.attempt(SHA_A, now - 2_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds", true)]),
    );
    let (run, job, attempt) = api.attempt(SHA_A, now - 1_000);
    api.junit(
        run,
        job,
        attempt,
        &report(&[junit_case("com.acme.Calc", "adds", false)]),
    );
    api.settled(2);

    let tool = |session: &(String, String), arguments: Value| {
        mcp_post(
            &api.base,
            &json!({
                "jsonrpc":"2.0", "id":2, "method":"tools/call",
                "params":{"name":"list_flaky_tests","arguments":arguments}
            }),
            &session.0,
            &[
                ("mcp-protocol-version", "2025-11-25"),
                ("mcp-session-id", session.1.as_str()),
            ],
        )
    };
    let reader = mcp_session(&api, "flaky-reader", Scopes::RUNS_READ);
    let (status, _, body) = tool(&reader, json!({"tenant":"acme","repo":"app"}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], false, "{body}");
    let listed = &body["result"]["structuredContent"];
    assert_eq!(listed["repository"], "app");
    let test = &listed["tests"][0];
    assert_eq!(test["identity"], "com.acme.Calc::adds");
    assert_eq!(test["flakes"], 1);
    assert_eq!(test["rate_bps"], 10_000);
    assert_eq!(listed["window"]["days"], 14);

    // A session that holds no runs:read is refused the tool before it reaches the repository.
    let narrow = mcp_session(&api, "flaky-narrow", Scopes::LOGS_READ);
    let (status, _, body) = tool(&narrow, json!({"tenant":"acme","repo":"app"}));
    assert_eq!(status, 403, "{body}");

    // The window is bounded at the tool's own ceiling.
    let (status, _, body) = tool(&reader, json!({"tenant":"acme","repo":"app","days":367}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
}
