//! O05 server additions over real HTTP on loopback: the run wait long poll
//! on the store's commit notifier and its subscriber cap (shared with
//! `logs?wait=1`), the bounded literal log search, the per-attempt cache
//! summary behind `cache:read`, and keyset pagination of a repository's
//! runs. The harness is the minimal one from `oauth_core.rs`.

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, Event, Fence, JobId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    oauth::CLI_CLIENT_ID,
    summary::{AttemptSummary, CacheRecord},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind},
    dispatch, jobs, local_auth,
    logs::LogStore,
    oauth::{self, GrantKind, NewGrant},
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::{Value, json};

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    /// `Bearer sntl_…` for root with every permission.
    auth: String,
    root: UserId,
    tenant: TenantId,
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
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let now = UnixMillis::now();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"correct horse battery", now).unwrap();
    let (tenant, repo) = (TenantId::new(), sentinel_core::RepoId::new());
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
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let granted =
        tokens::provision(&store, Grant::new(root, "test", P::ALL), UnixMillis::now()).unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs: Arc::clone(&logs),
        objects,
        controller: controller.handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
    })
    .unwrap();
    Deployment {
        base: format!("http://{}", server.local_addr()),
        _dir: dir,
        store,
        logs,
        _controller: controller,
        server: Some(server),
        auth: format!("Bearer {}", sentinel_auth::token::format(&granted.secret)),
        root,
        tenant,
    }
}

/// One request against `base`: status and JSON body.
fn call(base: &str, method: &str, path: &str, auth: &str) -> (u16, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let url = format!("{base}{path}");
    let response = match method {
        "GET" => agent.get(&url).header("authorization", auth).call(),
        _ => agent
            .post(&url)
            .header("authorization", auth)
            .header("content-type", "application/json")
            .send(b"{}".as_slice()),
    }
    .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn get(d: &Deployment, path: &str) -> (u16, Value) {
    call(&d.base, "GET", path, &d.auth)
}

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps: [{ id: s, run: 'true' }]
";

/// Dispatch a one-job run; its id and its job's id.
fn dispatch(d: &Deployment) -> (RunId, JobId) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let body = json!({
        "pipeline": PIPELINE,
        "source": { "repo": "https://github.com/o/r.git", "sha": "0123456789abcdef0123456789abcdef01234567" }
    });
    let response = agent
        .post(format!("{}/api/v1/tenants/acme/repos/app/runs", d.base))
        .header("authorization", &d.auth)
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    assert_eq!(response.status().as_u16(), 201);
    let run: Value = serde_json::from_str(&response.into_body().read_to_string().unwrap()).unwrap();
    (
        run["id"].as_str().unwrap().parse().unwrap(),
        run["jobs"][0]["id"].as_str().unwrap().parse().unwrap(),
    )
}

/// Lease the job to a made-up worker, the way the dispatcher would.
fn lease(d: &Deployment, job: JobId) -> (WorkerId, AttemptId, Fence) {
    let (tenant, worker) = (d.tenant, WorkerId::new());
    let (attempt, fence) = d
        .store
        .writer()
        .write(move |tx| {
            jobs::lease(
                tx,
                tenant,
                job,
                worker,
                UnixMillis(i64::MAX / 2),
                UnixMillis::now(),
            )
        })
        .unwrap();
    (worker, attempt, fence)
}

/// The worker's side of a passing attempt, with its terminal summary.
fn pass(d: &Deployment, lease: (WorkerId, AttemptId, Fence), summary: Vec<u8>) {
    let (worker, attempt, fence) = lease;
    d.store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            dispatch::acknowledge(tx, worker, attempt, fence, now)?;
            for event in [Event::StepsStarted, Event::FinalizationStarted] {
                dispatch::report(tx, worker, attempt, fence, event, None, now, None)?;
            }
            dispatch::report(
                tx,
                worker,
                attempt,
                fence,
                Event::Passed,
                Some(&summary),
                now,
                None,
            )
        })
        .unwrap();
}

fn version_of(body: &Value) -> String {
    let version = body["version"].as_str().unwrap().to_owned();
    assert_eq!(version.len(), 16);
    version
}

#[test]
fn a_wait_returns_as_soon_as_the_run_changes_and_parks_while_it_does_not() {
    let d = deployment();
    let (run, job) = dispatch(&d);
    // Without `since`: the current run at once.
    let started = Instant::now();
    let (status, first) = get(&d, &format!("/api/v1/runs/{run}/wait"));
    assert_eq!(status, 200, "{first}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(first["changed"], true);
    assert_eq!(first["finished"], false);
    assert_eq!(first["run"]["id"], run.to_string());
    let version = version_of(&first);
    // A different `since` answers at once.
    let started = Instant::now();
    let (_, other) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since=0000000000000000"),
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        (other["changed"].as_bool(), other["version"].as_str()),
        (Some(true), Some(version.as_str()))
    );
    // The current `since` parks until the deadline and reports no change.
    let started = Instant::now();
    let (status, same) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=400"),
    );
    let waited = started.elapsed();
    assert_eq!(status, 200);
    assert_eq!(same["changed"], false);
    assert_eq!(same["version"], version.as_str());
    assert!(waited >= Duration::from_millis(390), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
    // A commit that changes nothing visible about the run keeps it parked.
    let store = Arc::clone(&d.store);
    let unrelated = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        store
            .writer()
            .write(|tx| jobs::insert_tenant(tx, TenantId::new(), "noise", UnixMillis(1)))
            .unwrap();
    });
    let (_, same) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=500"),
    );
    unrelated.join().unwrap();
    assert_eq!(same["changed"], false);
    // A parked wait returns as soon as the job finishes.
    let (base, auth) = (d.base.clone(), d.auth.clone());
    let canceller = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        let (status, body) = call(&base, "POST", &format!("/api/v1/jobs/{job}/cancel"), &auth);
        assert_eq!(status, 200, "{body}");
    });
    let started = Instant::now();
    let (status, done) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=20000"),
    );
    let waited = started.elapsed();
    canceller.join().unwrap();
    assert_eq!(status, 200);
    assert!(waited >= Duration::from_millis(250), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    assert_eq!(done["changed"], true);
    assert_eq!(done["finished"], true);
    assert_eq!(done["run"]["state"], "canceled");
    // Finished: even the current `since` answers at once.
    let finished = version_of(&done);
    let started = Instant::now();
    let (_, again) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={finished}&timeout_ms=20000"),
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        (again["changed"].as_bool(), again["finished"].as_bool()),
        (Some(false), Some(true))
    );
    // Refusals: malformed `since`, out-of-range `timeout_ms`, unknown run.
    for query in [
        "since=xyz",
        "since=00000000000000000",
        "timeout_ms=0",
        "timeout_ms=25001",
    ] {
        let (status, body) = get(&d, &format!("/api/v1/runs/{run}/wait?{query}"));
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{query}"
        );
    }
    let (status, _) = get(&d, &format!("/api/v1/runs/{}/wait", RunId::new()));
    assert_eq!(status, 404);
}

#[test]
fn a_parked_subscriber_past_the_cap_is_rate_limited_and_log_follows_share_it() {
    let d = deployment();
    let (run, job) = dispatch(&d);
    // An attempt with one stored frame, so a follow past it would park.
    let (_, attempt, _) = lease(&d, job);
    d.logs
        .append(
            run,
            job,
            attempt,
            &Frame {
                seq: 1,
                step: 0,
                stream: Stream::Stdout,
                bytes: b"hello\n".to_vec(),
            },
        )
        .unwrap();
    let (_, first) = get(&d, &format!("/api/v1/runs/{run}/wait"));
    let version = version_of(&first);
    let parked: Vec<_> = (0..sentinel_api::SUBSCRIBERS)
        .map(|_| {
            let (base, auth, version) = (d.base.clone(), d.auth.clone(), version.clone());
            thread::spawn(move || {
                call(
                    &base,
                    "GET",
                    &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=2500"),
                    &auth,
                )
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(500));
    let (status, body) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=2500"),
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (429, Some("rate_limited")),
        "{body}"
    );
    assert_eq!(body["details"]["retry_after_ms"], 1000);
    // A wait that would answer at once needs no slot.
    let (status, _) = get(&d, &format!("/api/v1/runs/{run}/wait"));
    assert_eq!(status, 200);
    // A log follow that would park shares the same slots.
    let (status, body) = get(
        &d,
        &format!("/api/v1/attempts/{attempt}/logs?after=1&wait=1"),
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (429, Some("rate_limited")),
        "{body}"
    );
    let (status, _) = get(
        &d,
        &format!("/api/v1/attempts/{attempt}/logs?after=0&wait=1"),
    );
    assert_eq!(status, 200, "a follow with frames to return never parks");
    for waiter in parked {
        let (status, body) = waiter.join().unwrap();
        assert_eq!((status, body["changed"].as_bool()), (200, Some(false)));
    }
    // The slots came back.
    let (status, _) = get(
        &d,
        &format!("/api/v1/runs/{run}/wait?since={version}&timeout_ms=50"),
    );
    assert_eq!(status, 200);
}

#[test]
fn log_search_finds_literals_across_segments_within_the_byte_bound() {
    let d = deployment();
    let (run, job) = dispatch(&d);
    let (_, attempt, _) = lease(&d, job);
    // ~5 MiB in 32 KiB frames (two segments); a matching line every 32nd.
    let filler = "y".repeat(1023) + "\n";
    let frames = 160u64;
    for seq in 1..=frames {
        let mut text = filler.repeat(31);
        if seq % 32 == 1 {
            // Exactly 32 KiB like every other frame, so the bound is exact.
            let line = format!("found the needle here {seq}\n");
            text.push_str(&"y".repeat(1023 - line.len()));
            text.push('\n');
            text.push_str(&line);
        } else {
            text.push_str(&filler);
        }
        d.logs
            .append(
                run,
                job,
                attempt,
                &Frame {
                    seq,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes: text.into_bytes(),
                },
            )
            .unwrap();
    }
    let search = |query: &str| {
        get(
            &d,
            &format!("/api/v1/attempts/{attempt}/logs/search?{query}"),
        )
    };
    // `q` is percent-decoded: the space is part of the literal.
    let (status, first) = search("q=needle%20here");
    assert_eq!(status, 200, "{first}");
    let next = first["next_after"]
        .as_u64()
        .expect("the 4 MiB bound stops the first request");
    assert!(
        (120..=130).contains(&next),
        "about 128 frames of 32 KiB: {next}"
    );
    assert_eq!(first["complete"], false);
    let seqs = |body: &Value| -> Vec<u64> {
        body["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["seq"].as_u64().unwrap())
            .collect()
    };
    assert_eq!(seqs(&first), vec![1, 33, 65, 97]);
    assert_eq!(first["matches"][0]["text"], "found the needle here 1");
    assert_eq!(first["matches"][0]["stream"], "stdout");
    let (_, rest) = search(&format!("q=needle+here&after={next}"));
    assert_eq!(seqs(&rest), vec![129]);
    assert!(rest["next_after"].is_null());
    assert_eq!(rest["complete"], false, "the log is still being written");
    // The match limit stops a request too.
    let (_, limited) = search("q=needle&limit=2");
    assert_eq!(
        (seqs(&limited), limited["next_after"].as_u64()),
        (vec![1, 33], Some(33))
    );
    // Finished and scanned to the end: complete.
    d.logs.finish(run, job, attempt, frames, &[]).unwrap();
    let (_, done) = search("q=needle&after=120");
    assert_eq!(
        (seqs(&done), done["complete"].as_bool()),
        (vec![129], Some(true))
    );
    // Refusals.
    for query in [
        "",
        "q=",
        "q=a&q=b",
        &format!("q={}", "z".repeat(257)),
        "q=a&after=x",
    ] {
        let (status, body) = search(query);
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{query}"
        );
    }
    let (status, _) = get(
        &d,
        &format!("/api/v1/attempts/{}/logs/search?q=a", AttemptId::new()),
    );
    assert_eq!(status, 404);
}

#[test]
fn log_search_pages_find_a_literal_split_across_a_sealed_segment_once() {
    let d = deployment();
    let (run, job) = dispatch(&d);
    let (_, attempt, _) = lease(&d, job);
    // Records of exactly 32 KiB: segment 0 holds frames 1..=128, and the
    // 4 MiB scan bound stops the first request at the same frame.
    let payload = (32 << 10) - sentinel_protocol::logs::FRAME_HEADER_BYTES;
    let frame = |tail: &str, head: &str| {
        let mut text = head.to_owned();
        while text.len() + tail.len() < payload {
            let line = (payload - tail.len() - text.len()).min(100);
            text.push_str(&"q".repeat(line - 1));
            text.push('\n');
        }
        text.push_str(tail);
        text.into_bytes()
    };
    for seq in 1..=200u64 {
        let bytes = match seq {
            128 => frame("error: nee", ""),
            129 => frame("", "dle across the seal\n"),
            _ => frame("", ""),
        };
        d.logs
            .append(
                run,
                job,
                attempt,
                &Frame {
                    seq,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes,
                },
            )
            .unwrap();
    }
    d.logs.finish(run, job, attempt, 200, &[]).unwrap();
    let search = |query: &str| {
        get(
            &d,
            &format!("/api/v1/attempts/{attempt}/logs/search?q=needle&{query}"),
        )
    };
    let (status, first) = search("");
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["matches"], json!([]));
    assert_eq!(first["next_after"], 128, "stopped at the sealed boundary");
    let carry = first["next_carry"]
        .as_str()
        .expect("a carry with next_after");
    // Resuming with the carry finds the split exactly once and completes.
    let (_, second) = search(&format!("after=128&carry={carry}"));
    assert_eq!(
        second["matches"],
        json!([{"seq": 129, "step": 0, "stream": "stdout", "text": "needle across the seal"}])
    );
    assert_eq!(
        (
            &second["next_after"],
            &second["next_carry"],
            &second["complete"]
        ),
        (&Value::Null, &Value::Null, &json!(true))
    );
    // One request covering both sides reports it the same, once.
    let (_, whole) = search("after=100");
    assert_eq!(whole["matches"], second["matches"]);
    // A carry is bound to its `after` and needle.
    for query in [
        format!("after=127&carry={carry}"),
        "after=128&carry=zz".to_owned(),
        "after=128&carry=".to_owned(),
    ] {
        let (status, body) = search(&query);
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{query}"
        );
    }
}

#[test]
fn an_attempt_summary_needs_cache_read_and_reports_cache_records() {
    let d = deployment();
    let (_, job) = dispatch(&d);
    let leased = lease(&d, job);
    let attempt = leased.1;
    let path = format!("/api/v1/attempts/{attempt}/summary");
    let minted = |scopes| {
        oauth::issue_grant_trusted(
            &d.store,
            NewGrant {
                user: d.root,
                client_id: CLI_CLIENT_ID,
                kind: GrantKind::Code,
                scopes,
                tenant: None,
                repo: None,
                audience: Audience::Api,
                name: None,
                lifetime_ms: oauth::LOGIN_GRANT_MS,
                created_by: None,
            },
            UnixMillis::now(),
        )
        .unwrap()
    };
    let bearer = |m: &oauth::Minted| {
        format!(
            "Bearer {}",
            sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Access, &m.access)
        )
    };
    let runs_only = minted(Scopes::RUNS_READ);
    let (status, body) = call(&d.base, "GET", &path, &bearer(&runs_only));
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("forbidden")),
        "{body}"
    );
    assert_eq!(body["details"]["scope"], "cache:read");
    let cache = bearer(&minted(Scopes::CACHE_READ));
    let (status, body) = call(&d.base, "GET", &path, &cache);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({ "attempt": attempt.to_string(), "present": false })
    );
    let summary = AttemptSummary {
        image_present: Some(true),
        caches: vec![CacheRecord {
            name: "deps".into(),
            class: 1,
            outcome: "hit".into(),
            lookup_ns: Some(10),
            lock_wait_ns: None,
            clone_ns: Some(12),
            first_touch_ns: None,
            files: 40,
            bytes: 900,
            copied_bytes: 0,
            reflink: true,
            commit_ns: None,
            staged_bytes: None,
            reused_bytes: None,
            dirty_bytes: None,
            publish: None,
            costly_hit: false,
        }],
        ..AttemptSummary::default()
    };
    pass(&d, leased, summary.encode().unwrap());
    let (status, body) = call(&d.base, "GET", &path, &cache);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["present"], true);
    assert_eq!(body["image_present"], true);
    assert_eq!(body["caches"][0]["name"], "deps");
    assert_eq!(body["caches"][0]["outcome"], "hit");
    assert_eq!(body["caches"][0]["files"], 40);
    let (status, _) = call(
        &d.base,
        "GET",
        &format!("/api/v1/attempts/{}/summary", AttemptId::new()),
        &cache,
    );
    assert_eq!(status, 404);
}

#[test]
fn run_listing_pages_with_a_next_cursor() {
    let d = deployment();
    let ids: Vec<RunId> = (0..3).map(|_| dispatch(&d).0).collect();
    let (status, first) = get(&d, "/api/v1/tenants/acme/repos/app/runs?limit=2");
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["runs"].as_array().unwrap().len(), 2);
    let next = first["next"]
        .as_str()
        .expect("a third run exists")
        .to_owned();
    assert_eq!(first["runs"][1]["id"], next.as_str());
    let (status, second) = get(
        &d,
        &format!("/api/v1/tenants/acme/repos/app/runs?limit=2&before={next}"),
    );
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["runs"].as_array().unwrap().len(), 1);
    assert!(second["next"].is_null());
    let mut listed: Vec<String> = first["runs"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["runs"].as_array().unwrap())
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    listed.sort();
    let mut expected: Vec<String> = ids.iter().map(ToString::to_string).collect();
    expected.sort();
    assert_eq!(listed, expected);
    let (status, _) = get(&d, "/api/v1/tenants/acme/repos/app/runs?before=nope");
    assert_eq!(status, 400);
    let (status, _) = get(
        &d,
        &format!(
            "/api/v1/tenants/acme/repos/app/runs?before={}",
            RunId::new()
        ),
    );
    assert_eq!(status, 404);
}
