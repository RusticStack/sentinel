use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_checks::{
    Lane,
    github::GithubChecks,
    lane::{Config, Publish, Publisher},
};
use sentinel_core::{
    Fence, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
    state::{Actor, Event},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    checks::{self, State},
    intake::{self, NewDelivery},
    provenance::{self, Provenance},
    registration::{self, Authority},
    runs, sources,
    sources_forge::{self, Snapshot},
};

/// A test-only RSA key generated fresh for this test process with the `openssl`
/// CLI; it authenticates nothing and no private key is committed (see
/// `no_committed_keys` in the `sentinel` crate tests).
fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

const REF: &str = "refs/heads/main";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GITHUB_REPO_ID: u64 = 91;
const INSTALLATION: u64 = 42;
const ACCOUNT: u64 = 73;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

#[derive(Clone, Debug)]
struct Record {
    method: String,
    path: String,
    body: serde_json::Value,
    authorization: String,
}

#[derive(Clone, Debug)]
struct Reply {
    status: u16,
    body: serde_json::Value,
    headers: Vec<(String, String)>,
    lost: bool,
}

#[derive(Default)]
struct Data {
    records: Vec<Record>,
    scripted: VecDeque<(String, String, Reply)>,
    existing: Vec<serde_json::Value>,
    next_id: i64,
}

struct Stub {
    addr: SocketAddr,
    data: Arc<Mutex<Data>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Stub {
    fn start() -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let data = Arc::new(Mutex::new(Data {
            next_id: 500,
            ..Data::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (data, stop) = (Arc::clone(&data), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Windows: accepted sockets inherit the listener's non-blocking mode, so serve them blocking.
                            let _ = stream.set_nonblocking(false);
                            let data = Arc::clone(&data);
                            thread::spawn(move || serve(stream, &data));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Stub {
            addr,
            data,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn script(&self, method: &str, path: &str, status: u16, body: serde_json::Value) {
        self.script_headers(method, path, status, body, &[]);
    }

    fn script_headers(
        &self,
        method: &str,
        path: &str,
        status: u16,
        body: serde_json::Value,
        headers: &[(&str, &str)],
    ) {
        let mut data = self.data.lock().unwrap();
        data.scripted.push_back((
            method.to_owned(),
            path.to_owned(),
            Reply {
                status,
                body,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                lost: false,
            },
        ));
    }

    fn script_lost(&self, method: &str, path: &str, check_run_id: i64) {
        let mut data = self.data.lock().unwrap();
        data.scripted.push_back((
            method.to_owned(),
            path.to_owned(),
            Reply {
                status: 0,
                body: serde_json::json!({"id": check_run_id}),
                headers: Vec::new(),
                lost: true,
            },
        ));
    }

    fn adopt(&self, check_run_id: i64, external_id: &str) {
        let mut data = self.data.lock().unwrap();
        data.existing.push(serde_json::json!({
            "id": check_run_id,
            "external_id": external_id,
        }));
    }

    fn adopt_completed(&self, check_run_id: i64, external_id: &str) {
        let mut data = self.data.lock().unwrap();
        data.existing.push(serde_json::json!({
            "id": check_run_id,
            "external_id": external_id,
            "status": "completed",
        }));
    }

    fn records(&self) -> Vec<Record> {
        self.data.lock().unwrap().records.clone()
    }

    fn wait(&self, what: &str, matches: impl Fn(&[Record]) -> bool) -> Vec<Record> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let records = self.records();
            if matches(&records) {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {records:#?}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, data: &Arc<Mutex<Data>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    loop {
        let Some((method, path, body, authorization)) = read_request(&mut stream) else {
            return;
        };
        let parsed = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let reply = {
            let mut data = data.lock().unwrap();
            data.records.push(Record {
                method: method.clone(),
                path: path.clone(),
                body: parsed,
                authorization,
            });
            let scripted = data
                .scripted
                .iter()
                .position(|(wanted_method, wanted_path, _)| {
                    *wanted_method == method
                        && (wanted_path.is_empty() || path.contains(wanted_path))
                })
                .map(|index| data.scripted.remove(index).unwrap().2);
            match scripted {
                Some(reply) => reply,
                None => default_reply(&mut data, &method, &path),
            }
        };
        if reply.lost {
            let request: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            data.lock().unwrap().existing.push(serde_json::json!({
                "id": reply.body["id"],
                "external_id": request["external_id"],
                "status": request["status"],
            }));
            return;
        }
        let text = reply.body.to_string();
        let mut response = format!(
            "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: keep-alive\r\n",
            reply.status,
            text.len()
        );
        for (key, value) in &reply.headers {
            response.push_str(&format!("{key}: {value}\r\n"));
        }
        response.push_str("content-type: application/json\r\n\r\n");
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default().to_owned();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    let mut authorization = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap_or(0),
                "authorization" => authorization = value.trim().to_owned(),
                _ => {}
            }
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some((method, path, body, authorization))
}

fn default_reply(data: &mut Data, method: &str, path: &str) -> Reply {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let expires = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    if method == "GET" && path.contains(&format!("/app/installations/{INSTALLATION}")) {
        return Reply {
            status: 200,
            body: serde_json::json!({
                "id": INSTALLATION,
                "app_id": 1234,
                "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": {"contents": "read", "checks": "write"},
            }),
            headers: Vec::new(),
            lost: false,
        };
    }
    if method == "POST" && path.contains("/access_tokens") {
        return Reply {
            status: 201,
            body: serde_json::json!({
                "token": format!("ghs_{}", data.next_id),
                "expires_at": expires,
                "permissions": {"checks": "write", "metadata": "read"},
            }),
            headers: Vec::new(),
            lost: false,
        };
    }
    if method == "GET" && path.contains(&format!("/repositories/{GITHUB_REPO_ID}")) {
        return Reply {
            status: 200,
            body: serde_json::json!({
                "id": GITHUB_REPO_ID,
                "owner": {"id": ACCOUNT},
                "clone_url": "https://github.com/account/app.git",
            }),
            headers: Vec::new(),
            lost: false,
        };
    }
    if method == "GET" && path.contains("/check-runs") {
        let param = |name: &str| {
            path.split(['?', '&'])
                .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
                .and_then(|v| v.parse::<usize>().ok())
        };
        let per_page = param("per_page").unwrap_or(30);
        let page = param("page").unwrap_or(1).max(1);
        let listed: Vec<serde_json::Value> = data
            .existing
            .iter()
            .skip((page - 1) * per_page)
            .take(per_page)
            .cloned()
            .collect();
        return Reply {
            status: 200,
            body: serde_json::json!({"total_count": data.existing.len(), "check_runs": listed}),
            headers: Vec::new(),
            lost: false,
        };
    }
    if method == "POST" && path.contains("/check-runs") {
        data.next_id += 1;
        return Reply {
            status: 201,
            body: serde_json::json!({"id": data.next_id, "check_suite": {"id": 7001}}),
            headers: Vec::new(),
            lost: false,
        };
    }
    if method == "PATCH" && path.contains("/check-runs/") {
        let id: i64 = path
            .rsplit('/')
            .next()
            .and_then(|tail| tail.split('?').next())
            .and_then(|tail| tail.parse().ok())
            .unwrap_or(0);
        return Reply {
            status: 200,
            body: serde_json::json!({"id": id, "check_suite": {"id": 7002}}),
            headers: Vec::new(),
            lost: false,
        };
    }
    Reply {
        status: 404,
        body: serde_json::json!({"message": "not found"}),
        headers: Vec::new(),
        lost: false,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    stub: Stub,
    app: Arc<sentinel_github::app::App>,
    tenant: TenantId,
    repo: RepoId,
    public_url: Option<String>,
}

fn fixture(public_url: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let stub = Stub::start();
    let app = Arc::new(
        sentinel_github::app::App::new(1234, test_key())
            .unwrap()
            .with_endpoint(&stub.endpoint())
            .unwrap(),
    );
    let (alice, tenant, repo) = (
        Principal::new(UserId::new(), Permissions::ALL, None, None),
        TenantId::new(),
        RepoId::new(),
    );
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice.user, "alice", true, now)?;
            auth::create_namespace(
                tx,
                alice,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Personal(alice.user),
                now,
            )?;
            auth::create_repo(tx, alice, tenant, repo, "app", now)?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: INSTALLATION,
                    account_id: ACCOUNT,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(alice.user),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: "https://github.com/account/app.git".into(),
                        allowed_refs: vec![REF.into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            Ok(())
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        stub,
        app,
        tenant,
        repo,
        public_url: public_url.map(str::to_owned),
    }
}

fn spec() -> RunSpec {
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new("https://github.com/account/app.git", SHA_B, Some(REF)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

fn event_run(f: &mut Fixture) -> (RunId, JobId) {
    let (tenant, repo) = (f.tenant, f.repo);
    let run = RunId::new();
    let run_spec = spec();
    f.store
        .writer()
        .write(move |tx| {
            let jobs = runs::create_run(tx, tenant, repo, run, &run_spec, UnixMillis::now())?;
            provenance::insert(
                tx,
                &Provenance {
                    tenant,
                    repo,
                    trigger: "push".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some(REF.into()),
                    old_sha: Some(SHA_A.into()),
                    new_sha: Some(SHA_B.into()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: SHA_B.into(),
                    pipeline_path: Some(".sentinel.yml".into()),
                    pipeline_digest: run_spec.pipeline.digest.to_le_bytes(),
                    pr_number: None,
                },
                run,
                UnixMillis::now(),
            )?;
            checks::record_run(tx, tenant, run, UnixMillis::now())?;
            Ok(jobs[0])
        })
        .map(|job| (run, job))
        .unwrap()
}

fn step(f: &mut Fixture, job: JobId, actor: Actor, event: Event) {
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            sentinel_store::jobs::transition(tx, tenant, job, actor, event, UnixMillis::now())
        })
        .unwrap();
}

fn start_lane(f: &Fixture, publisher: GithubChecks) -> Lane {
    Lane::start(
        Arc::clone(&f.store),
        Box::new(publisher),
        Config {
            idle: Duration::from_millis(20),
            ..Config::default()
        },
        |batch| {
            if std::env::var_os("CHECKS_TRACE").is_some() {
                for entry in &batch.entries {
                    eprintln!("lane: {} -> {}", entry.name, entry.outcome);
                }
            }
        },
    )
}

fn publisher(f: &Fixture) -> GithubChecks {
    GithubChecks::new(
        Arc::clone(&f.store),
        Arc::clone(&f.app),
        f.public_url.clone(),
    )
}

fn posts<'a>(records: &'a [Record], path: &str) -> Vec<&'a Record> {
    records
        .iter()
        .filter(|r| r.method == "POST" && r.path.contains(path))
        .collect()
}

fn wait_settled_run(f: &Fixture, run: RunId, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
        let settled = |row: &sentinel_store::checks::Publication| {
            row.published_seq == row.seq || row.state == State::Refused
        };
        if !rows.is_empty() && rows.iter().all(settled) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {rows:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_settled_delivery(f: &Fixture, delivery: sentinel_core::DeliveryId, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let row = f.store.read(|c| checks::of_delivery(c, delivery)).unwrap();
        if row
            .as_ref()
            .is_some_and(|row| row.published_seq == row.seq || row.state == State::Refused)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {row:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_run_publishes_a_stable_aggregate_and_per_job_checks() {
    let mut f = fixture(Some("https://ci.example"));
    let (run, build) = event_run(&mut f);
    let lane = start_lane(&f, publisher(&f));

    let records = f.stub.wait("the queued checks", |records| {
        posts(records, "/check-runs").len() >= 2
    });
    let created = posts(&records, "/check-runs");
    assert_eq!(created.len(), 2, "{records:#?}");
    let names: Vec<&str> = created
        .iter()
        .filter_map(|r| r.body["name"].as_str())
        .collect();
    assert!(names.contains(&"sentinel / ci"), "{names:?}");
    assert!(names.contains(&"sentinel / build"), "{names:?}");
    let aggregate = created
        .iter()
        .find(|r| r.body["name"] == "sentinel / ci")
        .unwrap();
    assert_eq!(aggregate.body["status"], "queued");
    assert_eq!(aggregate.body["head_sha"], SHA_B);
    assert!(
        aggregate.body["external_id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("sentinel:{run}:aggregate:")),
        "{aggregate:?}"
    );
    assert_eq!(
        aggregate.body["details_url"],
        format!("https://ci.example/runs/{run}")
    );
    assert!(aggregate.body["check_run_id"].is_null());
    assert!(
        records
            .iter()
            .filter(|r| r.path.contains("/check-runs"))
            .all(|r| r.authorization.starts_with("Bearer ghs_")),
        "{records:#?}"
    );
    assert!(
        posts(&records, "/access_tokens")
            .iter()
            .all(|r| r.authorization.starts_with("Bearer ey"))
    );
    let job = created
        .iter()
        .find(|r| r.body["name"] == "sentinel / build")
        .unwrap();
    assert!(
        job.body["external_id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("sentinel:{run}:{build}:")),
        "{job:?}"
    );
    assert_eq!(
        job.body["details_url"],
        format!("https://ci.example/runs/{run}?job={build}")
    );
    assert_eq!(posts(&records, "/access_tokens").len(), 1);

    step(&mut f, build, Actor::Controller, Event::Leased(Fence(1)));
    step(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
    );
    step(&mut f, build, Actor::Worker(Fence(1)), Event::StepsStarted);
    step(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::FinalizationStarted,
    );
    step(&mut f, build, Actor::Worker(Fence(1)), Event::Passed);
    let records = f.stub.wait("the completed checks", |records| {
        let completed = |name: &str| {
            records.iter().any(|r| {
                r.method == "PATCH" && r.body["name"] == name && r.body["status"] == "completed"
            })
        };
        completed("sentinel / build") && completed("sentinel / ci")
    });
    let patches: Vec<&Record> = records.iter().filter(|r| r.method == "PATCH").collect();
    assert!(
        patches.iter().any(|r| {
            r.body["name"] == "sentinel / build"
                && r.body["status"] == "completed"
                && r.body["conclusion"] == "success"
        }),
        "{patches:#?}"
    );
    let last_aggregate = patches
        .iter()
        .rev()
        .find(|r| r.body["name"] == "sentinel / ci")
        .unwrap();
    assert_eq!(last_aggregate.body["status"], "completed");
    assert_eq!(last_aggregate.body["conclusion"], "success");
    assert_eq!(last_aggregate.body["output"]["title"], "Passed");
    assert!(last_aggregate.body["completed_at"].is_string());

    wait_settled_run(&f, run, "the settled run");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.state, State::Published, "{row:?}");
        assert_eq!(row.published_seq, row.seq, "{row:?}");
        assert!(row.check_run_id.is_some(), "{row:?}");
    }
    drop(lane);
    assert!(
        f.store
            .read(|c| checks::due(c, UnixMillis::now(), 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_ambiguous_create_is_adopted_instead_of_duplicated() {
    let mut f = fixture(None);
    let (run, build) = event_run(&mut f);
    let external = format!("sentinel:{run}:{build}");
    let (tenant, run_id, scope) = (f.tenant, run, build.to_string());
    let seq = f
        .store
        .writer()
        .write(move |tx| {
            let row = checks::of_run(tx, tenant, run_id)?
                .into_iter()
                .find(|row| row.scope == scope)
                .expect("the job's publication");
            checks::create_started(tx, row.id, row.seq, UnixMillis::now())?;
            Ok(row.seq)
        })
        .unwrap();
    f.stub.adopt(777, &checks::create_identity(&external, seq));
    let lane = start_lane(&f, publisher(&f));
    let records = f
        .stub
        .wait("the adopted update and the aggregate create", |records| {
            records
                .iter()
                .any(|r| r.method == "PATCH" && r.path.contains("/check-runs/777"))
                && !posts(records, "/check-runs").is_empty()
        });
    assert_eq!(posts(&records, "/check-runs").len(), 1, "{records:#?}");
    let created = posts(&records, "/check-runs");
    assert!(created[0].body["details_url"].is_null());
    wait_settled_run(&f, run, "the adopted check");
    let row = f
        .store
        .read(|c| checks::of_run(c, f.tenant, run))
        .unwrap()
        .into_iter()
        .find(|row| row.scope == build.to_string())
        .unwrap();
    assert_eq!(row.check_run_id, Some(777));
    assert_eq!(
        row.check_suite_id,
        Some(7002),
        "the patch carried the suite"
    );
    assert_eq!(row.published_seq, row.seq);
    drop(lane);
}

#[test]
fn adoption_finds_its_run_past_a_large_first_page() {
    let mut f = fixture(None);
    let (run, build) = event_run(&mut f);
    let external = format!("sentinel:{run}:{build}");
    let (tenant, run_id, scope) = (f.tenant, run, build.to_string());
    let seq = f
        .store
        .writer()
        .write(move |tx| {
            let row = checks::of_run(tx, tenant, run_id)?
                .into_iter()
                .find(|row| row.scope == scope)
                .expect("the job's publication");
            checks::create_started(tx, row.id, row.seq, UnixMillis::now())?;
            Ok(row.seq)
        })
        .unwrap();
    {
        let padding = "x".repeat(1024);
        let mut data = f.stub.data.lock().unwrap();
        for id in 0..120 {
            data.existing.push(serde_json::json!({
                "id": 10_000 + id,
                "external_id": format!("{external}:old{id}"),
                "status": "completed",
                "output": {"summary": padding},
            }));
        }
    }
    f.stub.adopt(999, &checks::create_identity(&external, seq));
    let lane = start_lane(&f, publisher(&f));
    f.stub
        .wait("the adopted update and the aggregate", |records| {
            records
                .iter()
                .any(|r| r.method == "PATCH" && r.path.contains("/check-runs/999"))
                && !posts(records, "/check-runs").is_empty()
        });
    wait_settled_run(&f, run, "the adopted check");
    let records = f.stub.records();
    assert!(
        records
            .iter()
            .any(|r| r.method == "GET" && r.path.contains("page=2")),
        "the second page was read: {records:#?}"
    );
    assert_eq!(posts(&records, "/check-runs").len(), 1, "{records:#?}");
    drop(lane);
}

#[test]
fn a_lost_create_response_is_found_by_external_id() {
    let mut f = fixture(None);
    let (run, _) = event_run(&mut f);
    f.stub.script_lost("POST", "/check-runs", 888);
    let lane = start_lane(&f, publisher(&f));
    let records = f.stub.wait("the adopted update", |records| {
        records
            .iter()
            .any(|r| r.method == "PATCH" && r.path.contains("/check-runs/888"))
    });
    assert_eq!(posts(&records, "/check-runs").len(), 2, "{records:#?}");
    assert_eq!(
        records.iter().filter(|r| r.method == "PATCH").count(),
        1,
        "{records:#?}"
    );
    wait_settled_run(&f, run, "the reconciled create");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    let adopted = rows
        .iter()
        .find(|row| row.check_run_id == Some(888))
        .expect("the lost run was adopted");
    assert_eq!(adopted.published_seq, adopted.seq, "{adopted:?}");
    assert_eq!(adopted.check_suite_id, Some(7002), "{adopted:?}");
    assert!(adopted.create_started_ms.is_some(), "{adopted:?}");
    drop(lane);
}

#[test]
fn a_rerun_creates_fresh_check_runs_because_completed_ones_are_immutable() {
    let mut f = fixture(None);
    let (run, build) = event_run(&mut f);
    let lane = start_lane(&f, publisher(&f));

    f.stub.wait("the queued creates", |records| {
        posts(records, "/check-runs").len() == 2
    });
    step(&mut f, build, Actor::Controller, Event::Leased(Fence(1)));
    step(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
    );
    step(&mut f, build, Actor::Worker(Fence(1)), Event::StepsStarted);
    step(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::FinalizationStarted,
    );
    step(&mut f, build, Actor::Worker(Fence(1)), Event::Passed);
    f.stub.wait("the completed checks", |records| {
        records
            .iter()
            .filter(|r| r.method == "PATCH" && r.body["status"] == "completed")
            .count()
            == 2
    });
    wait_settled_run(&f, run, "the settled run");

    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    let dead: Vec<i64> = rows.iter().filter_map(|row| row.check_run_id).collect();
    assert_eq!(dead.len(), 2);
    for row in &rows {
        f.stub
            .adopt_completed(row.check_run_id.unwrap(), &row.external_id);
    }
    let before = f.stub.records().len();

    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| runs::rerun_job(tx, tenant, build, UnixMillis::now()))
        .unwrap();
    let records = f.stub.wait("the rerun's fresh creates", |records| {
        posts(records, "/check-runs").len() == 4
    });
    let later = &records[before..];
    assert!(
        later.iter().all(|r| {
            r.method != "PATCH" || dead.iter().all(|id| !r.path.contains(&id.to_string()))
        }),
        "{later:#?}"
    );
    wait_settled_run(&f, run, "the rerun's publications");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    assert!(
        rows.iter()
            .all(|row| row.check_run_id.is_some_and(|id| !dead.contains(&id))),
        "{rows:?}"
    );
    drop(lane);
}

#[test]
fn a_rate_limit_pauses_delivery_and_a_retry_is_delivered() {
    for status in [403, 429] {
        let mut f = fixture(None);
        let (run, _) = event_run(&mut f);
        f.stub.script_headers(
            "POST",
            "/check-runs",
            status,
            serde_json::json!({"message": "You have exceeded a secondary rate limit"}),
            &[("retry-after", "1")],
        );
        let lane = start_lane(&f, publisher(&f));
        let records = f.stub.wait("all checks delivered", |records| {
            posts(records, "/check-runs").len() >= 3
        });
        assert_eq!(posts(&records, "/check-runs").len(), 3, "{records:#?}");
        wait_settled_run(&f, run, "the retried publications");
        let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
        assert!(
            rows.iter()
                .all(|row| row.published_seq == row.seq && row.seq == 1)
        );
        drop(lane);
    }
}

#[test]
fn an_expired_token_is_replaced_and_permanent_refusals_are_recorded() {
    let mut f = fixture(None);
    let (run, _) = event_run(&mut f);
    f.stub.script(
        "PATCH",
        "/check-runs/",
        401,
        serde_json::json!({"message": "Bad credentials"}),
    );
    f.stub.script(
        "POST",
        "/check-runs",
        401,
        serde_json::json!({"message": "Bad credentials"}),
    );
    let lane = start_lane(&f, publisher(&f));
    let records = f.stub.wait("delivery after a token refresh", |records| {
        posts(records, "/access_tokens").len() >= 2 && posts(records, "/check-runs").len() >= 3
    });
    assert!(posts(&records, "/access_tokens").len() >= 2, "{records:#?}");
    wait_settled_run(&f, run, "the refreshed token");
    let rows = f.store.read(|c| checks::of_run(c, f.tenant, run)).unwrap();
    assert!(rows.iter().all(|row| row.published_seq == row.seq));
    drop(lane);

    let mut f = fixture(None);
    let (run, _) = event_run(&mut f);
    f.stub.script(
        "POST",
        "/check-runs",
        422,
        serde_json::json!({"message": "Validation Failed"}),
    );
    let lane = start_lane(&f, publisher(&f));
    let records = f.stub.wait("both publications attempted", |records| {
        posts(records, "/check-runs").len() >= 2
    });
    let created = posts(&records, "/check-runs");
    assert_eq!(created.len(), 2, "{records:#?}");
    let (tenant, run_id) = (f.tenant, run);
    let refused: (i64, Option<String>) = f
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT count(*), max(reason) FROM check_publications
                 WHERE tenant_id = ?1 AND run_id = ?2 AND state = 2",
                [tenant.as_bytes(), run_id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(refused.0, 1, "one generation is refused");
    assert!(
        refused
            .1
            .as_deref()
            .is_some_and(|reason| reason.contains("Validation Failed")),
        "{:?}",
        refused.1
    );
    wait_settled_run(&f, run, "the other publication");
    let due = f
        .store
        .read(|c| checks::due(c, UnixMillis(UnixMillis::now().0 + 3_600_000), 10))
        .unwrap();
    assert!(
        due.is_empty(),
        "a permanent refusal and a published row leave nothing due"
    );
    drop(lane);
}

#[test]
fn a_revoked_binding_refuses_without_calling_github() {
    let mut f = fixture(None);
    let (run, _) = event_run(&mut f);
    let repo = f.repo;
    let actor = f
        .store
        .read(|c| {
            Ok(c.query_row("SELECT id FROM users LIMIT 1", [], |r| {
                r.get::<_, [u8; 16]>(0)
            })?)
        })
        .map(|bytes| UserId::from_bytes(bytes).unwrap())
        .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            sources::revoke(
                tx,
                Authority::HostLocal,
                Some(actor),
                repo,
                1,
                UnixMillis::now(),
            )
        })
        .unwrap();
    let mut publisher = publisher(&f);
    let publication = f
        .store
        .read(|c| checks::of_run(c, f.tenant, run))
        .unwrap()
        .remove(0);
    assert!(matches!(
        publisher.publish(&publication),
        Publish::Refused { ref reason } if reason == "binding_revoked"
    ));
    assert!(f.stub.records().is_empty(), "no request was made");
}

#[test]
fn a_settled_delivery_publishes_a_completed_check() {
    let f = fixture(None);
    let (tenant, repo) = (f.tenant, f.repo);
    let merge = "c".repeat(40);
    let sha = merge.clone();
    let accepted = f
        .store
        .writer()
        .write(move |tx| {
            let accepted = intake::accept(
                tx,
                repo,
                &NewDelivery {
                    authentication: sentinel_store::intake::Authentication::HookToken,
                    provider: "generic",
                    external_id: "no-pipeline",
                    event: "ref_update",
                    ref_name: REF,
                    old_sha: SHA_A,
                    new_sha: &sha,
                },
                None,
                UnixMillis::now(),
            )?;
            intake::settle(
                tx,
                accepted.id(),
                intake::Resolution::Failed("no_pipeline"),
                UnixMillis::now(),
            )?;
            Ok(accepted.id())
        })
        .unwrap();
    let lane = start_lane(&f, publisher(&f));
    let records = f.stub.wait("the delivery check", |records| {
        !posts(records, "/check-runs").is_empty()
    });
    let created = posts(&records, "/check-runs");
    assert_eq!(created[0].body["name"], "sentinel / ci");
    assert_eq!(created[0].body["status"], "completed");
    assert_eq!(created[0].body["conclusion"], "failure");
    assert_eq!(created[0].body["head_sha"], merge);
    assert_eq!(
        created[0].body["external_id"],
        format!("sentinel:dlv:{accepted}:1")
    );
    assert!(
        created[0].body["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("no_pipeline")
    );
    wait_settled_delivery(&f, accepted, "the delivery check");
    let row = f
        .store
        .read(|c| checks::of_delivery(c, accepted))
        .unwrap()
        .expect("a delivery publication");
    assert_eq!(row.published_seq, row.seq);
    drop(lane);
    let _ = tenant;
}

#[test]
fn a_lost_answer_to_a_completed_create_is_adopted_not_duplicated() {
    let f = fixture(None);
    let repo = f.repo;
    let sha = "c".repeat(40);
    let accepted = f
        .store
        .writer()
        .write(move |tx| {
            let accepted = intake::accept(
                tx,
                repo,
                &NewDelivery {
                    authentication: sentinel_store::intake::Authentication::HookToken,
                    provider: "generic",
                    external_id: "lost-completed",
                    event: "ref_update",
                    ref_name: REF,
                    old_sha: SHA_A,
                    new_sha: &sha,
                },
                None,
                UnixMillis::now(),
            )?;
            intake::settle(
                tx,
                accepted.id(),
                intake::Resolution::Failed("no_pipeline"),
                UnixMillis::now(),
            )?;
            Ok(accepted.id())
        })
        .unwrap();
    f.stub.script_lost("POST", "/check-runs", 888);
    let lane = start_lane(&f, publisher(&f));
    wait_settled_delivery(&f, accepted, "the adopted completed check");
    let records = f.stub.records();
    assert_eq!(
        posts(&records, "/check-runs").len(),
        1,
        "exactly one create: {records:#?}"
    );
    let row = f
        .store
        .read(|c| checks::of_delivery(c, accepted))
        .unwrap()
        .expect("a delivery publication");
    assert_eq!(row.check_run_id, Some(888), "{row:?}");
    assert_eq!(row.published_seq, row.seq, "{row:?}");
    drop(lane);
}

#[test]
fn dropping_the_lane_joins_its_thread() {
    let f = fixture(None);
    let lane = start_lane(&f, publisher(&f));
    let started = Instant::now();
    drop(lane);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the lane did not stop promptly"
    );
}
