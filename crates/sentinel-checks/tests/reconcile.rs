//! G05 reconcile: the `github_refresh` lane against a loopback stub — a
//! healthy pass verifies, a renamed or missing repository revokes its
//! binding, a 404 installation disables and revokes, a suspended installation
//! stays disabled, and a transient failure retries rather than revoking.

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
use sentinel_checks::reconcile::{Config, Reconcile};
use sentinel_core::{RepoId, TenantId, UnixMillis, UserId};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    sources::{self},
    sources_forge::{self, Snapshot},
};

/// A test-only RSA key, generated for this suite; it authenticates nothing.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCn0jnG5Bokc3Af
NRpzCYPskbFJvhtol1PCsuD1plfDG/Zl2UPU8U9Wv1d+kggr9b+yphtg4u2R1IXL
5VcSrVtEz4mHDQeRUtndXvPyCe3i+WIFkWd5YrVnFHzEyYyAXc2gxKlxvo715SEB
Zd+de78/2q706hZwHQ7SdODjQW5ly0JDwletAUTXMvzV7JaJ0ocwya9oIZi71PYW
v4QxOD8SQNHynMmJDJv5HADHijrFAaQyFAtsQjRGQfY/WxocdlB6YdNDCg5OOkke
tOri30xDGAPZvoPgtQp7WuEQY1AnyKKKkLjVVpNYraHy7GI2qGGKzHXylyjnqVTm
lzDfjRKBAgMBAAECggEAA1EJGZr4wJ9UEsHQEoBDI6yOFjjUE4E+GLBuorGACtfl
dYYm1tv9Uee5I8QLYPcGgVIoDgZIufjlu1hTxrI3W15F8lh5vaT8r5PIpWVjK/j6
t2/JXYxBAoGp+jzzcmFS3CpWy5Z/qRth8hmgeDJxs/eEkqGCV60zVZ8VXK22hVDH
/P36FENSTBHuCkONObeb6seoTiFq1bsFm09K4DwOHkZvG47DIbiXslMi6vjOklP9
MkRqq3qO6LL1fzLzEsO02hyVil+iyPMYHGntwf78wD/vGnhXD6+i/nH0PpqxTTtk
H36BMVpbmsfqyzEtkr5h8LprcS4GJu5DAwDPcRHJWQKBgQDXvsrQ23pfLuDAsmOO
T4wLTSADVcipAmkEZWPFbssXSHLrQfynnWCIbWOHhcrH4M5gdPA8p8DZztAcjAuN
qBf5b1vb/VxTrq5M3oqnC72SAjLIc9B+PXXLKdVnE9Ci+f3v3CVgXo0t/8bmOUf2
AotKKMbv0tLkp1YHhracj41CBQKBgQDHIk89X8LwtwB7SQGbCMtywMtbI8Nhz0Ib
Ec1te9famnzicSMb/oERrzNFJw1y/xpJ+vOXcayppMR3M91pygfoUx19dRTodoYT
mwwFuYiPSCwWpxoo0M0QdRPAtCTMGCSgyHO1he4zm96/EFIk/w0cTW1LK16J97QA
VZntcnILTQKBgE8MxGmEkbEAjy9r7Zh+QxT8/GbcbrqmfG407DqyHs34KMtUkUul
GXLDif1lI2jbUSL8le3TlZD4+z4Kfk04MxidGe5gRg0PayQVQn50idBO5+aUsOcg
g+GeAWhUVVTx/n59jmBiJJ6fInTGtjxIsFrK2CGVgNpxCc+WJ6Dz5FE1AoGBAJnp
fNF1GJkw+OBRNzp6+7TAKu1QoQ0SQoflpJ/Anr/JtEjZJUfX2C6w+bGzU4PUhJ81
pd0h8VBVl7yCi9neW2pIA30aZ4SdR1gT+KDcHB6Sq/D+SwvNBxJ3S0MgeWh+KKFV
DYn58HhXOzz2Amex8pIzjgwRg0qj965ie0y5rkfpAoGBAJ/J+9Py38IDhHs6K4Ek
GNuPWmoSiHHsvDN99rO5TahlKUw6E6Zy7hc5We0ET1HdcH+H9sQakOXf9dxgLEm7
rxl8y5pZ+rkMirxkGkfSo5k0JPL96DYRYd5GPPxxAaymC2DaaSIbBT20vtXZKyCO
BXHyoYy6w9e7POYAfdFeqKcU
-----END PRIVATE KEY-----";

const INSTALLATION: u64 = 42;
const ACCOUNT: u64 = 73;
const GITHUB_REPO: u64 = 91;
const REMOTE: &str = "https://github.com/account/app.git";
const REF: &str = "refs/heads/main";

#[derive(Default)]
struct Data {
    /// (method, path substring, status, body): the first match is consumed.
    /// For once-only faults like a transient 500.
    scripted: VecDeque<(String, String, u16, serde_json::Value)>,
    /// Persistent overrides: GitHub's answers are stable facts, so a gone or
    /// suspended installation answers the same way to every pass.
    installation_status: Option<u16>,
    installation: Option<serde_json::Value>,
    /// Repositories `/installation/repositories` reports; `None` keeps the
    /// bound repository present under its approved name.
    listed: Option<Vec<serde_json::Value>>,
    /// What `/repositories/{id}` answers by default.
    repository: Option<serde_json::Value>,
    requests: Vec<String>,
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
        let data = Arc::new(Mutex::new(Data::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (data, stop) = (Arc::clone(&data), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
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
        self.data.lock().unwrap().scripted.push_back((
            method.to_owned(),
            path.to_owned(),
            status,
            body,
        ));
    }

    fn requests(&self) -> Vec<String> {
        self.data.lock().unwrap().requests.clone()
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
        let Some((method, path)) = read_request(&mut stream) else {
            return;
        };
        let (status, body) = {
            let mut data = data.lock().unwrap();
            data.requests.push(format!("{method} {path}"));
            data.scripted
                .iter()
                .position(|(m, p, _, _)| *m == method && (p.is_empty() || path.contains(p)))
                .map(|index| {
                    let (_, _, status, body) = data.scripted.remove(index).unwrap();
                    (status, body)
                })
                .unwrap_or_else(|| default_reply(&data, &method, &path))
        };
        let text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n",
            text.len()
        );
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
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
    let mut parts = lines.next().unwrap_or_default().split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
    );
    // The body must be consumed too: it is bytes on this keep-alive
    // connection, not the start of the next request.
    let mut length = buffer.len() - (header_end + 4);
    let mut wanted = 0usize;
    for line in lines {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("content-length")
        {
            wanted = value.trim().parse().unwrap_or(0);
        }
    }
    while length < wanted {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => length += n,
        }
    }
    Some((method, path))
}

fn default_reply(data: &Data, method: &str, path: &str) -> (u16, serde_json::Value) {
    let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let expires = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    if method == "GET" && path.contains(&format!("/app/installations/{INSTALLATION}")) {
        if let Some(status) = data.installation_status {
            return (status, serde_json::json!({"message": "Not Found"}));
        }
        return (
            200,
            data.installation.clone().unwrap_or_else(|| {
                serde_json::json!({
                    "id": INSTALLATION,
                    "app_id": 1234,
                    "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                    "suspended_at": null,
                    "permissions": {"contents": "read", "checks": "write"},
                })
            }),
        );
    }
    if method == "POST" && path.contains("/access_tokens") {
        return (
            201,
            serde_json::json!({
                "token": "ghs_reconcile",
                "expires_at": expires,
                "permissions": {"contents": "read", "metadata": "read"},
            }),
        );
    }
    if method == "GET" && path.contains("/installation/repositories") {
        let repos = data.listed.clone().unwrap_or_else(|| {
            vec![serde_json::json!({"id": GITHUB_REPO, "full_name": "account/app", "archived": false})]
        });
        return (200, serde_json::json!({"repositories": repos}));
    }
    if method == "GET" && path.contains(&format!("/repositories/{GITHUB_REPO}")) {
        let body = data.repository.clone().unwrap_or_else(|| {
            serde_json::json!({
                "id": GITHUB_REPO,
                "owner": {"id": ACCOUNT},
                "clone_url": REMOTE,
            })
        });
        return (200, body);
    }
    (404, serde_json::json!({"message": "not found"}))
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    stub: Stub,
    app: Arc<sentinel_github::app::App>,
    repo: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let stub = Stub::start();
    let app = Arc::new(
        sentinel_github::app::App::new(1234, TEST_KEY)
            .unwrap()
            .with_endpoint(&stub.endpoint())
            .unwrap(),
    );
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let alice = UserId::new();
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            sentinel_store::auth::provisioning::insert_human(tx, alice, "alice", true, now)?;
            sentinel_store::auth::create_namespace(
                tx,
                sentinel_core::auth::Principal::new(
                    alice,
                    sentinel_core::auth::Permissions::ALL,
                    None,
                    None,
                ),
                tenant,
                sentinel_core::auth::Namespace::parse("acme").unwrap(),
                sentinel_store::auth::NamespaceKind::Personal(alice),
                now,
            )?;
            sentinel_store::auth::create_repo(
                tx,
                sentinel_core::auth::Principal::new(
                    alice,
                    sentinel_core::auth::Permissions::ALL,
                    None,
                    None,
                ),
                tenant,
                repo,
                "app",
                now,
            )?;
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
            sentinel_store::registration::bind_installation_trusted(tx, installation, tenant, now)?;
            sources::bind(
                tx,
                sentinel_store::registration::Authority::HostLocal,
                Some(alice),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: REMOTE.into(),
                        allowed_refs: vec![REF.into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO)),
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
        repo,
    }
}

fn start(f: &Fixture, notices: Arc<Mutex<Vec<String>>>) -> Reconcile {
    Reconcile::start(
        Arc::clone(&f.store),
        Arc::clone(&f.app),
        Config {
            idle: Duration::from_millis(20),
            ..Config::default()
        },
        move |notice| {
            eprintln!("reconcile[{}]: {}", notice.kind, notice.outcome);
            notices.lock().unwrap().push(notice.outcome.clone());
        },
    )
}

fn binding_revoked(f: &Fixture) -> bool {
    f.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT revoked FROM source_bindings WHERE repo_id=?1",
                [f.repo.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap()
}

fn installation_disabled(f: &Fixture) -> bool {
    f.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT suspended AND NOT permissions_valid FROM installations",
                [],
                |r| r.get::<_, bool>(0),
            )?)
        })
        .unwrap()
}

fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn until_stub(f: &Fixture, what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {what}\nrequests: {:?}",
                f.stub.requests()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn notices_have(notices: &Arc<Mutex<Vec<String>>>, outcome: &str) -> bool {
    notices.lock().unwrap().iter().any(|o| o == outcome)
}

#[test]
fn a_healthy_installation_and_repository_verify() {
    let f = fixture();
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    let f_ref = &f;
    until_stub(f_ref, "the periodic refresh", || {
        notices_have(&notices, "refreshed") && notices_have(&notices, "verified")
    });
    assert!(!binding_revoked(&f));
    // The reconcile token is installation-wide contents:read — never
    // checks:write and never repository-scoped.
    assert!(
        f.stub
            .requests()
            .iter()
            .any(|r| r.starts_with("GET") && r.contains("/installation/repositories")),
        "{:?}",
        f.stub.requests()
    );
    drop(lane);
}

#[test]
fn a_renamed_or_dropped_repository_loses_its_binding() {
    // The installation still covers the repository id, but under a different
    // name: the approved remote does not follow the rename.
    let f = fixture();
    f.stub.data.lock().unwrap().listed = Some(vec![
        serde_json::json!({"id": GITHUB_REPO, "full_name": "other/renamed", "archived": false}),
    ]);
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    until("the rename revoke", || binding_revoked(&f));
    assert!(
        notices
            .lock()
            .unwrap()
            .iter()
            .any(|o| o.contains("revoked")),
        "{:?}",
        notices.lock().unwrap()
    );
    drop(lane);

    // The repository vanished from the grant entirely: an untruncated list
    // that omits it revokes.
    let f = fixture();
    f.stub.data.lock().unwrap().listed = Some(Vec::new());
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    until("the removal revoke", || binding_revoked(&f));
    drop(lane);

    // And the repository pass itself: a mismatched clone URL revokes the
    // binding without rewriting the approved remote.
    let f = fixture();
    f.stub.data.lock().unwrap().repository = Some(serde_json::json!({
        "id": GITHUB_REPO,
        "owner": {"id": ACCOUNT},
        "clone_url": "https://github.com/other/moved.git",
    }));
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    until("the transfer revoke", || binding_revoked(&f));
    drop(lane);
}

#[test]
fn a_gone_installation_disables_issuance_and_revokes_bindings() {
    let f = fixture();
    f.stub.data.lock().unwrap().installation_status = Some(404);
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    until("the installation removal", || {
        installation_disabled(&f) && binding_revoked(&f)
    });
    drop(lane);
}

#[test]
fn a_suspended_installation_stays_disabled_until_the_api_clears_it() {
    let f = fixture();
    f.stub.data.lock().unwrap().installation = Some(serde_json::json!({
        "id": INSTALLATION,
        "app_id": 1234,
        "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
        "suspended_at": "2026-01-01T00:00:00Z",
        "permissions": {"contents": "read", "checks": "write"},
    }));
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    // The kind-0 pass applies the suspended snapshot; the kind-1 repository
    // pass cannot mint through a suspended installation and hands the row
    // back to kind 0.
    until("the suspended refresh", || {
        notices_have(&notices, "refreshed")
    });
    until("the suspended repository pass", || {
        notices_have(&notices, "installation refresh scheduled")
    });
    drop(lane);
    let suspended: bool = f
        .store
        .read(|c| Ok(c.query_row("SELECT suspended FROM installations", [], |r| r.get(0))?))
        .unwrap();
    assert!(suspended, "the API's suspension is durable");
    assert!(!binding_revoked(&f), "suspension alone does not revoke");
}

#[test]
fn a_transient_failure_retries_without_revoking() {
    let f = fixture();
    f.stub.script(
        "GET",
        "/repositories/",
        500,
        serde_json::json!({"message": "boom"}),
    );
    let notices = Arc::new(Mutex::new(Vec::new()));
    let lane = start(&f, Arc::clone(&notices));
    until("the retried repository pass", || {
        notices_have(&notices, "verified")
    });
    let seen = notices.lock().unwrap().clone();
    assert!(seen.contains(&"retry".to_owned()), "{seen:?}");
    assert!(!binding_revoked(&f), "a 500 is not proof of removal");
    drop(lane);
}

/// The lane survives its own settlement: rows seeded before start are due.
#[test]
fn dropping_the_lane_joins_its_thread() {
    let f = fixture();
    let lane = start(&f, Arc::new(Mutex::new(Vec::new())));
    let started = Instant::now();
    drop(lane);
    assert!(started.elapsed() < Duration::from_secs(2));
}
