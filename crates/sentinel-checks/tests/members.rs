use std::{
    collections::HashMap,
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
    Members,
    members::{Config, Notice},
};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    github_members,
    registration::{self, Authority},
    sources,
    sources_forge::{self, Snapshot},
};

/// A test-only RSA key, generated for this suite; it authenticates nothing.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDf6rEvjDV4LPW4
lLht6MWXLarjIFjXnB53o9UxkubIhOGY4RuGq7L2hz8Be5pLy+dA79JbgdoyCzrW
wR8IGVVdWFeSLC3U4RK+AvYhejVxForWyHIjb60GltbZN2pIADLCx2jS7KZK+3sP
fQQa7YxkRCAoZmqqEMV/JqNuFebmICrwN+Zm2NCRIsqxcjbbefIdhlHShveZ6ulS
QLxBN/ZFnCEWSZvZ5D5HDbJx3KHSFGpPZJ4Hyoghv20dYOmv8J2O2U246x9hq46Z
zeutnBkTY11jrYKTJnSt4Oc8Alsf75G9V+Q/nSbmbS2nje8y0qtpKIosSoqEd6Rb
e2+UrQSRAgMBAAECggEAAbj+T9iFGwmEAq10uYY9WmlT16tamZ6KKrcWQ1tPJpbk
niqprbydi+lclAonlMqS2vBZYsI2C7VjyI4L60HYIvekdVO9DsakQHVY/8cPGRGQ
hABe5exElVDU4m8LZJZJTa+vbBN9YEVs5ACtBtjB4C3YvjzS+F/YiB7TyiuVlxq/
r265ZXQdqjy/Hl5G8gwIEVWPF8diR1fQi5nfqKjybSe5DL5kdo3CDHvm6UbY1arI
0j7n/CDCERP/j4XnkS97vbKML3j2l2PFzQ42bgU6GuEtAlJLKHZKja1NiDfmCX2+
0zH6ueVcqVO9iZnxthWznJeUnVWp1V3NeUa8eN1HIQKBgQD8YzEzbpHmXFLd5CCG
i19bgpGIN0bPUpPF6Ipb73j8NW1dXdENRYgPKizWRdBQZygUmwvfuzsUnN+MZMgw
ic09xbw/slO75bDhLtnBDZ34hFloCjJHSXlxeKqlQCkifKmhcS2vkKgVoO3TMp1Z
iyZh2jvCVNOm9U+JfEE4y0+C8QKBgQDjHy0vNtnIvN65DHWsuJWoqrIORDcluExv
50tMySPQ6l/5t6zYW3GNdnUUkXdtjworvIunp7yCnM0FTL/mpFHOkruwr2fJXMIg
GOn0nzcGxKdyy9tFDx7FmJzwUiMow18qXptIdCQJZo0JO+w0iJYBX1pZYtvQSAjd
TJqXdiBboQKBgAQUCkB9gegKB+DEBe6GpATTiEx+MCu7dt3U0x+HMBpLNrgyguVH
AVrVYKIZwLL7577lfnygBuVfX5FiM4XtRB7CajdRR18a6A/LdQNUl//jC5rNx2A1
hLvbqk4/SirfftI4BPf4S28GCbHG+Jnw0K72Gs8aFc1121IqatdjGabRAoGAekkQ
9PjdbZ1zdcLloOeJfNTbJZ9I6gA+94lbG664oAVxQ2zHnX4ut3HuO/LOkKiRW1cb
AlvnvZNbN91I/Y+/lC+g6tKmWN6ejtWbMeB/qh874S0tlBM+CDnRVfuDfrEijhd+
GBagSId0rGIdHXPlADws0y/NFmmSjERwf9hUN8ECgYAlWpgQzrKS7xkaYaCngYgr
sDhna8Obj+EC26+CgQs5BEXE+xkfrGXrPnsjcKpYHXATzMc9wnlWbuTzqWbqkvM7
ya49XtXpSauI28m06lYEfdjXXItrna7u1Kxn02j/ZdJPmLT4KOy2QeDGJopezxB2
N1m0wYzl/x50+EWUWQ1veg==
-----END PRIVATE KEY-----";

const INSTALLATION: u64 = 42;
const ORG: u64 = 73;
const GITHUB_REPO: u64 = 91;
const ALICE_ID: u64 = 1001;

struct World {
    org_login: String,
    logins: HashMap<u64, String>,
    members: HashMap<String, (u64, &'static str, &'static str)>,
    perms: HashMap<(String, String), (u64, &'static str, &'static str)>,
    fail_memberships: Option<(u16, Option<i64>)>,
    fail_tokens: Option<u16>,
    requests: Vec<String>,
}

struct Stub {
    addr: SocketAddr,
    world: Arc<Mutex<World>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Stub {
    fn start() -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let world = Arc::new(Mutex::new(World {
            org_login: "acme".into(),
            logins: HashMap::new(),
            members: HashMap::new(),
            perms: HashMap::new(),
            fail_memberships: None,
            fail_tokens: None,
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (world, stop) = (Arc::clone(&world), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let world = Arc::clone(&world);
                            thread::spawn(move || serve(stream, &world));
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
            world,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn with<T>(&self, change: impl FnOnce(&mut World) -> T) -> T {
        change(&mut self.world.lock().unwrap())
    }

    fn requests(&self) -> Vec<String> {
        self.with(|w| w.requests.clone())
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

fn serve(mut stream: TcpStream, world: &Arc<Mutex<World>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    loop {
        let Some((method, path, body)) = read_request(&mut stream) else {
            return;
        };
        let (status, retry_after, reply) = {
            let mut world = world.lock().unwrap();
            world.requests.push(format!("{method} {path} {body}"));
            route(&world, &method, &path)
        };
        let text = reply.to_string();
        let extra = retry_after
            .map(|s| format!("retry-after: {s}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\n{extra}connection: keep-alive\r\n\r\n",
            text.len()
        );
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
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
    let mut wanted = 0usize;
    for line in lines {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("content-length")
        {
            wanted = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < wanted {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some((method, path, String::from_utf8_lossy(&body).to_string()))
}

fn route(world: &World, method: &str, path: &str) -> (u16, Option<i64>, serde_json::Value) {
    let path = path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let not_found = || (404, None, serde_json::json!({"message": "Not Found"}));
    match (method, segments.as_slice()) {
        ("GET", ["app", "installations", id]) if *id == INSTALLATION.to_string() => (
            200,
            None,
            serde_json::json!({
                "id": INSTALLATION,
                "app_id": 1234,
                "account": {"id": ORG, "login": world.org_login, "type": "Organization"},
                "suspended_at": null,
                "permissions": {"contents": "read", "checks": "write", "members": "read"},
            }),
        ),
        ("POST", ["app", "installations", _, "access_tokens"]) => {
            if let Some(status) = world.fail_tokens {
                return (
                    status,
                    None,
                    serde_json::json!({"message": "permissions not granted"}),
                );
            }
            let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
            (
                201,
                None,
                serde_json::json!({
                    "token": "ghs_members",
                    "expires_at": expires
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    "permissions": {"members": "read", "metadata": "read"},
                }),
            )
        }
        ("GET", ["user", id]) => {
            let Ok(id) = id.parse::<u64>() else {
                return not_found();
            };
            match world.logins.get(&id) {
                Some(login) => (200, None, serde_json::json!({"id": id, "login": login})),
                None => not_found(),
            }
        }
        ("GET", ["orgs", org, "memberships", login]) => {
            if let Some((status, retry)) = world.fail_memberships {
                return (status, retry, serde_json::json!({"message": "later"}));
            }
            if *org != world.org_login {
                return not_found();
            }
            match world.members.get(*login) {
                Some((id, state, role)) => (
                    200,
                    None,
                    serde_json::json!({
                        "state": state,
                        "role": role,
                        "user": {"id": id, "login": login},
                        "organization": {"id": ORG, "login": world.org_login},
                    }),
                ),
                None => not_found(),
            }
        }
        ("GET", ["repos", owner, name, "collaborators", login, "permission"]) => {
            match world
                .perms
                .get(&(format!("{owner}/{name}"), (*login).to_owned()))
            {
                Some((id, permission, role_name)) => (
                    200,
                    None,
                    serde_json::json!({
                        "permission": permission,
                        "role_name": role_name,
                        "user": {"id": id, "login": login},
                    }),
                ),
                None => (
                    200,
                    None,
                    serde_json::json!({
                        "permission": "none",
                        "role_name": "none",
                        "user": {"id": world.members.get(*login).map(|m| m.0), "login": login},
                    }),
                ),
            }
        }
        _ => not_found(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    stub: Stub,
    app: Arc<sentinel_github::app::App>,
    tenant: TenantId,
    repo: RepoId,
    alice: UserId,
    notices: Arc<Mutex<Vec<String>>>,
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
    let (tenant, repo, alice, root) =
        (TenantId::new(), RepoId::new(), UserId::new(), UserId::new());
    let now = UnixMillis::now();
    let admin = Principal::new(root, Permissions::ALL, None, None);
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "root", true, now)?;
            provisioning::insert_human(tx, alice, "alice", false, now)?;
            provisioning::link_verified_identity(tx, alice, "github", &ALICE_ID.to_string(), now)?;
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: INSTALLATION,
                    account_id: ORG,
                    login: "acme",
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
                Some(root),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: "https://github.com/acme/app.git".into(),
                        allowed_refs: vec!["refs/heads/main".into()],
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
            github_members::set_backing_trusted(tx, tenant, true, now)
        })
        .unwrap();
    stub.with(|w| {
        w.logins.insert(ALICE_ID, "alice-gh".into());
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "active", "member"));
        w.perms.insert(
            ("acme/app".into(), "alice-gh".into()),
            (ALICE_ID, "write", "write"),
        );
    });
    Fixture {
        _dir: dir,
        store,
        stub,
        app,
        tenant,
        repo,
        alice,
        notices: Arc::new(Mutex::new(Vec::new())),
    }
}

impl Fixture {
    fn start(&self) -> Members {
        let notices = Arc::clone(&self.notices);
        Members::start(
            Arc::clone(&self.store),
            Arc::clone(&self.app),
            Config {
                idle: Duration::from_millis(20),
                ..Config::default()
            },
            move |notice: &Notice| {
                eprintln!("members: {}", notice.outcome);
                notices.lock().unwrap().push(notice.outcome.clone());
            },
        )
    }

    fn ask(&self) {
        let (tenant, id) = (self.tenant, ALICE_ID);
        self.store
            .writer()
            .write(move |tx| github_members::hint(tx, tenant, Some(id), UnixMillis::now()))
            .unwrap();
    }

    fn passes(&self) -> usize {
        self.notices.lock().unwrap().len()
    }

    fn pass(&self) -> String {
        let before = self.passes();
        self.ask();
        until("a pass", || self.passes() > before);
        self.notices.lock().unwrap()[before].clone()
    }

    fn role(&self) -> Option<i64> {
        let (tenant, alice) = (self.tenant, self.alice);
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT role FROM memberships WHERE tenant_id = ?1 AND user_id = ?2",
                    [tenant.as_bytes(), alice.as_bytes()],
                    |r| r.get(0),
                )
                .ok())
            })
            .unwrap()
    }

    fn grant(&self) -> Option<i64> {
        let (tenant, alice, repo) = (self.tenant, self.alice, self.repo);
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT permissions FROM repo_grants WHERE tenant_id = ?1 AND user_id = ?2 AND repo_id = ?3",
                    [tenant.as_bytes(), alice.as_bytes(), repo.as_bytes()],
                    |r| r.get(0),
                )
                .ok())
            })
            .unwrap()
    }
}

fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_verified_member_joins_with_the_role_and_repository_permission_github_reports() {
    let f = fixture();
    let _lane = f.start();
    assert_eq!(f.pass(), "joined");
    assert_eq!(f.role(), Some(2), "a plain member operates");
    assert_eq!(
        f.grant(),
        Some(3),
        "write maps to read and run, not secrets"
    );

    let requests = f.stub.requests().join("\n");
    assert!(requests.contains("GET /user/1001"), "{requests}");
    assert!(
        requests.contains("GET /orgs/acme/memberships/alice-gh"),
        "{requests}"
    );
    assert!(
        requests.contains("/repos/acme/app/collaborators/alice-gh/permission"),
        "{requests}"
    );
    assert!(
        requests.contains(r#"{"permissions":{"members":"read","metadata":"read"}}"#),
        "{requests}"
    );
}

#[test]
fn an_owner_demoted_on_github_is_demoted_here_and_loses_the_implicit_reach() {
    let f = fixture();
    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "active", "admin"));
    });
    let _lane = f.start();
    assert_eq!(f.pass(), "joined");
    assert_eq!(f.role(), Some(3), "an organization owner administers");
    assert_eq!(f.grant(), None, "an administrator needs no derived grant");

    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "active", "member"));
    });
    assert_eq!(f.pass(), "role changed");
    assert_eq!(f.role(), Some(2));
    assert_eq!(
        f.grant(),
        Some(3),
        "the demoted owner's grants are derived afresh"
    );
}

#[test]
fn a_renamed_login_keeps_access_because_the_id_is_the_identity() {
    let f = fixture();
    let _lane = f.start();
    assert_eq!(f.pass(), "joined");
    f.stub.with(|w| {
        w.logins.insert(ALICE_ID, "alice-renamed".into());
        let entry = w.members.remove("alice-gh").unwrap();
        w.members.insert("alice-renamed".into(), entry);
        let perm = w
            .perms
            .remove(&("acme/app".into(), "alice-gh".into()))
            .unwrap();
        w.perms
            .insert(("acme/app".into(), "alice-renamed".into()), perm);
    });
    assert_eq!(f.pass(), "confirmed");
    assert_eq!(f.role(), Some(2));
    assert!(
        f.stub
            .requests()
            .iter()
            .any(|r| r.contains("/orgs/acme/memberships/alice-renamed")),
        "the current login was resolved from the immutable id"
    );
}

#[test]
fn a_reply_about_another_account_never_admits_or_removes() {
    let f = fixture();
    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (2002, "active", "admin"));
    });
    let _lane = f.start();
    assert_eq!(f.pass(), "kept: unreachable");
    assert_eq!(f.role(), None, "a reused login inherits nothing");
    assert_eq!(f.grant(), None);

    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "active", "member"));
    });
    assert_eq!(f.pass(), "joined");
    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (2002, "active", "member"));
    });
    assert_eq!(f.pass(), "kept: unreachable");
    assert_eq!(f.role(), Some(2));
}

#[test]
fn a_pending_invitation_is_not_membership_and_a_removed_member_is_removed() {
    let f = fixture();
    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "pending", "member"));
    });
    let _lane = f.start();
    assert_eq!(f.pass(), "not a member");
    assert_eq!(f.role(), None);

    f.stub.with(|w| {
        w.members
            .insert("alice-gh".into(), (ALICE_ID, "active", "member"));
    });
    assert_eq!(f.pass(), "joined");
    assert_eq!(f.grant(), Some(3));
    f.stub.with(|w| {
        w.members.remove("alice-gh");
    });
    assert_eq!(f.pass(), "removed: not a member");
    assert_eq!(f.role(), None);
    assert_eq!(f.grant(), None);
}

#[test]
fn a_renamed_organization_cannot_remove_anyone() {
    let f = fixture();
    let _lane = f.start();
    assert_eq!(f.pass(), "joined");
    f.stub.with(|w| w.org_login = "acme-renamed".into());
    assert_eq!(f.pass(), "kept: unreachable");
    assert_eq!(f.role(), Some(2), "nobody lost access over a rename");
}

#[test]
fn rate_limits_server_errors_and_a_missing_permission_keep_access_and_grant_nothing() {
    let f = fixture();
    let _lane = f.start();
    assert_eq!(f.pass(), "joined");

    for failure in [(429, Some(1)), (500, None), (403, None), (502, None)] {
        f.stub.with(|w| w.fail_memberships = Some(failure));
        assert_eq!(f.pass(), "kept: unreachable", "{failure:?}");
        assert_eq!(f.role(), Some(2), "{failure:?}");
        assert_eq!(f.grant(), Some(3), "{failure:?}");
        f.stub.with(|w| w.fail_memberships = None);
        let deadline = Instant::now() + Duration::from_secs(20);
        while f.pass() != "confirmed" {
            assert!(
                Instant::now() < deadline,
                "never recovered from {failure:?}"
            );
            thread::sleep(Duration::from_millis(250));
        }
        assert_eq!(f.role(), Some(2), "{failure:?}");
    }
}

#[test]
fn an_app_without_the_members_permission_admits_nobody_and_asks_nothing_about_them() {
    let f = fixture();
    f.stub.with(|w| w.fail_tokens = Some(422));
    let _lane = f.start();
    assert_eq!(f.pass(), "kept: unreachable");
    assert_eq!(f.role(), None);
    assert_eq!(f.grant(), None);
    assert!(
        f.stub.requests().iter().all(|r| !r.contains("/user/")),
        "no request about the person without a token"
    );
}

#[test]
fn a_person_without_a_linked_account_is_never_asked_about() {
    let f = fixture();
    let (alice, tenant) = (f.alice, f.tenant);
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM external_identities WHERE user_id = ?1",
                [alice.as_bytes()],
            )?;
            tx.execute(
                "INSERT INTO github_member_checks(tenant_id, user_id, next_ms) VALUES (?1, ?2, 0)",
                [tenant.as_bytes(), alice.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let _lane = f.start();
    until("the pass", || f.passes() >= 1);
    assert_eq!(f.role(), None);
    assert!(
        f.stub.requests().iter().all(|r| !r.contains("/user/")),
        "{:?}",
        f.stub.requests()
    );
}
