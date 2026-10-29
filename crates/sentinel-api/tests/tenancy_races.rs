//! Races that only show over HTTP: several clients presenting the one setup token, and the sign-up,
//! mail delivery and domain auto-join path run by several people at once. Mail goes to a fake endpoint
//! that records what the real Resend transport sends.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use fixture::{PASSWORD, call};
use sentinel_auth::sealed::Key;
use sentinel_core::{UnixMillis, UserId};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Error as StoreError, Store, auto_join, email,
    local_auth::{self, Policy},
    logs::LogStore,
    objects::Objects,
    registration::{self, Authority, DeploymentPolicy, Registration},
    setup,
};
use serde_json::{Value, json};

/// Accepts any number of connections and records each raw request; answers every one with success.
fn fake_resend() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/emails", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + length {
                        break;
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&raw).into_owned());
                let body = r#"{"id":"x"}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    (url, seen)
}

struct World {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    _lane: Option<sentinel_mail::Lane>,
    server: Option<sentinel_api::Server>,
    base: String,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

/// A server with no administrator yet (first-run setup open) and, when `mail` is set, a real mail lane
/// delivering sealed verification messages to the fake endpoint.
fn world(mail: bool) -> World {
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
    let (url, sent) = fake_resend();
    let (key, lane) = if mail {
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let key = Arc::new(Key::load(&path).unwrap());
        email::set_delivery(
            &store,
            true,
            Some("https://ci.example.com"),
            UnixMillis::now(),
        )
        .unwrap();
        let resend = Arc::new(sentinel_mail::Resend::with_endpoint(
            sentinel_mail::ApiKey::new(b"re_racekey_0123456789".to_vec()).unwrap(),
            sentinel_mail::Sender::parse("Sentinel <ci@example.com>").unwrap(),
            &url,
        ));
        let lane = sentinel_mail::Lane::start(
            Arc::clone(&store),
            Arc::clone(&key),
            Box::new(resend),
            sentinel_mail::LaneConfig {
                idle: Duration::from_millis(100),
                ..Default::default()
            },
            |_| {},
        );
        (Some(key), Some(lane))
    } else {
        (None, None)
    };
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: key,
            sessions: Policy::default(),
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
    World {
        _dir: dir,
        store,
        _controller: controller,
        _lane: lane,
        server: Some(server),
        base,
        sent,
    }
}

/// A distinct client address per caller, so the per-client admission budgets do not mask a race.
fn client(n: usize) -> String {
    format!("198.51.100.{}", n + 1)
}

fn count(w: &World, sql: &'static str) -> i64 {
    w.store
        .read(move |c| c.query_row(sql, [], |r| r.get(0)).map_err(StoreError::from))
        .unwrap()
}

#[test]
fn clients_racing_one_setup_token_create_one_administrator() {
    let w = world(false);
    let token = setup::issue(&w.store, UnixMillis::now()).unwrap().unwrap();
    let mut text = String::new();
    token.expose(&mut text);
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let runners: Vec<_> = (0..6)
            .map(|n| {
                let (base, text) = (&w.base, &text);
                scope.spawn(move || {
                    let xff = client(n);
                    call(
                        base,
                        "POST",
                        "/api/v1/setup",
                        Some(&json!({
                            "token": text,
                            "email": format!("ada{n}@example.com"),
                            "password": PASSWORD,
                            "registration": "approval-required",
                            "tenant_creation": "approved-users",
                            "instance_name": "Acme CI",
                            "organization": "acme",
                        })),
                        &[("x-forwarded-for", &xff)],
                    )
                    .0
                })
            })
            .collect();
        runners.into_iter().map(|r| r.join().unwrap()).collect()
    });
    assert_eq!(
        statuses.iter().filter(|s| **s == 201).count(),
        1,
        "exactly one presentation of the token wins: {statuses:?}"
    );
    assert!(
        statuses.iter().all(|s| *s == 201 || (400..500).contains(s)),
        "every loser is refused cleanly: {statuses:?}"
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM users WHERE kind = 0"),
        1,
        "one administrator exists"
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM tenants WHERE slug = 'acme'"),
        1
    );
    assert!(!w.store.read(setup::is_open).unwrap());
}

/// Registers `n` people at `example.com` through the public route at the same time and waits until the
/// mail lane has delivered every verification message. Returns the address and token of each, sorted.
fn register_everyone(w: &World, n: usize) -> Vec<(String, String)> {
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let runners: Vec<_> = (0..n)
            .map(|i| {
                let base = &w.base;
                scope.spawn(move || {
                    let xff = client(i);
                    call(
                        base,
                        "POST",
                        "/api/v1/register",
                        Some(&json!({
                            "email": format!("person{i}@example.com"),
                            "password": PASSWORD,
                        })),
                        &[("x-forwarded-for", &xff)],
                    )
                    .0
                })
            })
            .collect();
        runners.into_iter().map(|r| r.join().unwrap()).collect()
    });
    assert_eq!(statuses, vec![202; n]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while w.sent.lock().unwrap().len() < n {
        assert!(
            Instant::now() < deadline,
            "only {} of {n} messages arrived",
            w.sent.lock().unwrap().len()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Give a duplicate time to show itself, then require the outbox to be settled.
    std::thread::sleep(Duration::from_millis(500));
    let mut by_recipient: HashMap<String, String> = HashMap::new();
    for raw in w.sent.lock().unwrap().iter() {
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default();
        let message: Value = serde_json::from_str(body).expect("a JSON mail request");
        let to = message["to"][0].as_str().unwrap().to_owned();
        let text = message["text"].as_str().unwrap();
        let token = text
            .split("/verify-email#token=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("a verification link")
            .to_owned();
        assert!(
            by_recipient.insert(to.clone(), token).is_none(),
            "{to} was mailed twice"
        );
    }
    assert_eq!(by_recipient.len(), n);
    let (queued, _, abandoned) = w.store.read(email::counts).unwrap();
    assert_eq!((queued, abandoned), (0, 0));
    let mut all: Vec<(String, String)> = by_recipient.into_iter().collect();
    all.sort();
    all
}

fn open_registration(w: &World) {
    local_auth::bootstrap(
        &w.store,
        "root",
        "Root",
        b"an operator password",
        UnixMillis::now(),
    )
    .unwrap();
    w.store
        .writer()
        .write(|tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration: Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

#[test]
fn simultaneous_sign_ups_each_get_exactly_one_verification_message() {
    let w = world(true);
    open_registration(&w);
    let mails = register_everyone(&w, 6);
    for (n, (address, _)) in mails.iter().enumerate() {
        assert_eq!(address, &format!("person{n}@example.com"));
    }
    // A delivered link is the real one: it verifies the address it was mailed to, once.
    let (_, token) = &mails[0];
    let (status, _, answer) = call(
        &w.base,
        "POST",
        "/api/v1/email/verify",
        Some(&json!({ "token": token })),
        &[("x-forwarded-for", &client(20))],
    );
    assert_eq!(
        (status, &answer["verified"]),
        (200, &json!(true)),
        "{answer}"
    );
    assert_eq!(
        count(
            &w,
            "SELECT COUNT(*) FROM users WHERE email_verified_ms IS NOT NULL AND email LIKE 'person%'"
        ),
        1
    );
    let (status, _, _) = call(
        &w.base,
        "POST",
        "/api/v1/email/verify",
        Some(&json!({ "token": token })),
        &[("x-forwarded-for", &client(21))],
    );
    assert_eq!(status, 400);
}

#[test]
fn simultaneous_verifications_over_http_create_the_auto_join_organization_once() {
    let w = world(true);
    open_registration(&w);
    let parsed = auto_join::parse("example.com");
    assert!(parsed.ignored.is_empty());
    assert!(
        auto_join::set_rules(&w.store, &parsed.rules)
            .unwrap()
            .is_empty()
    );
    let mails = register_everyone(&w, 6);
    // Approval comes first: a person still waiting for it joins nothing.
    let users: Vec<UserId> = w
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT id FROM users WHERE email LIKE 'person%'")?;
            let rows = stmt.query_map([], |r| r.get::<_, [u8; 16]>(0))?;
            rows.map(|r| UserId::from_bytes(r?).map_err(|_| StoreError::Corrupt("users.id")))
                .collect::<Result<Vec<_>, StoreError>>()
        })
        .unwrap();
    assert_eq!(users.len(), 6);
    w.store
        .writer()
        .write(move |tx| {
            for user in &users {
                registration::approve(tx, Authority::HostLocal, *user, UnixMillis::now())?;
            }
            Ok(())
        })
        .unwrap();
    let answers: Vec<(u16, Value)> = std::thread::scope(|scope| {
        let runners: Vec<_> = mails
            .iter()
            .enumerate()
            .map(|(i, (_, token))| {
                let base = &w.base;
                scope.spawn(move || {
                    let xff = client(i);
                    let (status, _, answer) = call(
                        base,
                        "POST",
                        "/api/v1/email/verify",
                        Some(&json!({ "token": token })),
                        &[("x-forwarded-for", &xff)],
                    );
                    (status, answer)
                })
            })
            .collect();
        runners.into_iter().map(|r| r.join().unwrap()).collect()
    });
    for (status, answer) in &answers {
        assert_eq!(
            (*status, &answer["verified"]),
            (200, &json!(true)),
            "{answer}"
        );
    }
    assert_eq!(
        count(
            &w,
            "SELECT COUNT(*) FROM tenants WHERE slug = 'example-com'"
        ),
        1,
        "the organization exists once"
    );
    let with_role = |role: i64| -> i64 {
        w.store
            .read(move |c| {
                c.query_row(
                    "SELECT COUNT(*) FROM memberships m JOIN tenants t ON t.id = m.tenant_id
                     WHERE t.slug = 'example-com' AND m.role = ?1",
                    [role],
                    |r| r.get(0),
                )
                .map_err(StoreError::from)
            })
            .unwrap()
    };
    assert_eq!(with_role(3), 1, "the first to arrive administers it");
    assert_eq!(with_role(1), 5, "the other five join as readers");
}
