//! Short-lived download links: a minted token streams exactly what the authenticated routes stream, and every way a
//! token can be wrong answers the same `not_found`. The last test is the canary: no token text reaches a log line, an
//! error body or the database.

use std::{
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    ArtifactId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self, Authority, NamespaceKind},
    dispatch::{self, Capacity},
    local_auth,
    logs::LogStore,
    objects::{Entry, Expect, Kind, Objects},
    registration::{self, Admission, Applicant, Terms},
    runs, tenancy,
    tenancy::PoolKind,
    tokens::{self, Grant},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const DAY_MS: i64 = 86_400_000;
const PASSWORD: &str = "an acceptable member password";

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    controller: Controller,
    key_path: PathBuf,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    foreign: String,
    tenant: TenantId,
    repo: RepoId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    let foreign = foreign_member(&store, root);
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
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let token = bearer(&store, root, P::ALL, "links");
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let logs = Arc::clone(&logs);
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let server = start(
        &store,
        &logs,
        &objects,
        controller.handle(),
        Some(Arc::clone(&key)),
    );
    let base = format!("http://{}", server.local_addr());
    Deployment {
        dir,
        store,
        objects,
        logs,
        controller,
        key_path,
        server: Some(server),
        base,
        token,
        foreign,
        tenant,
        repo,
    }
}

fn start(
    store: &Arc<Store>,
    logs: &Arc<LogStore>,
    objects: &Arc<Objects>,
    controller: sentinel_link::controller::Handle,
    key: Option<Arc<Key>>,
) -> sentinel_api::Server {
    sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(store),
        logs: Arc::clone(logs),
        objects: Arc::clone(objects),
        controller,
        secret_key: key,
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap()
}

impl Deployment {
    /// Starts the API again from the key file as it now stands; the store, objects and controller carry over.
    fn restart(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
        let key = Arc::new(Key::load(&self.key_path).unwrap());
        let server = start(
            &self.store,
            &self.logs,
            &self.objects,
            self.controller.handle(),
            Some(key),
        );
        self.base = format!("http://{}", server.local_addr());
        self.server = Some(server);
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn bearer(store: &Store, user: UserId, permissions: P, name: &'static str) -> String {
    let granted = tokens::provision(
        store,
        Grant {
            user,
            name,
            permissions,
            tenant: None,
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
}

/// A second organization with its own member, who can read nothing of the first.
fn foreign_member(store: &Store, root: UserId) -> String {
    let invitation = store
        .writer()
        .write(|tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms::default(),
                UnixMillis::now(),
            )
        })
        .unwrap()
        .secret;
    let member = match registration::register(
        store,
        Applicant::Local {
            display_name: "outsider",
            username: "outsider",
            password: PASSWORD.as_bytes(),
        },
        Some(&invitation),
        UnixMillis::now(),
    )
    .unwrap()
    {
        Admission::Admitted(user) => user,
        other => panic!("{other:?}"),
    };
    let tenant = TenantId::new();
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("other").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, member, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, RepoId::new(), "other", now)
        })
        .unwrap();
    bearer(store, member, P::REPOSITORY, "outsider")
}

/// One published artifact: the run, its single job, and the artifact row with its manifest.
struct Published {
    run: RunId,
    artifact: ArtifactId,
    entries: Vec<Entry>,
}

fn publish(d: &Deployment, name: &str, bodies: &[(&str, Vec<u8>)], retain_ms: i64) -> Published {
    let name = name.to_owned();
    let (tenant, repo, store, objects) = (
        d.tenant,
        d.repo,
        Arc::clone(&d.store),
        Arc::clone(&d.objects),
    );
    let now = UnixMillis::now();
    let run = RunId::new();
    let spec = RunSpec::new(
        PinnedSource::new(
            &format!("https://git.example:8443/team/{name}.git"),
            SHA,
            Some("refs/heads/main"),
        )
        .unwrap(),
        compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
        )
        .unwrap(),
    )
    .unwrap();
    let job = store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, IMAGE, "linux/amd64")?;
            }
            Ok(ids[0])
        })
        .unwrap();
    let (pool, worker) = (PoolId::new(), WorkerId::new());
    let pool_name = format!("pool-{name}");
    let pool_id = store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                &pool_name,
                PoolKind::Dedicated(tenant),
                now,
            )?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &sentinel_auth::secret::Secret::parse(&text).unwrap(),
                Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "w",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                now,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 8 << 30,
                    disk_bytes: 0,
                },
            )?;
            Ok(pool)
        })
        .unwrap();
    let offer = store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool_id, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("the queued job was placed");
    let mut entries = Vec::with_capacity(bodies.len());
    let mut payload_len = 0;
    let mut staged = Vec::with_capacity(bodies.len());
    for (path, body) in bodies {
        let one = objects
            .stage(tenant, &body[..], u64::MAX, Expect::default())
            .unwrap();
        entries.push(Entry {
            path: (*path).to_owned(),
            digest: one.digest(),
            len: one.len(),
            mode: 0o644,
        });
        payload_len += one.len();
        staged.push(one);
    }
    let listed = entries.clone();
    let artifact = store
        .writer()
        .write(move |tx| {
            for one in &staged {
                objects.commit(tx, one)?;
            }
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, &name),
                &listed,
            )?;
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                offer.attempt,
                &name,
                artifacts::State::Captured,
                Some(version),
                listed.len() as u64,
                payload_len,
                UnixMillis(now.0 + retain_ms),
                now,
            )
        })
        .unwrap();
    Published {
        run,
        artifact,
        entries,
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
}

fn mint(d: &Deployment, p: &Published, body: Value, credential: Option<&str>) -> (u16, Value) {
    let url = format!(
        "{}/api/v1/runs/{}/artifacts/{}/link",
        d.base, p.run, p.artifact
    );
    let mut request = agent().post(&url);
    if let Some(credential) = credential {
        request = request.header("authorization", credential);
    }
    let response = request
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// The same request without a run or artifact to hang it on: a caller naming a foreign run uses this.
fn mint_for(
    d: &Deployment,
    run: RunId,
    art: ArtifactId,
    body: Value,
    credential: &str,
) -> (u16, Value) {
    let url = format!("{}/api/v1/runs/{run}/artifacts/{art}/link", d.base);
    let response = agent()
        .post(&url)
        .header("authorization", credential)
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn minted(d: &Deployment, p: &Published, body: Value) -> (String, i64) {
    let (status, answer) = mint(d, p, body, Some(&d.token));
    assert_eq!(status, 200, "{answer}");
    (
        answer["url"].as_str().expect("a url").to_owned(),
        answer["expires_ms"].as_i64().expect("an expiry"),
    )
}

struct Fetched {
    status: u16,
    body: Vec<u8>,
}

fn fetch(url: &str) -> Fetched {
    let response = agent().get(url).call().unwrap();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .into_body()
        .as_reader()
        .read_to_end(&mut body)
        .unwrap();
    Fetched { status, body }
}

fn authed(d: &Deployment, path: &str) -> Fetched {
    let response = agent()
        .get(&format!("{}{path}", d.base))
        .header("authorization", &d.token)
        .call()
        .unwrap();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .into_body()
        .as_reader()
        .read_to_end(&mut body)
        .unwrap();
    Fetched { status, body }
}

/// The refusal a client sees for a token that must not be distinguishable from an unknown one.
fn refusal(url: &str) -> Value {
    let response = agent().get(url).call().unwrap();
    assert_eq!(response.status().as_u16(), 404, "{url}");
    let text = response.into_body().read_to_string().unwrap_or_default();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn bodies() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("out/report.txt", b"a report\n".to_vec()),
        ("out/bin/padded.bin", vec![0x5Au8; 1500]),
        ("out/empty", Vec::new()),
    ]
}

#[test]
fn a_minted_link_streams_the_same_bytes_as_the_authenticated_routes() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    for format in ["tar", "zip"] {
        let (url, expires) = minted(&d, &published, json!({ "format": format }));
        assert!(
            expires > UnixMillis::now().0 && expires <= UnixMillis::now().0 + 300_000,
            "the default life is five minutes"
        );
        let linked = fetch(&url);
        assert_eq!(linked.status, 200);
        let direct = authed(
            &d,
            &format!(
                "/api/v1/runs/{}/artifacts/{}/archive?format={format}",
                published.run, published.artifact
            ),
        );
        assert_eq!(direct.status, 200);
        assert_eq!(linked.body, direct.body, "{format}");
        assert!(!linked.body.is_empty());
    }
    for entry in &published.entries {
        let (url, _) = minted(&d, &published, json!({ "entry": entry.path }));
        let linked = fetch(&url);
        assert_eq!(linked.status, 200, "{}", entry.path);
        let direct = authed(
            &d,
            &format!("/api/v1/tenants/acme/objects/{}", entry.digest),
        );
        assert_eq!(direct.status, 200);
        assert_eq!(linked.body, direct.body, "{}", entry.path);
    }
}

#[test]
fn another_tenants_member_is_refused_at_the_same_shape_as_a_forged_token() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let forged = refusal(&format!("{}/dl/forged-token", d.base));

    let (status, answer) = mint(&d, &published, json!({ "format": "tar" }), Some(&d.foreign));
    assert_eq!(status, 404, "{answer}");
    assert_eq!(answer, forged);

    // The same for a foreign run id: the run is resolved first, so nothing of it is confirmed.
    let (status, answer) = mint_for(
        &d,
        published.run,
        ArtifactId::new(),
        json!({ "format": "tar" }),
        &d.token,
    );
    assert_eq!(status, 404);
    assert_eq!(answer, forged);
}

#[test]
fn expiry_is_exclusive_and_a_token_past_it_is_refused_like_a_forgery() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (url, expires) = minted(&d, &published, json!({ "expires_secs": 1 }));
    assert!(expires <= UnixMillis::now().0 + 1_000);
    assert_eq!(fetch(&url).status, 200, "valid before its expiry");
    let forged = refusal(&format!("{}/dl/forged-token", d.base));
    std::thread::sleep(Duration::from_millis(1_100));
    let expired = refusal(&url);
    assert_eq!(expired, forged);

    let (status, answer) = mint(
        &d,
        &published,
        json!({ "expires_secs": 3_601 }),
        Some(&d.token),
    );
    assert_eq!(
        (status, answer["code"].as_str()),
        (400, Some("invalid_request"))
    );
    let (status, _) = mint(&d, &published, json!({ "expires_secs": 0 }), Some(&d.token));
    assert_eq!(status, 400);
}

#[test]
fn a_token_naming_an_artifact_past_its_retention_is_refused() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (url, _) = minted(&d, &published, json!({ "format": "tar" }));
    assert_eq!(fetch(&url).status, 200);

    // A second artifact whose deadline has already passed mints nothing, and a link minted before the deadline is
    // refused once it is reached.
    let retired = publish(&d, "retired", &bodies(), -1);
    let (status, answer) = mint(&d, &retired, json!({ "format": "tar" }), Some(&d.token));
    assert_eq!(status, 404, "{answer}");

    let short = publish(&d, "short", &bodies(), 300);
    let (url, _) = minted(&d, &short, json!({ "format": "tar" }));
    assert_eq!(fetch(&url).status, 200);
    std::thread::sleep(Duration::from_millis(400));
    let forged = refusal(&format!("{}/dl/forged-token", d.base));
    assert_eq!(refusal(&url), forged);
}

#[test]
fn a_token_from_a_previous_key_epoch_is_refused() {
    let mut d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (old_url, _) = minted(&d, &published, json!({ "format": "tar" }));
    assert_eq!(fetch(&old_url).status, 200);
    let old_token = old_url.rsplit('/').next().unwrap().to_owned();

    let backup = d.dir.path().join("pre-rotation.key");
    assert_eq!(Key::rotate(&d.key_path, &backup).unwrap(), 2);
    d.restart();

    let forged = refusal(&format!("{}/dl/forged-token", d.base));
    assert_eq!(refusal(&format!("{}/dl/{old_token}", d.base)), forged);

    // The new epoch mints links the new key verifies.
    let (new_url, _) = minted(&d, &published, json!({ "format": "tar" }));
    assert_eq!(fetch(&new_url).status, 200);
}

#[test]
fn a_tenant_suspended_after_minting_makes_its_links_not_found() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (url, _) = minted(&d, &published, json!({ "format": "tar" }));
    assert_eq!(fetch(&url).status, 200);
    let tenant = d.tenant;
    d.store
        .writer()
        .write(move |tx| tenancy::suspend(tx, Authority::HostLocal, tenant, UnixMillis::now()))
        .unwrap();
    let forged = refusal(&format!("{}/dl/forged-token", d.base));
    assert_eq!(refusal(&url), forged);
}

#[test]
fn minting_without_sealed_secret_storage_is_refused() {
    let mut d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    if let Some(server) = d.server.take() {
        server.shutdown();
    }
    let server = start(&d.store, &d.logs, &d.objects, d.controller.handle(), None);
    d.base = format!("http://{}", server.local_addr());
    d.server = Some(server);
    let (status, answer) = mint(&d, &published, json!({ "format": "tar" }), Some(&d.token));
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["code"].as_str(), Some("forbidden"));
}

#[test]
fn a_link_may_be_redeemed_more_than_once_inside_its_window() {
    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (url, _) = minted(&d, &published, json!({ "format": "zip" }));
    let first = fetch(&url);
    let second = fetch(&url);
    assert_eq!(first.status, 200);
    assert_eq!(second.status, 200);
    assert_eq!(first.body, second.body);
}

#[test]
fn no_token_text_reaches_a_log_line_an_error_body_or_the_database() {
    let sink = Capture::default();
    let writer = sink.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish(),
    )
    .expect("the test process owns its subscriber");

    let d = deployment();
    let published = publish(&d, "logs", &bodies(), 7 * DAY_MS);
    let (url, _) = minted(&d, &published, json!({ "format": "tar" }));
    let token = url.rsplit('/').next().unwrap().to_owned();
    let digest = {
        let hash = blake3::hash(token.as_bytes());
        hash.to_hex().as_str()[..16].to_owned()
    };

    assert_eq!(fetch(&url).status, 200);
    // A refusal and a forged attempt are logged too, and neither carries the text.
    let forged = format!("{}/dl/{token}x", d.base);
    let refused_body = refusal(&forged);
    let expired_body = refusal(&format!("{}/dl/expired", d.base));

    let logs = sink.text();
    assert!(
        logs.contains(&digest),
        "the access log names the digest: {logs}"
    );
    assert!(logs.contains("download_link"), "{logs}");
    assert!(
        logs.contains("served") && logs.contains("refused"),
        "{logs}"
    );
    assert!(!logs.contains(&token), "the token reached a log line");
    for (name, body) in [("forged", &refused_body), ("unknown", &expired_body)] {
        let text = body.to_string();
        assert!(
            !text.contains(&token),
            "the token reached the {name} body: {text}"
        );
    }

    // Every file SQLite may have written: the database, its write-ahead log and its shared-memory index.
    for name in ["metadata.sqlite", "metadata.sqlite-wal"] {
        let path = d.dir.path().join(name);
        if let Ok(bytes) = std::fs::read(&path) {
            assert!(
                !bytes
                    .windows(token.len())
                    .any(|window| window == token.as_bytes()),
                "the token reached {name}"
            );
        }
    }
}

/// A `tracing` writer that keeps every line the test process emits.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
