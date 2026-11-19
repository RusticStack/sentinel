//! Entry previews: what the run page's browser may show inline, bounded and served as an attachment.
//!
//! A preview is read back over the wire with its headers, because the headers are the contract: what the entry is served
//! as, that it is an attachment, that nothing is sniffed, that any document it names is sandboxed, and that a text body
//! stops exactly at the bound the answer promised.

use std::{collections::HashMap, io::Read, sync::Arc};

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
    objects::{Digest, Entry, Expect, Kind, Objects},
    registration::{self, Admission, Applicant, Terms},
    runs, tenancy,
    tenancy::PoolKind,
    tokens::{self, Grant},
    workers::{self, Presentation},
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const DAY_MS: i64 = 86_400_000;
const PASSWORD: &str = "correct horse battery staple";

/// A 1x1 transparent PNG: a real image, so what the route calls an image is one a browser draws.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    root: UserId,
    other: TenantId,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    tenant: TenantId,
    repo: RepoId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    sentinel_auth::sealed::Key::load(&key_path).unwrap();
    let (tenant, repo, other) = (TenantId::new(), RepoId::new(), TenantId::new());
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
            auth::set_membership(tx, admin, other, root, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let granted = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "preview",
            permissions: P::ALL,
            tenant: None,
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let api_key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
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
        logs,
        objects: Arc::clone(&objects),
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
        objects,
        root,
        other,
        _controller: controller,
        server: Some(server),
        base,
        token: sentinel_auth::token::format(&granted.secret),
        tenant,
        repo,
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn bearer(d: &Deployment) -> String {
    format!("Bearer {}", d.token)
}

/// Someone who belongs to another tenant and holds every permission: what they reach of this tenant's artifacts is
/// exactly what a stranger reaches.
fn outsider(d: &Deployment) -> String {
    let (store, other) = (Arc::clone(&d.store), d.other);
    let invitation = store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms {
                    tenant: Some(other),
                    role: Some(Role::TenantAdmin),
                    identity: None,
                    lifetime_ms: 600_000,
                },
                UnixMillis::now(),
            )
        })
        .unwrap()
        .secret;
    let user: UserId = match registration::register(
        &d.store,
        Applicant::Local {
            display_name: "Outsider",
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
    let granted = tokens::provision(
        &d.store,
        Grant {
            user,
            name: "outsider",
            permissions: P::REPOSITORY,
            tenant: None,
            repo: None,
            lifetime_ms: 600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
}

/// One published artifact: the run, its single job, and the artifact row with its manifest.
struct Published {
    run: RunId,
    artifact: ArtifactId,
}

/// Stages each body as an object and publishes them as one artifact of a fresh run, through the calls the controller's
/// own publication path makes.
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
    Published { run, artifact }
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
}

struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    stated: usize,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }
}

fn preview(d: &Deployment, p: &Published, path: &str, auth: Option<&str>) -> Answer {
    let url = format!(
        "{}/api/v1/runs/{}/artifacts/{}/preview?path={}",
        d.base,
        p.run,
        p.artifact,
        path.replace('/', "%2F")
    );
    let mut request = agent().get(&url);
    request = request.header(
        "authorization",
        auth.map_or_else(|| bearer(d), str::to_owned),
    );
    let response = request.call().unwrap();
    let status = response.status().as_u16();
    let mut response = response;
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.as_str().to_ascii_lowercase(),
                value.to_str().ok()?.to_owned(),
            ))
        })
        .collect();
    let stated = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .unwrap();
    Answer {
        status,
        headers,
        stated,
        body,
    }
}

fn detail(d: &Deployment, p: &Published) -> serde_json::Value {
    let response = agent()
        .get(&format!(
            "{}/api/v1/runs/{}/artifacts/{}",
            d.base, p.run, p.artifact
        ))
        .header("authorization", &bearer(d))
        .call()
        .unwrap();
    let text = response.into_body().read_to_string().unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The bodies every test previews from: a text file, a screenshot, a text entry past the bound, and a binary.
fn published(d: &Deployment, retain_ms: i64) -> Published {
    let big = vec![b'a'; (1 << 20) + 4_096];
    publish(
        d,
        "reports",
        &[
            (
                "logs/build.txt",
                b"compiling 42 crates\nfinished\n".to_vec(),
            ),
            ("reports/pass.png", PNG.to_vec()),
            ("logs/full.txt", big),
            ("bin/tool", vec![0, 1, 2, 0xff]),
        ],
        retain_ms,
    )
}

#[test]
fn a_text_entry_previews_as_an_attachment() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let answer = preview(&d, &p, "logs/build.txt", None);
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("content-type"), "text/plain; charset=utf-8");
    assert_eq!(
        answer.header("content-disposition"),
        "attachment; filename=\"build.txt\""
    );
    assert_eq!(answer.header("x-content-type-options"), "nosniff");
    assert_eq!(
        answer.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(answer.header("x-sentinel-truncated"), "false");
    assert_eq!(answer.body, b"compiling 42 crates\nfinished\n");
    assert_eq!(answer.stated, answer.body.len());
}

#[test]
fn a_text_preview_stops_at_one_mebibyte_and_says_so() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let answer = preview(&d, &p, "logs/full.txt", None);
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("x-sentinel-truncated"), "true");
    assert_eq!(answer.body.len(), 1 << 20);
    // The bound is the answer's own length, stated before the first byte: a client holds no more than it was promised.
    assert_eq!(answer.stated, 1 << 20);
    assert!(answer.body.iter().all(|b| *b == b'a'));
}

#[test]
fn an_image_previews_whole_with_its_own_type() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let answer = preview(&d, &p, "reports/pass.png", None);
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("content-type"), "image/png");
    assert_eq!(
        answer.header("content-disposition"),
        "attachment; filename=\"pass.png\""
    );
    assert_eq!(answer.header("x-content-type-options"), "nosniff");
    assert_eq!(
        answer.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(answer.body, PNG);
    assert_eq!(answer.stated, PNG.len());
}

#[test]
fn an_image_past_its_bound_is_refused_rather_than_half_served() {
    let d = deployment();
    let oversized = vec![0u8; (8 << 20) + 1];
    let p = publish(&d, "shots", &[("shots/wide.png", oversized)], DAY_MS);
    let answer = preview(&d, &p, "shots/wide.png", None);
    assert_eq!(
        answer.status,
        400,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

#[test]
fn entries_that_are_not_previewable_and_paths_the_manifest_lacks_are_refused() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let binary = preview(&d, &p, "bin/tool", None);
    assert_eq!(binary.status, 400, "a binary entry downloads instead");
    let missing = preview(&d, &p, "reports/absent.txt", None);
    assert_eq!(missing.status, 404);
    let no_path = agent()
        .get(&format!(
            "{}/api/v1/runs/{}/artifacts/{}/preview",
            d.base, p.run, p.artifact
        ))
        .header("authorization", &bearer(&d))
        .call()
        .unwrap();
    assert_eq!(no_path.status().as_u16(), 400);
    // A path twice is ambiguous, never silently one of them.
    let twice = agent()
        .get(&format!(
            "{}/api/v1/runs/{}/artifacts/{}/preview?path=logs%2Fbuild.txt&path=bin%2Ftool",
            d.base, p.run, p.artifact
        ))
        .header("authorization", &bearer(&d))
        .call()
        .unwrap();
    assert_eq!(twice.status().as_u16(), 400);
}

#[test]
fn another_tenant_previews_nothing_and_cannot_tell_it_from_a_missing_artifact() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let refuse = outsider(&d);
    let other = preview(&d, &p, "logs/build.txt", Some(&refuse));
    assert_eq!(
        other.status,
        404,
        "{}",
        String::from_utf8_lossy(&other.body)
    );
    let unknown = agent()
        .get(&format!(
            "{}/api/v1/runs/{}/artifacts/{}/preview?path=logs%2Fbuild.txt",
            d.base,
            p.run,
            ArtifactId::new()
        ))
        .header("authorization", &refuse)
        .call()
        .unwrap();
    assert_eq!(unknown.status().as_u16(), 404);
    // The owner still reads it: the refusal is the caller's, not the artifact's.
    assert_eq!(preview(&d, &p, "logs/build.txt", None).status, 200);
}

#[test]
fn a_preview_without_the_artifact_scope_is_forbidden() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let narrow = tokens::provision(
        &d.store,
        Grant {
            user: d.root,
            name: "runs-only",
            permissions: P::RUN,
            tenant: None,
            repo: None,
            lifetime_ms: 600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let answer = preview(
        &d,
        &p,
        "logs/build.txt",
        Some(&format!(
            "Bearer {}",
            sentinel_auth::token::format(&narrow.secret)
        )),
    );
    assert_eq!(answer.status, 403);
}

#[test]
fn an_artifact_past_its_deadline_previews_nothing_unless_pinned() {
    let d = deployment();
    let p = published(&d, -1_000);
    assert_eq!(preview(&d, &p, "logs/build.txt", None).status, 404);
}

#[test]
fn the_detail_labels_each_entry_with_what_it_previews_as() {
    let d = deployment();
    let p = published(&d, DAY_MS);
    let row = detail(&d, &p);
    let entries = row["manifest"]["entries"].as_array().unwrap();
    let label = |path: &str| {
        entries
            .iter()
            .find(|e| e["path"] == path)
            .map(|e| e["preview"].clone())
            .unwrap()
    };
    assert_eq!(label("logs/build.txt"), serde_json::json!("text"));
    assert_eq!(label("logs/full.txt"), serde_json::json!("text"));
    assert_eq!(label("reports/pass.png"), serde_json::json!("image"));
    assert_eq!(label("bin/tool"), serde_json::Value::Null);
    // The digest and length the page shows are the manifest's own.
    let entry = entries
        .iter()
        .find(|e| e["path"] == "logs/build.txt")
        .unwrap();
    assert_eq!(entry["len"], serde_json::json!(29));
    assert!(Digest::parse(entry["digest"].as_str().unwrap()).is_ok());
}
