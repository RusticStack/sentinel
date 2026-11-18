//! The whole-artifact archive route: its contents, its streaming bounds and its failure modes.
//!
//! The archive is generated from the stored manifest as it streams, so these tests read the wire bytes back with
//! their own tar and zip readers rather than with the code that wrote them: the tar records, the zip local
//! headers and the central directory are checked against the manifest's own entries.

use std::{
    collections::HashMap,
    io::{BufRead, Read, Write},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sentinel_core::{
    ArtifactId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, Authority, NamespaceKind},
    dispatch::{self, Capacity},
    local_auth,
    logs::LogStore,
    objects::{self, Digest, Entry, Expect, Kind, Objects, Remote},
    runs, tenancy,
    tenancy::PoolKind,
    tokens::{self, Grant},
    workers::{self, Presentation},
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const DAY_MS: i64 = 86_400_000;

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    tenant: TenantId,
    repo: RepoId,
}

fn deployment() -> Deployment {
    deployment_at(None)
}

fn deployment_at(root: Option<std::path::PathBuf>) -> Deployment {
    let dir = match root {
        Some(path) => tempfile::TempDir::new_in(path).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    sentinel_auth::sealed::Key::load(&key_path).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
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
            auth::set_membership(
                tx,
                admin,
                tenant,
                root,
                sentinel_core::auth::Role::TenantAdmin,
            )?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let granted = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "archive",
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

/// One published artifact: the run, its single job, and the artifact row with its manifest.
struct Published {
    run: RunId,
    artifact: ArtifactId,
    entries: Vec<Entry>,
    payload_len: u64,
}

/// Stages each body as an object and publishes them as an artifact of a fresh run, through the calls the
/// controller's own publication path makes.
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
        payload_len,
    }
}

fn archive(p: &Published, format: &str) -> String {
    format!(
        "/api/v1/runs/{}/artifacts/{}/archive?format={format}",
        p.run, p.artifact
    )
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
}

struct Download {
    status: u16,
    /// The length the response promised.
    stated: usize,
    /// The body, or what went wrong reading it.
    body: Result<Vec<u8>, String>,
}

/// Reads a whole archive. A body shorter than the promised length surfaces as an error here, which is how a
/// client tells a broken download from a complete one.
fn download(d: &Deployment, path: &str) -> Download {
    let response = agent()
        .get(&format!("{}{path}", d.base))
        .header("authorization", &bearer(d))
        .call()
        .unwrap();
    let status = response.status().as_u16();
    let mut response = response;
    let stated = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = Vec::new();
    let outcome = response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map(|_| body)
        .map_err(|e| e.to_string());
    Download {
        status,
        stated,
        body: outcome,
    }
}

fn get(d: &Deployment, path: &str, auth: Option<&str>) -> (u16, serde_json::Value) {
    let mut request = agent().get(&format!("{}{path}", d.base));
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = request.call().unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

/// One entry as an archive reader sees it.
#[derive(Debug, PartialEq, Eq)]
struct Item {
    path: String,
    body: Vec<u8>,
    mode: u32,
}

fn read_tar(bytes: &[u8]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut at = 0usize;
    let mut pending: Option<String> = None;
    while at + 512 <= bytes.len() {
        let block = &bytes[at..at + 512];
        if block.iter().all(|b| *b == 0) {
            break;
        }
        let field = |from: usize, to: usize| {
            let slice = &block[from..to];
            let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
            String::from_utf8_lossy(&slice[..end]).trim().to_owned()
        };
        let size = u64::from_str_radix(field(124, 136).trim(), 8).unwrap();
        let mode = u32::from_str_radix(field(100, 108).trim(), 8).unwrap();
        let kind = block[156];
        let body = bytes[at + 512..at + 512 + size as usize].to_vec();
        at += 512 + size.next_multiple_of(512) as usize;
        match kind {
            b'x' => {
                let text = String::from_utf8_lossy(&body).into_owned();
                let path = text
                    .trim_end_matches('\n')
                    .split_once(" path=")
                    .expect("a pax record names its path")
                    .1
                    .to_owned();
                pending = Some(path);
            }
            b'0' => {
                let name = field(0, 100);
                let prefix = field(345, 500);
                let path = match pending.take() {
                    Some(path) => path,
                    None if prefix.is_empty() => name,
                    None => format!("{prefix}/{name}"),
                };
                items.push(Item { path, body, mode });
            }
            other => panic!("unexpected tar entry type {other:?}"),
        }
    }
    items
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn read_zip(bytes: &[u8]) -> Vec<Item> {
    let eocd = bytes.len() - 22;
    assert_eq!(
        &bytes[eocd..eocd + 4],
        b"PK\x05\x06",
        "the end record closes the archive"
    );
    let count = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
    let start = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut at = start;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        assert_eq!(&bytes[at..at + 4], b"PK\x01\x02");
        let read16 = |o: usize| u16::from_le_bytes(bytes[at + o..at + o + 2].try_into().unwrap());
        let read32 = |o: usize| u32::from_le_bytes(bytes[at + o..at + o + 4].try_into().unwrap());
        let (crc, size, name_len, extra_len, comment_len, mode, offset) = (
            read32(16),
            read32(24),
            read16(28) as usize,
            read16(30) as usize,
            read16(32) as usize,
            read32(38) >> 16 & 0o777,
            read32(42) as usize,
        );
        let name = String::from_utf8(bytes[at + 46..at + 46 + name_len].to_vec()).unwrap();
        assert_eq!(&bytes[offset..offset + 4], b"PK\x03\x04");
        let local_name = u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into().unwrap());
        let local_extra = u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into().unwrap());
        assert_eq!(
            &bytes[offset + 30..offset + 30 + local_name as usize],
            name.as_bytes()
        );
        let body_at = offset + 30 + local_name as usize + local_extra as usize;
        let body = bytes[body_at..body_at + size as usize].to_vec();
        assert_eq!(crc32(&body), crc, "the central CRC-32 matches the body");
        items.push(Item {
            path: name,
            body,
            mode,
        });
        at += 46 + name_len + extra_len + comment_len;
    }
    items
}

fn expected(p: &Published, bodies: &[(&str, Vec<u8>)]) -> Vec<Item> {
    let mut items: Vec<Item> = bodies
        .iter()
        .zip(&p.entries)
        .map(|((_, body), entry)| Item {
            path: entry.path.clone(),
            body: body.clone(),
            mode: 0o644,
        })
        .collect();
    items.sort_by(|a, b| a.path.cmp(&b.path));
    items
}

fn object_path(d: &Deployment, digest: Digest) -> std::path::PathBuf {
    d._dir
        .path()
        .join(objects::object_relpath(d.tenant, &digest))
}

#[test]
fn tar_and_zip_carry_exactly_the_manifest_entries() {
    let d = deployment();
    let bodies = vec![
        ("out/report.txt", b"a report\n".to_vec()),
        ("out/empty", Vec::new()),
        ("out/bin/padded.bin", vec![0x5Au8; 1500]),
        (
            "deep/a/b/c/d.bin",
            (0..4096u32).flat_map(u32::to_le_bytes).collect(),
        ),
        // A single component longer than a tar name field, and a path that only fits as ustar prefix + name.
        (
            Box::leak("x".repeat(160).into_boxed_str()) as &str,
            b"long".to_vec(),
        ),
        (
            Box::leak(format!("{}/tail.txt", "d".repeat(120)).into_boxed_str()) as &str,
            b"prefixed".to_vec(),
        ),
    ];
    let p = publish(&d, "logs", &bodies, 7 * DAY_MS);
    let expected = expected(&p, &bodies);

    for format in ["tar", "zip"] {
        let downloaded = download(&d, &archive(&p, format));
        assert_eq!(downloaded.status, 200, "{format}");
        let bytes = downloaded.body.expect("a complete archive");
        assert_eq!(
            bytes.len(),
            downloaded.stated,
            "{format}: the body is exactly the stated length"
        );
        let mut read = if format == "tar" {
            read_tar(&bytes)
        } else {
            read_zip(&bytes)
        };
        read.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(read, expected, "{format} holds the manifest's entries");
    }
    assert_eq!(
        p.entries.iter().map(|e| e.len).sum::<u64>(),
        p.payload_len,
        "the fixture published what the manifest states"
    );
}

#[test]
fn the_response_names_its_type_its_format_and_its_file_name() {
    let d = deployment();
    let bodies: Vec<(&str, Vec<u8>)> = (0..8)
        .map(|i| {
            let body = vec![i as u8; 64 << 10];
            (
                Box::leak(format!("part-{i}.bin").into_boxed_str()) as &str,
                body,
            )
        })
        .collect();
    let p = publish(&d, "typed", &bodies, 7 * DAY_MS);
    for format in ["tar", "zip"] {
        let response = agent()
            .get(&format!("{}{}", d.base, archive(&p, format)))
            .header("authorization", &bearer(&d))
            .call()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            if format == "tar" {
                "application/x-tar"
            } else {
                "application/zip"
            }
        );
        let disposition = response
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            disposition,
            format!("attachment; filename=\"build-typed.{format}\"")
        );
    }
}

#[test]
fn a_large_entry_streams_without_a_temporary_file() {
    let d = deployment();
    let big = vec![0x33u8; 48 << 20];
    let bodies = vec![
        ("out/big.bin", big.clone()),
        ("out/tail.txt", b"tail".to_vec()),
    ];
    let p = publish(&d, "big", &bodies, 7 * DAY_MS);
    let tmp = d._dir.path().join(objects::TMP_DIR);
    assert_eq!(entries_in(&tmp), 0, "staging left nothing behind");
    let downloaded = download(&d, &archive(&p, "tar"));
    assert_eq!(downloaded.status, 200);
    let bytes = downloaded.body.expect("a complete archive");
    assert_eq!(entries_in(&tmp), 0, "the download wrote no temporary file");
    assert_eq!(entries_in(&d._dir.path().join(objects::INCOMING_DIR)), 0);
    let read = read_tar(&bytes);
    assert_eq!(read.len(), 2);
    assert_eq!(read[0].body, big);
    assert_eq!(read[1].body, b"tail");
    assert!(
        read[0].body.len() > 4 << 20,
        "one entry on its own is large"
    );
}

fn entries_in(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| entries.count())
        .unwrap_or(0)
}

#[test]
fn an_evicted_entry_streams_back_verified() {
    let d = deployment();
    let remote = Arc::new(Fake::default());
    d.objects.set_remote(Arc::clone(&remote) as Arc<dyn Remote>);
    let bodies = vec![
        ("a.txt", b"first entry\n".to_vec()),
        ("b.bin", vec![0x7Eu8; 300 << 10]),
    ];
    let p = publish(&d, "evicted", &bodies, 7 * DAY_MS);
    for entry in &p.entries {
        let (_, body) = bodies.iter().find(|(path, _)| *path == entry.path).unwrap();
        remote.holds(objects::remote_key(d.tenant, &entry.digest), body);
    }
    let evicted = d.objects.evict_files(
        &p.entries
            .iter()
            .map(|entry| (d.tenant, entry.digest))
            .collect::<Vec<_>>(),
    );
    assert_eq!(evicted.len(), 2, "both objects left the disk");
    let downloaded = download(&d, &archive(&p, "zip"));
    assert_eq!(downloaded.status, 200);
    let read = read_zip(&downloaded.body.expect("a complete archive"));
    assert_eq!(read.len(), 2);
    assert_eq!(read[0].body, bodies[0].1);
    assert_eq!(read[1].body, bodies[1].1);
    assert!(
        remote.ranged_requests() >= 2,
        "the bodies came in ranged reads"
    );
    assert!(
        !object_path(&d, p.entries[0].digest).exists(),
        "streaming an evicted entry placed no file back on disk"
    );
    assert_eq!(entries_in(&d._dir.path().join(objects::TMP_DIR)), 0);
}

#[test]
fn a_damaged_entry_ends_the_stream_short_of_its_length() {
    let d = deployment();
    let bodies = vec![
        ("first.txt", b"intact\n".to_vec()),
        ("second.bin", vec![0x11u8; 4096]),
        ("third.txt", b"never reached\n".to_vec()),
    ];
    let p = publish(&d, "damaged", &bodies, 7 * DAY_MS);
    let path = object_path(&d, p.entries[1].digest);
    let whole = std::fs::read(&path).unwrap();

    // A shortened file: the entry ends before the length its manifest states.
    std::fs::write(&path, &whole[..100]).unwrap();
    let downloaded = download(&d, &archive(&p, "tar"));
    assert_eq!(downloaded.status, 200);
    assert!(
        truncated(&downloaded),
        "a short entry leaves the press with a short body"
    );

    // The same length with other bytes: the digest is checked, so the last chunk is withheld.
    let mut altered = whole.clone();
    altered[0] ^= 0xFF;
    std::fs::write(&path, &altered).unwrap();
    let downloaded = download(&d, &archive(&p, "zip"));
    assert!(
        truncated(&downloaded),
        "a mismatched entry ends the stream instead of completing the archive"
    );

    // The external copy is verified the same way: a corrupt one never completes the archive.
    std::fs::remove_file(&path).unwrap();
    let remote = Arc::new(Fake::default());
    d.objects.set_remote(Arc::clone(&remote) as Arc<dyn Remote>);
    remote.holds(
        objects::remote_key(d.tenant, &p.entries[1].digest),
        &vec![0x22u8; p.entries[1].len as usize],
    );
    let downloaded = download(&d, &archive(&p, "tar"));
    assert!(
        truncated(&downloaded),
        "a corrupt copy in the external store ends the stream"
    );

    // A cut-short copy in the external store too.
    remote.holds(
        objects::remote_key(d.tenant, &p.entries[1].digest),
        &[0x22u8; 10],
    );
    let downloaded = download(&d, &archive(&p, "zip"));
    assert!(
        truncated(&downloaded),
        "a short remote copy ends the stream"
    );
}

fn truncated(download: &Download) -> bool {
    match &download.body {
        Err(_) => true,
        Ok(body) => body.len() < download.stated,
    }
}

#[test]
fn an_absent_expired_or_unrelated_artifact_is_not_found() {
    let d = deployment();
    let p = publish(&d, "logs", &[("a.txt", b"a".to_vec())], 7 * DAY_MS);
    let (status, _) = get(&d, &archive(&p, "tar"), None);
    assert_eq!(status, 401, "an anonymous caller is refused");

    let (status, body) = get(
        &d,
        &format!(
            "/api/v1/runs/{}/artifacts/{}/archive",
            p.run,
            ArtifactId::new()
        ),
        Some(&bearer(&d)),
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));

    let (status, body) = get(
        &d,
        &format!(
            "/api/v1/runs/{}/artifacts/{}/archive",
            RunId::new(),
            p.artifact
        ),
        Some(&bearer(&d)),
    );
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));

    let (status, body) = get(&d, &archive(&p, "rar"), Some(&bearer(&d)));
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );

    // A reader with the scope but no grant on the artifact's repository sees the same answer as an unknown id.
    let outsider = UserId::new();
    let now = UnixMillis::now();
    d.store
        .writer()
        .write(move |tx| {
            sentinel_store::auth::provisioning::insert_human(tx, outsider, "Olive", false, now)
        })
        .unwrap();
    let stranger = tokens::provision(
        &d.store,
        Grant {
            user: outsider,
            name: "stranger",
            permissions: P::READ,
            tenant: None,
            repo: None,
            lifetime_ms: 60_000,
        },
        now,
    )
    .unwrap();
    let stranger = format!("Bearer {}", sentinel_auth::token::format(&stranger.secret));
    let (status, body) = get(&d, &archive(&p, "tar"), Some(&stranger));
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
}

#[test]
fn retention_is_rechecked_when_the_archive_is_requested() {
    let d = deployment();
    let live = publish(&d, "live", &[("a.txt", b"a".to_vec())], 7 * DAY_MS);
    let expired = publish(&d, "expired", &[("a.txt", b"a".to_vec())], -1_000);

    // The row is still stored — only the maintenance sweep removes it — so the refusal has to come from the
    // request itself, not from the row's absence.
    let row = d
        .store
        .read(|c| artifacts::get(c, d.tenant, expired.run, expired.artifact))
        .expect("the expired row is still stored");
    assert!(row.retain_until_ms <= UnixMillis::now());

    let (status, body) = get(&d, &archive(&expired, "tar"), Some(&bearer(&d)));
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let (status, _) = get(&d, &archive(&live, "tar"), Some(&bearer(&d)));
    assert_eq!(
        status, 200,
        "the artifact inside its retention still downloads"
    );
}

#[derive(Default)]
struct Fake {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    ranges: std::sync::atomic::AtomicU32,
}

impl Fake {
    fn holds(&self, key: String, body: &[u8]) {
        self.objects.lock().unwrap().insert(key, body.to_vec());
    }
    fn ranged_requests(&self) -> u32 {
        self.ranges.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Remote for Fake {
    fn fetch(&self, key: &str, out: &mut dyn Write) -> sentinel_store::Result<u64> {
        let objects = self.objects.lock().unwrap();
        let body = objects.get(key).ok_or(Error::Corrupt("object missing"))?;
        out.write_all(body)?;
        Ok(body.len() as u64)
    }
    fn read_range(
        &self,
        key: &str,
        offset: u64,
        len: u64,
    ) -> sentinel_store::Result<Box<dyn Read + Send>> {
        self.ranges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let objects = self.objects.lock().unwrap();
        let body = objects.get(key).ok_or(Error::Corrupt("object missing"))?;
        let span = body
            .get(offset as usize..(offset + len) as usize)
            .ok_or(Error::Corrupt("range"))?;
        Ok(Box::new(std::io::Cursor::new(span.to_vec())))
    }
}

#[test]
fn local_entry_time_to_first_byte_p95_is_under_a_hundred_milliseconds() {
    let d = deployment();
    let bodies: Vec<(&str, Vec<u8>)> = (0..8)
        .map(|i| {
            let body = vec![i as u8; 256 << 10];
            (
                Box::leak(format!("part-{i}.bin").into_boxed_str()) as &str,
                body,
            )
        })
        .collect();
    let p = publish(&d, "latency", &bodies, 7 * DAY_MS);
    for format in ["tar", "zip"] {
        // One warm call first: the gate is what a client sees, not what a cold cache sees.
        let _ = first_byte(&d, &archive(&p, format));
        let mut seen: Vec<Duration> = (0..25)
            .map(|_| first_byte(&d, &archive(&p, format)))
            .collect();
        seen.sort();
        let p95 = seen[seen.len() * 95 / 100];
        println!(
            "{format}: first byte p95 {:?} over {} calls (min {:?}, max {:?})",
            p95,
            seen.len(),
            seen[0],
            seen[seen.len() - 1]
        );
        assert!(
            p95 < Duration::from_millis(100),
            "{format}: local time to first byte p95 was {p95:?}"
        );
    }
}

/// The time from sending the request to the first body byte.
fn first_byte(d: &Deployment, path: &str) -> Duration {
    let started = Instant::now();
    let response = agent()
        .get(&format!("{}{path}", d.base))
        .header("authorization", &bearer(d))
        .call()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let mut response = response;
    let mut byte = [0u8; 1];
    response
        .body_mut()
        .as_reader()
        .read_exact(&mut byte)
        .expect("the archive starts");
    started.elapsed()
}

/// The 4 GiB gate serves from a controller process of its own, so the resident set measured is the server's and
/// nothing the test allocated. The child is this same test binary re-run with `SENTINEL_ARCHIVE_SERVE` set.
#[test]
fn a_four_gib_archive_is_served_with_controller_rss_growth_under_64_mib() {
    if std::env::var_os("SENTINEL_ARCHIVE_SERVE").is_some() {
        serve_four_gib();
    }
    let scratch = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_four_gib_archive_is_served_with_controller_rss_growth_under_64_mib",
            "--nocapture",
        ])
        .env("SENTINEL_ARCHIVE_SERVE", scratch.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let child = Serve { child };
    let mut line = String::new();
    while !line.starts_with("READY ") {
        let read = out.read_line(&mut line).unwrap();
        assert!(
            read > 0,
            "the serving child exited before it announced itself"
        );
        if !line.starts_with("READY ") {
            line.clear();
        }
    }
    let fields: Vec<&str> = line.trim_end().split(' ').collect();
    let (base, token, run, artifact) = (fields[1], fields[2], fields[3], fields[4]);
    let path = format!("/api/v1/runs/{run}/artifacts/{artifact}/archive?format=tar");
    let before = resident(child.pid());
    let started = Instant::now();
    let response = agent()
        .get(&format!("{base}{path}"))
        .header("authorization", &format!("Bearer {token}"))
        .call()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let stated = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(
        stated >= 4 << 30,
        "the archive holds 4 GiB of entries: {stated}"
    );
    let mut response = response;
    let mut total = 0u64;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let got = response.body_mut().as_reader().read(&mut buffer).unwrap();
        if got == 0 {
            break;
        }
        total += got as u64;
    }
    let elapsed = started.elapsed();
    let after = resident(child.pid());
    assert_eq!(total, stated, "the whole archive arrived");
    let growth = after.saturating_sub(before);
    println!(
        "4 GiB archive in {elapsed:?}: controller RSS {before} -> {after} KiB, growth {growth} KiB"
    );
    assert!(
        growth <= 64 * 1024,
        "controller RSS grew {growth} KiB, past the 64 MiB gate"
    );
}

/// The serving child, killed and reaped however the test ends.
struct Serve {
    child: Child,
}

impl Serve {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// This process's resident set size in KiB (Linux: the resident line of `/proc/<pid>/status`).
fn resident(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("a resident set size")
}

/// The child: publishes a 4 GiB artifact of many entries, announces its address, and serves until killed.
fn serve_four_gib() -> ! {
    let root = std::path::PathBuf::from(std::env::var("SENTINEL_ARCHIVE_SERVE").unwrap());
    let d = deployment_at(Some(root));
    let chunk = vec![0x5Au8; 64 << 20];
    let mut bodies: Vec<(&str, Vec<u8>)> = Vec::with_capacity(64);
    for i in 0..64u8 {
        let mut body = chunk.clone();
        body[..16].copy_from_slice(&[i; 16]);
        bodies.push((
            Box::leak(format!("blob-{i:02}.bin").into_boxed_str()) as &str,
            body,
        ));
    }
    let p = publish(&d, "four-gib", &bodies, 7 * DAY_MS);
    drop(bodies);
    assert_eq!(p.payload_len, 4 << 30);
    println!("READY {} {} {} {}", d.base, d.token, p.run, p.artifact);
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(200));
    }
}
