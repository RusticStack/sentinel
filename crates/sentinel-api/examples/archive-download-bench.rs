//! What an artifact download costs: a whole-artifact archive in both formats and one entry, over the real HTTP
//! route on loopback, through the real store and object files.
//!
//! Every sample is one complete response, read to its last byte: the archive is generated from the committed
//! manifest as it streams, so the time is the controller's receipt, manifest read, object reads, hashing and the
//! socket, with no archive staged on disk. Time to first byte is measured separately from the total, because a
//! client that streams (a browser, a CLI writing to a file) feels both.
//!
//!   cargo build --release --locked -p sentinel-api --example archive-download-bench
//!   SENTINEL_SRC=$PWD SENTINEL_BIN=target/release/examples/archive-download-bench \
//!     SENTINEL_BENCH_HOST_LABEL=<label> bench/archive-download-record.sh
//!
//! The server, the store and the client are on one machine, so these are loopback figures for one store: they say
//! what the route costs, not what a link between two hosts costs.

use std::{
    io::Read,
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_core::{
    PoolId, RepoId, RunId, TenantId, UnixMillis, WorkerId,
    auth::{Namespace, Permissions, Principal},
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
    runs, tenancy,
    tenancy::PoolKind,
    tokens::{self, Grant},
    workers::{self, Presentation},
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const DAY_MS: i64 = 86_400_000;

/// One sample's case: a whole archive in one format, or one entry's bytes.
#[derive(Clone, Copy)]
enum Case {
    Tar,
    Zip,
    Entry,
}

impl Case {
    const ALL: [Case; 3] = [Case::Tar, Case::Zip, Case::Entry];

    fn name(self) -> &'static str {
        match self {
            Case::Tar => "tar",
            Case::Zip => "zip",
            Case::Entry => "entry",
        }
    }
}

struct Server {
    _dir: tempfile::TempDir,
    _api: sentinel_api::Server,
    base: String,
    token: String,
    object: String,
    archive: String,
}

/// A store with one published artifact of `files` entries of `file_bytes`, a controller and the API on loopback.
fn start(files: usize, file_bytes: usize) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(
        Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap(),
    );
    let logs = std::sync::Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = std::sync::Arc::new(Objects::open(dir.path().join("objects")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    let (tenant, repo, pool, worker) = (
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        WorkerId::new(),
    );
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, Permissions::ALL, None, None);
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
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                now,
            )
        })
        .unwrap();
    let mut stdout = String::new();
    let secret = store
        .writer()
        .write(move |tx| {
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
            issued.secret.expose(&mut stdout);
            Ok(stdout)
        })
        .unwrap();
    let run = RunId::new();
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
        compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
        )
        .unwrap(),
    )
    .unwrap();
    let job = store
        .writer()
        .write(move |tx| {
            auth::create_repo(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                repo,
                "app",
                now,
            )?;
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, IMAGE, "linux/amd64")?;
            }
            workers::enroll(
                tx,
                &sentinel_auth::secret::Secret::parse(&secret).unwrap(),
                Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "bench",
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
            Ok(ids[0])
        })
        .unwrap();
    let offer = store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("the queued job is placed");
    let mut entries: Vec<Entry> = Vec::with_capacity(files);
    let mut staged = Vec::with_capacity(files);
    let mut payload = 0u64;
    for index in 0..files {
        let body = vec![(index % 251) as u8; file_bytes];
        let one = objects
            .stage(tenant, &body[..], u64::MAX, Expect::default())
            .unwrap();
        entries.push(Entry {
            path: format!("out/part-{index:03}.bin"),
            digest: one.digest(),
            len: one.len(),
            mode: 0o644,
        });
        payload += one.len();
        staged.push(one);
    }
    let listed = entries.clone();
    let committer = std::sync::Arc::clone(&objects);
    let (artifact, first) = store
        .writer()
        .write(move |tx| {
            for one in &staged {
                committer.commit(tx, one)?;
            }
            let version = committer.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, "dist"),
                &listed,
            )?;
            let id = artifacts::record(
                tx,
                tenant,
                run,
                job,
                offer.attempt,
                "dist",
                artifacts::State::Captured,
                Some(version),
                listed.len() as u64,
                payload,
                UnixMillis(now.0 + 7 * DAY_MS),
                now,
            )?;
            Ok((id, listed[0].digest))
        })
        .unwrap();
    let controller = Controller::start(
        std::sync::Arc::clone(&store),
        std::sync::Arc::clone(&logs),
        std::sync::Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let granted = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "bench",
            permissions: Permissions::ALL,
            tenant: None,
            repo: None,
            lifetime_ms: 3_600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let api = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store,
        logs,
        objects,
        controller: controller.handle(),
        secret_key: Some(std::sync::Arc::new(
            sentinel_auth::sealed::Key::load(&key_path).unwrap(),
        )),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap();
    let base = format!("http://{}", api.local_addr());
    let archive = format!("/api/v1/runs/{run}/artifacts/{artifact}/archive?format=");
    Server {
        _dir: dir,
        _api: api,
        base,
        token: sentinel_auth::token::format(&granted.secret),
        object: format!("/api/v1/tenants/acme/objects/{first}"),
        archive,
    }
}

struct Sample {
    ttfb_ns: u128,
    total_ns: u128,
    bytes: u64,
}

fn one(agent: &ureq::Agent, url: &str, token: &str) -> Sample {
    let started = Instant::now();
    let mut response = agent
        .get(url)
        .header("authorization", &format!("Bearer {token}"))
        .call()
        .expect("the route answers");
    assert_eq!(response.status().as_u16(), 200, "{url}");
    let mut reader = response.body_mut().as_reader();
    let mut buf = vec![0u8; 64 << 10];
    let first = reader.read(&mut buf).expect("a first chunk");
    let ttfb = started.elapsed();
    let mut bytes = first as u64;
    loop {
        let read = reader.read(&mut buf).expect("a chunk");
        if read == 0 {
            break;
        }
        bytes += read as u64;
    }
    Sample {
        ttfb_ns: ttfb.as_nanos(),
        total_ns: started.elapsed().as_nanos(),
        bytes,
    }
}

fn main() -> ExitCode {
    let mut files = 48usize;
    let mut file_bytes = 1 << 20;
    let mut rounds = 5u32;
    let mut warmup = 1u32;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .unwrap_or_else(|| fail(&format!("{arg} needs a value")))
        };
        match arg.as_str() {
            "--files" => files = value().parse().unwrap_or_else(|_| fail("--files")),
            "--file-bytes" => file_bytes = value().parse().unwrap_or_else(|_| fail("--file-bytes")),
            "--rounds" => rounds = value().parse().unwrap_or_else(|_| fail("--rounds")),
            "--warmup" => warmup = value().parse().unwrap_or_else(|_| fail("--warmup")),
            "--help" | "-h" => {
                println!(
                    "archive-download-bench [--files N] [--file-bytes N] [--rounds N] [--warmup N]"
                );
                return ExitCode::SUCCESS;
            }
            other => fail(&format!("unknown argument {other}")),
        }
    }
    if files == 0 || file_bytes == 0 || rounds == 0 {
        fail("files, file-bytes and rounds must be positive");
    }
    let server = start(files, file_bytes);
    let agent: ureq::Agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let url = |case: Case| match case {
        Case::Tar => format!("{}{}tar", server.base, server.archive),
        Case::Zip => format!("{}{}zip", server.base, server.archive),
        Case::Entry => format!("{}{}", server.base, server.object),
    };
    // Warm every route once, so no sample pays a cold page cache it would not pay in service.
    for _ in 0..warmup {
        for case in Case::ALL {
            one(&agent, &url(case), &server.token);
        }
    }
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mut seq = 0u32;
    for round in 1..=rounds {
        // ABBA: every case takes each place in the order once per pair of rounds.
        let mut order = Vec::with_capacity(6);
        order.extend_from_slice(&Case::ALL);
        order.extend(Case::ALL.iter().rev().copied());
        for (position, case) in order.into_iter().enumerate() {
            let sample = one(&agent, &url(case), &server.token);
            seq += 1;
            println!(
                "{{\"schema\":\"sentinel-bench/archive-download/1\",\"seq\":{seq},\"round\":{round},\
                 \"position\":{position},\"case\":\"{}\",\"files\":{files},\"file_bytes\":{file_bytes},\
                 \"artifact_bytes\":{},\"bytes\":{},\"ttfb_ns\":{},\"total_ns\":{},\
                 \"started_at_unix_ms\":{started}}}",
                case.name(),
                files * file_bytes,
                sample.bytes,
                sample.ttfb_ns,
                sample.total_ns,
            );
        }
    }
    ExitCode::SUCCESS
}

fn fail(message: &str) -> ! {
    eprintln!("archive-download-bench: {message}");
    std::process::exit(2)
}
