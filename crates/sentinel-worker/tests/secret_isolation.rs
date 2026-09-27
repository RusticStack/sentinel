//! Part 10 delivery boundaries against rootless Podman and a real private
//! registry (`SENTINEL_PODMAN_TESTS=1` as the worker account, like
//! `end_to_end.rs`; the registry is a local `registry:2` with htpasswd
//! authentication, pulled from Docker Hub on first use):
//!
//! - P10D-1: a process an earlier step left running (a `setsid` watcher
//!   scanning `/proc/*/environ` and the secret mounts) records nothing of a
//!   later step's environment or files.
//! - P10D-4: an image that runs as a non-root user reads its file target.
//! - P10D-5 / S07: a private image is pulled with the tenant's
//!   `registry_auth` into the tenant's own store — the shared store never
//!   gets it; once resident there, an anonymous pull is still refused; and
//!   another tenant replaying its manifest and config from a registry of
//!   its own gets no layer.
//! - P10D-7: an undeliverable secret fails the attempt with a value-free
//!   detail naming it.
//! - P10D-8: a 65,000-byte environment value reaches the step.
//! - P10D-9: the step cannot raise its core-dump limit.
//!
//! One test function: the registry configuration is a process environment
//! variable, set once before any runtime process starts.

#![cfg(target_os = "linux")]

#[path = "support/live.rs"]
mod live;

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use live::{DIGEST, IMAGE, Live, eventually, podman_enabled};
use sentinel_auth::sealed::Key;
use sentinel_core::{
    AttemptId, JobState, Outcome, UnixMillis, WorkerId,
    auth::{Permissions as P, Principal},
};
use sentinel_protocol::{negotiate::Capabilities, summary::AttemptSummary};
use sentinel_store::{
    dispatch,
    secrets::{self, Binding, Scope},
};
use sentinel_worker::{
    executor::Executor,
    podman::{self, Container, Limits, Store},
};

/// `sentinel:registry-test-pass`, bcrypt, as registry:2's htpasswd wants.
const HTPASSWD: &str = "sentinel:$2b$05$FLtrX1HxgXf8j22jKC6xTuhjawXxqgbQWPCCfhsil94PyJI/CFU1G\n";
/// base64 of `sentinel:registry-test-pass`.
const BASIC: &str = "c2VudGluZWw6cmVnaXN0cnktdGVzdC1wYXNz";
const REGISTRY_IMAGE: &str = "docker.io/library/registry:2";

fn podman_cmd(args: &[&str]) -> std::process::Output {
    Command::new("podman").args(args).output().unwrap()
}

fn podman_ok(args: &[&str]) -> String {
    let out = podman_cmd(args);
    assert!(
        out.status.success(),
        "podman {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// What the replaying registry serves: manifest media type and bytes, config
/// digest and bytes.
type Served = (String, Vec<u8>, String, Vec<u8>);

/// A registry that serves one tenant's manifest and config — and nothing
/// else — the way a tenant replaying another's metadata would.
struct Replay {
    port: u16,
    served: Arc<Mutex<Option<Served>>>,
}

impl Replay {
    fn start() -> Replay {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served: Arc<Mutex<Option<Served>>> = Arc::new(Mutex::new(None));
        let content = Arc::clone(&served);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let content = Arc::clone(&content);
                thread::spawn(move || {
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
                        match stream.read(&mut byte) {
                            Ok(1) => request.push(byte[0]),
                            _ => return,
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let mut first = text.lines().next().unwrap_or("").split(' ');
                    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
                    let served = content.lock().unwrap().clone();
                    let (status, kind, body): (&str, String, Vec<u8>) = match served {
                        _ if path == "/v2/" || path == "/v2" => {
                            ("200 OK", "application/json".into(), b"{}".to_vec())
                        }
                        Some((kind, manifest, _, _)) if path.contains("/manifests/") => {
                            ("200 OK", kind, manifest)
                        }
                        Some((_, _, config, blob))
                            if path.ends_with(&format!("/blobs/{config}")) =>
                        {
                            ("200 OK", "application/octet-stream".into(), blob)
                        }
                        _ => ("404 Not Found", "text/plain".into(), Vec::new()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    if method != "HEAD" {
                        let _ = stream.write_all(&body);
                    }
                });
            }
        });
        Replay { port, served }
    }
}

/// The local authenticated registry, removed with its images on drop.
struct Registry {
    name: String,
    port: u16,
    dir: PathBuf,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = podman_cmd(&["rm", "-f", "-t", "0", &self.name]);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn start_registry(dir: &Path) -> Registry {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("htpasswd"), HTPASSWD).unwrap();
    let name = format!("sentinel-test-registry-{}", std::process::id());
    let _ = podman_cmd(&["rm", "-f", "-t", "0", &name]);
    podman_ok(&["pull", "-q", REGISTRY_IMAGE]);
    podman_ok(&[
        "run",
        "-d",
        "--name",
        &name,
        "-p",
        "127.0.0.1::5000",
        "-v",
        &format!("{}:/auth:ro", dir.display()),
        "-e",
        "REGISTRY_AUTH=htpasswd",
        "-e",
        "REGISTRY_AUTH_HTPASSWD_REALM=sentinel",
        "-e",
        "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
        REGISTRY_IMAGE,
    ]);
    let mapped = podman_ok(&["port", &name, "5000/tcp"]);
    let port: u16 = mapped.rsplit(':').next().unwrap().parse().unwrap();
    let registry = Registry {
        name,
        port,
        dir: dir.to_path_buf(),
    };
    eventually("registry up", Duration::from_secs(60), || {
        ureq::get(&format!("http://127.0.0.1:{port}/v2/"))
            .call()
            .map(|_| false)
            .unwrap_or_else(|e| matches!(e, ureq::Error::StatusCode(401)))
    });
    registry
}

/// `podman --root … --runroot …` for a private store.
fn store_args(store: &Store) -> Vec<String> {
    match store {
        Store::Shared => Vec::new(),
        Store::Private { graph, run } => vec![
            "--root".into(),
            graph.display().to_string(),
            "--runroot".into(),
            run.display().to_string(),
        ],
    }
}

/// Remove a private store whole — its files belong to subordinate ids.
fn drop_store(store: &Store) {
    let mut args = store_args(store);
    args.extend(["rmi".into(), "-a".into(), "-f".into()]);
    let _ = Command::new("podman").args(&args).output();
    if let Store::Private { graph, run } = store {
        for dir in [graph, run] {
            let _ = Command::new("podman")
                .args(["unshare", "rm", "-rf"])
                .arg(dir)
                .output();
        }
    }
}

fn exists_in(store: &Store, image: &str) -> bool {
    let mut args = store_args(store);
    args.extend(["image".into(), "exists".into(), image.into()]);
    Command::new("podman")
        .args(&args)
        .status()
        .unwrap()
        .success()
}

fn detail(live: &Live, job: sentinel_core::JobId) -> String {
    let attempt = live.attempt(job).unwrap();
    let bytes = live
        .store
        .read(|c| dispatch::attempt_summary(c, live.tenant, attempt))
        .unwrap()
        .unwrap_or_default();
    AttemptSummary::decode(&bytes)
        .map(|s| s.detail)
        .unwrap_or_default()
}

fn settled(live: &Live, job: sentinel_core::JobId) -> sentinel_store::jobs::JobRow {
    eventually("job settled", Duration::from_secs(180), || {
        matches!(live.job(job).state, JobState::Terminal(_))
    });
    live.job(job)
}

#[test]
fn secret_delivery_holds_its_boundaries_in_rootless_podman() {
    if !podman_enabled() {
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let replay = Replay::start();
    let registry = start_registry(&scratch.path().join("registry"));
    let port = registry.port;
    // Plain HTTP for the two local registries only.
    let conf = scratch.path().join("registries.conf");
    fs::write(
        &conf,
        format!(
            "unqualified-search-registries = []\n\
             [[registry]]\nlocation = \"127.0.0.1:{port}\"\ninsecure = true\n\
             [[registry]]\nlocation = \"127.0.0.1:{}\"\ninsecure = true\n",
            replay.port
        ),
    )
    .unwrap();
    // SAFETY: set before this test starts any thread that reads the
    // environment (the registry helpers above ran to completion), and this
    // binary holds this one test.
    unsafe { std::env::set_var("CONTAINERS_REGISTRIES_CONF", &conf) };

    // A private image with a layer of its own, running as `nobody`.
    let marker = format!("tenant-a-private-{}", AttemptId::new());
    let build = scratch.path().join("build");
    fs::create_dir_all(&build).unwrap();
    fs::write(
        build.join("Containerfile"),
        format!("FROM {IMAGE}@{DIGEST}\nRUN echo {marker} > /private.txt\nUSER 65534:65534\n"),
    )
    .unwrap();
    let tag = format!("127.0.0.1:{port}/acme/private:1");
    podman_ok(&[
        "build",
        "-q",
        "--pull=never",
        "-t",
        &tag,
        &build.display().to_string(),
    ]);
    let good = scratch.path().join("good.json");
    let good_auth = format!("{{\"auths\":{{\"127.0.0.1:{port}\":{{\"auth\":\"{BASIC}\"}}}}}}");
    fs::write(&good, &good_auth).unwrap();
    let anonymous = scratch.path().join("anonymous.json");
    fs::write(&anonymous, "{\"auths\":{}}").unwrap();
    let digest_file = scratch.path().join("digest");
    podman_ok(&[
        "push",
        "-q",
        "--authfile",
        &good.display().to_string(),
        "--digestfile",
        &digest_file.display().to_string(),
        &tag,
    ]);
    let private_digest = fs::read_to_string(&digest_file).unwrap().trim().to_owned();
    let private = format!("127.0.0.1:{port}/acme/private@{private_digest}");
    // Only the registry holds it now.
    let _ = podman_cmd(&["rmi", "-f", &tag]);
    assert!(!exists_in(&Store::Shared, &private));

    // ── P10D-5 / S07 at the runtime boundary ──────────────────────────
    let stores = scratch.path().join("stores");
    let tenant_a = Store::private(&stores, [0xaa; 16]).unwrap();
    let tenant_b = Store::private(&stores, [0xbb; 16]).unwrap();
    let never = std::sync::atomic::AtomicBool::new(false);
    let pull = |image: &str, auth: &Path, store: &Store| {
        podman::pull(image, auth, store, Duration::from_secs(300), &never)
    };
    assert!(
        pull(&private, &anonymous, &tenant_a).is_err(),
        "an anonymous pull of a private image is refused"
    );
    assert!(
        !pull(&private, &good, &tenant_a).unwrap(),
        "absent at first"
    );
    assert!(exists_in(&tenant_a, &private));
    assert!(
        !exists_in(&Store::Shared, &private),
        "never in the shared store"
    );
    // Resident in the tenant's store, and still the registry decides.
    match pull(&private, &anonymous, &tenant_a) {
        Err(sentinel_worker::Error::Preparation(ref why)) => {
            assert!(why.starts_with("image pull"), "{why}")
        }
        other => panic!("a resident private image served an anonymous pull: {other:?}"),
    }
    // Tenant B replays A's manifest and config from a registry of its own.
    let manifest_url =
        format!("http://127.0.0.1:{port}/v2/acme/private/manifests/{private_digest}");
    let mut response = ureq::get(&manifest_url)
        .header("Authorization", &format!("Basic {BASIC}"))
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
        )
        .call()
        .unwrap();
    let kind = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let manifest = response.body_mut().read_to_vec().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    let config = parsed["config"]["digest"].as_str().unwrap().to_owned();
    let blob = ureq::get(&format!(
        "http://127.0.0.1:{port}/v2/acme/private/blobs/{config}"
    ))
    .header("Authorization", &format!("Basic {BASIC}"))
    .call()
    .unwrap()
    .body_mut()
    .read_to_vec()
    .unwrap();
    *replay.served.lock().unwrap() = Some((kind, manifest, config, blob));
    let replayed = format!("127.0.0.1:{}/other/copy@{private_digest}", replay.port);
    assert!(
        pull(&replayed, &anonymous, &tenant_b).is_err(),
        "a replayed manifest got tenant A's private layers into tenant B's store"
    );
    assert!(!exists_in(&tenant_b, &replayed));
    drop_store(&tenant_a);
    drop_store(&tenant_b);

    // ── P10D-1: clearing a container, measured ────────────────────────
    let ws = tempfile::tempdir().unwrap();
    podman::pull(
        &format!("{IMAGE}@{DIGEST}"),
        &anonymous,
        &Store::Shared,
        Duration::from_secs(600),
        &never,
    )
    .unwrap();
    let container = Container::start(
        WorkerId::new(),
        AttemptId::new(),
        &format!("{IMAGE}@{DIGEST}"),
        Limits {
            cpu_millis: 1_000,
            memory_bytes: 128 << 20,
            pids: 256,
        },
        ws.path(),
        &[],
        &Store::Shared,
    )
    .unwrap();
    let step = |script: &str| sentinel_pipeline::run::StepCommand {
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: Vec::new(),
        workdir: None,
        timeout_secs: 30,
        secrets: Vec::new(),
        secret_files: Vec::new(),
    };
    let mut timings = Vec::new();
    for _ in 0..5 {
        let exit = container
            .exec(
                &step("for i in 1 2 3; do nohup setsid sh -c 'while :; do sleep 0.05; done' </dev/null >/dev/null 2>&1 & done"),
                &[],
            )
            .unwrap();
        assert_eq!(exit.code, Some(0));
        let started = Instant::now();
        let killed = container.clear_strays().unwrap();
        timings.push(started.elapsed());
        assert!(killed >= 3, "killed {killed}");
        // No stray is left, and the container still runs steps.
        let exit = container
            .exec(&step("ps -o args | grep -c '[s]leep 0.05'; true"), &[])
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&exit.stdout).trim(), "0");
    }
    timings.sort();
    eprintln!("clear_strays with 3 strays plus the keepalive's sleep: {timings:?}");
    let _ = container.destroy();

    // ── The executor: secrets over the link into real steps ───────────
    let key_path = scratch.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let (live, _executor) = Live::start_with(
        |dir, worker| Executor::start(dir.to_path_buf(), worker, |_| {}, false).unwrap(),
        10,
        Capabilities(Capabilities::REQUIRED.0 | Capabilities::SECRET_DELIVERY.0),
        Some(Arc::clone(&key)),
    );
    let big = "v".repeat(65_000);
    let cert = "-----BEGIN TEST-----\nline-one\nline-two-secret\n-----END TEST-----\n";
    let (repo, admin) = (live.repo_id, Principal::new(live.root, P::ALL, None, None));
    let values: Vec<(&str, Vec<u8>)> = vec![
        ("TOKEN", b"declared-step-secret-xyz".to_vec()),
        ("BIG", big.clone().into_bytes()),
        ("CERT", cert.as_bytes().to_vec()),
        ("OCI_AUTH", good_auth.clone().into_bytes()),
    ];
    for (name, value) in values {
        let key = Arc::clone(&key);
        live.store
            .writer()
            .write(move |tx| {
                let put = secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name,
                        expected: 0,
                        value: &value,
                    },
                    &key,
                    UnixMillis::now(),
                )?;
                secrets::bind(
                    tx,
                    admin,
                    &Binding {
                        repo,
                        job: String::new(),
                        step: String::new(),
                        name: name.into(),
                        secret: put.id,
                        override_tenant: false,
                    },
                    UnixMillis::now(),
                )
            })
            .unwrap();
    }
    // P10D-1, P10D-8, P10D-9 on the shared busybox; P10D-7 beside it.
    let watcher = "nohup setsid sh -c 'while :; do for p in /proc/[0-9]*; do tr \"\\000\" \"\\n\" < $p/environ 2>/dev/null | grep -e ^TOKEN= -e ^BIG= >> /tmp/stolen; done; cat /run/sentinel-secrets/tls/cert.pem /run/sentinel-env/*.sh >> /tmp/stolen 2>/dev/null; sleep 0.05; done' </dev/null >/dev/null 2>&1 & sleep 0.3";
    let yaml = format!(
        "schema: 1
on: [push]
jobs:
  isolated:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    secrets: [TOKEN, BIG, CERT]
    steps:
      - id: plant
        run: '{watcher}'
      - id: use
        run: 'test \"$TOKEN\" = declared-step-secret-xyz && test ${{#BIG}} -eq 65000 && grep -q line-two-secret /run/sentinel-secrets/tls/cert.pem && test \"$(ulimit -c)\" = 0 && test \"$(ulimit -Hc)\" = 0 && sleep 1'
        secrets: [TOKEN, BIG]
        secret_files: {{ CERT: tls/cert.pem }}
      - id: check
        run: 'test ! -s /tmp/stolen || {{ echo leaked; exit 7; }}'
  unbound:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    secrets: [NEVER_BOUND]
    steps:
      - id: s
        run: 'true'
        secrets: [NEVER_BOUND]
",
        watcher = watcher.replace('\'', "''"),
    );
    let (_, jobs) = live.enqueue(&yaml);
    let names = sentinel_pipeline::compile_str(&yaml).unwrap();
    let job = |name: &str| jobs[names.jobs.iter().position(|j| j.name == name).unwrap()];
    let isolated = settled(&live, job("isolated"));
    assert_eq!(
        isolated.state,
        JobState::Terminal(Outcome::Passed),
        "{:?}: {}",
        isolated.failure_class,
        detail(&live, job("isolated"))
    );
    let unbound = settled(&live, job("unbound"));
    assert_eq!(
        unbound.failure_class,
        Some(sentinel_core::FailureClass::Preparation)
    );
    assert_eq!(detail(&live, job("unbound")), "secret NEVER_BOUND: unbound");

    // P10D-4 and P10D-5 through the executor: the private image, pulled
    // with the tenant's registry auth into its own store, run as nobody.
    let yaml = format!(
        "schema: 1
on: [push]
jobs:
  private:
    image: 127.0.0.1:{port}/acme/private:1@{private_digest}
    resources: {{ cpu: 1, memory: 128MiB }}
    secrets: [TOKEN, CERT, OCI_AUTH]
    registry_auth: OCI_AUTH
    steps:
      - id: read
        run: 'test \"$(id -u)\" = 65534 && grep -q {marker} /private.txt && grep -q line-two-secret /run/sentinel-secrets/tls/cert.pem && test \"$TOKEN\" = declared-step-secret-xyz'
        secrets: [TOKEN]
        secret_files: {{ CERT: tls/cert.pem }}
"
    );
    let (_, jobs) = live.enqueue_pinned(&yaml, &private_digest);
    let private_job = settled(&live, jobs[0]);
    assert_eq!(
        private_job.state,
        JobState::Terminal(Outcome::Passed),
        "{:?}: {}",
        private_job.failure_class,
        detail(&live, jobs[0])
    );
    assert!(
        !exists_in(&Store::Shared, &private),
        "never in the shared store"
    );
    let tenant_store = Store::private(&live.worker_dir, *live.tenant.as_bytes()).unwrap();
    assert!(exists_in(&tenant_store, &private));
    drop_store(&tenant_store);
    let runtime = sentinel_worker::runtime_dir(&live.worker_dir);
    live.stop();
    // The worker's runtime directory lives outside the test's temp dir.
    let _ = fs::remove_dir_all(runtime);
    drop(registry);
}
