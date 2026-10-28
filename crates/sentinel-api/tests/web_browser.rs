//! Needs Node 22+, a built web interface and Edge, Chrome or Chromium: run with --ignored.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use fixture::{Fixture, PASSWORD};
use serde_json::json;

fn repo_root() -> std::path::PathBuf {
    // Not `canonicalize`: on Windows it yields a verbatim path Node rejects.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn node() -> String {
    std::env::var("SENTINEL_NODE").unwrap_or_else(|_| "node".into())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The web interface: one process, or during the strangler migration (plan 16.4) the
/// TanStack Start front (`SENTINEL_WEB_FRONT`, its server entry) with the Nuxt process
/// behind it on loopback. `SENTINEL_WEB_SERVER` replaces the default entry.
struct Web(Vec<Child>);

fn spawn_web(server: &std::path::Path, port: u16, envs: &[(&str, String)]) -> Child {
    assert!(
        server.exists(),
        "build the web interface first: {} is missing",
        server.display()
    );
    let mut command = Command::new(node());
    command
        .arg(server)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (k, v) in envs {
        command.env(k, v);
    }
    let child = command.spawn().expect("start the web interface");
    let deadline = Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the web interface did not listen"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    child
}

impl Web {
    fn start(port: u16, api: &str) -> Web {
        let entry = |var: &str, default: &str| {
            std::env::var_os(var)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| repo_root().join(default))
        };
        let server = entry("SENTINEL_WEB_SERVER", "web/.output/server/index.mjs");
        let api_env = [
            ("NUXT_SENTINEL_API", api.to_owned()),
            ("SENTINEL_API", api.to_owned()),
        ];
        match std::env::var_os("SENTINEL_WEB_FRONT") {
            None => Web(vec![spawn_web(&server, port, &api_env)]),
            Some(front) => {
                let legacy_port = free_port();
                let legacy = spawn_web(&server, legacy_port, &api_env);
                let mut envs = api_env.to_vec();
                envs.push((
                    "SENTINEL_LEGACY_ORIGIN",
                    format!("http://127.0.0.1:{legacy_port}"),
                ));
                let front = spawn_web(std::path::Path::new(&front), port, &envs);
                Web(vec![front, legacy])
            }
        }
    }

    fn pids(&self) -> Vec<u32> {
        self.0.iter().map(Child::id).collect()
    }
}

impl Drop for Web {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn keep_writing(f: &Arc<Fixture>, stop: &Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    let (f, stop) = (Arc::clone(f), Arc::clone(stop));
    std::thread::spawn(move || {
        let mut n = 0u64;
        while !stop.load(Ordering::Acquire) {
            n += 1;
            f.live_line(0, &format!("live line {n}"));
            std::thread::sleep(Duration::from_millis(150));
        }
    })
}

fn config(f: &Fixture, base: &str, web: &str, out: &std::path::Path) -> serde_json::Value {
    json!({
        "base": base,
        "web": web,
        "password": PASSWORD,
        "auth": f.auth,
        "out": out,
        "diamond": f.diamond.to_string(),
        "jobs": f.jobs.iter().map(|(k, v)| (k.to_string(), json!(v.to_string()))).collect::<serde_json::Map<_, _>>(),
        "attempts": f.attempts.iter().map(|(k, (a, _))| (k.to_string(), json!(a.to_string()))).collect::<serde_json::Map<_, _>>(),
        "live_attempt": f.live.2.to_string(),
        "bulk": f.bulk.to_string(),
        "bulk_attempt": f.bulk_attempt.to_string(),
        "bulk_lines": f.bulk_lines,
        "pr_run": f.pr_run.to_string(),
        "dana": f.dana.to_string(),
        "rui": f.rui.to_string(),
        "subscribers_per_user": sentinel_api::SUBSCRIBERS_PER_USER,
    })
}

fn deployment(bulk_mib: usize, relayed: bool) -> (Arc<Fixture>, Web, String, String) {
    let port = free_port();
    let web_addr = format!("http://127.0.0.1:{port}");
    let origin = if relayed {
        format!("http://127.0.0.1:{}", free_port())
    } else {
        web_addr.clone()
    };
    let f = Arc::new(Fixture::serving(bulk_mib, Some(origin.clone())));
    f.store
        .writer()
        .write(|tx| {
            sentinel_store::registration::set_policy(
                tx,
                sentinel_store::auth::Authority::HostLocal,
                sentinel_store::registration::DeploymentPolicy {
                    registration: sentinel_store::registration::Registration::InviteOnly,
                    ..sentinel_store::registration::policy(tx)?
                },
                sentinel_core::UnixMillis::now(),
            )
        })
        .unwrap();
    let web = Web::start(port, &f.base);
    (f, web, web_addr, origin)
}

#[test]
#[ignore = "needs Node, the built web interface and a Chromium-family browser"]
fn the_web_interface_in_a_real_browser() {
    let (f, web, web_addr, origin) = deployment(64, true);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = keep_writing(&f, &stop);
    let out = match std::env::var_os("SENTINEL_UI_OUT") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => f.dir.path().join("ui"),
    };
    std::fs::create_dir_all(&out).unwrap();
    let config_path = f.dir.path().join("ui.json");
    std::fs::write(
        &config_path,
        config(&f, &origin, &web_addr, &out).to_string(),
    )
    .unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web/test/ui.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    drop(web);
    assert!(status.success(), "ui.mjs failed: {status}");
}

/// The TanStack Start shell (U09): its own views under the hash-only policy, and the
/// strangler front serving the unmoved views, the API and the streams. Needs
/// `SENTINEL_WEB_FRONT` (the Start server entry) and the built Nuxt interface.
#[test]
#[ignore = "needs Node, both built web interfaces and a Chromium-family browser"]
fn the_start_shell_in_a_real_browser() {
    assert!(
        std::env::var_os("SENTINEL_WEB_FRONT").is_some(),
        "set SENTINEL_WEB_FRONT to web-start/.output/server/index.mjs"
    );
    let (f, web, web_addr, origin) = deployment(4, false);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = keep_writing(&f, &stop);
    let config_path = f.dir.path().join("shell.json");
    std::fs::write(
        &config_path,
        config(&f, &origin, &web_addr, f.dir.path()).to_string(),
    )
    .unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web-start/test/shell.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    drop(web);
    assert!(status.success(), "shell.mjs failed: {status}");
}

/// The first-run setup wizard (U10's seed): a controller with no administrator yet, its setup
/// token issued, the web interface in front, and `web/test/setup.mjs` driving every step.
#[test]
#[ignore = "needs Node, the built web interface and a Chromium-family browser"]
fn the_setup_wizard_in_a_real_browser() {
    use sentinel_link::{controller::Controller, identity::Identity};
    use sentinel_store::{Durability, Store, logs::LogStore, objects::Objects};

    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: Some(key),
            sessions: sentinel_store::local_auth::Policy::default(),
            github_webhook_secret: None,
            intake: None,
            public_url: Some(origin.clone()),
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        },
        sentinel_api::Options::default(),
    )
    .unwrap();
    let token = sentinel_store::setup::issue(&store, sentinel_core::UnixMillis::now())
        .unwrap()
        .unwrap();
    let mut token_text = String::new();
    token.expose(&mut token_text);
    let web = Web::start(port, &format!("http://{}", server.local_addr()));
    let out = match std::env::var_os("SENTINEL_UI_OUT") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => dir.path().join("ui"),
    };
    std::fs::create_dir_all(&out).unwrap();
    let config_path = dir.path().join("setup.json");
    std::fs::write(
        &config_path,
        json!({ "base": origin, "token": token_text, "out": out }).to_string(),
    )
    .unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web/test/setup.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    drop(web);
    server.shutdown();
    drop(controller);
    assert!(status.success(), "setup.mjs failed: {status}");
}

/// The U08/U14 measurement: `web/bench/web-bench.mjs` against this fixture, on the
/// reference host. `SENTINEL_BENCH_RECORD` appends the record to a file under the
/// repository; `SENTINEL_BENCH_HOST_LABEL` names the host in it.
#[test]
#[ignore = "benchmark: needs Node, the built web interface and a Chromium-family browser"]
fn measure_the_web_interface() {
    let bulk = std::env::var("SENTINEL_BULK_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let (f, web, web_addr, origin) = deployment(bulk, false);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = keep_writing(&f, &stop);
    let mut cfg = config(&f, &origin, &web_addr, f.dir.path());
    cfg["web_pids"] = json!(web.pids());
    cfg["interface"] = json!(std::env::var("SENTINEL_WEB_INTERFACE").unwrap_or_default());
    let config_path = f.dir.path().join("bench.json");
    std::fs::write(&config_path, cfg.to_string()).unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web/bench/web-bench.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    drop(web);
    assert!(status.success(), "web-bench.mjs failed: {status}");
}

#[test]
#[ignore = "manual: serves the fixture until the time runs out"]
fn serve_the_fixture() {
    let bulk = std::env::var("SENTINEL_BULK_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    let (f, web, web_addr, origin) = deployment(bulk, false);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = keep_writing(&f, &stop);
    println!("Sentinel web interface: {origin}/  (root / dana / rui, password {PASSWORD:?})");
    println!("{}", config(&f, &origin, &web_addr, f.dir.path()));
    let secs = std::env::var("SENTINEL_SERVE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    drop(web);
}
