//! The web interface in a real browser (U06): a seeded controller, the
//! built web interface (`web/.output`, Nuxt) in front of it as it is
//! deployed, a job still writing its log, and `web/test/ui.mjs` driving a
//! headless Chromium-family browser over the DevTools protocol — keyboard
//! and screen-reader structure, contrast in both colour schemes, narrow and
//! wide layouts, a role change and a membership removal while pages are
//! open, a dropped connection and a busy controller during live updates,
//! and the DOM and heap bounds on a large log.
//!
//! Needs Node (22+), the web interface built (`pnpm -C web install && pnpm
//! -C web build`) and Edge, Chrome or Chromium, so it is ignored by default:
//! `cargo test -p sentinel-api --test web_browser -- --ignored --nocapture`.
//! `SENTINEL_BROWSER` and `SENTINEL_NODE` override the executables;
//! `SENTINEL_UI_OUT` keeps screenshots and measurements.

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

/// A free loopback port for the web interface, chosen before the
/// controller starts so the controller can name it as its public origin.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The built web interface serving `port` in front of `api`; stopped when
/// dropped.
struct Web(Child);

impl Web {
    fn start(port: u16, api: &str) -> Web {
        let server = repo_root().join("web/.output/server/index.mjs");
        assert!(
            server.exists(),
            "build the web interface first: pnpm -C web install && pnpm -C web build"
        );
        let child = Command::new(node())
            .arg(&server)
            .env("PORT", port.to_string())
            .env("HOST", "127.0.0.1")
            .env("NUXT_SENTINEL_API", api)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the web interface");
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "the web interface did not listen"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Web(child)
    }
}

impl Drop for Web {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Keep appending to the running job's log until stopped: one numbered
/// line every 150 ms, as a job printing slowly does.
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

/// A controller and the web interface in front of it: the fixture, the
/// web process, its address, and the origin browsers use — `origin_port`
/// when a relay the test controls sits in front (to cut the network), else
/// the web interface itself.
fn deployment(bulk_mib: usize, relayed: bool) -> (Arc<Fixture>, Web, String, String) {
    let port = free_port();
    let web_addr = format!("http://127.0.0.1:{port}");
    let origin = if relayed {
        format!("http://127.0.0.1:{}", free_port())
    } else {
        web_addr.clone()
    };
    let f = Arc::new(Fixture::serving(bulk_mib, Some(origin.clone())));
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

/// Serve the seeded controller and the web interface for a person to look
/// at: `SENTINEL_SERVE_SECS` (default 600) seconds, a live log included.
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
