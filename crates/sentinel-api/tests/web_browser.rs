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
