//! Needs Node 22+, the built web interface (`pnpm -C web build`) and Edge, Chrome or Chromium: run with --ignored.

#[path = "support/web_fixture.rs"]
mod fixture;
#[path = "support/github_app.rs"]
mod github_app;

use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use fixture::{Fixture, PASSWORD, TAILCAT_ADDRESS};
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

/// The web interface, `web/.output/server/index.mjs` unless `SENTINEL_WEB_SERVER`
/// names another build of it.
struct Web(Vec<Child>);

/// `log` receives the process's standard output and error, to be scanned afterwards; without it the output is
/// dropped and the errors are shown.
fn spawn_web(
    server: &std::path::Path,
    port: u16,
    envs: &[(&str, String)],
    log: Option<&std::path::Path>,
) -> Child {
    assert!(
        server.exists(),
        "build the web interface first: {} is missing",
        server.display()
    );
    let mut command = Command::new(node());
    command
        .arg(server)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1");
    match log {
        Some(path) => {
            let file = std::fs::File::create(path).expect("create the web log");
            command
                .stdout(file.try_clone().expect("clone the web log"))
                .stderr(file);
        }
        None => {
            command.stdout(Stdio::null()).stderr(Stdio::inherit());
        }
    }
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
        Web::start_with(port, api, &[], None)
    }

    /// With more environment (such as `SENTINEL_GITHUB_WEB_URL`) and, optionally, a file for its output.
    fn start_with(
        port: u16,
        api: &str,
        extra: &[(&str, String)],
        log: Option<&std::path::Path>,
    ) -> Web {
        let server = std::env::var_os("SENTINEL_WEB_SERVER")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| repo_root().join("web/.output/server/index.mjs"));
        // `SENTINEL_WEB_API_ENV=NUXT_SENTINEL_API` checks the name an upgraded Nuxt deployment still sets.
        let name = std::env::var("SENTINEL_WEB_API_ENV").unwrap_or_else(|_| "SENTINEL_API".into());
        let name: &str = if name == "NUXT_SENTINEL_API" {
            "NUXT_SENTINEL_API"
        } else {
            "SENTINEL_API"
        };
        let mut envs = vec![(name, api.to_owned())];
        envs.extend(extra.iter().map(|(k, v)| (*k, v.clone())));
        Web(vec![spawn_web(&server, port, &envs, log)])
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
        "pat": f.pat.to_string(),
        "subscribers_per_user": sentinel_api::SUBSCRIBERS_PER_USER,
        "web_log": f.dir.path().join("web.log"),
        "tailcat_address": TAILCAT_ADDRESS,
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
    let web = Web::start_with(port, &f.base, &[], Some(&f.dir.path().join("web.log")));
    (f, web, web_addr, origin)
}

#[test]
#[ignore = "needs Node, the built web interface and a Chromium-family browser"]
fn the_web_interface_in_a_real_browser() {
    let (f, web, web_addr, origin) = deployment(64, true);
    let seed = f.seed_step_up_users();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = keep_writing(&f, &stop);
    let out = match std::env::var_os("SENTINEL_UI_OUT") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => f.dir.path().join("ui"),
    };
    std::fs::create_dir_all(&out).unwrap();
    let config_path = f.dir.path().join("ui.json");
    let mut cfg = config(&f, &origin, &web_addr, &out);
    cfg["ivy"] = json!(seed.ivy.to_string());
    cfg["mia"] =
        json!({ "user": seed.mia.to_string(), "key": seed.mfa_key, "recovery": seed.recovery });
    std::fs::write(&config_path, cfg.to_string()).unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web/test/ui.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    drop(web);
    if !status.success() {
        let log = std::fs::read_to_string(f.dir.path().join("web.log")).unwrap_or_default();
        let tail: Vec<&str> = log.lines().rev().take(40).collect();
        eprintln!(
            "web process output (last lines):
{}",
            tail.into_iter().rev().collect::<Vec<_>>().join(
                "
"
            )
        );
    }
    assert!(status.success(), "ui.mjs failed: {status}");
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
    let web = Web::start_with(
        port,
        &format!("http://{}", server.local_addr()),
        &[],
        Some(&dir.path().join("web.log")),
    );
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

/// One-click GitHub App setup (U17): a platform administrator creates the deployment's App from the page, the manifest
/// goes to the fake GitHub's pages on another site, the browser comes back signed in with the code, namespaces are
/// installed on, and `web/test/github.mjs` drives it all. Afterwards the App is proven in force in the controller
/// process, and no secret it was handed is in the web process's output, in a page the browser received, in an audit
/// row or in a database byte.
#[test]
#[ignore = "needs Node, the built web interface and a Chromium-family browser"]
fn the_github_app_setup_in_a_real_browser() {
    use std::sync::Mutex;

    use sentinel_github::fake::FakeGithub;

    let fake = FakeGithub::start("unused-oauth-secret");
    fake.set_blueprint(github_app::blueprint("acme-gh"));
    fake.offer_installation("acme-gh", 9000, false);
    let activated = Arc::new(Mutex::new(Vec::<u64>::new()));
    let recorder = Arc::clone(&activated);
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let f = Fixture::serving_with(
        1,
        Some(origin.clone()),
        sentinel_api::Options {
            github_app: sentinel_api::GithubAppSetup {
                web_url: fake.web_base(),
                api_url: fake.base(),
                sign_in_endpoints: fake.endpoints(),
                current: sentinel_github::app::Current::default(),
                source: None,
                on_activate: Some(Arc::new(move |activation: &sentinel_api::Activation| {
                    recorder.lock().unwrap().push(activation.app_id);
                })),
            },
            ..sentinel_api::Options::default()
        },
    );
    let out = match std::env::var_os("SENTINEL_UI_OUT") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => f.dir.path().join("ui"),
    };
    std::fs::create_dir_all(&out).unwrap();
    let web_log = f.dir.path().join("web.log");
    let web = Web::start_with(
        port,
        &f.base,
        &[("SENTINEL_GITHUB_WEB_URL", fake.web_base())],
        Some(&web_log),
    );
    let config_path = f.dir.path().join("github.json");
    std::fs::write(
        &config_path,
        json!({
            "web": origin,
            "github_web": fake.web_base(),
            "password": PASSWORD,
            "org": "acme-gh",
            "install_account": "acme-gh",
            "app": { "name": "Acme CI", "slug": "acme-ci" },
            "canaries": github_app::canaries(),
            "out": out,
        })
        .to_string(),
    )
    .unwrap();
    let status = Command::new(node())
        .arg(repo_root().join("web/test/github.mjs"))
        .arg(&config_path)
        .status()
        .expect("run node");
    drop(web);
    assert!(status.success(), "github.mjs failed: {status}");

    // The App is in force in the controller process: the activation hook ran once, and the webhook verifies with the
    // secret GitHub handed back while a wrong secret does not.
    assert_eq!(*activated.lock().unwrap(), vec![4242]);
    let hook = |secret: &[u8]| {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let body = "{\"zen\":\"x\"}";
        let tag = ring::hmac::sign(&key, body.as_bytes());
        let signature: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build(),
        );
        let response = agent
            .post(format!("{}/api/v1/hooks/github", f.base))
            .header("content-type", "application/json")
            .header("x-github-event", "ping")
            .header("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958")
            .header("x-hub-signature-256", format!("sha256={signature}"))
            .send(body.as_bytes())
            .unwrap();
        response.status().as_u16()
    };
    assert_eq!(hook(github_app::WEBHOOK_SECRET.as_bytes()), 200);
    assert_ne!(hook(b"some-other-secret-0123456789"), 200);

    // What GitHub was asked to create: the manifest the controller built for a loopback (unreachable) address.
    let posted = fake.manifests_posted();
    assert_eq!(posted.len(), 1, "one manifest");
    let manifest: serde_json::Value = serde_json::from_str(&posted[0]).unwrap();
    assert_eq!(
        manifest["default_permissions"],
        json!({
            "checks": "write", "contents": "read", "metadata": "read",
            "pull_requests": "read", "members": "read",
        })
    );
    assert_eq!(manifest["hook_attributes"]["active"], false);
    assert!(manifest.get("default_events").is_none());
    assert_eq!(
        manifest["redirect_url"],
        format!("{origin}/setup/github/created")
    );
    assert_eq!(
        manifest["setup_url"],
        format!("{origin}/setup/github/installed")
    );
    assert_eq!(
        fake.web_requests(),
        vec![
            "GET /apps/none/installations/new",
            "POST /organizations/acme-gh/settings/apps/new",
            "POST /__fake/create",
            "GET /apps/acme-ci/installations/new",
            "POST /__fake/install",
            "GET /apps/acme-ci/installations/new",
            "POST /__fake/install",
        ]
    );

    // No secret in the web process's output, in what the browser received, in the audit log or in the database.
    // (The positive control: the canaries are in the credentials the fake handed out.)
    let handed = github_app::blueprint("acme-gh");
    github_app::assert_present_in_source(&format!(
        "{}\n{}\n{}",
        handed.pem, handed.client_secret, handed.webhook_secret
    ));
    github_app::assert_clean_text(
        "the web process's output",
        &String::from_utf8_lossy(&std::fs::read(&web_log).unwrap()),
    );
    github_app::assert_clean_text(
        "a page the browser received",
        &std::fs::read_to_string(out.join("github-bodies.txt")).unwrap(),
    );
    let audit: Vec<String> = f
        .store
        .read(|c| sentinel_store::local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .map(|r| format!("{} {}", r.event.name(), r.detail.unwrap_or_default()))
        .collect();
    assert!(
        audit
            .iter()
            .any(|line| line == "github-app-created app 4242 acme-ci"),
        "{audit:?}"
    );
    github_app::assert_clean_text("the audit log", &audit.join("\n"));
    github_app::assert_clean_database(f.dir.path());
}
