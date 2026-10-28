//! Q11: the generated worker bootstrap script, linted with shellcheck and run end to end in containers against a
//! fake download server.
//!
//! These tests need Linux, `podman` with the base images already pulled (`--pull=never`) and `tar`, so they are
//! `#[ignore]`d and run explicitly on a verification host:
//! `cargo test -p sentinel-api --test worker_bootstrap_script -- --ignored`. Nothing here touches the host
//! running them beyond a loopback listener: every install happens inside a throw-away container whose only
//! mounts are the test's own scratch directory.

#![cfg(unix)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use sentinel_api::{Pin, TailcatRelease, WorkerBootstrap, WorkerBootstrapSettings};

const IMAGE: &str = "docker.io/library/almalinux:9";
const NO_DOWNLOADER_IMAGE: &str = "docker.io/library/debian:12-slim";
const SHELLCHECK_IMAGE: &str = "docker.io/koalaman/shellcheck:v0.10.0";
const FINGERPRINT: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const SECRET_HEX: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
const ADDRESS: &str = "tcQ2w3E4r5T6y7U8i9O0p1A2s3D4f5G6h7J8";

fn image(var: &str, default: &'static str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_owned())
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => panic!("the container tests run on x86_64 or aarch64, not {other}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

// ---- a fake download server -------------------------------------------------

struct Fake {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    fn start() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (log, served, halt) = (Arc::clone(&requests), Arc::clone(&files), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::Acquire) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 << 10 {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split(' ').nth(1))
                    .unwrap_or("")
                    .to_owned();
                log.lock().unwrap().push(head);
                let body = served.lock().unwrap().get(&path).cloned();
                let _ = match body {
                    Some(body) => {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(&body)
                    }
                    None => stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    ),
                };
            }
        });
        Fake {
            addr,
            requests,
            files,
            stop,
            thread: Some(thread),
        }
    }

    fn serve(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_owned(), bytes);
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|r| r.lines().next()?.split(' ').nth(1).map(str::to_owned))
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---- releases and stubs -----------------------------------------------------

/// The stand-in for `sentinel`: `--version`, `worker --check`, and a `worker` that behaves like the real one
/// where the bootstrap can see it (identity files, the Tailcat node key, consuming the enrollment file).
fn stub_sentinel(version: &str, fail_on_start: bool) -> String {
    format!(
        r##"#!/bin/sh
STUB_VERSION={version}
FAIL_ON_START={fail}
cmd=${{1:-}}
[ $# -eq 0 ] || shift
case $cmd in
    --version) echo "sentinel stub $STUB_VERSION"; exit 0 ;;
    worker) ;;
    *) exit 64 ;;
esac
config=''
check=0
while [ $# -gt 0 ]; do
    case $1 in
        --config) config=$2; shift 2 ;;
        --check) check=1; shift ;;
        *) shift ;;
    esac
done
[ -r "$config" ] || {{ echo "cannot read $config" >&2; exit 1; }}
data=$(sed -n 's/^data_dir = "\(.*\)"$/\1/p' "$config")
if [ "$check" = 1 ]; then
    [ -d "$data" ] || exit 1
    exit 0
fi
[ "$FAIL_ON_START" = 0 ] || exit 1
echo $$ >/tmp/stub-worker.pid
mkdir -p "$data/tailcat"
[ -s "$data/worker.id" ] || echo wrk_00000000-0000-4000-8000-000000000001 >"$data/worker.id"
echo certificate >"$data/worker.crt"
if grep -q '^\[tailcat\]' "$config"; then
    echo nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef >"$data/tailcat/client-default.nodekey"
fi
enrollment=$(sed -n 's/^enrollment_file = "\(.*\)"$/\1/p' "$config")
if [ -f "$enrollment" ]; then
    cat "$enrollment" >>/out/seen-enrollment
    rm -f "$enrollment"
fi
cp "$config" /out/worker.toml.seen
exec sleep 3600
"##,
        fail = u8::from(fail_on_start)
    )
}

const SYSTEMCTL: &str = r##"#!/bin/sh
echo "systemctl $*" >>/out/systemctl.log
pidfile=/tmp/stub-worker.pid
case ${1:-} in
    daemon-reload | enable | disable) exit 0 ;;
    stop)
        pid=$(cat "$pidfile" 2>/dev/null) && kill "$pid" 2>/dev/null
        rm -f "$pidfile"
        exit 0
        ;;
    start | restart)
        pid=$(cat "$pidfile" 2>/dev/null) && kill "$pid" 2>/dev/null
        rm -f "$pidfile"
        exec_start=$(sed -n 's/^ExecStart=//p' /etc/systemd/system/sentinel-worker.service)
        [ -n "$exec_start" ] || exit 5
        runuser -u sentinel-worker -- sh -c "exec $exec_start" >>/out/worker.log 2>&1 &
        exit 0
        ;;
    is-active)
        pid=$(cat "$pidfile" 2>/dev/null) || exit 3
        kill -0 "$pid" 2>/dev/null || exit 3
        exit 0
        ;;
    *) exit 0 ;;
esac
"##;

const LOGINCTL: &str = r##"#!/bin/sh
echo "loginctl $*" >>/out/systemctl.log
case ${1:-} in
    enable-linger) mkdir -p /var/lib/systemd/linger && : >"/var/lib/systemd/linger/$2" ;;
    disable-linger) rm -f "/var/lib/systemd/linger/$2" ;;
esac
exit 0
"##;

const PODMAN: &str = "#!/bin/sh\necho 'podman version 5.7.0'\n";
const TRUE: &str = "#!/bin/sh\nexit 0\n";

const PRELUDE: &str = r##"set -u
mkdir -p /run/systemd/system /var/lib/systemd/linger
install -m 0755 /work/stubs/* /usr/local/bin/
chmod 0777 /out
fact() { printf '%s=%s\n' "$1" "$2" >>/out/facts; }
# Sampled evidence only: every process command line seen while the scenario runs.
( while :; do cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' '\n'; sleep 0.02; done >>/out/cmdlines ) &
"##;

struct Release {
    archive: Vec<u8>,
    sha256: String,
}

fn release(scratch: &Path, version: &str, fail_on_start: bool) -> Release {
    let top = format!("sentinel-{version}-{}-linux-worker", arch());
    let build = scratch.join(format!("build-{version}-{fail_on_start}"));
    let bin = build.join(&top).join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("sentinel"), stub_sentinel(version, fail_on_start)).unwrap();
    let archive_path = build.join("worker.tar.gz");
    let status = Command::new("tar")
        .arg("-C")
        .arg(&build)
        .arg("-czf")
        .arg(&archive_path)
        .arg(&top)
        .status()
        .expect("tar runs");
    assert!(status.success());
    let archive = std::fs::read(archive_path).unwrap();
    Release {
        sha256: sha256(&archive),
        archive,
    }
}

const TAILCAT_STUB: &[u8] = b"#!/bin/sh\necho tailcat stub\n";

fn tailcat_pin(fake: &Fake) -> Pin {
    Pin {
        url: format!("{}/tailcat/tailcat-0.6.0", fake.base()),
        sha256: sha256(TAILCAT_STUB),
    }
}

/// Serve `release` and render the script that pins it. `sums_arch` is the architecture the pins are for.
fn script(fake: &Fake, version: &str, release: &Release, tailcat: bool, sums_arch: &str) -> String {
    let name = format!("sentinel-{version}-{sums_arch}-linux-worker.tar.gz");
    fake.serve(&format!("/rel/{name}"), release.archive.clone());
    fake.serve("/tailcat/tailcat-0.6.0", TAILCAT_STUB.to_vec());
    let pin = tailcat_pin(fake);
    WorkerBootstrap::new(WorkerBootstrapSettings {
        controller: "10.0.0.5:7443".parse().unwrap(),
        fingerprint: FINGERPRINT.into(),
        release_url: format!("{}/rel", fake.base()),
        release_sums: format!("{}  {name}\n", release.sha256),
        tailcat: Some(TailcatRelease {
            version: "0.6.0".into(),
            x86_64: Some(pin.clone()),
            aarch64: Some(pin),
            derpmap_url: None,
            region: None,
        }),
        tailcat_address_file: None,
    })
    .unwrap()
    .render(tailcat)
    .unwrap()
}

// ---- running a scenario in a container --------------------------------------

struct Scenario {
    dir: tempfile::TempDir,
    out: PathBuf,
}

impl Scenario {
    fn new() -> Scenario {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let stubs = dir.path().join("stubs");
        std::fs::create_dir(&stubs).unwrap();
        for (name, body) in [
            ("systemctl", SYSTEMCTL),
            ("loginctl", LOGINCTL),
            ("podman", PODMAN),
            ("newuidmap", TRUE),
            ("newgidmap", TRUE),
        ] {
            std::fs::write(stubs.join(name), body).unwrap();
        }
        let scenario = Scenario { dir, out };
        scenario.write("enroll", &format!("sntl_{SECRET_HEX}\n"), 0o600);
        scenario
    }

    fn write(&self, name: &str, body: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Run `body` (after the prelude) in a fresh container of `image`.
    fn run(&self, image: &str, body: &str) -> Output {
        self.write("scenario.sh", &format!("{PRELUDE}{body}"), 0o644);
        Command::new("podman")
            .args(["run", "--rm", "--network=host", "--pull=never", "-v"])
            .arg(format!("{}:/work:ro", self.dir.path().display()))
            .arg("-v")
            .arg(format!("{}:/out", self.out.display()))
            .arg(image)
            .args(["sh", "/work/scenario.sh"])
            .output()
            .expect("podman runs")
    }

    fn facts(&self) -> HashMap<String, String> {
        std::fs::read_to_string(self.out.join("facts"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn out_file(&self, name: &str) -> String {
        std::fs::read_to_string(self.out.join(name)).unwrap_or_default()
    }

    /// Everything that could show the secret: the scenario's stdout, the script's output, the sampled
    /// command lines and the requests the fake server saw.
    fn assert_secret_never_leaked(&self, run: &Output, fake: &Fake) {
        let mut seen = String::from_utf8_lossy(&run.stdout).into_owned();
        seen.push_str(&String::from_utf8_lossy(&run.stderr));
        for file in ["install.out", "install1.out", "install2.out", "cmdlines"] {
            seen.push_str(&self.out_file(file));
        }
        seen.push_str(&fake.requests().join("\n"));
        assert!(
            !seen.contains(SECRET_HEX),
            "the secret appeared in output, a command line or a request"
        );
        assert!(
            !seen.contains(ADDRESS),
            "the Tailcat address appeared in output, a command line or a request"
        );
    }
}

fn describe(run: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        run.status.code(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    )
}

const INSTALL_WITH_FILE: &str = "sh /work/boot.sh install --name build-1 --secret-file /work/enroll </dev/null >/out/install.out 2>&1\nfact rc $?\n";

// ---- tests -------------------------------------------------------------------

#[test]
#[ignore = "needs shellcheck, directly or through podman"]
fn the_template_and_both_rendered_scripts_pass_shellcheck() {
    let fake = Fake::start();
    let scratch = tempfile::tempdir().unwrap();
    let release = release(scratch.path(), "0.1.0", false);
    for (name, body) in [
        ("tailcat.sh", script(&fake, "0.1.0", &release, true, arch())),
        ("direct.sh", script(&fake, "0.1.0", &release, false, arch())),
        (
            "template.sh",
            include_str!("../src/worker_bootstrap.sh").to_owned(),
        ),
    ] {
        std::fs::write(scratch.path().join(name), body).unwrap();
    }
    let args = ["--shell=sh", "--severity=style"];
    let mut command = if Command::new("shellcheck").arg("--version").output().is_ok() {
        let mut c = Command::new("shellcheck");
        c.args(args).current_dir(scratch.path());
        c
    } else {
        let mut c = Command::new("podman");
        c.args(["run", "--rm", "--pull=never", "-w", "/mnt", "-v"])
            .arg(format!("{}:/mnt:ro", scratch.path().display()))
            .arg(image("SENTINEL_SHELLCHECK_IMAGE", SHELLCHECK_IMAGE))
            .args(args);
        c
    };
    let output = command
        .args(["tailcat.sh", "direct.sh", "template.sh"])
        .output()
        .expect("shellcheck runs");
    assert!(
        output.status.success(),
        "shellcheck findings:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn a_tailcat_install_verifies_places_and_hands_the_secret_to_the_worker_alone() {
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, true, arch()),
        0o644,
    );
    s.write("enroll", &format!("sntl_{SECRET_HEX}\n{ADDRESS}\n"), 0o600);
    s.write("secret-only", &format!("sntl_{SECRET_HEX}\n"), 0o600);
    s.write("address-only", &format!("{ADDRESS}\n"), 0o600);
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        &format!(
            "{INSTALL_WITH_FILE}
fact current \"$(readlink /opt/sentinel-worker/current)\"
fact tailcat_stat \"$(stat -c '%U:%G %a' /opt/sentinel-worker/tailcat/tailcat)\"
fact binary_stat \"$(stat -c '%U:%G %a' /opt/sentinel-worker/current/sentinel)\"
fact conf_stat \"$(stat -c '%U:%G %a' /etc/sentinel-worker/worker.toml)\"
fact data_stat \"$(stat -c '%U:%G %a' /var/lib/sentinel-worker)\"
fact unit \"$(tr '\\n' '|' </etc/systemd/system/sentinel-worker.service)\"
fact subuid \"$(grep -c '^sentinel-worker:' /etc/subuid)\"
fact linger \"$([ -e /var/lib/systemd/linger/sentinel-worker ] && echo yes || echo no)\"
fact identity \"$(sh /work/boot.sh identity)\"
fact enrollment_left \"$([ -e /var/lib/sentinel-worker/enrollment ] && echo yes || echo no)\"
fact state \"$(tr '\\n' '|' </opt/sentinel-worker/install.state)\"
fact leaked \"$(grep -rIlF -f /work/secret-only /etc /opt /var /usr/local /root /home /srv /run /tmp 2>/dev/null | tr '\\n' ' ')\"
fact addr_leaked \"$(grep -rIlF --exclude-dir=sentinel-worker -f /work/address-only /etc /opt /var /usr/local /root /home /srv /run /tmp 2>/dev/null | tr '\\n' ' ')\"
"
        ),
    );
    let facts = s.facts();
    let fact = |k: &str| facts.get(k).map(String::as_str).unwrap_or("<missing>");
    assert_eq!(
        fact("rc"),
        "0",
        "{}\n{}",
        describe(&run),
        s.out_file("install.out")
    );
    let version = format!("0.1.0-{}", &sha256(&rel.archive)[..12]);
    assert_eq!(fact("current"), format!("releases/{version}"));
    assert_eq!(fact("tailcat_stat"), "root:root 755");
    assert_eq!(fact("binary_stat"), "root:root 755");
    assert_eq!(fact("conf_stat"), "root:sentinel-worker 640");
    assert_eq!(fact("data_stat"), "sentinel-worker:sentinel-worker 700");
    assert_eq!(fact("subuid"), "1");
    assert_eq!(fact("linger"), "yes");
    let unit = fact("unit");
    for line in [
        "User=sentinel-worker|",
        "ExecStart=/opt/sentinel-worker/current/sentinel worker --config /etc/sentinel-worker/worker.toml|",
        "WantedBy=multi-user.target|",
    ] {
        assert!(unit.contains(line), "{unit}");
    }
    assert!(
        fact("identity").starts_with("nodekey:0123456789abcdef")
            && fact("identity").ends_with(" wrk_00000000-0000-4000-8000-000000000001"),
        "{}",
        fact("identity")
    );
    assert!(fact("state").contains("complete=1|") && fact("state").contains("created_account=1|"));

    let config = s.out_file("worker.toml.seen");
    for line in [
        "controller = \"127.0.0.1:7443\"",
        &format!("controller_fingerprint = \"{FINGERPRINT}\""),
        "worker_name = \"build-1\"",
        "enrollment_file = \"/var/lib/sentinel-worker/enrollment\"",
        &format!("tailcat_address = \"{ADDRESS}\""),
        "[tailcat]",
        "binary = \"/opt/sentinel-worker/tailcat/tailcat\"",
        &format!("sha256 = \"{}\"", sha256(TAILCAT_STUB)),
        "listen_port = 7443",
    ] {
        assert!(config.contains(line), "worker.toml lacks {line}:\n{config}");
    }
    assert!(!config.contains(SECRET_HEX));

    // The worker received the secret, once, and nothing on disk keeps a copy; the script's own file never had it.
    assert_eq!(
        s.out_file("seen-enrollment").trim(),
        format!("sntl_{SECRET_HEX}")
    );
    assert_eq!(fact("enrollment_left"), "no");
    assert_eq!(
        fact("leaked").trim(),
        "",
        "a copy of the secret stayed on disk"
    );
    assert_eq!(
        fact("addr_leaked").trim(),
        "",
        "the Tailcat address outside worker.toml"
    );
    assert!(
        !std::fs::read_to_string(s.dir.path().join("boot.sh"))
            .unwrap()
            .contains(SECRET_HEX)
    );
    s.assert_secret_never_leaked(&run, &fake);

    // Two downloads, plain GETs of the pinned locations, and nothing else.
    assert_eq!(
        fake.paths(),
        vec![
            format!("/rel/sentinel-0.1.0-{}-linux-worker.tar.gz", arch()),
            "/tailcat/tailcat-0.6.0".to_owned()
        ]
    );
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn a_direct_install_over_stdin_downloads_no_helper_and_a_tailcat_one_needs_its_address() {
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, arch()),
        0o644,
    );
    s.write("input", &format!("sntl_{SECRET_HEX}\n"), 0o600);
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        "sh /work/boot.sh install --name direct-1 --secret-stdin </work/input >/out/install.out 2>&1
fact rc $?
fact tailcat_dir \"$([ -e /opt/sentinel-worker/tailcat ] && echo yes || echo no)\"
",
    );
    let facts = s.facts();
    assert_eq!(
        facts["rc"],
        "0",
        "{}\n{}",
        describe(&run),
        s.out_file("install.out")
    );
    assert_eq!(facts["tailcat_dir"], "no");
    let config = s.out_file("worker.toml.seen");
    assert!(
        config.contains("controller = \"10.0.0.5:7443\""),
        "{config}"
    );
    assert!(!config.contains("tailcat"), "{config}");
    assert_eq!(
        s.out_file("seen-enrollment").trim(),
        format!("sntl_{SECRET_HEX}")
    );
    assert_eq!(
        fake.paths(),
        vec![format!(
            "/rel/sentinel-0.1.0-{}-linux-worker.tar.gz",
            arch()
        )]
    );
    s.assert_secret_never_leaked(&run, &fake);

    // A Tailcat script given only the secret refuses before downloading or changing anything.
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, true, arch()),
        0o644,
    );
    s.write("input", &format!("sntl_{SECRET_HEX}\n"), 0o600);
    s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        "sh /work/boot.sh install --secret-stdin </work/input >/out/install.out 2>&1
fact rc $?
fact opt \"$([ -e /opt/sentinel-worker ] && echo yes || echo no)\"
fact account \"$(getent passwd sentinel-worker >/dev/null && echo yes || echo no)\"
",
    );
    let facts = s.facts();
    assert_eq!(facts["rc"], "1");
    assert!(s.out_file("install.out").contains("Tailcat address"));
    assert_eq!(
        (facts["opt"].as_str(), facts["account"].as_str()),
        ("no", "no")
    );
    assert!(fake.paths().is_empty(), "nothing was downloaded");
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn an_upgrade_keeps_the_previous_release_and_rollback_switches_back() {
    let fake = Fake::start();
    let s = Scenario::new();
    let (one, two) = (
        release(s.dir.path(), "0.1.0", false),
        release(s.dir.path(), "0.2.0", false),
    );
    s.write(
        "boot1.sh",
        &script(&fake, "0.1.0", &one, false, arch()),
        0o644,
    );
    s.write(
        "boot2.sh",
        &script(&fake, "0.2.0", &two, false, arch()),
        0o644,
    );
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        "sh /work/boot1.sh install --name build-1 --secret-file /work/enroll </dev/null >/out/install1.out 2>&1
fact rc1 $?
fact ver1 \"$(/opt/sentinel-worker/current/sentinel --version)\"
sh /work/boot2.sh install </dev/null >/out/install2.out 2>&1
fact rc2 $?
fact current2 \"$(readlink /opt/sentinel-worker/current)\"
fact previous2 \"$(readlink /opt/sentinel-worker/previous)\"
fact ver2 \"$(/opt/sentinel-worker/current/sentinel --version)\"
fact name2 \"$(sed -n 's/^worker_name = //p' /etc/sentinel-worker/worker.toml)\"
fact releases2 \"$(ls /opt/sentinel-worker/releases | wc -l)\"
sh /work/boot2.sh rollback </dev/null >/out/rollback.out 2>&1
fact rc3 $?
fact current3 \"$(readlink /opt/sentinel-worker/current)\"
fact previous3 \"$(readlink /opt/sentinel-worker/previous)\"
fact ver3 \"$(/opt/sentinel-worker/current/sentinel --version)\"
fact state3 \"$(sed -n 's/^release=//p' /opt/sentinel-worker/install.state)\"
",
    );
    let f = s.facts();
    let (a, b) = (
        format!("0.1.0-{}", &one.sha256[..12]),
        format!("0.2.0-{}", &two.sha256[..12]),
    );
    assert_eq!(
        f["rc1"],
        "0",
        "{}\n{}",
        describe(&run),
        s.out_file("install1.out")
    );
    assert_eq!(f["rc2"], "0", "{}", s.out_file("install2.out"));
    assert_eq!(f["ver1"], "sentinel stub 0.1.0");
    assert_eq!(f["current2"], format!("releases/{b}"));
    assert_eq!(f["previous2"], format!("releases/{a}"));
    assert_eq!(f["ver2"], "sentinel stub 0.2.0");
    assert_eq!(
        f["name2"], "\"build-1\"",
        "an upgrade keeps the worker's name"
    );
    assert_eq!(f["releases2"], "2");
    assert_eq!(f["rc3"], "0", "{}", s.out_file("rollback.out"));
    assert_eq!(f["current3"], format!("releases/{a}"));
    assert_eq!(f["previous3"], format!("releases/{b}"));
    assert_eq!(f["ver3"], "sentinel stub 0.1.0");
    assert_eq!(f["state3"], a);
    // The upgrade ran without a secret and the worker started on each release.
    assert!(!s.out_file("install2.out").contains("enrollment secret"));
    assert!(
        s.out_file("systemctl.log")
            .matches("systemctl restart sentinel-worker")
            .count()
            >= 3
    );
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn an_upgrade_that_does_not_stay_up_is_rolled_back_by_the_script() {
    let fake = Fake::start();
    let s = Scenario::new();
    let (one, broken) = (
        release(s.dir.path(), "0.1.0", false),
        release(s.dir.path(), "0.2.0", true),
    );
    s.write(
        "boot1.sh",
        &script(&fake, "0.1.0", &one, false, arch()),
        0o644,
    );
    s.write(
        "boot2.sh",
        &script(&fake, "0.2.0", &broken, false, arch()),
        0o644,
    );
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        "sh /work/boot1.sh install --name build-1 --secret-file /work/enroll </dev/null >/out/install1.out 2>&1
fact rc1 $?
sh /work/boot2.sh install </dev/null >/out/install2.out 2>&1
fact rc2 $?
fact current \"$(readlink /opt/sentinel-worker/current)\"
fact previous \"$([ -e /opt/sentinel-worker/previous ] && echo present || echo absent)\"
fact releases \"$(ls /opt/sentinel-worker/releases | wc -l)\"
fact active \"$(systemctl is-active --quiet sentinel-worker && echo yes || echo no)\"
fact ver \"$(/opt/sentinel-worker/current/sentinel --version)\"
fact state \"$(sed -n 's/^release=//p' /opt/sentinel-worker/install.state)\"
",
    );
    let f = s.facts();
    assert_eq!(
        f["rc1"],
        "0",
        "{}\n{}",
        describe(&run),
        s.out_file("install1.out")
    );
    assert_eq!(f["rc2"], "1", "{}", s.out_file("install2.out"));
    let failed = s.out_file("install2.out");
    assert!(
        failed.contains("did not stay up") && failed.contains("undoing"),
        "{failed}"
    );
    let a = format!("0.1.0-{}", &one.sha256[..12]);
    assert_eq!(f["current"], format!("releases/{a}"));
    assert_eq!(f["previous"], "absent");
    assert_eq!(f["releases"], "1");
    assert_eq!(f["active"], "yes", "the old release runs again");
    assert_eq!(f["ver"], "sentinel stub 0.1.0");
    assert_eq!(f["state"], a);
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn a_download_that_does_not_match_its_pin_installs_nothing() {
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, arch()),
        0o644,
    );
    let mut tampered = rel.archive.clone();
    tampered.push(0);
    fake.serve(
        &format!("/rel/sentinel-0.1.0-{}-linux-worker.tar.gz", arch()),
        tampered,
    );
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        &format!(
            "{INSTALL_WITH_FILE}
fact opt \"$([ -e /opt/sentinel-worker ] && echo yes || echo no)\"
fact etc \"$([ -e /etc/sentinel-worker ] && echo yes || echo no)\"
fact data \"$([ -e /var/lib/sentinel-worker ] && echo yes || echo no)\"
fact unit \"$([ -e /etc/systemd/system/sentinel-worker.service ] && echo yes || echo no)\"
fact account \"$(getent passwd sentinel-worker >/dev/null && echo yes || echo no)\"
fact staging \"$(ls /var/tmp | grep -c sentinel-worker-bootstrap)\"
"
        ),
    );
    let f = s.facts();
    assert_eq!(f["rc"], "1", "{}", describe(&run));
    assert!(
        s.out_file("install.out")
            .contains("does not match the digest pinned by the controller")
    );
    for key in ["opt", "etc", "data", "unit", "account"] {
        assert_eq!(f[key], "no", "{key} was created");
    }
    assert_eq!(f["staging"], "0", "the staging directory is removed");
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn uninstall_removes_what_the_install_created_and_keep_data_keeps_the_identity() {
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, arch()),
        0o644,
    );
    let gone = "gone() {
    fact \"$1_opt\" \"$([ -e /opt/sentinel-worker ] && echo yes || echo no)\"
    fact \"$1_etc\" \"$([ -e /etc/sentinel-worker ] && echo yes || echo no)\"
    fact \"$1_unit\" \"$([ -e /etc/systemd/system/sentinel-worker.service ] && echo yes || echo no)\"
    fact \"$1_account\" \"$(getent passwd sentinel-worker >/dev/null && echo yes || echo no)\"
    fact \"$1_linger\" \"$([ -e /var/lib/systemd/linger/sentinel-worker ] && echo yes || echo no)\"
    fact \"$1_active\" \"$(systemctl is-active --quiet sentinel-worker && echo yes || echo no)\"
}
";
    let run = s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        &format!(
            "{gone}{INSTALL_WITH_FILE}
sh /work/boot.sh uninstall --keep-data </dev/null >/out/uninstall1.out 2>&1
fact rc_keep $?
fact data_kept \"$([ -s /var/lib/sentinel-worker/worker.id ] && echo yes || echo no)\"
gone keep
sh /work/boot.sh install --name build-1 --secret-file /work/enroll </dev/null >/out/reinstall.out 2>&1
fact rc_reinstall $?
rm -rf /var/lib/sentinel-worker
sh /work/boot.sh install --name build-1 --secret-file /work/enroll </dev/null >/out/install2.out 2>&1
fact rc_fresh $?
sh /work/boot.sh uninstall </dev/null >/out/uninstall2.out 2>&1
fact rc_full $?
fact data_full \"$([ -e /var/lib/sentinel-worker ] && echo yes || echo no)\"
gone full
"
        ),
    );
    let f = s.facts();
    assert_eq!(
        f["rc"],
        "0",
        "{}\n{}",
        describe(&run),
        s.out_file("install.out")
    );
    assert_eq!(f["rc_keep"], "0", "{}", s.out_file("uninstall1.out"));
    assert_eq!(f["data_kept"], "yes", "--keep-data keeps the identity");
    assert_eq!(
        f["rc_reinstall"],
        "2",
        "a kept identity blocks a fresh install: {}",
        s.out_file("reinstall.out")
    );
    assert!(s.out_file("reinstall.out").contains("already exists"));
    assert_eq!(f["rc_fresh"], "0", "{}", s.out_file("install2.out"));
    assert_eq!(f["rc_full"], "0", "{}", s.out_file("uninstall2.out"));
    assert_eq!(f["data_full"], "no");
    for phase in ["keep", "full"] {
        for key in ["opt", "etc", "unit", "account", "linger", "active"] {
            assert_eq!(
                f[&format!("{phase}_{key}")],
                "no",
                "{key} remains after the {phase} uninstall"
            );
        }
    }
    let log = s.out_file("systemctl.log");
    assert!(
        log.contains("systemctl stop sentinel-worker")
            && log.contains("systemctl disable sentinel-worker")
    );
    assert!(log.contains("loginctl disable-linger sentinel-worker"));
}

#[test]
#[ignore = "needs podman, tar and pre-pulled base images; run on a verification host"]
fn unsupported_or_unsafe_setups_are_refused_visibly_before_anything_changes() {
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, arch()),
        0o644,
    );
    s.write("loose", &format!("sntl_{SECRET_HEX}\n"), 0o644);
    s.write("malformed", "sntl_not-a-secret\n", 0o600);
    s.write(
        "uname-riscv",
        "#!/bin/sh\n[ \"${1:-}\" = -m ] && echo riscv64 || echo Linux\n",
        0o755,
    );
    s.write("uname-darwin", "#!/bin/sh\necho Darwin\n", 0o755);
    s.write(
        "old-podman",
        "#!/bin/sh\necho 'podman version 3.4.4'\n",
        0o755,
    );
    let untouched = "fact opt_$n \"$([ -e /opt/sentinel-worker ] && echo yes || echo no)\"
fact account_$n \"$(getent passwd sentinel-worker >/dev/null && echo yes || echo no)\"
";
    let case = |n: &str, setup: &str, command: &str| {
        format!(
            "n={n}\n{setup}\nsh /work/boot.sh {command} </dev/null >/out/{n}.out 2>&1\nfact rc_$n $?\n{untouched}"
        )
    };
    let body = [
        case(
            "arch",
            "install -m 0755 /work/uname-riscv /usr/local/bin/uname",
            "install --secret-file /work/enroll",
        ),
        case(
            "os",
            "install -m 0755 /work/uname-darwin /usr/local/bin/uname",
            "check",
        ),
        case(
            "podman",
            "rm -f /usr/local/bin/uname; install -m 0755 /work/old-podman /usr/local/bin/podman",
            "install --secret-file /work/enroll",
        ),
        case(
            "nosystemd",
            "install -m 0755 /work/stubs/podman /usr/local/bin/podman; rmdir /run/systemd/system",
            "install --secret-file /work/enroll",
        ),
        case(
            "loose",
            "mkdir -p /run/systemd/system",
            "install --secret-file /work/loose",
        ),
        case("malformed", "", "install --secret-file /work/malformed"),
        case("nosecret", "", "install"),
        case("badoption", "", "install --secret-stdin --frobnicate"),
        case("badcommand", "", "frobnicate"),
        case(
            "foreign",
            "useradd --system sentinel-worker",
            "install --secret-file /work/enroll",
        ),
    ]
    .join("\n");
    let run = s.run(&image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE), &body);
    let f = s.facts();
    let said = |n: &str| s.out_file(&format!("{n}.out"));
    for (n, rc, message) in [
        ("arch", "2", "unsupported CPU architecture riscv64"),
        ("os", "2", "installs a Linux worker; this host runs Darwin"),
        ("podman", "2", "Podman 4 or newer is required"),
        ("nosystemd", "2", "systemd is not this host's init system"),
        ("loose", "1", "is mode 644"),
        ("malformed", "1", "malformed"),
        ("nosecret", "64", "needs the enrollment secret"),
        ("badoption", "64", "unknown option '--frobnicate'"),
        ("badcommand", "64", "unknown command 'frobnicate'"),
        (
            "foreign",
            "2",
            "already exists and was not created by this script",
        ),
    ] {
        assert_eq!(
            f[&format!("rc_{n}")],
            rc,
            "{n}: {}\n{}",
            said(n),
            describe(&run)
        );
        assert!(said(n).contains(message), "{n}: {}", said(n));
        assert_eq!(
            f[&format!("opt_{n}")],
            "no",
            "{n} created /opt/sentinel-worker"
        );
    }
    for n in [
        "arch",
        "os",
        "podman",
        "nosystemd",
        "loose",
        "malformed",
        "nosecret",
        "badoption",
        "badcommand",
    ] {
        assert_eq!(f[&format!("account_{n}")], "no", "{n} created the account");
    }
    assert!(fake.paths().is_empty(), "a refused run downloads nothing");

    // A missing pin for this CPU is a refusal too, naming the architecture.
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    let other = if arch() == "x86_64" {
        "aarch64"
    } else {
        "x86_64"
    };
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, other),
        0o644,
    );
    s.run(
        &image("SENTINEL_BOOTSTRAP_IMAGE", IMAGE),
        "sh /work/boot.sh check </dev/null >/out/pin.out 2>&1\nfact rc $?\n",
    );
    assert_eq!(s.facts()["rc"], "2");
    assert!(
        s.out_file("pin.out")
            .contains(&format!("publishes no worker release for {}", arch()))
    );

    // No downloader on the host.
    let fake = Fake::start();
    let s = Scenario::new();
    let rel = release(s.dir.path(), "0.1.0", false);
    s.write(
        "boot.sh",
        &script(&fake, "0.1.0", &rel, false, arch()),
        0o644,
    );
    s.run(
        &image("SENTINEL_NO_DOWNLOADER_IMAGE", NO_DOWNLOADER_IMAGE),
        "sh /work/boot.sh check </dev/null >/out/dl.out 2>&1\nfact rc $?\n",
    );
    assert_eq!(s.facts()["rc"], "2");
    assert!(s.out_file("dl.out").contains("neither 'curl' nor 'wget'"));
}
