//! The Unix implementation: process-group deadlines, owner-only credential
//! files, and the two entry points.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::UnixMillis;
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::{Access, Credential as SourceCredential};

use crate::{Error, Result};

/// A whole checkout — every Git invocation together — must finish in this.
pub const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Longest path [`file_at`] accepts.
pub const MAX_PATH_BYTES: usize = 1024;
/// Bytes of diagnostics kept per stream (payload reads are explicitly capped).
const OUTPUT_TAIL_BYTES: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(20);

/// What a helper produced. `code` is `None` when it died from a signal.
#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The last line of stderr, printable characters only, for an error.
    pub fn stderr_excerpt(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let line = text
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        let mut out: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
        if out.is_empty() {
            out.push_str("no diagnostic output");
        }
        out
    }
}

/// A short-lived, repository-scoped credential for the fetch.
pub struct Credential {
    pub username: String,
    pub secret: String,
}

/// What was checked out: the verified revision.
#[derive(Debug, PartialEq, Eq)]
pub struct Checkout {
    pub sha: String,
}

/// One file read from one revision; `commit` is the peeled commit the file
/// was read at (a tag object resolves to what it points to).
#[derive(Debug, PartialEq, Eq)]
pub struct FetchedFile {
    pub commit: String,
    pub bytes: Vec<u8>,
}

fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .current_dir(dir);
    cmd
}

/// How a stream is captured: a payload is kept whole up to a cap; diagnostics
/// keep only a trailing window so a noisy helper cannot exhaust memory.
enum Capture {
    Payload(Arc<Overflow>),
    Tail,
}

struct Overflow {
    limit: usize,
    exceeded: AtomicBool,
}

fn drain(mut stream: impl Read + Send + 'static, capture: Capture) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut out = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => match &capture {
                    Capture::Payload(overflow) => {
                        if out.len() + n > overflow.limit {
                            overflow.exceeded.store(true, Ordering::Release);
                            break;
                        }
                        out.extend_from_slice(&chunk[..n]);
                    }
                    Capture::Tail => {
                        out.extend_from_slice(&chunk[..n]);
                        if out.len() > OUTPUT_TAIL_BYTES {
                            let excess = out.len() - OUTPUT_TAIL_BYTES;
                            out.drain(..excess);
                        }
                    }
                },
            }
        }
        out
    })
}

fn kill_group(child: &mut Child) {
    // SAFETY: a plain syscall on our own child's process group id; a group
    // that already vanished makes kill fail harmlessly.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.wait();
}

/// Run `command` as the leader of a new process group, with stdin closed, and
/// wait until it exits or `deadline` passes — then the whole group is killed
/// and `Timeout(what)` returned. Diagnostics are trimmed; a `None` cap keeps
/// stdout whole.
pub fn run(command: Command, deadline: Instant, what: &'static str) -> Result<Output> {
    run_capped(command, deadline, what, None)
}

fn run_capped(
    mut command: Command,
    deadline: Instant,
    what: &'static str,
    max_payload: Option<usize>,
) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let overflow = max_payload.map(|limit| {
        Arc::new(Overflow {
            limit,
            exceeded: AtomicBool::new(false),
        })
    });
    let stdout = drain(
        child.stdout.take().expect("piped"),
        match &overflow {
            Some(overflow) => Capture::Payload(Arc::clone(overflow)),
            None => Capture::Tail,
        },
    );
    let stderr = drain(child.stderr.take().expect("piped"), Capture::Tail);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if overflow
            .as_ref()
            .is_some_and(|o| o.exceeded.load(Ordering::Acquire))
        {
            kill_group(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(Error::TooLarge(what));
        }
        if Instant::now() >= deadline {
            kill_group(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(Error::Timeout(what));
        }
        thread::sleep(POLL);
    };
    Ok(Output {
        code: status.code(),
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

fn step(cmd: Command, deadline: Instant, what: &'static str, secrets: &[String]) -> Result<Output> {
    let output = run(cmd, deadline, what)?;
    if output.success() {
        Ok(output)
    } else {
        // Git/SSH servers may reflect a credential in stderr. Take one bounded
        // line and strip anything this fetch installed as a secret.
        let mut excerpt = output.stderr_excerpt();
        for secret in secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        Err(Error::Preparation(format!("{what} failed: {excerpt}")))
    }
}

fn trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// A full object id: 40 (SHA-1) or 64 (SHA-256) lower-case hex digits.
pub fn valid_sha(sha: &str) -> bool {
    (sha.len() == 40 || sha.len() == 64)
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A safe `rev:path` path: relative, printable, bounded, and free of `:`,
/// `\` and traversal segments. Hidden files (`.sentinel.yml`) are ordinary.
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains(':')
        && !path.contains('\\')
        && !path.contains("..")
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
        && !path.bytes().any(|b| b <= 32 || b == 127)
}

fn init(work: &Path, deadline: Instant) -> Result<()> {
    let mut init = git(work);
    init.args(["init", "-q", "--initial-branch=main", "."]);
    step(init, deadline, "git init", &[])?;
    Ok(())
}

/// Fetch `sha` itself (never a branch), depth one and without tags. The
/// credential files are installed for this invocation only.
fn fetch(
    work: &Path,
    remote: &str,
    sha: &str,
    private: Option<&Private>,
    credential: Option<&Credential>,
    deadline: Instant,
) -> Result<()> {
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut fetch = git(work);
    let secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    if let Some(private) = private {
        private.configure(&mut fetch);
    }
    fetch.args([
        "fetch",
        "-q",
        "--no-tags",
        "--depth",
        "1",
        "--",
        remote,
        sha,
    ]);
    let askpass = match credential {
        Some(credential) => Some(Askpass::install(work, credential)?),
        None => None,
    };
    if let Some(askpass) = &askpass {
        fetch
            .env("GIT_ASKPASS", &askpass.path)
            .env("SENTINEL_GIT_USERNAME", &askpass.username)
            .env("SENTINEL_GIT_SECRET", &askpass.secret);
    }
    let fetched = step(fetch, deadline, "git fetch", &secrets);
    // The credential files go as soon as the fetch returns; the caller owns
    // the `Private` install for the checkout that follows.
    drop(askpass);
    fetched.map(|_| ())
}

/// Check out `source.sha` from `source.repo` into `workspace` (which must be
/// empty), within `timeout`. `credential` is presented through the askpass
/// helper for the fetch only.
pub fn checkout(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    timeout: Duration,
) -> Result<Checkout> {
    checkout_inner(workspace, source, credential, None, timeout)
}

/// The same checkout under a source access: expiry, exact remote and allowed
/// ref are rechecked here, never trusted from the run spec.
pub fn checkout_authorized(
    workspace: &Path,
    source: &PinnedSource,
    access: &Access,
    timeout: Duration,
) -> Result<Checkout> {
    if !access.validate(UnixMillis::now().0)
        || source.repo != access.binding.remote
        || source
            .ref_name
            .as_ref()
            .is_some_and(|r| !access.binding.allows(r))
    {
        return Err(Error::Preparation("source access refused".into()));
    }
    checkout_inner(workspace, source, None, Some(access), timeout)
}

fn checkout_inner(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    access: Option<&Access>,
    timeout: Duration,
) -> Result<Checkout> {
    let deadline = Instant::now() + timeout;
    if source.repo.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    init(workspace, deadline)?;
    let private = access.map(|a| Private::install(workspace, a)).transpose()?;
    fetch(
        workspace,
        &source.repo,
        &source.sha,
        private.as_ref(),
        credential,
        deadline,
    )?;
    drop(private);

    let mut detach = git(workspace);
    detach.args(["checkout", "-q", "--detach", "FETCH_HEAD"]);
    step(detach, deadline, "git checkout", &[])?;

    let mut head = git(workspace);
    head.args(["rev-parse", "HEAD"]);
    let output = step(head, deadline, "git rev-parse", &[])?;
    let sha = trim(&output.stdout);
    if sha != source.sha {
        return Err(Error::Preparation(format!(
            "checkout produced {sha}, not the pinned revision"
        )));
    }
    Ok(Checkout { sha })
}

/// Fetch `sha` from `remote` into `work` (which must be empty), peel it to its
/// commit (an annotated tag resolves to what it points to), and read `path`
/// from that commit with a hard byte cap. `access`, when present, supplies the
/// credential and trust and is revalidated here.
pub fn file_at(
    work: &Path,
    remote: &str,
    access: Option<&Access>,
    sha: &str,
    path: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<FetchedFile> {
    if !valid_sha(sha) {
        return Err(Error::Preparation(
            "revision is not a full object id".into(),
        ));
    }
    if !valid_path(path) {
        return Err(Error::Preparation(
            "path is not a safe relative path".into(),
        ));
    }
    if let Some(access) = access
        && (!access.validate(UnixMillis::now().0) || access.binding.remote != remote)
    {
        return Err(Error::Preparation("source access refused".into()));
    }
    let deadline = Instant::now() + timeout;
    init(work, deadline)?;
    let private = access.map(|a| Private::install(work, a)).transpose()?;
    let secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    fetch(work, remote, sha, private.as_ref(), None, deadline)?;
    drop(private);

    let mut peel = git(work);
    peel.args(["rev-parse", "--verify", "FETCH_HEAD^{commit}"]);
    let output = step(peel, deadline, "git rev-parse", &secrets)?;
    let commit = trim(&output.stdout);
    if !valid_sha(&commit) {
        return Err(Error::Preparation(
            "the fetched revision is not a commit".into(),
        ));
    }

    // Probe the size first so an oversized file is refused without reading it.
    let mut size = git(work);
    size.args(["cat-file", "-s", &format!("{commit}:{path}")]);
    let output = match step(size, deadline, "git cat-file", &secrets) {
        Ok(output) => output,
        Err(_) => return Err(Error::Missing),
    };
    let bytes: usize = match trim(&output.stdout).parse() {
        Ok(bytes) => bytes,
        Err(_) => return Err(Error::Missing),
    };
    if bytes > max_bytes {
        return Err(Error::TooLarge("the file at that revision"));
    }

    let mut cat = git(work);
    cat.args(["cat-file", "blob", &format!("{commit}:{path}")]);
    let output = run_capped(cat, deadline, "git cat-file", Some(max_bytes))?;
    if !output.success() {
        return Err(Error::Missing);
    }
    Ok(FetchedFile {
        commit,
        bytes: output.stdout,
    })
}

/// Fetch-only files are siblings of the work directory, never mounted in a
/// job. Mode is set at creation, including on every partial-failure path.
struct Private {
    dir: PathBuf,
    ssh: bool,
    ca: bool,
    username: Option<String>,
    secret: Option<String>,
}

impl Private {
    fn install(work: &Path, access: &Access) -> Result<Self> {
        let dir = work.with_extension("askpass");
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let mut private = Self {
            dir,
            ssh: false,
            ca: false,
            username: None,
            secret: None,
        };
        if !access.binding.trust.is_empty() {
            private.write("trust", access.binding.trust.as_bytes(), 0o600)?;
            private.ca = true;
        }
        match &access.credential {
            SourceCredential::Public => {}
            SourceCredential::Https { username, secret } => {
                private.write("askpass",b"#!/bin/sh\ncase \"$1\" in\nUsername*) printf '%s' \"$SENTINEL_GIT_USERNAME\";;\n*) printf '%s' \"$SENTINEL_GIT_SECRET\";;\nesac\n",0o700)?;
                private.username = Some(username.clone());
                private.secret = Some(secret.clone());
            }
            SourceCredential::Ssh { private_key } => {
                private.ssh = true;
                private.write("key", private_key.as_bytes(), 0o600)?;
                private.write("ssh", b"#!/bin/sh\nexec ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=\"$SENTINEL_GIT_TRUST\" -o UpdateHostKeys=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -i \"$SENTINEL_GIT_KEY\" \"$@\"\n",0o700)?;
            }
        }
        Ok(private)
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(self.dir.join(name))?
            .write_all(bytes)?;
        Ok(())
    }

    fn secrets(&self) -> Vec<String> {
        self.secret.iter().cloned().collect()
    }

    fn configure(&self, cmd: &mut Command) {
        cmd.args([
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-c",
            if self.ssh {
                "protocol.ssh.allow=always"
            } else {
                "protocol.https.allow=always"
            },
        ]);
        if self.ssh {
            cmd.env("GIT_SSH", self.dir.join("ssh"))
                .env("GIT_SSH_VARIANT", "ssh")
                .env("SENTINEL_GIT_TRUST", self.dir.join("trust"))
                .env("SENTINEL_GIT_KEY", self.dir.join("key"));
        } else {
            if self.ca {
                cmd.env("GIT_SSL_CAINFO", self.dir.join("trust"));
            }
            if let (Some(username), Some(secret)) = (&self.username, &self.secret) {
                cmd.env("GIT_ASKPASS", self.dir.join("askpass"))
                    .env("SENTINEL_GIT_USERNAME", username)
                    .env("SENTINEL_GIT_SECRET", secret);
            }
        }
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The legacy askpass helper: an owner-only script beside the workspace that
/// answers Git's username/password prompts from its own environment and is
/// removed as soon as the fetch has finished.
struct Askpass {
    path: PathBuf,
    username: String,
    secret: String,
}

impl Askpass {
    fn install(workspace: &Path, credential: &Credential) -> Result<Askpass> {
        let dir = workspace.with_extension("askpass");
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let path = dir.join("askpass.sh");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)?
            .write_all(b"#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s' \"$SENTINEL_GIT_USERNAME\" ;;\n  *) printf '%s' \"$SENTINEL_GIT_SECRET\" ;;\nesac\n")?;
        Ok(Askpass {
            path,
            username: credential.username.clone(),
            secret: credential.secret.clone(),
        })
    }
}

impl Drop for Askpass {
    fn drop(&mut self) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}
