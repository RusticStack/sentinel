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

use crate::{Error, Merge, Result, destination};

pub const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const MAX_PATH_BYTES: usize = 1024;
const OUTPUT_TAIL_BYTES: usize = 64 * 1024;
const CHECK: Duration = Duration::from_millis(50);
const POLL: Duration = Duration::from_millis(20);

thread_local! {
    static CANCEL: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

pub fn cancel_scope<T>(cancel: Arc<AtomicBool>, f: impl FnOnce() -> T) -> T {
    let previous = CANCEL.with(|slot| slot.borrow_mut().replace(cancel));
    let out = f();
    CANCEL.with(|slot| *slot.borrow_mut() = previous);
    out
}

fn canceled() -> bool {
    CANCEL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    })
}

pub struct ExitWatch(#[cfg(target_os = "linux")] Option<std::os::fd::OwnedFd>);

impl ExitWatch {
    pub fn of(child: &Child) -> ExitWatch {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::FromRawFd;
            // SAFETY: pidfd_open on our own, not yet reaped child: the pid
            // cannot have been recycled. A negative answer (no pidfd
            // support) is simply not used.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
            ExitWatch((fd >= 0).then(|| {
                // SAFETY: `fd` is a fresh descriptor this call owns alone.
                unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = child;
            ExitWatch()
        }
    }

    pub fn wakes_on_exit(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.0.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn park(&self, wait: Duration) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.0 {
            use std::os::fd::AsRawFd;
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = wait.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            // SAFETY: one valid pollfd on the stack for the duration of the
            // call; an interrupted poll simply returns early.
            unsafe {
                libc::poll(&mut poll, 1, ms);
            }
            return;
        }
        thread::sleep(wait.min(POLL));
    }
}

pub fn wait_step(
    child: &mut Child,
    watch: &ExitWatch,
    until: Instant,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    let now = Instant::now();
    if now < until {
        watch.park((until - now).min(CHECK));
    }
    child.try_wait()
}

pub(crate) fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

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

pub struct Credential {
    pub username: String,
    pub secret: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Checkout {
    pub sha: String,
    pub fetch_ns: u64,
    pub materialize_ns: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FetchedFile {
    pub commit: String,
    pub bytes: Vec<u8>,
}

const NO_HOME: &str = "/nonexistent-sentinel-git-home";

pub(crate) fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", NO_HOME)
        .env("XDG_CONFIG_HOME", NO_HOME)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .current_dir(dir);
    cmd
}

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

pub fn die_with_parent(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `getpid` has no preconditions and cannot fail.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the closure runs in the forked child before `exec` and
        // calls only `prctl` and `getppid`, both async-signal-safe; it
        // allocates nothing and takes no lock.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

fn kill_group(child: &mut Child) {
    // SAFETY: a plain syscall on our own child's process group id; a group
    // that already vanished makes kill fail harmlessly.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.wait();
}

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
    die_with_parent(&mut command);
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
    let watch = ExitWatch::of(&child);
    let status = loop {
        match wait_step(&mut child, &watch, deadline) {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                kill_group(&mut child);
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(error.into());
            }
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
        if canceled() {
            kill_group(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(Error::Preparation(format!("{what} canceled")));
        }
        if Instant::now() >= deadline {
            kill_group(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(Error::Timeout(what));
        }
    };
    Ok(Output {
        code: status.code(),
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

pub(crate) fn step(
    cmd: Command,
    deadline: Instant,
    what: &'static str,
    secrets: &[String],
) -> Result<Output> {
    let output = run(cmd, deadline, what)?;
    if output.success() {
        Ok(output)
    } else {
        let mut excerpt = output.stderr_excerpt();
        for secret in secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        Err(Error::Preparation(format!("{what} failed: {excerpt}")))
    }
}

pub(crate) fn trim(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

pub fn valid_sha(sha: &str) -> bool {
    (sha.len() == 40 || sha.len() == 64)
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

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

pub(crate) fn init(work: &Path, deadline: Instant) -> Result<()> {
    let mut init = git(work);
    init.args(["init", "-q", "--initial-branch=main", "."]);
    step(init, deadline, "git init", &[])?;
    Ok(())
}

fn fetch(
    work: &Path,
    remote: &str,
    sha: &str,
    private: Option<&Private>,
    credential: Option<&Credential>,
    pin: Option<&str>,
    deadline: Instant,
) -> Result<()> {
    fetch_with(
        work,
        remote,
        sha,
        private,
        credential,
        pin,
        &["--depth", "1"],
        deadline,
    )
}

#[allow(clippy::too_many_arguments)]
fn fetch_with(
    work: &Path,
    remote: &str,
    sha: &str,
    private: Option<&Private>,
    credential: Option<&Credential>,
    pin: Option<&str>,
    extra: &[&str],
    deadline: Instant,
) -> Result<()> {
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut fetch = git(work);
    let mut secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    if let Some(credential) = credential
        && !credential.secret.is_empty()
    {
        secrets.push(credential.secret.clone());
    }
    transport(&mut fetch, private);
    if let Some(pin) = pin {
        fetch.arg("-c").arg(format!("http.curloptResolve={pin}"));
    }
    fetch.args(["fetch", "-q", "--no-tags"]);
    fetch.args(extra);
    fetch.args(["--", remote, sha]);
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
    drop(askpass);
    fetched.map(|_| ())
}

pub(crate) fn transport(cmd: &mut Command, private: Option<&Private>) {
    match private {
        Some(private) => private.configure(cmd),
        None => {
            cmd.args([
                "-c",
                "http.followRedirects=false",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "protocol.file.allow=always",
            ]);
        }
    }
}

pub(crate) fn valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/")
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
        && !name.contains("..")
        && !name.ends_with('/')
}

fn fetch_head(work: &Path, deadline: Instant, secrets: &[String]) -> Result<String> {
    let mut peel = git(work);
    peel.args(["rev-parse", "--verify", "FETCH_HEAD^{commit}"]);
    let output = step(peel, deadline, "git rev-parse", secrets)?;
    let commit = trim(&output.stdout);
    if !valid_sha(&commit) {
        return Err(Error::Preparation(
            "the fetched revision is not a commit".into(),
        ));
    }
    Ok(commit)
}

fn read_path(
    work: &Path,
    commit: &str,
    path: &str,
    max_bytes: usize,
    deadline: Instant,
    secrets: &[String],
) -> Result<Vec<u8>> {
    let mut size = git(work);
    size.args(["cat-file", "-s", &format!("{commit}:{path}")]);
    let output = match step(size, deadline, "git cat-file", secrets) {
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
    Ok(output.stdout)
}

pub fn checkout(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    timeout: Duration,
) -> Result<Checkout> {
    checkout_inner(workspace, source, credential, None, timeout)
}

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
    let pre_started = Instant::now();
    init(workspace, deadline)?;
    let private = access.map(|a| Private::install(workspace, a)).transpose()?;
    let pre_ns = elapsed_ns(pre_started);

    let fetch_started = Instant::now();
    // Judged before Git connects: a failure must not reveal the worker's own network to the client.
    let manual = access.is_none() && source.repo.starts_with("https://");
    let pin = if access.is_none() {
        destination::pin(&source.repo, deadline)?
    } else {
        None
    };
    match fetch(
        workspace,
        &source.repo,
        &source.sha,
        private.as_ref(),
        credential,
        pin.as_deref(),
        deadline,
    ) {
        Err(Error::Preparation(_)) if manual => {
            return Err(Error::Preparation(destination::UNREACHABLE.into()));
        }
        fetched => fetched?,
    }
    drop(private);
    let fetch_ns = elapsed_ns(fetch_started);

    let post_started = Instant::now();
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
    Ok(Checkout {
        sha,
        fetch_ns,
        materialize_ns: pre_ns.saturating_add(elapsed_ns(post_started)),
    })
}

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
    let filtered = partial_origin(work, remote, deadline).is_ok()
        && fetch_with(
            work,
            PARTIAL_REMOTE,
            sha,
            private.as_ref(),
            None,
            None,
            &["--depth", "1", "--filter=blob:none"],
            deadline,
        )
        .is_ok();
    if !filtered {
        fetch(work, remote, sha, private.as_ref(), None, None, deadline)?;
    }
    let commit = fetch_head(work, deadline, &secrets)?;
    if filtered
        && let Some(blob) = path_blob(work, &commit, path, deadline, &secrets)?
        && !object_present(work, &blob, deadline)
        && fetch_with(
            work,
            PARTIAL_REMOTE,
            &blob,
            private.as_ref(),
            None,
            None,
            &["--filter=blob:none"],
            deadline,
        )
        .is_err()
    {
        fetch(work, remote, sha, private.as_ref(), None, None, deadline)?;
    }
    drop(private);
    let bytes = read_path(work, &commit, path, max_bytes, deadline, &secrets)?;
    Ok(FetchedFile { commit, bytes })
}

const PARTIAL_REMOTE: &str = "origin";

fn partial_origin(work: &Path, remote: &str, deadline: Instant) -> Result<()> {
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    for (key, value) in [
        ("core.repositoryformatversion", "1"),
        ("extensions.partialclone", PARTIAL_REMOTE),
        ("remote.origin.url", remote),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
    ] {
        let mut config = git(work);
        config.args(["config", "--", key, value]);
        step(config, deadline, "git config", &[])?;
    }
    Ok(())
}

fn path_blob(
    work: &Path,
    commit: &str,
    path: &str,
    deadline: Instant,
    secrets: &[String],
) -> Result<Option<String>> {
    let mut tree = git(work);
    tree.args(["ls-tree", "-z", commit, "--", path]);
    let output = step(tree, deadline, "git ls-tree", secrets)?;
    // `<mode> SP <type> SP <oid> TAB <path> NUL`
    let entry = String::from_utf8_lossy(&output.stdout);
    let mut fields = entry
        .split('\t')
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace();
    Ok(match (fields.next(), fields.next(), fields.next()) {
        (Some(_), Some("blob"), Some(oid)) if valid_sha(oid) => Some(oid.to_owned()),
        _ => None,
    })
}

fn object_present(work: &Path, oid: &str, deadline: Instant) -> bool {
    let mut exists = git(work);
    // GIT_NO_LAZY_FETCH: a partial clone would otherwise fetch the missing object just to answer.
    exists.env("GIT_NO_LAZY_FETCH", "1");
    exists.args(["cat-file", "-e", oid]);
    step(exists, deadline, "git cat-file", &[]).is_ok()
}

pub fn file_at_merge(
    work: &Path,
    remote: &str,
    access: Option<&Access>,
    merge: Merge<'_>,
    path: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<FetchedFile> {
    let Merge {
        r#ref: merge_ref,
        head,
    } = merge;
    if !valid_ref_name(merge_ref) || !valid_sha(head) {
        return Err(Error::Preparation("merge revision is not usable".into()));
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
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut fetch = git(work);
    transport(&mut fetch, private.as_ref());
    fetch.args([
        "fetch",
        "-q",
        "--no-tags",
        "--depth",
        "1",
        "--",
        remote,
        merge_ref,
    ]);
    let output = run(fetch, deadline, "git fetch")?;
    if !output.success() {
        let mut excerpt = output.stderr_excerpt();
        for secret in &secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        if merge_ref_missing(&excerpt) {
            return Err(Error::Merge);
        }
        return Err(Error::Preparation(format!("git fetch failed: {excerpt}")));
    }
    drop(private);
    let commit = fetch_head(work, deadline, &secrets)?;

    // A merge computed for an earlier head would test the wrong change.
    let mut object = git(work);
    object.args(["cat-file", "-p", &commit]);
    let output = run_capped(object, deadline, "git cat-file", Some(64 * 1024))?;
    if !output.success() {
        return Err(Error::Preparation("git cat-file failed".into()));
    }
    let parents = output.stdout.split(|&b| b == b'\n').filter(|line| {
        line.strip_prefix(b"parent ")
            .is_some_and(|sha| sha == head.as_bytes())
    });
    if parents.count() == 0 {
        return Err(Error::Merge);
    }

    let bytes = read_path(work, &commit, path, max_bytes, deadline, &secrets)?;
    Ok(FetchedFile { commit, bytes })
}

fn merge_ref_missing(excerpt: &str) -> bool {
    excerpt.contains("couldn't find remote ref")
}

/// `false` means not proven, not absent: a vanished tip answers `false`, an unreachable remote errors.
pub fn is_ancestor(
    work: &Path,
    remote: &str,
    access: Option<&Access>,
    ancestor: &str,
    tip: &str,
    depth: u32,
    timeout: Duration,
) -> Result<bool> {
    if !valid_sha(ancestor) || !valid_sha(tip) || depth == 0 {
        return Err(Error::Preparation("ancestry request is not usable".into()));
    }
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    if let Some(access) = access
        && (!access.validate(UnixMillis::now().0) || access.binding.remote != remote)
    {
        return Err(Error::Preparation("source access refused".into()));
    }
    if ancestor == tip {
        return Ok(true);
    }
    let deadline = Instant::now() + timeout;
    init(work, deadline)?;
    let private = access.map(|a| Private::install(work, a)).transpose()?;
    let secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    let mut name = git(work);
    name.args(["config", "--local", "remote.origin.url", remote]);
    step(name, deadline, "git config", &secrets)?;
    let mut fetch = git(work);
    transport(&mut fetch, private.as_ref());
    let depth_arg = depth.to_string();
    fetch.args([
        "fetch",
        "-q",
        "--no-tags",
        "--filter=tree:0",
        "--depth",
        &depth_arg,
        "origin",
        tip,
    ]);
    let output = run(fetch, deadline, "git fetch")?;
    drop(private);
    if !output.success() {
        let mut excerpt = output.stderr_excerpt();
        for secret in &secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        if excerpt.contains("not our ref") || excerpt.contains("couldn't find remote ref") {
            return Ok(false);
        }
        return Err(Error::Preparation(format!("git fetch failed: {excerpt}")));
    }
    let limit = (depth as usize).saturating_mul(8).min(1 << 16);
    let mut walk = git(work);
    walk.env("GIT_NO_LAZY_FETCH", "1").args([
        "rev-list",
        &format!("--max-count={limit}"),
        tip,
        "--",
    ]);
    let output = run_capped(walk, deadline, "git rev-list", Some(limit * 66))?;
    if !output.success() {
        return Err(Error::Preparation("git rev-list failed".into()));
    }
    Ok(output
        .stdout
        .split(|&b| b == b'\n')
        .any(|line| line == ancestor.as_bytes()))
}

pub fn ls_remote(
    dir: &Path,
    remote: &str,
    access: Option<&Access>,
    max_refs: usize,
    timeout: Duration,
) -> Result<Vec<crate::RefTip>> {
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    if let Some(access) = access
        && (!access.validate(UnixMillis::now().0) || access.binding.remote != remote)
    {
        return Err(Error::Preparation("source access refused".into()));
    }
    fs::create_dir_all(dir)?;
    let deadline = Instant::now() + timeout;
    let private = access.map(|a| Private::install(dir, a)).transpose()?;
    let secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    let mut cmd = git(dir);
    transport(&mut cmd, private.as_ref());
    cmd.args(["ls-remote", "--heads", "--tags", "--", remote]);
    let cap = max_refs.min(65_536).saturating_mul(1_200);
    let output = run_capped(cmd, deadline, "git ls-remote", Some(cap))?;
    drop(private);
    if !output.success() {
        let mut excerpt = output.stderr_excerpt();
        for secret in &secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        return Err(Error::Preparation(format!(
            "git ls-remote failed: {excerpt}"
        )));
    }
    parse_tips(&output.stdout, max_refs)
}

fn parse_tips(out: &[u8], max_refs: usize) -> Result<Vec<crate::RefTip>> {
    let mut tips: Vec<crate::RefTip> = Vec::new();
    let mut peeled: Vec<crate::RefTip> = Vec::new();
    for line in out.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return Err(Error::Preparation("unexpected ls-remote output".into()));
        };
        let Some((oid, name)) = line.split_once('\t') else {
            return Err(Error::Preparation("unexpected ls-remote output".into()));
        };
        if !valid_sha(oid) {
            return Err(Error::Preparation("unexpected ls-remote output".into()));
        }
        let tip = if let Some(base) = name.strip_suffix("^{}") {
            crate::RefTip {
                name: base.to_owned(),
                oid: oid.to_owned(),
                peeled: Some(oid.to_owned()),
            }
        } else {
            crate::RefTip {
                name: name.to_owned(),
                oid: oid.to_owned(),
                peeled: None,
            }
        };
        if !advertised(&tip.name) {
            return Err(Error::Preparation("unexpected ls-remote output".into()));
        }
        if tip.peeled.is_some() {
            peeled.push(tip);
        } else {
            tips.push(tip);
        }
    }
    if tips.len() > max_refs {
        return Err(Error::TooLarge("git ls-remote"));
    }
    for peel in peeled {
        if let Some(tip) = tips.iter_mut().find(|t| t.name == peel.name) {
            tip.peeled = peel.peeled;
        }
    }
    Ok(tips)
}

fn advertised(name: &str) -> bool {
    name.starts_with("refs/")
        && name.len() <= 1024
        && !name.contains("..")
        && !name.bytes().any(|b| !(0x21..=0x7e).contains(&b))
}

pub(crate) struct Private {
    dir: PathBuf,
    ssh: bool,
    ca: bool,
    username: Option<String>,
    secret: Option<String>,
}

impl Private {
    pub(crate) fn install(work: &Path, access: &Access) -> Result<Self> {
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

    pub(crate) fn secrets(&self) -> Vec<String> {
        self.secret.iter().cloned().collect()
    }

    pub(crate) fn configure(&self, cmd: &mut Command) {
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

pub(crate) struct Askpass {
    pub(crate) path: PathBuf,
    pub(crate) username: String,
    pub(crate) secret: String,
}

impl Askpass {
    pub(crate) fn install(workspace: &Path, credential: &Credential) -> Result<Askpass> {
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

#[cfg(test)]
mod tests {
    use super::merge_ref_missing;

    #[test]
    fn a_committed_gitconfig_cannot_configure_git() {
        let work = tempfile::tempdir().unwrap();
        std::fs::write(
            work.path().join(".gitconfig"),
            "[user]\n\tname = planted\n[core]\n\tfsmonitor = false\n",
        )
        .unwrap();
        let cmd = super::git(work.path());
        let home = cmd
            .get_envs()
            .find(|(k, _)| *k == "HOME")
            .and_then(|(_, v)| v)
            .unwrap()
            .to_owned();
        assert!(!std::path::Path::new(&home).exists());
        assert!(!std::path::Path::new(&home).starts_with(work.path()));
        let mut read = super::git(work.path());
        read.args(["config", "--global", "--list"]);
        let out = super::run(
            read,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            "git config",
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("planted"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_childs_exit_wakes_a_parked_wait() {
        use std::{
            process::Command,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            thread,
            time::{Duration, Instant},
        };
        let mut child = Command::new("sleep").arg("600").spawn().unwrap();
        let watch = super::ExitWatch::of(&child);
        assert!(watch.wakes_on_exit(), "this kernel has pidfds");
        let woke = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&woke);
        let parked = thread::spawn(move || {
            watch.park(Duration::from_secs(60));
            flag.store(true, Ordering::Release);
        });
        thread::sleep(Duration::from_millis(200));
        assert!(
            !woke.load(Ordering::Acquire),
            "the wait returned while the child was alive"
        );
        let killed = Instant::now();
        child.kill().unwrap();
        parked.join().unwrap();
        assert!(woke.load(Ordering::Acquire));
        assert!(
            killed.elapsed() < Duration::from_secs(30),
            "held to the park bound"
        );
        child.wait().unwrap();
    }

    #[test]
    fn only_a_missing_ref_is_a_pending_merge() {
        assert!(merge_ref_missing(
            "fatal: couldn't find remote ref refs/pull/7/merge"
        ));
        for excerpt in [
            "fatal: repository 'https://github.com/o/r.git/' not found",
            "remote: Repository not found.",
            "fatal: Authentication failed for 'https://github.com/o/r.git/'",
            "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host",
        ] {
            assert!(!merge_ref_missing(excerpt), "{excerpt}");
        }
    }
}
