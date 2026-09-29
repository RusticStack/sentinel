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

use crate::{Error, Merge, Result};

/// A whole checkout — every Git invocation together — must finish in this.
pub const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Longest path [`file_at`] accepts.
pub const MAX_PATH_BYTES: usize = 1024;
/// Bytes of diagnostics kept per stream (payload reads are explicitly capped).
const OUTPUT_TAIL_BYTES: usize = 64 * 1024;
/// Longest a helper wait sleeps before looking at its cancel flag and
/// output caps again. The child's own exit wakes it at once (a pidfd on
/// Linux); only where that is unavailable is this a polling interval.
const CHECK: Duration = Duration::from_millis(50);
/// The fallback polling interval where no pidfd can be opened.
const POLL: Duration = Duration::from_millis(20);

thread_local! {
    /// The cancel flag of the work this thread is doing, if any (see
    /// [`cancel_scope`]).
    static CANCEL: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with every Git helper it starts on this thread tied to `cancel`:
/// once the flag is set, the running helper's whole process group is killed
/// at its next check (at most [`CHECK`] later) and the call fails, instead
/// of a fetch running on to its deadline after the work was cancelled.
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

/// A handle that becomes readable when the child exits, so waiting costs
/// no polling; `None` where the kernel has no pidfd (then [`wait_step`]
/// polls).
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

    /// Whether the child's exit itself wakes a wait (a pidfd), rather than
    /// the next [`POLL`] tick.
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

    /// Block until the child may have exited or `wait` passed.
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

/// Wait for `child` until it exits or `until` passes, returning early —
/// with `None` — at least every [`CHECK`] so the caller can look at its
/// cancel flag and caps. The exit itself wakes the wait at once.
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

/// Monotonic nanoseconds since `started`, saturated at `u64::MAX`.
pub(crate) fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

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

/// What was checked out: the verified revision, with the fetch and the
/// worktree materialization measured separately (monotonic nanoseconds).
#[derive(Debug, PartialEq, Eq)]
pub struct Checkout {
    pub sha: String,
    /// Getting the objects: the remote fetch, or the mirror update.
    pub fetch_ns: u64,
    /// Turning objects into the worktree: init, object copy, checkout and
    /// the final `HEAD` verification.
    pub materialize_ns: u64,
}

/// One file read from one revision; `commit` is the peeled commit the file
/// was read at (a tag object resolves to what it points to).
#[derive(Debug, PartialEq, Eq)]
pub struct FetchedFile {
    pub commit: String,
    pub bytes: Vec<u8>,
}

pub(crate) fn git(dir: &Path) -> Command {
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
    let watch = ExitWatch::of(&child);
    let status = loop {
        if let Some(status) = wait_step(&mut child, &watch, deadline)? {
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
        // Git/SSH servers may reflect a credential in stderr. Take one bounded
        // line and strip anything this fetch installed as a secret.
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

pub(crate) fn init(work: &Path, deadline: Instant) -> Result<()> {
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
    fetch_with(
        work,
        remote,
        sha,
        private,
        credential,
        &["--depth", "1"],
        deadline,
    )
}

/// [`fetch`] with the given extra arguments before `--` (a depth, a
/// partial-clone filter).
fn fetch_with(
    work: &Path,
    remote: &str,
    sha: &str,
    private: Option<&Private>,
    credential: Option<&Credential>,
    extra: &[&str],
    deadline: Instant,
) -> Result<()> {
    if remote.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut fetch = git(work);
    let mut secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
    // A manual credential a server echoes back is redacted like a bound
    // one (P07-25): no error excerpt may carry either.
    if let Some(credential) = credential
        && !credential.secret.is_empty()
    {
        secrets.push(credential.secret.clone());
    }
    transport(&mut fetch, private);
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
    // The credential files go as soon as the fetch returns; the caller owns
    // the `Private` install for the checkout that follows.
    drop(askpass);
    fetched.map(|_| ())
}

/// The transport discipline for one fetch. An authorized fetch gets the
/// binding's pinned trust ([`Private::configure`]). A fetch with no access —
/// the manual mode, whose remote a client named — gets the same refusals
/// minus the credential: no redirects, no credential helper from anywhere,
/// and only `https` or a local path. `ssh` is refused outright there, since
/// OpenSSH would present the worker account's own identity and
/// configuration; `git://`, plain `http://` and remote helpers never run.
/// Local paths stay possible here for worker-local mirrors and tests; the
/// controller refuses them as a client-named manual source.
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

/// A full ref name under `refs/` — the merge ref a forge computes for a pull
/// request. Anything else never reaches Git.
pub(crate) fn valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/")
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
        && !name.contains("..")
        && !name.ends_with('/')
}

/// The commit `FETCH_HEAD` names after a fetch, peeled if it is a tag object.
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

/// Read `path` at `commit` in `work`, probing the size first so an oversized
/// file is refused without being read.
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
    // Materialization is everything except the fetch itself: the init and
    // credential install that precede it, and the detach plus verification
    // that follow. The segments are timed separately, never subtracted.
    let pre_started = Instant::now();
    init(workspace, deadline)?;
    let private = access.map(|a| Private::install(workspace, a)).transpose()?;
    let pre_ns = elapsed_ns(pre_started);

    let fetch_started = Instant::now();
    fetch(
        workspace,
        &source.repo,
        &source.sha,
        private.as_ref(),
        credential,
        deadline,
    )?;
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
    // B04: the commit and its trees only, then the one blob the pipeline
    // is. A depth-one fetch of the whole tree cost 3.6 s and 75 MB on
    // Lockwell for a 1.5 KB file; this costs about 0.3 s and 0.2 MB. The
    // work repository is a partial clone of `remote` (a promisor remote
    // named `origin`: without one, a filtered fetch fails its connectivity
    // check). A server that ignores the filter sends everything and the
    // blob is simply present; anything else that goes wrong on this path
    // gets the whole depth-one fetch, as before.
    let filtered = partial_origin(work, remote, deadline).is_ok()
        && fetch_with(
            work,
            PARTIAL_REMOTE,
            sha,
            private.as_ref(),
            None,
            &["--depth", "1", "--filter=blob:none"],
            deadline,
        )
        .is_ok();
    if !filtered {
        fetch(work, remote, sha, private.as_ref(), None, deadline)?;
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
            &["--filter=blob:none"],
            deadline,
        )
        .is_err()
    {
        fetch(work, remote, sha, private.as_ref(), None, deadline)?;
    }
    drop(private);
    let bytes = read_path(work, &commit, path, max_bytes, deadline, &secrets)?;
    Ok(FetchedFile { commit, bytes })
}

/// The promisor remote a filtered pipeline read fetches through.
const PARTIAL_REMOTE: &str = "origin";

/// Make `work` a partial clone of `remote`: a promisor remote
/// [`PARTIAL_REMOTE`] with a `blob:none` filter. Nothing is fetched here.
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

/// The object id of the blob at `path` in `commit`, from its trees alone;
/// `None` when the path is absent or not a regular file (the read that
/// follows then says `Missing`).
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

/// Whether the object store holds `oid` locally, without a lazy fetch.
fn object_present(work: &Path, oid: &str, deadline: Instant) -> bool {
    let mut exists = git(work);
    // A partial clone would fetch a missing object to answer; the question
    // is only whether it is here.
    exists.env("GIT_NO_LAZY_FETCH", "1");
    exists.args(["cat-file", "-e", oid]);
    step(exists, deadline, "git cat-file", &[]).is_ok()
}

/// Fetch `merge_ref` — the tested-merge ref a forge computes for a pull
/// request — from `remote` into `work` (which must be empty), require the
/// commit it names to list `head` among its parents, and read `path` at it.
/// A payload's claimed merge can be stale: only a merge commit that actually
/// names the delivered head is truthful to test. `Error::Merge` means the ref
/// is absent or still names a merge for another head — the forge may simply
/// not have recomputed it yet.
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

    // The merge must name the delivered head among its parents; a merge
    // computed for an earlier head would test the wrong change.
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

/// Whether a failed merge-ref fetch means the ref is absent — the forge has
/// not computed the merge (yet), which is retryable. Every other failure is
/// the remote itself: in particular a repository that is gone, renamed or
/// inaccessible (`repository '…' not found`) is not a merge still pending.
fn merge_ref_missing(excerpt: &str) -> bool {
    excerpt.contains("couldn't find remote ref")
}

/// Whether `ancestor` is in the history of `tip` on `remote`, looking at most
/// `depth` generations back from `tip` — the intake resolver's test for "the
/// repository already moved past this commit". Only commits are fetched
/// (`--filter=tree:0`, where the server supports it; otherwise the depth
/// alone bounds the transfer), into `work`, which must be empty; nothing is
/// ever fetched lazily afterwards.
///
/// The answer is conservative: `false` means "not proven", including an
/// ancestor older than the window and a `tip` the remote no longer has
/// (force-pushed away). A remote that cannot be reached is an error.
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
    // A filtered fetch records its remote as a promisor, which needs a name:
    // a bare URL or path is not one. The scratch repository gets `origin`
    // (no refspec, so only the wanted commit is fetched).
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
        // The remote no longer has the tip: nothing can be proven about it.
        if excerpt.contains("not our ref") || excerpt.contains("couldn't find remote ref") {
            return Ok(false);
        }
        return Err(Error::Preparation(format!("git fetch failed: {excerpt}")));
    }
    // Walk only what was fetched: the shallow boundary ends the walk, and
    // lazy fetching is disabled so a missing object is never requested.
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

/// Advertise `remote`'s heads and tags without fetching anything — the ref
/// poller's whole view of a remote. `dir` is scratch only: credential
/// helpers live next to it for the duration of the one command, and Git's
/// own configuration is ignored as everywhere else. Output and the ref
/// count are both capped; an annotated tag arrives as its object id with the
/// peeled commit recorded on the same tip.
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
    // `--heads --tags` keeps the advertisement to the refs a binding can
    // name; `--` keeps the remote itself unambiguous as an argument.
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

/// `oid<TAB>ref` lines, with `<ref>^{}` lines folding onto their base ref.
/// Anything that is not that shape is not an ls-remote answer.
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

/// An advertised ref name: under `refs/`, printable and bounded. Selection
/// is the caller's; this only rejects lines that are not refs at all.
fn advertised(name: &str) -> bool {
    name.starts_with("refs/")
        && name.len() <= 1024
        && !name.contains("..")
        && !name.bytes().any(|b| !(0x21..=0x7e).contains(&b))
}

/// Fetch-only files are siblings of the work directory, never mounted in a
/// job. Mode is set at creation, including on every partial-failure path.
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

/// The legacy askpass helper: an owner-only script beside the workspace that
/// answers Git's username/password prompts from its own environment and is
/// removed as soon as the fetch has finished.
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

    /// A helper's exit wakes its wait at once, with no poll tick: parked
    /// for a minute, the wait does not return while the child lives (a
    /// polling wait would be back within one 20 ms tick) and returns once
    /// it exits. Decided by the child's exit, not by timing, so machine
    /// load cannot fail it (the paired-timing test it replaces swung by
    /// ±2.9 s under load).
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
        // What Git prints when the forge has not computed the merge ref.
        assert!(merge_ref_missing(
            "fatal: couldn't find remote ref refs/pull/7/merge"
        ));
        // A repository that is gone, renamed or inaccessible is the remote's
        // answer, not a merge still pending.
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
