//! Worker-local Git object mirrors (K04).
//!
//! One bare mirror per repository id lives at `<data_dir>/mirrors/<repo-id>/`.
//! Attempts share it under three rules:
//!
//! - **Serialized writes.** A `flock(LOCK_EX)` on the sibling
//!   `<repo-id>.lock` serializes every writer (init/fetch/verify/gc). The
//!   lock is kernel-held on an open file: a dead owner releases it, so there
//!   is no stale-lock state to take over; a bounded non-blocking poll is the
//!   whole wait. The lock file's contents (owner pid and the wait deadline)
//!   are provenance for an operator, never part of the protocol.
//! - **Reader leases.** Materialization copies the object store while a
//!   writer may be appending to it; Git never removes objects outside `gc`,
//!   and `gc` runs only under the write lock with no live lease in
//!   `<repo-id>.leases/`. A lease is a file named by the attempt holding an
//!   expiry timestamp, published by rename; an expired or stale lease file
//!   is swept, so a crashed attempt can hold GC off for at most its TTL.
//! - **Private objects.** The worktree gets its own object files: a
//!   reflink (`FICLONE`, copy-on-write extents) when the data directory's
//!   filesystem supports it — probed once at [`Mirrors::open`] — else a
//!   plain copy. Nothing in the job's `.git` shares an inode with the
//!   mirror, so a job cannot rewrite shared objects, and no `alternates`
//!   file ever points outside the workspace.
//!
//! Fetches are incremental and full-history: the pinned commit itself plus
//! the event ref the binding allows (`+ref:refs/sentinel/event`), so a later
//! attempt negotiates against real history instead of re-cloning. The pinned
//! SHA is verified as a commit after the fetch — an absent or non-commit
//! revision is a preparation failure naming the SHA, never a fallback.
//! `gc.auto` and `maintenance.auto` are disabled per invocation: pruning
//! only ever happens through the lease-checked path here.
//!
//! Mirror failures split two ways: [`Error::Mirror`] (and [`Error::Io`])
//! mean the *infrastructure* could not serve — the caller may fall back to a
//! direct checkout; [`Error::Preparation`] names the remote's answer or the
//! missing pinned revision and never falls back.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{RepoId, UnixMillis};
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::Access;

use crate::{
    Checkout, Credential, Error, Result,
    unix::{Askpass, Private, elapsed_ns, git, init, step, trim, valid_ref_name, valid_sha},
};

/// The directory under the worker's data directory holding every mirror.
pub const MIRRORS_DIR: &str = "mirrors";
/// Longest wait for a mirror's writer lock before the caller falls back to
/// a direct checkout. Fetches are incremental, so a healthy lock moves fast;
/// a writer doing a first full fetch may legitimately hold it for a while.
pub const LOCK_WAIT: Duration = Duration::from_secs(120);
/// A reader lease is trusted for at most this long; a crashed attempt's
/// lease stops blocking GC once this TTL passes.
pub const LEASE_TTL: Duration = Duration::from_secs(20 * 60);
/// Default GC trigger: more than this many pack files in the mirror.
pub const GC_MAX_PACKS: usize = 16;
/// Default GC trigger: more than this many loose objects in the mirror.
pub const GC_MAX_LOOSE: usize = 4096;
/// A materialization copying more files than this is not copying a mirror.
const MAX_OBJECT_FILES: u64 = 2_000_000;
/// Poll interval for the lock and for lease drains.
const WAIT_POLL: Duration = Duration::from_millis(25);

/// Handle over `<data_dir>/mirrors`, created once per worker process: the
/// reflink capability of the filesystem is probed here, not per attempt.
#[derive(Clone, Debug)]
pub struct Mirrors {
    root: PathBuf,
    reflink: bool,
    gc_max_packs: usize,
    gc_max_loose: usize,
}

/// A reader lease: a file under `<repo-id>.leases/` named by the attempt,
/// holding its expiry in unix milliseconds. Published by rename so a sweeper
/// never reads a torn record; removed on drop.
struct Lease(PathBuf);

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// How a mirror fetch is authorized: a bound source access, or a manual
/// run's plain credential. Exactly one applies per checkout.
enum Auth<'a> {
    Manual(Option<&'a Credential>),
    Bound(&'a Access),
}

/// The context every mirror fetch shares: the bound credential install and
/// the manual credential (at most one applies), the stderr redaction list
/// and the deadline.
struct Ctx<'a> {
    private: Option<&'a Private>,
    credential: Option<&'a Credential>,
    secrets: &'a [String],
    deadline: Instant,
}

impl Mirrors {
    /// Open (creating) the mirrors root and probe reflink support once.
    /// Failure is an `Error::Io`: the caller decides whether the process
    /// runs checkouts directly instead.
    pub fn open(root: &Path) -> Result<Mirrors> {
        Self::open_tuned(root, GC_MAX_PACKS, GC_MAX_LOOSE)
    }

    /// `open` with a lowered GC trigger, so conformance tests can reach the
    /// GC path deterministically.
    pub fn open_tuned(root: &Path, gc_max_packs: usize, gc_max_loose: usize) -> Result<Mirrors> {
        fs::create_dir_all(root)?;
        let reflink = reflink_supported(root)?;
        Ok(Mirrors {
            root: root.to_path_buf(),
            reflink,
            gc_max_packs,
            gc_max_loose,
        })
    }

    /// Whether the filesystem holding `root` performed the reflink probe.
    pub fn reflink(&self) -> bool {
        self.reflink
    }

    /// The mirror's path for `repo` — stable across attempts.
    pub fn path(&self, repo: &RepoId) -> PathBuf {
        self.root.join(repo.to_string())
    }

    /// Mirrored checkout without a source access (manual mode): fetch the
    /// pinned commit from `source.repo`, verify it, materialize privately.
    pub fn checkout(
        &self,
        workspace: &Path,
        repo: &RepoId,
        source: &PinnedSource,
        credential: Option<&Credential>,
        lease: &str,
        timeout: Duration,
    ) -> Result<Checkout> {
        self.inner(
            workspace,
            repo,
            source,
            Auth::Manual(credential),
            lease,
            timeout,
        )
    }

    /// Mirrored checkout under a source access: expiry, exact remote and
    /// the allowed ref are rechecked before Git runs, exactly like
    /// [`crate::checkout_authorized`].
    pub fn checkout_authorized(
        &self,
        workspace: &Path,
        repo: &RepoId,
        source: &PinnedSource,
        access: &Access,
        lease: &str,
        timeout: Duration,
    ) -> Result<Checkout> {
        self.inner(workspace, repo, source, Auth::Bound(access), lease, timeout)
    }

    fn inner(
        &self,
        workspace: &Path,
        repo: &RepoId,
        source: &PinnedSource,
        auth: Auth<'_>,
        lease_name: &str,
        timeout: Duration,
    ) -> Result<Checkout> {
        let (access, credential) = match auth {
            Auth::Bound(access) => (Some(access), None),
            Auth::Manual(credential) => (None, credential),
        };
        if let Some(access) = access
            && (!access.validate(UnixMillis::now().0)
                || source.repo != access.binding.remote
                || source
                    .ref_name
                    .as_ref()
                    .is_some_and(|r| !access.binding.allows(r)))
        {
            return Err(Error::Preparation("source access refused".into()));
        }
        if source.repo.starts_with('-') {
            return Err(Error::Preparation("repository looks like an option".into()));
        }
        if !valid_sha(&source.sha) {
            return Err(Error::Preparation(
                "pinned revision is not a full object id".into(),
            ));
        }
        // The event ref enriches the mirror's history when the access names
        // one the binding allows (a bound run) or the run recorded a real
        // ref (manual mode); the pinned SHA is always the authority.
        let event_ref = source.ref_name.as_deref().filter(|r| match access {
            Some(access) => access.binding.allows(r),
            None => valid_ref_name(r),
        });
        let deadline = Instant::now() + timeout;
        let dir = self.path(repo);
        let leases = self.root.join(format!("{repo}.leases"));
        let suspect = self.root.join(format!("{repo}.suspect"));

        // The writer phase, serialized on the flock'd lock file. The `File`
        // itself is the lock: the kernel releases it on close or death, so
        // there is no stale-lock state to take over.
        let lock_deadline = Instant::now() + LOCK_WAIT.min(timeout);
        let lock = Self::lock(&self.root.join(format!("{repo}.lock")), lock_deadline)?;
        let fetch_started = Instant::now();
        self.ensure(&dir, &suspect, &leases, deadline)?;
        let private = access.map(|a| Private::install(&dir, a)).transpose()?;
        let secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
        let ctx = Ctx {
            private: private.as_ref(),
            credential,
            secrets: &secrets,
            deadline,
        };
        let commit = self.fetch_and_verify(&dir, source, event_ref, &ctx, &suspect, &leases)?;
        drop(private);
        // Pin the verified commit so a lease-checked GC can never prune the
        // objects this attempt is about to copy. A store that cannot take a
        // ref is the mirror's fault, so it reports as such.
        let mut pin = git(&dir);
        pin.args(["update-ref", "refs/sentinel/pin", &commit]);
        step(pin, deadline, "git update-ref", &secrets).map_err(|e| match e {
            Error::Preparation(what) => Error::Mirror(what),
            other => other,
        })?;
        self.gc_if_due(&dir, &leases, deadline)?;
        // The reader lease is created while still holding the write lock:
        // a GC that follows can never miss it.
        let lease = self.lease(&leases, lease_name)?;
        let fetch_ns = elapsed_ns(fetch_started);
        drop(lock);

        // The reader phase: a private object store in the workspace.
        let materialize_started = Instant::now();
        let materialized = self.materialize(&dir, workspace, &commit, deadline);
        drop(lease);
        match materialized {
            Ok(()) => Ok(Checkout {
                sha: commit,
                fetch_ns,
                materialize_ns: elapsed_ns(materialize_started),
            }),
            Err(e) => {
                // The copied store verified nothing: mark the mirror so the
                // next writer rebuilds it rather than serving it again.
                let _ = fs::write(&suspect, b"materialization failed\n");
                Err(match e {
                    Error::Mirror(_) | Error::Timeout(_) => e,
                    Error::Preparation(what) => Error::Mirror(what),
                    Error::TooLarge(what) => {
                        Error::Mirror(format!("{what} during materialization"))
                    }
                    other => Error::Mirror(format!("materialization: {other}")),
                })
            }
        }
    }

    /// Acquire the writer lock, polling `flock(LOCK_NB)` until `deadline`.
    /// The file records owner and deadline for an operator's eyes only.
    fn lock(path: &Path, deadline: Instant) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // The incumbent's provenance is only rewritten by whoever next
            // holds the lock — a waiter must not wipe it.
            .truncate(false)
            .open(path)?;
        let fd = file.as_raw_fd();
        loop {
            // SAFETY: flock on our own open fd; the kernel releases it on
            // close or process death, so there is nothing stale to take over.
            if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Err(Error::Mirror("writer lock wait exceeded its bound".into()));
            }
            thread::sleep(WAIT_POLL);
        }
        let _ = file.set_len(0);
        let _ = writeln!(
            &file,
            "pid={} until_ms={}",
            std::process::id(),
            UnixMillis::now().0
                + deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as i64
        );
        Ok(file)
    }

    /// Does the mirror look like a bare repository — without asking Git?
    fn looks_bare(dir: &Path) -> bool {
        dir.join("HEAD").is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir()
    }

    /// Whether Git itself accepts the store; costs one process, run only
    /// when a fetch or verify has already failed.
    fn healthy(&self, dir: &Path, deadline: Instant) -> bool {
        let mut probe = git(dir);
        probe.args(["rev-parse", "--is-bare-repository"]);
        match step(probe, deadline, "git rev-parse", &[]) {
            Ok(output) => trim(&output.stdout) == "true",
            Err(_) => false,
        }
    }

    /// Bring the mirror up: a missing or damaged store is rebuilt (after
    /// any live readers drain, bounded by `deadline`); a `suspect` mark from
    /// a failed materialization forces the same. Also drops a credential
    /// helper directory a crashed fetch may have left behind.
    fn ensure(&self, dir: &Path, suspect: &Path, leases: &Path, deadline: Instant) -> Result<()> {
        if suspect.exists() || !Self::looks_bare(dir) {
            self.rebuild(dir, suspect, leases, deadline)?;
        }
        let _ = fs::remove_dir_all(dir.with_extension("askpass"));
        Ok(())
    }

    /// Rebuild the mirror from scratch. Readers copying the old store would
    /// see it vanish mid-copy, so live leases are drained first, bounded.
    fn rebuild(&self, dir: &Path, suspect: &Path, leases: &Path, deadline: Instant) -> Result<()> {
        while Self::leases_live(leases)? {
            if Instant::now() >= deadline {
                return Err(Error::Mirror(
                    "mirror rebuild waited on readers past its deadline".into(),
                ));
            }
            thread::sleep(WAIT_POLL);
        }
        match fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        fs::create_dir(dir)?;
        let mut init = git(dir);
        init.args(["init", "-q", "--bare", "--initial-branch=main", "."]);
        step(init, deadline, "git init", &[]).map_err(|e| match e {
            Error::Preparation(what) => Error::Mirror(what),
            other => other,
        })?;
        let _ = fs::remove_file(suspect);
        Ok(())
    }

    /// Fetch, then require the pinned commit to verify. A failure splits by
    /// cause: a store Git itself rejects is rebuilt once and the whole round
    /// retried; a failure on a sound store is the remote's answer and
    /// propagates; an absent pinned commit is a preparation failure naming
    /// the SHA, never a fallback to another revision.
    fn fetch_and_verify(
        &self,
        dir: &Path,
        source: &PinnedSource,
        event_ref: Option<&str>,
        ctx: &Ctx<'_>,
        suspect: &Path,
        leases: &Path,
    ) -> Result<String> {
        for pass in 0..2u8 {
            let outcome = self.fetch_wants(dir, source, event_ref, ctx);
            match outcome {
                Ok(commit) => return Ok(commit),
                // Deadlines and IO are neither the remote's answer nor store
                // damage — they propagate unchanged.
                Err(e @ (Error::Timeout(_) | Error::Io(_))) => return Err(e),
                Err(e) => {
                    if self.healthy(dir, ctx.deadline) {
                        return Err(e);
                    }
                    if pass == 1 {
                        return Err(Error::Mirror(format!(
                            "mirror unusable after a rebuild: {e}"
                        )));
                    }
                    self.rebuild(dir, suspect, leases, ctx.deadline)?;
                }
            }
        }
        unreachable!("the loop returns on its second pass at the latest")
    }

    /// One round of wants, tried in the order that fails cheapest: the
    /// pinned commit and the event ref together (the common case, one round
    /// trip), then each alone — the commit may be reachable from the ref
    /// even when the server refuses a SHA it never advertised, and the ref
    /// may simply have been deleted. Any fetch that runs is followed by the
    /// same verify; the last failure propagates.
    fn fetch_wants(
        &self,
        dir: &Path,
        source: &PinnedSource,
        event_ref: Option<&str>,
        ctx: &Ctx<'_>,
    ) -> Result<String> {
        let mut wants = vec![source.sha.clone()];
        if let Some(r) = event_ref {
            wants.push(format!("+{r}:refs/sentinel/event"));
        }
        match self.fetch(dir, &source.repo, &wants, ctx) {
            Ok(()) => return self.verify(dir, &source.sha, ctx.deadline),
            Err(e) if event_ref.is_none() => return Err(e),
            Err(_) => {}
        }
        if let Some(r) = event_ref
            && self
                .fetch(
                    dir,
                    &source.repo,
                    &[format!("+{r}:refs/sentinel/event")],
                    ctx,
                )
                .is_ok()
            && let Ok(commit) = self.verify(dir, &source.sha, ctx.deadline)
        {
            return Ok(commit);
        }
        self.fetch(dir, &source.repo, std::slice::from_ref(&source.sha), ctx)?;
        self.verify(dir, &source.sha, ctx.deadline)
    }

    /// One incremental fetch of `wants` — refspecs after `--`. `gc.auto`
    /// and `maintenance.auto` are off: pruning is this module's own
    /// decision, taken under the lock with no live readers. Credential files
    /// are the same askpass/GIT_SSH discipline as the direct checkout,
    /// installed beside the mirror for this fetch only.
    fn fetch(&self, dir: &Path, remote: &str, wants: &[String], ctx: &Ctx<'_>) -> Result<()> {
        let mut fetch = git(dir);
        if let Some(private) = ctx.private {
            private.configure(&mut fetch);
        }
        fetch.args(["-c", "gc.auto=0", "-c", "maintenance.auto=0"]);
        fetch.args(["fetch", "-q", "--no-tags", "--", remote]);
        fetch.args(wants);
        let askpass = match ctx.credential {
            Some(credential) => Some(Askpass::install(dir, credential)?),
            None => None,
        };
        if let Some(askpass) = &askpass {
            fetch
                .env("GIT_ASKPASS", &askpass.path)
                .env("SENTINEL_GIT_USERNAME", &askpass.username)
                .env("SENTINEL_GIT_SECRET", &askpass.secret);
        }
        let output = step(fetch, ctx.deadline, "git fetch", ctx.secrets);
        drop(askpass);
        output.map(|_| ())
    }

    /// The pinned revision must verify as a commit after the fetch — a
    /// missing or non-commit object is a preparation failure naming the
    /// SHA, never a fallback to another revision.
    fn verify(&self, dir: &Path, sha: &str, deadline: Instant) -> Result<String> {
        let mut verify = git(dir);
        verify.args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{sha}^{{commit}}"),
        ]);
        let output = step(verify, deadline, "git rev-parse", &[]).map_err(|e| match e {
            Error::Preparation(_) => Error::Preparation(format!(
                "pinned revision {sha} is not a commit in the mirror"
            )),
            other => other,
        })?;
        let commit = trim(&output.stdout);
        if commit != sha {
            return Err(Error::Preparation(format!(
                "pinned revision {sha} verified as {commit}, not itself"
            )));
        }
        Ok(commit)
    }

    /// GC only when the store actually crossed a trigger, and only with no
    /// live readers: expired leases are swept first, a live one skips this
    /// round — a later fetch retries.
    fn gc_if_due(&self, dir: &Path, leases: &Path, deadline: Instant) -> Result<()> {
        let (packs, loose) = Self::object_stats(&dir.join("objects"))?;
        if packs <= self.gc_max_packs && loose <= self.gc_max_loose as u64 {
            return Ok(());
        }
        if Self::leases_live(leases)? {
            return Ok(());
        }
        let mut gc = git(dir);
        gc.args([
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=0",
            "gc",
            "--prune=now",
            "--quiet",
        ]);
        step(gc, deadline, "git gc", &[]).map_err(|e| match e {
            Error::Preparation(what) => Error::Mirror(what),
            other => other,
        })?;
        Ok(())
    }

    /// `(pack files, loose objects)` in the mirror's object store; transient
    /// `tmp_*` names are not counted.
    fn object_stats(objects: &Path) -> Result<(usize, u64)> {
        let mut packs = 0usize;
        let mut loose = 0u64;
        let pack_dir = objects.join("pack");
        if let Ok(entries) = fs::read_dir(&pack_dir) {
            for entry in entries.flatten() {
                if entry.file_name().as_bytes().ends_with(b".pack") {
                    packs += 1;
                }
            }
        }
        for entry in fs::read_dir(objects)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.len() == 2
                && name.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
                && entry.file_type().is_ok_and(|t| t.is_dir())
            {
                for inner in fs::read_dir(entry.path())?.flatten() {
                    if inner.file_type().is_ok_and(|t| t.is_file())
                        && !inner.file_name().as_bytes().starts_with(b"tmp_")
                    {
                        loose += 1;
                    }
                }
            }
        }
        Ok((packs, loose))
    }

    /// Are readers holding leases? Expired and stale records are swept as a
    /// side effect — a crashed attempt can hold GC off for at most its TTL.
    fn leases_live(leases: &Path) -> Result<bool> {
        let entries = match fs::read_dir(leases) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let now_ms = UnixMillis::now().0;
        let mut live = false;
        for entry in entries.flatten() {
            let path = entry.path();
            let expired = fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok())
                .is_some_and(|expiry| now_ms >= expiry);
            if expired {
                let _ = fs::remove_file(&path);
                continue;
            }
            // Unparseable content means a lease mid-publish or a stale
            // record: trust its age — older than a lease can live is stale,
            // younger is conservatively a live reader.
            let stale = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > LEASE_TTL);
            if stale {
                let _ = fs::remove_file(&path);
            } else {
                live = true;
            }
        }
        Ok(live)
    }

    /// Publish a reader lease for `name` (the attempt id): expiry timestamp
    /// inside, written to a temp file then renamed so a sweeper never reads
    /// a torn record. Runs under the write lock.
    fn lease(&self, leases: &Path, name: &str) -> Result<Lease> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(Error::Preparation("lease name is not usable".into()));
        }
        fs::create_dir_all(leases)?;
        let expiry = UnixMillis::now().0 + LEASE_TTL.as_millis() as i64;
        let tmp = leases.join(format!(".{name}.tmp"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?
            .write_all(format!("{expiry}\n").as_bytes())?;
        let path = leases.join(name);
        fs::rename(&tmp, &path)?;
        Ok(Lease(path))
    }

    /// Populate `workspace` (empty) with `commit` out of the mirror: a
    /// private object store — reflink when the filesystem proved capable,
    /// a byte copy otherwise — then `checkout --detach` and a final HEAD
    /// verification.
    fn materialize(
        &self,
        mirror: &Path,
        workspace: &Path,
        commit: &str,
        deadline: Instant,
    ) -> Result<()> {
        init(workspace, deadline)?;
        let mut files = 0u64;
        Self::copy_objects(
            &mirror.join("objects"),
            &workspace.join(".git/objects"),
            self.reflink,
            &mut files,
            deadline,
        )?;
        let mut checkout = git(workspace);
        checkout.args([
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=0",
            "checkout",
            "-q",
            "-f",
            "--detach",
            commit,
        ]);
        step(checkout, deadline, "git checkout", &[])?;
        let mut head = git(workspace);
        head.args(["rev-parse", "HEAD"]);
        let output = step(head, deadline, "git rev-parse", &[])?;
        if trim(&output.stdout) != commit {
            return Err(Error::Preparation(
                "materialized workspace is not the pinned revision".into(),
            ));
        }
        Ok(())
    }

    /// Copy the mirror's object store file by file, reflink or bytes. Git's
    /// own in-flight names (`tmp_*`) and anything that is not a regular
    /// file or directory are never copied; `info/alternates` is never
    /// copied either — the workspace's object store must stand alone.
    fn copy_objects(
        src: &Path,
        dst: &Path,
        reflink: bool,
        files: &mut u64,
        deadline: Instant,
    ) -> Result<()> {
        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((from, to)) = stack.pop() {
            for entry in fs::read_dir(&from)? {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout("mirror materialization"));
                }
                let entry = entry?;
                let name = entry.file_name();
                if name.as_bytes().starts_with(b"tmp_") {
                    continue;
                }
                let ftype = entry.file_type()?;
                let target = to.join(&name);
                if ftype.is_dir() {
                    match fs::create_dir(&target) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                    stack.push((entry.path(), target));
                } else if ftype.is_file() {
                    // No alternates may reach the job: it would point at the
                    // mirror's store the job must not mutate.
                    if name == OsStr::new("alternates")
                        && from.file_name() == Some(OsStr::new("info"))
                    {
                        continue;
                    }
                    Self::copy_file(&entry.path(), &target, reflink)?;
                    *files += 1;
                    if *files > MAX_OBJECT_FILES {
                        return Err(Error::TooLarge("mirror object store"));
                    }
                }
            }
        }
        Ok(())
    }

    /// One object file: reflink when supported — copy-on-write extents keep
    /// the job's store private without the copy's cost — else `fs::copy`,
    /// which reflinks transparently on filesystems that support it anyway.
    /// A reflink failure falls back to the byte copy.
    fn copy_file(src: &Path, dst: &Path, reflink: bool) -> Result<()> {
        if reflink && Self::reflink_file(src, dst).is_ok() {
            return Ok(());
        }
        fs::copy(src, dst)?;
        Ok(())
    }

    /// `FICLONE` `src` onto `dst`: shared extents, separate inode — writing
    /// through the workspace copy can never alter the mirror's bytes.
    fn reflink_file(src: &Path, dst: &Path) -> std::io::Result<()> {
        let from = File::open(src)?;
        let mode = from.metadata()?.mode();
        let to = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)?;
        // SAFETY: a plain ioctl between two files this process just opened;
        // FICLONE takes the source descriptor as its argument.
        if unsafe { libc::ioctl(to.as_raw_fd(), libc::FICLONE, from.as_raw_fd()) } != 0 {
            let error = std::io::Error::last_os_error();
            let _ = fs::remove_file(dst);
            return Err(error);
        }
        fs::set_permissions(dst, fs::Permissions::from_mode(mode & 0o7777))?;
        Ok(())
    }
}

/// Does `root`'s filesystem support `FICLONE`? One real clone of a probe
/// pair — created, exercised and removed here — settles it for the process.
fn reflink_supported(root: &Path) -> Result<bool> {
    let src = root.join(".reflink-probe-src");
    let dst = root.join(".reflink-probe-dst");
    let _ = fs::remove_file(&src);
    let _ = fs::remove_file(&dst);
    struct Clean<'a>(&'a Path, &'a Path);
    impl Drop for Clean<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0);
            let _ = fs::remove_file(self.1);
        }
    }
    let _clean = Clean(&src, &dst);
    let mut from = OpenOptions::new().write(true).create_new(true).open(&src)?;
    from.write_all(b"sentinel")?;
    from.sync_data()?;
    let to = OpenOptions::new().write(true).create_new(true).open(&dst)?;
    // SAFETY: a plain ioctl between two files this process just opened;
    // FICLONE takes the source descriptor as its argument.
    if unsafe { libc::ioctl(to.as_raw_fd(), libc::FICLONE, from.as_raw_fd()) } != 0 {
        return Ok(false);
    }
    Ok(to.metadata().map(|m| m.len() == 8).unwrap_or(false))
}
