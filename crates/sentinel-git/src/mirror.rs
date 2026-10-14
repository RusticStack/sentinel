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
    unix::{
        Askpass, Private, elapsed_ns, git, init, step, transport, trim, valid_ref_name, valid_sha,
    },
};

pub const MIRRORS_DIR: &str = "mirrors";
pub const LOCK_WAIT: Duration = Duration::from_secs(120);
pub const LEASE_TTL: Duration = Duration::from_secs(20 * 60);
pub const GC_MAX_PACKS: usize = 16;
pub const GC_MAX_LOOSE: usize = 4096;
const MAX_OBJECT_FILES: u64 = 2_000_000;
const COPY_MAX_BYTES: u64 = 48 << 20;
const WAIT_POLL: Duration = Duration::from_millis(25);
const REMOTE_FILE: &str = "sentinel-remote";
pub const MIRRORS_BUDGET_BYTES: u64 = 50 << 30;
pub const MIRROR_IDLE: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const STALE_TMP: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug)]
pub struct Mirrors {
    root: PathBuf,
    reflink: bool,
    gc_max_packs: usize,
    gc_max_loose: usize,
    copy_max: u64,
}

struct Lease(PathBuf);

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

enum Auth<'a> {
    Manual(Option<&'a Credential>),
    Bound(&'a Access),
}

struct Ctx<'a> {
    private: Option<&'a Private>,
    credential: Option<&'a Credential>,
    secrets: &'a [String],
    deadline: Instant,
}

impl Mirrors {
    pub fn open(root: &Path) -> Result<Mirrors> {
        Self::open_tuned(root, GC_MAX_PACKS, GC_MAX_LOOSE)
    }

    pub fn open_tuned(root: &Path, gc_max_packs: usize, gc_max_loose: usize) -> Result<Mirrors> {
        fs::create_dir_all(root)?;
        let reflink = reflink_supported(root)?;
        Ok(Mirrors {
            root: root.to_path_buf(),
            reflink,
            gc_max_packs,
            gc_max_loose,
            copy_max: COPY_MAX_BYTES,
        })
    }

    #[doc(hidden)]
    pub fn fetch_materialization(mut self) -> Mirrors {
        self.reflink = false;
        self.copy_max = 0;
        self
    }

    pub fn reflink(&self) -> bool {
        self.reflink
    }

    pub fn path(&self, repo: &RepoId) -> PathBuf {
        self.root.join(repo.to_string())
    }

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
        let event_ref = source.ref_name.as_deref().filter(|r| match access {
            Some(access) => access.binding.allows(r),
            None => valid_ref_name(r),
        });
        let deadline = Instant::now() + timeout;
        let dir = self.path(repo);
        let leases = self.root.join(format!("{repo}.leases"));
        let suspect = self.root.join(format!("{repo}.suspect"));

        let lock_deadline = Instant::now() + LOCK_WAIT.min(timeout);
        let lock = Self::lock(&self.root.join(format!("{repo}.lock")), lock_deadline)?;
        let fetch_started = Instant::now();
        self.ensure(&dir, &suspect, &leases, &source.repo, deadline)?;
        let private = access.map(|a| Private::install(&dir, a)).transpose()?;
        let mut secrets = private.as_ref().map(|p| p.secrets()).unwrap_or_default();
        if let Some(credential) = credential
            && !credential.secret.is_empty()
        {
            secrets.push(credential.secret.clone());
        }
        let ctx = Ctx {
            private: private.as_ref(),
            credential,
            secrets: &secrets,
            deadline,
        };
        let commit = self.fetch_and_verify(&dir, source, event_ref, &ctx, &suspect, &leases)?;
        drop(private);
        let mut pin = git(&dir);
        pin.args(["update-ref", "refs/sentinel/pin", &commit]);
        step(pin, deadline, "git update-ref", &secrets).map_err(|e| match e {
            Error::Preparation(what) => Error::Mirror(what),
            other => other,
        })?;
        let store_bytes = self.gc_if_due(&dir, &leases, deadline)?;
        let lease = self.lease(&leases, lease_name, deadline)?;
        let fetch_ns = elapsed_ns(fetch_started);
        drop(lock);

        let materialize_started = Instant::now();
        let materialized = self.materialize(&dir, workspace, &commit, store_bytes, deadline);
        drop(lease);
        match materialized {
            Ok(()) => Ok(Checkout {
                sha: commit,
                fetch_ns,
                materialize_ns: elapsed_ns(materialize_started),
            }),
            Err(e) => {
                // Only store damage earns a rebuild; a deadline or full workspace would refetch all history for nothing.
                let damaged = !matches!(e, Error::Timeout(_) | Error::TooLarge(_))
                    && !self.healthy(&dir, Instant::now() + Duration::from_secs(30));
                let e = if damaged {
                    match fs::write(&suspect, b"materialization failed\n") {
                        Ok(()) => e,
                        Err(mark) => Error::Mirror(format!(
                            "{e}; the store could not be marked for a rebuild: {}",
                            mark.kind()
                        )),
                    }
                } else {
                    e
                };
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

    fn lock(path: &Path, deadline: Instant) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Do not truncate: a waiter must not wipe the incumbent's provenance before it holds the lock.
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

    fn looks_bare(dir: &Path) -> bool {
        dir.join("HEAD").is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir()
    }

    fn healthy(&self, dir: &Path, deadline: Instant) -> bool {
        let mut probe = git(dir);
        probe.args(["rev-parse", "--is-bare-repository"]);
        let bare = match step(probe, deadline, "git rev-parse", &[]) {
            Ok(output) => trim(&output.stdout) == "true",
            Err(_) => false,
        };
        let mut tips = git(dir);
        tips.args(["rev-list", "--no-walk", "--all", "--quiet"]);
        bare && step(tips, deadline, "git rev-list", &[]).is_ok()
    }

    fn ensure(
        &self,
        dir: &Path,
        suspect: &Path,
        leases: &Path,
        remote: &str,
        deadline: Instant,
    ) -> Result<()> {
        // A mirror serves only the remote that filled it: other remotes start from an empty store.
        let recorded = fs::read_to_string(dir.join(REMOTE_FILE)).ok();
        if suspect.exists() || !Self::looks_bare(dir) || recorded.as_deref() != Some(remote) {
            self.rebuild(dir, suspect, leases, deadline)?;
            fs::write(dir.join(REMOTE_FILE), remote)?;
        }
        let _ = fs::remove_dir_all(dir.with_extension("askpass"));
        Ok(())
    }

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
            // Narrower wants help only when the server refused a want; auth or network failures would repeat.
            Err(e) if !want_refused(&e) => return Err(e),
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

    fn fetch(&self, dir: &Path, remote: &str, wants: &[String], ctx: &Ctx<'_>) -> Result<()> {
        let mut fetch = git(dir);
        transport(&mut fetch, ctx.private);
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

    fn gc_if_due(&self, dir: &Path, leases: &Path, deadline: Instant) -> Result<u64> {
        let objects = dir.join("objects");
        let (packs, loose, bytes) = Self::object_stats(&objects)?;
        if packs <= self.gc_max_packs && loose <= self.gc_max_loose as u64 {
            return Ok(bytes);
        }
        if Self::leases_live(leases)? {
            return Ok(bytes);
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
        Ok(Self::object_stats(&objects)?.2)
    }

    fn object_stats(objects: &Path) -> Result<(usize, u64, u64)> {
        let mut packs = 0usize;
        let mut loose = 0u64;
        let mut bytes = 0u64;
        let pack_dir = objects.join("pack");
        if let Ok(entries) = fs::read_dir(&pack_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.as_bytes().ends_with(b".pack") || name.as_bytes().starts_with(b"tmp_") {
                    packs += 1;
                }
                if let Ok(meta) = entry.metadata() {
                    bytes = bytes.saturating_add(meta.len());
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
                    if inner.file_type().is_ok_and(|t| t.is_file()) {
                        loose += 1;
                        if bytes <= COPY_MAX_BYTES
                            && let Ok(meta) = inner.metadata()
                        {
                            bytes = bytes.saturating_add(meta.len());
                        }
                    }
                }
            }
        }
        Ok((packs, loose, bytes))
    }

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
            if entry.file_name().as_bytes().starts_with(b".") {
                let _ = fs::remove_file(&path);
                continue;
            }
            let declared = fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok());
            match declared {
                Some(expiry) if now_ms >= expiry => {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                Some(_) => {
                    live = true;
                    continue;
                }
                None => {}
            }
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

    fn lease(&self, leases: &Path, name: &str, deadline: Instant) -> Result<Lease> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(Error::Preparation("lease name is not usable".into()));
        }
        fs::create_dir_all(leases)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let expiry = UnixMillis::now().0 + (remaining + LEASE_MARGIN).as_millis() as i64;
        let tmp = leases.join(format!(".{name}.tmp"));
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?
            .write_all(format!("{expiry}\n").as_bytes())?;
        let path = leases.join(name);
        fs::rename(&tmp, &path)?;
        Ok(Lease(path))
    }

    fn materialize(
        &self,
        mirror: &Path,
        workspace: &Path,
        commit: &str,
        store_bytes: u64,
        deadline: Instant,
    ) -> Result<()> {
        init(workspace, deadline)?;
        if self.reflink || store_bytes <= self.copy_max {
            let mut files = 0u64;
            Self::copy_objects(
                &mirror.join("objects"),
                &workspace.join(".git/objects"),
                self.reflink,
                &mut files,
                deadline,
            )?;
        } else {
            Self::fetch_pinned(mirror, workspace, commit, deadline)?;
        }
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

    fn fetch_pinned(
        mirror: &Path,
        workspace: &Path,
        commit: &str,
        deadline: Instant,
    ) -> Result<()> {
        let Some(from) = mirror.to_str() else {
            return Err(Error::Mirror("mirror path is not UTF-8".into()));
        };
        let mut fetch = git(workspace);
        fetch.args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "protocol.version=2",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=0",
            "fetch",
            "-q",
            "--no-tags",
            "--no-write-fetch-head",
            "--depth",
            "1",
            "--",
            from,
            commit,
        ]);
        step(fetch, deadline, "git fetch (mirror)", &[])?;
        Ok(())
    }

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

    fn copy_file(src: &Path, dst: &Path, reflink: bool) -> Result<()> {
        if reflink && Self::reflink_file(src, dst).is_ok() {
            return Ok(());
        }
        fs::copy(src, dst)?;
        Ok(())
    }

    fn reflink_file(src: &Path, dst: &Path) -> std::io::Result<()> {
        let from = File::open(src)?;
        let mode = from.metadata()?.mode();
        let to = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)?;
        if let Err(error) = ficlone(&to, &from) {
            let _ = fs::remove_file(dst);
            return Err(error);
        }
        fs::set_permissions(dst, fs::Permissions::from_mode(mode & 0o7777))?;
        Ok(())
    }
}

fn want_refused(error: &Error) -> bool {
    let Error::Preparation(text) = error else {
        return false;
    };
    let text = text.to_ascii_lowercase();
    [
        "not our ref",
        "unadvertised object",
        "no such remote ref",
        "couldn't find remote ref",
        "not a valid object",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MirrorSweep {
    pub mirrors: u64,
    pub bytes: u64,
    pub removed: u64,
    pub tmp_removed: u64,
    pub bytes_freed: u64,
}

impl Mirrors {
    pub fn sweep(&self, budget_bytes: u64) -> MirrorSweep {
        let mut out = MirrorSweep::default();
        let Ok(entries) = fs::read_dir(&self.root) else {
            return out;
        };
        let now = std::time::SystemTime::now();
        let mut kept: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().is_ok_and(|t| t.is_dir()) || !Self::looks_bare(&path) {
                continue;
            }
            out.mirrors += 1;
            let Some(guard) = self.try_lock(&path) else {
                continue;
            };
            let used = guard.metadata().and_then(|m| m.modified()).unwrap_or(now);
            let leases = path.with_extension("leases");
            let idle = now.duration_since(used).is_ok_and(|age| age > MIRROR_IDLE);
            if idle && !Self::leases_live(&leases).unwrap_or(true) {
                let bytes = tree_bytes(&path);
                if fs::remove_dir_all(&path).is_ok() {
                    out.removed += 1;
                    out.bytes_freed += bytes;
                }
                continue;
            }
            out.tmp_removed += remove_stale_tmp(&path.join("objects"), now);
            kept.push((used, tree_bytes(&path), path));
        }
        let mut total: u64 = kept.iter().map(|(_, bytes, _)| bytes).sum();
        kept.sort_by_key(|(used, _, _)| *used);
        for (_, bytes, path) in kept {
            if total <= budget_bytes {
                break;
            }
            let Some(_guard) = self.try_lock(&path) else {
                continue;
            };
            if Self::leases_live(&path.with_extension("leases")).unwrap_or(true) {
                continue;
            }
            if fs::remove_dir_all(&path).is_ok() {
                out.removed += 1;
                out.bytes_freed += bytes;
                total -= bytes;
            }
        }
        out.bytes = total;
        out
    }

    fn try_lock(&self, mirror: &Path) -> Option<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(mirror.with_extension("lock"))
            .ok()?;
        // SAFETY: flock on our own open fd; released when `file` closes.
        (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)
            .then_some(file)
    }
}

fn tree_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(entry.path()),
                Ok(t) if t.is_file() => {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    total
}

fn remove_stale_tmp(objects: &Path, now: std::time::SystemTime) -> u64 {
    let mut removed = 0;
    let mut stack = vec![objects.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(entry.path());
            } else if entry.file_name().as_bytes().starts_with(b"tmp_")
                && entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| now.duration_since(t).ok())
                    .is_some_and(|age| age > STALE_TMP)
                && fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

fn ficlone(to: &File, from: &File) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a plain ioctl between two files the caller holds open;
        // FICLONE takes the source descriptor as its argument.
        if unsafe { libc::ioctl(to.as_raw_fd(), libc::FICLONE, from.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (to, from);
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

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
    let mut from = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&src)?;
    from.write_all(b"sentinel")?;
    from.sync_data()?;
    let to = OpenOptions::new().write(true).create_new(true).open(&dst)?;
    if ficlone(&to, &from).is_err() {
        return Ok(false);
    }
    Ok(to.metadata().map(|m| m.len() == 8).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reflink_probe_agrees_with_a_real_clone() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::write(&src, b"sentinel").unwrap();
        let real = Mirrors::reflink_file(&src, &dir.path().join("dst")).is_ok();
        assert_eq!(reflink_supported(dir.path()).unwrap(), real);
    }

    #[test]
    fn only_a_refused_want_is_retried_narrower() {
        for refused in [
            "git fetch: fatal: remote error: upload-pack: not our ref 0123",
            "git fetch: error: Server does not allow request for unadvertised object 0123",
            "git fetch: fatal: couldn't find remote ref refs/heads/gone",
        ] {
            assert!(
                want_refused(&Error::Preparation(refused.into())),
                "{refused}"
            );
        }
        for final_answer in [
            "git fetch: fatal: Authentication failed for 'https://forge.example/r.git/'",
            "git fetch: fatal: unable to access: Could not resolve host",
        ] {
            assert!(!want_refused(&Error::Preparation(final_answer.into())));
        }
        assert!(!want_refused(&Error::Timeout("git fetch")));
        assert!(!want_refused(&Error::Mirror("not our ref".into())));
    }
}
