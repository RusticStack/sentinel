//! One attempt from offer to terminal: prepare (workspace, checkout, image,
//! container), run the steps in order, finalize (tear everything down), and
//! report each phase under the attempt's fence with a measured summary.
//!
//! Step semantics are the run spec's: `/bin/sh -e -c` or `bash -eo
//! pipefail -c`, job environment then step environment then the worker's
//! own context, working directory under the workspace, per-step timeout
//! bounded by what is left of the job's. A step's `if` is evaluated in the
//! worker phase against the job context and the checkout; false skips the
//! step, anything else than a boolean fails preparation. Steps after a
//! failed one never start.
//!
//! The verdict keeps the plan's distinctions: exit 0 passes; any other
//! status is `CommandFailed`; death by signal `CommandSignaled`, unless the
//! cgroup's OOM counter moved, which is `OutOfMemory`; a step past its
//! budget `ExecutionTimeout`; a runtime that could not run the step
//! `Runtime`; anything that stops the steps from starting `Preparation`; a
//! cancel seen between steps `Canceled`. Every phase is timed monotonically
//! and the summary travels with the terminal report.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, FailureClass, Fence, WorkerId};
use sentinel_link::session::JobContext;
use sentinel_pipeline::{RunSpec, expr::EvalError};
use sentinel_protocol::{
    logs::Stream,
    negotiate::Arch,
    summary::{AttemptSummary, CacheRecord, MAX_CACHE_RECORDS, StepOutcome, StepRecord},
};

use crate::{
    Error, Result, artifacts,
    checkout::{self, CHECKOUT_TIMEOUT},
    context::WorkerContext,
    images::Images,
    podman::{self, Container, DEFAULT_PIDS_LIMIT, Limits},
    recovery,
    workspace::Workspace,
};

/// What the attempt is: identity, fence, the spec, which job of it, and
/// the controller's context for its expressions.
/// Test builds only: a step with this id panics the attempt thread just
/// before it would run (P04-30).
#[cfg(test)]
pub(crate) const PANIC_STEP: &str = "panic-injected";

pub struct Job {
    pub worker: WorkerId,
    pub attempt: AttemptId,
    pub fence: Fence,
    pub job_index: usize,
    /// `sha256:…`, as the controller resolved it; the name is the spec's.
    pub digest: String,
    pub spec: RunSpec,
    pub context: JobContext,
    /// Controller-authorized values bound to the acknowledged attempt's
    /// fence. The protocol wrapper wipes each owned value on drop.
    pub secret_bundle: sentinel_protocol::secrets::DeliveryBundle,
    /// The worker's image pulls: concurrent attempts share one download
    /// per `name@sha256:…`.
    pub images: Images,
    /// The job's declared caches as restored for this attempt: filled by
    /// preparation (K02), read back by finalization (K03). The carrier is
    /// `sentinel_cache::Attached` — each entry holds its scope, rendered
    /// key, the outcome that produced the view and the private writable
    /// directory the container saw.
    pub caches: Vec<sentinel_cache::attach::Attached>,
    /// The worker's shared object mirrors, when the process could open them;
    /// `None` runs every checkout direct.
    pub mirrors: Option<checkout::Mirrors>,
    /// A pause between starting the checkout and pulling the image, so a
    /// cancel that arrives during preparation can be exercised
    /// deterministically. Zero in production.
    pub prepare_hold: std::time::Duration,
}

/// Where a step's file targets appear in its container.
pub const SECRET_FILES_MOUNT: &str = "/run/sentinel-secrets";
/// Where a step's environment targets appear in its container, as a shell
/// file its wrapper sources (P10D-8).
pub const SECRET_ENV_MOUNT: &str = "/run/sentinel-env";

/// Where delivered secrets are staged: under the worker's runtime
/// directory — a tmpfs when `$XDG_RUNTIME_DIR` is usable (P10D-8) — never
/// the workspace, caches or artifact roots.
pub fn secret_root(root: &Path) -> PathBuf {
    crate::runtime_dir(root).join("secret-delivery")
}

/// The store an attempt's image and container live in (P10D-5): the
/// tenant's private store when the job pulls with `registry_auth`, the
/// shared one otherwise. Deterministic, so the executor's teardown paths
/// name the same store preparation used.
pub fn store_for(root: &Path, job: &Job) -> Result<podman::Store> {
    let private = job.secret_bundle.targets.iter().any(|target| {
        matches!(
            target.target,
            sentinel_protocol::secrets::TargetKind::RegistryAuth
        )
    });
    if !private {
        return Ok(podman::Store::Shared);
    }
    // Registry auth only travels on protocol 10, whose context always
    // names the tenant; without one there is no store to scope it to.
    let tenant = job
        .context
        .tenant
        .ok_or_else(|| Error::Preparation("registry auth without a tenant".into()))?;
    podman::Store::private(root, *tenant.as_bytes())
}

/// Protected scratch for one attempt. It is outside the checkout so
/// artifacts and cache publication never traverse secret material. The
/// attempt directory is owner-only on the host; the two directories below
/// it are mounted read-only into the attempt's container alone and are
/// world-readable inside so an image that runs as a non-root user can read
/// its targets (P10D-4).
struct SecretDirectory {
    attempt_dir: PathBuf,
    files_dir: PathBuf,
    env_dir: PathBuf,
}

impl SecretDirectory {
    fn create(root: &Path, attempt: AttemptId) -> Result<Self> {
        let base = secret_root(root);
        if let Some(runtime) = base.parent() {
            create_private_dir(runtime, true)?;
        }
        create_private_dir(&base, true)?;
        let attempt_dir = base.join(attempt.to_string());
        create_private_dir(&attempt_dir, false)?;
        let files_dir = attempt_dir.join("files");
        let env_dir = attempt_dir.join("env");
        let result = (|| {
            create_mounted_dir(&files_dir)?;
            create_mounted_dir(&env_dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&attempt_dir);
            return Err(error);
        }
        Ok(Self {
            attempt_dir,
            files_dir,
            env_dir,
        })
    }

    fn write_registry_auth(&self, value: &[u8]) -> Result<PathBuf> {
        let path = self.attempt_dir.join("registry-auth.json");
        let mut file = create_secret_file(&path)?;
        file.write_all(value)?;
        Ok(path)
    }
}

impl Drop for SecretDirectory {
    fn drop(&mut self) {
        wipe_file(&self.attempt_dir.join("registry-auth.json"));
        let _ = fs::remove_dir_all(&self.attempt_dir);
    }
}

/// Per-step paths are removed and overwritten before another step starts,
/// including error, timeout, cancellation, and unwind paths.
struct StepSecrets {
    env_file: Option<PathBuf>,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl Drop for StepSecrets {
    fn drop(&mut self) {
        if let Some(path) = &self.env_file {
            wipe_file(path);
            let _ = fs::remove_file(path);
        }
        for path in &self.files {
            wipe_file(path);
            let _ = fs::remove_file(path);
        }
        for dir in self.directories.iter().rev() {
            let _ = fs::remove_dir(dir);
        }
    }
}

fn create_private_dir(path: &Path, allow_existing: bool) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if allow_existing && error.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(Error::Preparation("secret directory".into()));
            }
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A directory under a secret mount: readable and traversable by any
/// container user (the mount is read-only and private to the attempt; the
/// owner-only attempt directory above it is the host boundary).
fn create_mounted_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// A host-only secret file (the registry auth file): owner-only.
fn create_secret_file(path: &Path) -> Result<std::fs::File> {
    create_file_mode(path, 0o600)
}

/// A file under a secret mount: readable by the image's user, whoever that
/// is (P10D-4).
fn create_mounted_file(path: &Path) -> Result<std::fs::File> {
    create_file_mode(path, 0o644)
}

fn create_file_mode(path: &Path, mode: u32) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let file = options.open(path)?;
    // The umask may have narrowed it; the mode is part of the contract.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(file)
}

/// Write `value` as one `export NAME='value'` line for the step's wrapper
/// shell to source. Env values are UTF-8 without NUL, CR or LF (checked on
/// arrival); inside single quotes only `'` itself needs care.
fn write_export(file: &mut std::fs::File, name: &str, value: &[u8]) -> Result<()> {
    let mut line = Vec::with_capacity(name.len() + value.len() + 12);
    line.extend_from_slice(b"export ");
    line.extend_from_slice(name.as_bytes());
    line.extend_from_slice(b"='");
    for &byte in value {
        if byte == b'\'' {
            line.extend_from_slice(b"'\\''");
        } else {
            line.push(byte);
        }
    }
    line.extend_from_slice(b"'\n");
    let written = file.write_all(&line);
    line.fill(0);
    written?;
    Ok(())
}

/// The step's argv behind a `/bin/sh` wrapper that exports its secret
/// environment from the private mount and then `exec`s it: the values
/// never pass through Podman, which would copy them into the exec
/// session's spec on disk (P10D-8), nor through any argv.
fn wrap_with_env(argv: Vec<String>, step: usize) -> Vec<String> {
    let mut wrapped = Vec::with_capacity(argv.len() + 4);
    wrapped.push("/bin/sh".to_owned());
    wrapped.push("-c".to_owned());
    wrapped.push(format!(
        ". {SECRET_ENV_MOUNT}/step-{step}.sh && exec \"$@\""
    ));
    wrapped.push("sentinel-step".to_owned());
    wrapped.extend(argv);
    wrapped
}

fn wipe_file(path: &Path) {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = OpenOptions::new().write(true).open(path) else {
        return;
    };
    let Ok(length) = file.metadata().map(|meta| meta.len()) else {
        return;
    };
    let zeros = [0u8; 8192];
    let mut left = length;
    while left > 0 {
        let n = usize::try_from(left.min(zeros.len() as u64)).unwrap_or(zeros.len());
        if file.write_all(&zeros[..n]).is_err() {
            break;
        }
        left -= n as u64;
    }
    let _ = file.seek(SeekFrom::Start(0));
}

fn materialize_step_secrets(
    directory: &SecretDirectory,
    bundle: &sentinel_protocol::secrets::DeliveryBundle,
    step: usize,
) -> Result<StepSecrets> {
    use sentinel_protocol::secrets::TargetKind;
    let mut cleanup = StepSecrets {
        env_file: None,
        files: Vec::new(),
        directories: Vec::new(),
    };
    let mut has_env = false;
    for target in &bundle.targets {
        if target.step as usize == step && matches!(target.target, TargetKind::Environment) {
            has_env = true;
            break;
        }
    }
    let env_path = has_env.then(|| directory.env_dir.join(format!("step-{step}.sh")));
    if let Some(path) = &env_path {
        cleanup.env_file = Some(path.clone());
    }
    let mut env_file = match &env_path {
        Some(path) => Some(create_mounted_file(path)?),
        None => None,
    };
    for target in &bundle.targets {
        if target.step as usize != step {
            continue;
        }
        let value = bundle
            .values
            .get(target.value as usize)
            .ok_or_else(|| Error::Preparation("secret target index".into()))?
            .expose();
        match &target.target {
            TargetKind::Environment => {
                let file = env_file
                    .as_mut()
                    .ok_or_else(|| Error::Preparation("secret env file".into()))?;
                write_export(file, &target.name, value)?;
            }
            TargetKind::File { path } => {
                let path = directory.files_dir.join(path);
                let parent = path
                    .parent()
                    .ok_or_else(|| Error::Preparation("secret file path".into()))?;
                let mut current = directory.files_dir.clone();
                let relative_parent = parent
                    .strip_prefix(&directory.files_dir)
                    .map_err(|_| Error::Preparation("secret file path".into()))?;
                for component in relative_parent.components() {
                    current.push(component);
                    match fs::create_dir(&current) {
                        Ok(()) => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                fs::set_permissions(&current, fs::Permissions::from_mode(0o755))?;
                            }
                            cleanup.directories.push(current.clone());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            let meta = fs::symlink_metadata(&current)?;
                            if !meta.is_dir() || meta.file_type().is_symlink() {
                                return Err(Error::Preparation("secret file parent".into()));
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                cleanup.files.push(path.clone());
                create_mounted_file(&path)?.write_all(value)?;
            }
            TargetKind::RegistryAuth => continue,
        }
    }
    Ok(cleanup)
}

/// Where the phases are reported. Ordered per attempt; the link's reporter
/// or a test's recorder.
pub trait Report: Send + Sync {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event);
    /// The terminal event with the encoded summary.
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>);
    /// A cache publication's outcome from finalization — diagnostics only,
    /// never the verdict. The default drops it.
    fn cache_note(&self, _attempt: AttemptId, _note: CacheNote) {}
    /// A nominal hit's restore tripped the costly-hit rule (K08,
    /// docs/cache.md) — diagnostics only, never the verdict. `stats` is
    /// the measured evidence. The default drops it.
    fn costly_hit(
        &self,
        _attempt: AttemptId,
        _name: &str,
        _costly: sentinel_cache::Costly,
        _stats: &sentinel_cache::Stats,
    ) {
    }
    /// The session's remote-cache transport (Q08), when the link offers
    /// one: a local miss may hydrate through it and a sealed generation
    /// may be offered back. `None` — the default — leaves both off.
    fn remote(&self) -> Option<Arc<dyn sentinel_cache::remote::Remote>> {
        None
    }
}

/// One cache's publication outcome, reported once per attempted entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheNote {
    /// The declared cache's name.
    pub name: String,
    pub outcome: CacheOutcome,
}

/// What publication did with one attached cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheOutcome {
    /// A new generation was sealed and is now `current`.
    Sealed {
        generation: String,
        bytes: u64,
        /// Of `bytes`, how much was staged from the source generation.
        reused_bytes: u64,
    },
    /// Nothing committed; the publish module's stable reason.
    Skipped(&'static str),
    /// The commit failed; bounded detail, never the job's failure.
    Failed(String),
}

/// Where step output goes (W05): the executor's spool and link. Writes are
/// called from the reader threads with small chunks and must be quick;
/// `complete` runs after the last step and blocks, bounded, until the log
/// is acknowledged and closed, returning whether that happened.
pub trait Output: Send + Sync {
    fn write(&self, step: u32, stream: Stream, bytes: &[u8]);
    fn complete(&self) -> bool;
    /// Step `step` finished: output it held back (a possible secret prefix)
    /// is released as that step's. The default holds nothing.
    fn step_done(&self, _step: u32) {}
    /// `text` with the attempt's registered values redacted: every
    /// diagnostic that leaves the attempt (the verdict detail, the stored
    /// summary, the process log) passes through here. The default redacts
    /// nothing.
    fn redact(&self, text: String) -> String {
        text
    }
    /// The bounded excerpt of a failed step's stderr tail for its verdict
    /// detail, redacted before it is decoded, cut to a line and shortened
    /// (P10D-2). The default redacts nothing.
    fn excerpt(&self, stderr: &[u8]) -> String {
        crate::redact::excerpt(stderr)
    }
}

/// An output that discards everything, for callers without a log.
pub struct NoOutput;
impl Output for NoOutput {
    fn write(&self, _: u32, _: Stream, _: &[u8]) {}
    fn complete(&self) -> bool {
        true
    }
}

/// The attempt's verdict as reported, with the bounded reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Passed,
    Failed(FailureClass, String),
}

/// The per-attempt cancel flag the executor flips on `stop`.
pub type Cancel = Arc<AtomicBool>;

fn ns(started: Instant) -> Option<u64> {
    Some(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
}

/// Run the whole attempt. Returns the verdict and the summary that were
/// reported. `sink` publishes declared artifacts during finalization, while
/// the workspace still exists. `job` is mutable because preparation fills
/// `job.caches` — the restored-cache carrier finalization reads (K02/K03).
pub fn run(
    root: &Path,
    job: &mut Job,
    report: &dyn Report,
    output: Arc<dyn Output>,
    sink: &dyn artifacts::Sink,
    cancel: &Cancel,
) -> (Verdict, AttemptSummary) {
    report.event(job.attempt, job.fence, Event::PreparationStarted);
    // Q08: the session's remote transport, when it has one. Resolved once
    // per attempt: hydration during preparation, offers after the
    // verdict both go through it.
    let remote = report.remote();
    let mut summary = AttemptSummary::default();
    let prepared = prepare(root, job, cancel, &mut summary, remote.as_deref());
    // K08: a nominal hit that paid rebuild-scale restore cost is a
    // diagnostic on the attempt, never its verdict — flagged once per
    // entry now that preparation has filled `job.caches`.
    for attached in &job.caches {
        if let Some(costly) = attached.costly_hit() {
            report.costly_hit(job.attempt, &attached.name, costly, &attached.stats);
        }
    }
    let mut sealed: Vec<SealedCache> = Vec::new();
    let verdict = match prepared {
        // A cancel that lands while preparing is a cancel, whatever step of
        // the preparation it interrupted. The log — empty or not — is closed
        // on this path too, so nothing waits in the spool for steps that
        // never ran.
        Err(_) if cancel.load(Ordering::Acquire) => {
            if output.complete() {
                recovery::mark_ended(root, job.attempt);
            }
            Verdict::Failed(FailureClass::Canceled, "canceled during preparation".into())
        }
        Err(e) => {
            if output.complete() {
                recovery::mark_ended(root, job.attempt);
            }
            Verdict::Failed(FailureClass::Preparation, e.to_string())
        }
        Ok(prepared) => {
            report.event(job.attempt, job.fence, Event::StepsStarted);
            let started = Instant::now();
            let verdict = execute(
                job,
                &prepared.container,
                prepared.workspace.path(),
                prepared.secret_directory.as_ref(),
                &output,
                cancel,
                &mut summary,
            );
            summary.steps_ns = ns(started);
            report.event(job.attempt, job.fence, Event::FinalizationStarted);
            let started = Instant::now();
            // Artifacts are part of finalization: resolved against the live
            // workspace and committed on the controller before teardown —
            // `when: always` captures even a canceled run's remains.
            let declared = job
                .spec
                .pipeline
                .jobs
                .get(job.job_index)
                .map(|j| j.spec.artifacts.as_slice())
                .unwrap_or(&[]);
            let artifact_failure = capture_artifacts(
                job.attempt,
                prepared.workspace.path(),
                declared,
                matches!(verdict, Verdict::Passed),
                sink,
            );
            sealed = finalize(root, job, &verdict, report, prepared, cancel);
            // The log is part of finalization: the attempt is not done until
            // what it printed is durable on the controller, or the wait ran
            // out and the failure is on record.
            let published = output.complete();
            if published {
                // The spool went with it; if the report below never leaves,
                // recovery must still call the log delivered, not lost.
                recovery::mark_ended(root, job.attempt);
            }
            summary.finalize_ns = ns(started);
            match (verdict, published, artifact_failure) {
                (Verdict::Passed, false, _) => Verdict::Failed(
                    FailureClass::Publication,
                    "log frames were not acknowledged in time".into(),
                ),
                (Verdict::Passed, _, Some(why)) => Verdict::Failed(FailureClass::Publication, why),
                (verdict, _, _) => verdict,
            }
        }
    };
    // A step's stderr, a helper's excerpt or a fallback reason can carry a
    // value the job printed: redacted like its log before it becomes the
    // verdict, the stored summary or a line in the worker's own log.
    let verdict = match verdict {
        Verdict::Failed(class, why) => Verdict::Failed(class, output.redact(why)),
        passed => passed,
    };
    if !summary.detail.is_empty() {
        summary.detail = output.redact(std::mem::take(&mut summary.detail));
    }
    let event = match &verdict {
        Verdict::Passed => Event::Passed,
        Verdict::Failed(class, why) => {
            // The failure reason leads; a mirror fallback reason recorded
            // during preparation stays after it rather than being lost
            // (P07-24), both inside the same 500-character bound.
            summary.detail = failure_detail(why, &summary.detail);
            Event::Failed(*class)
        }
    };
    // K08: one bounded record per declared cache rides the terminal
    // summary; a phase that never ran stays absent, never zero.
    summary.caches = job
        .caches
        .iter()
        .take(MAX_CACHE_RECORDS)
        .map(cache_record)
        .collect();
    match summary.encode() {
        Ok(bytes) => report.finish(job.attempt, job.fence, event, bytes),
        Err(_) => report.event(job.attempt, job.fence, event),
    }
    // Q08: a sealed generation may be offered to the controller — but
    // only now, after the terminal report already left. The offer is
    // bounded background work; whether it lands can never change what
    // this attempt reported.
    offer_caches(root, job, &sealed, remote.as_deref(), cancel);
    (verdict, summary)
}

/// The summary's `detail` for a failed attempt: the failure reason, then
/// any checkout fallback reason preparation recorded, within 500 chars.
fn failure_detail(why: &str, fallback: &str) -> String {
    if fallback.is_empty() {
        why.chars().take(500).collect()
    } else {
        format!("{why} (checkout fell back: {fallback})")
            .chars()
            .take(500)
            .collect()
    }
}

fn prepare(
    root: &Path,
    job: &mut Job,
    cancel: &Cancel,
    summary: &mut AttemptSummary,
    remote: Option<&dyn sentinel_cache::remote::Remote>,
) -> Result<PreparedExecution> {
    let compiled = job
        .spec
        .pipeline
        .jobs
        .get(job.job_index)
        .ok_or_else(|| Error::Preparation("job index outside the spec".into()))?;
    // The spec names the image; the run pinned its digest. Both are used,
    // never the tag: the bytes are the ones every attempt of the run gets.
    let image = sentinel_pipeline::run::ImageRef::parse(&compiled.spec.image)
        .map_err(|_| Error::Preparation("image reference".into()))?;
    let image = format!("{}@{}", image.name, job.digest);
    // Lift what the closure needs out of the `job` borrow: the declared
    // caches feed `restore_caches`, which takes `&mut Job` to record the
    // attachments, so the slice cannot stay borrowed from `job`.
    let declared = compiled.spec.cache.clone();
    let resources = compiled.spec.resources;
    let workspace = Workspace::create(root, job.attempt)?;
    let secret_directory = if job.secret_bundle.is_empty() {
        None
    } else {
        match SecretDirectory::create(root, job.attempt) {
            Ok(directory) => Some(directory),
            Err(error) => {
                let _ = workspace.destroy();
                return Err(error);
            }
        }
    };
    let outcome = (|| {
        // The checkout and the image pull are independent — one fills the
        // fresh workspace, the other the worker's content store — so the
        // checkout runs on its own thread while the pull overlaps it here,
        // joined before the container starts. Each summary field still
        // measures its own phase's wall time, so `checkout_ns` and
        // `image_pull_ns` together can exceed the preparation's. The
        // thread returns the mirror-aware outcome so the fetch and
        // materialization halves land on the summary too.
        // The Git helpers it runs are tied to the attempt's cancel flag: a
        // cancel kills a fetch under way instead of letting it run on to
        // the checkout deadline.
        let spawned = std::thread::Builder::new()
            .name(format!("sentinel-checkout-{}", job.attempt))
            .spawn({
                let path = workspace.path().to_path_buf();
                let source = job.spec.source.clone();
                let access = job.context.source.clone();
                let mirrors = job.mirrors.clone();
                let repo = job.context.repo;
                let lease = job.attempt.to_string();
                let cancel = Arc::clone(cancel);
                move || -> Result<(checkout::Outcome, Option<u64>)> {
                    sentinel_git::cancel_scope(cancel, || {
                        let started = Instant::now();
                        let outcome = checkout::checkout_mirrored(
                            &path,
                            mirrors.as_ref(),
                            &repo,
                            &source,
                            access.as_ref(),
                            &lease,
                            CHECKOUT_TIMEOUT,
                        )?;
                        Ok((outcome, ns(started)))
                    })
                }
            })
            .map_err(|_| Error::Preparation("checkout thread could not start".into()))?;
        let mut co = Some(spawned);
        if !job.prepare_hold.is_zero() {
            let until = Instant::now() + job.prepare_hold;
            while Instant::now() < until && !cancel.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if cancel.load(Ordering::Acquire) {
            // The checkout owns the workspace until it finishes; join it
            // before the teardown below destroys the directory.
            let _ = join_checkout(&mut co, summary);
            return Err(Error::Preparation("canceled".into()));
        }
        // A checkout that has already failed — an unknown revision says so
        // in milliseconds — still skips the pull, exactly as when the two
        // ran in sequence.
        if co.as_ref().is_some_and(|co| co.is_finished()) {
            join_checkout(&mut co, summary)?;
        }
        let started = Instant::now();
        let registry_auth = job.secret_bundle.targets.iter().find(|target| {
            matches!(
                target.target,
                sentinel_protocol::secrets::TargetKind::RegistryAuth
            )
        });
        let has_registry_auth = registry_auth.is_some();
        let (authfile, credential) = match registry_auth {
            Some(target) => {
                let value = job
                    .secret_bundle
                    .values
                    .get(target.value as usize)
                    .ok_or_else(|| Error::Preparation("registry auth target".into()))?
                    .expose();
                let directory = secret_directory
                    .as_ref()
                    .ok_or_else(|| Error::Preparation("registry auth directory".into()))?;
                (
                    directory.write_registry_auth(value)?,
                    *blake3::hash(value).as_bytes(),
                )
            }
            None => (job.images.anonymous_authfile().to_path_buf(), [0; 32]),
        };
        let tenant = job
            .context
            .tenant
            .map(|tenant| *tenant.as_bytes())
            .unwrap_or(*job.attempt.as_bytes());
        let store = store_for(root, job);
        let pulled = match &store {
            Ok(store) => job.images.pull_for_tenant(
                &image,
                tenant,
                credential,
                &authfile,
                store,
                podman::IMAGE_PULL_TIMEOUT,
                cancel,
            ),
            Err(_) => Err(Error::Preparation("private image store".into())),
        };
        if has_registry_auth {
            wipe_file(&authfile);
            let _ = fs::remove_file(&authfile);
        }
        if let Ok(present) = &pulled {
            summary.image_pull_ns = ns(started);
            // K08: whether the digest was resident before the authorized
            // registry check — the availability signal placement reads.
            summary.image_present = Some(*present);
        }
        // Join before the workspace could be torn down under a checkout
        // still running. The first failure wins — the checkout's ahead of
        // the pull's, as when the two ran in sequence.
        let checked_out = join_checkout(&mut co, summary);
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        checked_out.and(pulled)?;
        let store = store?;
        // K02: attach the declared caches — each hit is cloned into the
        // job's private view, each miss still leaves the writable target
        // directories a job always sees. Never fatal: a cache-path error
        // is an explainable miss recorded on the entry. Absolute declared
        // paths reach the container through the collected bind mounts.
        let mut mounts = restore_caches(root, job, &declared, workspace.path(), &image, remote);
        let (mut files, mut env) = (false, false);
        for target in &job.secret_bundle.targets {
            match target.target {
                sentinel_protocol::secrets::TargetKind::File { .. } => files = true,
                sentinel_protocol::secrets::TargetKind::Environment => env = true,
                sentinel_protocol::secrets::TargetKind::RegistryAuth => {}
            }
        }
        if files || env {
            let directory = secret_directory
                .as_ref()
                .ok_or_else(|| Error::Preparation("secret directory".into()))?;
            if files {
                mounts.push(podman::Mount {
                    host: directory.files_dir.clone(),
                    container: SECRET_FILES_MOUNT.into(),
                    read_only: true,
                });
            }
            if env {
                mounts.push(podman::Mount {
                    host: directory.env_dir.clone(),
                    container: SECRET_ENV_MOUNT.into(),
                    read_only: true,
                });
            }
        }
        let started = Instant::now();
        let container = Container::start(
            job.worker,
            job.attempt,
            &image,
            Limits {
                cpu_millis: resources.cpu_millis,
                memory_bytes: resources.memory_bytes,
                pids: DEFAULT_PIDS_LIMIT,
            },
            workspace.path(),
            &mounts,
            &store,
        )?;
        summary.container_start_ns = ns(started);
        Ok(container)
    })();
    match outcome {
        Ok(container) => Ok(PreparedExecution {
            workspace,
            container,
            secret_directory,
        }),
        Err(e) => {
            let _ = workspace.destroy();
            Err(e)
        }
    }
}

/// The checkout thread's handle: the mirror-aware outcome carries the
/// fetch/materialization split and route; the `Option<u64>` is the phase's
/// own wall time so a joined thread can still stamp `checkout_ns`.
type CheckoutThread = std::thread::JoinHandle<Result<(checkout::Outcome, Option<u64>)>>;

/// Join the checkout thread, once — `None` after the first call. A thread
/// that could not produce its result is a preparation failure like the
/// checkout's own; `checkout_ns` is stamped only when the checkout
/// completed, as a lone call was.
fn join_checkout(co: &mut Option<CheckoutThread>, summary: &mut AttemptSummary) -> Result<()> {
    let Some(handle) = co.take() else {
        return Ok(());
    };
    let done = handle
        .join()
        .unwrap_or_else(|_| Err(Error::Preparation("checkout thread failed".into())));
    let (outcome, taken) = done?;
    summary.checkout_ns = taken;
    summary.checkout_fetch_ns = Some(outcome.checkout.fetch_ns);
    summary.checkout_materialize_ns = Some(outcome.checkout.materialize_ns);
    summary.checkout_route = Some(outcome.route);
    if let Some(why) = outcome.fallback_reason {
        summary.detail = why;
    }
    Ok(())
}

/// K02: resolve every declared `cache:` entry against the fresh checkout —
/// render its key (`hash_files` reads the workspace), derive the scope
/// through the shared `attach` derivations, look the entry up and clone a
/// hit into the job's private view. `job.caches` receives one `Attached`
/// per declaration, in order, for finalization (K03) to publish; the
/// returned mounts carry the absolute declared paths into the container.
/// Never fails the attempt: any error on the cache path is an explainable
/// miss recorded on the entry, and the declared paths stay writable
/// directories either way. `image` is the pinned `name@digest` — the
/// toolchain descriptor every scope is built under. `remote` is the
/// session's transport (Q08): when present, a local miss may hydrate
/// through the controller under `min(5 s, job timeout / 4)`.
fn restore_caches(
    root: &Path,
    job: &mut Job,
    declared: &[sentinel_pipeline::schema::Cache],
    workspace: &Path,
    image: &str,
    remote: Option<&dyn sentinel_cache::remote::Remote>,
) -> Vec<podman::Mount> {
    if declared.is_empty() {
        return Vec::new();
    }
    // The hydration budget comes from the job's own wall-time allowance,
    // never from anything the worker invents: a quarter of the job's
    // timeout, capped at five seconds (remote::BUDGET_MAX).
    let job_timeout = job
        .spec
        .pipeline
        .jobs
        .get(job.job_index)
        .map(|j| Duration::from_secs(j.spec.timeout_secs.max(1)))
        .unwrap_or(Duration::ZERO);
    // One hydration deadline for the whole job, fixed before its first
    // restore: N declared caches share the budget rather than each taking
    // their own (P08-C6).
    let remote = remote.map(|source| sentinel_cache::remote::Policy {
        source,
        attempt: *job.attempt.as_bytes(),
        deadline: sentinel_cache::remote::Policy::deadline_for(job_timeout),
    });
    let context = WorkerContext::new(&job.context, &job.spec, workspace);
    let cache_root = root.join(sentinel_cache::attach::ROOT_DIR);
    let env = sentinel_cache::restore::Context {
        cache_root: &cache_root,
        workspace,
        workspace_mount: podman::WORKSPACE_MOUNT,
        backend: sentinel_cache::clone::detect(&cache_root),
    };
    let tenant = job
        .context
        .tenant
        .unwrap_or(sentinel_cache::attach::UNKNOWN_TENANT);
    let platform = sentinel_cache::Platform {
        os: sentinel_cache::Os::Linux,
        arch: if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        },
    };
    let toolchain = sentinel_cache::Scope::toolchain_digest(image.as_bytes());
    let owner = job.attempt.to_string();
    job.caches = declared
        .iter()
        .filter_map(|decl| {
            // A name `Scope::new` rejects never passed the schema; a spec
            // built by hand gets no entry rather than a guessed one. A key
            // that will not render is an explainable miss, not a failure.
            let scope = sentinel_cache::Scope::new(
                tenant,
                job.context.repo,
                decl.class,
                job.context.trust,
                platform,
                toolchain,
                &decl.name,
            )
            .ok()?;
            let key = decl
                .key
                .render(&context, sentinel_cache::attach::MAX_KEY_BYTES)
                .ok();
            Some(sentinel_cache::restore::restore_remote(
                &env, decl, key, scope, &owner, remote,
            ))
        })
        .collect();
    job.caches
        .iter()
        .flat_map(|a| a.targets.iter())
        .filter(|t| t.mount)
        .map(|t| podman::Mount {
            host: t.dir.clone(),
            container: t.container.clone(),
            read_only: false,
        })
        .collect()
}

/// Podman's own exit codes for an exec that never ran the command. 126 and
/// 127 are also what a shell returns for an unrunnable or missing command,
/// so the runtime's `Error:` line on stderr is what settles it.
fn runtime_failure(exit: &podman::Exit) -> bool {
    let text = String::from_utf8_lossy(&exit.stderr);
    let last = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    matches!(exit.code, Some(125..=127)) && last.starts_with("Error:")
}

fn execute(
    job: &Job,
    container: &Container,
    workspace: &Path,
    secret_directory: Option<&SecretDirectory>,
    output: &Arc<dyn Output>,
    cancel: &Cancel,
    summary: &mut AttemptSummary,
) -> Verdict {
    let extra = [
        ("SENTINEL_RUN".to_owned(), job.context.run.to_string()),
        ("SENTINEL_JOB".to_owned(), job.context.job.to_string()),
        ("SENTINEL_ATTEMPT".to_owned(), job.attempt.to_string()),
        ("SENTINEL_SHA".to_owned(), job.spec.source.sha.clone()),
        (
            "SENTINEL_WORKSPACE".to_owned(),
            podman::WORKSPACE_MOUNT.to_owned(),
        ),
        ("CI".to_owned(), "true".to_owned()),
    ];
    let compiled = &job.spec.pipeline.jobs[job.job_index].spec;
    let job_deadline = Instant::now() + Duration::from_secs(compiled.timeout_secs.max(1));
    let context = WorkerContext::new(&job.context, &job.spec, workspace);
    let mut oom_seen = container.oom_kills().unwrap_or(0);
    let mut failure: Option<(FailureClass, String)> = None;
    // Every declared step is considered in order — the restored-cache
    // outcome is never consulted here (K06). `job.caches` is written by
    // `restore_caches` during preparation and read only by
    // `publish_caches` during finalization, so a cache hit restores
    // bytes, never a verdict: there is no path by which a hit skips work.
    for (index, step) in compiled.steps.iter().enumerate() {
        let mut record = StepRecord {
            index: index as u32,
            id: step.id.clone(),
            outcome: StepOutcome::NotRun,
            duration_ns: None,
        };
        if failure.is_some() {
            summary.steps.push(record);
            continue;
        }
        // The executor's panic containment (P04-30) is tested by panicking
        // here, with the container running and output spooled. Test builds
        // only: no pipeline can reach this in any other build.
        #[cfg(test)]
        if step.id == PANIC_STEP {
            panic!("injected panic before step {index}");
        }
        if cancel.load(Ordering::Acquire) {
            summary.steps.push(record);
            failure = Some((
                FailureClass::Canceled,
                format!("canceled before step {index}"),
            ));
            continue;
        }
        if let Some(condition) = &step.condition {
            match condition.eval(&context).map(|v| v.as_condition()) {
                Ok(Some(true)) => {}
                Ok(Some(false)) => {
                    record.outcome = StepOutcome::Skipped;
                    summary.steps.push(record);
                    continue;
                }
                Ok(None) => {
                    summary.steps.push(record);
                    failure = Some((
                        FailureClass::Preparation,
                        format!("step {index} `if` did not evaluate to a boolean"),
                    ));
                    continue;
                }
                Err(e) => {
                    summary.steps.push(record);
                    failure = Some((
                        FailureClass::Preparation,
                        format!("step {index} `if`: {}", describe(&e)),
                    ));
                    continue;
                }
            }
        }
        let Some(mut command) = job.spec.step_command(job.job_index, index) else {
            summary.steps.push(record);
            failure = Some((
                FailureClass::Preparation,
                format!("step {index} outside the spec"),
            ));
            continue;
        };
        // The job's budget bounds every step's; a job cannot outlive its
        // timeout by having many steps each within theirs.
        let remaining = job_deadline.saturating_duration_since(Instant::now());
        command.timeout_secs = command.timeout_secs.min(remaining.as_secs().max(1));
        let started = Instant::now();
        let secret_step = !command.secrets.is_empty() || !command.secret_files.is_empty();
        let step_secrets = if !secret_step {
            None
        } else {
            let Some(directory) = secret_directory else {
                summary.steps.push(record);
                failure = Some((
                    FailureClass::Preparation,
                    format!("step {index} secret directory is unavailable"),
                ));
                continue;
            };
            // P10D-1: nothing an earlier step left running may watch this
            // step's environment or files. The container is emptied down
            // to its keepalive before anything is materialized; a
            // container that cannot be emptied gets no secret.
            if let Err(e) = container.clear_strays() {
                record.outcome = StepOutcome::Runtime;
                summary.steps.push(record);
                failure = Some((FailureClass::Runtime, format!("step {index}: {e}")));
                continue;
            }
            match materialize_step_secrets(directory, &job.secret_bundle, index) {
                Ok(paths) => Some(paths),
                Err(_) => {
                    summary.steps.push(record);
                    failure = Some((
                        FailureClass::Preparation,
                        format!("step {index} secret delivery failed"),
                    ));
                    continue;
                }
            }
        };
        if step_secrets.as_ref().is_some_and(|s| s.env_file.is_some()) {
            command.argv = wrap_with_env(std::mem::take(&mut command.argv), index);
        }
        let sink: crate::process::Sink = {
            let output = Arc::clone(output);
            let step_index = index as u32;
            Arc::new(move |stream, bytes: &[u8]| output.write(step_index, stream, bytes))
        };
        let exec = container.exec_streaming(&command, &extra, Some(sink));
        // …and nothing this step started outlives it into a later one,
        // whatever it held. Its files go only once its processes have.
        // A timed-out or canceled step's container is already stopped.
        let cleared = if secret_step
            && exec.as_ref().is_ok_and(|exit| !exit.timed_out)
            && !cancel.load(Ordering::Acquire)
        {
            container.clear_strays().map(|_| ())
        } else {
            Ok(())
        };
        drop(step_secrets);
        // Whatever the step printed last and the redactor held back is
        // this step's output, released before the next one starts.
        output.step_done(index as u32);
        let exit = match exec.and_then(|exit| cleared.map(|()| exit)) {
            Ok(exit) => exit,
            Err(e) => {
                record.outcome = StepOutcome::Runtime;
                record.duration_ns = ns(started);
                summary.steps.push(record);
                failure = Some((FailureClass::Runtime, format!("step {index}: {e}")));
                continue;
            }
        };
        record.duration_ns = ns(started);
        let (outcome, why) = if cancel.load(Ordering::Acquire) {
            // Ended by the cancel order, however the process went: the
            // desired state wins over the incidental exit status.
            (
                StepOutcome::Signaled {
                    signal: exit.signal.unwrap_or(0),
                },
                Some((FailureClass::Canceled, format!("step {index} canceled"))),
            )
        } else if exit.timed_out {
            (
                StepOutcome::TimedOut,
                Some((
                    FailureClass::ExecutionTimeout,
                    format!("step {index} exceeded {} s", command.timeout_secs),
                )),
            )
        } else if runtime_failure(&exit) {
            (
                StepOutcome::Runtime,
                Some((
                    FailureClass::Runtime,
                    format!("step {index}: {}", output.excerpt(&exit.stderr)),
                )),
            )
        } else if exit.signal.is_some() || exit.code != Some(0) {
            let oom_now = container.oom_kills().unwrap_or(oom_seen);
            let oom = oom_now > oom_seen;
            oom_seen = oom_now;
            if oom {
                (
                    StepOutcome::OutOfMemory,
                    Some((
                        FailureClass::OutOfMemory,
                        format!("step {index} exceeded the memory limit"),
                    )),
                )
            } else if let Some(signal) = exit.signal {
                (
                    StepOutcome::Signaled { signal },
                    Some((
                        FailureClass::CommandSignaled,
                        format!("step {index} died from signal {signal}"),
                    )),
                )
            } else {
                let code = exit.code.unwrap_or(-1);
                (
                    StepOutcome::Failed { code },
                    Some((
                        FailureClass::CommandFailed,
                        format!("step {index} exited with {code}"),
                    )),
                )
            }
        } else {
            (StepOutcome::Passed, None)
        };
        record.outcome = outcome;
        summary.steps.push(record);
        failure = why;
    }
    match failure {
        None => Verdict::Passed,
        Some((class, why)) => Verdict::Failed(class, why),
    }
}

/// Capture every declared artifact whose `when` matches the step verdict.
/// A required artifact that does not publish — no match, capture failure or
/// a refused verdict — is a finalization failure; optional outcomes are
/// recorded and left out of the verdict.
pub fn capture_artifacts(
    attempt: AttemptId,
    workspace: &Path,
    declared: &[sentinel_pipeline::schema::Artifact],
    passed: bool,
    sink: &dyn artifacts::Sink,
) -> Option<String> {
    let mut failed = None;
    for decl in declared {
        if !artifacts::due(decl, passed) {
            continue;
        }
        let outcome = artifacts::capture(workspace, decl, sink, attempt);
        if decl.required && outcome != artifacts::Outcome::Published {
            failed.get_or_insert_with(|| {
                format!("required artifact `{}` was not published", decl.name)
            });
        }
    }
    failed
}

fn describe(error: &EvalError) -> String {
    match error {
        EvalError::Unresolved { needs, .. } => {
            format!("value not known to this run (needs {needs:?} context)")
        }
        EvalError::TypeMismatch { expected, found } => {
            format!("expected {expected}, found {found}")
        }
        EvalError::HashFiles(e) => format!("hash_files: {e:?}"),
    }
}

/// Whether the steps' verdict leaves cache state worth keeping: the job's
/// commands ran, so their writes are real work the next attempt can reuse.
/// A canceled, timed-out or never-started attempt publishes nothing.
fn cache_worthy(verdict: &Verdict) -> bool {
    match verdict {
        Verdict::Passed => true,
        Verdict::Failed(class, _) => matches!(
            class,
            FailureClass::CommandFailed | FailureClass::CommandSignaled | FailureClass::OutOfMemory
        ),
    }
}

/// K08: the summary's per-entry record from the carrier restore filled
/// and the commit answered — stable vocabulary throughout: `"hit"` or a
/// `Miss` reason for the lookup, `"sealed"` or a `SkipReason`/`"failed"`
/// for the publish, and the documented costly-hit flag.
fn cache_record(attached: &sentinel_cache::attach::Attached) -> CacheRecord {
    let stats = &attached.stats;
    let (staged, reused, dirty, publish) = match stats.committed {
        Some(sentinel_cache::Committed::Sealed {
            staged_bytes,
            reused_bytes,
        }) => (
            Some(staged_bytes),
            Some(reused_bytes),
            // The dirty side: what the job's view rewrote versus the
            // source generation — staged minus reused (reused is a
            // subset of staged by construction; saturating anyway, a
            // record must never panic).
            Some(staged_bytes.saturating_sub(reused_bytes)),
            Some("sealed".to_owned()),
        ),
        Some(sentinel_cache::Committed::Skipped(why)) => {
            (None, None, None, Some(why.as_str().to_owned()))
        }
        Some(sentinel_cache::Committed::Failed) => (None, None, None, Some("failed".to_owned())),
        None => (None, None, None, None),
    };
    CacheRecord {
        name: attached.name.clone(),
        class: attached.scope.class.to_u8(),
        outcome: match &attached.outcome {
            sentinel_cache::Outcome::Hit(_) => "hit".to_owned(),
            sentinel_cache::Outcome::Miss(miss) => miss.as_str().to_owned(),
        },
        lookup_ns: stats.lookup_ns,
        lock_wait_ns: stats.lock_wait_ns,
        clone_ns: stats.clone_ns,
        first_touch_ns: stats.first_touch_ns,
        files: stats.files,
        bytes: stats.bytes,
        copied_bytes: stats.copied_bytes,
        reflink: stats.reflink,
        commit_ns: stats.commit_ns,
        staged_bytes: staged,
        reused_bytes: reused,
        dirty_bytes: dirty,
        publish,
        costly_hit: attached.costly_hit().is_some(),
    }
}

/// Commit each attached cache under its own scope, while the workspace's
/// writable views still exist. The verdict never depends on publication (its report waits for it): the
/// whole batch is bounded by `CACHE_PUBLISH_TIMEOUT`, each entry's outcome
/// is reported as a `CacheNote` and stamped on the carrier's stats (K08)
/// for the summary's per-entry record, and nothing here changes what the
/// attempt reported. The returned list names the generations this attempt
/// sealed — what a later offer (Q08) may send to the controller.
fn publish_caches(
    root: &Path,
    job: &mut Job,
    report: &dyn Report,
    cancel: &Cancel,
) -> Vec<SealedCache> {
    let mut sealed = Vec::new();
    if job.caches.is_empty() {
        return sealed;
    }
    let cache_root = root.join(sentinel_cache::CACHE_DIR);
    let deadline = Instant::now() + sentinel_cache::publish::CACHE_PUBLISH_TIMEOUT;
    let canceled = || cancel.load(Ordering::Acquire);
    for (index, attached) in job.caches.iter_mut().enumerate() {
        let started = Instant::now();
        let committed = sentinel_cache::publish::commit(
            &cache_root,
            attached,
            job.context.trust,
            sentinel_core::UnixMillis::now(),
            deadline,
            &canceled,
        );
        // The commit's cost and answer land on the carrier — the summary
        // reads them back for the attempt's per-entry records.
        attached.stats.commit_ns = ns(started);
        let outcome = match committed {
            Ok(sentinel_cache::publish::Published::Sealed {
                generation,
                bytes,
                reused_bytes,
                ..
            }) => {
                attached.stats.committed = Some(sentinel_cache::Committed::Sealed {
                    staged_bytes: bytes,
                    reused_bytes,
                });
                sealed.push(SealedCache {
                    index,
                    generation: generation.clone(),
                });
                CacheOutcome::Sealed {
                    generation,
                    bytes,
                    reused_bytes,
                }
            }
            Ok(sentinel_cache::publish::Published::Skipped(why)) => {
                attached.stats.committed = Some(sentinel_cache::Committed::Skipped(why));
                CacheOutcome::Skipped(why.as_str())
            }
            Err(e) => {
                attached.stats.committed = Some(sentinel_cache::Committed::Failed);
                CacheOutcome::Failed(e.to_string())
            }
        };
        report.cache_note(
            job.attempt,
            CacheNote {
                name: attached.name.clone(),
                outcome,
            },
        );
    }
    sealed
}

struct PreparedExecution {
    workspace: Workspace,
    container: Container,
    secret_directory: Option<SecretDirectory>,
}

fn finalize(
    root: &Path,
    job: &mut Job,
    verdict: &Verdict,
    report: &dyn Report,
    prepared: PreparedExecution,
    cancel: &Cancel,
) -> Vec<SealedCache> {
    let PreparedExecution {
        workspace,
        container,
        secret_directory,
    } = prepared;
    // The container goes first (P07-1): once it is stopped and removed no
    // job process — the keepalive, or anything a step left running — can
    // rewrite, swap or re-link the writable views while publication reads
    // them. The views themselves live in the workspace (and its private
    // `.sentinel-cache/` directory), which outlives the container.
    // Publication then walks them confined beneath the workspace anyway, so
    // a container that would not stop cannot redirect it either.
    let _ = container.destroy();
    drop(secret_directory);
    // Cache publication is finalization work: it reads the job's writable
    // views, so it must precede the workspace's teardown — and a verdict
    // that never ran the job's commands leaves nothing worth keeping.
    let sealed = if cache_worthy(verdict) {
        publish_caches(root, job, report, cancel)
    } else {
        Vec::new()
    };
    // Runs even when the container would not stop: a container that will
    // not stop must not keep a workspace alive. The failure is a
    // reconciliation matter for W07, which lists what this worker still
    // owns.
    let _ = workspace.destroy();
    sealed
}

/// One generation this attempt sealed: the carrier it belongs to (by
/// position, the same order `job.caches` is in) and the directory name
/// under its entry.
struct SealedCache {
    index: usize,
    generation: String,
}

/// Offer every sealed generation to the controller (Q08), one bounded
/// transfer each, long after the terminal report already left. An offer
/// never changes a verdict: a refusal, a session that went away, or a
/// deadline that passed simply drops it — the local copy is already the
/// job's own.
fn offer_caches(
    root: &Path,
    job: &Job,
    sealed: &[SealedCache],
    remote: Option<&dyn sentinel_cache::remote::Remote>,
    cancel: &Cancel,
) {
    let Some(source) = remote else {
        return;
    };
    if sealed.is_empty() {
        return;
    }
    let cache_root = root.join(sentinel_cache::CACHE_DIR);
    let deadline = Instant::now() + sentinel_cache::remote::OFFER_BUDGET;
    let canceled = || cancel.load(Ordering::Acquire);
    for entry in sealed {
        let Some(attached) = job.caches.get(entry.index) else {
            continue;
        };
        let _ = sentinel_cache::remote::offer_generation(
            &cache_root,
            attached,
            &entry.generation,
            *job.attempt.as_bytes(),
            source,
            deadline,
            &canceled,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Mutex};

    use sentinel_core::{JobId, RepoId, RunId};
    use sentinel_link::session::EventContext;
    use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
    use sentinel_protocol::cache::Trust;

    use super::*;

    #[test]
    fn delivered_env_and_files_live_outside_workspace_and_are_removed_after_step() {
        use sentinel_protocol::secrets::{
            DeliveryBundle, DeliveryTarget, DeliveryValue, TargetKind,
        };

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("worker");
        let workspace = root.join("workspaces").join("attempt");
        fs::create_dir_all(&workspace).unwrap();
        let attempt = AttemptId::new();
        let attempt_dir = secret_root(&root).join(attempt.to_string());
        let directory = SecretDirectory::create(&root, attempt).unwrap();
        let bundle = DeliveryBundle {
            values: vec![
                DeliveryValue::new(b"a-token-value".to_vec()),
                DeliveryValue::new(b"certificate-bytes".to_vec()),
            ],
            targets: vec![
                DeliveryTarget {
                    step: 0,
                    name: "TOKEN".into(),
                    value: 0,
                    target: TargetKind::Environment,
                },
                DeliveryTarget {
                    step: 0,
                    name: "CERT".into(),
                    value: 1,
                    target: TargetKind::File {
                        path: "tls/client.pem".into(),
                    },
                },
            ],
        };
        let paths = materialize_step_secrets(&directory, &bundle, 0).unwrap();
        let env = paths.env_file.as_ref().unwrap().clone();
        let cert = directory.files_dir.join("tls/client.pem");
        assert!(env.starts_with(secret_root(&root)));
        assert!(cert.starts_with(secret_root(&root)));
        assert!(!env.starts_with(&workspace));
        assert!(!cert.starts_with(&workspace));
        assert_eq!(fs::read(&env).unwrap(), b"export TOKEN='a-token-value'\n");
        assert_eq!(fs::read(&cert).unwrap(), b"certificate-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            // P10D-4: the host boundary is the owner-only attempt
            // directory; what is mounted read-only into the attempt's
            // container is readable by whatever user its image runs as.
            assert_eq!(mode(&attempt_dir), 0o700);
            assert_eq!(mode(&secret_root(&root)), 0o700);
            assert_eq!(mode(&directory.files_dir), 0o755);
            assert_eq!(mode(&directory.files_dir.join("tls")), 0o755);
            assert_eq!(mode(&cert), 0o644);
            assert_eq!(mode(&env), 0o644);
        }

        drop(paths);
        assert!(!env.exists());
        assert!(!cert.exists());
        drop(directory);
        assert!(!attempt_dir.exists());
    }

    /// P10D-8: environment targets reach the step through the wrapper
    /// shell that sources the private file and `exec`s the step — exactly,
    /// whatever the value holds (quotes, `$`, backticks, spaces, non-ASCII)
    /// and up to the 64 KiB value bound, which Podman's `--env-file`
    /// reader refused. The values appear in no argv.
    #[test]
    fn env_targets_reach_the_step_exactly_through_the_wrapper() {
        use sentinel_protocol::secrets::{
            DeliveryBundle, DeliveryTarget, DeliveryValue, TargetKind,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("worker");
        fs::create_dir_all(&root).unwrap();
        let directory = SecretDirectory::create(&root, AttemptId::new()).unwrap();
        let tricky = "it's $HOME `id` \"q\" \\n x  é";
        let big = "b".repeat(sentinel_protocol::secrets::MAX_SECRET_BYTES);
        let bundle = DeliveryBundle {
            values: vec![
                DeliveryValue::new(tricky.as_bytes().to_vec()),
                DeliveryValue::new(big.as_bytes().to_vec()),
            ],
            targets: vec![
                DeliveryTarget {
                    step: 3,
                    name: "TRICKY".into(),
                    value: 0,
                    target: TargetKind::Environment,
                },
                DeliveryTarget {
                    step: 3,
                    name: "BIG".into(),
                    value: 1,
                    target: TargetKind::Environment,
                },
            ],
        };
        let paths = materialize_step_secrets(&directory, &bundle, 3).unwrap();
        let env = paths.env_file.clone().unwrap();
        // The wrapper as the container runs it, with the mount path
        // pointing at the host file.
        let argv = wrap_with_env(
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf '%s' \"$TRICKY\" > \"$0\"; printf '%s' \"${#BIG}\" > \"$0.len\"".into(),
                temp.path().join("seen").display().to_string(),
            ],
            3,
        );
        assert!(argv.iter().all(|a| !a.contains("$HOME `id`") && !a.contains(&big)));
        let script = argv[2].replace(SECRET_ENV_MOUNT, &directory.env_dir.display().to_string());
        let status = std::process::Command::new(&argv[0])
            .arg(&argv[1])
            .arg(script)
            .args(&argv[3..])
            .env_clear()
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(temp.path().join("seen")).unwrap(), tricky);
        assert_eq!(
            fs::read_to_string(temp.path().join("seen.len")).unwrap(),
            big.len().to_string()
        );
        drop(paths);
        assert!(!env.exists());
    }

    /// P07-24: a failed attempt keeps the mirror fallback reason next to
    /// its own, bounded.
    #[test]
    fn a_failure_keeps_the_checkout_fallback_reason() {
        assert_eq!(
            failure_detail("step 0 exited with 1", ""),
            "step 0 exited with 1"
        );
        let detail = failure_detail("step 0 exited with 1", "git mirror: lock wait");
        assert_eq!(
            detail,
            "step 0 exited with 1 (checkout fell back: git mirror: lock wait)"
        );
        assert_eq!(failure_detail(&"x".repeat(600), "y").chars().count(), 500);
    }

    #[test]
    fn publication_follows_whether_the_commands_ran() {
        // Passed and command-level failures publish; everything that
        // stopped the commands from running — or the operator's cancel —
        // keeps nothing.
        assert!(cache_worthy(&Verdict::Passed));
        for class in [
            FailureClass::CommandFailed,
            FailureClass::CommandSignaled,
            FailureClass::OutOfMemory,
        ] {
            assert!(
                cache_worthy(&Verdict::Failed(class, String::new())),
                "{class:?}"
            );
        }
        for class in [
            FailureClass::ExecutionTimeout,
            FailureClass::Canceled,
            FailureClass::Preparation,
            FailureClass::Runtime,
            FailureClass::Publication,
            FailureClass::LeaseExpired,
            FailureClass::WorkerLost,
            FailureClass::Reconciled,
            FailureClass::QueueTimeout,
        ] {
            assert!(
                !cache_worthy(&Verdict::Failed(class, String::new())),
                "{class:?}"
            );
        }
    }

    /// The smallest spec that carries cache declarations: a push pipeline
    /// whose `key` renders through `hash_files` against the checkout.
    fn spec() -> RunSpec {
        let yaml = "schema: 1\non: [push]\njobs:\n  main:\n    image: example.test/i:1@sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n    resources: { cpu: 1, memory: 128MiB }\n    cache:\n      - name: deps\n        key: deps-${{ hash_files('f.lock') }}\n        paths: [vendor, /opt/cc]\n    steps: [{ id: s, run: 'true' }]\n";
        RunSpec::new(
            PinnedSource::new("file:///nowhere", &"a".repeat(40), Some("main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap()
    }

    fn job(spec: RunSpec) -> Job {
        Job {
            worker: WorkerId::new(),
            attempt: AttemptId::new(),
            fence: Fence(1),
            job_index: 0,
            digest: "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .into(),
            spec,
            context: JobContext {
                source: None,
                run: RunId::new(),
                repo: RepoId::new(),
                repo_name: "app".into(),
                job: JobId::new(),
                job_name: "main".into(),
                sha: "a".repeat(40),
                event: EventContext {
                    name: "push".into(),
                    ref_name: "main".into(),
                    base_ref: None,
                    pr_number: None,
                    key: "k".into(),
                },
                cancelled: false,
                needs: Vec::new(),
                tenant: None,
                trust: Trust::Protected,
            },
            images: Images::with_download(|_, _, _, _, _| Ok(false)),
            caches: Vec::new(),
            mirrors: None,
            prepare_hold: Duration::ZERO,
            secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        }
    }

    /// The job-side contract of a miss: `job.caches` is populated in
    /// declaration order with the explainable outcome, and every declared
    /// path is a writable directory the job can just use.
    #[test]
    fn a_cache_miss_still_leaves_writable_targets_and_populates_job() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        let mounts = restore_caches(&root, &mut job, &declared, &ws, &image, None);

        assert_eq!(job.caches.len(), 1);
        let attached = &job.caches[0];
        assert_eq!(attached.name, "deps");
        assert!(
            attached.key.starts_with("deps-") && attached.key.len() > 5,
            "the key rendered through hash_files: {:?}",
            attached.key
        );
        assert_eq!(
            attached.outcome,
            sentinel_cache::Outcome::Miss(sentinel_cache::Miss::Absent)
        );
        assert_eq!(attached.targets.len(), 2);
        // The relative target materialized under the workspace and a job
        // can write it; the absolute one is private and mounts in.
        let vendor = ws.join("vendor");
        assert!(vendor.is_dir());
        fs::write(vendor.join("fresh"), b"x").unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].container, "/opt/cc");
        assert_eq!(mounts[0].host, attached.targets[1].dir);
        assert!(mounts[0].host.is_dir());

        // K08: the summary's record for the entry — the miss's reason and
        // the lookup measurement, everything else absent.
        let record = cache_record(attached);
        assert_eq!(record.name, "deps");
        assert_eq!(
            record.class,
            sentinel_protocol::cache::Class::Dependencies.to_u8()
        );
        assert_eq!(record.outcome, "absent");
        assert!(record.lookup_ns.is_some());
        assert!(record.clone_ns.is_none() && record.first_touch_ns.is_none());
        assert!(record.commit_ns.is_none() && record.publish.is_none());
        assert!(!record.costly_hit);
    }

    /// A report sink that records the diagnostics `run` emits, and hands
    /// out whatever remote transport a test installed on it (Q08).
    #[derive(Default)]
    struct Notes {
        cache_notes: Mutex<Vec<CacheNote>>,
        costly: Mutex<Vec<(String, sentinel_cache::Costly)>>,
        remote: Mutex<Option<Arc<dyn sentinel_cache::remote::Remote>>>,
    }
    impl Report for Notes {
        fn event(&self, _: AttemptId, _: Fence, _: Event) {}
        fn finish(&self, _: AttemptId, _: Fence, _: Event, _: Vec<u8>) {}
        fn cache_note(&self, _: AttemptId, note: CacheNote) {
            self.cache_notes.lock().unwrap().push(note);
        }
        fn costly_hit(
            &self,
            _: AttemptId,
            name: &str,
            costly: sentinel_cache::Costly,
            _: &sentinel_cache::Stats,
        ) {
            self.costly.lock().unwrap().push((name.to_owned(), costly));
        }
        fn remote(&self) -> Option<Arc<dyn sentinel_cache::remote::Remote>> {
            self.remote.lock().unwrap().clone()
        }
    }

    /// A transport that records every offer it stores; a fetch always
    /// misses, which is all the offer path needs of it.
    #[derive(Default)]
    struct Recorder {
        offered: Mutex<Vec<(String, u64)>>,
    }
    impl sentinel_cache::remote::Remote for Recorder {
        fn fetch(
            &self,
            _: &sentinel_cache::remote::Need,
            _: Instant,
            _: &mut dyn sentinel_cache::remote::Sink,
        ) -> std::result::Result<(), sentinel_cache::remote::Refusal> {
            Err(sentinel_cache::remote::Refusal::NoBundle)
        }
        fn offer(
            &self,
            upload: &sentinel_cache::remote::Upload,
            _: Instant,
            source: &mut dyn std::io::Read,
        ) -> std::result::Result<[u8; 32], sentinel_cache::remote::Refusal> {
            let mut bytes = Vec::new();
            source
                .read_to_end(&mut bytes)
                .map_err(|_| sentinel_cache::remote::Refusal::Store)?;
            assert_eq!(bytes.len() as u64, upload.total);
            self.offered
                .lock()
                .unwrap()
                .push((upload.key.clone(), bytes.len() as u64));
            Ok(upload.digest)
        }
    }

    /// A job that wrote into its view publishes; the commit's cost and
    /// byte split land on the carrier and ride the summary record.
    #[test]
    fn publish_stamps_commit_stats_and_the_record_carries_them() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        restore_caches(&root, &mut job, &declared, &ws, &image, None);
        // The job's own work: one new file in the declared path's view.
        fs::write(ws.join("vendor/lib"), b"new").unwrap();
        let notes = Notes::default();
        let flag: Cancel = Arc::new(AtomicBool::new(false));
        let sealed = publish_caches(&root, &mut job, &notes, &flag);
        assert_eq!(sealed.len(), 1, "one sealed generation is one offer");
        assert_eq!(sealed[0].index, 0);
        assert!(sealed[0].generation.starts_with("gen-"));

        let attached = &job.caches[0];
        assert!(attached.stats.commit_ns.is_some());
        assert!(matches!(
            attached.stats.committed,
            Some(sentinel_cache::Committed::Sealed {
                staged_bytes: 3,
                reused_bytes: 0
            })
        ));
        let record = cache_record(attached);
        assert_eq!(record.publish.as_deref(), Some("sealed"));
        assert_eq!(record.staged_bytes, Some(3));
        assert_eq!(record.reused_bytes, Some(0));
        assert_eq!(record.dirty_bytes, Some(3));
        assert!(matches!(
            notes.cache_notes.lock().unwrap().as_slice(),
            [CacheNote {
                outcome: CacheOutcome::Sealed { .. },
                ..
            }]
        ));
    }

    /// A sealed generation is offered through the session's transport —
    /// and only there: with no transport the same publish stands, and a
    /// refused offer leaves the local generation and every stat exactly
    /// as they were.
    #[test]
    fn a_sealed_generation_is_offered_only_when_a_transport_exists() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        restore_caches(&root, &mut job, &declared, &ws, &image, None);
        fs::write(ws.join("vendor/lib"), b"new").unwrap();
        let notes = Notes::default();
        let flag: Cancel = Arc::new(AtomicBool::new(false));
        let sealed = publish_caches(&root, &mut job, &notes, &flag);
        let generation = sealed[0].generation.clone();

        // No transport: an offer is impossible and nothing pretends
        // otherwise.
        offer_caches(&root, &job, &sealed, None, &flag);
        assert!(job.caches[0].stats.committed.is_some());

        // With one: the canonical stream is read whole and the key the
        // controller receives is the entry's own.
        let recorder = Arc::new(Recorder::default());
        let transport: &dyn sentinel_cache::remote::Remote = recorder.as_ref();
        offer_caches(&root, &job, &sealed, Some(transport), &flag);
        let offered = recorder.offered.lock().unwrap();
        assert_eq!(offered.len(), 1);
        assert!(offered[0].0.starts_with("deps-"), "{}", offered[0].0);
        let offered_len = offered[0].1;
        drop(offered);

        // The stream is exactly the sealed generation: head, manifest,
        // listing and payload — and the generation is still there after.
        let attached = &job.caches[0];
        let gen_dir = attached
            .scope
            .entry_dir(
                &root.join(sentinel_cache::CACHE_DIR),
                sentinel_cache::attach::entry_key(attached.scope.class, &attached.key),
            )
            .join(&generation);
        let expected = 40
            + fs::read(gen_dir.join(sentinel_cache::scope::MANIFEST_NAME))
                .unwrap()
                .len() as u64
            + fs::read(gen_dir.join(sentinel_cache::scope::FILES_NAME))
                .unwrap()
                .len() as u64
            + 3;
        assert_eq!(offered_len, expected);
    }

    /// The record's flag is the carrier's rule: a reflink-root hit that
    /// copied every byte reads `costly_hit` — the notice goes through
    /// `report.costly_hit` the same way.
    #[test]
    fn a_hit_that_paid_full_copy_records_the_flag() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        restore_caches(&root, &mut job, &declared, &ws, &image, None);
        // Shape the carrier the way a reflink root that refused every
        // file leaves it: a hit whose copy covered all bytes.
        let attached = &mut job.caches[0];
        attached.outcome = sentinel_cache::Outcome::Hit(Box::new(sentinel_cache::Hit {
            manifest: sentinel_cache::Manifest::writing(
                &attached.scope,
                &attached.key,
                attached.compat.clone(),
            ),
            bytes: 100,
        }));
        attached.stats.reflink = true;
        attached.stats.bytes = 100;
        attached.stats.copied_bytes = 100;
        assert_eq!(
            attached.costly_hit(),
            Some(sentinel_cache::Costly::CopiedAll)
        );
        let record = cache_record(attached);
        assert!(record.costly_hit);
        assert_eq!(record.outcome, "hit");
    }

    /// A spec with a `class: compiler` cache and two steps: the K06
    /// carrier for proving a hit never becomes a cached verdict.
    fn spec_compiler() -> RunSpec {
        let yaml = "schema: 1\non: [push]\njobs:\n  main:\n    image: example.test/i:1@sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n    resources: { cpu: 1, memory: 128MiB }\n    cache:\n      - name: cc\n        class: compiler\n        key: cc-normal-${{ hash_files('f.lock') }}\n        paths: [ccache]\n    steps: [{ id: build, run: 'cc -c a.c' }, { id: test, run: './run-tests' }]\n";
        RunSpec::new(
            PinnedSource::new("file:///nowhere", &"a".repeat(40), Some("main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap()
    }

    /// Seal a compiler generation exactly where `restore_caches` will
    /// look: the same tenant/repo/trust/platform/toolchain derivation,
    /// the rendered key's stem as the entry, the rendered key itself in
    /// the manifest — so `cc-normal-<h1>` is what a `cc-normal-<h2>`
    /// request serves.
    fn seal_compiler(
        root: &Path,
        job: &Job,
        ws: &Path,
        decl: &sentinel_pipeline::schema::Cache,
        files: &[(&str, &[u8])],
    ) {
        use sentinel_cache::{
            manifest::{FileEntry, FilesBlob, Manifest},
            scope::{self, Os, Platform, Scope},
        };
        let platform = Platform {
            os: Os::Linux,
            arch: if cfg!(target_arch = "aarch64") {
                Arch::Aarch64
            } else {
                Arch::X86_64
            },
        };
        let image = format!("example.test/i@{}", job.digest);
        let scope = Scope::new(
            sentinel_cache::attach::UNKNOWN_TENANT,
            job.context.repo,
            decl.class,
            job.context.trust,
            platform,
            Scope::toolchain_digest(image.as_bytes()),
            &decl.name,
        )
        .unwrap();
        // Render the key exactly as `restore_caches` will: `hash_files`
        // reads the workspace that is already standing.
        let context = WorkerContext::new(&job.context, &job.spec, ws);
        let key = decl
            .key
            .render(&context, sentinel_cache::attach::MAX_KEY_BYTES)
            .unwrap();
        let compat = sentinel_cache::attach::declared_compat(decl, &key, platform);
        // `restore_caches` resolves entries under `<root>/cache`.
        let cache_root = root.join(sentinel_cache::attach::ROOT_DIR);
        let entry = scope.entry_dir(
            &cache_root,
            sentinel_cache::attach::entry_key(decl.class, &key),
        );
        let name = scope::gen_name(1_700_000_000_000, 0x00ab_cdef);
        let gdir = entry.join(&name);
        let mut entries = Vec::new();
        let mut total = 0u64;
        for (rel, body) in files {
            let path = gdir.join("payload/0").join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
            entries.push(FileEntry {
                path: format!("payload/0/{rel}"),
                size: body.len() as u64,
                // BLAKE3 of the content — the same digest the store
                // computes, reached through the public toolchain hash.
                digest: Scope::toolchain_digest(body),
                mode: 0o644,
            });
            total += body.len() as u64;
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let blob = FilesBlob { entries };
        fs::write(gdir.join(scope::FILES_NAME), blob.encode()).unwrap();
        let mut manifest = Manifest::writing(&scope, &key, compat);
        manifest.bytes = total;
        manifest.files = blob.entries.len() as u32;
        manifest.files_digest = blob.digest();
        manifest.seal(sentinel_core::UnixMillis(1_700_000_000_001));
        fs::write(gdir.join(scope::MANIFEST_NAME), manifest.encode()).unwrap();
        fs::write(entry.join(scope::CURRENT_NAME), format!("{name}\n")).unwrap();
    }

    /// K06: a cache hit restores bytes into the job's private view and
    /// nothing else. `execute` iterates `compiled.steps` unconditionally
    /// — `job.caches` is written by `restore_caches` and read only by
    /// `publish_caches` at finalization — so a hit can never suppress a
    /// step or carry a verdict. This test proves the observable half:
    /// after a hit, the spec `execute` runs is the freshly compiled one,
    /// every declared step still present.
    #[test]
    fn a_cache_hit_restores_bytes_and_never_touches_the_step_plan() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec_compiler());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        // A generation sealed under `cc-normal-<h1>`; the request renders
        // `cc-normal-<h2>` — same stem, small lockfile edit.
        seal_compiler(&root, &job, &ws, &declared[0], &[("obj/a.o", b"object")]);

        let mounts = restore_caches(&root, &mut job, &declared, &ws, &image, None);

        assert_eq!(job.caches.len(), 1);
        let attached = &job.caches[0];
        assert!(
            matches!(attached.outcome, sentinel_cache::Outcome::Hit(_)),
            "the sealed stem must serve the moved tail: {:?}",
            attached.outcome
        );
        assert_eq!(
            fs::read(ws.join("ccache/obj/a.o")).unwrap(),
            b"object",
            "the hit materialized real bytes into the job's view"
        );
        assert!(mounts.is_empty(), "a relative path needs no bind mount");
        // The step plan is untouched by the hit: the spec `execute` will
        // run is identical to a fresh compile, both steps still present.
        assert_eq!(job.spec, spec_compiler());
        let steps = &job.spec.pipeline.jobs[0].spec.steps;
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].id, "build");
        assert_eq!(steps[1].id, "test");
    }
}
