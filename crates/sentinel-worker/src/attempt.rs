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
    host::Isolation,
    images::Images,
    microvm,
    podman::{self, Container, DEFAULT_PIDS_LIMIT, Limits},
    recovery,
    sandbox::Sandbox,
    workspace::Workspace,
};

#[cfg(test)]
pub(crate) const PANIC_STEP: &str = "panic-injected";

pub struct Job {
    pub worker: WorkerId,
    pub attempt: AttemptId,
    pub fence: Fence,
    pub job_index: usize,
    pub digest: String,
    pub spec: RunSpec,
    pub context: JobContext,
    pub secret_bundle: sentinel_protocol::secrets::DeliveryBundle,
    pub images: Images,
    pub caches: Vec<sentinel_cache::attach::Attached>,
    pub cache_budget_bytes: u64,
    pub mirrors: Option<checkout::Mirrors>,
    pub prepare_hold: std::time::Duration,
    pub network: podman::Network,
    pub runtime: Runtime,
}

/// What a worker runs jobs on: its default executor and, where microVMs can run, their setup.
#[derive(Clone, Debug, Default)]
pub struct Runtime {
    pub default: Option<Isolation>,
    pub microvm: Option<Arc<microvm::Setup>>,
}

impl Runtime {
    /// The executor for a job: the isolation it states, else the worker's default (a container when unset).
    pub fn for_job(&self, stated: Option<sentinel_pipeline::schema::Isolation>) -> Isolation {
        match stated {
            Some(sentinel_pipeline::schema::Isolation::Microvm) => Isolation::Microvm,
            Some(sentinel_pipeline::schema::Isolation::Container) => Isolation::Container,
            Some(sentinel_pipeline::schema::Isolation::Native) | None => {
                self.default.unwrap_or(Isolation::Container)
            }
        }
    }
}

pub const SECRET_FILES_MOUNT: &str = "/run/sentinel-secrets";
pub const SECRET_ENV_MOUNT: &str = "/run/sentinel-env";

pub fn secret_root(root: &Path) -> PathBuf {
    crate::runtime_dir(root).join("secret-delivery")
}

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
    let tenant = job
        .context
        .tenant
        .ok_or_else(|| Error::Preparation("registry auth without a tenant".into()))?;
    podman::Store::private(root, *tenant.as_bytes())
}

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
    // Created owner-only in one step, so a secret directory never shows the umask's mode.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
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

fn create_mounted_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn create_secret_file(path: &Path) -> Result<std::fs::File> {
    create_file_mode(path, 0o600)
}

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(file)
}

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

/// Values reach the step by sourced file, never through Podman or argv, which would persist them.
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

pub trait Report: Send + Sync {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event);
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>);
    fn cache_note(&self, _attempt: AttemptId, _note: CacheNote) {}
    fn costly_hit(
        &self,
        _attempt: AttemptId,
        _name: &str,
        _costly: sentinel_cache::Costly,
        _stats: &sentinel_cache::Stats,
    ) {
    }
    fn remote(&self) -> Option<Arc<dyn sentinel_cache::remote::Remote>> {
        None
    }
    /// The worker's measured restore and rebuild costs; without one the fixed default rule applies.
    fn cost_book(&self) -> Option<&sentinel_cache::CostBook> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheNote {
    pub name: String,
    pub outcome: CacheOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheOutcome {
    Sealed {
        generation: String,
        bytes: u64,
        reused_bytes: u64,
    },
    Skipped(&'static str),
    Failed(String),
}

pub trait Output: Send + Sync {
    fn write(&self, step: u32, stream: Stream, bytes: &[u8]);
    fn complete(&self) -> bool;
    fn step_done(&self, _step: u32) {}
    fn redact(&self, text: String) -> String {
        text
    }
    fn excerpt(&self, stderr: &[u8]) -> String {
        crate::redact::excerpt(stderr)
    }
}

pub struct NoOutput;
impl Output for NoOutput {
    fn write(&self, _: u32, _: Stream, _: &[u8]) {}
    fn complete(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Passed,
    Failed(FailureClass, String),
}

pub type Cancel = Arc<AtomicBool>;

fn ns(started: Instant) -> Option<u64> {
    Some(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
}

pub fn run(
    root: &Path,
    job: &mut Job,
    report: &dyn Report,
    output: Arc<dyn Output>,
    sink: &dyn artifacts::Sink,
    cancel: &Cancel,
) -> (Verdict, AttemptSummary) {
    report.event(job.attempt, job.fence, Event::PreparationStarted);
    let remote = report.remote();
    let mut summary = AttemptSummary::default();
    let prepared = prepare(root, job, cancel, &mut summary, remote.as_deref());
    // Judged once, before publication rewrites the carrier's stats, so the notice and the summary agree.
    let costly: Vec<Option<sentinel_cache::Costly>> = job
        .caches
        .iter()
        .map(|attached| {
            let verdict = match report.cost_book() {
                Some(book) => {
                    let verdict = attached.costly_hit_with(book);
                    book.observe(attached);
                    verdict
                }
                None => attached.costly_hit(),
            };
            if let Some(costly) = verdict {
                report.costly_hit(job.attempt, &attached.name, costly, &attached.stats);
            }
            verdict
        })
        .collect();
    let mut sealed: Vec<SealedCache> = Vec::new();
    let verdict = match prepared {
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
                &prepared.sandbox,
                prepared.workspace.path(),
                prepared.secret_directory.as_ref(),
                &output,
                cancel,
                &mut summary,
            );
            summary.steps_ns = ns(started);
            report.event(job.attempt, job.fence, Event::FinalizationStarted);
            let started = Instant::now();
            let declared = job
                .spec
                .pipeline
                .jobs
                .get(job.job_index)
                .map(|j| j.spec.artifacts.as_slice())
                .unwrap_or(&[]);
            let paths: Vec<String> = declared
                .iter()
                .flat_map(|a| a.paths.iter().cloned())
                .collect();
            if let Err(e) = prepared.sandbox.sync_out(prepared.workspace.path(), &paths) {
                summary.detail = format!("copying results out of the microVM: {e}");
            }
            let artifact_failure = capture_artifacts(
                job.attempt,
                prepared.workspace.path(),
                declared,
                matches!(verdict, Verdict::Passed),
                sink,
            );
            sealed = finalize(root, job, &verdict, report, prepared, cancel);
            let published = output.complete();
            if published {
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
    // Job-printed values can reach these strings: redact them before they leave the attempt.
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
            summary.detail = failure_detail(why, &summary.detail);
            Event::Failed(*class)
        }
    };
    summary.caches = job
        .caches
        .iter()
        .zip(&costly)
        .take(MAX_CACHE_RECORDS)
        .map(|(attached, costly)| cache_record(attached, costly.is_some()))
        .collect();
    match summary.encode() {
        Ok(bytes) => report.finish(job.attempt, job.fence, event, bytes),
        Err(_) => report.event(job.attempt, job.fence, event),
    }
    offer_caches(root, job, &sealed, remote.as_deref(), cancel);
    (verdict, summary)
}

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
    let image = sentinel_pipeline::run::ImageRef::parse(&compiled.spec.image)
        .map_err(|_| Error::Preparation("image reference".into()))?;
    let image = format!("{}@{}", image.name, job.digest);
    let declared = compiled.spec.cache.clone();
    let resources = compiled.spec.resources;
    let timeout_secs = compiled.spec.timeout_secs;
    let stated_isolation = compiled.spec.runs_on.isolation;
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
            let _ = join_checkout(&mut co, summary);
            return Err(Error::Preparation("canceled".into()));
        }
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
            summary.image_present = Some(*present);
        }
        let checked_out = join_checkout(&mut co, summary);
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        checked_out.and(pulled)?;
        let store = store?;
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
        let limits = Limits {
            cpu_millis: resources.cpu_millis,
            memory_bytes: resources.memory_bytes,
            pids: DEFAULT_PIDS_LIMIT,
            disk_bytes: resources.disk_bytes,
            lifetime_secs: timeout_secs
                .max(1)
                .saturating_add(podman::KEEPALIVE_SLACK_SECS),
        };
        let sandbox = match job.runtime.for_job(stated_isolation) {
            Isolation::Container => Sandbox::Container(Container::start_canceled(
                job.worker,
                job.attempt,
                &image,
                limits,
                workspace.path(),
                &mounts,
                &store,
                job.network,
                cancel,
            )?),
            Isolation::Microvm => {
                let setup = job.runtime.microvm.as_deref().ok_or_else(|| {
                    Error::Preparation("this worker has no microVM executor".into())
                })?;
                Sandbox::Vm(microvm::Vm::start(
                    root,
                    setup,
                    job.worker,
                    job.attempt,
                    &image,
                    limits,
                    workspace.path(),
                    &mounts,
                    &store,
                    job.network,
                )?)
            }
        };
        summary.container_start_ns = ns(started);
        Ok(sandbox)
    })();
    match outcome {
        Ok(sandbox) => Ok(PreparedExecution {
            workspace,
            sandbox,
            secret_directory,
        }),
        Err(e) => {
            let _ = workspace.destroy();
            Err(e)
        }
    }
}

type CheckoutThread = std::thread::JoinHandle<Result<(checkout::Outcome, Option<u64>)>>;

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
    let job_timeout = job
        .spec
        .pipeline
        .jobs
        .get(job.job_index)
        .map(|j| Duration::from_secs(j.spec.timeout_secs.max(1)))
        .unwrap_or(Duration::ZERO);
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

/// Exit codes 125-127 also come from the shell, so the runtime's `Error:` line decides.
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
    container: &Sandbox,
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
            // Clear strays before materializing secrets: no earlier process may watch them.
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
        let cleared = if secret_step
            && exec.as_ref().is_ok_and(|exit| !exit.timed_out)
            && !cancel.load(Ordering::Acquire)
        {
            container.clear_strays().map(|_| ())
        } else {
            Ok(())
        };
        drop(step_secrets);
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

fn cache_worthy(verdict: &Verdict) -> bool {
    match verdict {
        Verdict::Passed => true,
        Verdict::Failed(class, _) => matches!(
            class,
            FailureClass::CommandFailed | FailureClass::CommandSignaled | FailureClass::OutOfMemory
        ),
    }
}

fn cache_record(attached: &sentinel_cache::attach::Attached, costly_hit: bool) -> CacheRecord {
    let stats = &attached.stats;
    let (staged, reused, dirty, publish) = match stats.committed {
        Some(sentinel_cache::Committed::Sealed {
            staged_bytes,
            reused_bytes,
        }) => (
            Some(staged_bytes),
            Some(reused_bytes),
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
        costly_hit,
    }
}

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
        let committed = sentinel_cache::publish::commit_with_budget(
            &cache_root,
            job.cache_budget_bytes,
            attached,
            job.context.trust,
            sentinel_core::UnixMillis::now(),
            deadline,
            &canceled,
        );
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
    sandbox: Sandbox,
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
        sandbox,
        secret_directory,
    } = prepared;
    // Stop the sandbox first: no job process may rewrite the views publication reads.
    let _ = sandbox.destroy();
    drop(secret_directory);
    let sealed = if cache_worthy(verdict) {
        publish_caches(root, job, report, cancel)
    } else {
        Vec::new()
    };
    let _ = workspace.destroy();
    sealed
}

struct SealedCache {
    index: usize,
    generation: String,
}

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
        let argv = wrap_with_env(
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf '%s' \"$TRICKY\" > \"$0\"; printf '%s' \"${#BIG}\" > \"$0.len\"".into(),
                temp.path().join("seen").display().to_string(),
            ],
            3,
        );
        assert!(
            argv.iter()
                .all(|a| !a.contains("$HOME `id`") && !a.contains(&big))
        );
        let script = argv[2].replace(SECRET_ENV_MOUNT, &directory.env_dir.display().to_string());
        let status = std::process::Command::new(&argv[0])
            .arg(&argv[1])
            .arg(script)
            .args(&argv[3..])
            .env_clear()
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(temp.path().join("seen")).unwrap(),
            tricky
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("seen.len")).unwrap(),
            big.len().to_string()
        );
        drop(paths);
        assert!(!env.exists());
    }

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
            cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
            mirrors: None,
            prepare_hold: Duration::ZERO,
            network: podman::Network::None,
            runtime: Default::default(),
            secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        }
    }

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
        let vendor = ws.join("vendor");
        assert!(vendor.is_dir());
        fs::write(vendor.join("fresh"), b"x").unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].container, "/opt/cc");
        assert_eq!(mounts[0].host, attached.targets[1].dir);
        assert!(mounts[0].host.is_dir());

        let record = cache_record(attached, attached.costly_hit().is_some());
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
        let record = cache_record(attached, attached.costly_hit().is_some());
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

    #[test]
    fn publish_uses_the_attempt_cache_budget() {
        const BUDGET: u64 = 1 << 30;

        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec());
        job.cache_budget_bytes = BUDGET;
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
        restore_caches(&root, &mut job, &declared, &ws, &image, None);
        let huge = fs::File::create(ws.join("vendor/lib")).unwrap();
        huge.set_len(BUDGET / 4 + 1).unwrap();
        let notes = Notes::default();
        let flag: Cancel = Arc::new(AtomicBool::new(false));
        let sealed = publish_caches(&root, &mut job, &notes, &flag);

        assert!(sealed.is_empty());
        assert!(matches!(
            job.caches[0].stats.committed,
            Some(sentinel_cache::Committed::Failed)
        ));
        assert!(matches!(
            notes.cache_notes.lock().unwrap().as_slice(),
            [CacheNote {
                outcome: CacheOutcome::Failed(_),
                ..
            }]
        ));
    }

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

        offer_caches(&root, &job, &sealed, None, &flag);
        assert!(job.caches[0].stats.committed.is_some());

        let recorder = Arc::new(Recorder::default());
        let transport: &dyn sentinel_cache::remote::Remote = recorder.as_ref();
        offer_caches(&root, &job, &sealed, Some(transport), &flag);
        let offered = recorder.offered.lock().unwrap();
        assert_eq!(offered.len(), 1);
        assert!(offered[0].0.starts_with("deps-"), "{}", offered[0].0);
        let offered_len = offered[0].1;
        drop(offered);

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
        let record = cache_record(attached, attached.costly_hit().is_some());
        assert!(record.costly_hit);
        assert_eq!(record.outcome, "hit");
    }

    fn spec_compiler() -> RunSpec {
        let yaml = "schema: 1\non: [push]\njobs:\n  main:\n    image: example.test/i:1@sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n    resources: { cpu: 1, memory: 128MiB }\n    cache:\n      - name: cc\n        class: compiler\n        key: cc-normal-${{ hash_files('f.lock') }}\n        paths: [ccache]\n    steps: [{ id: build, run: 'cc -c a.c' }, { id: test, run: './run-tests' }]\n";
        RunSpec::new(
            PinnedSource::new("file:///nowhere", &"a".repeat(40), Some("main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap()
    }

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
        let context = WorkerContext::new(&job.context, &job.spec, ws);
        let key = decl
            .key
            .render(&context, sentinel_cache::attach::MAX_KEY_BYTES)
            .unwrap();
        let compat = sentinel_cache::attach::declared_compat(decl, &key, platform);
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

    #[test]
    fn a_cache_hit_restores_bytes_and_never_touches_the_step_plan() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("worker"), temp.path().join("ws"));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f.lock"), b"locked").unwrap();
        let mut job = job(spec_compiler());
        let declared = job.spec.pipeline.jobs[0].spec.cache.clone();
        let image = format!("example.test/i@{}", job.digest);
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
        assert_eq!(job.spec, spec_compiler());
        let steps = &job.spec.pipeline.jobs[0].spec.steps;
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].id, "build");
        assert_eq!(steps[1].id, "test");
    }
}
