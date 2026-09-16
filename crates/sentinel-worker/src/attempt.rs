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
    path::Path,
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
    summary::{AttemptSummary, StepOutcome, StepRecord},
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
pub struct Job {
    pub worker: WorkerId,
    pub attempt: AttemptId,
    pub fence: Fence,
    pub job_index: usize,
    /// `sha256:…`, as the controller resolved it; the name is the spec's.
    pub digest: String,
    pub spec: RunSpec,
    pub context: JobContext,
    /// The worker's image pulls: concurrent attempts share one download
    /// per `name@sha256:…`.
    pub images: Images,
    /// The job's declared caches as restored for this attempt: filled by
    /// preparation (K02), read back by finalization (K03). The carrier is
    /// `sentinel_cache::Attached` — each entry holds its scope, rendered
    /// key, the outcome that produced the view and the private writable
    /// directory the container saw.
    pub caches: Vec<sentinel_cache::attach::Attached>,
    /// A pause between starting the checkout and pulling the image, so a
    /// cancel that arrives during preparation can be exercised
    /// deterministically. Zero in production.
    pub prepare_hold: std::time::Duration,
}

/// Where the phases are reported. Ordered per attempt; the link's reporter
/// or a test's recorder.
pub trait Report: Send + Sync {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event);
    /// The terminal event with the encoded summary.
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>);
}

/// Where step output goes (W05): the executor's spool and link. Writes are
/// called from the reader threads with small chunks and must be quick;
/// `complete` runs after the last step and blocks, bounded, until the log
/// is acknowledged and closed, returning whether that happened.
pub trait Output: Send + Sync {
    fn write(&self, step: u32, stream: Stream, bytes: &[u8]);
    fn complete(&self) -> bool;
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
    let mut summary = AttemptSummary::default();
    let verdict = match prepare(root, job, cancel, &mut summary) {
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
        Ok((workspace, container)) => {
            report.event(job.attempt, job.fence, Event::StepsStarted);
            let started = Instant::now();
            let verdict = execute(
                job,
                &container,
                workspace.path(),
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
                workspace.path(),
                declared,
                matches!(verdict, Verdict::Passed),
                sink,
            );
            finalize(workspace, container);
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
    let event = match &verdict {
        Verdict::Passed => Event::Passed,
        Verdict::Failed(class, why) => {
            summary.detail = why.chars().take(500).collect();
            Event::Failed(*class)
        }
    };
    match summary.encode() {
        Ok(bytes) => report.finish(job.attempt, job.fence, event, bytes),
        Err(_) => report.event(job.attempt, job.fence, event),
    }
    (verdict, summary)
}

fn prepare(
    root: &Path,
    job: &mut Job,
    cancel: &Cancel,
    summary: &mut AttemptSummary,
) -> Result<(Workspace, Container)> {
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
    let outcome = (|| {
        // The checkout and the image pull are independent — one fills the
        // fresh workspace, the other the worker's content store — so the
        // checkout runs on its own thread while the pull overlaps it here,
        // joined before the container starts. Each summary field still
        // measures its own phase's wall time, so `checkout_ns` and
        // `image_pull_ns` together can exceed the preparation's.
        let mut co = Some(std::thread::spawn({
            let path = workspace.path().to_path_buf();
            let source = job.spec.source.clone();
            let access = job.context.source.clone();
            move || -> Result<Option<u64>> {
                let started = Instant::now();
                match &access {
                    Some(access) => {
                        checkout::checkout_authorized(&path, &source, access, CHECKOUT_TIMEOUT)?
                    }
                    None => checkout::checkout(&path, &source, None, CHECKOUT_TIMEOUT)?,
                };
                Ok(ns(started))
            }
        }));
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
        let pulled = job.images.pull(&image, podman::IMAGE_PULL_TIMEOUT, cancel);
        if pulled.is_ok() {
            summary.image_pull_ns = ns(started);
        }
        // Join before the workspace could be torn down under a checkout
        // still running. The first failure wins — the checkout's ahead of
        // the pull's, as when the two ran in sequence.
        let checked_out = join_checkout(&mut co, summary);
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        checked_out.and(pulled)?;
        // K02: attach the declared caches — each hit is cloned into the
        // job's private view, each miss still leaves the writable target
        // directories a job always sees. Never fatal: a cache-path error
        // is an explainable miss recorded on the entry. Absolute declared
        // paths reach the container through the collected bind mounts.
        let mounts = restore_caches(root, job, &declared, workspace.path(), &image);
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
        )?;
        summary.container_start_ns = ns(started);
        Ok(container)
    })();
    match outcome {
        Ok(container) => Ok((workspace, container)),
        Err(e) => {
            let _ = workspace.destroy();
            Err(e)
        }
    }
}

/// Join the checkout thread, once — `None` after the first call. A thread
/// that could not produce its result is a preparation failure like the
/// checkout's own; `checkout_ns` is stamped only when the checkout
/// completed, as a lone call was.
fn join_checkout(
    co: &mut Option<std::thread::JoinHandle<Result<Option<u64>>>>,
    summary: &mut AttemptSummary,
) -> Result<()> {
    let Some(handle) = co.take() else {
        return Ok(());
    };
    let done = handle
        .join()
        .unwrap_or_else(|_| Err(Error::Preparation("checkout thread failed".into())));
    summary.checkout_ns = done.as_ref().ok().copied().flatten();
    done?;
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
/// toolchain descriptor every scope is built under.
fn restore_caches(
    root: &Path,
    job: &mut Job,
    declared: &[sentinel_pipeline::schema::Cache],
    workspace: &Path,
    image: &str,
) -> Vec<podman::Mount> {
    if declared.is_empty() {
        return Vec::new();
    }
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
            Some(sentinel_cache::restore::restore(
                &env, decl, key, scope, &owner,
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
        let sink: crate::process::Sink = {
            let output = Arc::clone(output);
            let step_index = index as u32;
            Arc::new(move |stream, bytes: &[u8]| output.write(step_index, stream, bytes))
        };
        let exit = match container.exec_streaming(&command, &extra, Some(sink)) {
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
                    format!("step {index}: {}", exit.stderr_excerpt()),
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

fn finalize(workspace: Workspace, container: Container) {
    // Both run even when one fails: a container that will not stop must not
    // keep a workspace alive, and vice versa. The failure is a reconciliation
    // matter for W07, which lists what this worker still owns.
    let _ = container.destroy();
    let _ = workspace.destroy();
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sentinel_core::{JobId, RepoId, RunId};
    use sentinel_link::session::EventContext;
    use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
    use sentinel_protocol::cache::Trust;

    use super::*;

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
            images: Images::new(),
            caches: Vec::new(),
            prepare_hold: Duration::ZERO,
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
        let mounts = restore_caches(&root, &mut job, &declared, &ws, &image);

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
    }
}
