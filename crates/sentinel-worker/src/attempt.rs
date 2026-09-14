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
    summary::{AttemptSummary, StepOutcome, StepRecord},
};

use crate::{
    Error, Result,
    checkout::{self, CHECKOUT_TIMEOUT},
    context::WorkerContext,
    podman::{self, Container, DEFAULT_PIDS_LIMIT, Limits},
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
    /// A pause between checkout and image pull, so a cancel that arrives
    /// during preparation can be exercised deterministically. Zero in
    /// production.
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
/// reported.
pub fn run(
    root: &Path,
    job: &Job,
    report: &dyn Report,
    output: Arc<dyn Output>,
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
            let _ = output.complete();
            Verdict::Failed(FailureClass::Canceled, "canceled during preparation".into())
        }
        Err(e) => {
            let _ = output.complete();
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
            finalize(workspace, container);
            // The log is part of finalization: the attempt is not done until
            // what it printed is durable on the controller, or the wait ran
            // out and the failure is on record.
            let published = output.complete();
            summary.finalize_ns = ns(started);
            match (verdict, published) {
                (Verdict::Passed, false) => Verdict::Failed(
                    FailureClass::Publication,
                    "log frames were not acknowledged in time".into(),
                ),
                (verdict, _) => verdict,
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
    job: &Job,
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
    let workspace = Workspace::create(root, job.attempt)?;
    let outcome = (|| {
        let started = Instant::now();
        match &job.context.source {
            Some(access) => checkout::checkout_authorized(
                workspace.path(),
                &job.spec.source,
                access,
                CHECKOUT_TIMEOUT,
            )?,
            None => checkout::checkout(workspace.path(), &job.spec.source, None, CHECKOUT_TIMEOUT)?,
        };
        summary.checkout_ns = ns(started);
        if !job.prepare_hold.is_zero() {
            let until = Instant::now() + job.prepare_hold;
            while Instant::now() < until && !cancel.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        let started = Instant::now();
        podman::pull(&image, podman::IMAGE_PULL_TIMEOUT)?;
        summary.image_pull_ns = ns(started);
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        let resources = compiled.spec.resources;
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
