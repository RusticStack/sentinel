//! One attempt from offer to terminal: prepare (workspace, checkout, image,
//! container), run the steps in order, finalize (tear everything down), and
//! report each phase under the attempt's fence.
//!
//! The verdict follows the run spec's contract: exit 0 passes, any other
//! status is `CommandFailed`, death by signal `CommandSignaled`, a step past
//! its timeout `ExecutionTimeout`. Anything that stops the steps from
//! starting — a fetch that fails, an image that will not pull, a container
//! that will not start — is `Preparation`, never a failed command. A cancel
//! seen between steps is `Canceled`. Teardown runs on every path.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use sentinel_core::{AttemptId, Event, FailureClass, Fence, JobId, RunId, WorkerId};
use sentinel_pipeline::RunSpec;

use crate::{
    Error, Result,
    checkout::{self, CHECKOUT_TIMEOUT},
    podman::{self, Container, DEFAULT_PIDS_LIMIT, Limits},
    workspace::Workspace,
};

/// What the attempt is: identity, fence, the spec and which job of it.
pub struct Job {
    pub worker: WorkerId,
    pub attempt: AttemptId,
    pub fence: Fence,
    pub run: RunId,
    pub job: JobId,
    pub job_index: usize,
    /// `sha256:…`, as the controller resolved it; the name is the spec's.
    pub digest: String,
    pub spec: RunSpec,
}

/// Where the phases are reported. Ordered per attempt; the link's reporter
/// or a test's recorder.
pub trait Report: Send + Sync {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event);
}

/// How a step ended, for diagnostics beyond the verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepExit {
    pub index: usize,
    pub exit: podman::Exit,
}

/// The attempt's verdict as reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Passed,
    Failed(FailureClass, String),
}

/// The per-attempt cancel flag the executor flips on `stop`.
pub type Cancel = Arc<AtomicBool>;

/// Run the whole attempt. Returns the verdict that was reported and every
/// step's exit for the caller's diagnostics.
pub fn run(
    root: &Path,
    job: &Job,
    report: &dyn Report,
    cancel: &Cancel,
) -> (Verdict, Vec<StepExit>) {
    report.event(job.attempt, job.fence, Event::PreparationStarted);
    let mut steps = Vec::new();
    let verdict = match prepare(root, job, cancel) {
        Err(e) => Verdict::Failed(FailureClass::Preparation, e.to_string()),
        Ok((workspace, container)) => {
            report.event(job.attempt, job.fence, Event::StepsStarted);
            let verdict = execute(job, &container, cancel, &mut steps);
            report.event(job.attempt, job.fence, Event::FinalizationStarted);
            finalize(workspace, container);
            verdict
        }
    };
    report.event(
        job.attempt,
        job.fence,
        match &verdict {
            Verdict::Passed => Event::Passed,
            Verdict::Failed(class, _) => Event::Failed(*class),
        },
    );
    (verdict, steps)
}

fn prepare(root: &Path, job: &Job, cancel: &Cancel) -> Result<(Workspace, Container)> {
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
        checkout::checkout(workspace.path(), &job.spec.source, None, CHECKOUT_TIMEOUT)?;
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        podman::pull(&image, podman::IMAGE_PULL_TIMEOUT)?;
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        let resources = compiled.spec.resources;
        Container::start(
            job.worker,
            job.attempt,
            &image,
            Limits {
                cpu_millis: resources.cpu_millis,
                memory_bytes: resources.memory_bytes,
                pids: DEFAULT_PIDS_LIMIT,
            },
            workspace.path(),
        )
    })();
    match outcome {
        Ok(container) => Ok((workspace, container)),
        Err(e) => {
            let _ = workspace.destroy();
            Err(e)
        }
    }
}

fn execute(
    job: &Job,
    container: &Container,
    cancel: &Cancel,
    steps: &mut Vec<StepExit>,
) -> Verdict {
    let extra = [
        ("SENTINEL_RUN".to_owned(), job.run.to_string()),
        ("SENTINEL_JOB".to_owned(), job.job.to_string()),
        ("SENTINEL_ATTEMPT".to_owned(), job.attempt.to_string()),
        ("SENTINEL_SHA".to_owned(), job.spec.source.sha.clone()),
        (
            "SENTINEL_WORKSPACE".to_owned(),
            podman::WORKSPACE_MOUNT.to_owned(),
        ),
        ("CI".to_owned(), "true".to_owned()),
    ];
    let count = job.spec.pipeline.jobs[job.job_index].spec.steps.len();
    for index in 0..count {
        if cancel.load(Ordering::Acquire) {
            return Verdict::Failed(FailureClass::Canceled, "canceled before the step".into());
        }
        let Some(command) = job.spec.step_command(job.job_index, index) else {
            return Verdict::Failed(FailureClass::Preparation, "step outside the spec".into());
        };
        let exit = match container.exec(&command, &extra) {
            Ok(exit) => exit,
            Err(e) => return Verdict::Failed(FailureClass::Preparation, e.to_string()),
        };
        let verdict = if exit.timed_out {
            Some((
                FailureClass::ExecutionTimeout,
                format!("step {index} exceeded {} s", command.timeout_secs),
            ))
        } else if let Some(signal) = exit.signal {
            Some((
                FailureClass::CommandSignaled,
                format!("step {index} died from signal {signal}"),
            ))
        } else if exit.code != Some(0) {
            Some((
                FailureClass::CommandFailed,
                format!("step {index} exited with {}", exit.code.unwrap_or(-1)),
            ))
        } else {
            None
        };
        steps.push(StepExit { index, exit });
        if let Some((class, why)) = verdict {
            return Verdict::Failed(class, why);
        }
    }
    Verdict::Passed
}

fn finalize(workspace: Workspace, container: Container) {
    // Both run even when one fails: a container that will not stop must not
    // keep a workspace alive, and vice versa. The failure is a reconciliation
    // matter for W07, which lists what this worker still owns.
    let _ = container.destroy();
    let _ = workspace.destroy();
}
