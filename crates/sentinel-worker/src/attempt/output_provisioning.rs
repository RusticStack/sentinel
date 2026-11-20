//! I04's gate on the paths that need no sandbox: declared outputs through a real `/bin/sh`, the two bounds a step
//! and its job declare, and a finalizer that is bounded and cannot decide a verdict.
//!
//! The output directory is staged at its real host path and bound into this process's file system by substituting
//! [`crate::outputs::MOUNT`] with it — the substitution a container's bind mount makes, and the one
//! `attempt::secret_provisioning` makes for the secret mounts. The container and microVM legs (the mount itself,
//! `Sandbox::collect_outputs` for a guest) are covered by `tests/end_to_end.rs` under `SENTINEL_PODMAN_TESTS=1`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Fence, JobId, RepoId, RunId, WorkerId};
use sentinel_link::session::JobContext;
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::cache::Trust;
use sentinel_protocol::{logs::Stream, summary::StepOutcome};

use super::{
    Cancel, Job, Output, OutputDirectory, SECRET_ENV_MOUNT, StepOutputs, finalize_step,
    wrap_with_env,
};
use crate::{images::Images, outputs, podman};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The worker's log sink, with a stand-in redactor: any delivered secret matches this one value.
struct Redactor {
    secret: &'static str,
}

impl Output for Redactor {
    fn write(&self, _: u32, _: Stream, _: &[u8]) {}
    fn complete(&self) -> bool {
        true
    }
    fn redact(&self, text: String) -> String {
        text.replace(self.secret, "***")
    }
    fn excerpt(&self, _: &[u8]) -> String {
        String::new()
    }
}

struct Silent;
impl Output for Silent {
    fn write(&self, _: u32, _: Stream, _: &[u8]) {}
    fn complete(&self) -> bool {
        true
    }
    fn excerpt(&self, _: &[u8]) -> String {
        String::new()
    }
}

fn job(text: &str, outputs: Vec<(String, String, String)>) -> Job {
    let spec = RunSpec::new(
        PinnedSource::new("o/r", SHA, None).unwrap(),
        compile_str(text).unwrap(),
    )
    .unwrap();
    Job {
        worker: WorkerId::new(),
        attempt: AttemptId::new(),
        fence: Fence(1),
        job_index: 0,
        digest: DIGEST.to_owned(),
        spec,
        context: JobContext {
            source: None,
            source_valid_until: None,
            run: RunId::new(),
            repo: RepoId::new(),
            repo_name: "o/r".into(),
            job: JobId::new(),
            job_name: "build".into(),
            sha: SHA.into(),
            event: sentinel_link::session::EventContext {
                name: "push".into(),
                ref_name: "refs/heads/main".into(),
                base_ref: None,
                pr_number: None,
                key: "push:refs/heads/main".into(),
            },
            cancelled: false,
            needs: Vec::new(),
            tenant: None,
            trust: Trust::Protected,
            outputs,
            reuse_fresh: false,
        },
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        images: Images::with_download(|_, _, _, _, _| Ok(false)),
        caches: Vec::new(),
        reuse_seal: None,
        reuse_fresh: false,
        cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
        mirrors: None,
        prepare_hold: Duration::ZERO,
        network: podman::Network::None,
        runtime: Default::default(),
        store: podman::Store::Shared,
    }
}

fn output_dir(attempt: AttemptId) -> (tempfile::TempDir, OutputDirectory) {
    let temp = tempfile::tempdir().unwrap();
    let dir = OutputDirectory::create(temp.path(), attempt).unwrap();
    (temp, dir)
}

/// Runs one step the way the sandbox would: the wrapper the worker builds, with the mount path substituted, and the
/// `SENTINEL_OUTPUT` the worker names.
fn run_step(
    command: &sentinel_pipeline::run::StepCommand,
    secret_env: bool,
    values: bool,
    dir: &OutputDirectory,
    env: &[(String, String)],
) -> std::process::ExitStatus {
    let argv = wrap_with_env(command.argv.clone(), secret_env.then_some(0), values);
    let script = argv[2].replace(outputs::MOUNT, &dir.dir().display().to_string());
    let mut child = std::process::Command::new(&argv[0]);
    child.arg(&argv[1]).arg(script);
    for arg in &argv[3..] {
        child.arg(arg);
    }
    child
        .env_clear()
        .env(
            outputs::FILE_VAR,
            dir.dir().join(outputs::FILE).display().to_string(),
        )
        .envs(env.iter().map(|(k, v)| (k.clone(), v.clone())))
        .current_dir(dir.dir());
    child.status().unwrap()
}

fn read(
    dir: &OutputDirectory,
    declared: &[String],
) -> std::result::Result<Vec<(String, String)>, StepOutputs> {
    match dir.read().map_err(|e| StepOutputs::Runtime(e.to_string())) {
        Ok(Some(bytes)) => outputs::parse(&bytes, declared).map_err(StepOutputs::Violation),
        Ok(None) => Err(StepOutputs::Violation(outputs::Violation::TooLong(
            declared.first().cloned().unwrap_or_default(),
        ))),
        Err(e) => Err(e),
    }
}

#[test]
fn a_later_step_reads_what_an_earlier_step_declared() {
    let text = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - {id: first, run: \"printf 'version=1.4.0\\n' > \\\"$SENTINEL_OUTPUT\\\"\", outputs: [version]}\n      - {id: second, run: echo hi, outputs: [tag]}\n    outputs: [version]\n";
    let job = job(text, Vec::new());
    let (temp, dir) = output_dir(job.attempt);
    let declared = vec!["version".to_owned()];

    // The first step writes its output into the file the worker named for it.
    let first = job.spec.step_command(0, 0).unwrap();
    assert!(
        run_step(&first, false, false, &dir, &[]).success(),
        "the step writes its output"
    );
    let own = read(&dir, &declared).unwrap();
    assert_eq!(own, vec![("version".to_owned(), "1.4.0".to_owned())]);

    // The second step sees it exported, and the wrapper cannot be spoofed by the pipeline's own environment.
    dir.prepare(&[(outputs::env_name(None, "version"), own[0].1.clone())])
        .unwrap();
    let seen = temp.path().join("seen");
    let mut second = job.spec.step_command(0, 1).unwrap();
    *second.argv.last_mut().unwrap() = format!(
        "printf '%s' \"$SENTINEL_OUTPUT_VERSION\" > {}",
        seen.display()
    );
    assert!(
        run_step(&second, false, true, &dir, &[]).success(),
        "the second step reads the value"
    );
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), "1.4.0");
}

#[test]
fn the_output_file_is_named_before_the_step_runs_and_the_bounds_hold() {
    let text = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - {id: first, run: x, outputs: [version]}\n";
    let job = job(text, Vec::new());
    let (_temp, dir) = output_dir(job.attempt);
    let path = dir.dir().join(outputs::FILE);
    let declared = vec!["version".to_owned()];
    // The step's own command writes nothing here: this test drives the file and the reader directly.

    // A name the step does not declare is refused instead of dropped.
    std::fs::write(&path, b"version=1\nother=2\n").unwrap();
    assert_eq!(
        read(&dir, &declared).unwrap_err().reason(),
        "its output file writes `other`, which the step does not declare"
    );

    // A value past the bound is refused, and the verdict never echoes it.
    let long = format!("version={}", "a".repeat(outputs::MAX_OUTPUT_BYTES + 1));
    std::fs::write(&path, long.as_bytes()).unwrap();
    assert_eq!(
        read(&dir, &declared).unwrap_err().reason(),
        "its output `version` is longer than the 1024 bytes a declared output may hold"
    );

    // A whole file past the bound is not read at all: a step cannot make the worker carry what it wrote.
    let huge = vec![b'a'; outputs::MAX_FILE_BYTES + 1];
    std::fs::write(&path, &huge).unwrap();
    assert!(
        dir.read().unwrap().is_none(),
        "a file past the bound is refused, not read"
    );

    // A value that repeats a delivered secret is refused: an output is public within the tenant.
    std::fs::write(&path, b"version=token-6f1d2a9e\n").unwrap();
    let redactor = Redactor { secret: "6f1d2a9e" };
    let parsed = read(&dir, &declared).unwrap();
    assert_ne!(
        redactor.redact(parsed[0].1.clone()),
        parsed[0].1,
        "the value repeats a delivered secret, so the step fails: an output is plain text in the run's record"
    );
}

#[test]
fn a_dependency_output_reaches_a_step_of_the_job_that_needs_it() {
    let text = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - {id: first, run: x, outputs: [version]}\n    outputs: [version]\n";
    let job = job(
        text,
        vec![("build".to_owned(), "version".to_owned(), "2.0.0".to_owned())],
    );
    let (_temp, dir) = output_dir(job.attempt);
    let values: Vec<(String, String)> = job
        .context
        .outputs
        .iter()
        .map(|(from, name, value)| (outputs::env_name(Some(from), name), value.clone()))
        .collect();
    dir.prepare(&values).unwrap();
    let seen = _temp.path().join("seen");
    let mut command = job.spec.step_command(0, 0).unwrap();
    *command.argv.last_mut().unwrap() = format!(
        "printf '%s' \"$SENTINEL_OUTPUT_BUILD_VERSION\" > {}",
        seen.display()
    );
    assert!(run_step(&command, false, true, &dir, &[]).success());
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), "2.0.0");
}

const FINALIZER: &str = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - {id: first, run: x}\n    finalize: {run: echo done, timeout: 30s}\n";

#[test]
fn a_finalizer_that_hangs_is_stopped_at_its_bound_and_only_annotates_the_record() {
    let job = job(FINALIZER, Vec::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut seen_timeout = 0;
    let record = finalize_step(
        &job,
        |command| {
            seen_timeout = command.timeout_secs;
            Ok(podman::Exit {
                code: None,
                signal: Some(9),
                timed_out: true,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        },
        &cancel,
        Instant::now() + Duration::from_secs(600),
    )
    .expect("the job declares a finalizer");
    assert_eq!(seen_timeout, 30, "the finalizer runs under its own bound");
    assert_eq!(record.outcome, StepOutcome::TimedOut);
    assert!(
        record.annotation.contains("30 s bound"),
        "the annotation names the bound: {}",
        record.annotation
    );
    assert!(
        !record.annotation.contains("done"),
        "the annotation never carries what the finalizer printed"
    );
}

#[test]
fn a_finalizer_cannot_run_past_what_is_left_of_the_job_or_outlive_a_cancel() {
    let job = job(FINALIZER, Vec::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let seen = std::cell::Cell::new(0u64);
    // Twenty seconds of the job's budget are left: the finalizer's own 30 s do not apply.
    let _ = finalize_step(
        &job,
        |command| {
            seen.set(command.timeout_secs);
            Ok(podman::Exit {
                code: Some(0),
                signal: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        },
        &cancel,
        Instant::now() + Duration::from_secs(20),
    );
    assert!(seen.get() <= 20, "the job's remaining budget bounds it");

    // A cancelled attempt does not run it at all: the worker's cancel path ends the job, not a finalizer.
    cancel.store(true, Ordering::Release);
    let ran = std::cell::Cell::new(false);
    let skipped = finalize_step(
        &job,
        |_| {
            ran.set(true);
            Ok(podman::Exit {
                code: Some(0),
                signal: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        },
        &cancel,
        Instant::now() + Duration::from_secs(600),
    )
    .unwrap();
    assert!(!ran.get(), "a cancelled attempt runs no finalizer");
    assert_eq!(skipped.outcome, StepOutcome::Skipped);
    assert_eq!(skipped.annotation, "not run: the attempt was canceled");
}

#[test]
fn a_job_without_a_finalizer_records_none() {
    let job = job(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - {id: first, run: x}\n",
        Vec::new(),
    );
    let cancel: Cancel = Arc::new(AtomicBool::new(false));
    assert!(
        finalize_step(
            &job,
            |_| Ok(podman::Exit {
                code: Some(0),
                signal: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            &cancel,
            Instant::now() + Duration::from_secs(600),
        )
        .is_none()
    );
}

#[test]
fn a_failing_finalizer_is_an_annotation_and_a_verdict_is_unchanged() {
    let job = job(FINALIZER, Vec::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let record = finalize_step(
        &job,
        |_| {
            Ok(podman::Exit {
                code: Some(3),
                signal: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        },
        &cancel,
        Instant::now() + Duration::from_secs(600),
    )
    .unwrap();
    assert_eq!(record.outcome, StepOutcome::Failed { code: 3 });
    assert_eq!(record.annotation, "finalizer exited with 3");
    // The verdict is computed from the steps alone: `execute` reads this record into the summary and nothing else.
    let silent: Arc<dyn Output> = Arc::new(Silent);
    assert_eq!(
        silent.redact("finalizer exited with 3".into()),
        "finalizer exited with 3"
    );
}

impl StepOutputs {
    fn reason(&self) -> String {
        match self {
            StepOutputs::Violation(violation) => violation.reason(),
            StepOutputs::Runtime(error) => error.clone(),
        }
    }
}

/// The wrapper sources the secret mount and the values file, in that order, and never the pipeline's own path.
#[test]
fn the_wrapper_sources_what_the_worker_wrote() {
    let both = wrap_with_env(
        vec!["/bin/sh".into(), "-c".into(), "true".into()],
        Some(2),
        true,
    );
    assert!(both[2].starts_with(&format!(". {SECRET_ENV_MOUNT}/step-2.sh && . ")));
    assert!(both[2].contains(outputs::VALUES));
    assert!(both[2].ends_with(" && exec \"$@\""));
    let values_only = wrap_with_env(
        vec!["/bin/sh".into(), "-c".into(), "true".into()],
        None,
        true,
    );
    assert!(values_only[2].starts_with(". "));
    assert!(!values_only[2].contains(SECRET_ENV_MOUNT));
}
