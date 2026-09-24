//! The real executor under faults the Part 04 audit found untested, each
//! against a live controller and rootless Podman (`SENTINEL_PODMAN_TESTS=1`
//! as the worker account, like `end_to_end.rs`):
//!
//! - P04-5: the worker's clock ahead of the controller's must not end live
//!   work — the lease is measured on the worker's own monotonic clock.
//! - P04-15: a cancel that arrives while a step's `podman exec` is still
//!   starting finds nothing to signal; the next heartbeat's cancel must try
//!   again instead of being dropped for the rest of the step.
//! - P04-27: a stop order must not run `podman rm -f` on the heartbeat
//!   thread, where a slow removal would hold the next heartbeat.
//!
//! `podman` is wrapped on `PATH` by a shim that passes every call to the
//! real binary, but can hold a step's `exec` or slow a removal on request.
//! The shim is process-wide, so the tests here run one at a time.

#![cfg(target_os = "linux")]

#[path = "support/live.rs"]
mod live;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use live::{DIGEST, IMAGE, Live, eventually, podman_enabled};
use sentinel_core::{AttemptId, JobState, Outcome, UnixMillis};
use sentinel_link::session::{ArtifactCode, Executor as LinkExecutor, JobContext, Offer, Reporter};
use sentinel_store::dispatch;
use sentinel_worker::{
    executor::{Executor, Notice},
    podman,
};

/// One test at a time: the shim's switches are process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

const SHIM: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
case "$1 $2" in
  "exec --workdir")
    # A step's exec, not the runtime's own: held while asked, so a cancel
    # can land while the step is still starting.
    if [ -e "$dir/hold-exec" ]; then
      : > "$dir/exec-held"
      i=0
      while [ -e "$dir/hold-exec" ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done
    fi ;;
  rm*)
    if [ -e "$dir/slow-rm" ]; then sleep 3; fi ;;
esac
exec REAL "$@"
"#;

/// The shim directory, first on `PATH` for this whole binary.
fn shim() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let real = std::process::Command::new("sh")
            .args(["-c", "command -v podman"])
            .output()
            .unwrap();
        let real = String::from_utf8(real.stdout).unwrap().trim().to_owned();
        assert!(!real.is_empty(), "podman not found");
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("podman");
        fs::write(&path, SHIM.replace("REAL", &real)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let joined = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // SAFETY: set once, before any test in this binary spawns a helper
        // (every test calls `shim()` first, and `OnceLock` serializes it).
        unsafe {
            std::env::set_var("PATH", joined);
        }
        dir
    })
}

/// The real executor, seen through the link: a skewed clock on renewals,
/// and a record of the cancel and stop orders and how long a stop held the
/// heartbeat thread.
struct Probe {
    inner: Executor,
    /// Milliseconds the worker's wall clock is ahead of the controller's.
    skew_ms: i64,
    cancels: AtomicUsize,
    stops: Mutex<Vec<Duration>>,
    notices: Arc<Mutex<Vec<String>>>,
}

impl Probe {
    fn start(dir: &std::path::Path, worker: sentinel_core::WorkerId, skew_ms: i64) -> Probe {
        let notices = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&notices);
        let inner = Executor::start(
            dir.to_path_buf(),
            worker,
            move |notice: Notice| log.lock().unwrap().push(format!("{notice:?}")),
            false,
        )
        .unwrap();
        inner.set_cancel_grace(Duration::from_secs(2));
        Probe {
            inner,
            skew_ms,
            cancels: AtomicUsize::new(0),
            stops: Mutex::new(Vec::new()),
            notices,
        }
    }

    fn noticed(&self, what: &str) -> bool {
        self.notices
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains(what))
    }
}

impl LinkExecutor for Probe {
    fn accepted(&self, attempt: AttemptId) {
        self.inner.accepted(attempt);
    }
    fn offered(&self, offer: &Offer) -> bool {
        self.inner.offered(offer)
    }
    fn stop(&self, attempt: AttemptId) {
        let started = Instant::now();
        self.inner.stop(attempt);
        self.stops.lock().unwrap().push(started.elapsed());
    }
    fn cancel(&self, attempt: AttemptId) {
        self.cancels.fetch_add(1, Ordering::SeqCst);
        self.inner.cancel(attempt);
    }
    fn held(&self) -> Vec<AttemptId> {
        self.inner.held()
    }
    fn renewed(&self, until: UnixMillis) {
        self.inner.renewed(UnixMillis(until.0 - self.skew_ms));
    }
    fn renewed_at(&self, until: UnixMillis, sent: Instant) {
        // What a worker whose clock runs `skew_ms` ahead sees: the
        // controller's deadline, read on the worker's clock, is that much
        // nearer.
        self.inner
            .renewed_at(UnixMillis(until.0 - self.skew_ms), sent);
    }
    fn attached(&self, reporter: Reporter) {
        self.inner.attached(reporter);
    }
    fn detached(&self) {
        self.inner.detached();
    }
    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>) {
        self.inner.spec(attempt, context, bytes);
    }
    fn no_spec(&self, attempt: AttemptId) {
        self.inner.no_spec(attempt);
    }
    fn bulk_detached(&self) {
        self.inner.bulk_detached();
    }
    fn log_acked(&self, attempt: AttemptId, through: u64) {
        self.inner.log_acked(attempt, through);
    }
    fn log_refused(&self, attempt: AttemptId) {
        self.inner.log_refused(attempt);
    }
    fn log_ended(&self, attempt: AttemptId) {
        self.inner.log_ended(attempt);
    }
    fn artifact_granted(&self, attempt: AttemptId, name: &str) {
        self.inner.artifact_granted(attempt, name);
    }
    fn artifact_verdict(&self, attempt: AttemptId, name: &str, code: ArtifactCode) {
        self.inner.artifact_verdict(attempt, name, code);
    }
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        self.inner.availability()
    }
}

fn one_job(steps: &str) -> String {
    format!(
        "schema: 1\non: [push]\njobs:\n  work:\n    image: {IMAGE}@{DIGEST}\n    resources: {{ cpu: 1, memory: 128MiB }}\n    steps:\n{steps}"
    )
}

/// P04-5. The controller renews to its own `now + LEASE_MS`; a worker
/// whose clock runs a minute ahead reads that deadline as already past.
/// Before the fix the watchdog compared the two clocks, ended the attempt
/// within a second and it was recorded as a cancel nobody asked for. Now
/// the lease is measured from the heartbeat on the worker's monotonic
/// clock: the job runs to its end and passes.
#[test]
fn a_worker_clock_a_minute_ahead_never_ends_live_work() {
    if !podman_enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    shim();
    let (live, probe) = Live::start(|dir, worker| Probe::start(dir, worker, 60_000));
    // Longer than a lease, so the job lives through several renewals.
    let (_, jobs) = live.enqueue(&one_job(
        "      - id: wait\n        run: 'sleep 40; echo done'\n",
    ));
    eventually("the job ended", Duration::from_secs(120), || {
        matches!(live.job(jobs[0]).state, JobState::Terminal(_))
    });
    let job = live.job(jobs[0]);
    assert_eq!(
        (job.state, job.failure_class),
        (JobState::Terminal(Outcome::Passed), None),
        "notices: {:?}",
        probe.notices.lock().unwrap()
    );
    assert!(!probe.noticed("LeaseLost"));
    live.stop();
}

/// P04-15. The cancel lands while the step's `podman exec` is held in the
/// shim: the container has no step process to signal, so the first cancel
/// finds nothing (`Gone`). Before the fix that answer left the attempt
/// marked "canceling" and every later cancel was ignored — the step then
/// started and ran to its own end. Now the next heartbeat's cancel tries
/// again and ends the step.
#[test]
fn a_cancel_that_finds_the_step_still_starting_is_tried_again() {
    if !podman_enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = shim();
    let hold = dir.join("hold-exec");
    let held = dir.join("exec-held");
    let _ = fs::remove_file(&held);
    fs::write(&hold, "").unwrap();
    let (live, probe) = Live::start(|dir, worker| Probe::start(dir, worker, 0));
    let (_, jobs) = live.enqueue(&one_job(
        "      - id: wait\n        run: 'echo started; sleep 300'\n      - id: never\n        run: 'true'\n",
    ));
    eventually("the step's exec held", Duration::from_secs(120), || {
        held.exists()
    });
    let (tenant, job) = (live.tenant, jobs[0]);
    live.store
        .writer()
        .write(move |tx| dispatch::cancel(tx, tenant, job, UnixMillis::now()))
        .unwrap();
    // Two heartbeats carry the cancel while the exec is still held: the
    // first found nothing to signal, the second must not be ignored.
    eventually("the cancel repeated", Duration::from_secs(30), || {
        probe.cancels.load(Ordering::SeqCst) >= 3
    });
    assert!(!probe.noticed("Canceled {"), "nothing to signal yet");
    let released = Instant::now();
    fs::remove_file(&hold).unwrap();
    eventually("the job canceled", Duration::from_secs(30), || {
        live.job(job).state == JobState::Terminal(Outcome::Canceled)
    });
    assert!(released.elapsed() < Duration::from_secs(30));
    assert_eq!(
        live.job(job).failure_class,
        Some(sentinel_core::FailureClass::Canceled)
    );
    assert!(
        probe.noticed("Canceled {"),
        "{:?}",
        probe.notices.lock().unwrap()
    );
    eventually("containers gone", Duration::from_secs(30), || {
        podman::owned(live.worker).unwrap().is_empty()
    });
    live.stop();
}

/// P04-27. The controller stops counting an attempt as held (here it is
/// abandoned under the worker's fence); the next heartbeat's answer orders
/// the worker to stop it. The container's removal is slow (the shim sleeps
/// 3 s before `podman rm`). Before the fix `stop` ran the removal inline on
/// the heartbeat thread; now it returns at once, the removal happens off
/// that thread, and the session stays up.
#[test]
fn a_stop_order_never_holds_the_heartbeat_thread() {
    if !podman_enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = shim();
    let slow = dir.join("slow-rm");
    let (live, probe) = Live::start(|dir, worker| Probe::start(dir, worker, 0));
    let (run, jobs) = live.enqueue(&one_job(
        "      - id: wait\n        run: 'echo started; sleep 300'\n",
    ));
    let job = jobs[0];
    eventually("the step started", Duration::from_secs(120), || {
        live.printed(run, job, "started")
    });
    fs::write(&slow, "").unwrap();
    let worker = live.worker;
    let attempt = live.attempt(job).unwrap();
    let fence = live.job(job).fence;
    live.store
        .writer()
        .write(move |tx| dispatch::abandon(tx, worker, attempt, fence, UnixMillis::now(), None))
        .unwrap();
    eventually("the stop order", Duration::from_secs(30), || {
        !probe.stops.lock().unwrap().is_empty()
    });
    let held_for = probe.stops.lock().unwrap()[0];
    assert!(
        held_for < Duration::from_millis(500),
        "stop held the heartbeat thread for {held_for:?}"
    );
    eventually("the container removed", Duration::from_secs(30), || {
        podman::owned(worker).unwrap().is_empty()
    });
    fs::remove_file(&slow).unwrap();
    // The session never dropped for it.
    assert_eq!(live.controller().connected(), vec![worker]);
    assert!(probe.noticed("Stopped"));
    live.stop();
}
