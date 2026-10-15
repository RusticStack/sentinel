#![cfg(target_os = "linux")]

#[path = "support/live.rs"]
mod live;
#[path = "support/shim_dir.rs"]
mod shim_dir;

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

static SERIAL: Mutex<()> = Mutex::new(());

const SHIM: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
if [ "$1" = create ]; then echo "$*" >> "$dir/creates"; fi
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

fn shim() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let real = std::process::Command::new("sh")
            .args(["-c", "command -v podman"])
            .output()
            .unwrap();
        let real = String::from_utf8(real.stdout).unwrap().trim().to_owned();
        assert!(!real.is_empty(), "podman not found");
        let dir = shim_dir::create("executor-faults");
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

type HeldSpec = (AttemptId, JobContext, Vec<u8>);

struct Probe {
    inner: Executor,
    skew_ms: i64,
    offers: Mutex<Vec<Offer>>,
    cancels: AtomicUsize,
    stops: Mutex<Vec<Duration>>,
    notices: Arc<Mutex<Vec<String>>>,
    held_specs: Mutex<Option<Vec<HeldSpec>>>,
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
            offers: Mutex::new(Vec::new()),
            cancels: AtomicUsize::new(0),
            stops: Mutex::new(Vec::new()),
            notices,
            held_specs: Mutex::new(None),
        }
    }

    fn noticed(&self, what: &str) -> bool {
        self.notices
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains(what))
    }

    fn notices_of(&self, what: &str) -> usize {
        self.notices
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n.starts_with(what))
            .count()
    }

    fn hold_specs(&self) {
        *self.held_specs.lock().unwrap() = Some(Vec::new());
    }

    fn specs_held(&self) -> usize {
        self.held_specs.lock().unwrap().as_ref().map_or(0, Vec::len)
    }

    fn release_specs(&self) {
        let held = self.held_specs.lock().unwrap().take().unwrap_or_default();
        for (attempt, context, bytes) in held {
            self.inner.spec(attempt, context, bytes);
        }
    }

    fn offer_again(&self, offer: &Offer) -> bool {
        let take = self.inner.offered(offer);
        if take {
            self.inner.accepted(offer.attempt);
        }
        take
    }
}

impl LinkExecutor for Probe {
    fn accepted(&self, attempt: AttemptId) {
        self.inner.accepted(attempt);
    }
    fn offered(&self, offer: &Offer) -> bool {
        self.offers.lock().unwrap().push(offer.clone());
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
        {
            let mut held = self.held_specs.lock().unwrap();
            if let Some(held) = held.as_mut() {
                held.push((attempt, context, bytes));
                return;
            }
        }
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

/// Lease expiry is measured on the worker's monotonic clock, so a skewed wall clock cannot end live work.
#[test]
fn a_worker_clock_a_minute_ahead_never_ends_live_work() {
    if !podman_enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    shim();
    let (live, probe) = Live::start(|dir, worker| Probe::start(dir, worker, 60_000));
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
    assert_eq!(live.controller().connected(), vec![worker]);
    assert!(probe.noticed("Stopped"));
    live.stop();
}

/// A duplicate offer must never start the attempt again: its workspace already exists.
#[test]
fn a_repeated_offer_is_acknowledged_again_and_never_started_twice() {
    if !podman_enabled() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let creates = shim().join("creates");
    let _ = fs::remove_file(&creates);
    let (live, probe) = Live::start(|dir, worker| Probe::start(dir, worker, 0));
    probe.hold_specs();
    let (run, jobs) = live.enqueue(&one_job(
        "      - id: work\n        run: 'echo started; sleep 5; echo done'\n",
    ));
    let job = jobs[0];
    eventually("the spec held back", Duration::from_secs(60), || {
        probe.specs_held() > 0
    });
    let offer = probe.offers.lock().unwrap()[0].clone();
    assert_eq!(Some(offer.attempt), live.attempt(job));

    assert!(
        probe.offer_again(&offer),
        "awaiting: not acknowledged again"
    );
    assert_eq!(probe.inner.held(), vec![offer.attempt]);
    probe.release_specs();

    eventually("the step started", Duration::from_secs(120), || {
        live.printed(run, job, "started")
    });
    assert!(probe.offer_again(&offer), "running: not acknowledged again");
    assert_eq!(probe.inner.held(), vec![offer.attempt]);

    eventually("the job ended", Duration::from_secs(120), || {
        matches!(live.job(job).state, JobState::Terminal(_))
    });
    let row = live.job(job);
    assert_eq!(
        (row.state, row.failure_class),
        (JobState::Terminal(Outcome::Passed), None),
        "notices: {:?}",
        probe.notices.lock().unwrap()
    );
    assert!(live.printed(run, job, "done"));
    assert_eq!(live.attempt(job), Some(offer.attempt), "no second attempt");
    assert_eq!(
        (probe.notices_of("Started("), probe.notices_of("Finished(")),
        (1, 1),
        "notices: {:?}",
        probe.notices.lock().unwrap()
    );
    assert!(!probe.noticed("SpecRefused"));
    let created = fs::read_to_string(&creates).unwrap_or_default();
    assert_eq!(created.lines().count(), 1, "podman create calls: {created}");
    eventually("nothing held", Duration::from_secs(30), || {
        probe.inner.held().is_empty()
    });
    live.stop();
}
