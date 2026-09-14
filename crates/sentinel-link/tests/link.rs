//! W01/W02 end to end over real TLS on loopback against a running
//! `Controller`: enrollment and identity refusals; then dispatch — a queued
//! job reaches a connected worker on the wake, not on a poll; offers are
//! acknowledged and reserved; a decline or a missed acknowledgement lapses
//! back to the queue under a higher fence; leases renew on the heartbeat;
//! completion frees capacity and queues dependents; a worker reconnects.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, Fence, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    Error,
    controller::{Controller, RECONCILE_INTERVAL},
    identity::Identity,
    session::{self, Capacity, Executor, Offer, Rejection},
    tls, worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch,
    logs::LogStore,
    runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const CAPACITY: Capacity = Capacity {
    cpu_millis: 4_000,
    memory_bytes: 8 << 30,
};

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    controller: Option<Controller>,
    identity_files: (std::path::PathBuf, std::path::PathBuf),
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )?;
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis(1),
            )
        })
        .unwrap();
    let identity = Identity::generate("controller").unwrap();
    let files = (dir.path().join("c.crt"), dir.path().join("c.key"));
    identity.save(&files.0, &files.1).unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        identity,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Deployment {
        _dir: dir,
        store,
        logs,
        controller: Some(controller),
        identity_files: files,
        tenant,
        repo,
        pool,
    }
}

impl Deployment {
    fn controller(&self) -> &Controller {
        self.controller.as_ref().unwrap()
    }

    fn enrollment(&self, lifetime_ms: i64) -> Secret {
        let pool = self.pool;
        self.store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(
                    tx,
                    Authority::HostLocal,
                    pool,
                    lifetime_ms,
                    UnixMillis::now(),
                )
            })
            .unwrap()
            .secret
    }

    fn connect(
        &self,
        identity: Identity,
        worker: WorkerId,
        enrollment: Option<&Secret>,
    ) -> Result<session::Link, Error> {
        let config = tls::client_config(identity, self.controller().fingerprint()).unwrap();
        session::connect(
            self.controller().local_addr(),
            config,
            worker,
            "worker-1",
            hello(),
            enrollment,
            CAPACITY,
        )
    }

    /// Create a run with every image resolved and wake the dispatcher.
    fn run(&self, yaml: &str) -> (RunId, Vec<JobId>) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap();
        let ids = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        self.controller().wake();
        (run, ids)
    }

    fn state(&self, job: JobId) -> JobState {
        let tenant = self.tenant;
        self.store
            .read(|c| sentinel_store::jobs::get_job(c, tenant, job))
            .unwrap()
            .state
    }
}

use sentinel_core::JobId;

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(3),
        capabilities: Capabilities::REQUIRED.union(Capabilities::REFLINK),
        arch: Arch::X86_64,
        software: "test".into(),
    }
}

/// A spec delivery: the attempt, its context (none when refused), the bytes.
type SpecRecord = (AttemptId, Option<session::JobContext>, Vec<u8>);

/// An executor that records what it is told and holds what it accepts.
struct Recorder {
    offers: Mutex<mpsc::Sender<(Offer, Instant)>>,
    held: Mutex<Vec<AttemptId>>,
    stopped: Mutex<Vec<AttemptId>>,
    canceled: Mutex<Vec<AttemptId>>,
    renewed: AtomicI64,
    /// Decline offers for these jobs once, to exercise the lapse path.
    decline_once: Mutex<Vec<JobId>>,
    reporter: Mutex<Option<session::Reporter>>,
    specs: Mutex<Vec<SpecRecord>>,
    log_acks: Mutex<Vec<(AttemptId, u64)>>,
    log_refusals: Mutex<Vec<AttemptId>>,
}

impl Recorder {
    fn new() -> (Arc<Recorder>, mpsc::Receiver<(Offer, Instant)>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Recorder {
                offers: Mutex::new(tx),
                held: Mutex::new(Vec::new()),
                stopped: Mutex::new(Vec::new()),
                canceled: Mutex::new(Vec::new()),
                renewed: AtomicI64::new(0),
                decline_once: Mutex::new(Vec::new()),
                reporter: Mutex::new(None),
                specs: Mutex::new(Vec::new()),
                log_acks: Mutex::new(Vec::new()),
                log_refusals: Mutex::new(Vec::new()),
            }),
            rx,
        )
    }

    fn release(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
}

impl Executor for Recorder {
    fn offered(&self, offer: &Offer) -> bool {
        let mut decline = self.decline_once.lock().unwrap();
        let take = match decline.iter().position(|j| *j == offer.job) {
            Some(i) => {
                decline.remove(i);
                false
            }
            None => true,
        };
        if take {
            self.held.lock().unwrap().push(offer.attempt);
        }
        let _ = self
            .offers
            .lock()
            .unwrap()
            .send((offer.clone(), Instant::now()));
        take
    }
    fn stop(&self, attempt: AttemptId) {
        self.stopped.lock().unwrap().push(attempt);
        self.release(attempt);
    }
    fn cancel(&self, attempt: AttemptId) {
        self.canceled.lock().unwrap().push(attempt);
    }
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, until: UnixMillis) {
        self.renewed.store(until.0, Ordering::SeqCst);
    }
    fn attached(&self, reporter: session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, attempt: AttemptId, context: session::JobContext, bytes: Vec<u8>) {
        self.specs
            .lock()
            .unwrap()
            .push((attempt, Some(context), bytes));
    }
    fn no_spec(&self, attempt: AttemptId) {
        self.specs.lock().unwrap().push((attempt, None, Vec::new()));
    }
    fn log_acked(&self, attempt: AttemptId, through: u64) {
        self.log_acks.lock().unwrap().push((attempt, through));
    }
    fn log_refused(&self, attempt: AttemptId) {
        self.log_refusals.lock().unwrap().push(attempt);
    }
}

/// A worker process: `worker::run` on its own thread with a stop handle.
struct WorkerProcess {
    handle: Arc<worker::Handle>,
    events: Arc<Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<Result<(), Error>>>,
}

impl WorkerProcess {
    fn start(
        d: &Deployment,
        identity: Identity,
        id: WorkerId,
        enrollment: Option<Secret>,
        executor: Arc<Recorder>,
    ) -> WorkerProcess {
        Self::start_version(d, identity, id, enrollment, executor, 3)
    }

    fn start_version(
        d: &Deployment,
        identity: Identity,
        id: WorkerId,
        enrollment: Option<Secret>,
        executor: Arc<Recorder>,
        protocol: u16,
    ) -> WorkerProcess {
        let handle = Arc::new(worker::Handle::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let config = worker::Config {
            controller: d.controller().local_addr(),
            server: d.controller().fingerprint(),
            worker: id,
            name: "builder-1".into(),
            hello: {
                let mut h = hello();
                h.protocol_max = ProtocolVersion(protocol);
                h
            },
            capacity: CAPACITY,
        };
        let (grip, log) = (Arc::clone(&handle), Arc::clone(&events));
        let thread = thread::spawn(move || {
            worker::run(config, identity, enrollment, &*executor, &grip, &|event| {
                log.lock().unwrap().push(format!("{event:?}"));
            })
        });
        WorkerProcess {
            handle,
            events,
            thread: Some(thread),
        }
    }

    fn wait_for(&self, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.contains(needle))
            .count()
            < count
        {
            assert!(
                Instant::now() < deadline,
                "{:?}",
                self.events.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Result<(), Error> {
        let asked = Instant::now();
        self.handle.stop();
        let outcome = self.thread.take().unwrap().join().unwrap();
        // Stopping closes the socket: no heartbeat interval has to elapse.
        assert!(asked.elapsed() < Duration::from_secs(2));
        outcome
    }
}

/// Wait until `predicate` holds, within ten seconds.
fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

struct Idle;
impl Executor for Idle {
    fn offered(&self, _: &Offer) -> bool {
        true
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, _: session::Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: session::JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

#[test]
fn a_worker_enrolls_once_heartbeats_reconnects_and_is_refused_after_revocation() {
    let d = deployment();
    let secret = d.enrollment(60_000);
    let (worker, identity) = (WorkerId::new(), Identity::generate("worker-1").unwrap());
    let (cert, key) = (d._dir.path().join("w.crt"), d._dir.path().join("w.key"));
    identity.save(&cert, &key).unwrap();
    let load = || Identity::load(&cert, &key).unwrap();

    // Without the enrollment, an unknown certificate is refused.
    let refused = d.connect(load(), worker, None).unwrap_err();
    assert!(
        matches!(refused, Error::Rejected(Rejection::NotEnrolled)),
        "{refused}"
    );

    // With it: welcomed, negotiated, capacity recorded, beats answered.
    let mut link = d.connect(load(), worker, Some(&secret)).unwrap();
    assert_eq!(link.worker, worker);
    assert_eq!(link.negotiated.protocol, ProtocolVersion(3));
    for _ in 0..3 {
        link.beat(&Idle).unwrap();
    }
    let stored = d
        .store
        .read(|conn| workers::authenticate(conn, &load().fingerprint()))
        .unwrap();
    assert_eq!(stored.pool, d.pool);
    assert!(stored.last_seen.is_some());
    assert_eq!(
        d.store
            .read(|c| dispatch::free_capacity(c, worker))
            .unwrap(),
        dispatch::Capacity {
            cpu_millis: 4_000,
            memory_bytes: 8 << 30
        }
    );
    eventually("fleet registration", || {
        d.controller().connected() == vec![worker]
    });
    drop(link);
    eventually("fleet removal", || d.controller().connected().is_empty());

    // The enrollment is spent: presenting it again from another machine fails.
    let impostor = d
        .connect(
            Identity::generate("impostor").unwrap(),
            WorkerId::new(),
            Some(&secret),
        )
        .unwrap_err();
    assert!(
        matches!(impostor, Error::Rejected(Rejection::Enrollment)),
        "{impostor}"
    );
    // The enrolled identity reconnects with no enrollment at all.
    let mut again = d.connect(load(), worker, None).unwrap();
    again.beat(&Idle).unwrap();
    drop(again);

    // Revoked: the same certificate is refused from now on, and it cannot
    // enroll again under the same identity with a fresh secret.
    d.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, UnixMillis::now()))
        .unwrap();
    let refused = d.connect(load(), worker, None).unwrap_err();
    assert!(matches!(refused, Error::Rejected(Rejection::NotEnrolled)));
    let fresh = d.enrollment(60_000);
    let refused = d.connect(load(), worker, Some(&fresh)).unwrap_err();
    assert!(matches!(refused, Error::Rejected(Rejection::Identity)));
    assert_eq!(d.controller().stats().admitted.load(Ordering::SeqCst), 2);
    assert_eq!(d.controller().stats().rejected.load(Ordering::SeqCst), 4);
}

#[test]
fn wrong_fingerprint_unsupported_version_and_expired_enrollment_are_refused_in_place() {
    let d = deployment();
    let secret = d.enrollment(60_000);
    let wrong = Identity::generate("not-the-controller")
        .unwrap()
        .fingerprint();
    let config = tls::client_config(Identity::generate("w").unwrap(), wrong).unwrap();
    let failure = session::connect(
        d.controller().local_addr(),
        config,
        WorkerId::new(),
        "w",
        hello(),
        Some(&secret),
        CAPACITY,
    )
    .unwrap_err();
    assert!(matches!(failure, Error::Tls(_) | Error::Io(_)), "{failure}");
    // The enrollment was never presented, so it is still unspent.
    assert!(
        d.connect(
            Identity::generate("w2").unwrap(),
            WorkerId::new(),
            Some(&secret)
        )
        .is_ok()
    );

    let config = tls::client_config(
        Identity::generate("old").unwrap(),
        d.controller().fingerprint(),
    )
    .unwrap();
    let old = Hello {
        protocol_min: ProtocolVersion(0),
        protocol_max: ProtocolVersion(0),
        ..hello()
    };
    let failure = session::connect(
        d.controller().local_addr(),
        config,
        WorkerId::new(),
        "old",
        old,
        Some(&secret),
        CAPACITY,
    )
    .unwrap_err();
    assert!(
        matches!(
            failure,
            Error::Rejected(Rejection::UnsupportedVersion {
                upgrade_worker: true,
                ..
            })
        ),
        "{failure}"
    );

    let short = d.enrollment(1);
    thread::sleep(Duration::from_millis(20));
    let failure = d
        .connect(
            Identity::generate("late").unwrap(),
            WorkerId::new(),
            Some(&short),
        )
        .unwrap_err();
    assert!(matches!(failure, Error::Rejected(Rejection::Enrollment)));
}

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
  lint:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
  test:
    image: alpine:3
    needs: [build]
    resources: { cpu: 2, memory: 2GiB }
    steps: [{ id: s, run: 'true' }]
";

#[test]
fn queued_work_reaches_a_connected_worker_on_the_wake_and_completion_queues_dependents() {
    let d = deployment();
    let secret = d.enrollment(60_000);
    let (recorder, offers) = Recorder::new();
    let id = WorkerId::new();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("w").unwrap(),
        id,
        Some(secret),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected", 1);
    eventually("fleet", || d.controller().connected() == vec![id]);

    // Enqueue, wake: both ready jobs arrive well inside the reconciliation
    // interval, so it was the wake that delivered them, not the poll.
    let woken = Instant::now();
    let (_, ids) = d.run(PIPELINE);
    let (build, lint, test) = (ids[0], ids[1], ids[2]);
    let first = offers.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = offers.recv_timeout(Duration::from_secs(5)).unwrap();
    let latency = second.1.duration_since(woken);
    assert!(
        latency < RECONCILE_INTERVAL / 2,
        "offers took {latency:?}; the wake did not fire"
    );
    let mut placed = [first.0.job, second.0.job];
    placed.sort();
    let mut expected = [build, lint];
    expected.sort();
    assert_eq!(placed, expected);
    assert_eq!(first.0.image_digest, DIGEST);
    // `test` needs `build`: not offered, and the wait reason says why.
    assert!(offers.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(d.state(test), JobState::Blocked);

    // Acknowledged on the controller: attempts marked, capacity reserved.
    eventually("acknowledgements", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == 2
    });
    let held = d.store.read(|c| dispatch::held_by(c, id)).unwrap();
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|h| h.acknowledged));
    assert_eq!(
        d.store
            .read(|c| dispatch::free_capacity(c, id))
            .unwrap()
            .cpu_millis,
        2_000
    );
    assert_eq!(d.state(build), JobState::Leased);

    // The worker reports `build` done (W03's executor will do this through
    // its own messages); capacity comes back and `test` is queued in the
    // same transaction, then placed on the wake.
    let build_attempt = if first.0.job == build {
        &first.0
    } else {
        &second.0
    };
    let (attempt, fence) = (build_attempt.attempt, build_attempt.fence);
    // The worker asks for the spec it will run and gets the stored bytes.
    let reporter = recorder.reporter.lock().unwrap().clone().unwrap();
    reporter.need_spec(attempt).unwrap();
    eventually("spec", || !recorder.specs.lock().unwrap().is_empty());
    let (spec_attempt, context, bytes) = recorder.specs.lock().unwrap()[0].clone();
    assert_eq!(spec_attempt, attempt);
    let spec = RunSpec::decode(&bytes).unwrap();
    assert_eq!(spec.pipeline.jobs.len(), 3);
    let context = context.unwrap();
    assert_eq!((context.job, context.job_name.as_str()), (build, "build"));
    assert_eq!(context.repo_name, "app");
    assert_eq!(context.sha, SHA);
    assert!(context.needs.is_empty() && !context.cancelled);
    // A spec for an attempt this worker does not hold is refused.
    reporter.need_spec(AttemptId::new()).unwrap();
    eventually("no spec", || recorder.specs.lock().unwrap().len() == 2);
    assert!(recorder.specs.lock().unwrap()[1].2.is_empty());

    // Log frames of a held attempt are acknowledged only once stored and
    // synced on the controller: what the acknowledgement covers is exactly
    // what a reader sees. A resend is acknowledged again without a second
    // copy; a jump is refused; the end marker completes the log.
    let text = |seq: u64, s: &str| Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: s.as_bytes().to_vec(),
    };
    reporter.log(attempt, &text(1, "one\n")).unwrap();
    reporter.log(attempt, &text(2, "two\n")).unwrap();
    eventually("log acks", || {
        recorder.log_acks.lock().unwrap().last() == Some(&(attempt, 2))
    });
    let tail = d.logs.tail(attempt, 0, 10).unwrap();
    assert_eq!(tail.frames.len(), 2);
    assert!(!tail.complete);
    reporter.log(attempt, &text(2, "two\n")).unwrap();
    eventually("duplicate acked", || {
        recorder.log_acks.lock().unwrap().len() == 3
    });
    assert_eq!(d.logs.tail(attempt, 0, 10).unwrap().frames.len(), 2);
    reporter.log(attempt, &text(9, "nine\n")).unwrap();
    eventually("jump refused", || {
        recorder.log_refusals.lock().unwrap().as_slice() == [attempt]
    });
    // Frames for an attempt this worker does not hold are refused too.
    let foreign = AttemptId::new();
    reporter.log(foreign, &text(1, "x")).unwrap();
    eventually("foreign refused", || {
        recorder.log_refusals.lock().unwrap().len() == 2
    });
    assert!(matches!(
        d.logs.tail(foreign, 0, 10),
        Err(sentinel_store::Error::NotFound)
    ));
    reporter.log_end(attempt, 2, &[]).unwrap();
    eventually("log complete", || {
        d.logs.tail(attempt, 0, 10).unwrap().complete
    });

    // The worker reports its progress over the wire; the terminal report
    // frees the capacity, queues `test` and wakes the dispatcher — no
    // `wake()` call from the test.
    recorder.release(attempt);
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(attempt, fence, event).unwrap();
    }
    let woken = Instant::now();
    eventually("terminal", || {
        d.state(build) == JobState::Terminal(Outcome::Passed)
    });
    // A stale fence is refused without effect.
    reporter.report(attempt, Fence(0), Event::Passed).unwrap();
    eventually("stale report counted", || {
        d.controller().stats().stale_reports.load(Ordering::SeqCst) == 1
    });
    let third = offers.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(third.0.job, test);
    assert!(third.1.duration_since(woken) < RECONCILE_INTERVAL / 2);
    assert_eq!(third.0.cpu_millis, 2_000);

    // Leases renew on the heartbeat: the deadline the worker sees moves.
    let before = recorder.renewed.load(Ordering::SeqCst);
    eventually("renewal", || {
        recorder.renewed.load(Ordering::SeqCst) > before
    });
    assert!(recorder.stopped.lock().unwrap().is_empty());

    // Cancellation is desired state on the controller and reaches the
    // worker with its next beat, repeated until the worker reports.
    let (test_attempt, test_fence) = (third.0.attempt, third.0.fence);
    let tenant = d.tenant;
    assert_eq!(
        d.store
            .writer()
            .write(move |tx| dispatch::cancel(tx, tenant, test, UnixMillis::now()))
            .unwrap(),
        dispatch::Cancelled::Requested
    );
    eventually("cancel delivered", || {
        recorder.canceled.lock().unwrap().contains(&test_attempt)
    });
    assert_eq!(d.state(test), JobState::Leased);
    reporter
        .report(
            test_attempt,
            test_fence,
            Event::Failed(sentinel_core::FailureClass::Canceled),
        )
        .unwrap();
    eventually("canceled", || {
        d.state(test) == JobState::Terminal(Outcome::Canceled)
    });
    recorder.release(test_attempt);

    // A worker that restarted with `lint` in its leftovers abandons it:
    // reconciled as an infrastructure failure under the right fence only.
    let (lint_attempt, lint_fence) = if first.0.job == lint {
        (first.0.attempt, first.0.fence)
    } else {
        (second.0.attempt, second.0.fence)
    };
    reporter
        .abandon(lint_attempt, Fence(lint_fence.0 + 7))
        .unwrap();
    eventually("stale abandon counted", || {
        d.controller().stats().stale_reports.load(Ordering::SeqCst) == 2
    });
    assert_eq!(d.state(lint), JobState::Leased);
    reporter.abandon(lint_attempt, lint_fence).unwrap();
    eventually("abandoned", || {
        d.state(lint) == JobState::Terminal(Outcome::InfraFailed)
    });
    assert_eq!(d.controller().stats().abandoned.load(Ordering::SeqCst), 1);
    recorder.release(lint_attempt);

    // A clean stop says goodbye; the fleet forgets the worker; nothing is
    // held any more.
    process.stop().unwrap();
    eventually("fleet removal", || d.controller().connected().is_empty());
    assert!(
        d.store
            .read(|c| dispatch::held_by(c, id))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_declined_offer_returns_to_the_queue_and_is_reoffered_under_a_higher_fence() {
    let d = deployment();
    let secret = d.enrollment(60_000);
    let (recorder, offers) = Recorder::new();
    let id = WorkerId::new();
    let (_, ids) = d.run(
        "schema: 1
on: [push]
jobs:
  only:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
",
    );
    recorder.decline_once.lock().unwrap().push(ids[0]);
    let process = WorkerProcess::start(
        &d,
        Identity::generate("w").unwrap(),
        id,
        Some(secret),
        Arc::clone(&recorder),
    );
    // Work was waiting before the worker arrived: its arrival is a wake.
    let declined = offers.recv_timeout(Duration::from_secs(5)).unwrap().0;
    assert_eq!(declined.fence, Fence(1));
    eventually("lapse", || {
        d.controller().stats().lapsed.load(Ordering::SeqCst) == 1
    });
    // Re-offered at the next reconciliation (not immediately: a refusing
    // worker is bounded to one offer per interval), under fence 2.
    let again = offers
        .recv_timeout(RECONCILE_INTERVAL + Duration::from_secs(5))
        .unwrap()
        .0;
    assert_eq!(again.job, ids[0]);
    assert_eq!(again.fence, Fence(2));
    assert_ne!(again.attempt, declined.attempt);
    eventually("acknowledgement", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == 1
    });
    let held = d.store.read(|c| dispatch::held_by(c, id)).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].attempt, again.attempt);
    process.stop().unwrap();
}

#[test]
fn an_unacknowledged_offer_lapses_and_the_late_acknowledgement_is_stale() {
    let d = deployment();
    let secret = d.enrollment(60_000);
    let id = WorkerId::new();
    let mut link = d
        .connect(Identity::generate("w").unwrap(), id, Some(&secret))
        .unwrap();
    eventually("fleet", || d.controller().connected() == vec![id]);
    let (_, ids) = d.run(
        "schema: 1
on: [push]
jobs:
  only:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
",
    );
    eventually("offer sent", || {
        d.controller().stats().offers.load(Ordering::SeqCst) == 1
    });
    let first = d.store.read(|c| dispatch::held_by(c, id)).unwrap();
    assert_eq!((first.len(), first[0].acknowledged), (1, false));
    // The worker reads nothing for longer than the ack timeout.
    thread::sleep(Duration::from_millis(
        dispatch::OFFER_ACK_MS as u64 + RECONCILE_INTERVAL.as_millis() as u64 + 500,
    ));
    eventually("lapse", || {
        d.controller().stats().lapsed.load(Ordering::SeqCst) >= 1
    });
    // Now it reads: the stale offer is acknowledged late (ignored), the
    // re-offer under fence 2 is acknowledged for real, the beat is answered.
    link.beat(&Idle).unwrap();
    eventually("fresh acknowledgement", || {
        d.store
            .read(|c| dispatch::held_by(c, id))
            .unwrap()
            .iter()
            .any(|h| h.acknowledged && h.fence == Fence(2))
    });
    let held = d.store.read(|c| dispatch::held_by(c, id)).unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_ne!(held[0].attempt, first[0].attempt);
    assert_eq!(d.state(ids[0]), JobState::Leased);
}

#[test]
fn a_worker_reconnects_with_backoff_after_the_controller_restarts() {
    let mut d = deployment();
    let secret = d.enrollment(60_000);
    let (recorder, _offers) = Recorder::new();
    let id = WorkerId::new();
    let addr = d.controller().local_addr();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("w").unwrap(),
        id,
        Some(secret),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected { worker: wrk_", 1);
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
    process.wait_for("Disconnected", 1);
    process.wait_for("Backoff", 1);
    // Same identity, same address: the worker's pin still holds.
    let identity = Identity::load(&d.identity_files.0, &d.identity_files.1).unwrap();
    d.controller =
        Some(Controller::start(Arc::clone(&d.store), Arc::clone(&d.logs), identity, addr).unwrap());
    process.wait_for("Connected { worker: wrk_", 2);
    let events = process.events.lock().unwrap().clone();
    // The second connection presented no enrollment.
    assert_eq!(
        events
            .iter()
            .filter(|e| e.contains("enrolled: true"))
            .count(),
        1,
        "{events:?}"
    );
    eventually("fleet", || d.controller().connected() == vec![id]);
    process.stop().unwrap();
}
