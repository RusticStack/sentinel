//! The link's `Executor`, backed by real attempts on threads.
//!
//! An offer is taken when the runtime is usable and the worker holds fewer
//! than its bound of attempts; the spec is then asked for over the link and
//! the attempt starts once it arrives. Reports go out on the live session
//! from the attempt's own thread, in order; when there is no session they
//! queue in memory and are replayed at the next attach (a durable spool is
//! W05). A `stop` from the controller flips the attempt's cancel flag and
//! ends its container; it is not reported, because the controller already
//! counts the attempt as gone. The lease watchdog ends every attempt the
//! same way once the lease it measured (monotonically, from the heartbeat
//! that renewed it) has run out, and nothing it ended is reported either.
//!
//! A spec that does not arrive is asked for again every [`SPEC_RETRY`]; one
//! refused for good fails the attempt at once as `Preparation`; and an
//! attempt that still has none after [`SPEC_DEADLINE`] is handed back — it
//! never started, so the controller requeues it rather than recording a
//! failure.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, Fence, UnixMillis};
use sentinel_link::session::{ArtifactCode, Executor as LinkExecutor, JobContext, Offer, Reporter};
use sentinel_pipeline::RunSpec;
use sentinel_protocol::limits::MAX_LIST_ITEMS;

use crate::{
    Result,
    artifacts::{self, REPLY_TIMEOUT},
    attempt::{self, CacheNote, Cancel, Job, Report, Verdict},
    images::Images,
    logpipe::LogPipe,
    podman,
    recovery::{self, Leftover, Recovered},
    redact::Redactor,
    spool::{DEFAULT_SPOOL_QUOTA, DEFAULT_SPOOL_RESERVE, Refused, SpoolSpace},
};

/// What happened, for the process's diagnostics.
#[derive(Debug)]
pub enum Notice {
    Started(AttemptId),
    Finished(AttemptId, Verdict),
    SpecRefused(AttemptId),
    /// The spec never arrived within [`SPEC_DEADLINE`]: the attempt was
    /// handed back to the controller unstarted.
    HandedBack(AttemptId),
    Stopped(AttemptId),
    /// A cancel order was carried out; `forced` when the grace ran out.
    Canceled {
        attempt: AttemptId,
        forced: bool,
    },
    /// The lease deadline passed with no renewal: every attempt was ended
    /// without a report, because the controller has already expired them.
    LeaseLost(Vec<AttemptId>),
    /// A leftover of the previous process was handed to the controller:
    /// its spool delivered (or refused) and the attempt abandoned.
    Abandoned {
        attempt: AttemptId,
        log_delivered: bool,
    },
    /// The mirrors root could not be opened at start; every checkout runs
    /// direct for the life of this process. The reason is bounded.
    MirrorsUnavailable(String),
    /// An attempt's spool refused output — its cap, the worker's spool
    /// quota, the free-space reserve, a failed write — and declared it as
    /// gaps in the log. Emitted once, when the attempt finishes.
    SpoolRefused {
        attempt: AttemptId,
        refused: Refused,
    },
    /// A declared cache's publication settled during finalization —
    /// sealed, skipped or failed; the attempt's verdict never depends on it.
    CachePublished {
        attempt: AttemptId,
        note: CacheNote,
    },
    /// A bounded reclamation pass over the cache root removed something —
    /// expired leases, dead staging or generations past retention/budget.
    CacheSwept(sentinel_cache::gc::GcStats),
    /// A nominal cache hit paid rebuild-scale restore cost — the K08
    /// costly-hit rule (docs/cache.md) tripped. Diagnostics only; the
    /// attempt's verdict never depends on it.
    CostlyCacheHit {
        attempt: AttemptId,
        /// The declared cache's name.
        name: String,
        /// Which clause tripped (`copied_all`/`slow`).
        costly: sentinel_cache::Costly,
        /// The restore's measured stats — the evidence.
        stats: sentinel_cache::Stats,
    },
    /// The worker's compact availability snapshot (K08), emitted after
    /// each bounded cache sweep — at start and after every attempt's
    /// finalization, never on a timer. Part 08's placement consumes it.
    Availability(Availability),
}

/// The snapshot [`Notice::Availability`] carries — bounded, learned from
/// pull outcomes and the sweep's own walk; never a store scan.
#[derive(Clone, Debug)]
pub struct Availability {
    /// Image digests the local store is known to hold — sorted, bounded
    /// by `images::MAX_HELD`.
    pub images_held: Vec<String>,
    /// Image pulls in flight right now.
    pub images_in_flight: usize,
    /// Cache entry directories the sweep saw.
    pub cache_entries: u64,
    /// Generation directories the sweep saw.
    pub cache_generations: u64,
    /// Payload bytes the store holds now — what the pass saw less what it
    /// freed (`bytes_freed`).
    pub cache_bytes: u64,
    /// The pass hit its work bound — the occupancy counts are partial.
    pub truncated: bool,
}

/// TERM-to-KILL grace for a cancel when the process sets none.
pub const DEFAULT_CANCEL_GRACE: Duration = Duration::from_secs(30);
/// Subtracted from the lease the worker measured: it acts before the
/// controller could have expired the attempt, never after.
pub const LEASE_GUARD: Duration = Duration::from_secs(5);
/// The lease a renewal grants, as the worker protocol fixes it.
const LEASE: Duration = Duration::from_millis(sentinel_protocol::limits::LEASE_MS as u64);
/// How often the lease watchdog looks.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);
/// How long a spec request goes unanswered before it is asked again.
pub const SPEC_RETRY: Duration = Duration::from_secs(10);
/// How long an acknowledged attempt waits for its spec before it is handed
/// back to the controller unstarted.
pub const SPEC_DEADLINE: Duration = Duration::from_secs(60);

struct Live {
    cancel: Cancel,
    logs: Arc<LogPipe>,
    /// A cancel order is already being carried out.
    canceling: bool,
    /// The lease watchdog ended it: the controller has (or will have)
    /// settled it by expiry, so nothing about it is reported.
    lost: bool,
}

/// An offer taken and waiting for its spec.
struct Awaiting {
    offer: Offer,
    /// When the spec was first asked for, and last.
    since: Instant,
    asked: Instant,
    /// It is being handed back; a spec arriving now is not used.
    declining: bool,
    /// Values registered before the attempt started, for its redactor.
    secrets: Vec<sentinel_protocol::secrets::SecretBytes>,
}

fn valid_delivery(
    spec: &RunSpec,
    job_index: usize,
    bundle: &sentinel_protocol::secrets::DeliveryBundle,
) -> bool {
    use sentinel_protocol::secrets::TargetKind;
    let Some(job) = spec.pipeline.jobs.get(job_index).map(|job| &job.spec) else {
        return false;
    };
    if !bundle.valid() {
        return false;
    }
    let mut expected = HashSet::with_capacity(
        job.steps
            .iter()
            .map(|step| step.secrets.len() + step.secret_files.len())
            .sum::<usize>()
            + usize::from(job.registry_auth.is_some()),
    );
    for (index, step) in job.steps.iter().enumerate() {
        for name in &step.secrets {
            expected.insert((index as u16, name.clone(), TargetKind::Environment));
        }
        for file in &step.secret_files {
            expected.insert((
                index as u16,
                file.name.clone(),
                TargetKind::File {
                    path: file.path.clone(),
                },
            ));
        }
    }
    if let Some(name) = &job.registry_auth {
        expected.insert((0, name.clone(), TargetKind::RegistryAuth));
    }
    if expected.len() != bundle.targets.len() {
        return false;
    }
    let mut seen = HashSet::with_capacity(expected.len());
    let mut referenced = vec![false; bundle.values.len()];
    for target in &bundle.targets {
        let key = (target.step, target.name.clone(), target.target.clone());
        if !expected.contains(&key) || !seen.insert(key) {
            return false;
        }
        let Some(value) = bundle.values.get(target.value as usize) else {
            return false;
        };
        referenced[target.value as usize] = true;
        match &target.target {
            TargetKind::Environment => {
                let bytes = value.expose();
                if std::str::from_utf8(bytes).is_err()
                    || bytes.iter().any(|b| matches!(*b, 0 | b'\n' | b'\r'))
                {
                    return false;
                }
            }
            TargetKind::File { .. } => {}
            TargetKind::RegistryAuth => {
                let Ok(auth) = serde_json::from_slice::<serde_json::Value>(value.expose()) else {
                    return false;
                };
                let Some(auth) = auth.as_object() else {
                    return false;
                };
                // Credential helpers and Docker config extensions can invoke
                // worker-side helpers or introduce unrelated auth sources.
                // The protocol accepts only the tenant's explicit auth map.
                if auth.len() != 1 || !auth.get("auths").is_some_and(serde_json::Value::is_object) {
                    return false;
                }
            }
        }
    }
    referenced.into_iter().all(|used| used)
}

#[cfg(test)]
mod secret_delivery_tests {
    use super::*;
    use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
    use sentinel_protocol::secrets::{DeliveryBundle, DeliveryTarget, DeliveryValue, TargetKind};

    fn spec() -> RunSpec {
        let yaml = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    secrets: [TOKEN, CERT, OCI_AUTH]\n    registry_auth: OCI_AUTH\n    steps:\n      - id: test\n        run: echo test\n        secrets: [TOKEN]\n        secret_files: { CERT: tls/client.pem }\n";
        RunSpec::new(
            PinnedSource::new("https://example.test/repo.git", &"a".repeat(40), None).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap()
    }

    fn bundle(token: &[u8], auth: &[u8], include_file: bool) -> DeliveryBundle {
        let mut targets = vec![
            DeliveryTarget {
                step: 0,
                name: "OCI_AUTH".into(),
                value: 0,
                target: TargetKind::RegistryAuth,
            },
            DeliveryTarget {
                step: 0,
                name: "TOKEN".into(),
                value: 1,
                target: TargetKind::Environment,
            },
        ];
        let mut values = vec![
            DeliveryValue::new(auth.to_vec()),
            DeliveryValue::new(token.to_vec()),
        ];
        if include_file {
            targets.push(DeliveryTarget {
                step: 0,
                name: "CERT".into(),
                value: 2,
                target: TargetKind::File {
                    path: "tls/client.pem".into(),
                },
            });
            values.push(DeliveryValue::new(b"certificate".to_vec()));
        }
        DeliveryBundle { values, targets }
    }

    #[test]
    fn only_the_exact_declared_targets_and_oci_auth_shape_are_accepted() {
        let spec = spec();
        let auth = br#"{"auths":{"ghcr.io":{"auth":"dG9rZW4="}}}"#;
        assert!(valid_delivery(&spec, 0, &bundle(b"token", auth, true)));
        assert!(!valid_delivery(&spec, 0, &bundle(b"token", auth, false)));
        assert!(!valid_delivery(
            &spec,
            0,
            &bundle(b"token\nINJECTED=x", auth, true)
        ));
        assert!(!valid_delivery(
            &spec,
            0,
            &bundle(b"token", br#"{"auths":[]}"#, true)
        ));
        assert!(!valid_delivery(
            &spec,
            0,
            &bundle(
                b"token",
                br#"{"auths":{},"credHelpers":{"ghcr.io":"secretservice"}}"#,
                true
            )
        ));

        let mut extra = bundle(b"token", auth, true);
        extra.targets.push(DeliveryTarget {
            step: 0,
            name: "OTHER".into(),
            value: 1,
            target: TargetKind::Environment,
        });
        assert!(!valid_delivery(&spec, 0, &extra));

        let mut duplicate = bundle(b"token", auth, true);
        duplicate.targets.push(duplicate.targets[1].clone());
        assert!(!valid_delivery(&spec, 0, &duplicate));

        let mut unreferenced = bundle(b"token", auth, true);
        unreferenced
            .values
            .push(DeliveryValue::new(b"extra".to_vec()));
        assert!(!valid_delivery(&spec, 0, &unreferenced));
    }
}

struct State {
    reporter: Option<Reporter>,
    /// Offers taken and waiting for their spec.
    awaiting: HashMap<AttemptId, Awaiting>,
    live: HashMap<AttemptId, Live>,
    /// Reports that found no session, in order, with the summary of a
    /// terminal one.
    pending: Vec<(AttemptId, Fence, Event, Option<Vec<u8>>)>,
    /// Monotonic deadline: the lease the last renewal granted, measured
    /// from the heartbeat that asked for it, minus the guard.
    lease_deadline: Option<Instant>,
    cancel_grace: Duration,
    prepare_hold: Duration,
    /// Attempts of the previous process still to abandon, once a session is up.
    leftovers: Vec<Leftover>,
    /// Leftover spools being delivered, so their acknowledgements route.
    recovering: HashMap<AttemptId, Arc<LogPipe>>,
    /// Artifact reply waiters, one per attempt: the link admits one
    /// in-flight publication per attempt and the attempt thread captures
    /// its artifacts sequentially.
    artifact_waits: HashMap<AttemptId, Arc<Watch>>,
}

/// The controller's next artifact answer, shared with the attempt thread.
/// `gate` makes the check-and-send of each in-flight frame atomic against
/// a verdict resolving the watch: a frame can never be sent after the
/// controller has closed the artifact.
#[derive(Default)]
struct Watch {
    reply: Mutex<Option<Reply>>,
    cv: std::sync::Condvar,
    gate: Mutex<()>,
}

/// What a watch can carry: the grant that opens a stream, or the terminal
/// verdict that closes it.
#[derive(Clone, Copy)]
enum Reply {
    Granted,
    Done(ArtifactCode),
}

impl Watch {
    /// The latest answer wins; a verdict can always follow a grant.
    fn resolve(&self, reply: Reply) {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner()) = Some(reply);
        self.cv.notify_all();
    }
    /// The current answer without consuming it.
    fn peek(&self) -> Option<Reply> {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Wait for the first answer — `Granted` or a verdict.
    fn wait_reply(&self, timeout: Duration) -> Option<Reply> {
        let slot = self.reply.lock().unwrap_or_else(|p| p.into_inner());
        let (slot, waited) = self
            .cv
            .wait_timeout_while(slot, timeout, |r| r.is_none())
            .unwrap_or_else(|p| p.into_inner());
        if waited.timed_out() {
            return None;
        }
        *slot
    }
    /// Wait for the terminal verdict only; a stale `Granted` is not it.
    fn wait_done(&self, timeout: Duration) -> Option<ArtifactCode> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.reply.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(Reply::Done(code)) = *slot {
                return Some(code);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (s, _) = self
                .cv
                .wait_timeout(slot, remaining)
                .unwrap_or_else(|p| p.into_inner());
            slot = s;
        }
    }
}

/// The executor handle the link holds; cheap to clone, one runtime behind it.
#[derive(Clone)]
pub struct Executor(Arc<Inner>);

impl std::ops::Deref for Executor {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

pub struct Inner {
    root: PathBuf,
    worker: sentinel_core::WorkerId,
    runtime: podman::Runtime,
    /// One in-flight pull per image reference across every attempt, and
    /// the record of what the local store holds.
    images: Images,
    /// K05: background pulls of what the controller's hints name, through
    /// `images`, within their own bounds.
    prefetch: crate::prefetch::Prefetcher,
    /// The worker-local object mirrors, opened once here so the reflink
    /// probe and the root are settled for the process's life. `None` —
    /// configured off, or open failed — runs every checkout direct.
    mirrors: Option<crate::checkout::Mirrors>,
    /// The disk every attempt's spool shares: a quota and a free-space
    /// reserve on the data directory.
    spool: Arc<SpoolSpace>,
    state: Mutex<State>,
    /// One cache reclamation pass at a time; a second caller skips rather
    /// than waits, because the running pass already covers its work. The
    /// lock holds the resume cursor, so bounded passes cover the whole
    /// tree across attempts (P07-4).
    gc_lock: Mutex<sentinel_cache::gc::Cursor>,
    /// The cache store's payload bytes as the last pass estimated them —
    /// the availability the link reports to placement (K08).
    cache_bytes: std::sync::atomic::AtomicU64,
    /// Moves whenever `cache_bytes` changes.
    cache_version: std::sync::atomic::AtomicU64,
    notify: Box<dyn Fn(Notice) + Send + Sync>,
    recovered: Recovered,
}

impl Executor {
    /// Probe the runtime and prepare the data directory. Refuses to exist
    /// without rootless Podman: an executor that cannot isolate is not one.
    /// `git_mirrors` is the operator's escape hatch; when on, a mirror root
    /// that cannot be opened is reported once and checkouts run direct.
    pub fn start(
        root: PathBuf,
        worker: sentinel_core::WorkerId,
        notify: impl Fn(Notice) + Send + Sync + 'static,
        git_mirrors: bool,
    ) -> Result<Executor> {
        let runtime = podman::probe()?;
        std::fs::create_dir_all(root.join(crate::workspace::WORKSPACES_DIR))?;
        let mirrors = if git_mirrors {
            match crate::checkout::Mirrors::open(&root.join(crate::checkout::MIRRORS_DIR)) {
                Ok(mirrors) => Some(mirrors),
                Err(error) => {
                    notify(Notice::MirrorsUnavailable(error.to_string()));
                    None
                }
            }
        } else {
            None
        };
        // Before any offer: what the previous process left is settled on
        // disk and in the runtime; what it owed the controller waits for
        // the session.
        let (recovered, leftovers) = recovery::recover(&root, worker)?;
        let images = Images::for_worker_data_dir(&root)?;
        let prefetch = crate::prefetch::Prefetcher::new(
            images.clone(),
            crate::prefetch::Bounds::default(),
            crate::prefetch::PodmanProbe::new(),
        );
        let spool = SpoolSpace::new(root.clone(), DEFAULT_SPOOL_RESERVE, DEFAULT_SPOOL_QUOTA);
        let executor = Executor(Arc::new(Inner {
            root,
            worker,
            runtime,
            images,
            prefetch,
            mirrors,
            spool,
            state: Mutex::new(State {
                reporter: None,
                awaiting: HashMap::new(),
                live: HashMap::new(),
                pending: Vec::new(),
                lease_deadline: None,
                cancel_grace: DEFAULT_CANCEL_GRACE,
                prepare_hold: Duration::ZERO,
                leftovers,
                recovering: HashMap::new(),
                artifact_waits: HashMap::new(),
            }),
            notify: Box::new(notify),
            gc_lock: Mutex::new(sentinel_cache::gc::Cursor::default()),
            cache_bytes: std::sync::atomic::AtomicU64::new(0),
            cache_version: std::sync::atomic::AtomicU64::new(0),
            recovered,
        }));
        // One bounded reclamation pass at start: what a dead process left —
        // expired leases, a torn staging dir, generations a crashed publish
        // abandoned — collects here rather than under a running job. Off
        // this thread, so a large store cannot hold executor start.
        let watched = Arc::downgrade(&executor.0);
        let _ = thread::Builder::new()
            .name("sentinel-cache-gc".into())
            .spawn(move || {
                if let Some(inner) = watched.upgrade() {
                    inner.sweep_caches();
                }
            });
        let watched = Arc::downgrade(&executor.0);
        thread::Builder::new()
            .name("sentinel-lease-watchdog".into())
            .spawn(move || {
                while let Some(inner) = watched.upgrade() {
                    inner.watch_lease();
                    inner.watch_specs();
                    drop(inner);
                    thread::sleep(WATCHDOG_INTERVAL);
                }
            })?;
        Ok(executor)
    }

    /// The free space every spool leaves on the data directory's file
    /// system, and the bytes all of them may hold together (defaults
    /// `DEFAULT_SPOOL_RESERVE` and `DEFAULT_SPOOL_QUOTA`). Output past
    /// either is declared as gaps in the attempt's log.
    pub fn set_spool_limits(&self, reserve: u64, quota: u64) {
        self.spool.set_limits(reserve, quota);
    }

    /// How long a canceled step gets between `SIGTERM` and the forced stop.
    pub fn set_cancel_grace(&self, grace: Duration) {
        self.state().cancel_grace = grace;
    }

    /// Hold every attempt between checkout and image pull; a test aid for
    /// cancellation during preparation. Zero (the default) holds nothing.
    pub fn set_prepare_hold(&self, hold: Duration) {
        self.state().prepare_hold = hold;
    }

    /// Redact `value` from `attempt`'s output — only that attempt's, from
    /// now on, for its lifetime; it goes with the attempt. A value
    /// registered before the attempt starts applies from its first byte.
    /// Returns whether it was accepted: `false` for an empty value or an
    /// attempt not held here.
    pub fn register_secret(&self, attempt: AttemptId, value: &[u8]) -> bool {
        if value.is_empty() {
            return false;
        }
        let pipe = {
            let mut state = self.state();
            if let Some(waiting) = state.awaiting.get_mut(&attempt) {
                waiting
                    .secrets
                    .push(sentinel_protocol::secrets::SecretBytes::copy_from(value));
                return true;
            }
            match state.live.get(&attempt) {
                Some(live) => Arc::clone(&live.logs),
                None => return false,
            }
        };
        pipe.register_secret(value)
    }

    fn accept_spec(
        &self,
        attempt: AttemptId,
        context: JobContext,
        bytes: Vec<u8>,
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        let waiting = {
            let mut state = self.state();
            if state.awaiting.get(&attempt).is_none_or(|w| w.declining) {
                return;
            }
            state.awaiting.remove(&attempt).expect("checked present")
        };
        let offer = waiting.offer;
        let job_index = offer.job_index as usize;
        let decoded = RunSpec::decode(&bytes);
        match decoded {
            Ok(spec) if valid_delivery(&spec, job_index, &secret_bundle) => {
                self.spawn(
                    offer,
                    spec,
                    context,
                    job_index,
                    waiting.secrets,
                    secret_bundle,
                );
            }
            _ => self.send(
                attempt,
                offer.fence,
                Event::Failed(sentinel_core::FailureClass::Preparation),
                None,
            ),
        }
    }

    fn spawn(
        &self,
        offer: Offer,
        spec: RunSpec,
        context: JobContext,
        job_index: usize,
        secrets: Vec<sentinel_protocol::secrets::SecretBytes>,
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        let cancel: Cancel = Arc::new(AtomicBool::new(false));
        let logs = {
            let state = self.state();
            let mut redactor = Redactor::new();
            for secret in &secrets {
                redactor.register(secret.as_slice());
            }
            for value in &secret_bundle.values {
                redactor.register(value.expose());
            }
            match LogPipe::open_in(&self.spool, offer.attempt, redactor, state.reporter.clone()) {
                Ok(pipe) => Arc::new(pipe),
                Err(_) => {
                    drop(state);
                    self.send(
                        offer.attempt,
                        offer.fence,
                        Event::Failed(sentinel_core::FailureClass::Publication),
                        None,
                    );
                    return;
                }
            }
        };
        self.state().live.insert(
            offer.attempt,
            Live {
                cancel: Arc::clone(&cancel),
                logs: Arc::clone(&logs),
                canceling: false,
                lost: false,
            },
        );
        let executor = Arc::clone(&self.0);
        let mut job = Job {
            worker: self.worker,
            attempt: offer.attempt,
            fence: offer.fence,
            job_index,
            digest: offer.image_digest.clone(),
            spec,
            context,
            images: self.images.clone(),
            caches: Vec::new(),
            mirrors: self.mirrors.clone(),
            prepare_hold: self.state().prepare_hold,
            secret_bundle,
        };
        // On disk before anything runs: a crash from here on leaves a
        // marker the next process reconciles. If the marker cannot be
        // written the attempt must not start — a crash would leave a
        // spool with no marker, which recovery discards as reported.
        if recovery::mark(&self.root, offer.attempt, offer.fence).is_err() {
            self.state().live.remove(&offer.attempt);
            self.send(
                offer.attempt,
                offer.fence,
                Event::Failed(sentinel_core::FailureClass::Publication),
                None,
            );
            return;
        }
        let spawned = thread::Builder::new()
            .name(format!("sentinel-attempt-{}", offer.attempt))
            .spawn(move || {
                let (attempt, fence) = (job.attempt, job.fence);
                (executor.notify)(Notice::Started(attempt));
                let pipe = Arc::clone(&logs);
                let output: Arc<dyn attempt::Output> = logs;
                let sink: &dyn artifacts::Sink = &*executor;
                // A panic anywhere in the attempt must not leave it held,
                // renewed and running until the controller's backstop: tear
                // down what it may have left and report it as a runtime
                // failure, like any other thing the runtime could not do.
                let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    attempt::run(&executor.root, &mut job, &*executor, output, sink, &cancel)
                }));
                let verdict = match ran {
                    Ok((verdict, _)) => verdict,
                    Err(_) => {
                        cancel.store(true, Ordering::Release);
                        let _ = podman::remove_named(&format!("sentinel-{attempt}"));
                        let _ = crate::workspace::remove_tree(
                            &executor
                                .root
                                .join(crate::workspace::WORKSPACES_DIR)
                                .join(attempt.to_string()),
                        );
                        // What it printed before the panic is delivered and
                        // the log closed, so the spool goes too.
                        if attempt::Output::complete(&*pipe) {
                            recovery::mark_ended(&executor.root, attempt);
                        }
                        executor.send(
                            attempt,
                            fence,
                            Event::Failed(sentinel_core::FailureClass::Runtime),
                            None,
                        );
                        Verdict::Failed(
                            sentinel_core::FailureClass::Runtime,
                            "the attempt thread panicked".into(),
                        )
                    }
                };
                let delivered = {
                    let mut state = executor.state();
                    state.live.remove(&job.attempt);
                    state.artifact_waits.remove(&job.attempt);
                    // The marker outlives the report: if the terminal event
                    // is still waiting for a session, a crash now must be
                    // reconciled, not forgotten.
                    !state.pending.iter().any(|p| p.0 == job.attempt)
                };
                if delivered {
                    recovery::unmark(&executor.root, job.attempt);
                }
                let refused = pipe.refusals();
                if refused.total() > 0 {
                    (executor.notify)(Notice::SpoolRefused {
                        attempt: job.attempt,
                        refused,
                    });
                }
                (executor.notify)(Notice::Finished(job.attempt, verdict));
                // Finalization is where the store grows: one bounded pass
                // now keeps publication's remains from accumulating.
                executor.sweep_caches();
            });
        if spawned.is_err() {
            // Nothing ran: the marker goes, the attempt is reported as the
            // runtime failing to start it.
            self.state().live.remove(&offer.attempt);
            recovery::unmark(&self.root, offer.attempt);
            self.send(
                offer.attempt,
                offer.fence,
                Event::Failed(sentinel_core::FailureClass::Runtime),
                None,
            );
        }
    }
}

impl Inner {
    pub fn runtime(&self) -> &podman::Runtime {
        &self.runtime
    }

    /// The worker's image pulls and what its store is known to hold —
    /// the locality record a later part advertises to placement.
    pub fn images(&self) -> &Images {
        &self.images
    }

    /// The background prefetcher the controller's hints drive (K05).
    pub fn prefetcher(&self) -> &crate::prefetch::Prefetcher {
        &self.prefetch
    }

    /// What starting this executor found of the previous process.
    pub fn recovered(&self) -> &Recovered {
        &self.recovered
    }

    /// Attempts still to be abandoned to the controller.
    pub fn leftovers_pending(&self) -> usize {
        self.state().leftovers.len()
    }

    /// No attempt running or waiting for its spec.
    pub fn state_is_idle(&self) -> bool {
        let state = self.state();
        state.live.is_empty() && state.awaiting.is_empty()
    }

    /// Reports that found no session and wait for the next one.
    pub fn pending_reports(&self) -> usize {
        self.state().pending.len()
    }

    /// Hand the previous process's attempts to the controller: the spool's
    /// frames and end first (the attempt is still held, so they are
    /// accepted — or refused if its lease already expired), then the
    /// abandonment under the fence, then the marker goes.
    fn abandon_leftovers(&self, leftovers: Vec<Leftover>, reporter: Reporter) {
        for leftover in leftovers {
            let delivered = if leftover.spooled {
                match LogPipe::recover(&self.spool, leftover.attempt, Some(reporter.clone())) {
                    Ok(pipe) => {
                        let pipe = Arc::new(pipe);
                        self.state()
                            .recovering
                            .insert(leftover.attempt, Arc::clone(&pipe));
                        let ok = attempt::Output::complete(&*pipe);
                        self.state().recovering.remove(&leftover.attempt);
                        if ok {
                            // The spool is gone now; a crash before the
                            // abandon lands must still call this delivered.
                            recovery::mark_ended(&self.root, leftover.attempt);
                        }
                        ok
                    }
                    Err(_) => false,
                }
            } else {
                // No spool: either its end was already durable when it went
                // (`ended`), or the frames are genuinely gone — say which.
                leftover.ended
            };
            if reporter.abandon(leftover.attempt, leftover.fence).is_err() {
                // Session gone: keep it for the next attach.
                self.state().leftovers.push(leftover);
                return;
            }
            recovery::unmark(&self.root, leftover.attempt);
            (self.notify)(Notice::Abandoned {
                attempt: leftover.attempt,
                log_delivered: delivered,
            });
        }
    }

    /// One bounded reclamation pass over the cache root — skipped while
    /// another runs, because the running pass already covers its work.
    /// A pass that touched nothing stays quiet, but every pass ends by
    /// emitting the K08 availability snapshot: the sweep is the bounded
    /// cadence (start plus post-attempt) that Part 08's placement feed
    /// rides, so the occupancy it already computed costs a second walk
    /// never.
    fn sweep_caches(&self) {
        let mut cursor = match self.gc_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let stats = sentinel_cache::gc::resume(
            &self.root.join(sentinel_cache::CACHE_DIR),
            sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
            sentinel_cache::gc::DEFAULT_PASS_WORK,
            &mut cursor,
        );
        drop(cursor);
        // The mirrors share the pass's cadence: bounded, and skipped for
        // any mirror a checkout holds (P07-22).
        if let Some(mirrors) = &self.mirrors {
            let _ = mirrors.sweep(crate::checkout::MIRRORS_BUDGET_BYTES);
        }
        if self
            .cache_bytes
            .swap(stats.estimated_bytes, std::sync::atomic::Ordering::Relaxed)
            != stats.estimated_bytes
        {
            self.cache_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        (self.notify)(Notice::Availability(Availability {
            images_held: self.images.held(),
            images_in_flight: self.images.in_flight(),
            cache_entries: stats.entries_seen,
            cache_generations: stats.generations_seen,
            cache_bytes: stats.estimated_bytes,
            truncated: stats.truncated,
        }));
        if stats.did_work() {
            (self.notify)(Notice::CacheSwept(stats));
        }
    }

    /// The lease watchdog: once the lease the last renewal granted —
    /// measured on this machine's monotonic clock from the heartbeat that
    /// asked for it, less the guard — has run out, no attempt here is ours
    /// any more. End them all, forced, and report nothing: the controller
    /// settles them by expiry, and a report would be stale, or worse,
    /// recorded as a cancel nobody asked for.
    fn watch_lease(&self) {
        let lost: Vec<(AttemptId, Cancel)> = {
            let mut state = self.state();
            let Some(deadline) = state.lease_deadline else {
                return;
            };
            if Instant::now() < deadline || state.live.is_empty() {
                return;
            }
            state.lease_deadline = None;
            state
                .live
                .iter_mut()
                .map(|(id, live)| {
                    live.canceling = true;
                    live.lost = true;
                    (*id, Arc::clone(&live.cancel))
                })
                .collect()
        };
        for (attempt, cancel) in &lost {
            cancel.store(true, Ordering::Release);
            let _ = podman::remove_named(&format!("sentinel-{attempt}"));
        }
        (self.notify)(Notice::LeaseLost(
            lost.into_iter().map(|(a, _)| a).collect(),
        ));
    }

    /// Spec requests that went unanswered are asked again; an attempt with
    /// no spec past [`SPEC_DEADLINE`] is handed back to the controller. It
    /// stays held (and renewed) until the hand-back is on the wire, and a
    /// spec that arrives meanwhile is not used.
    fn watch_specs(&self) {
        let (reporter, ask, give_back) = {
            let mut state = self.state();
            let Some(reporter) = state.reporter.clone() else {
                return;
            };
            let (mut ask, mut give_back) = (Vec::new(), Vec::new());
            for (attempt, waiting) in state.awaiting.iter_mut() {
                if waiting.declining || waiting.since.elapsed() >= SPEC_DEADLINE {
                    waiting.declining = true;
                    give_back.push((*attempt, waiting.offer.fence));
                } else if waiting.asked.elapsed() >= SPEC_RETRY {
                    waiting.asked = Instant::now();
                    ask.push(*attempt);
                }
            }
            (reporter, ask, give_back)
        };
        for attempt in ask {
            let _ = reporter.need_spec(attempt);
        }
        for (attempt, fence) in give_back {
            if reporter.decline(attempt, fence).is_ok() {
                self.state().awaiting.remove(&attempt);
                (self.notify)(Notice::HandedBack(attempt));
            }
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The log pipe of a live or recovering attempt.
    fn pipe(&self, attempt: AttemptId) -> Option<Arc<LogPipe>> {
        let state = self.state();
        state
            .live
            .get(&attempt)
            .map(|l| Arc::clone(&l.logs))
            .or_else(|| state.recovering.get(&attempt).cloned())
    }

    fn send(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Option<Vec<u8>>) {
        let mut state = self.state();
        if state.live.get(&attempt).is_some_and(|live| live.lost) {
            // Ended by the lease watchdog: the controller settles it by
            // expiry; nothing is reported, not even the forced verdict.
            return;
        }
        let sent = match (&state.reporter, &summary) {
            (Some(reporter), Some(summary)) => reporter
                .finish(attempt, fence, event, summary.clone())
                .is_ok(),
            (Some(reporter), None) => reporter.report(attempt, fence, event).is_ok(),
            (None, _) => false,
        };
        if !sent {
            state.pending.push((attempt, fence, event, summary));
        }
    }

    /// One in-flight artifact frame under the send gate: refuses once the
    /// stream is closed, and a dead wire resolves the watch `Store` so the
    /// capture settles without another wait.
    fn stream(
        &self,
        attempt: AttemptId,
        send: impl FnOnce(&Reporter) -> std::result::Result<(), sentinel_link::Error>,
    ) -> bool {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return false;
        };
        let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(watch.peek(), Some(Reply::Done(_))) {
            return false;
        }
        let Some(reporter) = self.state().reporter.clone() else {
            watch.resolve(Reply::Done(ArtifactCode::Store));
            return false;
        };
        if send(&reporter).is_err() {
            watch.resolve(Reply::Done(ArtifactCode::Store));
            return false;
        }
        true
    }
}

impl Report for Inner {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event) {
        self.send(attempt, fence, event, None);
    }
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>) {
        self.send(attempt, fence, event, Some(summary));
    }
    /// Cache notes are process diagnostics, not wire traffic: the
    /// controller's summary format is not theirs to ride.
    fn cache_note(&self, attempt: AttemptId, note: CacheNote) {
        (self.notify)(Notice::CachePublished { attempt, note });
    }
    /// The costly-hit flag is the same kind of diagnostic — the summary's
    /// per-entry record carries the flag; the notice carries the numbers.
    fn costly_hit(
        &self,
        attempt: AttemptId,
        name: &str,
        costly: sentinel_cache::Costly,
        stats: &sentinel_cache::Stats,
    ) {
        (self.notify)(Notice::CostlyCacheHit {
            attempt,
            name: name.to_owned(),
            costly,
            stats: *stats,
        });
    }
    /// Q08: the session's remote-cache transport, when the link offers
    /// one. It is session state, not attempt state — a reconnect that
    /// replaces the reporter replaces this handle with it, and an
    /// attempt holding the old one simply drops its offers.
    fn remote(&self) -> Option<std::sync::Arc<dyn sentinel_cache::remote::Remote>> {
        self.state()
            .reporter
            .as_ref()
            .and_then(Reporter::remote_cache)
    }
}

impl artifacts::Sink for Inner {
    fn capable(&self) -> bool {
        self.state()
            .reporter
            .as_ref()
            .is_some_and(Reporter::artifacts)
    }

    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode> {
        let watch = Arc::new(Watch::default());
        let reporter = {
            let mut state = self.state();
            let reporter = state.reporter.clone();
            match &reporter {
                Some(r) if r.artifacts() => {
                    state.artifact_waits.insert(attempt, Arc::clone(&watch));
                }
                _ => return Some(ArtifactCode::Stale),
            }
            reporter
        };
        if reporter
            .expect("capability checked")
            .artifact_begin(attempt, name)
            .is_err()
        {
            self.state().artifact_waits.remove(&attempt);
            return Some(ArtifactCode::Store);
        }
        match watch.wait_reply(REPLY_TIMEOUT) {
            Some(Reply::Granted) => None,
            answer => {
                self.state().artifact_waits.remove(&attempt);
                match answer {
                    Some(Reply::Done(code)) => Some(code),
                    _ => Some(ArtifactCode::Store),
                }
            }
        }
    }

    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool {
        self.stream(attempt, |reporter| {
            reporter.artifact_file(attempt, path, len, mode)
        })
    }

    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool {
        self.stream(attempt, |reporter| {
            reporter.artifact_data(attempt, seq, bytes)
        })
    }

    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return ArtifactCode::Stale;
        };
        {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(Reply::Done(code)) = watch.peek() {
                self.state().artifact_waits.remove(&attempt);
                return code;
            }
            match self.state().reporter.clone() {
                Some(reporter) => {
                    if reporter.artifact_end(attempt, name).is_err() {
                        watch.resolve(Reply::Done(ArtifactCode::Store));
                    }
                }
                None => watch.resolve(Reply::Done(ArtifactCode::Store)),
            }
        }
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }

    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode {
        let watch = {
            let mut state = self.state();
            match state.artifact_waits.get(&attempt) {
                Some(watch) => Arc::clone(watch),
                None => {
                    if state.reporter.is_none() {
                        return ArtifactCode::Stale;
                    }
                    let watch = Arc::new(Watch::default());
                    state.artifact_waits.insert(attempt, Arc::clone(&watch));
                    watch
                }
            }
        };
        {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(Reply::Done(code)) = watch.peek() {
                self.state().artifact_waits.remove(&attempt);
                return code;
            }
            match self.state().reporter.clone() {
                Some(reporter) => {
                    if reporter.artifact_absent(attempt, name, reason).is_err() {
                        watch.resolve(Reply::Done(ArtifactCode::Store));
                    }
                }
                None => watch.resolve(Reply::Done(ArtifactCode::Store)),
            }
        }
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }

    fn settle(&self, attempt: AttemptId, _name: &str) -> ArtifactCode {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return ArtifactCode::Store;
        };
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }
}

impl LinkExecutor for Executor {
    /// P07-6: the image keys the local store is known to hold (newest
    /// first, bounded by the wire's list limit) and the cache store's bytes
    /// as the last sweep estimated them. Both come from state the worker
    /// already keeps — no store scan, no podman call; the version moves
    /// when either changes, so the link resends only then.
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        let version = self.images.version().wrapping_add(
            self.cache_version
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        Some((
            version,
            sentinel_protocol::negotiate::Availability {
                images: self
                    .images
                    .held_keys(sentinel_protocol::limits::MAX_LIST_ITEMS),
                cache_bytes: self.cache_bytes.load(std::sync::atomic::Ordering::Relaxed),
                load_ns: 0,
            },
        ))
    }

    /// K05: the controller's latest hint replaces the wanted set; pulls
    /// run in the background within the prefetcher's bounds.
    fn prefetch(&self, images: &[String]) {
        self.prefetch.hint(images);
    }

    fn offered(&self, offer: &Offer) -> bool {
        let mut state = self.state();
        // An attempt already taken — a repeated offer, in this session or
        // an earlier one — is acknowledged again, never started twice.
        if state.live.contains_key(&offer.attempt) || state.awaiting.contains_key(&offer.attempt) {
            return true;
        }
        if state.live.len() + state.awaiting.len() >= MAX_LIST_ITEMS || state.reporter.is_none() {
            return false;
        }
        let now = Instant::now();
        // Until the first renewal, the offer's own lease bounds the work:
        // it was granted no earlier than it arrived.
        if state.lease_deadline.is_none() {
            state.lease_deadline = Some(now + LEASE.saturating_sub(LEASE_GUARD));
        }
        state.awaiting.insert(
            offer.attempt,
            Awaiting {
                offer: offer.clone(),
                since: now,
                asked: now,
                declining: false,
                secrets: Vec::new(),
            },
        );
        true
    }

    fn accepted(&self, attempt: AttemptId) {
        let reporter = {
            let mut state = self.state();
            let Some(waiting) = state.awaiting.get_mut(&attempt) else {
                return;
            };
            waiting.asked = Instant::now();
            state.reporter.clone()
        };
        if let Some(reporter) = reporter {
            let _ = reporter.need_spec(attempt);
        }
    }

    fn stop(&self, attempt: AttemptId) {
        let live = {
            let mut state = self.state();
            state.awaiting.remove(&attempt);
            state.live.get(&attempt).map(|l| Arc::clone(&l.cancel))
        };
        if let Some(cancel) = live {
            cancel.store(true, Ordering::Release);
            // End the container now, off this thread — it is the session's
            // heartbeat thread, and a removal can take seconds; the attempt
            // thread finalizes what is left and exits.
            let spawned = thread::Builder::new()
                .name(format!("sentinel-stop-{attempt}"))
                .spawn(move || {
                    let _ = podman::remove_named(&format!("sentinel-{attempt}"));
                });
            if spawned.is_err() {
                let _ = podman::remove_named(&format!("sentinel-{attempt}"));
            }
        }
        (self.notify)(Notice::Stopped(attempt));
    }

    fn cancel(&self, attempt: AttemptId) {
        let (cancel, grace) = {
            let mut state = self.state();
            let grace = state.cancel_grace;
            match state.live.get_mut(&attempt) {
                Some(live) if !live.canceling => {
                    live.canceling = true;
                    (Arc::clone(&live.cancel), grace)
                }
                _ => return,
            }
        };
        // Desired state first, so a step that ends by itself meanwhile is
        // still reported as canceled; then the signals, off this thread.
        cancel.store(true, Ordering::Release);
        let executor = Arc::clone(&self.0);
        let spawned = thread::Builder::new()
            .name(format!("sentinel-cancel-{attempt}"))
            .spawn(move || {
                let outcome = podman::terminate_named(&format!("sentinel-{attempt}"), grace);
                match outcome {
                    Ok(podman::Terminated::Graceful | podman::Terminated::Forced) => {
                        let forced = matches!(outcome, Ok(podman::Terminated::Forced));
                        (executor.notify)(Notice::Canceled { attempt, forced });
                    }
                    // Nothing was signalled — an exec still starting, a
                    // runtime that could not be asked — while the attempt
                    // may still be running a step: let the cancel the next
                    // heartbeat repeats try again rather than dropping it
                    // for the rest of the step.
                    Ok(podman::Terminated::Gone) | Err(_) => {
                        if let Some(live) = executor.state().live.get_mut(&attempt) {
                            live.canceling = false;
                        }
                    }
                }
            });
        if spawned.is_err()
            && let Some(live) = self.state().live.get_mut(&attempt)
        {
            live.canceling = false;
        }
    }

    fn held(&self) -> Vec<AttemptId> {
        let state = self.state();
        state
            .live
            .keys()
            .chain(state.awaiting.keys())
            .copied()
            .collect()
    }

    fn renewed(&self, until: UnixMillis) {
        self.renewed_at(until, Instant::now());
    }

    /// The controller renewed to `now + LEASE` after the heartbeat left at
    /// `sent`, so on this machine the lease lasts at least until
    /// `sent + LEASE`. The controller's wall-clock deadline is never
    /// compared with this machine's clock: skew between the two hosts can
    /// neither kill live work early nor let it run past its expiry.
    fn renewed_at(&self, _until: UnixMillis, sent: Instant) {
        self.state().lease_deadline = Some(sent + LEASE.saturating_sub(LEASE_GUARD));
    }

    fn attached(&self, reporter: Reporter) {
        let (pending, pipes) = {
            let mut state = self.state();
            state.reporter = Some(reporter.clone());
            (
                std::mem::take(&mut state.pending),
                state
                    .live
                    .values()
                    .map(|l| Arc::clone(&l.logs))
                    .collect::<Vec<_>>(),
            )
        };
        for pipe in pipes {
            pipe.attached(reporter.clone());
        }
        // Leftovers of the previous process: deliver what they printed,
        // close the log, then abandon them — off this thread, since the
        // delivery waits for acknowledgements.
        let leftovers = std::mem::take(&mut self.state().leftovers);
        if !leftovers.is_empty() {
            // Handed through a slot so a failed spawn re-queues them for
            // the next attach instead of waiting for a process restart.
            let slot = Arc::new(Mutex::new(Some(leftovers)));
            let hand = Arc::clone(&slot);
            let executor = Arc::clone(&self.0);
            let reporter = reporter.clone();
            let spawned = thread::Builder::new()
                .name("sentinel-recovery".into())
                .spawn(move || {
                    let leftovers = hand
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take()
                        .unwrap_or_default();
                    executor.abandon_leftovers(leftovers, reporter);
                });
            if spawned.is_err()
                && let Some(leftovers) = slot.lock().unwrap_or_else(|p| p.into_inner()).take()
            {
                self.state().leftovers = leftovers;
            }
        }
        for (attempt, fence, event, summary) in pending {
            let sent = match &summary {
                Some(bytes) => reporter
                    .finish(attempt, fence, event, bytes.clone())
                    .is_ok(),
                None => reporter.report(attempt, fence, event).is_ok(),
            };
            if !sent {
                self.state().pending.push((attempt, fence, event, summary));
            } else if summary.is_some() || matches!(event, Event::Passed | Event::Failed(_)) {
                recovery::unmark(&self.root, attempt);
            }
        }
        // Specs asked for on a lost session: ask again (hand-backs under
        // way go out with the next watchdog look).
        let awaiting: Vec<AttemptId> = {
            let mut state = self.state();
            let now = Instant::now();
            state
                .awaiting
                .iter_mut()
                .filter(|(_, waiting)| !waiting.declining)
                .map(|(attempt, waiting)| {
                    waiting.asked = now;
                    *attempt
                })
                .collect()
        };
        for attempt in awaiting {
            let _ = reporter.need_spec(attempt);
        }
    }

    fn bulk_detached(&self) {
        let pipes: Vec<Arc<LogPipe>> = self
            .state()
            .live
            .values()
            .map(|l| Arc::clone(&l.logs))
            .collect();
        for pipe in pipes {
            pipe.resync();
        }
    }

    fn detached(&self) {
        let (pipes, watches): (Vec<Arc<LogPipe>>, Vec<Arc<Watch>>) = {
            let mut state = self.state();
            state.reporter = None;
            (
                state.live.values().map(|l| Arc::clone(&l.logs)).collect(),
                state.artifact_waits.drain().map(|(_, w)| w).collect(),
            )
        };
        for pipe in pipes {
            pipe.detached();
        }
        // Any capture waiting on a controller reply is told the link is
        // gone; nothing was committed, so the artifact fails to publish.
        for watch in watches {
            watch.resolve(Reply::Done(ArtifactCode::Store));
        }
    }

    fn artifact_granted(&self, attempt: AttemptId, _name: &str) {
        let watch = self.state().artifact_waits.get(&attempt).cloned();
        if let Some(watch) = watch {
            // Resolve under the send gate: an `ArtifactFile` either ships
            // before this grant is seen or sees it first — never both.
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            watch.resolve(Reply::Granted);
        }
    }

    fn artifact_verdict(&self, attempt: AttemptId, _name: &str, code: ArtifactCode) {
        let watch = self.state().artifact_waits.get(&attempt).cloned();
        if let Some(watch) = watch {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            watch.resolve(Reply::Done(code));
        }
    }

    fn log_acked(&self, attempt: AttemptId, through: u64) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.acked(through);
        }
    }

    fn log_refused(&self, attempt: AttemptId) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.refused();
        }
    }

    fn log_ended(&self, attempt: AttemptId) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.end_acked();
        }
    }

    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>) {
        self.accept_spec(
            attempt,
            context,
            bytes,
            sentinel_protocol::secrets::DeliveryBundle::empty(),
        );
    }

    fn spec_with_secrets(
        &self,
        attempt: AttemptId,
        context: JobContext,
        bytes: Vec<u8>,
        secrets: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        self.accept_spec(attempt, context, bytes, secrets);
    }

    /// A definitive refusal: the attempt is settled at once as the
    /// preparation failure it is, never left for the lease to expire. When
    /// the controller already settled it (cancelled, or not this worker's)
    /// the report is refused as stale and changes nothing.
    fn no_spec(&self, attempt: AttemptId) {
        let Some(waiting) = self.state().awaiting.remove(&attempt) else {
            return;
        };
        if !waiting.declining {
            self.send(
                attempt,
                waiting.offer.fence,
                Event::Failed(sentinel_core::FailureClass::Preparation),
                None,
            );
        }
        (self.notify)(Notice::SpecRefused(attempt));
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Ask every live attempt to stop; their threads finalize on their own.
        for live in self.state().live.values() {
            live.cancel.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "../tests/support/live.rs"]
mod live;

#[cfg(test)]
mod tests {
    use super::live::{DIGEST, IMAGE, Live, eventually, podman_enabled};
    use super::*;
    use sentinel_core::{FailureClass, JobState, Outcome};

    /// P04-30. A step panics the attempt thread (a test-only hook in
    /// `attempt::run`) while its container runs and its output is spooled.
    /// Before the fix nothing caught it: the attempt stayed held and renewed
    /// until the controller's backstop, the container and the workspace
    /// until the next restart. Now the panic is contained: the container
    /// and the workspace are removed, what the attempt printed reaches the
    /// controller and the log is closed, and it is reported as the runtime
    /// failure it is — nothing is left held.
    #[test]
    fn a_panicking_attempt_is_torn_down_and_reported() {
        if !podman_enabled() {
            return;
        }
        let (live, executor) = Live::start(|dir, worker| {
            Executor::start(dir.to_path_buf(), worker, |_| {}, false).unwrap()
        });
        let yaml = format!(
            "schema: 1\non: [push]\njobs:\n  work:\n    image: {IMAGE}@{DIGEST}\n    resources: {{ cpu: 1, memory: 128MiB }}\n    steps:\n      - id: first\n        run: 'echo before the panic'\n      - id: {}\n        run: 'sleep 300'\n",
            attempt::PANIC_STEP
        );
        let (run, jobs) = live.enqueue(&yaml);
        let job = jobs[0];
        eventually("the job ended", Duration::from_secs(120), || {
            matches!(live.job(job).state, JobState::Terminal(_))
        });
        let row = live.job(job);
        assert_eq!(
            (row.state, row.failure_class),
            (
                JobState::Terminal(Outcome::InfraFailed),
                Some(FailureClass::Runtime)
            )
        );
        eventually("the container removed", Duration::from_secs(30), || {
            podman::owned(live.worker).unwrap().is_empty()
        });
        eventually("nothing held", Duration::from_secs(30), || {
            executor.state_is_idle()
        });
        assert!(
            crate::workspace::Workspace::leftovers(&live.worker_dir)
                .unwrap()
                .is_empty()
        );
        let attempt = live.attempt(job).unwrap();
        let tail = live.logs.tail(run, job, attempt, 0, 100, None).unwrap();
        assert!(tail.complete, "the log was closed");
        assert!(
            tail.frames
                .iter()
                .any(|f| String::from_utf8_lossy(&f.bytes).contains("before the panic"))
        );
        eventually(
            "the marker and the spool gone",
            Duration::from_secs(30),
            || {
                recovery::leftovers(&live.worker_dir).unwrap().is_empty()
                    && crate::spool::Spool::leftovers(&live.worker_dir)
                        .unwrap()
                        .is_empty()
            },
        );
        live.stop();
    }
}
