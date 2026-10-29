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

#[derive(Debug)]
pub enum Notice {
    Started(AttemptId),
    Finished(AttemptId, Verdict),
    SpecRefused(AttemptId),
    HandedBack(AttemptId),
    Stopped(AttemptId),
    Canceled {
        attempt: AttemptId,
        forced: bool,
    },
    LeaseLost(Vec<AttemptId>),
    Abandoned {
        attempt: AttemptId,
        log_delivered: bool,
    },
    MirrorsUnavailable(String),
    SpoolRefused {
        attempt: AttemptId,
        refused: Refused,
    },
    CachePublished {
        attempt: AttemptId,
        note: CacheNote,
    },
    CacheSwept(sentinel_cache::gc::GcStats),
    ImagesReclaimed(usize),
    CostlyCacheHit {
        attempt: AttemptId,
        name: String,
        costly: sentinel_cache::Costly,
        stats: sentinel_cache::Stats,
    },
    Availability(Availability),
    /// One attempt's cache figures, summed over its entries.
    CacheFigures(CacheTotals),
    OfferRefused {
        attempt: AttemptId,
        free_bytes: u64,
        floor_bytes: u64,
    },
    ShutDown {
        ended: usize,
        left: usize,
        handed_back: usize,
    },
}

pub fn admission_floor(total: u64) -> u64 {
    (total / 8).clamp(512 << 20, 2 << 30)
}

/// The scratch disk a host offers jobs out of `free` bytes on the data directory's file system: the free
/// space less the same reserve the admission floor keeps (an eighth, 512 MiB to 2 GiB).
pub fn job_disk_room(free: u64) -> u64 {
    free.saturating_sub(admission_floor(free))
}

fn admits(free: Option<u64>, floor: u64) -> bool {
    free.is_none_or(|free| free >= floor)
}

/// What one attempt's cache entries cost and did, summed; durations are monotonic nanoseconds, and a phase that
/// never ran adds nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheTotals {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub costly_hits: u64,
    pub lock_wait_ns: u64,
    pub clone_ns: u64,
    pub first_touch_ns: u64,
    pub commit_ns: u64,
    /// Bytes and copied bytes of the hits only: a miss restored nothing.
    pub restored_bytes: u64,
    pub copied_bytes: u64,
    pub staged_bytes: u64,
    pub dirty_bytes: u64,
}

impl CacheTotals {
    pub fn of(records: &[sentinel_protocol::summary::CacheRecord]) -> CacheTotals {
        let mut totals = CacheTotals::default();
        for r in records {
            totals.entries += 1;
            if r.outcome == "hit" {
                totals.hits += 1;
                totals.restored_bytes = totals.restored_bytes.saturating_add(r.bytes);
                totals.copied_bytes = totals.copied_bytes.saturating_add(r.copied_bytes);
            } else {
                totals.misses += 1;
            }
            totals.costly_hits += u64::from(r.costly_hit);
            let add = |sum: &mut u64, value: Option<u64>| {
                *sum = sum.saturating_add(value.unwrap_or(0));
            };
            add(&mut totals.lock_wait_ns, r.lock_wait_ns);
            add(&mut totals.clone_ns, r.clone_ns);
            add(&mut totals.first_touch_ns, r.first_touch_ns);
            add(&mut totals.commit_ns, r.commit_ns);
            add(&mut totals.staged_bytes, r.staged_bytes);
            add(&mut totals.dirty_bytes, r.dirty_bytes);
        }
        totals
    }
}

#[derive(Clone, Debug)]
pub struct Availability {
    /// The measured restore and rebuild cost per cache class, settled estimates only (docs/cache.md).
    pub cache_costs: [sentinel_cache::ClassFigures; sentinel_protocol::cache::Class::ALL.len()],
    pub images_held: Vec<String>,
    pub images_in_flight: usize,
    pub cache_entries: u64,
    pub cache_generations: u64,
    pub cache_bytes: u64,
    pub truncated: bool,
}

pub const DEFAULT_CANCEL_GRACE: Duration = Duration::from_secs(30);
pub const LEASE_GUARD: Duration = Duration::from_secs(5);
const LEASE: Duration = Duration::from_millis(sentinel_protocol::limits::LEASE_MS as u64);
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);
pub const SPEC_RETRY: Duration = Duration::from_secs(10);
const REPORT_RESEND: Duration = Duration::from_secs(5);
const REPORT_KEEP: Duration = Duration::from_secs(600);
pub const SPEC_DEADLINE: Duration = Duration::from_secs(60);

struct Live {
    cancel: Cancel,
    logs: Arc<LogPipe>,
    canceling: bool,
    lost: bool,
    store: podman::Store,
}

struct Awaiting {
    offer: Offer,
    since: Instant,
    asked: Instant,
    declining: bool,
    /// A cancel arrived before the spec did: the attempt starts canceled.
    canceled: bool,
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
    if bundle
        .values
        .iter()
        .any(|value| value.expose().len() < crate::redact::MIN_SECRET_BYTES)
    {
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
                // Credential helpers and Docker config extensions could run helpers or add auth sources, so only the explicit auths map is accepted.
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
        assert!(!valid_delivery(&spec, 0, &bundle(b"123", auth, true)));
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

struct Unconfirmed {
    fence: Fence,
    event: Event,
    summary: Option<Vec<u8>>,
    first: Instant,
    sent: Instant,
}

fn forget_unconfirmed(unconfirmed: &mut HashMap<AttemptId, Unconfirmed>, now: Instant) {
    unconfirmed.retain(|_, u| now.saturating_duration_since(u.first) < REPORT_KEEP);
}

fn due_resends(
    unconfirmed: &mut HashMap<AttemptId, Unconfirmed>,
    now: Instant,
) -> Vec<(AttemptId, Fence, Event, Option<Vec<u8>>)> {
    let mut due = Vec::new();
    for (attempt, u) in unconfirmed.iter_mut() {
        if now.saturating_duration_since(u.sent) >= REPORT_RESEND {
            u.sent = now;
            due.push((*attempt, u.fence, u.event, u.summary.clone()));
        }
    }
    due
}

struct State {
    reporter: Option<Reporter>,
    unconfirmed: HashMap<AttemptId, Unconfirmed>,
    awaiting: HashMap<AttemptId, Awaiting>,
    /// Attempts whose spec arrived and whose live entry is not made yet, with whether a cancel came meanwhile.
    starting: HashMap<AttemptId, bool>,
    live: HashMap<AttemptId, Live>,
    pending: Vec<(AttemptId, Fence, Event, Option<Vec<u8>>)>,
    lease_deadline: Option<Instant>,
    cancel_grace: Duration,
    prepare_hold: Duration,
    network: podman::Network,
    runtime: attempt::Runtime,
    leftovers: Vec<Leftover>,
    recovering: HashMap<AttemptId, Arc<LogPipe>>,
    artifact_waits: HashMap<AttemptId, Arc<Watch>>,
    draining: bool,
}

/// The gate makes each frame's check-and-send atomic against a verdict closing the artifact.
#[derive(Default)]
struct Watch {
    reply: Mutex<Option<Reply>>,
    cv: std::sync::Condvar,
    gate: Mutex<()>,
}

#[derive(Clone, Copy)]
enum Reply {
    Granted,
    Done(ArtifactCode),
}

impl Watch {
    fn resolve(&self, reply: Reply) {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner()) = Some(reply);
        self.cv.notify_all();
    }
    fn peek(&self) -> Option<Reply> {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner())
    }
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
    images: Images,
    prefetch: crate::prefetch::Prefetcher,
    mirrors: Option<crate::checkout::Mirrors>,
    spool: Arc<SpoolSpace>,
    admission_floor: std::sync::atomic::AtomicU64,
    measured_disk: std::sync::atomic::AtomicBool,
    refusal_noted: Mutex<Option<Instant>>,
    state: Mutex<State>,
    gc_lock: Mutex<sentinel_cache::gc::Cursor>,
    cache_bytes: std::sync::atomic::AtomicU64,
    cache_version: std::sync::atomic::AtomicU64,
    budgets: Mutex<StorageBudgets>,
    image_swept: Mutex<Option<std::time::Instant>>,
    notify: Box<dyn Fn(Notice) + Send + Sync>,
    recovered: Recovered,
    costs: sentinel_cache::CostBook,
}

const REFUSAL_NOTICE_EVERY: Duration = Duration::from_secs(30);

const IMAGE_SWEEP_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageBudgets {
    pub cache_bytes: u64,
    pub mirror_bytes: u64,
    pub image_bytes: u64,
}

impl StorageBudgets {
    pub fn sized(total: u64) -> StorageBudgets {
        const GIB: u64 = 1 << 30;
        const MAX: u64 = sentinel_cache::gc::MAX_BUDGET_BYTES;
        StorageBudgets {
            cache_bytes: (total / 5).clamp(GIB, MAX),
            mirror_bytes: (total / 10).clamp(GIB, MAX),
            image_bytes: (total / 5).clamp(2 * GIB, MAX),
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::StorageBudgets;

    #[test]
    fn budgets_follow_the_disk_and_stay_clamped() {
        const GIB: u64 = 1 << 30;
        let big = StorageBudgets::sized(1_000_000_000_000);
        assert_eq!(
            (big.cache_bytes, big.mirror_bytes, big.image_bytes),
            (50 * GIB, 50 * GIB, 50 * GIB)
        );
        assert_eq!(big.cache_bytes, sentinel_cache::gc::MAX_BUDGET_BYTES);
        let small = StorageBudgets::sized(100 * GIB);
        assert_eq!(
            (small.cache_bytes, small.mirror_bytes, small.image_bytes),
            (20 * GIB, 10 * GIB, 20 * GIB)
        );
        let tiny = StorageBudgets::sized(0);
        assert_eq!(
            (tiny.cache_bytes, tiny.mirror_bytes, tiny.image_bytes),
            (GIB, GIB, 2 * GIB)
        );
    }
}

#[cfg(test)]
mod admission_tests {
    use super::{admission_floor, admits};

    #[test]
    fn a_low_disk_refuses_and_an_unmeasured_one_does_not() {
        const GIB: u64 = 1 << 30;
        assert!(!admits(Some(GIB - 1), GIB));
        assert!(admits(Some(GIB), GIB));
        assert!(admits(Some(5 * GIB), GIB));
        assert!(!admits(Some(0), GIB));
        assert!(admits(None, GIB));
    }

    #[test]
    fn the_offered_scratch_disk_is_the_free_space_less_the_reserve() {
        const MIB: u64 = 1 << 20;
        const GIB: u64 = 1 << 30;
        assert_eq!(super::job_disk_room(0), 0);
        assert_eq!(super::job_disk_room(100 * MIB), 0);
        assert_eq!(super::job_disk_room(8 * GIB), 7 * GIB);
        assert_eq!(super::job_disk_room(100 * GIB), 98 * GIB);
    }

    #[test]
    fn the_floor_is_an_eighth_of_the_disk_within_bounds() {
        const MIB: u64 = 1 << 20;
        const GIB: u64 = 1 << 30;
        assert_eq!(admission_floor(0), 512 * MIB);
        assert_eq!(admission_floor(100 * GIB), 2 * GIB);
        assert_eq!(admission_floor(8 * GIB), GIB);
        assert_eq!(admission_floor(1_000_000_000_000), 2 * GIB);
    }
}

impl Default for StorageBudgets {
    fn default() -> Self {
        StorageBudgets {
            cache_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
            mirror_bytes: crate::checkout::MIRRORS_BUDGET_BYTES,
            image_bytes: 50 << 30,
        }
    }
}

impl Executor {
    pub fn start(
        root: PathBuf,
        worker: sentinel_core::WorkerId,
        notify: impl Fn(Notice) + Send + Sync + 'static,
        git_mirrors: bool,
    ) -> Result<Executor> {
        let runtime = podman::probe()?;
        for dir in [
            crate::workspace::WORKSPACES_DIR,
            crate::checkout::MIRRORS_DIR,
            sentinel_cache::attach::ROOT_DIR,
            crate::spool::SPOOL_DIR,
            recovery::ATTEMPTS_DIR,
        ] {
            crate::private_dir_all(&root.join(dir))?;
        }
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
        let (recovered, leftovers) = recovery::recover(&root, worker)?;
        let images = Images::for_worker_data_dir(&root)?;
        let prefetch = crate::prefetch::Prefetcher::new(
            images.clone(),
            crate::prefetch::Bounds::default(),
            crate::prefetch::PodmanProbe::new(),
        );
        let spool = SpoolSpace::new(root.clone(), DEFAULT_SPOOL_RESERVE, DEFAULT_SPOOL_QUOTA);
        let floor = admission_floor(crate::spool::filesystem_bytes(&root).unwrap_or(0));
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
                unconfirmed: HashMap::new(),
                awaiting: HashMap::new(),
                starting: HashMap::new(),
                live: HashMap::new(),
                pending: Vec::new(),
                lease_deadline: None,
                cancel_grace: DEFAULT_CANCEL_GRACE,
                network: podman::Network::None,
                runtime: attempt::Runtime::default(),
                prepare_hold: Duration::ZERO,
                leftovers,
                recovering: HashMap::new(),
                artifact_waits: HashMap::new(),
                draining: false,
            }),
            admission_floor: std::sync::atomic::AtomicU64::new(floor),
            measured_disk: std::sync::atomic::AtomicBool::new(false),
            refusal_noted: Mutex::new(None),
            notify: Box::new(notify),
            gc_lock: Mutex::new(sentinel_cache::gc::Cursor::default()),
            cache_bytes: std::sync::atomic::AtomicU64::new(0),
            cache_version: std::sync::atomic::AtomicU64::new(0),
            budgets: Mutex::new(StorageBudgets::default()),
            image_swept: Mutex::new(None),
            recovered,
            costs: sentinel_cache::CostBook::new(),
        }));
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

    pub fn set_spool_limits(&self, reserve: u64, quota: u64) {
        self.spool.set_limits(reserve, quota);
    }

    pub fn set_admission_floor(&self, bytes: u64) {
        self.admission_floor
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the scratch disk offered to the controller follows the data directory's free space (`true`,
    /// the default for a worker whose operator states no `disk_bytes`) or stays the figure sent at connect.
    pub fn set_measured_disk(&self, measured: bool) {
        self.measured_disk
            .store(measured, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn shutdown(&self, grace: Duration) {
        let (waiting, live, reporter) = {
            let mut state = self.state();
            state.draining = true;
            let waiting: Vec<(AttemptId, Fence)> = state
                .awaiting
                .drain()
                .map(|(attempt, waiting)| (attempt, waiting.offer.fence))
                .collect();
            let live: Vec<(AttemptId, Cancel, podman::Store)> = state
                .live
                .iter_mut()
                .map(|(attempt, live)| {
                    live.canceling = true;
                    live.lost = true;
                    (*attempt, Arc::clone(&live.cancel), live.store.clone())
                })
                .collect();
            (waiting, live, state.reporter.clone())
        };
        let mut handed_back = 0;
        if let Some(reporter) = reporter {
            for (attempt, fence) in waiting {
                if reporter.decline(attempt, fence).is_ok() {
                    handed_back += 1;
                    (self.notify)(Notice::HandedBack(attempt));
                }
            }
        }
        for (_, cancel, _) in &live {
            cancel.store(true, Ordering::Release);
        }
        let root = &self.root;
        thread::scope(|scope| {
            for (attempt, _, store) in &live {
                scope.spawn(move || {
                    let _ = crate::sandbox::remove(root, *attempt, store);
                });
            }
        });
        let until = Instant::now() + grace;
        let left = loop {
            let left = self.state().live.len();
            if left == 0 || Instant::now() >= until {
                break left;
            }
            thread::sleep(Duration::from_millis(20));
        };
        (self.notify)(Notice::ShutDown {
            ended: live.len() - left.min(live.len()),
            left,
            handed_back,
        });
    }

    pub fn set_storage_budgets(&self, budgets: StorageBudgets) {
        *self.budgets.lock().unwrap_or_else(|p| p.into_inner()) = budgets;
    }

    pub fn set_cancel_grace(&self, grace: Duration) {
        self.state().cancel_grace = grace;
    }

    pub fn set_job_network(&self, network: podman::Network) {
        self.state().network = network;
    }

    /// The default executor and, where microVMs can run, their setup (plan 16.8 runtime selection).
    pub fn set_runtime(&self, runtime: attempt::Runtime) {
        self.state().runtime = runtime;
    }

    pub fn set_prepare_hold(&self, hold: Duration) {
        self.state().prepare_hold = hold;
    }

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
            let waiting = state.awaiting.remove(&attempt).expect("checked present");
            // In one step with the removal, so a cancel never finds the attempt in neither place.
            state.starting.insert(attempt, waiting.canceled);
            waiting
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
            _ => {
                self.state().starting.remove(&attempt);
                self.send(
                    attempt,
                    offer.fence,
                    Event::Failed(sentinel_core::FailureClass::Preparation),
                    None,
                )
            }
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
            let mut state = self.state();
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
                    state.starting.remove(&offer.attempt);
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
        {
            let mut state = self.state();
            let canceled = state.starting.remove(&offer.attempt).unwrap_or(false);
            if state.draining {
                return;
            }
            cancel.store(canceled, Ordering::Release);
            state.live.insert(
                offer.attempt,
                Live {
                    cancel: Arc::clone(&cancel),
                    logs: Arc::clone(&logs),
                    canceling: false,
                    lost: false,
                    store: podman::Store::Shared,
                },
            );
        }
        let executor = Arc::clone(&self.0);
        // One guard: a second `self.state()` inside the literal would wait on the first, which lives to the end of
        // the statement.
        let (prepare_hold, network, runtime) = {
            let state = self.state();
            (state.prepare_hold, state.network, state.runtime.clone())
        };
        let cache_budget_bytes = self
            .budgets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cache_bytes;
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
            cache_budget_bytes,
            mirrors: self.mirrors.clone(),
            prepare_hold,
            network,
            runtime,
            secret_bundle,
        };
        let store = attempt::store_for(&self.root, &job).unwrap_or(podman::Store::Shared);
        if let Some(live) = self.state().live.get_mut(&offer.attempt) {
            live.store = store.clone();
        }
        // A crash after this point must leave a marker for recovery, so an unwritable marker means the attempt must not start.
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
                // A panic must not leave the attempt held and renewed: tear it down and report a runtime failure.
                let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    attempt::run(&executor.root, &mut job, &*executor, output, sink, &cancel)
                }));
                let verdict = match ran {
                    Ok((verdict, _)) => verdict,
                    Err(_) => {
                        cancel.store(true, Ordering::Release);
                        let _ = crate::sandbox::remove(&executor.root, attempt, &store);
                        let _ = crate::workspace::remove_tree(
                            &executor
                                .root
                                .join(crate::workspace::WORKSPACES_DIR)
                                .join(attempt.to_string()),
                        );
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
                executor.sweep_caches();
            });
        if spawned.is_err() {
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
    /// The measured cache costs the costly-hit rule reads; a cold-rebuild measurement is recorded here.
    pub fn costs(&self) -> &sentinel_cache::CostBook {
        &self.costs
    }

    pub fn runtime(&self) -> &podman::Runtime {
        &self.runtime
    }

    pub fn images(&self) -> &Images {
        &self.images
    }

    pub fn prefetcher(&self) -> &crate::prefetch::Prefetcher {
        &self.prefetch
    }

    pub fn recovered(&self) -> &Recovered {
        &self.recovered
    }

    pub fn spool_used(&self) -> u64 {
        self.spool.used()
    }

    pub fn attempts_live(&self) -> usize {
        let state = self.state();
        state.live.len() + state.awaiting.len()
    }

    pub fn leftovers_pending(&self) -> usize {
        self.state().leftovers.len()
    }

    pub fn state_is_idle(&self) -> bool {
        let state = self.state();
        state.live.is_empty() && state.awaiting.is_empty()
    }

    pub fn pending_reports(&self) -> usize {
        self.state().pending.len()
    }

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
                            recovery::mark_ended(&self.root, leftover.attempt);
                        }
                        ok
                    }
                    Err(_) => false,
                }
            } else {
                leftover.ended
            };
            if reporter.abandon(leftover.attempt, leftover.fence).is_err() {
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

    fn sweep_images(&self, budget: u64) {
        {
            let mut swept = self.image_swept.lock().unwrap_or_else(|p| p.into_inner());
            if swept.is_some_and(|at| at.elapsed() < IMAGE_SWEEP_EVERY) {
                return;
            }
            *swept = Some(std::time::Instant::now());
        }
        let mut removed = 0usize;
        // Cached microVM root file systems count against the same budget as Podman's images: Podman's go
        // first, against what the guest images leave; the guest images then give back whatever still does
        // not fit, least recently used first.
        let guests = crate::microvm::guest_images(&self.root);
        let guest_total: u64 = guests.iter().map(|g| g.bytes).sum();
        let podman_budget = budget.saturating_sub(guest_total);
        let mut podman_left = 0u64;
        for store in podman::Store::all(&self.root) {
            let Ok(images) = podman::list_images(&store) else {
                continue;
            };
            let mut left: u64 = images.iter().map(|i| i.bytes).sum();
            for id in self.images.reclaimable(&images, podman_budget) {
                if podman::remove_image(&store, &id) {
                    removed += 1;
                    left = left
                        .saturating_sub(images.iter().find(|i| i.id == id).map_or(0, |i| i.bytes));
                }
            }
            podman_left = podman_left.max(left);
        }
        let over = crate::images::guest_overage(guest_total, podman_left, budget);
        for key in self.images.reclaimable_guests(&guests, over) {
            removed += usize::from(crate::microvm::remove_guest_image(&self.root, &key));
        }
        crate::microvm::sweep_guest_orphans(&self.root);
        if removed > 0 {
            (self.notify)(Notice::ImagesReclaimed(removed));
        }
    }

    fn sweep_caches(&self) {
        let mut cursor = match self.gc_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let budgets = *self.budgets.lock().unwrap_or_else(|p| p.into_inner());
        let stats = sentinel_cache::gc::resume(
            &self.root.join(sentinel_cache::CACHE_DIR),
            budgets.cache_bytes,
            sentinel_cache::gc::DEFAULT_PASS_WORK,
            &mut cursor,
        );
        drop(cursor);
        if let Some(mirrors) = &self.mirrors {
            let _ = mirrors.sweep(budgets.mirror_bytes);
        }
        self.sweep_images(budgets.image_bytes);
        if self
            .cache_bytes
            .swap(stats.estimated_bytes, std::sync::atomic::Ordering::Relaxed)
            != stats.estimated_bytes
        {
            self.cache_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        (self.notify)(Notice::Availability(Availability {
            cache_costs: self.costs.figures(),
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

    fn watch_lease(&self) {
        let lost: Vec<(AttemptId, Cancel, podman::Store)> = {
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
                    (*id, Arc::clone(&live.cancel), live.store.clone())
                })
                .collect()
        };
        for (attempt, cancel, store) in &lost {
            cancel.store(true, Ordering::Release);
            let _ = crate::sandbox::remove(&self.root, *attempt, store);
        }
        (self.notify)(Notice::LeaseLost(
            lost.into_iter().map(|(a, _, _)| a).collect(),
        ));
    }

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
            return;
        }
        let sent = match (&state.reporter, &summary) {
            (Some(reporter), Some(summary)) => reporter
                .finish(attempt, fence, event, summary.clone())
                .is_ok(),
            (Some(reporter), None) => reporter.report(attempt, fence, event).is_ok(),
            (None, _) => false,
        };
        if matches!(event, Event::Passed | Event::Failed(_)) {
            let now = Instant::now();
            state.unconfirmed.insert(
                attempt,
                Unconfirmed {
                    fence,
                    event,
                    summary: summary.clone(),
                    first: now,
                    sent: now,
                },
            );
        }
        if !sent {
            state.pending.push((attempt, fence, event, summary));
        }
    }

    fn resend_unconfirmed(&self) {
        let (reporter, due) = {
            let mut state = self.state();
            let now = Instant::now();
            forget_unconfirmed(&mut state.unconfirmed, now);
            let Some(reporter) = state.reporter.clone() else {
                return;
            };
            (reporter, due_resends(&mut state.unconfirmed, now))
        };
        for (attempt, fence, event, summary) in due {
            let _ = match summary {
                Some(bytes) => reporter.finish(attempt, fence, event, bytes),
                None => reporter.report(attempt, fence, event),
            };
        }
    }

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
    fn cache_note(&self, attempt: AttemptId, note: CacheNote) {
        (self.notify)(Notice::CachePublished { attempt, note });
    }
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
    fn cache_records(
        &self,
        _attempt: AttemptId,
        records: &[sentinel_protocol::summary::CacheRecord],
    ) {
        (self.notify)(Notice::CacheFigures(CacheTotals::of(records)));
    }
    fn remote(&self) -> Option<std::sync::Arc<dyn sentinel_cache::remote::Remote>> {
        self.state()
            .reporter
            .as_ref()
            .and_then(Reporter::remote_cache)
    }
    fn cost_book(&self) -> Option<&sentinel_cache::CostBook> {
        Some(&self.costs)
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

    fn disk_room(&self) -> Option<u64> {
        if !self
            .measured_disk
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }
        crate::spool::free_bytes(&self.root).map(job_disk_room)
    }

    fn prefetch(&self, images: &[String]) {
        self.prefetch.hint(images);
    }

    fn offered(&self, offer: &Offer) -> bool {
        let state = self.state();
        if state.live.contains_key(&offer.attempt) || state.awaiting.contains_key(&offer.attempt) {
            return true;
        }
        if state.draining
            || state.live.len() + state.awaiting.len() >= MAX_LIST_ITEMS
            || state.reporter.is_none()
        {
            return false;
        }
        drop(state);
        let floor = self
            .admission_floor
            .load(std::sync::atomic::Ordering::Relaxed);
        let free = crate::spool::free_bytes(&self.root);
        if !admits(free, floor) {
            let mut noted = self.refusal_noted.lock().unwrap_or_else(|p| p.into_inner());
            if noted.is_none_or(|at| at.elapsed() >= REFUSAL_NOTICE_EVERY) {
                *noted = Some(Instant::now());
                drop(noted);
                (self.notify)(Notice::OfferRefused {
                    attempt: offer.attempt,
                    free_bytes: free.unwrap_or(0),
                    floor_bytes: floor,
                });
            }
            return false;
        }
        let mut state = self.state();
        if state.draining
            || state.live.len() + state.awaiting.len() >= MAX_LIST_ITEMS
            || state.reporter.is_none()
        {
            return false;
        }
        let now = Instant::now();
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
                canceled: false,
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
        let (live, confirmed_only) = {
            let mut state = self.state();
            let confirmed = state.unconfirmed.remove(&attempt).is_some();
            let waiting = state.awaiting.remove(&attempt).is_some();
            let live = state
                .live
                .get(&attempt)
                .map(|l| (Arc::clone(&l.cancel), l.store.clone()));
            let only = confirmed && !waiting && live.is_none();
            (live, only)
        };
        if confirmed_only {
            return;
        }
        if let Some((cancel, store)) = live {
            cancel.store(true, Ordering::Release);
            let spawned = thread::Builder::new()
                .name(format!("sentinel-stop-{attempt}"))
                .spawn({
                    let (store, root) = (store.clone(), self.root.clone());
                    move || {
                        let _ = crate::sandbox::remove(&root, attempt, &store);
                    }
                });
            if spawned.is_err() {
                let _ = crate::sandbox::remove(&self.root, attempt, &store);
            }
        }
        (self.notify)(Notice::Stopped(attempt));
    }

    fn cancel(&self, attempt: AttemptId) {
        let (cancel, grace, store) = {
            let mut state = self.state();
            let grace = state.cancel_grace;
            match state.live.get_mut(&attempt) {
                Some(live) if !live.canceling => {
                    live.canceling = true;
                    (Arc::clone(&live.cancel), grace, live.store.clone())
                }
                Some(_) => return,
                None => {
                    // Offered and accepted, or its spec arrived and it is starting: the cancel is kept, so the
                    // attempt starts canceled instead of running a job the controller already gave up on.
                    if let Some(waiting) = state.awaiting.get_mut(&attempt) {
                        waiting.canceled = true;
                    } else if let Some(canceled) = state.starting.get_mut(&attempt) {
                        *canceled = true;
                    }
                    return;
                }
            }
        };
        // Desired state is set first, so a step that ends by itself meanwhile is still reported as canceled.
        cancel.store(true, Ordering::Release);
        let executor = Arc::clone(&self.0);
        let spawned = thread::Builder::new()
            .name(format!("sentinel-cancel-{attempt}"))
            .spawn(move || {
                let outcome = crate::sandbox::terminate(&executor.root, attempt, &store, grace);
                match outcome {
                    Ok(podman::Terminated::Graceful | podman::Terminated::Forced) => {
                        let forced = matches!(outcome, Ok(podman::Terminated::Forced));
                        (executor.notify)(Notice::Canceled { attempt, forced });
                    }
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
            .chain(state.unconfirmed.keys())
            .copied()
            .collect()
    }

    fn renewed(&self, until: UnixMillis) {
        self.renewed_at(until, Instant::now());
    }

    /// Monotonic time only: wall-clock skew between the hosts must neither kill live work early nor let it outlive its expiry.
    fn renewed_at(&self, _until: UnixMillis, sent: Instant) {
        self.state().lease_deadline = Some(sent + LEASE.saturating_sub(LEASE_GUARD));
        self.resend_unconfirmed();
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
        let leftovers = std::mem::take(&mut self.state().leftovers);
        if !leftovers.is_empty() {
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
        for watch in watches {
            watch.resolve(Reply::Done(ArtifactCode::Store));
        }
    }

    fn artifact_granted(&self, attempt: AttemptId, _name: &str) {
        let watch = self.state().artifact_waits.get(&attempt).cloned();
        if let Some(watch) = watch {
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

    fn fence_of(&self, attempt: AttemptId) -> Option<Fence> {
        self.state()
            .awaiting
            .get(&attempt)
            .filter(|waiting| !waiting.declining)
            .map(|waiting| waiting.offer.fence)
    }

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

    fn record(outcome: &str) -> sentinel_protocol::summary::CacheRecord {
        sentinel_protocol::summary::CacheRecord {
            name: "deps".into(),
            class: 1,
            outcome: outcome.into(),
            lookup_ns: Some(1),
            lock_wait_ns: None,
            clone_ns: None,
            first_touch_ns: None,
            files: 0,
            bytes: 0,
            copied_bytes: 0,
            reflink: false,
            commit_ns: None,
            staged_bytes: None,
            reused_bytes: None,
            dirty_bytes: None,
            publish: None,
            costly_hit: false,
        }
    }

    #[test]
    fn cache_totals_sum_hits_misses_and_only_the_phases_that_ran() {
        let mut hit = record("hit");
        hit.lock_wait_ns = Some(5);
        hit.clone_ns = Some(7);
        hit.first_touch_ns = Some(11);
        hit.bytes = 1000;
        hit.copied_bytes = 400;
        hit.costly_hit = true;
        hit.commit_ns = Some(13);
        hit.staged_bytes = Some(300);
        hit.dirty_bytes = Some(120);
        let mut miss = record("absent");
        miss.bytes = 99;
        miss.copied_bytes = 99;
        miss.commit_ns = Some(17);
        let totals = CacheTotals::of(&[hit, miss, record("hit")]);
        assert_eq!(
            totals,
            CacheTotals {
                entries: 3,
                hits: 2,
                misses: 1,
                costly_hits: 1,
                lock_wait_ns: 5,
                clone_ns: 7,
                first_touch_ns: 11,
                commit_ns: 30,
                restored_bytes: 1000,
                copied_bytes: 400,
                staged_bytes: 300,
                dirty_bytes: 120,
            },
            "a miss restored nothing, so its bytes are not restored bytes"
        );
        assert_eq!(CacheTotals::of(&[]), CacheTotals::default());
    }

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

    #[test]
    fn a_shutdown_ends_the_running_attempt_without_reporting_it() {
        if !podman_enabled() {
            return;
        }
        let (live, executor) = Live::start(|dir, worker| {
            Executor::start(dir.to_path_buf(), worker, |_| {}, false).unwrap()
        });
        let yaml = format!(
            "schema: 1\non: [push]\njobs:\n  work:\n    image: {IMAGE}@{DIGEST}\n    resources: {{ cpu: 1, memory: 128MiB }}\n    steps:\n      - id: wait\n        run: 'echo started; sleep 300'\n"
        );
        let (run, jobs) = live.enqueue(&yaml);
        let job = jobs[0];
        eventually("the step started", Duration::from_secs(120), || {
            live.printed(run, job, "started")
        });
        assert!(!podman::owned(live.worker).unwrap().is_empty());
        executor.shutdown(Duration::from_secs(60));
        assert!(
            podman::owned(live.worker).unwrap().is_empty(),
            "the container survived the shutdown"
        );
        assert_eq!(executor.attempts_live(), 0);
        assert!(
            crate::workspace::Workspace::leftovers(&live.worker_dir)
                .unwrap()
                .is_empty()
        );
        assert!(
            !matches!(live.job(job).state, JobState::Terminal(_)),
            "a leaving worker reported a verdict"
        );
        live.stop();
    }

    fn unconfirmed(sent: Instant, summary: Option<Vec<u8>>) -> Unconfirmed {
        Unconfirmed {
            fence: Fence(3),
            event: Event::Passed,
            summary,
            first: sent,
            sent,
        }
    }

    #[test]
    fn an_unconfirmed_verdict_is_resent_on_its_interval_with_its_summary() {
        let (a, b) = (AttemptId::new(), AttemptId::new());
        let t0 = Instant::now();
        let mut map = HashMap::new();
        map.insert(a, unconfirmed(t0, Some(b"summary".to_vec())));
        map.insert(b, unconfirmed(t0 + Duration::from_secs(3), None));
        assert!(due_resends(&mut map, t0 + REPORT_RESEND - Duration::from_millis(1)).is_empty());
        let due = due_resends(&mut map, t0 + REPORT_RESEND);
        assert_eq!(due.len(), 1);
        let (attempt, fence, event, summary) = &due[0];
        assert_eq!(
            (*attempt, *fence, *event, summary.as_deref()),
            (a, Fence(3), Event::Passed, Some(&b"summary"[..]))
        );
        assert!(due_resends(&mut map, t0 + REPORT_RESEND + Duration::from_secs(1)).is_empty());
        let later = due_resends(&mut map, t0 + REPORT_RESEND * 2);
        let mut got: Vec<_> = later.iter().map(|d| d.0).collect();
        got.sort_by_key(|id| id.as_bytes().to_vec());
        let mut want = vec![a, b];
        want.sort_by_key(|id| id.as_bytes().to_vec());
        assert_eq!(got, want);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn an_unconfirmed_verdict_is_kept_until_its_keep_window_ends() {
        let a = AttemptId::new();
        let t0 = Instant::now();
        let mut map = HashMap::new();
        map.insert(a, unconfirmed(t0, None));
        forget_unconfirmed(&mut map, t0 + REPORT_KEEP - Duration::from_secs(1));
        assert!(map.contains_key(&a), "still held and renewing its lease");
        forget_unconfirmed(&mut map, t0 + REPORT_KEEP);
        assert!(map.is_empty());
    }
}
