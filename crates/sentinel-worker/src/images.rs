//! Image pulls through the worker's own content store.
//!
//! Concurrent attempts needing the same `name@sha256:…` reference share
//! one in-flight pull: the first caller leads it, the rest wait for its
//! outcome — bounded by their own deadline and stopped early by their
//! cancel flag — instead of running competing copies of the same
//! download. The pull itself is the podman one (`podman image exists`,
//! then `podman pull -q` when it does not), so a leader that finds the
//! store already holding the image resolves every follower in one cheap
//! lookup. A finished pull leaves no slot behind, so a failure retries
//! fresh on the next attempt, and a slot whose leader vanished before
//! publishing is dropped by the first follower whose deadline passes.
//!
//! Every confirmed pull records the digest in a bounded held set — what a
//! later part advertises for locality-aware placement. The set is
//! learned from pull outcomes alone, never scanned: a restarted worker
//! starts empty and relearns on the next pull, whose `image exists`
//! check is the same authority.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{Error, Result, attempt::Cancel, podman};

/// How many digests the held record keeps before the oldest learned is
/// evicted — far more distinct images than a worker cycles between
/// offers, and each entry is a 71-byte `sha256:…`.
pub const MAX_HELD: usize = 1024;

/// How often a follower's wait re-checks its cancel flag.
const FOLLOW_POLL: Duration = Duration::from_millis(50);

/// What does the pulling: `podman::pull` in production, a stub in tests.
type Download = Arc<dyn Fn(&str, Duration) -> Result<()> + Send + Sync>;

/// One in-flight pull: the outcome the leader publishes exactly once.
#[derive(Default)]
struct Pull {
    result: Mutex<Option<std::result::Result<(), Shared>>>,
    done: Condvar,
    /// Followers parked on this pull, so the count is observable.
    waiters: AtomicUsize,
}

/// A leader's error as a follower can own it: `io::Error` does not
/// clone, so its kind and message are carried instead.
#[derive(Clone, Debug)]
enum Shared {
    Preparation(String),
    Runtime(String),
    Timeout(&'static str),
    Workspace(String),
    Io(std::io::ErrorKind, String),
}

impl Shared {
    fn of(error: &Error) -> Shared {
        match error {
            Error::Preparation(what) => Shared::Preparation(what.clone()),
            Error::Runtime(what) => Shared::Runtime(what.clone()),
            Error::Timeout(what) => Shared::Timeout(what),
            Error::Workspace(what) => Shared::Workspace(what.clone()),
            Error::Io(e) => Shared::Io(e.kind(), e.to_string()),
        }
    }

    fn into_error(self) -> Error {
        match self {
            Shared::Preparation(what) => Error::Preparation(what),
            Shared::Runtime(what) => Error::Runtime(what),
            Shared::Timeout(what) => Error::Timeout(what),
            Shared::Workspace(what) => Error::Workspace(what),
            Shared::Io(kind, what) => Error::Io(std::io::Error::new(kind, what)),
        }
    }
}

struct State {
    /// References with a pull in flight. A slot leaves the map as its
    /// outcome is published, so it never outlives its use.
    pulling: HashMap<String, Arc<Pull>>,
    /// Digests (`sha256:…`) confirmed in the local store.
    held: HashSet<Box<str>>,
    /// The `held` digests oldest-first, for eviction past [`MAX_HELD`].
    order: VecDeque<Box<str>>,
}

struct Inner {
    state: Mutex<State>,
    download: Download,
}

/// The worker's image-pull state: one per process, cheap to clone —
/// the executor holds one and every attempt's [`crate::attempt::Job`]
/// carries a clone of it.
#[derive(Clone)]
pub struct Images {
    inner: Arc<Inner>,
}

impl Images {
    /// Pulls through podman, which enforces the digest pin itself.
    pub fn new() -> Self {
        Self::with_download(podman::pull)
    }

    /// A pull backend other than podman's — the test seam.
    #[doc(hidden)]
    pub fn with_download(
        download: impl Fn(&str, Duration) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Images {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    pulling: HashMap::new(),
                    held: HashSet::new(),
                    order: VecDeque::new(),
                }),
                download: Arc::new(download),
            }),
        }
    }

    /// Make `image` — the exact `name@sha256:…` reference handed to the
    /// pull — available in the local store, sharing the in-flight pull
    /// for it if there is one. The leader's outcome is what every waiter
    /// gets: on success the image is present, on failure the same typed
    /// error (`Preparation` for a refused or failed pull, `Timeout` past
    /// the deadline, `Io` for a helper that would not start).
    ///
    /// A follower's wait is bounded by `timeout` and ends early on
    /// `cancel`; the pull it watched may still complete for the others.
    /// The leader is not interruptible, exactly as a lone pull is not.
    pub fn pull(&self, image: &str, timeout: Duration, cancel: &Cancel) -> Result<()> {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        let (slot, leader) = {
            let mut state = self.state();
            match state.pulling.get(image) {
                Some(slot) => (Arc::clone(slot), false),
                None => {
                    let slot = Arc::new(Pull::default());
                    state.pulling.insert(image.to_owned(), Arc::clone(&slot));
                    (slot, true)
                }
            }
        };
        if leader {
            let outcome = (self.inner.download)(image, timeout);
            if outcome.is_ok() {
                self.record(image);
            }
            // Publish before the slot leaves the map: a caller between the
            // two still follows this pull rather than leading a second one.
            *slot.result.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(outcome.as_ref().map(|_| ()).map_err(Shared::of));
            slot.done.notify_all();
            self.state().pulling.remove(image);
            return outcome;
        }
        slot.waiters.fetch_add(1, Ordering::Relaxed);
        let deadline = Instant::now() + timeout;
        let mut result = slot.result.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(outcome) = result.clone() {
                // The lock is dropped before `record` so the slot mutex is
                // never held across the state one.
                drop(result);
                if outcome.is_ok() {
                    self.record(image);
                }
                return outcome.map_err(Shared::into_error);
            }
            if cancel.load(Ordering::Acquire) {
                return Err(Error::Preparation("canceled".into()));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // A leader this late cannot still be pulling — its own
                // deadline passed — so the slot is stale (a panic skips
                // the publish). Drop it so the next attempt pulls fresh.
                let mut state = self.state();
                if state
                    .pulling
                    .get(image)
                    .is_some_and(|s| Arc::ptr_eq(s, &slot))
                {
                    state.pulling.remove(image);
                }
                return Err(Error::Timeout("image pull"));
            }
            let (guard, _) = slot
                .done
                .wait_timeout(result, remaining.min(FOLLOW_POLL))
                .unwrap_or_else(|p| p.into_inner());
            result = guard;
        }
    }

    /// Whether `digest` — the `sha256:…` half of a pulled reference — is
    /// in the held record. Advisory for placement: `pull` still verifies
    /// against the store on every call.
    pub fn holds(&self, digest: &str) -> bool {
        self.state().held.contains(digest)
    }

    /// What this worker's store is known to hold, sorted for a stable
    /// wire form. Bounded by [`MAX_HELD`]; learned lazily from pull
    /// outcomes, so a restarted worker's is empty until the first pull.
    pub fn held(&self) -> Vec<String> {
        let mut held: Vec<String> = self
            .state()
            .held
            .iter()
            .map(|digest| digest.to_string())
            .collect();
        held.sort_unstable();
        held
    }

    /// Pulls in flight right now; never more than the attempt bound.
    pub fn in_flight(&self) -> usize {
        self.state().pulling.len()
    }

    /// The pull landed: the digest half of `name@sha256:…` joins the held
    /// record, evicting the oldest learned past [`MAX_HELD`].
    fn record(&self, image: &str) {
        let Some((_, digest)) = image.split_once('@') else {
            return;
        };
        let mut state = self.state();
        if state.held.contains(digest) {
            return;
        }
        if state.held.len() >= MAX_HELD
            && let Some(oldest) = state.order.pop_front()
        {
            state.held.remove(&oldest);
        }
        let digest: Box<str> = digest.into();
        state.order.push_back(digest.clone());
        state.held.insert(digest);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Default for Images {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Barrier, atomic::AtomicBool, mpsc},
        thread,
    };

    use super::*;

    const IMAGE: &str = "example.test/image@sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    fn cancel() -> Cancel {
        Arc::new(AtomicBool::new(false))
    }

    /// How many followers are parked on `image`'s pull right now.
    fn waiters(images: &Images, image: &str) -> usize {
        images
            .state()
            .pulling
            .get(image)
            .map(|slot| slot.waiters.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn parked(images: &Images, image: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while waiters(images, image) < n {
            assert!(Instant::now() < deadline, "followers never parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A download that counts its calls, reports each entry on `entered`
    /// and finishes with `outcome` when `release` is tripped.
    struct Stub {
        calls: Arc<AtomicUsize>,
        entered: mpsc::Sender<()>,
        release: Arc<Barrier>,
        /// `Err("…")` maps to `Error::Timeout` — one typed error is enough
        /// to prove the leader's outcome is what followers get.
        outcome: std::result::Result<(), &'static str>,
    }

    impl Stub {
        fn new(outcome: std::result::Result<(), &'static str>) -> (Stub, mpsc::Receiver<()>) {
            let (entered, rx) = mpsc::channel();
            (
                Stub {
                    calls: Arc::new(AtomicUsize::new(0)),
                    entered,
                    release: Arc::new(Barrier::new(2)),
                    outcome,
                },
                rx,
            )
        }

        fn images(&self) -> Images {
            let (calls, entered, release, outcome) = (
                Arc::clone(&self.calls),
                self.entered.clone(),
                Arc::clone(&self.release),
                self.outcome,
            );
            Images::with_download(move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                let _ = entered.send(());
                release.wait();
                outcome.map_err(Error::Timeout)
            })
        }
    }

    #[test]
    fn concurrent_pulls_share_one_download() {
        let (stub, entered) = Stub::new(Ok(()));
        let images = stub.images();
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let (images, cancel) = (images.clone(), cancel());
                thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
            })
            .collect();
        // The leader is inside the download; every follower is parked on
        // the slot before it is allowed to finish.
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        parked(&images, IMAGE, 4);
        stub.release.wait();
        for caller in callers {
            caller.join().unwrap().unwrap();
        }
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            1,
            "one download for five"
        );
        assert_eq!(images.in_flight(), 0, "no slot left behind");
        assert!(images.holds(DIGEST));
        assert_eq!(images.held(), vec![DIGEST.to_string()]);
    }

    #[test]
    fn followers_get_the_leaders_error_and_the_next_attempt_retries() {
        let (stub, entered) = Stub::new(Err("podman pull"));
        let images = stub.images();
        let callers: Vec<_> = (0..3)
            .map(|_| {
                let (images, cancel) = (images.clone(), cancel());
                thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
            })
            .collect();
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        parked(&images, IMAGE, 2);
        stub.release.wait();
        for caller in callers {
            match caller.join().unwrap() {
                Err(Error::Timeout("podman pull")) => {}
                other => panic!("follower got {other:?}"),
            }
        }
        assert_eq!(images.in_flight(), 0);
        assert!(!images.holds(DIGEST), "a failed pull records nothing");
        // The slot is gone: the next pull leads a fresh download rather
        // than replaying the failure.
        let retry = {
            let (images, cancel) = (images.clone(), cancel());
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
        };
        entered
            .recv_timeout(Duration::from_secs(10))
            .expect("a fresh download ran");
        stub.release.wait();
        match retry.join().unwrap() {
            Err(Error::Timeout("podman pull")) => {}
            other => panic!("retry got {other:?}"),
        }
        assert_eq!(stub.calls.load(Ordering::SeqCst), 2, "a fresh download ran");
    }

    #[test]
    fn a_canceled_follower_stops_waiting_without_ending_the_pull() {
        let (stub, entered) = Stub::new(Ok(()));
        let images = stub.images();
        let leader = {
            let (images, cancel) = (images.clone(), cancel());
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
        };
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        let flag = cancel();
        let follower = {
            let (images, flag) = (images.clone(), Arc::clone(&flag));
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &flag))
        };
        parked(&images, IMAGE, 1);
        flag.store(true, Ordering::Release);
        // The canceled follower leaves promptly — well before the pull it
        // was watching ends.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(follower.join().unwrap()).unwrap());
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Err(Error::Preparation(what)) => assert_eq!(what, "canceled"),
            other => panic!("canceled follower got {other:?}"),
        }
        assert_eq!(images.in_flight(), 1, "the leader's pull goes on");
        stub.release.wait();
        leader.join().unwrap().unwrap();
        assert_eq!(images.in_flight(), 0);
        assert!(images.holds(DIGEST), "the completed pull still records");
    }

    #[test]
    fn a_pull_after_the_leader_finishes_pulls_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let images = Images::with_download({
            let calls = Arc::clone(&calls);
            move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        images
            .pull(IMAGE, Duration::from_secs(30), &cancel())
            .unwrap();
        images
            .pull(IMAGE, Duration::from_secs(30), &cancel())
            .unwrap();
        // Back-to-back pulls each run their own check: sharing covers the
        // in-flight window, not forever — `podman image exists` is the
        // cheap authority for an image already held.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(images.in_flight(), 0);
        assert_eq!(images.held(), vec![DIGEST.to_string()]);
        assert!(!images.holds("sha256:never-pulled"));
    }

    #[test]
    fn the_held_record_is_bounded_and_evicts_the_oldest() {
        let images = Images::with_download(|_, _| Ok(()));
        let flag = cancel();
        for i in 0..MAX_HELD + 1 {
            let image = format!("example.test/i@sha256:{i:064}");
            images.pull(&image, Duration::from_secs(30), &flag).unwrap();
        }
        let held = images.held();
        assert_eq!(held.len(), MAX_HELD);
        assert!(!images.holds(&format!("sha256:{:064}", 0)));
        assert!(images.holds(&format!("sha256:{:064}", MAX_HELD)));
    }

    #[test]
    fn the_wrapped_pull_still_refuses_an_unpinned_reference() {
        // With the real backend this stops before any helper runs; the
        // stubbed one would not be asked either way.
        let images = Images::new();
        match images.pull(
            "example.test/image:latest",
            Duration::from_secs(1),
            &cancel(),
        ) {
            Err(Error::Preparation(what)) => assert_eq!(what, "image is not pinned by digest"),
            other => panic!("unpinned reference got {other:?}"),
        }
        assert_eq!(images.in_flight(), 0);
        assert!(images.held().is_empty());
    }
}
