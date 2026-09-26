//! K05 bounded image prefetch: pull, in the background, the images the
//! controller says queued work this worker could be placed will need.
//!
//! The controller's hint (`Prefetch`, protocol 9) is the whole wanted set;
//! each one replaces the last. A reference that left the set is stale: a
//! prefetch of it that has not started is dropped, and one under way is
//! killed — unless an attempt already joined its pull, which makes it no
//! longer a guess. Everything a prefetch does is bounded:
//!
//! - **Concurrency.** At most [`Bounds::concurrency`] prefetch pulls at a
//!   time (default one), and none starts while an attempt leads a pull of
//!   its own: an attempt's image is the critical path, a prefetch is not.
//! - **Bandwidth.** A byte budget per window ([`Bounds::window_bytes`] per
//!   [`Bounds::window`], default 4 GiB per 10 minutes), charged with each
//!   pulled image's size; past it, prefetch waits for the next window.
//!   `podman pull` has no rate limit, so this bounds the average, and the
//!   concurrency bound bounds the burst.
//! - **Disk.** A pull starts only while the image store's filesystem keeps
//!   [`Bounds::disk_reserve`] free (default a tenth of it, at least 2 GiB),
//!   and never when its free space cannot be measured.
//! - **Time.** Each pull is bounded by [`Bounds::pull_timeout`].
//!
//! A prefetch goes through the same [`Images`] coordinator an attempt's
//! pull does: it shares the single-flight slot (an attempt needing the
//! image follows it and shares the download), records the digest in the
//! held set when it lands — which the link reports as warm, so placement's
//! locality prefers this worker — and pulls with the worker's own registry
//! authority, exactly what a job the worker could be placed would pull.
//! The hint names only such jobs (tenant pool access, architecture, labels,
//! capacity — `dispatch::prefetch_hints`); tenant-scoped registry
//! credentials are S05.

use std::{
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_protocol::negotiate::MAX_PREFETCH_IMAGES;

use crate::{attempt::Cancel, images::Images, podman};

/// How long a prefetch that is ready but waiting on an attempt's pull
/// sleeps before looking again.
const YIELD_POLL: Duration = Duration::from_millis(200);

/// The bounds one worker's prefetching keeps.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Prefetch pulls in flight at once.
    pub concurrency: usize,
    /// The bandwidth window and the bytes prefetch may pull within it.
    pub window: Duration,
    pub window_bytes: u64,
    /// Free bytes the image store's filesystem keeps, as a function of its
    /// total size: see [`Bounds::reserve`].
    pub disk_reserve_min: u64,
    /// The reserve is at least this fraction of the filesystem (1/n).
    pub disk_reserve_divisor: u64,
    /// One pull's deadline.
    pub pull_timeout: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            concurrency: 1,
            window: Duration::from_secs(10 * 60),
            window_bytes: 4 << 30,
            disk_reserve_min: 2 << 30,
            disk_reserve_divisor: 10,
            pull_timeout: podman::IMAGE_PULL_TIMEOUT,
        }
    }
}

impl Bounds {
    /// Free bytes a filesystem of `total` bytes must keep.
    pub fn reserve(&self, total: u64) -> u64 {
        (total / self.disk_reserve_divisor.max(1)).max(self.disk_reserve_min)
    }
}

/// What prefetching needs from the runtime, as a seam: the podman one in
/// production, a stub in tests.
pub trait Probe: Send + Sync {
    /// `(free, total)` bytes of the filesystem holding the image store;
    /// `None` when it cannot be measured.
    fn space(&self) -> Option<(u64, u64)>;
    /// Bytes `image` takes in the store once pulled; `None` when unknown.
    fn image_bytes(&self, image: &str) -> Option<u64>;
}

/// The podman probe: the store's graph root (asked once) and `statvfs`.
pub struct PodmanProbe {
    root: std::sync::OnceLock<Option<std::path::PathBuf>>,
}

impl PodmanProbe {
    pub fn new() -> Self {
        PodmanProbe {
            root: std::sync::OnceLock::new(),
        }
    }
}

impl Default for PodmanProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe for PodmanProbe {
    fn space(&self) -> Option<(u64, u64)> {
        let root = self.root.get_or_init(|| podman::graph_root().ok());
        statvfs(root.as_deref()?)
    }

    fn image_bytes(&self, image: &str) -> Option<u64> {
        podman::image_bytes(image)
    }
}

/// `(available, total)` bytes of the filesystem holding `path`.
fn statvfs(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statvfs` is a valid value of the plain C struct,
    // and it is only read after the call below filled it.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `cpath` is a valid NUL-terminated path and `stat` is a
    // writable, properly aligned statvfs.
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let unit = stat.f_frsize as u64;
    Some((
        (stat.f_bavail as u64).saturating_mul(unit),
        (stat.f_blocks as u64).saturating_mul(unit),
    ))
}

/// Counters for diagnostics and tests. Monotonic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Hints received.
    pub hints: u64,
    /// References a hint named that were refused as not `name@sha256:…`.
    pub refused: u64,
    /// Prefetch pulls started, and how they ended.
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
    /// Pulls killed because their reference went stale.
    pub canceled: u64,
    /// References dropped because the disk reserve would not hold (or the
    /// store's space could not be measured).
    pub skipped_disk: u64,
    /// Times a ready prefetch waited for the byte window to roll over.
    pub waited_budget: u64,
    /// The most prefetch pulls ever in flight at once.
    pub peak: usize,
    /// Bytes charged to the current window.
    pub window_used: u64,
}

struct Running {
    image: String,
    cancel: Cancel,
}

struct State {
    /// The latest hint, canonical references in the controller's order,
    /// minus what was prefetched, failed or skipped since.
    wanted: Vec<String>,
    running: Vec<Running>,
    threads: usize,
    window_start: Instant,
    stats: Stats,
    stopped: bool,
}

struct Inner {
    images: Images,
    bounds: Bounds,
    probe: Box<dyn Probe>,
    state: Mutex<State>,
    wake: Condvar,
}

/// The worker's prefetcher: one per process, cheap to clone. Threads are
/// started on the first hint, up to the concurrency bound, and park when
/// there is nothing to do.
#[derive(Clone)]
pub struct Prefetcher {
    inner: Arc<Inner>,
}

impl Prefetcher {
    pub fn new(images: Images, bounds: Bounds, probe: impl Probe + 'static) -> Prefetcher {
        Prefetcher {
            inner: Arc::new(Inner {
                images,
                bounds,
                probe: Box::new(probe),
                state: Mutex::new(State {
                    wanted: Vec::new(),
                    running: Vec::new(),
                    threads: 0,
                    window_start: Instant::now(),
                    stats: Stats::default(),
                    stopped: false,
                }),
                wake: Condvar::new(),
            }),
        }
    }

    /// Replace the wanted set with `images`, the controller's latest hint.
    /// Each reference must be `name@sha256:<64 hex>` with a name in the
    /// reference charset; anything else is refused (counted, never pulled).
    /// A running prefetch of a reference the new set drops is killed
    /// unless an attempt follows it.
    pub fn hint(&self, images: &[String]) {
        let mut wanted: Vec<String> = Vec::with_capacity(images.len().min(MAX_PREFETCH_IMAGES));
        let mut refused = 0;
        for image in images.iter().take(MAX_PREFETCH_IMAGES) {
            match canonical(image) {
                Some(image) if !wanted.contains(&image) => wanted.push(image),
                Some(_) => {}
                None => refused += 1,
            }
        }
        let mut state = self.state();
        state.stats.hints += 1;
        state.stats.refused += refused;
        for running in &state.running {
            if !wanted.contains(&running.image) && self.inner.images.followers(&running.image) == 0
            {
                running.cancel.store(true, Ordering::Release);
            }
        }
        state.wanted = wanted;
        let spawn = (self.inner.bounds.concurrency.max(1)).saturating_sub(state.threads);
        let spawn = if state.wanted.is_empty() || state.stopped {
            0
        } else {
            spawn
        };
        state.threads += spawn;
        drop(state);
        for _ in 0..spawn {
            let me = self.clone();
            let started = thread::Builder::new()
                .name("sentinel-prefetch".into())
                .spawn(move || me.work());
            if started.is_err() {
                self.state().threads -= 1;
            }
        }
        self.inner.wake.notify_all();
    }

    /// Counters so far.
    pub fn stats(&self) -> Stats {
        self.state().stats
    }

    /// Prefetch pulls in flight right now.
    pub fn running(&self) -> usize {
        self.state().running.len()
    }

    /// Stop: running pulls are killed and the threads exit.
    pub fn stop(&self) {
        let mut state = self.state();
        state.stopped = true;
        state.wanted.clear();
        for running in &state.running {
            running.cancel.store(true, Ordering::Release);
        }
        drop(state);
        self.inner.wake.notify_all();
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One prefetch thread: take the next wanted reference the bounds
    /// admit, pull it, account it, repeat; park when nothing is wanted.
    fn work(&self) {
        loop {
            let Some((image, cancel)) = self.next() else {
                return;
            };
            let pulled =
                self.inner
                    .images
                    .prefetch(&image, self.inner.bounds.pull_timeout, &cancel);
            // Charged by what landed: a download's size, never a store hit.
            let bytes = match &pulled {
                Some(Ok(false)) => self.inner.probe.image_bytes(&image).unwrap_or(0),
                _ => 0,
            };
            let mut state = self.state();
            state.running.retain(|r| r.image != image);
            match pulled {
                Some(Ok(_)) => state.stats.completed += 1,
                Some(Err(_)) if cancel.load(Ordering::Acquire) => state.stats.canceled += 1,
                Some(Err(_)) => state.stats.failed += 1,
                None => {}
            }
            state.stats.window_used = state.stats.window_used.saturating_add(bytes);
            // Done, failed or stale: it leaves the wanted set, and only a
            // new hint naming it again retries — no hot retry loop.
            state.wanted.retain(|w| *w != image);
            drop(state);
            self.inner.wake.notify_all();
        }
    }

    /// Block until a reference may be pulled under every bound; `None`
    /// when the prefetcher stopped.
    fn next(&self) -> Option<(String, Cancel)> {
        let bounds = self.inner.bounds;
        let mut state = self.state();
        loop {
            if state.stopped {
                state.threads -= 1;
                return None;
            }
            let images = &self.inner.images;
            // What the store already holds needs no pull.
            state.wanted.retain(|image| {
                image
                    .split_once('@')
                    .is_none_or(|(_, digest)| !images.holds(digest))
            });
            let candidate = state
                .wanted
                .iter()
                .find(|image| !state.running.iter().any(|r| r.image == **image))
                .cloned();
            let Some(image) = candidate else {
                state = self
                    .inner
                    .wake
                    .wait(state)
                    .unwrap_or_else(|p| p.into_inner());
                continue;
            };
            if state.running.len() >= bounds.concurrency.max(1) {
                state = self
                    .inner
                    .wake
                    .wait(state)
                    .unwrap_or_else(|p| p.into_inner());
                continue;
            }
            // Attempts first: an attempt's own pull is the critical path.
            if images.attempt_pulls() > 0 {
                state = self
                    .inner
                    .wake
                    .wait_timeout(state, YIELD_POLL)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
                continue;
            }
            // The byte window: roll it over, or wait for it.
            let elapsed = state.window_start.elapsed();
            if elapsed >= bounds.window {
                state.window_start = Instant::now();
                state.stats.window_used = 0;
            } else if state.stats.window_used >= bounds.window_bytes {
                state.stats.waited_budget += 1;
                let left = bounds.window - elapsed;
                state = self
                    .inner
                    .wake
                    .wait_timeout(state, left)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
                continue;
            }
            // The disk reserve, measured now; unmeasurable is a refusal.
            let room = self
                .inner
                .probe
                .space()
                .is_some_and(|(free, total)| free > bounds.reserve(total));
            if !room {
                state.stats.skipped_disk += 1;
                state.wanted.retain(|w| *w != image);
                continue;
            }
            let cancel: Cancel = Arc::new(AtomicBool::new(false));
            state.running.push(Running {
                image: image.clone(),
                cancel: Arc::clone(&cancel),
            });
            state.stats.started += 1;
            state.stats.peak = state.stats.peak.max(state.running.len());
            return Some((image, cancel));
        }
    }
}

/// `name@sha256:<64 hex>` rebuilt from its parts — a tag or anything else
/// the controller could have sent is never passed to the pull — or `None`
/// when `image` is not a digest-pinned reference with a name in the OCI
/// reference charset.
pub fn canonical(image: &str) -> Option<String> {
    let parsed = sentinel_pipeline::run::ImageRef::parse(image).ok()?;
    let digest = parsed.digest?;
    let name = parsed.name;
    let charset = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'));
    if parsed.tag.is_some()
        || !charset
        || !(1..=255).contains(&name.len())
        || name.starts_with(['/', '-', ':', '.'])
    {
        return None;
    }
    Some(format!("{name}@{digest}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize},
        mpsc,
    };

    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn reference(n: u8) -> String {
        format!("registry.example/img{n}@sha256:{n:02x}{}", &HEX[2..])
    }

    /// Space and sizes the test decides.
    struct Fixed {
        free: AtomicU64,
        total: u64,
        size: u64,
    }

    impl Probe for Arc<Fixed> {
        fn space(&self) -> Option<(u64, u64)> {
            Some((self.free.load(Ordering::Relaxed), self.total))
        }
        fn image_bytes(&self, _: &str) -> Option<u64> {
            Some(self.size)
        }
    }

    fn roomy(size: u64) -> Arc<Fixed> {
        Arc::new(Fixed {
            free: AtomicU64::new(900 << 30),
            total: 1000 << 30,
            size,
        })
    }

    /// A download that parks until released (or canceled), counting how
    /// many run at once.
    struct Gate {
        running: AtomicUsize,
        peak: AtomicUsize,
        release: Mutex<bool>,
        released: Condvar,
        started: Mutex<mpsc::Sender<String>>,
    }

    fn gated() -> (Arc<Gate>, mpsc::Receiver<String>, Images) {
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(Gate {
            running: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            release: Mutex::new(false),
            released: Condvar::new(),
            started: Mutex::new(tx),
        });
        let seen = Arc::clone(&gate);
        let images = Images::with_download(move |image, _, _, cancel| {
            let now = seen.running.fetch_add(1, Ordering::SeqCst) + 1;
            seen.peak.fetch_max(now, Ordering::SeqCst);
            let _ = seen.started.lock().unwrap().send(image.to_owned());
            let mut open = seen.release.lock().unwrap();
            let outcome = loop {
                if cancel.load(Ordering::Acquire) {
                    break Err(crate::Error::Preparation("killed".into()));
                }
                if *open {
                    break Ok(false);
                }
                open = seen
                    .released
                    .wait_timeout(open, Duration::from_millis(10))
                    .unwrap()
                    .0;
            };
            seen.running.fetch_sub(1, Ordering::SeqCst);
            outcome
        });
        (gate, rx, images)
    }

    fn release(gate: &Gate) {
        *gate.release.lock().unwrap() = true;
        gate.released.notify_all();
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn only_digest_pinned_references_in_the_charset_are_pulled() {
        let pinned = reference(1);
        assert_eq!(canonical(&pinned), Some(pinned.clone()));
        let tagged = format!("registry.example/img:1@sha256:{HEX}");
        for bad in [
            "registry.example/img:1".to_owned(),
            tagged,
            format!("-rm@sha256:{HEX}"),
            format!("reg istry/img@sha256:{HEX}"),
            format!("img@sha256:{}", &HEX[..60]),
        ] {
            assert_eq!(canonical(&bad), None, "{bad}");
        }
    }

    /// Bounded concurrency: five wanted images, a bound of two — never more
    /// than two pulls at once, and all five land.
    #[test]
    fn prefetch_never_runs_more_pulls_than_its_bound() {
        let (gate, started, images) = gated();
        let bounds = Bounds {
            concurrency: 2,
            ..Bounds::default()
        };
        let prefetcher = Prefetcher::new(images.clone(), bounds, roomy(1));
        let wanted: Vec<String> = (1..=5).map(reference).collect();
        prefetcher.hint(&wanted);
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        // A third must not start while two are parked.
        assert!(started.recv_timeout(Duration::from_millis(300)).is_err());
        assert_eq!(prefetcher.running(), 2);
        release(&gate);
        eventually("every image held", || {
            wanted
                .iter()
                .all(|w| images.holds(w.split_once('@').unwrap().1))
        });
        assert_eq!(gate.peak.load(Ordering::SeqCst), 2);
        let stats = prefetcher.stats();
        assert_eq!((stats.started, stats.completed, stats.peak), (5, 5, 2));
        prefetcher.stop();
    }

    /// Cancellation: a hint that drops a running prefetch kills it; one an
    /// attempt joined in the meantime is kept, and the attempt gets it.
    #[test]
    fn a_stale_prefetch_is_killed_unless_an_attempt_joined_it() {
        let (gate, started, images) = gated();
        let prefetcher = Prefetcher::new(images.clone(), Bounds::default(), roomy(1));
        let (stale, kept) = (reference(1), reference(2));
        prefetcher.hint(std::slice::from_ref(&stale));
        assert_eq!(
            started.recv_timeout(Duration::from_secs(10)).unwrap(),
            stale
        );
        prefetcher.hint(&[]);
        eventually("the stale pull killed", || prefetcher.stats().canceled == 1);
        assert!(!images.holds(stale.split_once('@').unwrap().1));
        assert_eq!(prefetcher.running(), 0);

        prefetcher.hint(std::slice::from_ref(&kept));
        assert_eq!(started.recv_timeout(Duration::from_secs(10)).unwrap(), kept);
        // An attempt needs the same image and follows the prefetch.
        let follower = {
            let (images, kept) = (images.clone(), kept.clone());
            thread::spawn(move || {
                images.pull(
                    &kept,
                    Duration::from_secs(30),
                    &Arc::new(AtomicBool::new(false)),
                )
            })
        };
        eventually("the attempt parked", || images.followers(&kept) == 1);
        prefetcher.hint(&[]);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            prefetcher.stats().canceled,
            1,
            "a followed pull is not stale"
        );
        release(&gate);
        assert!(
            !follower.join().unwrap().unwrap(),
            "the attempt shared the prefetch's download"
        );
        assert_eq!(gate.peak.load(Ordering::SeqCst), 1);
        prefetcher.stop();
    }

    /// Attempts first: no prefetch starts while an attempt leads a pull.
    #[test]
    fn prefetch_waits_for_an_attempt_pull_to_finish() {
        let (gate, started, images) = gated();
        let prefetcher = Prefetcher::new(images.clone(), Bounds::default(), roomy(1));
        let attempt = reference(9);
        let leader = {
            let (images, attempt) = (images.clone(), attempt.clone());
            thread::spawn(move || {
                images.pull(
                    &attempt,
                    Duration::from_secs(30),
                    &Arc::new(AtomicBool::new(false)),
                )
            })
        };
        assert_eq!(
            started.recv_timeout(Duration::from_secs(10)).unwrap(),
            attempt
        );
        prefetcher.hint(&[reference(1)]);
        assert!(
            started.recv_timeout(Duration::from_millis(500)).is_err(),
            "a prefetch started beside the attempt's pull"
        );
        release(&gate);
        leader.join().unwrap().unwrap();
        assert_eq!(
            started.recv_timeout(Duration::from_secs(10)).unwrap(),
            reference(1)
        );
        prefetcher.stop();
    }

    /// The disk reserve and the byte window: no pull starts below the
    /// reserve, and a spent window defers the next pull.
    #[test]
    fn the_disk_reserve_and_the_byte_window_hold() {
        let (gate, started, images) = gated();
        release(&gate);
        let probe = roomy(3 << 30);
        probe.free.store(50 << 30, Ordering::Relaxed); // under 10 % of 1000 GiB
        let bounds = Bounds {
            window: Duration::from_secs(3600),
            window_bytes: 4 << 30,
            ..Bounds::default()
        };
        let prefetcher = Prefetcher::new(images.clone(), bounds, Arc::clone(&probe));
        prefetcher.hint(&[reference(1)]);
        eventually("the skip", || prefetcher.stats().skipped_disk == 1);
        assert!(started.try_recv().is_err(), "nothing pulled without room");

        probe.free.store(900 << 30, Ordering::Relaxed);
        prefetcher.hint(&[reference(1), reference(2), reference(3)]);
        // 3 GiB each against a 4 GiB window: two land, the third waits.
        eventually("two pulls", || prefetcher.stats().completed == 2);
        eventually("the budget wait", || prefetcher.stats().waited_budget >= 1);
        thread::sleep(Duration::from_millis(200));
        let stats = prefetcher.stats();
        assert_eq!((stats.started, stats.completed), (2, 2));
        assert_eq!(stats.window_used, 6 << 30);
        prefetcher.stop();
    }
}
