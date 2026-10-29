//! Measured per-job storage enforcement for rootless containers.
//!
//! Rootless Podman has no quota on a bind mount: project quotas and size-bound mounts need privileges the
//! worker does not have (docs/executor.md#disk). A job's workspace is therefore bounded by measurement. A
//! [`Guard`] walks the workspace while the steps run, charges the blocks every file and directory occupies
//! (hard links once, symbolic links never followed, nothing across a mount boundary), and the moment the total
//! passes the job's declared `resources.disk` it stops the container. The overshoot is what a job writes
//! between two samples: the interval follows the cost of a walk (an eighth of a core at most, 0.5 to 5 s), so a
//! fast writer can pass the limit by its rate times that interval before the stop lands. It is a bounded
//! overshoot, not a kernel byte quota; microVMs have a size-bound scratch disk instead and need no guard.

use std::{
    collections::HashSet,
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The first sample comes this soon after the steps start, so a short job that writes fast is still seen.
pub const FIRST_SAMPLE: Duration = Duration::from_millis(200);
pub const MIN_INTERVAL: Duration = Duration::from_millis(500);
pub const MAX_INTERVAL: Duration = Duration::from_secs(5);
/// A walk that takes longer than this stops where it is and is reported incomplete.
pub const WALK_BUDGET: Duration = Duration::from_secs(3);
/// Directory levels followed (the walk holds one descriptor per level). No real checkout nests this deep, so a
/// tree that does is refused as over the limit instead of being measured short: a job must not be able to hide
/// bytes below the level the walk can reach.
pub(crate) const MAX_DEPTH: usize = 128;
/// Hard-linked files remembered so each is charged once; beyond this each further link is charged again.
const MAX_LINKS_TRACKED: usize = 1 << 20;
const CHECK_TIME_EVERY: u64 = 512;

/// What one walk found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Bytes the files and directories occupy on disk (allocated blocks, not apparent sizes).
    pub bytes: u64,
    /// Entries visited.
    pub entries: u64,
    /// False when the walk stopped early (time budget, abort, depth) or met a directory it could not read;
    /// `bytes` is then a lower bound.
    pub complete: bool,
    /// The walk ran out of its time budget or was aborted: it did not see the whole tree.
    pub timed_out: bool,
    /// A directory lay deeper than the walk follows. The tree is refused rather than measured short; `bytes`
    /// stays the honest lower bound.
    pub too_deep: bool,
    /// A directory could not be entered, so what is inside it is not counted.
    pub unreadable: bool,
}

struct Walk<'a> {
    abort: &'a AtomicBool,
    limit: u64,
    deadline: Instant,
    root_dev: u64,
    bytes: u64,
    entries: u64,
    complete: bool,
    timed_out: bool,
    too_deep: bool,
    unreadable: bool,
    links: HashSet<(u64, u64)>,
}

impl Walk<'_> {
    fn over(&self) -> bool {
        self.bytes > self.limit || self.too_deep
    }

    fn out_of_time(&mut self) -> bool {
        if self.entries.is_multiple_of(CHECK_TIME_EVERY)
            && (Instant::now() >= self.deadline || self.abort.load(Ordering::Relaxed))
        {
            self.complete = false;
            self.timed_out = true;
            return true;
        }
        false
    }
}

fn fstatat(dir: &OwnedFd, name: &std::ffi::CStr) -> Option<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `dir` is an open descriptor, `name` is NUL-terminated and `stat` is a writable `stat`; the
    // call never follows a final symbolic link.
    let status = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    // SAFETY: `fstatat` returned 0, so it filled the structure.
    (status == 0).then(|| unsafe { stat.assume_init() })
}

fn open_dir(parent: libc::c_int, name: &std::ffi::CStr) -> Option<OwnedFd> {
    // SAFETY: `name` is NUL-terminated and `parent` is a live descriptor or `AT_FDCWD`; the flags only open an
    // existing directory and never follow a final symbolic link.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    // SAFETY: a non-negative `openat` result is a descriptor this call owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn charge(walk: &mut Walk, stat: &libc::stat) {
    let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
    if !is_dir && stat.st_nlink > 1 && walk.links.len() < MAX_LINKS_TRACKED {
        let key = (stat.st_dev, stat.st_ino);
        if !walk.links.insert(key) {
            return;
        }
    }
    walk.bytes = walk
        .bytes
        .saturating_add((stat.st_blocks as u64).saturating_mul(512));
}

fn descend(dir: &OwnedFd, depth: usize, walk: &mut Walk) {
    let Ok(entries) = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())) else {
        walk.complete = false;
        walk.unreadable = true;
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            walk.complete = false;
            walk.unreadable = true;
            continue;
        };
        walk.entries += 1;
        if walk.out_of_time() {
            return;
        }
        let Ok(name) = CString::new(entry.file_name().into_vec()) else {
            continue;
        };
        let Some(stat) = fstatat(dir, &name) else {
            // Gone between the listing and the stat: the job deleted it.
            continue;
        };
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if stat.st_dev != walk.root_dev {
                continue;
            }
            charge(walk, &stat);
            if walk.over() {
                return;
            }
            if depth >= MAX_DEPTH {
                walk.complete = false;
                walk.too_deep = true;
                return;
            }
            match open_dir(dir.as_raw_fd(), &name) {
                Some(child) => descend(&child, depth + 1, walk),
                None => {
                    walk.complete = false;
                    walk.unreadable = true;
                }
            }
        } else {
            charge(walk, &stat);
        }
        if walk.over() || (!walk.complete && Instant::now() >= walk.deadline) {
            walk.timed_out |= !walk.over();
            return;
        }
    }
}

/// Walks `root` and returns what it occupies. The walk stops as soon as the total passes `limit` (the caller
/// only needs to know it did), `budget` runs out or `abort` is set.
pub fn measure(
    root: &Path,
    limit: u64,
    budget: Duration,
    abort: &AtomicBool,
) -> std::io::Result<Usage> {
    let path = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dir = open_dir(libc::AT_FDCWD, &path).ok_or_else(std::io::Error::last_os_error)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `dir` is open and `stat` is a writable `stat`.
    if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fstat` returned 0, so it filled the structure.
    let stat = unsafe { stat.assume_init() };
    let mut walk = Walk {
        abort,
        limit,
        deadline: Instant::now() + budget,
        root_dev: stat.st_dev,
        bytes: 0,
        entries: 0,
        complete: true,
        timed_out: false,
        too_deep: false,
        unreadable: false,
        links: HashSet::new(),
    };
    charge(&mut walk, &stat);
    if !walk.over() {
        descend(&dir, 0, &mut walk);
    }
    Ok(Usage {
        bytes: walk.bytes,
        entries: walk.entries,
        complete: walk.complete,
        timed_out: walk.timed_out,
        too_deep: walk.too_deep,
        unreadable: walk.unreadable,
    })
}

/// The wait between two samples after a walk that took `walked`: an eighth of a core at most.
pub fn next_interval(walked: Duration) -> Duration {
    walked.saturating_mul(8).clamp(MIN_INTERVAL, MAX_INTERVAL)
}

struct Shared {
    abort: AtomicBool,
    exceeded: AtomicBool,
    too_deep: AtomicBool,
    unreadable: AtomicBool,
    timed_out: AtomicBool,
    used: AtomicU64,
    stopped: Mutex<bool>,
    wake: Condvar,
}

/// Watches a job's directories (its workspace and its `/tmp`) while its steps run, charging them together.
/// Dropping it stops the watcher.
pub struct Guard {
    shared: Arc<Shared>,
    limit: u64,
    thread: Option<JoinHandle<()>>,
}

impl Guard {
    /// Starts watching `roots` against `limit` bytes taken together (0 watches nothing); a root that does not
    /// exist is not charged. `stop` is called once, from the watcher thread, when they pass the limit; it must end
    /// the job's processes.
    pub fn start(roots: Vec<PathBuf>, limit: u64, stop: impl FnOnce() + Send + 'static) -> Guard {
        let shared = Arc::new(Shared {
            abort: AtomicBool::new(false),
            exceeded: AtomicBool::new(false),
            too_deep: AtomicBool::new(false),
            unreadable: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            used: AtomicU64::new(0),
            stopped: Mutex::new(false),
            wake: Condvar::new(),
        });
        if limit == 0 {
            return Guard {
                shared,
                limit,
                thread: None,
            };
        }
        let watcher = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("sentinel-disk-guard".into())
            .spawn(move || watch(&watcher, &roots, limit, stop))
            .ok();
        Guard {
            shared,
            limit,
            thread,
        }
    }

    /// The bytes the job's directories occupied when they passed the limit, once they have. When the cause was a
    /// tree nested too deep to measure ([`Guard::too_deep`]) this is the lower bound the walk reached, which
    /// may be under the limit.
    pub fn exceeded(&self) -> Option<u64> {
        self.shared
            .exceeded
            .load(Ordering::Acquire)
            .then(|| self.shared.used.load(Ordering::Acquire))
    }

    /// A directory lay deeper than the walk follows, which is refused as over the limit.
    pub fn too_deep(&self) -> bool {
        self.shared.too_deep.load(Ordering::Acquire)
    }

    /// Some sample could not enter a directory, so what is inside it was not counted: the figures are lower
    /// bounds and a job can hide bytes there (docs/executor.md#disk).
    pub fn unreadable(&self) -> bool {
        self.shared.unreadable.load(Ordering::Acquire)
    }

    /// Some sample ran out of its time budget before it saw the whole tree, so it measured up to that point.
    pub fn timed_out(&self) -> bool {
        self.shared.timed_out.load(Ordering::Acquire)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.shared.abort.store(true, Ordering::Relaxed);
        *self
            .shared
            .stopped
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = true;
        self.shared.wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Waits up to `wait`; true when the guard was dropped meanwhile.
fn wait_stopped(shared: &Shared, wait: Duration) -> bool {
    let stopped = shared.stopped.lock().unwrap_or_else(|p| p.into_inner());
    let (stopped, _) = shared
        .wake
        .wait_timeout_while(stopped, wait, |stopped| !*stopped)
        .unwrap_or_else(|p| p.into_inner());
    *stopped
}

/// What one sample of all roots found.
struct Sample {
    bytes: u64,
    too_deep: bool,
    unreadable: bool,
    timed_out: bool,
}

/// The bytes `roots` occupy together, stopping once the total passes `limit` or a tree is too deep to follow. A
/// root that cannot be opened is not over its limit: the steps are ending or it is already gone.
fn measure_all(roots: &[PathBuf], limit: u64, abort: &AtomicBool) -> Sample {
    let mut sample = Sample {
        bytes: 0,
        too_deep: false,
        unreadable: false,
        timed_out: false,
    };
    for root in roots {
        if let Ok(usage) = measure(root, limit.saturating_sub(sample.bytes), WALK_BUDGET, abort) {
            sample.bytes = sample.bytes.saturating_add(usage.bytes);
            sample.too_deep |= usage.too_deep;
            sample.unreadable |= usage.unreadable;
            sample.timed_out |= usage.timed_out;
        }
        if sample.bytes > limit || sample.too_deep {
            break;
        }
    }
    sample
}

fn watch(shared: &Shared, roots: &[PathBuf], limit: u64, stop: impl FnOnce()) {
    let mut wait = FIRST_SAMPLE;
    loop {
        if wait_stopped(shared, wait) {
            return;
        }
        let started = Instant::now();
        let sample = measure_all(roots, limit, &shared.abort);
        if shared.abort.load(Ordering::Relaxed) {
            return;
        }
        if sample.unreadable {
            shared.unreadable.store(true, Ordering::Release);
        }
        if sample.timed_out {
            shared.timed_out.store(true, Ordering::Release);
        }
        if sample.bytes > limit || sample.too_deep {
            shared.used.store(sample.bytes, Ordering::Release);
            shared.too_deep.store(sample.too_deep, Ordering::Release);
            shared.exceeded.store(true, Ordering::Release);
            stop();
            return;
        }
        wait = next_interval(started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::{fd::AsRawFd, unix::fs::symlink},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    const BUDGET: Duration = Duration::from_secs(10);
    static NO_ABORT: AtomicBool = AtomicBool::new(false);

    fn fill(path: &Path, bytes: usize) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0xA5u8; bytes]).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn a_tree_is_charged_by_the_blocks_it_occupies() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a/b")).unwrap();
        fill(&dir.path().join("a/one"), 1 << 20);
        fill(&dir.path().join("a/b/two"), 3 << 20);
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.complete);
        assert!(usage.entries >= 4);
        // Allocation rounds up and directories occupy blocks, so the total is at least the data.
        assert!(usage.bytes >= 4 << 20, "{usage:?}");
        assert!(usage.bytes < 5 << 20, "{usage:?}");
    }

    #[test]
    fn a_sparse_file_costs_what_it_allocates_not_what_it_claims() {
        let dir = tempfile::tempdir().unwrap();
        let file = fs::File::create(dir.path().join("sparse")).unwrap();
        file.set_len(1 << 40).unwrap();
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.bytes < 1 << 20, "{usage:?}");
    }

    #[test]
    fn a_hard_link_is_charged_once() {
        let dir = tempfile::tempdir().unwrap();
        fill(&dir.path().join("first"), 2 << 20);
        for i in 0..4 {
            fs::hard_link(
                dir.path().join("first"),
                dir.path().join(format!("link{i}")),
            )
            .unwrap();
        }
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.bytes >= 2 << 20, "{usage:?}");
        assert!(usage.bytes < 3 << 20, "{usage:?}");
    }

    #[test]
    fn a_symbolic_link_is_not_followed_out_of_the_workspace() {
        let outside = tempfile::tempdir().unwrap();
        fill(&outside.path().join("big"), 8 << 20);
        let dir = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join("out")).unwrap();
        symlink(outside.path().join("big"), dir.path().join("file")).unwrap();
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.bytes < 1 << 20, "{usage:?}");
    }

    #[test]
    fn the_walk_stops_once_the_limit_is_passed() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..50 {
            fill(&dir.path().join(format!("f{i}")), 1 << 20);
        }
        let usage = measure(dir.path(), 4 << 20, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.bytes > 4 << 20);
        assert!(usage.entries < 50, "{usage:?}");
    }

    #[test]
    fn an_unreadable_directory_makes_the_total_a_lower_bound() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sealed")).unwrap();
        fill(&dir.path().join("sealed/hidden"), 1 << 20);
        fs::set_permissions(dir.path().join("sealed"), fs::Permissions::from_mode(0o000)).unwrap();
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        fs::set_permissions(dir.path().join("sealed"), fs::Permissions::from_mode(0o700)).unwrap();
        // Running as root reads it anyway; otherwise the walk says it could not, and says why.
        assert!(usage.complete || usage.bytes >= 1 << 20, "{usage:?}");
        assert_eq!(usage.unreadable, !usage.complete, "{usage:?}");
        assert!(!usage.timed_out && !usage.too_deep, "{usage:?}");
    }

    fn deep_tree_with_payload(dir: &Path, levels: usize, bytes: usize) -> Vec<fs::File> {
        let chain = crate::workspace::build_deep(dir, levels);
        let deepest = chain.last().unwrap();
        let payload = format!("/proc/self/fd/{}/payload", deepest.as_raw_fd());
        fill(Path::new(&payload), bytes);
        chain
    }

    #[test]
    fn a_tree_deeper_than_the_walk_cannot_hide_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let _chain = deep_tree_with_payload(dir.path(), MAX_DEPTH + 2, 2 << 20);
        let usage = measure(dir.path(), 1 << 20, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.too_deep && !usage.complete, "{usage:?}");
        assert!(!usage.timed_out && !usage.unreadable, "{usage:?}");

        let stops = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&stops);
        let guard = Guard::start(vec![dir.path().to_path_buf()], 1 << 20, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let started = Instant::now();
        while guard.exceeded().is_none() && started.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            guard.exceeded().is_some(),
            "the bytes below the walk limit were not refused"
        );
        assert!(guard.too_deep());
        drop(guard);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_tree_just_inside_the_walk_limit_is_measured_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let _chain = deep_tree_with_payload(dir.path(), MAX_DEPTH, 2 << 20);
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.complete && !usage.too_deep, "{usage:?}");
        assert!(usage.bytes >= 2 << 20, "{usage:?}");
    }

    #[test]
    fn a_walk_that_never_completes_is_reported_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..1500 {
            fs::File::create(dir.path().join(format!("f{i}"))).unwrap();
        }
        let usage = measure(dir.path(), u64::MAX, Duration::ZERO, &NO_ABORT).unwrap();
        assert!(!usage.complete, "{usage:?}");
        assert!(usage.timed_out, "{usage:?}");
        assert!(!usage.too_deep && !usage.unreadable, "{usage:?}");
        assert!(usage.entries < 1500, "{usage:?}");
        // The same tree with time to spare is complete, so the flag is not a constant.
        let usage = measure(dir.path(), u64::MAX, BUDGET, &NO_ABORT).unwrap();
        assert!(usage.complete && !usage.timed_out, "{usage:?}");
        assert!(usage.entries >= 1500, "{usage:?}");
    }

    #[test]
    fn the_sampling_interval_follows_the_cost_of_a_walk() {
        assert_eq!(next_interval(Duration::ZERO), MIN_INTERVAL);
        assert_eq!(
            next_interval(Duration::from_millis(100)),
            Duration::from_millis(800)
        );
        assert_eq!(next_interval(Duration::from_secs(2)), MAX_INTERVAL);
    }

    #[test]
    fn a_workspace_over_its_limit_is_stopped_and_one_under_it_is_not() {
        let dir = tempfile::tempdir().unwrap();
        fill(&dir.path().join("data"), 1 << 20);
        let stops = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&stops);
        let guard = Guard::start(vec![dir.path().to_path_buf()], 4 << 20, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        thread::sleep(FIRST_SAMPLE * 4);
        assert_eq!(guard.exceeded(), None);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        fill(&dir.path().join("more"), 6 << 20);
        let started = Instant::now();
        while guard.exceeded().is_none() && started.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(50));
        }
        let used = guard.exceeded().expect("the watcher noticed the overrun");
        assert!(used > 4 << 20);
        assert_eq!(guard.limit(), 4 << 20);
        drop(guard);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_job_tmp_is_charged_with_the_workspace_and_a_missing_root_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let (workspace, tmp) = (dir.path().join("ws"), dir.path().join("ws.tmp"));
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&tmp).unwrap();
        // Each is under the 4 MiB limit alone; together they pass it.
        fill(&workspace.join("data"), 3 << 20);
        fill(&tmp.join("scratch"), 3 << 20);
        let missing = dir.path().join("absent");
        let stops = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&stops);
        let guard = Guard::start(vec![workspace, tmp, missing], 4 << 20, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let started = Instant::now();
        while guard.exceeded().is_none() && started.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            guard
                .exceeded()
                .expect("the two directories were charged together")
                > 4 << 20
        );
        drop(guard);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_the_guard_ends_the_watcher_without_stopping_anything() {
        let dir = tempfile::tempdir().unwrap();
        let stops = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&stops);
        let guard = Guard::start(vec![dir.path().to_path_buf()], 1 << 30, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let started = Instant::now();
        drop(guard);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(stops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_zero_limit_watches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        fill(&dir.path().join("data"), 1 << 20);
        let guard = Guard::start(vec![dir.path().to_path_buf()], 0, || {
            panic!("must not stop")
        });
        thread::sleep(FIRST_SAMPLE * 3);
        assert_eq!(guard.exceeded(), None);
    }
}
