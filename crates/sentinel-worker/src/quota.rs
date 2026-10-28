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
/// Directory levels followed; a deeper tree is reported incomplete (the walk holds one descriptor per level).
const MAX_DEPTH: usize = 128;
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
    /// False when the walk stopped early (time budget, depth) or met a directory it could not read; `bytes` is
    /// then a lower bound.
    pub complete: bool,
}

struct Walk<'a> {
    abort: &'a AtomicBool,
    limit: u64,
    deadline: Instant,
    root_dev: u64,
    bytes: u64,
    entries: u64,
    complete: bool,
    links: HashSet<(u64, u64)>,
}

impl Walk<'_> {
    fn over(&self) -> bool {
        self.bytes > self.limit
    }

    fn out_of_time(&mut self) -> bool {
        if self.entries.is_multiple_of(CHECK_TIME_EVERY)
            && (Instant::now() >= self.deadline || self.abort.load(Ordering::Relaxed))
        {
            self.complete = false;
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
        let key = (stat.st_dev as u64, stat.st_ino as u64);
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
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            walk.complete = false;
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
            if stat.st_dev as u64 != walk.root_dev {
                continue;
            }
            charge(walk, &stat);
            if walk.over() {
                return;
            }
            if depth >= MAX_DEPTH {
                walk.complete = false;
                continue;
            }
            match open_dir(dir.as_raw_fd(), &name) {
                Some(child) => descend(&child, depth + 1, walk),
                None => walk.complete = false,
            }
        } else {
            charge(walk, &stat);
        }
        if walk.over() || (!walk.complete && Instant::now() >= walk.deadline) {
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
        root_dev: stat.st_dev as u64,
        bytes: 0,
        entries: 0,
        complete: true,
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
    })
}

/// The wait between two samples after a walk that took `walked`: an eighth of a core at most.
pub fn next_interval(walked: Duration) -> Duration {
    walked.saturating_mul(8).clamp(MIN_INTERVAL, MAX_INTERVAL)
}

struct Shared {
    abort: AtomicBool,
    exceeded: AtomicBool,
    used: AtomicU64,
    stopped: Mutex<bool>,
    wake: Condvar,
}

/// Watches one workspace while its steps run. Dropping it stops the watcher.
pub struct Guard {
    shared: Arc<Shared>,
    limit: u64,
    thread: Option<JoinHandle<()>>,
}

impl Guard {
    /// Starts watching `workspace` against `limit` bytes (0 watches nothing). `stop` is called once, from the
    /// watcher thread, when the workspace passes the limit; it must end the job's processes.
    pub fn start(workspace: PathBuf, limit: u64, stop: impl FnOnce() + Send + 'static) -> Guard {
        let shared = Arc::new(Shared {
            abort: AtomicBool::new(false),
            exceeded: AtomicBool::new(false),
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
            .spawn(move || watch(&watcher, &workspace, limit, stop))
            .ok();
        Guard {
            shared,
            limit,
            thread,
        }
    }

    /// The bytes the workspace occupied when it passed the limit, once it has.
    pub fn exceeded(&self) -> Option<u64> {
        self.shared
            .exceeded
            .load(Ordering::Acquire)
            .then(|| self.shared.used.load(Ordering::Acquire))
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

fn watch(shared: &Shared, workspace: &Path, limit: u64, stop: impl FnOnce()) {
    let mut wait = FIRST_SAMPLE;
    loop {
        if wait_stopped(shared, wait) {
            return;
        }
        let started = Instant::now();
        // A workspace that cannot be read is not over its limit: the steps are ending or already gone.
        if let Ok(usage) = measure(workspace, limit, WALK_BUDGET, &shared.abort)
            && usage.bytes > limit
            && !shared.abort.load(Ordering::Relaxed)
        {
            shared.used.store(usage.bytes, Ordering::Release);
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
        os::unix::fs::symlink,
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
        // Running as root reads it anyway; otherwise the walk says it could not.
        assert!(usage.complete || usage.bytes >= 1 << 20, "{usage:?}");
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
        let guard = Guard::start(dir.path().to_path_buf(), 4 << 20, move || {
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
    fn dropping_the_guard_ends_the_watcher_without_stopping_anything() {
        let dir = tempfile::tempdir().unwrap();
        let stops = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&stops);
        let guard = Guard::start(dir.path().to_path_buf(), 1 << 30, move || {
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
        let guard = Guard::start(dir.path().to_path_buf(), 0, || panic!("must not stop"));
        thread::sleep(FIRST_SAMPLE * 3);
        assert_eq!(guard.exceeded(), None);
    }
}
