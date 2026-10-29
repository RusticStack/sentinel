//! Snapshots of booted guests (plan 16.8, TODO M06): what is stored, when it may be used and how it is
//! reclaimed. The VM-driving flows (building a snapshot, restoring one) are in the parent module.
//!
//! A snapshot is a booted, idle guest of one *shape* (image, vCPUs, memory, scratch size, network or not)
//! that has not seen any job data: Firecracker's `state` file, its `mem` file (mapped copy-on-write by every
//! restore, so the page cache backs all of them and each VM pays only for the pages it touches) and the
//! scratch disk as it was at that moment, which every attempt clones before its restore. `meta.json` is
//! written last and is the marker that the snapshot is complete; its modification time is the last use.
//!
//! A snapshot is only ever valid against the exact bytes it was taken from: the root file system file
//! (rebuilt images are new files with new identities), the guest kernel, the agent (its initramfs name carries
//! the agent's digest), Firecracker and the host CPU and kernel that saved the device and CPU state. All of
//! them are in the snapshot's name, so a changed input is a miss and the old directory is reclaimed.

use std::{
    collections::HashMap,
    fs,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use super::{DIR, STAMP_AFTER};

/// 2: the VMM runs in a chroot that is the VM's directory, so a snapshot's saved paths no longer name the
/// worker's data directory.
const FORMAT: u64 = 2;
/// A guest with more memory than this boots cold: its memory file would be written whole at every build.
pub(super) const MAX_MEMORY_MIB: u64 = 8192;
/// After a snapshot of a shape failed to build, the shape boots cold for this long before another try.
const RETRY_AFTER: Duration = Duration::from_secs(600);

pub(super) fn dir(root: &Path) -> PathBuf {
    root.join(DIR).join("snapshots")
}

/// What a snapshot's guest is configured with; all of it is baked into the saved state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Shape {
    pub vcpus: u64,
    pub mib: u64,
    pub scratch_bytes: u64,
    pub net: bool,
}

/// A usable snapshot's files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub state: PathBuf,
    pub mem: PathBuf,
    pub scratch: PathBuf,
}

/// The identity of a file's bytes as far as a cache needs it: replaced files differ in inode or time.
pub(super) fn file_identity(path: &Path) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    Ok(format!(
        "{}:{}:{}.{:09}",
        meta.len(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec()
    ))
}

/// The host CPU and kernel a snapshot's device and CPU state were saved on, once per process.
fn host_identity() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        let cpu = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let first: Vec<&str> = cpu
            .lines()
            .take_while(|line| !line.trim().is_empty())
            .filter(|line| {
                [
                    "vendor_id",
                    "cpu family",
                    "model",
                    "stepping",
                    "microcode",
                    "flags",
                ]
                .iter()
                .any(|key| line.starts_with(key))
            })
            .collect();
        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        blake3::hash(format!("{}\n{}", first.join("\n"), kernel.trim()).as_bytes()).to_hex()[..16]
            .to_owned()
    })
}

/// The snapshot's name: the image's key (so the image's snapshots are found by prefix) and a digest of
/// everything else the saved state depends on.
pub(super) fn name(
    image_key: &str,
    rootfs: &str,
    initrd: &Path,
    kernel: &Path,
    firecracker: &Path,
    shape: &Shape,
    boot_args: &str,
) -> io::Result<String> {
    let text = format!(
        "{FORMAT}\0{rootfs}\0{boot_args}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        super::CPU_CONFIG,
        initrd.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        file_identity(kernel)?,
        file_identity(firecracker)?,
        host_identity(),
        shape.vcpus,
        shape.mib,
        shape.scratch_bytes,
        shape.net,
    );
    Ok(format!(
        "{image_key}-{}",
        &blake3::hash(text.as_bytes()).to_hex()[..16]
    ))
}

fn is_name(text: &str) -> bool {
    let Some((key, hash)) = text.split_once('-') else {
        return false;
    };
    let hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    key.len() == 32 && hash.len() == 16 && hex(key) && hex(hash)
}

/// Allocated bytes of a file, never more than its apparent size.
fn allocated(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|m| (m.blocks() * 512).min(m.len()))
        .unwrap_or(0)
}

fn meta_json(bytes: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "format": FORMAT, "bytes": bytes }))
        .expect("a JSON value serializes")
}

fn parse_meta(bytes: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("format")?.as_u64()? != FORMAT {
        return None;
    }
    value.get("bytes")?.as_u64()
}

/// The complete snapshot `name`, stamping its last use when the stamp is old. A directory that is not complete
/// (no marker, a missing or empty file) is not a snapshot.
pub(super) fn open(root: &Path, name: &str) -> Option<Snapshot> {
    if !is_name(name) {
        return None;
    }
    let base = dir(root).join(name);
    let mut marker = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(base.join("meta.json"))
        .ok()?;
    let mut text = Vec::new();
    marker.read_to_end(&mut text).ok()?;
    parse_meta(&text)?;
    let snapshot = Snapshot {
        state: base.join("state"),
        mem: base.join("mem"),
        scratch: base.join("scratch.ext4"),
    };
    for file in [&snapshot.state, &snapshot.mem, &snapshot.scratch] {
        if fs::metadata(file).ok()?.len() == 0 {
            return None;
        }
    }
    let stamp = marker.metadata().ok()?.modified().ok()?;
    let now = SystemTime::now();
    if now.duration_since(stamp).is_ok_and(|age| age > STAMP_AFTER) {
        let _ = marker.set_modified(now);
    }
    Some(snapshot)
}

/// A directory for a snapshot under construction; [`publish`] makes it the snapshot.
pub(super) fn staging(root: &Path, name: &str, nonce: &str) -> io::Result<PathBuf> {
    let path = dir(root).join(format!(".{name}.{nonce}.building"));
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Completes a staged snapshot: the marker is written after the files are in place, then the directory takes
/// the snapshot's name. Another build of the same name that finished first wins and this one is removed.
pub(super) fn publish(root: &Path, name: &str, staged: &Path) -> io::Result<()> {
    let bytes: u64 = ["state", "mem", "scratch.ext4"]
        .iter()
        .map(|f| allocated(&staged.join(f)))
        .sum();
    let marker = staged.join("meta.json");
    let tmp = staged.join("meta.json.tmp");
    fs::write(&tmp, meta_json(bytes))?;
    fs::rename(&tmp, &marker)?;
    let target = dir(root).join(name);
    match fs::rename(staged, &target) {
        Ok(()) => Ok(()),
        Err(_) if open(root, name).is_some() => {
            let _ = fs::remove_dir_all(staged);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Removes one snapshot, marker first so no attempt picks up a half-removed one.
pub(super) fn remove(root: &Path, name: &str) -> bool {
    if !is_name(name) {
        return false;
    }
    let base = dir(root).join(name);
    let removed = fs::remove_file(base.join("meta.json")).is_ok();
    let _ = fs::remove_dir_all(&base);
    removed
}

/// Removes every snapshot of one image (its root file system is gone or rebuilt).
pub(super) fn remove_for_image(root: &Path, image_key: &str) -> usize {
    let Ok(entries) = fs::read_dir(dir(root)) else {
        return 0;
    };
    let prefix = format!("{image_key}-");
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.starts_with(&prefix) && remove(root, name))
        .count()
}

/// The bytes the complete snapshots of each image hold, for the image budget.
pub(super) fn bytes_by_image(root: &Path) -> HashMap<String, u64> {
    let mut out: HashMap<String, u64> = HashMap::new();
    let Ok(entries) = fs::read_dir(dir(root)) else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if !is_name(&name) {
            continue;
        }
        let Some(bytes) = fs::read(entry.path().join("meta.json"))
            .ok()
            .and_then(|text| parse_meta(&text))
        else {
            continue;
        };
        if let Some((key, _)) = name.split_once('-') {
            *out.entry(key.to_owned()).or_default() += bytes;
        }
    }
    out
}

/// Removes what no complete image owns and what is an old, abandoned build: snapshots of images that are gone,
/// and staging directories (`.…building`) older than `max_age`. The count removed.
pub(super) fn sweep(root: &Path, has_image: impl Fn(&str) -> bool, max_age: Duration) -> usize {
    let Ok(entries) = fs::read_dir(dir(root)) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .unwrap_or(Duration::ZERO);
        let orphan = if name.starts_with('.') {
            age >= max_age
        } else if is_name(&name) {
            // No complete image owns it, or it is of a format this worker does not restore (never counted in
            // the budget, so nothing else would remove it).
            let stale = fs::read(entry.path().join("meta.json"))
                .ok()
                .and_then(|text| parse_meta(&text))
                .is_none();
            (stale || !name.split_once('-').is_some_and(|(key, _)| has_image(key)))
                && age >= max_age
        } else {
            age >= max_age
        };
        if orphan && fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// A copy of `from` for one attempt: a reflink where the file system has them (the copy is copy-on-write on
/// disk, as the memory mapping is in memory), else a copy of only the data extents, so a mostly empty scratch
/// disk costs what it holds and not what it spans.
pub(super) fn clone_file(from: &Path, to: &Path) -> io::Result<()> {
    let src = fs::File::open(from)?;
    let dst = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(to)?;
    // SAFETY: both descriptors are open files owned here; FICLONE takes the source descriptor as its argument.
    if unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) } == 0 {
        return Ok(());
    }
    let len = src.metadata()?.len();
    dst.set_len(len)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut at: i64 = 0;
    while (at as u64) < len {
        // SAFETY: lseek on an open descriptor.
        let data = unsafe { libc::lseek(src.as_raw_fd(), at, libc::SEEK_DATA) };
        if data < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(src.as_raw_fd(), data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let (mut pos, end) = (data as u64, hole as u64);
        while pos < end {
            let want = buf.len().min((end - pos) as usize);
            let n = src.read_at(&mut buf[..want], pos)?;
            if n == 0 {
                break;
            }
            dst.write_all_at(&buf[..n], pos)?;
            pos += n as u64;
        }
        at = hole;
    }
    Ok(())
}

// ---------------------------------------------------------------- build coordination

type Locks = Mutex<Vec<(String, Arc<Mutex<()>>)>>;

fn locks() -> &'static Locks {
    static LOCKS: Locks = Mutex::new(Vec::new());
    &LOCKS
}

/// The lock of one snapshot's build: attempts that find it held boot cold instead of waiting.
pub(super) fn build_lock(name: &str) -> Arc<Mutex<()>> {
    let mut all = locks().lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, lock)) = all.iter().find(|(n, _)| n == name) {
        return Arc::clone(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    all.push((name.to_owned(), Arc::clone(&lock)));
    lock
}

pub(super) fn release_build_lock(name: &str) {
    let mut all = locks().lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|(n, lock)| n != name || Arc::strong_count(lock) > 1);
}

type Failures = Mutex<HashMap<String, Instant>>;

fn failures() -> &'static Failures {
    static FAILURES: OnceLock<Failures> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether a build of this snapshot failed recently enough that the shape boots cold without trying again.
pub(super) fn recently_failed(name: &str) -> bool {
    let map = failures().lock().unwrap_or_else(|p| p.into_inner());
    map.get(name).is_some_and(|at| at.elapsed() < RETRY_AFTER)
}

pub(super) fn note_failure(name: &str) {
    let mut map = failures().lock().unwrap_or_else(|p| p.into_inner());
    map.retain(|_, at| at.elapsed() < RETRY_AFTER);
    map.insert(name.to_owned(), Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn shape() -> Shape {
        Shape {
            vcpus: 2,
            mib: 512,
            scratch_bytes: 1 << 30,
            net: false,
        }
    }

    fn files(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let kernel = dir.join("vmlinux");
        let firecracker = dir.join("firecracker");
        let initrd = dir.join("initramfs-aaaa.cpio");
        for f in [&kernel, &firecracker, &initrd] {
            fs::write(f, b"x").unwrap();
        }
        (kernel, firecracker, initrd)
    }

    fn named(
        files: &(PathBuf, PathBuf, PathBuf),
        shape: &Shape,
        rootfs: &str,
        args: &str,
    ) -> String {
        let (kernel, firecracker, initrd) = files;
        name(KEY, rootfs, initrd, kernel, firecracker, shape, args).unwrap()
    }

    fn plant(root: &Path, name: &str, bytes: usize) {
        let staged = staging(root, name, "t").unwrap();
        for f in ["state", "mem", "scratch.ext4"] {
            fs::write(staged.join(f), vec![7u8; bytes]).unwrap();
        }
        publish(root, name, &staged).unwrap();
    }

    #[test]
    fn a_snapshot_is_named_by_everything_its_saved_state_depends_on() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        let base = named(&files, &shape(), "1:2:3.0", "console=ttyS0");
        assert!(is_name(&base) && base.starts_with(KEY), "{base}");
        assert_eq!(base, named(&files, &shape(), "1:2:3.0", "console=ttyS0"));
        let other = |s: Shape| named(&files, &s, "1:2:3.0", "console=ttyS0");
        assert_ne!(
            base,
            other(Shape {
                vcpus: 4,
                ..shape()
            })
        );
        assert_ne!(
            base,
            other(Shape {
                mib: 1024,
                ..shape()
            })
        );
        assert_ne!(
            base,
            other(Shape {
                scratch_bytes: 2 << 30,
                ..shape()
            })
        );
        assert_ne!(
            base,
            other(Shape {
                net: true,
                ..shape()
            })
        );
        // A rebuilt root file system (a new file) and a changed boot line are new snapshots.
        assert_ne!(base, named(&files, &shape(), "1:9:3.0", "console=ttyS0"));
        assert_ne!(base, named(&files, &shape(), "1:2:3.0", "console=ttyS0 x"));
    }

    #[test]
    fn a_replaced_kernel_agent_or_firecracker_is_a_different_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (kernel, firecracker, initrd) = files(dir.path());
        let args = "a";
        let base = name(KEY, "r", &initrd, &kernel, &firecracker, &shape(), args).unwrap();
        fs::write(&kernel, b"a longer kernel").unwrap();
        assert_ne!(
            base,
            name(KEY, "r", &initrd, &kernel, &firecracker, &shape(), args).unwrap()
        );
        let newer = dir.path().join("initramfs-bbbb.cpio");
        fs::write(&newer, b"x").unwrap();
        assert_ne!(
            name(KEY, "r", &initrd, &kernel, &firecracker, &shape(), args).unwrap(),
            name(KEY, "r", &newer, &kernel, &firecracker, &shape(), args).unwrap()
        );
        assert!(
            name(
                KEY,
                "r",
                &initrd,
                &dir.path().join("none"),
                &firecracker,
                &shape(),
                args
            )
            .is_err()
        );
    }

    #[test]
    fn only_a_complete_snapshot_opens() {
        let root = tempfile::tempdir().unwrap();
        let n = format!("{KEY}-0123456789abcdef");
        assert!(open(root.path(), &n).is_none());
        // Files without a marker are a build that did not finish.
        let base = dir(root.path()).join(&n);
        fs::create_dir_all(&base).unwrap();
        for f in ["state", "mem", "scratch.ext4"] {
            fs::write(base.join(f), b"x").unwrap();
        }
        assert!(open(root.path(), &n).is_none());
        fs::remove_dir_all(&base).unwrap();
        plant(root.path(), &n, 8);
        let snapshot = open(root.path(), &n).unwrap();
        assert!(snapshot.mem.is_file() && snapshot.state.is_file() && snapshot.scratch.is_file());
        // A truncated memory file (a crash after the marker, a full disk) is not used.
        fs::write(&snapshot.mem, b"").unwrap();
        assert!(open(root.path(), &n).is_none());
        // A name that is not a snapshot's never reaches the file system.
        assert!(open(root.path(), "../../etc").is_none());
    }

    #[test]
    fn publishing_keeps_the_first_of_two_builds_and_leaves_no_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let n = format!("{KEY}-0123456789abcdef");
        plant(root.path(), &n, 8);
        let second = staging(root.path(), &n, "second").unwrap();
        for f in ["state", "mem", "scratch.ext4"] {
            fs::write(second.join(f), b"2").unwrap();
        }
        publish(root.path(), &n, &second).unwrap();
        assert!(!second.exists());
        let kept = open(root.path(), &n).unwrap();
        assert_eq!(fs::read(&kept.mem).unwrap(), vec![7u8; 8]);
        let leftovers: Vec<_> = fs::read_dir(dir(root.path()))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn an_images_snapshots_are_counted_and_removed_with_it() {
        let root = tempfile::tempdir().unwrap();
        let a = format!("{KEY}-aaaaaaaaaaaaaaaa");
        let b = format!("{KEY}-bbbbbbbbbbbbbbbb");
        let other_key = "fedcba9876543210fedcba9876543210";
        let c = format!("{other_key}-cccccccccccccccc");
        for n in [&a, &b, &c] {
            plant(root.path(), n, 4096);
        }
        let by_image = bytes_by_image(root.path());
        assert!(by_image[KEY] >= by_image[other_key] * 2 - 1);
        assert!(by_image[other_key] > 0);
        assert_eq!(remove_for_image(root.path(), KEY), 2);
        assert!(open(root.path(), &a).is_none() && open(root.path(), &b).is_none());
        assert!(open(root.path(), &c).is_some());
        assert!(!bytes_by_image(root.path()).contains_key(KEY));
    }

    #[test]
    fn sweeping_takes_snapshots_of_missing_images_and_old_staging_only() {
        let root = tempfile::tempdir().unwrap();
        let kept = format!("{KEY}-aaaaaaaaaaaaaaaa");
        let gone = format!("{}-bbbbbbbbbbbbbbbb", "f".repeat(32));
        plant(root.path(), &kept, 4);
        plant(root.path(), &gone, 4);
        let staging_dir = staging(root.path(), &kept, "x").unwrap();
        // Nothing is old enough yet: a build in progress and a fresh snapshot are left alone.
        assert_eq!(
            sweep(root.path(), |k| k == KEY, Duration::from_secs(3600)),
            0
        );
        assert!(staging_dir.exists());
        // With a zero age the staging directory and the snapshot of the missing image go.
        assert_eq!(sweep(root.path(), |k| k == KEY, Duration::ZERO), 2);
        assert!(open(root.path(), &kept).is_some());
        assert!(open(root.path(), &gone).is_none());
        assert!(!staging_dir.exists());
    }

    #[test]
    fn a_snapshot_of_an_older_format_is_not_opened_and_is_swept_with_its_image_present() {
        let root = tempfile::tempdir().unwrap();
        let old = format!("{KEY}-aaaaaaaaaaaaaaaa");
        let current = format!("{KEY}-bbbbbbbbbbbbbbbb");
        plant(root.path(), &old, 4);
        plant(root.path(), &current, 4);
        fs::write(
            dir(root.path()).join(&old).join("meta.json"),
            br#"{"format":1,"bytes":4}"#,
        )
        .unwrap();
        assert!(open(root.path(), &old).is_none());
        assert!(open(root.path(), &current).is_some());
        // Its image is still there, so only its format marks it for the sweep (and a fresh one is left alone).
        assert_eq!(
            sweep(root.path(), |k| k == KEY, Duration::from_secs(3600)),
            0
        );
        assert_eq!(sweep(root.path(), |k| k == KEY, Duration::ZERO), 1);
        assert!(!dir(root.path()).join(&old).exists());
        assert!(open(root.path(), &current).is_some());
    }

    #[test]
    fn a_clone_has_the_bytes_and_only_the_data_extents() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("from");
        let file = fs::File::create(&from).unwrap();
        file.set_len(64 << 20).unwrap();
        file.write_all_at(b"head", 0).unwrap();
        file.write_all_at(b"middle", 30 << 20).unwrap();
        file.write_all_at(b"tail", (64 << 20) - 4).unwrap();
        drop(file);
        let to = dir.path().join("to");
        clone_file(&from, &to).unwrap();
        assert_eq!(fs::read(&from).unwrap(), fs::read(&to).unwrap());
        let meta = fs::metadata(&to).unwrap();
        assert_eq!(meta.len(), 64 << 20);
        // Neither a reflink nor a hole-less copy: the clone is still sparse (or shares extents).
        assert!(
            meta.blocks() * 512 < 8 << 20,
            "{} bytes allocated",
            meta.blocks() * 512
        );
        // The clone is a new file: it refuses to overwrite one.
        assert!(clone_file(&from, &to).is_err());
        fs::write(&to, b"changed").unwrap();
        assert_eq!(&fs::read(&from).unwrap()[..4], b"head");
    }

    #[test]
    fn a_failed_build_is_not_retried_at_once_and_a_held_lock_is_seen() {
        let n = format!("{KEY}-failedfailedfail");
        assert!(!recently_failed(&n));
        note_failure(&n);
        assert!(recently_failed(&n));
        let lock = build_lock(&n);
        let held = lock.try_lock().unwrap();
        assert!(
            build_lock(&n).try_lock().is_err(),
            "a second builder must see the lock held"
        );
        drop(held);
        drop(lock);
        release_build_lock(&n);
    }
}
