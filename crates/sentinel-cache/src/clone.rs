//! K02 — job-private writable clones of immutable generations.
//! Capability-detected reflink (`FICLONE`) with a safe byte-copy fallback;
//! never writable hardlinks. See `docs/cache.md`.
//!
//! A generation's payload is immutable once sealed, so a job never writes
//! into the store: `tree` materializes a private copy the attempt owns.
//! On a reflink-capable filesystem each file is an extent share — cost per
//! file, not per byte — and anywhere else the same tree is produced by a
//! bounded read/write copy. Symlinks are recreated verbatim, never
//! followed — a link inside a generation is data, not a path — and
//! anything that is not a directory, regular file or symlink is skipped
//! and counted. Hardlinks are never created: a shared inode would let one
//! job's write corrupt the generation for every other.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// The copy buffer: large enough that a big file is a handful of reads,
/// small enough to stay in cache between them.
const COPY_BUFFER: usize = 256 << 10;

/// How a payload reaches the job's private view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// `FICLONE` per file: shared extents, cost per file not per byte.
    /// A capable filesystem can still refuse an individual file — those
    /// fall back to the byte copy per file.
    Reflink,
    /// Bounded read/write copy — correct on any filesystem.
    Copy,
}

/// What one `tree` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Regular files materialized.
    pub files: u64,
    /// Payload bytes across them.
    pub bytes: u64,
    /// Bytes physically copied; reflinked files share extents instead.
    pub copied_bytes: u64,
    /// Files cloned through `FICLONE`.
    pub reflinks: u64,
    /// Symlinks recreated verbatim.
    pub symlinks: u64,
    /// Entries that are neither file, dir nor symlink — fifos, sockets,
    /// devices — skipped: a cache never carries them.
    pub skipped: u64,
}

/// Probe answers are per filesystem, so they are remembered per cache
/// root for the life of the process.
static PROBES: OnceLock<Mutex<BTreeMap<PathBuf, Backend>>> = OnceLock::new();

/// The clone backend `cache_root`'s filesystem gives, probed once per
/// root and remembered: a probe is two small files and one ioctl — cheap,
/// but a worker that probed per attempt would pay it forever. A probe
/// that cannot run answers `Copy` *without* being remembered: a transient
/// failure at startup must not pin the slow path.
pub fn detect(cache_root: &Path) -> Backend {
    let key = fs::canonicalize(cache_root).unwrap_or_else(|_| cache_root.to_path_buf());
    let probes = PROBES.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(backend) = probes.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return *backend;
    }
    match probe(cache_root) {
        Some(backend) => {
            probes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key, backend);
            backend
        }
        None => Backend::Copy,
    }
}

/// Two files and one `FICLONE` under the real root. `Some` is the
/// filesystem's answer — `Copy` included — and is remembered; `None`
/// means the probe itself failed (unwritable root) and nothing is cached.
fn probe(cache_root: &Path) -> Option<Backend> {
    if fs::create_dir_all(cache_root).is_err() {
        return None;
    }
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let tag = format!(
        ".probe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let (src, dst) = (cache_root.join(&tag), cache_root.join(format!("{tag}-b")));
    let backend = fs::write(&src, b"p")
        .ok()
        .and_then(|_| reflink(&src, &dst).ok().map(|_| Backend::Reflink));
    let _ = fs::remove_file(&src);
    let _ = fs::remove_file(&dst);
    Some(backend.unwrap_or(Backend::Copy))
}

/// Materialize `src` under `dst`: directories are 0755, regular files go
/// through `backend` (reflink, or a byte copy when the filesystem
/// refuses), symlinks are recreated verbatim. `dst` is created if absent
/// and must be a directory or nothing; its parent must exist. Checkout
/// content already under `dst` is kept except on the exact slots a
/// generation entry claims — which are cleared first, never followed.
///
/// Payload digests are deliberately not re-verified: reading every byte
/// would defeat the reflink path. The `files` blob's digest was verified
/// against the manifest before materialization — that is the trust split
/// `docs/cache.md` describes.
pub fn tree(src: &Path, dst: &Path, backend: Backend) -> io::Result<Stats> {
    if !fs::symlink_metadata(src)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "generation payload is not a directory",
        ));
    }
    let mut stats = Stats::default();
    // The copy buffer is allocated lazily so an all-reflink clone never
    // touches the 256 KiB it would not use.
    let mut buf = Vec::new();
    fill(src, dst, backend, &mut stats, &mut buf)?;
    Ok(stats)
}

fn fill(
    src: &Path,
    dst: &Path,
    backend: Backend,
    stats: &mut Stats,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    ensure_dir(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `DirEntry::metadata` is `symlink_metadata`: the link itself, so
        // nothing here is ever resolved through a symlink.
        let meta = entry.metadata()?;
        let kind = meta.file_type();
        if kind.is_dir() {
            fill(&from, &to, backend, stats, buf)?;
        } else if kind.is_symlink() {
            let target = fs::read_link(&from)?;
            clear(&to)?;
            link(&target, &to)?;
            stats.symlinks += 1;
        } else if kind.is_file() {
            file(&from, &to, &meta, backend, stats, buf)?;
        } else {
            stats.skipped += 1;
        }
    }
    Ok(())
}

/// One regular file: reflink when the backend is `Reflink`, byte-copy on
/// any refusal — a capable filesystem can still reject an individual
/// file. Either way the mode the generation recorded (the source's own
/// permission bits, exec included) is applied: `FICLONE` shares extents,
/// not inode metadata, and `File::create` defaults to 0666 & umask.
fn file(
    from: &Path,
    to: &Path,
    meta: &fs::Metadata,
    backend: Backend,
    stats: &mut Stats,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    clear(to)?;
    let reflinked = match backend {
        Backend::Reflink => reflink(from, to).is_ok(),
        Backend::Copy => false,
    };
    if reflinked {
        stats.reflinks += 1;
    } else {
        stats.copied_bytes += copy(from, to, buf)?;
    }
    set_mode(to, mode_of(meta))?;
    stats.files += 1;
    stats.bytes += meta.len();
    Ok(())
}

/// Byte-copy `from` to `to` through the shared buffer; returns the bytes
/// written. Never follows a symlink: `from` was classified a regular file
/// by `symlink_metadata` and `to`'s slot was cleared.
fn copy(from: &Path, to: &Path, buf: &mut Vec<u8>) -> io::Result<u64> {
    if buf.len() < COPY_BUFFER {
        buf.resize(COPY_BUFFER, 0);
    }
    let mut input = fs::File::open(from)?;
    let mut output = fs::File::create(to)?;
    let mut total = 0u64;
    loop {
        let n = input.read(buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

/// `dst` becomes a real 0755 directory: an existing directory is kept
/// (and keeps its own mode), anything else in the slot is removed —
/// a symlink is unlinked, never followed.
fn ensure_dir(dst: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dst) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => clear(dst)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::create_dir(dst)?;
    set_mode(dst, 0o755)
}

/// The generation claims this slot: whatever the checkout left there goes
/// — a directory whole, a file or symlink by unlink, never followed.
fn clear(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// `FICLONE` `to` from `from`: the destination keeps its own inode, so
/// a write through it can never touch the generation. Any failure is the
/// caller's signal to copy instead.
#[cfg(target_os = "linux")]
fn reflink(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let input = fs::File::open(from)?;
    let output = fs::File::create(to)?;
    // SAFETY: `input` and `output` are open, owned file descriptors that
    // outlive the call, and `FICLONE`'s third argument is the source
    // descriptor passed as an integer.
    if unsafe { libc::ioctl(output.as_raw_fd(), libc::FICLONE, input.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reflink(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reflink is Linux-only",
    ))
}

#[cfg(unix)]
fn link(original: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

#[cfg(not(unix))]
fn link(_original: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlinks are unix-only",
    ))
}

/// The permission bits worth keeping — the same set `FileEntry::mode`
/// records.
#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every (relative path, content) in `dir`, sorted — what "identical
    /// trees" means for the assertions below.
    fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    out.push((
                        path.strip_prefix(dir)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .replace('\\', "/"),
                        fs::read(&path).unwrap(),
                    ));
                }
            }
        }
        out.sort();
        out
    }

    /// A payload the way K03 writes one: nested files with distinct bytes,
    /// an executable, and symlinks (one dangling, one escaping the tree).
    fn generation() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("gen");
        fs::create_dir_all(src.join("a/b")).unwrap();
        fs::write(src.join("a/b/one"), b"one").unwrap();
        fs::write(src.join("two"), vec![7u8; 300_000]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::write(src.join("tool"), b"#!/bin/sh\n").unwrap();
            fs::set_permissions(src.join("tool"), fs::Permissions::from_mode(0o750)).unwrap();
            symlink("../outside", src.join("escape")).unwrap();
            symlink("missing", src.join("dangling")).unwrap();
        }
        (temp, src)
    }

    #[test]
    fn a_copy_clone_round_trips_contents_and_modes() {
        let (temp, src) = generation();
        let dst = temp.path().join("dst");
        let stats = tree(&src, &dst, Backend::Copy).unwrap();
        assert_eq!(contents(&src), contents(&dst));
        assert_eq!(stats.files, if cfg!(unix) { 3 } else { 2 });
        assert_eq!(stats.reflinks, 0);
        assert!(stats.copied_bytes > 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dst.join("tool")).unwrap().permissions().mode() & 0o777,
                0o750
            );
            assert_eq!(stats.symlinks, 2);
        }
    }

    #[test]
    fn a_reflink_clone_is_identical_and_writes_never_reach_the_source() {
        let (temp, src) = generation();
        let dst = temp.path().join("dst");
        let stats = tree(&src, &dst, Backend::Reflink).unwrap();
        // Whether this filesystem took the ioctl or the per-file copy
        // fallback, the produced tree is the same.
        assert_eq!(contents(&src), contents(&dst));
        assert_eq!(stats.files + stats.symlinks, if cfg!(unix) { 5 } else { 2 });

        // The contract the whole design rests on: a job writing into its
        // private view cannot alter the sealed generation — on reflink
        // filesystems by COW, elsewhere by having copied.
        fs::write(dst.join("two"), b"job wrote here").unwrap();
        assert_eq!(fs::read(src.join("two")).unwrap(), vec![7u8; 300_000]);
        fs::write(src.join("two"), b"new seal").unwrap();
        assert_eq!(fs::read(dst.join("two")).unwrap(), b"job wrote here");
    }

    #[test]
    fn detect_caches_per_root_and_only_reports_real_backends() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let a = detect(&root);
        let b = detect(&root);
        assert_eq!(a, b);
        // A directory that cannot be created is `Copy`, never a panic.
        assert_eq!(detect(Path::new("/proc/definitely-not")), Backend::Copy);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_recreated_never_followed() {
        use std::os::unix::fs::symlink;
        let (temp, src) = generation();
        // The escape target: a file the link points at outside the tree.
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let dst = temp.path().join("dst");
        tree(&src, &dst, Backend::Copy).unwrap();
        // The link is a link, pointing where it pointed — not the file.
        let meta = fs::symlink_metadata(dst.join("escape")).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            fs::read_link(dst.join("escape")).unwrap(),
            Path::new("../outside")
        );
        // A dangling link clones as a dangling link.
        assert!(
            fs::symlink_metadata(dst.join("dangling"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // And a link whose target is inside the tree stays a link too.
        symlink("a/b/one", src.join("inside")).unwrap();
        tree(&src, &temp.path().join("dst2"), Backend::Copy).unwrap();
        assert!(
            fs::symlink_metadata(temp.path().join("dst2/inside"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn special_files_are_skipped() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let (temp, src) = generation();
        let fifo = CString::new(src.join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a valid path; mode 0644, no device.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let dst = temp.path().join("dst");
        let stats = tree(&src, &dst, Backend::Copy).unwrap();
        assert_eq!(stats.skipped, 1);
        assert!(!dst.join("pipe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn occupied_slots_are_cleared_never_followed() {
        use std::os::unix::fs::symlink;
        let (temp, src) = generation();
        let dst = temp.path().join("dst");
        // A symlink sitting where the generation wants a directory: the
        // clone must replace the link, not write through it.
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir(&dst).unwrap();
        symlink(&elsewhere, dst.join("a")).unwrap();
        tree(&src, &dst, Backend::Copy).unwrap();
        assert!(dst.join("a/b/one").is_file());
        // `elsewhere` received nothing: the link was replaced, not followed.
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        assert!(
            !fs::symlink_metadata(dst.join("a"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
