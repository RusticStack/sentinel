//! Never hardlink: a shared inode would let one job's write corrupt the generation for every other.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

const COPY_BUFFER: usize = 256 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Reflink,
    Copy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
    pub copied_bytes: u64,
    pub reflinks: u64,
    pub symlinks: u64,
    pub skipped: u64,
}

static PROBES: OnceLock<Mutex<BTreeMap<PathBuf, Backend>>> = OnceLock::new();

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

/// Payload digests are not re-verified: reading every byte would defeat the reflink path.
pub fn tree(src: &Path, dst: &Path, backend: Backend) -> io::Result<Stats> {
    if !fs::symlink_metadata(src)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "generation payload is not a directory",
        ));
    }
    let mut stats = Stats::default();
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

/// `FICLONE` shares extents, not mode bits, so the mode is set explicitly.
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

pub(crate) fn empty(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        clear(&entry?.path())?;
    }
    Ok(())
}

fn clear(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

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
        assert_eq!(contents(&src), contents(&dst));
        assert_eq!(stats.files + stats.symlinks, if cfg!(unix) { 5 } else { 2 });

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
        assert_eq!(detect(Path::new("/proc/definitely-not")), Backend::Copy);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_recreated_never_followed() {
        use std::os::unix::fs::symlink;
        let (temp, src) = generation();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let dst = temp.path().join("dst");
        tree(&src, &dst, Backend::Copy).unwrap();
        let meta = fs::symlink_metadata(dst.join("escape")).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            fs::read_link(dst.join("escape")).unwrap(),
            Path::new("../outside")
        );
        assert!(
            fs::symlink_metadata(dst.join("dangling"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        symlink("a/b/one", src.join("inside")).unwrap();
        tree(&src, &temp.path().join("dst2"), Backend::Copy).unwrap();
        assert!(
            fs::symlink_metadata(temp.path().join("dst2/inside"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(target_os = "linux")]
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
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir(&dst).unwrap();
        symlink(&elsewhere, dst.join("a")).unwrap();
        tree(&src, &dst, Backend::Copy).unwrap();
        assert!(dst.join("a/b/one").is_file());
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        assert!(
            !fs::symlink_metadata(dst.join("a"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
