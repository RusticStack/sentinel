#[cfg(target_os = "linux")]
pub mod artifacts;
#[cfg(target_os = "linux")]
pub mod attempt;
#[cfg(target_os = "linux")]
pub mod checkout;
#[cfg(target_os = "linux")]
pub mod context;
#[cfg(target_os = "linux")]
pub mod executor;
pub mod host;
#[cfg(target_os = "linux")]
pub mod images;
#[cfg(target_os = "linux")]
pub mod logpipe;
#[cfg(target_os = "linux")]
pub mod microvm;
#[cfg(target_os = "linux")]
pub mod podman;
#[cfg(target_os = "linux")]
pub mod prefetch;
#[cfg(target_os = "linux")]
mod process;
/// A step's output callback: the log path and tests take it.
#[cfg(target_os = "linux")]
pub use process::Sink as OutputSink;
#[cfg(target_os = "linux")]
pub mod recovery;
pub mod redact;
#[cfg(target_os = "linux")]
pub mod sandbox;
pub mod spool;
#[cfg(target_os = "linux")]
pub mod workspace;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Preparation(String),
    Runtime(String),
    Timeout(&'static str),
    Workspace(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(what) => write!(f, "preparation: {what}"),
            Self::Runtime(what) => write!(f, "runtime: {what}"),
            Self::Timeout(what) => write!(f, "{what} exceeded its deadline"),
            Self::Workspace(what) => write!(f, "workspace: {what}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl Drop for Error {
    fn drop(&mut self) {
        let text = match self {
            Self::Preparation(text) | Self::Runtime(text) | Self::Workspace(text) => text,
            Self::Timeout(_) | Self::Io(_) => return,
        };
        let mut bytes = std::mem::take(text).into_bytes();
        bytes.fill(0);
        core::hint::black_box(&mut bytes);
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Entries created, renamed or removed survive power loss only once their directory is synced.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Only directories this user owns are tightened; others are left as they are.
pub(crate) fn private_dir_all(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(dir)?;
        if meta.is_dir() && meta.uid() == euid() && meta.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(meta.mode() & 0o7700))?;
        }
    }
    Ok(())
}

/// Keeps secrets and private run roots off persistent disk: a tmpfs on systemd hosts, keyed per data directory.
#[cfg(target_os = "linux")]
pub fn runtime_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    match xdg_runtime_dir() {
        Some(dir) => {
            let key = blake3::hash(data_dir.as_os_str().as_bytes());
            dir.join(format!("sentinel-{}", &key.to_hex()[..16]))
        }
        None => data_dir.join("run"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn xdg_runtime_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let dir = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    (dir.is_absolute() && meta.is_dir() && meta.uid() == euid() && meta.mode() & 0o077 == 0)
        .then_some(dir)
}

#[cfg(target_os = "linux")]
pub(crate) fn euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
pub fn cache_reflink(data_dir: &std::path::Path) -> bool {
    sentinel_cache::clone::detect(&data_dir.join(sentinel_cache::attach::ROOT_DIR))
        == sentinel_cache::clone::Backend::Reflink
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn private_dir_all_preserves_a_symlink_targets_mode() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &link).unwrap();

        private_dir_all(&link).unwrap();

        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
