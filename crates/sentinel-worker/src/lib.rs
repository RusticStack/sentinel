//! Worker execution (W03): a fresh workspace per attempt, an exact-revision
//! checkout, a rootless Podman container with the job's limits and no
//! privileges, and the attempt lifecycle that reports through the link.
//!
//! Everything here runs helper processes — `git` and `podman` — and never
//! implements containers or Git transport itself. Every helper runs in its
//! own process group under a deadline, so a hung fetch or pull is killed as
//! a group, and every container carries the worker's labels so what this
//! process owns can be listed and reaped after a crash (W07).
//!
//! Linux only: on other targets the crate is empty, like the resolver.

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
#[cfg(target_os = "linux")]
pub mod images;
#[cfg(target_os = "linux")]
pub mod logpipe;
#[cfg(target_os = "linux")]
pub mod podman;
#[cfg(target_os = "linux")]
pub mod prefetch;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
pub mod recovery;
pub mod redact;
pub mod spool;
#[cfg(target_os = "linux")]
pub mod workspace;

use std::fmt;

/// Why preparation or execution could not proceed. `Preparation` and
/// `Runtime` are infrastructure failures, never a failed command: a step's
/// own exit status is a `StepOutcome` in the attempt summary, not an error.
#[derive(Debug)]
pub enum Error {
    /// Checkout, image pull or container creation failed. Carries a bounded,
    /// credential-free excerpt of the helper's stderr.
    Preparation(String),
    /// The container runtime is unusable or refused an operation.
    Runtime(String),
    /// A helper process exceeded its deadline and was killed as a group.
    Timeout(&'static str),
    /// The workspace already exists or cannot be created: never reused.
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

/// Make the entries of `dir` durable: a file created, renamed or removed in
/// it survives a power loss only once its directory is synced.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Where the worker keeps short-lived private state that should never
/// reach persistent disk — delivered secrets, private stores' run roots
/// (P10D-8): `$XDG_RUNTIME_DIR/sentinel-<key>` when that variable names an
/// absolute, owner-only directory of this user (a tmpfs on systemd hosts),
/// keyed by the data directory so two workers of one account never share
/// it; `<data_dir>/run` otherwise. Only the path is computed here; users
/// create what they need beneath it owner-only.
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

/// `$XDG_RUNTIME_DIR` when it is an absolute, owner-only directory of
/// this user.
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

/// Whether the worker's cache root — `<data_dir>/cache` — can serve
/// reflink clones: the `Capabilities::REFLINK` bit a `worker` role's Hello
/// advertises. The answer is `clone::detect`'s, probed once per root and
/// remembered, so the capability and the backend restore actually uses can
/// never disagree. An unanswerable probe is `false` — the copy fallback.
#[cfg(target_os = "linux")]
pub fn cache_reflink(data_dir: &std::path::Path) -> bool {
    sentinel_cache::clone::detect(&data_dir.join(sentinel_cache::attach::ROOT_DIR))
        == sentinel_cache::clone::Backend::Reflink
}
