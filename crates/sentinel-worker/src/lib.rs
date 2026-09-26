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
