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
pub mod attempt;
#[cfg(target_os = "linux")]
pub mod checkout;
#[cfg(target_os = "linux")]
pub mod context;
#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(target_os = "linux")]
pub mod logpipe;
#[cfg(target_os = "linux")]
pub mod podman;
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
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
