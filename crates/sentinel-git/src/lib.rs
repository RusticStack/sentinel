//! Bounded Git access, shared by the controller's source resolution and the
//! worker's exact-revision checkout.
//!
//! One discipline, one implementation: nothing from the host's Git
//! configuration is consulted (`GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_CONFIG_NOSYSTEM=1`), Git can never prompt, every invocation runs in
//! its own process group under one deadline (past it the group is killed),
//! credentials reach Git through owner-only helper files that are removed as
//! soon as the fetch returns, and a failure excerpt is one bounded line with
//! the credential replaced before it can reach a diagnostic.
//!
//! Two entries are offered: [`checkout`], which materialises one exact revision
//! into a workspace, and [`file_at`], which reads one file from a revision —
//! peeling an annotated tag to its commit — for source resolution.
//!
//! Unix only: elsewhere every entry point refuses with
//! [`Error::UnsupportedPlatform`], because the helper discipline (process
//! groups, owner-only modes, `/dev/null`) is not portable.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::{
    CHECKOUT_TIMEOUT, Checkout, Credential, FetchedFile, MAX_PATH_BYTES, Output, checkout,
    checkout_authorized, file_at, run,
};

#[cfg(not(unix))]
mod stub;

#[cfg(not(unix))]
pub use stub::{
    CHECKOUT_TIMEOUT, Checkout, Credential, FetchedFile, Output, checkout, checkout_authorized,
    file_at, run,
};

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Git refused or the repository/path cannot be used; the message carries
    /// a bounded, credential-free excerpt.
    Preparation(String),
    /// The requested path does not exist at the requested revision.
    Missing,
    /// The command exceeded its deadline and its process group was killed.
    Timeout(&'static str),
    /// The command produced more output than the caller allowed.
    TooLarge(&'static str),
    /// Git is not available here (non-Unix host).
    UnsupportedPlatform,
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(what) => write!(f, "git: {what}"),
            Self::Missing => f.write_str("git: path is not present at that revision"),
            Self::Timeout(what) => write!(f, "{what} exceeded its deadline"),
            Self::TooLarge(what) => write!(f, "{what} produced too much output"),
            Self::UnsupportedPlatform => f.write_str("git access requires a Unix host"),
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
