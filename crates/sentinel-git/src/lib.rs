//! Bounded Git access, Unix only: host Git configuration is never read and Git never prompts.
//! Credentials live in owner-only files removed after the fetch; failure excerpts are redacted before a diagnostic.

#[cfg(unix)]
mod destination;

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub mod mirror;

#[cfg(unix)]
pub use unix::{
    CHECKOUT_TIMEOUT, Checkout, Credential, ExitWatch, FetchedFile, MAX_PATH_BYTES, Output,
    cancel_scope, checkout, checkout_authorized, die_with_parent, file_at, file_at_merge,
    is_ancestor, ls_remote, run, wait_step,
};

#[cfg(not(unix))]
mod stub;

#[cfg(not(unix))]
pub use stub::{
    CHECKOUT_TIMEOUT, Checkout, Credential, FetchedFile, Output, cancel_scope, checkout,
    checkout_authorized, file_at, file_at_merge, is_ancestor, ls_remote, run,
};

use std::fmt;

#[derive(Debug, Clone, Copy)]
pub struct Merge<'a> {
    pub r#ref: &'a str,
    pub head: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefTip {
    pub name: String,
    pub oid: String,
    pub peeled: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    Preparation(String),
    /// Never about the requested revision, so callers may fall back to a direct checkout.
    Mirror(String),
    Missing,
    Merge,
    Timeout(&'static str),
    TooLarge(&'static str),
    UnsupportedPlatform,
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(what) => write!(f, "git: {what}"),
            Self::Mirror(what) => write!(f, "git mirror: {what}"),
            Self::Missing => f.write_str("git: path is not present at that revision"),
            Self::Merge => f.write_str("git: the tested merge is absent or names another head"),
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
