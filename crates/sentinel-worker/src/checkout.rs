//! Exact-revision checkout into a fresh workspace.
//!
//! The implementation lives in `sentinel-git`, shared with the controller's
//! source resolution: one command discipline, one credential path, one
//! process-group deadline. This module is the worker's typed facade over it —
//! the commit is what the run pinned, never a branch — and it maps the shared
//! crate's errors onto the worker's.
use std::path::Path;
use std::time::Duration;

use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::Access;

use crate::{Error, Result};

pub use sentinel_git::{CHECKOUT_TIMEOUT, Checkout, Credential};

fn map(error: sentinel_git::Error) -> Error {
    match error {
        sentinel_git::Error::Preparation(what) => Error::Preparation(what),
        sentinel_git::Error::Missing => Error::Preparation("revision is not present".into()),
        sentinel_git::Error::Timeout(what) => Error::Timeout(what),
        sentinel_git::Error::TooLarge(what) => {
            Error::Preparation(format!("{what} produced too much output"))
        }
        sentinel_git::Error::UnsupportedPlatform => {
            Error::Preparation("git access requires a Unix host".into())
        }
        sentinel_git::Error::Io(e) => Error::Io(e),
    }
}

/// Check out `source.sha` from `source.repo` into `workspace` (which must be
/// empty), within `timeout`.
pub fn checkout(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    timeout: Duration,
) -> Result<Checkout> {
    sentinel_git::checkout(workspace, source, credential, timeout).map_err(map)
}

/// The same checkout under a source access: expiry, exact remote and allowed
/// ref are rechecked before Git runs.
pub fn checkout_authorized(
    workspace: &Path,
    source: &PinnedSource,
    access: &Access,
    timeout: Duration,
) -> Result<Checkout> {
    sentinel_git::checkout_authorized(workspace, source, access, timeout).map_err(map)
}
