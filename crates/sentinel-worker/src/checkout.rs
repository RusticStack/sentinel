//! Exact-revision checkout into a fresh workspace.
//!
//! The implementation lives in `sentinel-git`, shared with the controller's
//! source resolution: one command discipline, one credential path, one
//! process-group deadline. This module is the worker's typed facade over it —
//! the commit is what the run pinned, never a branch — and it maps the shared
//! crate's errors onto the worker's.
//!
//! With a [`Mirrors`] handle the checkout goes through the worker-local bare
//! mirror for the repository (see `docs/mirrors.md`): a serialized
//! incremental fetch, the pinned commit verified as a commit, then a private
//! object store materialized into the workspace. A failure that is about the
//! mirror itself — lock wait, IO, a damaged store — falls back to the direct
//! fetch with the reason recorded; the remote's own answer (access refused,
//! the pinned commit absent, a spent deadline) never retries, since the
//! direct path could only repeat it.
use std::fs;
use std::path::Path;
use std::time::Duration;

use sentinel_core::RepoId;
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::Access;
use sentinel_protocol::summary::CheckoutRoute;

use crate::{Error, Result};

pub use sentinel_git::mirror::{MIRRORS_DIR, Mirrors};
pub use sentinel_git::{CHECKOUT_TIMEOUT, Checkout, Credential};

/// What a checkout produced and how. `route` is the truth about where the
/// objects came from; `fallback_reason` names why the mirror could not
/// serve when the route is [`CheckoutRoute::MirrorFallback`].
#[derive(Debug)]
pub struct Outcome {
    pub checkout: Checkout,
    pub route: CheckoutRoute,
    pub fallback_reason: Option<String>,
}

fn map(error: sentinel_git::Error) -> Error {
    match error {
        sentinel_git::Error::Preparation(what) => Error::Preparation(what),
        sentinel_git::Error::Mirror(what) => Error::Preparation(format!("git mirror: {what}")),
        sentinel_git::Error::Missing => Error::Preparation("revision is not present".into()),
        // The worker checks out an already-verified revision; a merge result
        // here means the pinned merge was never for this head — treat it as
        // unusable source.
        sentinel_git::Error::Merge => {
            Error::Preparation("the pinned merge is not for this head".into())
        }
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

/// Check out through the mirror for `repo` when `mirrors` is available.
/// `access`, the dispatched source access, authorizes the mirror fetch
/// exactly as it would the direct one; `lease` names the reader lease while
/// the worktree is materialized — the attempt id.
///
/// `Error::Mirror` and `Error::Io` from the mirror mean the store could not
/// serve — never that the revision is wrong — so the workspace is emptied
/// and the direct path runs with the reason recorded. Anything else
/// propagates unchanged.
pub fn checkout_mirrored(
    workspace: &Path,
    mirrors: Option<&Mirrors>,
    repo: &RepoId,
    source: &PinnedSource,
    access: Option<&Access>,
    lease: &str,
    timeout: Duration,
) -> Result<Outcome> {
    let Some(mirrors) = mirrors else {
        return direct(workspace, source, access, timeout).map(|checkout| Outcome {
            checkout,
            route: CheckoutRoute::Direct,
            fallback_reason: None,
        });
    };
    let attempted = match access {
        Some(access) => {
            mirrors.checkout_authorized(workspace, repo, source, access, lease, timeout)
        }
        None => mirrors.checkout(workspace, repo, source, None, lease, timeout),
    };
    match attempted {
        Ok(checkout) => Ok(Outcome {
            checkout,
            route: CheckoutRoute::Mirror,
            fallback_reason: None,
        }),
        Err(e @ (sentinel_git::Error::Mirror(_) | sentinel_git::Error::Io(_))) => {
            let reason: String = e.to_string().chars().take(300).collect();
            // The mirror may have half-materialized the workspace; the
            // direct path requires it empty.
            clear(workspace)?;
            let checkout = direct(workspace, source, access, timeout)?;
            Ok(Outcome {
                checkout,
                route: CheckoutRoute::MirrorFallback,
                fallback_reason: Some(reason),
            })
        }
        Err(e) => Err(map(e)),
    }
}

/// One direct fetch into `workspace`, authorized or manual. A worker has
/// no manual credential — bound access is the only credential path.
fn direct(
    workspace: &Path,
    source: &PinnedSource,
    access: Option<&Access>,
    timeout: Duration,
) -> Result<Checkout> {
    match access {
        Some(access) => {
            sentinel_git::checkout_authorized(workspace, source, access, timeout).map_err(map)
        }
        None => sentinel_git::checkout(workspace, source, None, timeout).map_err(map),
    }
}

/// Empty `workspace` for a retry: a failed materialization may have left a
/// partial `.git` and the direct path requires an empty directory.
fn clear(workspace: &Path) -> Result<()> {
    for entry in fs::read_dir(workspace)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            crate::workspace::remove_tree(&entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
