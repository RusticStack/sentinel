//! Only mirror-side failures fall back to direct; remote answers never retry, since direct would repeat them.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use sentinel_core::RepoId;
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::Access;
use sentinel_protocol::summary::CheckoutRoute;

use crate::{Error, Result};

pub use sentinel_git::mirror::{MIRRORS_BUDGET_BYTES, MIRRORS_DIR, Mirrors};
pub use sentinel_git::{CHECKOUT_TIMEOUT, Checkout, Credential};

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

/// Caps `timeout` by the access's remaining monotonic validity and refuses an expired one, before anything
/// reads the credential or opens a connection. `None` is an access with no monotonic bound (the controller's
/// wall-clock check in `sentinel-git` still applies).
fn bounded(valid_until: Option<Instant>, timeout: Duration) -> Result<Duration> {
    let Some(until) = valid_until else {
        return Ok(timeout);
    };
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Preparation(EXPIRED.into()));
    }
    Ok(timeout.min(left))
}

const EXPIRED: &str = "source access expired";

pub fn checkout(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    timeout: Duration,
) -> Result<Checkout> {
    sentinel_git::checkout(workspace, source, credential, timeout).map_err(map)
}

pub fn checkout_authorized(
    workspace: &Path,
    source: &PinnedSource,
    access: &Access,
    valid_until: Option<Instant>,
    timeout: Duration,
) -> Result<Checkout> {
    let timeout = bounded(valid_until, timeout)?;
    sentinel_git::checkout_authorized(workspace, source, access, timeout).map_err(map)
}

#[allow(clippy::too_many_arguments)]
pub fn checkout_mirrored(
    workspace: &Path,
    mirrors: Option<&Mirrors>,
    repo: &RepoId,
    source: &PinnedSource,
    access: Option<&Access>,
    valid_until: Option<Instant>,
    lease: &str,
    timeout: Duration,
) -> Result<Outcome> {
    // Only the bound repository's mirror: a manual remote may be a path to another store.
    match (mirrors, access) {
        (Some(mirrors), Some(access)) => through_mirror(
            workspace,
            mirrors,
            repo,
            source,
            Some(access),
            valid_until,
            lease,
            timeout,
        ),
        _ => direct(workspace, source, access, valid_until, timeout).map(|checkout| Outcome {
            checkout,
            route: CheckoutRoute::Direct,
            fallback_reason: None,
        }),
    }
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn through_mirror(
    workspace: &Path,
    mirrors: &Mirrors,
    repo: &RepoId,
    source: &PinnedSource,
    access: Option<&Access>,
    valid_until: Option<Instant>,
    lease: &str,
    timeout: Duration,
) -> Result<Outcome> {
    let timeout = match access {
        Some(_) => bounded(valid_until, timeout)?,
        None => timeout,
    };
    let deadline = Instant::now() + timeout;
    let share = timeout / 2;
    let attempted = match access {
        Some(access) => mirrors.checkout_authorized(workspace, repo, source, access, lease, share),
        None => mirrors.checkout(workspace, repo, source, None, lease, share),
    };
    match attempted {
        Ok(checkout) => Ok(Outcome {
            checkout,
            route: CheckoutRoute::Mirror,
            fallback_reason: None,
        }),
        Err(
            e @ (sentinel_git::Error::Mirror(_)
            | sentinel_git::Error::Io(_)
            | sentinel_git::Error::Timeout(_)),
        ) => {
            let reason: String = e.to_string().chars().take(300).collect();
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(map(e));
            }
            clear(workspace)?;
            let checkout = direct(workspace, source, access, valid_until, left)?;
            Ok(Outcome {
                checkout,
                route: CheckoutRoute::MirrorFallback,
                fallback_reason: Some(reason),
            })
        }
        Err(e) => Err(map(e)),
    }
}

fn direct(
    workspace: &Path,
    source: &PinnedSource,
    access: Option<&Access>,
    valid_until: Option<Instant>,
    timeout: Duration,
) -> Result<Checkout> {
    match access {
        Some(access) => checkout_authorized(workspace, source, access, valid_until, timeout),
        None => sentinel_git::checkout(workspace, source, None, timeout).map_err(map),
    }
}

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
