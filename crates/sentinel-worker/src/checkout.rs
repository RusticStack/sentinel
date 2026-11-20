//! Only mirror-side failures fall back to direct; remote answers never retry, since direct would repeat them.
//!
//! An additional checkout of the job is fetched the same way as the run's own: through that repository's
//! mirror when it asks for nothing but its commit, and directly at the depth it declares otherwise.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use sentinel_core::RepoId;
use sentinel_pipeline::{PinnedSource, schema::History};
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
    checkout_at(workspace, source, credential, History::Shallow, timeout)
}

/// A manual checkout at the history selection the job declared.
pub fn checkout_at(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    history: History,
    timeout: Duration,
) -> Result<Checkout> {
    sentinel_git::checkout_at(workspace, source, credential, history.depth(), timeout).map_err(map)
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
    history: History,
    lease: &str,
    timeout: Duration,
) -> Result<Outcome> {
    // Only a bound repository has a mirror, and only a checkout that asks for nothing but its commit uses
    // it: a deeper one would get whatever history the mirror happens to hold.
    match (mirrors, access, history) {
        (Some(mirrors), Some(access), History::Shallow) => through_mirror(
            workspace,
            mirrors,
            repo,
            source,
            Some(access),
            valid_until,
            lease,
            timeout,
        ),
        _ => direct(workspace, source, access, valid_until, history, timeout).map(|checkout| {
            Outcome {
                checkout,
                route: CheckoutRoute::Direct,
                fallback_reason: None,
            }
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
            let checkout = direct(
                workspace,
                source,
                access,
                valid_until,
                History::Shallow,
                left,
            )?;
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
    history: History,
    timeout: Duration,
) -> Result<Checkout> {
    match access {
        Some(access) => {
            let timeout = bounded(valid_until, timeout)?;
            sentinel_git::checkout_authorized_at(
                workspace,
                source,
                access,
                history.depth(),
                timeout,
            )
            .map_err(map)
        }
        None => checkout_at(workspace, source, None, history, timeout),
    }
}

/// One additional checkout of the job into `workspace`, at the history its declaration asks for.
///
/// `recorded` says the revision is the run's recorded one: when the fetch cannot find it, that is reported
/// as a vanished recorded revision — the rerun must not quietly build the branch's current tip instead.
#[allow(clippy::too_many_arguments)]
pub fn checkout_extra(
    workspace: &Path,
    mirrors: Option<&Mirrors>,
    repo: &RepoId,
    source: &PinnedSource,
    access: &Access,
    valid_until: Option<Instant>,
    history: History,
    recorded: bool,
    lease: &str,
    timeout: Duration,
) -> Result<Outcome> {
    let timeout = bounded(valid_until, timeout)?;
    // A shallow checkout of a bound repository is the mirror's own case; a deeper one would get whatever
    // history the mirror happens to hold, so it fetches from the remote itself.
    let (outcome, route) = match (mirrors, history) {
        (Some(mirrors), History::Shallow) => (
            mirrors.checkout_authorized(workspace, repo, source, access, lease, timeout),
            CheckoutRoute::Mirror,
        ),
        _ => (
            sentinel_git::checkout_authorized_at(
                workspace,
                source,
                access,
                history.depth(),
                timeout,
            ),
            CheckoutRoute::Direct,
        ),
    };
    match outcome {
        Ok(checkout) => Ok(Outcome {
            checkout,
            route,
            fallback_reason: None,
        }),
        Err(sentinel_git::Error::Missing | sentinel_git::Error::Preparation(_)) if recorded => {
            Err(Error::Preparation(format!(
                "the run's recorded revision {} of {} is no longer fetchable from its remote",
                source.sha,
                source
                    .ref_name
                    .as_deref()
                    .unwrap_or("the additional repository")
            )))
        }
        Err(error) => Err(map(error)),
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
