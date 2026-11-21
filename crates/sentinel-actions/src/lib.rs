//! Runner mode's cache and artifact services on the worker host (AR06): the Actions cache service,
//! the `setup-*` caches and `upload-artifact`/`download-artifact` served from Sentinel's own disk
//! instead of GitHub's storage, without the workflow changing.
//!
//! Three facts make that transparent, and each has its own module:
//!
//! - **One certificate authority per sandbox** ([`ca`]). It is minted with the sandbox, signs the leaf
//!   the endpoint presents for the two service names, and is written into that sandbox's own
//!   filesystem and nowhere else. A request from outside the sandbox is not one this endpoint can
//!   serve: the client does not have the anchor, so the handshake never completes.
//! - **One name answer per sandbox** ([`dns`]). The sandbox's resolver answers the cache host and the
//!   results host with this sandbox's endpoint and refuses every other name, because forwarding is
//!   how a job's bytes would reach GitHub.
//! - **One scope per sandbox, decided by the listener it reaches** ([`endpoint`]). The scope is not
//!   read from the request: the client's key, version, run id and token are the job's business, and
//!   the boundary a cache entry or an artifact lands in comes from the lease the listener serves. A
//!   sandbox that has not been told its boundary refuses every call ([`Refusal::Unscoped`]).
//!
//! What the endpoint speaks is pinned to the open-source clients rather than to a GitHub document:
//! `actions/cache` 4.2.0 with `@actions/cache` 4.0.0 for the cache service ([`cache`]) and
//! `upload-artifact` 4.6.2's `@actions/artifact` 2.0.1 for the artifact service ([`artifact`]). A
//! call outside that surface is refused, never forwarded.

pub mod artifact;
pub mod ca;
pub mod cache;
pub mod dns;
pub mod endpoint;
mod http;
pub mod store;

pub use ca::SandboxCa;
pub use dns::Resolver;
pub use endpoint::{Endpoint, Refusal, Stats};
pub use store::{Archive, Platform, Store};

use sentinel_core::{RepoId, TenantId};
use sentinel_protocol::{cache::Trust, negotiate::Arch};

/// The cache service host a client reaches when it is not on the v2 service: `ACTIONS_CACHE_URL`'s
/// authority, which `@actions/cache` builds `_apis/artifactcache/...` paths against.
pub const CACHE_HOST: &str = "artifactcache.actions.githubusercontent.com";

/// The results service host: `ACTIONS_RESULTS_URL`'s authority, which serves the v2 cache service and
/// the whole artifact service (`upload-artifact`'s Twirp calls and its signed blob URLs).
pub const RESULTS_HOST: &str = "results-receiver.actions.githubusercontent.com";

/// The two names one sandbox's certificate covers and one sandbox's resolver answers. Everything else
/// a runner talks to is GitHub's own host and is never intercepted.
pub const HOSTS: [&str; 2] = [CACHE_HOST, RESULTS_HOST];

/// The most bytes one request body may carry. A cache archive chunk is 32 MiB in the pinned client; a
/// file the client streams itself can be larger, and 8 GiB refuses a body no runner would send in one
/// request rather than filling the disk with it.
pub const MAX_BODY_BYTES: u64 = 8 << 30;

/// The name a refusal body names its contract by, so a client's log says what answered it.
pub const SCHEMA: &str = "sentinel.actions/1";

/// What one sealed `upload-artifact` body is published to beyond this worker's own disk: the
/// controller's artifact store. The worker implements it over its link, so what a runner-mode job
/// uploads is an artifact row of its tenant — with a class, a deadline, a charge against the
/// repository and tenant quotas, and a manifest another host of the same run can read — rather than a
/// file only this machine knows about.
///
/// Publication is part of the client's upload, not a task behind it: the endpoint answers
/// `FinalizeArtifact` only once the controller holds the row, and a refusal is the client's error, so
/// an artifact is never reported uploaded while the tenant's evidence holds no trace of it.
pub trait Publisher: Send + Sync {
    fn publish(&self, sealed: &Sealed<'_>) -> Published;
}

/// One sealed artifact offered for publication: the boundary it was written under, its name, and the
/// blob on this host that has already been assembled and hashed.
#[derive(Clone, Copy, Debug)]
pub struct Sealed<'a> {
    pub scope: &'a Scope,
    pub name: &'a str,
    /// The sealed blob; its length and digest are the store's own, not the client's claim.
    pub path: &'a std::path::Path,
    pub len: u64,
    pub digest: [u8; 32],
}

/// What a publisher answered. `Refused` carries the reason the controller gave, which the client's
/// upload is failed with, so a job whose artifact the tenant could not hold fails visibly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    Stored,
    Refused(&'static str),
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The sandbox's own certificate authority could not be minted or its leaf could not be signed.
    Ca(String),
    /// The TLS configuration could not be built from the leaf.
    Tls(String),
    /// A request, manifest or wire frame that does not decode. Never a guess: the caller refuses.
    Wire(&'static str),
    /// The archive store refused: a boundary that does not match, a chunk out of order, no space.
    Store(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Ca(why) => write!(f, "sandbox certificate: {why}"),
            Self::Tls(why) => write!(f, "sandbox TLS: {why}"),
            Self::Wire(why) => write!(f, "wire: {why}"),
            Self::Store(why) => write!(f, "store: {why}"),
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

/// The boundary one sandbox's accesses land under: the lease's tenant and repository, the trust its
/// job's provenance allows, and the platform of the machine the sandbox runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub trust: Trust,
    pub platform: Platform,
    /// The GitHub run and job the sandbox's provenance named. They identify an artifact the way GitHub
    /// does, and they are never read from the request: the client's own run id is not authority.
    pub run: u64,
    pub job: u64,
}

impl Scope {
    /// The trust a runner-mode job's provenance allows. A fork pull request's content is the fork's, so
    /// everything it writes is `pull_request`; a run whose delivery arrived through Sentinel's verified
    /// intake for a push or a tag is `protected`; anything else is also `pull_request` rather than
    /// `unprotected`, because a GitHub runner-mode job's content always came from this repository
    /// through GitHub's own admission.
    pub fn trust_of(fork_pr: bool, event: &str, verified_intake: bool) -> Trust {
        if fork_pr {
            return Trust::PullRequest;
        }
        match event {
            "push" | "tag" if verified_intake => Trust::Protected,
            _ => Trust::PullRequest,
        }
    }

    pub fn new(tenant: TenantId, repo: RepoId, trust: Trust, arch: Arch) -> Scope {
        Scope::with_job(tenant, repo, trust, arch, 0, 0)
    }

    pub fn with_job(
        tenant: TenantId,
        repo: RepoId,
        trust: Trust,
        arch: Arch,
        run: u64,
        job: u64,
    ) -> Scope {
        Scope {
            tenant,
            repo,
            trust,
            platform: Platform {
                os: sentinel_cache::Os::Linux,
                arch,
            },
            run,
            job,
        }
    }
}
