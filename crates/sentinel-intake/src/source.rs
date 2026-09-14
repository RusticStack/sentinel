//! Source credentials for resolution work: a sealed generic credential, or a
//! short-lived GitHub App installation token scoped to one repository.
//!
//! Both the worker's spec delivery and the intake resolver go through this:
//! [`lookup`] reads what the binding authorizes, [`issue`] mints the access
//! (the only network step), and a fresh read afterwards proves the binding and
//! its installation did not change while the token was being minted.

use std::sync::Arc;

use sentinel_auth::sealed::Key;
use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_github::app::App;
use sentinel_protocol::source::{Access, Credential};
use sentinel_store::{
    Error as StoreError, Store,
    sources::{self, Metadata},
    sources_forge::{self, Grant},
};

/// Why an access could not be issued. Permanent refusals settle a delivery;
/// transient ones retry under the attempt budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Refused(&'static str),
    Unavailable(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "source access refused: {why}"),
            Self::Unavailable(why) => write!(f, "source access unavailable: {why}"),
        }
    }
}

/// What a repository's binding authorizes right now: its terms, and the forge
/// installation association when there is one. `None` means the repository
/// has no binding at all (the explicit manual mode).
pub struct Binding {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub metadata: Metadata,
    pub forge: Option<Grant>,
}

pub fn lookup(store: &Store, repo: RepoId) -> Result<Option<Binding>, StoreError> {
    store.read(move |conn| lookup_conn(conn, repo))
}

/// The same lookup inside an existing read snapshot.
pub fn lookup_conn(
    conn: &sentinel_store::Connection,
    repo: RepoId,
) -> Result<Option<Binding>, StoreError> {
    let metadata = match sources::load_metadata(conn, repo) {
        Ok(metadata) => metadata,
        Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let tenant = sources::repo_tenant(conn, repo)?;
    let forge = if metadata.forge.is_some() {
        Some(sources_forge::grant(conn, tenant, repo)?)
    } else {
        None
    };
    Ok(Some(Binding {
        tenant,
        repo,
        metadata,
        forge,
    }))
}

/// Mint an access for a bound repository: the sealed generic credential, or a
/// newly minted App token (the only network step). For a forge association the
/// binding's version, lifecycle grant and active tenant are rechecked after
/// the request, so a revocation that lands mid-flight wins.
pub fn issue(
    store: &Store,
    key: Option<&Key>,
    app: Option<&Arc<App>>,
    binding: &Binding,
    now: UnixMillis,
) -> Result<Access, Error> {
    if binding.metadata.revoked {
        return Err(Error::Refused("binding_revoked"));
    }
    let Some(forge) = &binding.forge else {
        let key = key.ok_or(Error::Refused("source_unavailable"))?;
        return store
            .read(move |conn| sources::issue(conn, binding.tenant, binding.repo, key, now))
            .map_err(|_| Error::Refused("source_unavailable"));
    };
    let app = app.ok_or(Error::Refused("github_unconfigured"))?;
    let token = app
        .source_token(
            forge.installation,
            forge.account,
            forge.repo,
            &binding.metadata.binding.remote,
            now.0,
        )
        .map_err(|_| Error::Unavailable("github_unavailable"))?;
    // The HTTP call held no database connection. A rotated binding, a
    // suspended installation or a suspended tenant wins this race.
    let version = binding.metadata.version;
    let grant = forge.clone();
    let (tenant, repo) = (binding.tenant, binding.repo);
    store
        .read(move |conn| {
            if sources::repo_tenant(conn, repo)? != tenant
                || sources::load_metadata(conn, repo)?.version != version
                || sources_forge::grant(conn, tenant, repo)? != grant
            {
                return Err(StoreError::Forbidden);
            }
            Ok(())
        })
        .map_err(|_| Error::Refused("source_changed"))?;
    Ok(Access {
        binding: binding.metadata.binding.clone(),
        version,
        expires_ms: token.expires_ms.min(now.0.saturating_add(60_000)),
        credential: Credential::Https {
            username: "x-access-token".into(),
            secret: token.secret,
        },
    })
}
