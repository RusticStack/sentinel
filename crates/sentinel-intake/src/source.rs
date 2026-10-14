//! A binding that authorizes nothing is a typed Unusable answer, never a store error, so one item cannot stall a lane.

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

pub struct Binding {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub metadata: Metadata,
    pub forge: Option<Grant>,
}

pub enum Lookup {
    Unbound,
    Unusable(&'static str),
    Bound(Binding),
}

pub fn classify(store: &Store, repo: RepoId) -> Result<Lookup, StoreError> {
    store.read(move |conn| classify_conn(conn, repo))
}

pub fn classify_conn(
    conn: &sentinel_store::Connection,
    repo: RepoId,
) -> Result<Lookup, StoreError> {
    let metadata = match sources::load_metadata(conn, repo) {
        Ok(metadata) => metadata,
        Err(StoreError::NotFound) => return Ok(Lookup::Unbound),
        Err(e) => return Err(e),
    };
    let tenant = match sources::repo_tenant(conn, repo) {
        Ok(tenant) => tenant,
        Err(StoreError::NotFound) => return Ok(Lookup::Unusable("tenant_suspended")),
        Err(e) => return Err(e),
    };
    if metadata.revoked {
        return Ok(Lookup::Unusable("binding_revoked"));
    }
    let forge = if metadata.forge.is_some() {
        match sources_forge::grant(conn, tenant, repo) {
            Ok(grant) => Some(grant),
            Err(StoreError::NotFound) => return Ok(Lookup::Unusable("access_removed")),
            Err(e) => return Err(e),
        }
    } else {
        None
    };
    Ok(Lookup::Bound(Binding {
        tenant,
        repo,
        metadata,
        forge,
    }))
}

pub fn lookup_conn(
    conn: &sentinel_store::Connection,
    repo: RepoId,
) -> Result<Option<Binding>, StoreError> {
    match classify_conn(conn, repo)? {
        Lookup::Unbound => Ok(None),
        Lookup::Unusable(_) => Err(StoreError::Forbidden),
        Lookup::Bound(binding) => Ok(Some(binding)),
    }
}

/// Bind time checks the policy too, but it can be narrowed later, so every fetch rechecks it.
pub fn destination_allowed(destinations: &[String], remote: &str) -> bool {
    sentinel_protocol::source::remote(remote)
        .is_some_and(|authority| destinations.iter().any(|d| d == authority))
}

/// NotFound/Forbidden here means the binding changed after the lookup, so it is transient.
fn store_refusal(error: StoreError) -> Error {
    match error {
        StoreError::NotFound | StoreError::Forbidden => Error::Unavailable("source_changed"),
        StoreError::Corrupt(_) => Error::Refused("source_unavailable"),
        _ => Error::Unavailable("store_unavailable"),
    }
}

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
    let version = binding.metadata.version;
    let Some(forge) = &binding.forge else {
        let key = key.ok_or(Error::Refused("source_unavailable"))?;
        let access = store
            .read(move |conn| sources::issue(conn, binding.tenant, binding.repo, key, now))
            .map_err(store_refusal)?;
        if access.version != version {
            return Err(Error::Unavailable("source_changed"));
        }
        return Ok(access);
    };
    let app = app.ok_or(Error::Refused("github_unconfigured"))?;
    let mut token = app
        .source_token(
            forge.installation,
            forge.account,
            forge.repo,
            &binding.metadata.binding.remote,
            now.0,
        )
        .map_err(|_| Error::Unavailable("github_unavailable"))?;
    let grant = forge.clone();
    let (tenant, repo) = (binding.tenant, binding.repo);
    let unchanged = store
        .read(move |conn| {
            Ok(match classify_conn(conn, repo)? {
                Lookup::Bound(current) => {
                    current.tenant == tenant
                        && current.metadata.version == version
                        && current.forge.as_ref() == Some(&grant)
                }
                Lookup::Unbound | Lookup::Unusable(_) => false,
            })
        })
        .map_err(store_refusal)?;
    if !unchanged {
        return Err(Error::Unavailable("source_changed"));
    }
    Ok(Access {
        binding: binding.metadata.binding.clone(),
        version,
        expires_ms: token.expires_ms.min(now.0.saturating_add(60_000)),
        credential: Credential::Https {
            username: "x-access-token".into(),
            secret: std::mem::take(&mut token.secret),
        },
    })
}
