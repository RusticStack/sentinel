//! Source credentials for resolution work: a sealed generic credential, or a
//! short-lived GitHub App installation token scoped to one repository.
//!
//! Both the worker's spec delivery and the intake resolver go through this:
//! [`classify`] reads what the binding authorizes, [`issue`] mints the access
//! (the only network step), and a fresh read afterwards proves the binding and
//! its installation did not change while the token was being minted.
//!
//! A binding that exists but authorizes nothing *right now* — its tenant is
//! suspended, its installation suspended or its permissions withdrawn, the
//! binding itself revoked — is a typed [`Lookup::Unusable`] answer, never a
//! store error: a lane that meets one settles or parks that one item and
//! carries on with everybody else's work.

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
/// installation association when there is one.
pub struct Binding {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub metadata: Metadata,
    pub forge: Option<Grant>,
}

/// A repository's source standing, classified. Only a store fault is an
/// error; every lifecycle state is an answer.
pub enum Lookup {
    /// No binding at all: the explicit manual mode.
    Unbound,
    /// A binding exists but authorizes nothing now. The reason is stable and
    /// operator-readable: `tenant_suspended`, `binding_revoked` or
    /// `access_removed` (the forge installation is suspended, deleted or no
    /// longer holds the permissions the binding needs).
    Unusable(&'static str),
    /// A live binding.
    Bound(Binding),
}

pub fn classify(store: &Store, repo: RepoId) -> Result<Lookup, StoreError> {
    store.read(move |conn| classify_conn(conn, repo))
}

/// The same classification inside an existing read snapshot.
pub fn classify_conn(
    conn: &sentinel_store::Connection,
    repo: RepoId,
) -> Result<Lookup, StoreError> {
    let metadata = match sources::load_metadata(conn, repo) {
        Ok(metadata) => metadata,
        Err(StoreError::NotFound) => return Ok(Lookup::Unbound),
        Err(e) => return Err(e),
    };
    // `repo_tenant` answers `NotFound` exactly when the tenant is inactive:
    // the binding row's foreign key guarantees the repository exists.
    let tenant = match sources::repo_tenant(conn, repo) {
        Ok(tenant) => tenant,
        Err(StoreError::NotFound) => return Ok(Lookup::Unusable("tenant_suspended")),
        Err(e) => return Err(e),
    };
    // A revoked forge binding keeps its installation association, so this is
    // decided before the grant, which only a live binding has.
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

/// The controller's spec-delivery view: `None` is the manual mode, and a
/// binding that authorizes nothing is `Forbidden` — the attempt gets no spec.
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

/// Whether the deployment's destination policy (`source-destinations.json`)
/// still approves `remote`. Bind time checks it too, but the policy can be
/// narrowed afterwards, so every controller-side fetch rechecks it.
pub fn destination_allowed(destinations: &[String], remote: &str) -> bool {
    sentinel_protocol::source::remote(remote)
        .is_some_and(|authority| destinations.iter().any(|d| d == authority))
}

/// What a store answer while issuing means. The caller classified the
/// binding as usable a moment ago, so `NotFound`/`Forbidden` here say it
/// changed since — retried, and the next lookup names the precise reason. A
/// sealed credential that does not open (version and ciphertext are read in
/// one statement, so no race produces it) is permanent. Every other fault —
/// an overloaded reader, a busy writer — is transient.
fn store_refusal(error: StoreError) -> Error {
    match error {
        StoreError::NotFound | StoreError::Forbidden => Error::Unavailable("source_changed"),
        StoreError::Corrupt(_) => Error::Refused("source_unavailable"),
        _ => Error::Unavailable("store_unavailable"),
    }
}

/// Mint an access for a bound repository: the sealed generic credential, or a
/// newly minted App token (the only network step). The access is for exactly
/// the binding version `binding` was read at: a rotation that committed after
/// the lookup is `Unavailable("source_changed")`, so the caller retries with
/// a fresh lookup rather than pairing new terms with an old read. For a forge
/// association the binding's version, lifecycle grant and active tenant are
/// rechecked after the request, so a revocation that lands mid-flight wins.
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
    // suspended installation or a suspended tenant wins this race; the next
    // attempt's lookup decides which of them it was.
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
            secret: token.secret,
        },
    })
}
