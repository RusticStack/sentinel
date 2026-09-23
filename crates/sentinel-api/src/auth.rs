//! Who is calling: a bearer credential (`Authorization: Bearer sntl_…`), an
//! OAuth access token (`Authorization: Bearer sntl_at_…`) or the session
//! cookie, resolved to a `Principal` and its scopes per request. A cookie
//! session must also present the CSRF header on every mutation; a bearer
//! needs no CSRF (no browser sends it ambiently) and can never step up.
//!
//! Scopes are a second ceiling beside the principal's permissions. An API
//! credential and a session carry the scopes their permissions imply
//! (`Scopes::from_permissions`), so their authority is unchanged; an OAuth
//! access token carries exactly its grant's scopes. [`require_scope`] is the
//! per-route check.

use sentinel_auth::{
    cookie,
    oauth::{self, Bearer},
    secret::Secret,
};
use sentinel_core::{
    GrantId, UnixMillis, UserId,
    auth::{Audience, Permissions, Principal, Scopes},
};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{Store, local_auth, tokens};

/// How the caller proved who they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// A `sntl_` API credential.
    Bearer,
    /// The browser session cookie.
    Session,
    /// A `sntl_at_` OAuth access token.
    OAuth,
}

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub principal: Principal,
    pub user: UserId,
    pub super_admin: bool,
    pub via: Via,
    /// The session's CSRF digest; mutations must match it.
    pub csrf: Option<sentinel_auth::secret::Digest>,
    /// What this caller may do by scope. Every route checks its own.
    pub scopes: Scopes,
    /// The OAuth grant behind an access token.
    pub grant: Option<GrantId>,
    /// When an OAuth access token stops working.
    pub expires: Option<UnixMillis>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No credential, or one the store does not recognise.
    Unauthenticated,
    /// A session mutation without its CSRF header.
    Csrf,
}

/// Resolve the request's credential. `authorization` and `cookie` are the
/// raw header values; `csrf` the CSRF header, required for mutations from
/// a session. An `Authorization` header that is present but not a Sentinel
/// bearer (a refresh token, a code, a GitHub token) is refused by its shape
/// before any lookup, and never falls back to the cookie.
pub fn identify(
    store: &Store,
    authorization: Option<&str>,
    cookie_header: Option<&str>,
    csrf: Option<&str>,
    mutation: bool,
    now: UnixMillis,
) -> Result<Identity, Refusal> {
    if let Some(header) = authorization {
        return match oauth::bearer(header).ok_or(Refusal::Unauthenticated)? {
            Bearer::Credential(secret) => {
                let authenticated = store
                    .read(|c| tokens::authenticate(c, &secret, now))
                    .map_err(|_| Refusal::Unauthenticated)?;
                if authenticated.record_use_due(now) {
                    let _ = tokens::record_use(store, authenticated.token, now);
                }
                let principal = authenticated.principal;
                Ok(Identity {
                    principal,
                    user: principal.user,
                    super_admin: principal.permissions.contains(Permissions::PLATFORM_ADMIN),
                    via: Via::Bearer,
                    csrf: None,
                    scopes: Scopes::from_permissions(principal.permissions),
                    grant: None,
                    expires: None,
                })
            }
            Bearer::Access(secret) => {
                let authenticated = store
                    .read(|c| {
                        sentinel_store::oauth::authenticate_access(c, &secret, Audience::Api, now)
                    })
                    .map_err(|_| Refusal::Unauthenticated)?;
                let principal = authenticated.principal;
                Ok(Identity {
                    principal,
                    user: principal.user,
                    super_admin: principal.permissions.contains(Permissions::PLATFORM_ADMIN),
                    via: Via::OAuth,
                    csrf: None,
                    scopes: authenticated.scopes,
                    grant: Some(authenticated.grant),
                    expires: Some(authenticated.expires),
                })
            }
        };
    }
    let header = cookie_header.ok_or(Refusal::Unauthenticated)?;
    let secret: Secret =
        cookie::read(cookie::SESSION_COOKIE, header).ok_or(Refusal::Unauthenticated)?;
    let session = store
        .read(|c| local_auth::authenticate(c, &secret, now))
        .map_err(|_| Refusal::Unauthenticated)?;
    if mutation && !cookie::csrf_accepted(&session.csrf, csrf) {
        return Err(Refusal::Csrf);
    }
    let principal = session.principal();
    Ok(Identity {
        principal,
        user: session.user,
        super_admin: session.super_admin,
        via: Via::Session,
        csrf: Some(session.csrf),
        scopes: Scopes::from_permissions(principal.permissions),
        grant: None,
        expires: None,
    })
}

/// Require every scope in `required`. The refusal is `forbidden` with
/// `details.scope` naming what is missing; the response layer turns that
/// detail into `WWW-Authenticate: Bearer error="insufficient_scope"`.
pub fn require_scope(identity: &Identity, required: Scopes) -> Result<(), ApiError> {
    if identity.scopes.contains(required) {
        return Ok(());
    }
    Err(ApiError::new(
        ErrorCode::Forbidden,
        "the credential lacks a required scope",
    )
    .with_detail("scope", required.difference(identity.scopes).to_names()))
}
