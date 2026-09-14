//! Who is calling: a bearer credential (`Authorization: Bearer sntl_…`) or
//! the session cookie, resolved to a `Principal` per request. A cookie
//! session must also present the CSRF header on every mutation; a bearer
//! credential needs no CSRF (no browser sends it ambiently) and can never
//! step up.

use sentinel_auth::{cookie, secret::Secret, token};
use sentinel_core::{UnixMillis, UserId, auth::Principal};
use sentinel_store::{Store, local_auth, tokens};

/// How the caller proved who they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Bearer,
    Session,
}

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub principal: Principal,
    pub user: UserId,
    pub super_admin: bool,
    pub via: Via,
    /// The session's CSRF digest; mutations must match it.
    pub csrf: Option<sentinel_auth::secret::Digest>,
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
/// a session.
pub fn identify(
    store: &Store,
    authorization: Option<&str>,
    cookie_header: Option<&str>,
    csrf: Option<&str>,
    mutation: bool,
    now: UnixMillis,
) -> Result<Identity, Refusal> {
    if let Some(header) = authorization {
        let secret = token::from_authorization(header).ok_or(Refusal::Unauthenticated)?;
        let authenticated = store
            .read(|c| tokens::authenticate(c, &secret, now))
            .map_err(|_| Refusal::Unauthenticated)?;
        if authenticated.record_use_due(now) {
            let _ = tokens::record_use(store, authenticated.token, now);
        }
        return Ok(Identity {
            principal: authenticated.principal,
            user: authenticated.principal.user,
            super_admin: authenticated
                .principal
                .permissions
                .contains(sentinel_core::auth::Permissions::PLATFORM_ADMIN),
            via: Via::Bearer,
            csrf: None,
        });
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
    Ok(Identity {
        principal: session.principal(),
        user: session.user,
        super_admin: session.super_admin,
        via: Via::Session,
        csrf: Some(session.csrf),
    })
}
