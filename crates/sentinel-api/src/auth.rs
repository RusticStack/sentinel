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
use sentinel_store::{Error as StoreError, Store, auth::Authority, local_auth, tokens};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Bearer,
    Session,
    OAuth,
}

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub principal: Principal,
    pub user: UserId,
    pub super_admin: bool,
    pub via: Via,
    pub csrf: Option<sentinel_auth::secret::Digest>,
    pub scopes: Scopes,
    pub grant: Option<GrantId>,
    pub expires: Option<UnixMillis>,
    /// Display only: privileged changes are authorized through `authority`, not this flag.
    pub stepped_up: bool,
    authority: Authority,
}

impl Identity {
    pub fn authority(&self) -> Authority {
        self.authority
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unauthenticated,
    Csrf,
    /// Not Unauthenticated: an OAuth client answers a 401 by spending its refresh token.
    Busy,
    Fault,
}

fn refused(e: StoreError) -> Refusal {
    match e {
        StoreError::NotFound => Refusal::Unauthenticated,
        StoreError::Overloaded | StoreError::WriterUnavailable | StoreError::WriteAmbiguous => {
            Refusal::Busy
        }
        _ => Refusal::Fault,
    }
}

/// A present Authorization header that is not a Sentinel bearer is refused, never falling back to the cookie.
pub fn identify(
    store: &Store,
    sessions: local_auth::Policy,
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
                    .map_err(refused)?;
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
                    stepped_up: false,
                    authority: Authority::credential(principal),
                })
            }
            Bearer::Access(secret) => {
                let authenticated = store
                    .read(|c| {
                        sentinel_store::oauth::authenticate_access(c, &secret, Audience::Api, now)
                    })
                    .map_err(refused)?;
                Ok(oauth_identity(authenticated))
            }
        };
    }
    let header = cookie_header.ok_or(Refusal::Unauthenticated)?;
    let secret: Secret =
        cookie::read(cookie::SESSION_COOKIE, header).ok_or(Refusal::Unauthenticated)?;
    let session = store
        .read(|c| local_auth::authenticate(c, &secret, now))
        .map_err(refused)?;
    if mutation && !cookie::csrf_accepted(&session.csrf, csrf) {
        return Err(Refusal::Csrf);
    }
    if local_auth::refresh_due(&session, sessions, now) {
        let _ = local_auth::refresh(store, &secret, sessions, now);
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
        stepped_up: session.stepped_up_within(sessions, now),
        authority: Authority::live_session(&session, secret.digest(), sessions),
    })
}

pub(crate) fn identify_mcp(
    store: &Store,
    authorization: Option<&str>,
    now: UnixMillis,
) -> Result<Identity, Refusal> {
    let header = authorization.ok_or(Refusal::Unauthenticated)?;
    let Bearer::Access(secret) = oauth::bearer(header).ok_or(Refusal::Unauthenticated)? else {
        return Err(Refusal::Unauthenticated);
    };
    let authenticated = store
        .read(|c| sentinel_store::oauth::authenticate_access(c, &secret, Audience::Mcp, now))
        .map_err(refused)?;
    Ok(oauth_identity(authenticated))
}

fn oauth_identity(authenticated: sentinel_store::oauth::Authenticated) -> Identity {
    let principal = authenticated.principal;
    Identity {
        principal,
        user: principal.user,
        super_admin: principal.permissions.contains(Permissions::PLATFORM_ADMIN),
        via: Via::OAuth,
        csrf: None,
        scopes: authenticated.scopes,
        grant: Some(authenticated.grant),
        expires: Some(authenticated.expires),
        stepped_up: false,
        authority: Authority::credential(principal),
    }
}

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
