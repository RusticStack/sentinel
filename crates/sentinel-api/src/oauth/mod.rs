//! The OAuth 2.0 authorization server's HTTP surface (O01–O06).
//!
//! [`route`] runs before the `/api/v1` router and owns `/.well-known/*`,
//! `/oauth/*`, `/device`, `/api/v1/grants*` and
//! `/api/v1/tenants/{slug}/service-accounts*`. This module answers the
//! metadata documents, dispatches the token endpoint by `grant_type`
//! (implementing `refresh_token`; `authorization_code` goes to [`code`],
//! the device grant to [`device`]) and implements RFC 7009 revocation.
//!
//! The `/oauth/*` endpoints speak RFC 6749: `application/x-www-form-urlencoded`
//! bodies of at most [`MAX_OAUTH_FORM_BYTES`], a repeated parameter is
//! `invalid_request`, and errors are `{"error", "error_description"}` with
//! `cache-control: no-store` and `pragma: no-cache`. Unauthenticated POSTs
//! share one token bucket (20/s, burst 40); overflow is
//! `temporarily_unavailable`.

pub(crate) mod code;
pub(crate) mod device;
pub(crate) mod html;
pub(crate) mod service;

use std::{collections::HashMap, sync::Mutex, time::Instant};

use sentinel_auth::oauth::{self as forms, Kind};
use sentinel_core::{UnixMillis, UserId, auth::Scopes};
use sentinel_protocol::{
    error::ErrorCode,
    limits::MAX_OAUTH_FORM_BYTES,
    oauth::{
        API_RESOURCE_SUFFIX, GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN,
        Metadata, OAuthError, OAuthErrorCode, ProtectedResource, TokenResponse,
    },
};
use sentinel_store::oauth::{self as grants, Client, Minted, RefreshError};
use serde_json::json;

use crate::{
    State,
    auth::{Identity, Via},
    http::{Header, Request},
    routes::{self, Reply, Route},
};

/// Unauthenticated OAuth POSTs admitted per second, and the burst above it.
pub(crate) const UNAUTH_RATE_PER_SEC: u64 = 20;
pub(crate) const UNAUTH_BURST: u64 = 40;

/// A token bucket in thousandths of a token, refilled on each take.
pub(crate) struct TokenBucket {
    milli: u64,
    last: Instant,
}

impl TokenBucket {
    fn full(now: Instant) -> Self {
        Self {
            milli: UNAUTH_BURST * 1000,
            last: now,
        }
    }

    /// Take one token at `now`; `false` when the bucket is empty.
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_millis();
        // RATE tokens per second is RATE thousandths per millisecond.
        let refill = u64::try_from(elapsed)
            .unwrap_or(u64::MAX)
            .saturating_mul(UNAUTH_RATE_PER_SEC);
        self.milli = self.milli.saturating_add(refill).min(UNAUTH_BURST * 1000);
        self.last = now;
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// The authorization server's per-process state.
pub(crate) struct OAuthState {
    /// The issuer: `public_url`, or `http://{bound address}`.
    pub issuer: String,
    /// `scheme://host[:port]` of the issuer, for `Origin` checks.
    pub origin: String,
    /// `{issuer}/api/v1`, the `resource` of `Audience::Api`.
    pub api_resource: String,
    /// Keys consent and device-approval form tokens; random per process.
    pub form_key: [u8; 32],
    /// Shared by every unauthenticated OAuth POST.
    pub unauth: Mutex<TokenBucket>,
    /// Device-code digest -> (last poll, current interval in ms), bounded by
    /// `sentinel_store::oauth::MAX_PENDING_DEVICE`.
    pub device_polls: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
    /// Wrong user codes per account: (count, window start).
    pub user_code_failures: Mutex<HashMap<UserId, (u8, Instant)>>,
}

impl OAuthState {
    pub(crate) fn new(issuer: String) -> Self {
        let origin = match issuer.find("://") {
            Some(at) => match issuer[at + 3..].find('/') {
                Some(slash) => issuer[..at + 3 + slash].to_owned(),
                None => issuer.clone(),
            },
            None => issuer.clone(),
        };
        Self {
            api_resource: format!("{issuer}{API_RESOURCE_SUFFIX}"),
            origin,
            issuer,
            form_key: sentinel_auth::cookie::form_key(),
            unauth: Mutex::new(TokenBucket::full(Instant::now())),
            device_polls: Mutex::new(HashMap::new()),
            user_code_failures: Mutex::new(HashMap::new()),
        }
    }
}

/// Route the requests this module owns; `None` passes the request on.
pub(crate) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
    query: &str,
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", [".well-known", "oauth-authorization-server"]) => metadata(state),
        ("GET", [".well-known", "oauth-protected-resource", "api", "v1"]) => {
            protected_resource(state)
        }
        ("POST", ["oauth", "token"]) => Ok(token(state, request)),
        ("POST", ["oauth", "revoke"]) => Ok(revoke(state, request)),
        ("GET" | "POST", ["oauth", "authorize"]) => code::authorize(state, request, method, query),
        ("POST", ["oauth", "device_authorization"]) => device::authorization(state, request),
        ("GET" | "POST", ["device"]) => device::page(state, request, method, query),
        (_, ["api", "v1", "grants", rest @ ..]) => service::grants(state, request, method, rest),
        (_, ["api", "v1", "tenants", slug, "service-accounts", rest @ ..]) => {
            service::accounts(state, request, method, slug, rest, query)
        }
        _ => return None,
    })
}

fn metadata(state: &State) -> Route {
    routes::ok(json!(Metadata::for_issuer(
        &state.oauth.issuer,
        &Scopes::NAMES
    )))
}

fn protected_resource(state: &State) -> Route {
    routes::ok(json!(ProtectedResource::for_issuer(
        &state.oauth.issuer,
        &Scopes::NAMES
    )))
}

fn no_cache() -> Vec<Header> {
    vec![routes::header("pragma", "no-cache")]
}

/// An RFC 6749 error answer (`cache-control: no-store` is added for every
/// JSON reply; `pragma: no-cache` here).
pub(crate) fn error(code: OAuthErrorCode, description: &str) -> Reply {
    error_status(code.http_status(), code, description)
}

/// An RFC 6749 error answer with an explicit status (413, 429).
pub(crate) fn error_status(status: u16, code: OAuthErrorCode, description: &str) -> Reply {
    Reply::Json(
        status,
        json!(OAuthError::new(code, description)),
        no_cache(),
    )
}

/// A store failure at an OAuth endpoint: busy is `temporarily_unavailable`,
/// anything else `server_error`.
pub(crate) fn store_failure(e: sentinel_store::Error) -> Reply {
    match e {
        sentinel_store::Error::WriterUnavailable
        | sentinel_store::Error::Overloaded
        | sentinel_store::Error::WriteAmbiguous => error(
            OAuthErrorCode::TemporarilyUnavailable,
            "the authorization server is busy; retry",
        ),
        _ => error(OAuthErrorCode::ServerError, "authorization server fault"),
    }
}

/// The token response for a freshly minted pair (RFC 6749 §5.1).
pub(crate) fn token_reply(minted: &Minted, now: UnixMillis) -> Reply {
    let seconds =
        |until: UnixMillis| u64::try_from(until.0.saturating_sub(now.0) / 1000).unwrap_or(0);
    let body = TokenResponse {
        access_token: forms::format(Kind::Access, &minted.access),
        token_type: "Bearer".to_owned(),
        expires_in: seconds(minted.access_expires),
        refresh_token: forms::format(Kind::Refresh, &minted.refresh),
        scope: minted.scopes.to_names(),
        sentinel_grant: minted.grant.to_string(),
        sentinel_refresh_expires_in: seconds(minted.refresh_expires),
    };
    Reply::Json(200, json!(body), no_cache())
}

/// Admit one unauthenticated OAuth POST against the shared bucket.
pub(crate) fn admit(state: &State) -> Result<(), Reply> {
    let admitted = state
        .oauth
        .unauth
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take(Instant::now());
    if admitted {
        Ok(())
    } else {
        let mut reply = error(
            OAuthErrorCode::TemporarilyUnavailable,
            "too many requests; retry shortly",
        );
        if let Reply::Json(_, _, headers) = &mut reply {
            headers.push(routes::header("retry-after", "1"));
        }
        Err(reply)
    }
}

/// A parsed `application/x-www-form-urlencoded` body. Each name appears at
/// most once; an empty value counts as absent (RFC 6749 §3.1).
pub(crate) struct Form(Vec<(String, String)>);

/// More parameters than any OAuth request needs.
const MAX_FORM_PAIRS: usize = 32;

impl Form {
    /// Parse a form body, refusing repeated names and runaway pair counts.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Form, OAuthError> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (name, value) in form_urlencoded::parse(bytes) {
            if pairs.len() == MAX_FORM_PAIRS {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidRequest,
                    "too many parameters",
                ));
            }
            if pairs.iter().any(|(seen, _)| *seen == name) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidRequest,
                    "a parameter is repeated",
                ));
            }
            pairs.push((name.into_owned(), value.into_owned()));
        }
        Ok(Form(pairs))
    }

    /// A parameter's value; `None` when absent or empty.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

/// Read and parse a form body at an OAuth endpoint.
pub(crate) fn read_form(request: &mut Request) -> Result<Form, Reply> {
    let form_type = routes::header_value(request, "content-type").is_some_and(|value| {
        value.split(';').next().is_some_and(|t| {
            t.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    });
    if !form_type {
        return Err(error(
            OAuthErrorCode::InvalidRequest,
            "expected an application/x-www-form-urlencoded body",
        ));
    }
    let bytes = routes::body_limit(request, MAX_OAUTH_FORM_BYTES).map_err(|e| {
        if e.code == ErrorCode::PayloadTooLarge {
            error_status(413, OAuthErrorCode::InvalidRequest, "body too large")
        } else {
            error(OAuthErrorCode::InvalidRequest, "unreadable body")
        }
    })?;
    Form::parse(&bytes).map_err(|e| Reply::Json(e.http_status(), json!(e), no_cache()))
}

/// The session behind a browser page request, if any. Bearer credentials
/// never drive consent or device approval.
pub(crate) fn session(state: &State, request: &Request) -> Option<Identity> {
    routes::identify(state, request, false)
        .ok()
        .filter(|who| who.via == Via::Session)
}

/// The OAuth token endpoint (RFC 6749 §3.2): public clients identify by
/// `client_id`; `resource`, when given, must be this deployment's API.
fn token(state: &State, request: &mut Request) -> Reply {
    if let Err(reply) = admit(state) {
        return reply;
    }
    let form = match read_form(request) {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let Some(grant_type) = form.get("grant_type") else {
        return error(OAuthErrorCode::InvalidRequest, "grant_type is required");
    };
    let Some(client_id) = form.get("client_id") else {
        return error(OAuthErrorCode::InvalidRequest, "client_id is required");
    };
    let client = match state.store.read(|c| grants::client(c, client_id)) {
        Ok(client) => client,
        Err(sentinel_store::Error::NotFound) => {
            return error(OAuthErrorCode::InvalidClient, "unknown client");
        }
        Err(e) => return store_failure(e),
    };
    if form
        .get("resource")
        .is_some_and(|resource| resource != state.oauth.api_resource)
    {
        return error(
            OAuthErrorCode::InvalidTarget,
            "resource must be this deployment's API",
        );
    }
    match grant_type {
        GRANT_REFRESH_TOKEN => refresh(state, &client, &form),
        GRANT_AUTHORIZATION_CODE => code::token(state, &client, &form),
        GRANT_DEVICE_CODE => device::token(state, &client, &form),
        _ => error(
            OAuthErrorCode::UnsupportedGrantType,
            "grant_type is not supported",
        ),
    }
}

/// The `refresh_token` grant: rotate, optionally narrowing `scope`.
fn refresh(state: &State, client: &Client, form: &Form) -> Reply {
    let Some(text) = form.get("refresh_token") else {
        return error(OAuthErrorCode::InvalidRequest, "refresh_token is required");
    };
    let Some(presented) = forms::parse(Kind::Refresh, text) else {
        return error(OAuthErrorCode::InvalidGrant, "refresh token is not valid");
    };
    let narrow = match form.get("scope").map(Scopes::parse) {
        None => None,
        Some(Ok(scopes)) => Some(scopes),
        Some(Err(_)) => return error(OAuthErrorCode::InvalidScope, "unknown scope"),
    };
    let now = UnixMillis::now();
    match grants::refresh(&state.store, &client.id, &presented, narrow, now) {
        Ok(minted) => token_reply(&minted, now),
        Err(RefreshError::Invalid | RefreshError::Replay) => {
            error(OAuthErrorCode::InvalidGrant, "refresh token is not valid")
        }
        Err(RefreshError::InvalidScope) => error(
            OAuthErrorCode::InvalidScope,
            "scope may only narrow the grant",
        ),
        Err(RefreshError::Store(e)) => store_failure(e),
    }
}

/// RFC 7009 revocation: either token kind revokes its whole grant. The
/// answer is 200 whether or not the token was known.
fn revoke(state: &State, request: &mut Request) -> Reply {
    if let Err(reply) = admit(state) {
        return reply;
    }
    let form = match read_form(request) {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let Some(client_id) = form.get("client_id") else {
        return error(OAuthErrorCode::InvalidRequest, "client_id is required");
    };
    let Some(token) = form.get("token") else {
        return error(OAuthErrorCode::InvalidRequest, "token is required");
    };
    match state.store.read(|c| grants::client(c, client_id)) {
        Ok(_) => {}
        Err(sentinel_store::Error::NotFound) => {
            return error(OAuthErrorCode::InvalidClient, "unknown client");
        }
        Err(e) => return store_failure(e),
    }
    match grants::revoke_presented(&state.store, client_id, token, UnixMillis::now()) {
        Ok(()) => Reply::Json(200, json!({}), no_cache()),
        Err(e) => store_failure(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_bucket_admits_a_burst_then_the_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::full(start);
        for _ in 0..UNAUTH_BURST {
            assert!(bucket.take(start));
        }
        assert!(!bucket.take(start));
        // 50 ms at 20/s is one token.
        assert!(bucket.take(start + Duration::from_millis(50)));
        assert!(!bucket.take(start + Duration::from_millis(50)));
        assert!(bucket.take(start + Duration::from_secs(60)));
    }

    #[test]
    fn forms_refuse_repeats_and_treat_empty_as_absent() {
        let form = Form::parse(b"grant_type=refresh_token&scope=&client_id=sentinel-cli").unwrap();
        assert_eq!(form.get("grant_type"), Some("refresh_token"));
        assert_eq!(form.get("scope"), None);
        assert_eq!(form.get("missing"), None);
        let decoded = Form::parse(b"scope=runs%3Aread+logs%3Aread").unwrap();
        assert_eq!(decoded.get("scope"), Some("runs:read logs:read"));
        let repeated = Form::parse(b"a=1&b=2&a=1").err().unwrap();
        assert_eq!(repeated.error, OAuthErrorCode::InvalidRequest);
        let many = (0..=MAX_FORM_PAIRS)
            .map(|i| format!("p{i}=1"))
            .collect::<Vec<_>>()
            .join("&");
        assert!(Form::parse(many.as_bytes()).is_err());
    }

    #[test]
    fn the_origin_drops_any_path() {
        assert_eq!(
            OAuthState::new("https://ci.example/sentinel".into()).origin,
            "https://ci.example"
        );
        assert_eq!(
            OAuthState::new("http://127.0.0.1:7080".into()).origin,
            "http://127.0.0.1:7080"
        );
    }
}
