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
//! are admitted per client and under a deployment-wide ceiling ([`limit`]);
//! overflow is `temporarily_unavailable`.
//!
//! The issuer may carry a path (`https://ci.example.com/sentinel`). Every URL
//! a page or document hands out is built from the issuer, and the metadata
//! documents are served both at the issuer-relative paths and at the RFC
//! 8414 §3.1 / RFC 9728 §3.1 locations (well-known segment between host and
//! issuer path). [`OAuthState::local_path`] strips the issuer path from a
//! request that a proxy forwarded without stripping it.

pub(crate) mod client;
pub(crate) mod code;
pub(crate) mod device;
pub(crate) mod html;
pub(crate) mod limit;
pub(crate) mod service;

use std::{collections::HashMap, sync::Mutex, time::Instant};

use sentinel_auth::oauth::{self as forms, Kind};
use sentinel_core::{
    UnixMillis,
    auth::{Audience, Scopes},
};
use sentinel_protocol::{
    error::ErrorCode,
    limits::MAX_OAUTH_FORM_BYTES,
    oauth::{
        API_RESOURCE_SUFFIX, DEVICE_VERIFICATION_PATH, GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE,
        GRANT_REFRESH_TOKEN, MCP_RESOURCE_SUFFIX, Metadata, OAuthError, OAuthErrorCode,
        ProtectedResource, TokenResponse,
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
use limit::{Limiter, Rate};

/// Which admission budget an unauthenticated OAuth POST draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Budget {
    /// `/oauth/token`: refresh, code exchange and device polling.
    Token,
    /// `/oauth/revoke`.
    Revoke,
    /// `/oauth/device_authorization`: the revoke budget, plus the slow
    /// per-client device bucket.
    Device,
    /// RFC 7591 client registration.
    Registration,
    /// Client ID Metadata Document retrieval.
    Metadata,
}

/// Per client at the token endpoint: 10/s, burst 20.
const TOKEN_CLIENT: Rate = Rate::per_sec(10, 20);
/// Per client at revocation and device authorization: 5/s, burst 10.
const BEGIN_CLIENT: Rate = Rate::per_sec(5, 10);
/// The deployment-wide ceiling of each of those two budgets: 20/s, burst 40.
const CEILING: Rate = Rate::per_sec(20, 40);
/// New device requests per client: burst 8, then one per 30 s, so one
/// client holds at most about 28 of the deployment's pending requests over
/// a request's ten-minute life.
const DEVICE_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(30), 8);
const REGISTRATION_CLIENT: Rate = Rate::per_sec(2, 5);
const REGISTRATION_CEILING: Rate = Rate::per_sec(10, 20);
const METADATA_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(5), 4);
const METADATA_CEILING: Rate = Rate::per_sec(10, 20);

/// The authorization server's per-process state.
pub(crate) struct OAuthState {
    /// The issuer: `public_url`, or `http://{bound address}`.
    pub issuer: String,
    /// `scheme://host[:port]` of the issuer, for `Origin` checks.
    pub origin: String,
    /// The issuer's path (`/sentinel`), or empty.
    pub path: String,
    /// `{issuer}/api/v1`, the `resource` of `Audience::Api`.
    pub api_resource: String,
    /// `{issuer}/mcp`, the `resource` of `Audience::Mcp`.
    pub mcp_resource: String,
    /// The RFC 9728 §3.1 metadata URL of `api_resource`, named in every
    /// `401` challenge.
    pub resource_metadata: String,
    /// RFC 9728 metadata URL for the MCP resource.
    pub mcp_resource_metadata: String,
    /// `{issuer}/api/v1/login`, which the embedded sign-in posts to.
    pub login_url: String,
    /// `{issuer}/device`, which the device page's forms submit to.
    pub device_url: String,
    /// Keys consent and device-approval form tokens; random per process.
    pub form_key: [u8; 32],
    /// Admission of `/oauth/token`.
    pub token_budget: Mutex<Limiter>,
    /// Admission of `/oauth/revoke` and `/oauth/device_authorization`.
    pub begin_budget: Mutex<Limiter>,
    /// The per-client device-request bucket.
    pub device_budget: Mutex<Limiter>,
    /// Public DCR registration admission.
    pub registration_budget: Mutex<Limiter>,
    /// CIMD metadata fetch admission.
    pub metadata_budget: Mutex<Limiter>,
    /// Bounded in-memory CIMD cache.
    pub client_metadata: client::MetadataCache,
    /// Device-code digest -> (last poll, current interval in ms), bounded by
    /// `sentinel_store::oauth::MAX_PENDING_DEVICE`.
    pub device_polls: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
    /// Wrong user codes per account, bounded.
    pub user_code_failures: Mutex<device::WrongCodes>,
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
        let path = issuer[origin.len()..].to_owned();
        let now = Instant::now();
        Self {
            api_resource: format!("{issuer}{API_RESOURCE_SUFFIX}"),
            mcp_resource: format!("{issuer}{MCP_RESOURCE_SUFFIX}"),
            resource_metadata: format!(
                "{origin}/.well-known/oauth-protected-resource{path}{API_RESOURCE_SUFFIX}"
            ),
            mcp_resource_metadata: format!(
                "{origin}/.well-known/oauth-protected-resource{path}{MCP_RESOURCE_SUFFIX}"
            ),
            login_url: format!("{issuer}/api/v1/login"),
            device_url: format!("{issuer}{DEVICE_VERIFICATION_PATH}"),
            origin,
            path,
            issuer,
            form_key: sentinel_auth::cookie::form_key(),
            token_budget: Mutex::new(Limiter::new(TOKEN_CLIENT, Some(CEILING), now)),
            begin_budget: Mutex::new(Limiter::new(BEGIN_CLIENT, Some(CEILING), now)),
            device_budget: Mutex::new(Limiter::new(DEVICE_CLIENT, None, now)),
            registration_budget: Mutex::new(Limiter::new(
                REGISTRATION_CLIENT,
                Some(REGISTRATION_CEILING),
                now,
            )),
            metadata_budget: Mutex::new(Limiter::new(METADATA_CLIENT, Some(METADATA_CEILING), now)),
            client_metadata: client::MetadataCache::default(),
            device_polls: Mutex::new(HashMap::new()),
            user_code_failures: Mutex::new(device::WrongCodes::new()),
        }
    }

    pub(crate) fn resource(&self, audience: Audience) -> &str {
        match audience {
            Audience::Api => &self.api_resource,
            Audience::Mcp => &self.mcp_resource,
        }
    }

    pub(crate) fn resource_audience(&self, resource: &str) -> Option<Audience> {
        if resource == self.api_resource {
            Some(Audience::Api)
        } else if resource == self.mcp_resource {
            Some(Audience::Mcp)
        } else {
            None
        }
    }

    /// A request path as this server routes it: a proxy that forwards
    /// `/sentinel/device` unchanged for the issuer `…/sentinel` reaches
    /// `/device`. A path outside the issuer's is left alone.
    pub(crate) fn local_path<'a>(&self, path: &'a str) -> &'a str {
        if self.path.is_empty() {
            return path;
        }
        match path.strip_prefix(self.path.as_str()) {
            Some("") => "/",
            Some(rest) if rest.starts_with('/') => rest,
            _ => path,
        }
    }

    /// Whether `rest` (path segments after a well-known name) is the
    /// issuer's path followed by `suffix`: the RFC 8414 / 9728 location for
    /// a path-carrying issuer. With no issuer path, only `suffix` matches.
    fn issuer_path_then(&self, rest: &[&str], suffix: &[&str]) -> bool {
        let mut segments = self.path.split('/').filter(|s| !s.is_empty());
        let mut rest = rest.iter();
        for expected in segments.by_ref() {
            if rest.next() != Some(&expected) {
                return false;
            }
        }
        rest.copied().eq(suffix.iter().copied())
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
        // Issuer-relative (what the CLI asks for through a path-stripping
        // proxy), and the RFC location with the issuer path appended.
        ("GET", [".well-known", "oauth-authorization-server", rest @ ..])
            if rest.is_empty() || state.oauth.issuer_path_then(rest, &[]) =>
        {
            metadata(state)
        }
        ("GET", [".well-known", "oauth-protected-resource", rest @ ..])
            if rest == ["api", "v1"] || state.oauth.issuer_path_then(rest, &["api", "v1"]) =>
        {
            protected_resource(state, Audience::Api)
        }
        ("GET", [".well-known", "oauth-protected-resource", rest @ ..])
            if rest == ["mcp"] || state.oauth.issuer_path_then(rest, &["mcp"]) =>
        {
            protected_resource(state, Audience::Mcp)
        }
        ("POST", ["oauth", "token"]) => Ok(token(state, request)),
        ("POST", ["oauth", "register"]) => client::register(state, request),
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

fn protected_resource(state: &State, audience: Audience) -> Route {
    let scopes: &[&str] = match audience {
        Audience::Api => &Scopes::NAMES,
        Audience::Mcp => &Scopes::MCP_NAMES,
    };
    routes::ok(json!(ProtectedResource::for_resource(
        state.oauth.resource(audience),
        &state.oauth.issuer,
        scopes
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

/// Admit one unauthenticated OAuth POST from this request's client against
/// `budget` ([`limit`]).
pub(crate) fn admit(state: &State, request: &Request, budget: Budget) -> Result<(), Reply> {
    let client = limit::client_key(
        request.peer(),
        routes::header_value(request, "x-forwarded-for"),
    );
    let now = Instant::now();
    let take = |limiter: &Mutex<Limiter>| {
        limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit(client, now)
    };
    let oauth = &state.oauth;
    let admitted = match budget {
        Budget::Token => take(&oauth.token_budget),
        Budget::Revoke => take(&oauth.begin_budget),
        // The slow device bucket first: a client past it spends nothing
        // from the budget revocation shares.
        Budget::Device => take(&oauth.device_budget) && take(&oauth.begin_budget),
        Budget::Registration => take(&oauth.registration_budget),
        Budget::Metadata => take(&oauth.metadata_budget),
    };
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
/// `client_id`; `resource`, when given, must name a resource of this deployment.
fn token(state: &State, request: &mut Request) -> Reply {
    if let Err(reply) = admit(state, request, Budget::Token) {
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
    let Some(internal_id) = client::internal_id(client_id) else {
        return error(OAuthErrorCode::InvalidClient, "client_id is not valid");
    };
    let client = match state
        .store
        .read(|c| grants::client(c, internal_id.as_ref()))
    {
        Ok(client) => client,
        Err(sentinel_store::Error::NotFound) => {
            return error(OAuthErrorCode::InvalidClient, "unknown client");
        }
        Err(e) => return store_failure(e),
    };
    let resource = match form.get("resource") {
        None => None,
        Some(resource) => match state.oauth.resource_audience(resource) {
            Some(resource) => Some(resource),
            None => return error(OAuthErrorCode::InvalidTarget, "resource is not served here"),
        },
    };
    if client.resource != resource.unwrap_or(Audience::Api) {
        return error(
            OAuthErrorCode::InvalidTarget,
            "resource is not permitted for this client",
        );
    }
    match grant_type {
        GRANT_REFRESH_TOKEN => refresh(state, &client, &form, resource),
        GRANT_AUTHORIZATION_CODE => code::token(state, &client, &form, resource),
        GRANT_DEVICE_CODE => device::token(state, &client, &form, resource),
        _ => error(
            OAuthErrorCode::UnsupportedGrantType,
            "grant_type is not supported",
        ),
    }
}

/// The `refresh_token` grant: rotate, optionally narrowing `scope`.
fn refresh(state: &State, client: &Client, form: &Form, resource: Option<Audience>) -> Reply {
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
    match grants::refresh(&state.store, &client.id, &presented, narrow, resource, now) {
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
    if let Err(reply) = admit(state, request, Budget::Revoke) {
        return reply;
    }
    let form = match read_form(request) {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let Some(client_id) = form.get("client_id") else {
        return error(OAuthErrorCode::InvalidRequest, "client_id is required");
    };
    let Some(internal_id) = client::internal_id(client_id) else {
        return error(OAuthErrorCode::InvalidClient, "client_id is not valid");
    };
    let Some(token) = form.get("token") else {
        return error(OAuthErrorCode::InvalidRequest, "token is required");
    };
    let client = match state
        .store
        .read(|c| grants::client(c, internal_id.as_ref()))
    {
        Ok(client) => client,
        Err(sentinel_store::Error::NotFound) => {
            return error(OAuthErrorCode::InvalidClient, "unknown client");
        }
        Err(e) => return store_failure(e),
    };
    match grants::revoke_presented(&state.store, &client.id, token, UnixMillis::now()) {
        Ok(()) => Reply::Json(200, json!({}), no_cache()),
        Err(e) => store_failure(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_issuer_builds_every_url_from_the_issuer() {
        let s = OAuthState::new("https://ci.example/sentinel".into());
        assert_eq!(s.path, "/sentinel");
        assert_eq!(s.login_url, "https://ci.example/sentinel/api/v1/login");
        assert_eq!(s.device_url, "https://ci.example/sentinel/device");
        // RFC 9728 §3.1: the well-known segment goes before the path.
        assert_eq!(
            s.resource_metadata,
            "https://ci.example/.well-known/oauth-protected-resource/sentinel/api/v1"
        );
        assert_eq!(s.local_path("/sentinel/device"), "/device");
        assert_eq!(s.local_path("/sentinel"), "/");
        assert_eq!(s.local_path("/device"), "/device");
        assert_eq!(s.local_path("/sentinelx/device"), "/sentinelx/device");
        assert!(s.issuer_path_then(&["sentinel"], &[]));
        assert!(s.issuer_path_then(&["sentinel", "api", "v1"], &["api", "v1"]));
        assert!(!s.issuer_path_then(&["other"], &[]));
        assert!(!s.issuer_path_then(&["sentinel", "x"], &[]));

        let root = OAuthState::new("http://127.0.0.1:7080".into());
        assert_eq!(root.path, "");
        assert_eq!(
            root.resource_metadata,
            "http://127.0.0.1:7080/.well-known/oauth-protected-resource/api/v1"
        );
        assert_eq!(root.local_path("/device"), "/device");
        assert!(!root.issuer_path_then(&["sentinel"], &[]));
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
