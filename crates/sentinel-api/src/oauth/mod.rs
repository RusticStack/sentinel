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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Budget {
    Token,
    Revoke,
    Device,
    Registration,
    Metadata,
    Login,
    Signup,
    Mail,
    Setup,
    SetupStatus,
    Organization,
    Enrollment,
    Bootstrap,
    HostPolicy,
    Redeem,
}

const TOKEN_CLIENT: Rate = Rate::per_sec(10, 20);
const BEGIN_CLIENT: Rate = Rate::per_sec(5, 10);
const CEILING: Rate = Rate::per_sec(20, 40);
const DEVICE_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(30), 8);
const REGISTRATION_CLIENT: Rate = Rate::per_sec(2, 5);
const REGISTRATION_CEILING: Rate = Rate::per_sec(10, 20);
const METADATA_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(5), 4);
const METADATA_CEILING: Rate = Rate::per_sec(10, 20);
const LOGIN_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(3), 10);
const LOGIN_CEILING: Rate = Rate::per_sec(10, 20);
const SIGNUP_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(20), 5);
const SIGNUP_CEILING: Rate = Rate::per_sec(2, 10);
const MAIL_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(15), 8);
const MAIL_CEILING: Rate = Rate::per_sec(5, 20);
const SETUP_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(10), 5);
const SETUP_CEILING: Rate = Rate::per_sec(1, 5);
const SETUP_STATUS_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(2), 10);
const SETUP_STATUS_CEILING: Rate = Rate::per_sec(20, 40);
const ORGANIZATION_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(10), 5);
const ORGANIZATION_CEILING: Rate = Rate::per_sec(2, 10);
// Per platform administrator, not per address: one enrollment per 6 s sustained, 5 in a burst; 1 a second overall.
const ENROLLMENT_ACTOR: Rate = Rate::new(std::time::Duration::from_secs(6), 5);
const ENROLLMENT_CEILING: Rate = Rate::per_sec(1, 5);
const BOOTSTRAP_ACTOR: Rate = Rate::new(std::time::Duration::from_secs(2), 10);
const BOOTSTRAP_CEILING: Rate = Rate::per_sec(2, 10);
// Host policy and uninstall requests, per platform administrator: 10 in a burst, then one a second.
const HOST_POLICY_ACTOR: Rate = Rate::new(std::time::Duration::from_secs(1), 10);
const HOST_POLICY_CEILING: Rate = Rate::per_sec(2, 10);
// An unauthenticated enrollment redemption: 5 attempts per address then one every 12 s, and 20 then one every 3 s
// overall, the same bounds as the link's own enrollment attempts. Each wrong secret may write an audit row.
const REDEEM_CLIENT: Rate = Rate::new(std::time::Duration::from_secs(12), 5);
const REDEEM_CEILING: Rate = Rate::new(std::time::Duration::from_secs(3), 20);

pub(crate) struct OAuthState {
    pub issuer: String,
    pub origin: String,
    pub path: String,
    pub api_resource: String,
    pub mcp_resource: String,
    pub resource_metadata: String,
    pub mcp_resource_metadata: String,
    pub login_url: String,
    pub device_url: String,
    pub form_key: [u8; 32],
    pub token_budget: Mutex<Limiter>,
    pub begin_budget: Mutex<Limiter>,
    pub device_budget: Mutex<Limiter>,
    pub registration_budget: Mutex<Limiter>,
    pub metadata_budget: Mutex<Limiter>,
    pub login_budget: Mutex<Limiter>,
    pub signup_budget: Mutex<Limiter>,
    pub mail_budget: Mutex<Limiter>,
    pub setup_budget: Mutex<Limiter>,
    pub setup_status_budget: Mutex<Limiter>,
    pub organization_budget: Mutex<Limiter>,
    pub enrollment_budget: Mutex<Limiter>,
    pub bootstrap_budget: Mutex<Limiter>,
    pub host_policy_budget: Mutex<Limiter>,
    pub redeem_budget: Mutex<Limiter>,
    pub client_metadata: client::MetadataCache,
    pub device_polls: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
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
            login_budget: Mutex::new(Limiter::new(LOGIN_CLIENT, Some(LOGIN_CEILING), now)),
            signup_budget: Mutex::new(Limiter::new(SIGNUP_CLIENT, Some(SIGNUP_CEILING), now)),
            mail_budget: Mutex::new(Limiter::new(MAIL_CLIENT, Some(MAIL_CEILING), now)),
            setup_budget: Mutex::new(Limiter::new(SETUP_CLIENT, Some(SETUP_CEILING), now)),
            setup_status_budget: Mutex::new(Limiter::new(
                SETUP_STATUS_CLIENT,
                Some(SETUP_STATUS_CEILING),
                now,
            )),
            organization_budget: Mutex::new(Limiter::new(
                ORGANIZATION_CLIENT,
                Some(ORGANIZATION_CEILING),
                now,
            )),
            enrollment_budget: Mutex::new(Limiter::new(
                ENROLLMENT_ACTOR,
                Some(ENROLLMENT_CEILING),
                now,
            )),
            bootstrap_budget: Mutex::new(Limiter::new(
                BOOTSTRAP_ACTOR,
                Some(BOOTSTRAP_CEILING),
                now,
            )),
            host_policy_budget: Mutex::new(Limiter::new(
                HOST_POLICY_ACTOR,
                Some(HOST_POLICY_CEILING),
                now,
            )),
            redeem_budget: Mutex::new(Limiter::new(REDEEM_CLIENT, Some(REDEEM_CEILING), now)),
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

// Registration members follow the live policy, so turning DCR off also stops advertising it.
fn metadata(state: &State) -> Route {
    let policy = state
        .store
        .read(grants::client_registration)
        .map_err(routes::store_error)?;
    routes::ok(json!(
        Metadata::for_issuer(&state.oauth.issuer, &Scopes::NAMES)
            .with_client_registration(policy.dynamic(), policy.metadata())
    ))
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

pub(crate) fn error(code: OAuthErrorCode, description: &str) -> Reply {
    error_status(code.http_status(), code, description)
}

pub(crate) fn error_status(status: u16, code: OAuthErrorCode, description: &str) -> Reply {
    Reply::Json(
        status,
        json!(OAuthError::new(code, description)),
        no_cache(),
    )
}

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

pub(crate) fn admit(state: &State, request: &Request, budget: Budget) -> Result<(), Reply> {
    if admitted(state, request, budget) {
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

pub(crate) fn admitted(state: &State, request: &Request, budget: Budget) -> bool {
    admitted_as(state, client_of(state, request), budget)
}

/// Like [`admitted`], for a budget kept per authenticated actor instead of per client address.
pub(crate) fn admitted_as(state: &State, client: u128, budget: Budget) -> bool {
    let now = Instant::now();
    let take = |limiter: &Mutex<Limiter>| {
        limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit(client, now)
    };
    let oauth = &state.oauth;
    match budget {
        Budget::Token => take(&oauth.token_budget),
        Budget::Revoke => take(&oauth.begin_budget),
        // The slow device bucket goes first, so a client past it spends nothing from the shared budget.
        Budget::Device => take(&oauth.device_budget) && take(&oauth.begin_budget),
        Budget::Registration => take(&oauth.registration_budget),
        Budget::Metadata => take(&oauth.metadata_budget),
        Budget::Login => take(&oauth.login_budget),
        Budget::Signup => take(&oauth.signup_budget),
        Budget::Mail => take(&oauth.mail_budget),
        Budget::Setup => take(&oauth.setup_budget),
        Budget::SetupStatus => take(&oauth.setup_status_budget),
        Budget::Organization => take(&oauth.organization_budget),
        Budget::Enrollment => take(&oauth.enrollment_budget),
        Budget::Bootstrap => take(&oauth.bootstrap_budget),
        Budget::HostPolicy => take(&oauth.host_policy_budget),
        Budget::Redeem => take(&oauth.redeem_budget),
    }
}

/// The key for per-client budgets and the sign-in lockout: the client a trusted proxy names, else the
/// connection ([`limit::connection_key`]).
pub(crate) fn client_of(state: &State, request: &Request) -> u128 {
    limit::connection_key(
        request.peer_addr(),
        routes::header_value(request, "x-forwarded-for"),
        &state.trusted_proxies,
    )
}

/// The key for a quota that reconnecting must not mint (client registrations): the proxy's address when
/// it names no client, so everything behind it shares the quota.
pub(crate) fn client_of_address(state: &State, request: &Request) -> u128 {
    limit::client_key(
        request.peer(),
        routes::header_value(request, "x-forwarded-for"),
        &state.trusted_proxies,
    )
}

pub(crate) struct Form(Vec<(String, String)>);

const MAX_FORM_PAIRS: usize = 32;

impl Form {
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

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

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
    let bytes = routes::public_body_limit(request, MAX_OAUTH_FORM_BYTES).map_err(|e| {
        if e.code == ErrorCode::PayloadTooLarge {
            error_status(413, OAuthErrorCode::InvalidRequest, "body too large")
        } else if e.code == ErrorCode::RateLimited {
            error_status(
                503,
                OAuthErrorCode::TemporarilyUnavailable,
                "too many requests; retry shortly",
            )
        } else {
            error(OAuthErrorCode::InvalidRequest, "unreadable body")
        }
    })?;
    Form::parse(&bytes).map_err(|e| Reply::Json(e.http_status(), json!(e), no_cache()))
}

// Bearer credentials never drive consent or device approval.
pub(crate) fn session(state: &State, request: &Request) -> Option<Identity> {
    routes::identify(state, request, false)
        .ok()
        .filter(|who| who.via == Via::Session)
}

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
