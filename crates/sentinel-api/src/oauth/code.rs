//! The authorization-code flow over HTTP (O01): `GET`/`POST
//! /oauth/authorize` (sign-in, consent, approve or deny, `303` back to the
//! client) and the `authorization_code` branch of the token endpoint.
//!
//! Consent is stateless. `GET` validates the request and renders the page
//! with every parameter in hidden fields plus a form token keyed to the
//! session's CSRF digest; `POST` re-validates all of it from the body,
//! checks the form token and, when present, `Origin`, and only then writes
//! (the code on approval, an audit row on denial).
//!
//! Until the client and its redirect URI are established nothing is sent
//! back to the client: an unknown client or an unacceptable redirect gets
//! an error page with no `location`. Every later refusal is an RFC 6749
//! §4.1.2.1 redirect carrying `error`, `state` and `iss` (RFC 9207).

mod consent;

use sentinel_auth::{
    cookie,
    oauth::{self as forms, Kind, pkce},
};
use sentinel_core::{
    TenantId, UnixMillis,
    auth::{Audience, Scopes},
};
use sentinel_protocol::oauth::OAuthErrorCode;
use sentinel_store::oauth::{
    self as grants, Client,
    code::{self as codes, Approval, CodeError},
};

use super::{Form, html};
use crate::{
    State,
    auth::Identity,
    http::Request,
    routes::{self, Reply, Route},
};

/// Longest `state` accepted, in bytes.
const MAX_STATE_BYTES: usize = 512;

/// `GET` renders sign-in or consent; `POST` records the decision.
pub(crate) fn authorize(state: &State, request: &mut Request, method: &str, query: &str) -> Route {
    Ok(match method {
        "POST" => decide(state, request),
        _ => show(state, request, query),
    })
}

/// A validated authorization request. Borrowed from the query or form.
pub(super) struct Params<'a> {
    pub client: Client,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub scopes: Scopes,
    pub resource: Option<&'a str>,
}

fn show(state: &State, request: &Request, query: &str) -> Reply {
    let Ok(form) = Form::parse(query.as_bytes()) else {
        return html::error_page(400, "The authorization request is malformed.");
    };
    let params = match validate(state, &form) {
        Ok(params) => params,
        Err(reply) => return reply,
    };
    let Some((who, csrf)) = signed_in(state, request) else {
        let mut message = String::with_capacity(64 + params.client.name.len());
        message.push_str("Sign in to continue to ");
        message.push_str(&params.client.name);
        message.push('.');
        return html::sign_in_page(&state.oauth.login_url, "Sign in to Sentinel", &message);
    };
    if let Err(reply) = eligible(state, &params, &who) {
        return reply;
    }
    let token = cookie::form_token(&state.oauth.form_key, &csrf);
    consent::page(state, &params, &who, &token, None)
}

fn decide(state: &State, request: &mut Request) -> Reply {
    // A cross-site POST cannot carry the session cookie (SameSite=Strict),
    // but a present Origin that is not ours is refused outright.
    if routes::header_value(request, "origin").is_some_and(|o| o != state.oauth.origin) {
        return html::error_page(403, "This form was submitted from another site.");
    }
    let Ok(form) = super::read_form(request) else {
        return html::error_page(400, "The consent form is malformed.");
    };
    let Some((who, csrf)) = signed_in(state, request) else {
        return html::error_page(
            401,
            "Your session has ended. Start signing in again from the application.",
        );
    };
    if !cookie::form_token_accepted(&state.oauth.form_key, &csrf, form.get("form_token")) {
        return html::error_page(
            403,
            "This consent form has expired. Start signing in again from the application.",
        );
    }
    let params = match validate(state, &form) {
        Ok(params) => params,
        Err(reply) => return reply,
    };
    if let Err(reply) = eligible(state, &params, &who) {
        return reply;
    }
    match form.get("decision") {
        Some("approve") => approve(state, &form, &params, &who),
        Some("deny") => match codes::deny(&state.store, &params.client.id, who.user) {
            Ok(()) => refuse(
                state,
                &params,
                OAuthErrorCode::AccessDenied,
                "the account declined the request",
            ),
            Err(e) => unavailable(&e),
        },
        _ => html::error_page(400, "Choose approve or deny."),
    }
}

fn approve(state: &State, form: &Form, params: &Params<'_>, who: &Identity) -> Reply {
    let tenant = match form.get("tenant").map(str::parse::<TenantId>) {
        None => None,
        Some(Ok(tenant)) => Some(tenant),
        Some(Err(_)) => return html::error_page(400, "The selected tenant is malformed."),
    };
    let again = |notice: &str| {
        let token = form.get("form_token").unwrap_or_default();
        consent::page_status(state, params, who, token, Some(notice), 400)
    };
    let repo = match (form.get("repo"), tenant) {
        (None, _) => None,
        (Some(_), None) => return again("Choose a tenant to limit access to one repository."),
        (Some(name), Some(tenant)) => {
            match state
                .store
                .read(|c| codes::repo_named(c, who.user, tenant, name))
            {
                Ok(repo) => Some(repo),
                Err(sentinel_store::Error::NotFound) => {
                    return again("That tenant has no repository of that name.");
                }
                Err(e) => return unavailable(&e),
            }
        }
    };
    let approval = Approval {
        client_id: &params.client.id,
        redirect_uri: params.redirect_uri,
        code_challenge: params.code_challenge,
        user: who.user,
        scopes: params.scopes,
        tenant,
        repo,
        audience: Audience::Api,
    };
    match codes::approve(&state.store, &approval, UnixMillis::now()) {
        Ok(code) => {
            let code = forms::format(Kind::Code, &code);
            back(
                params.redirect_uri,
                &[
                    ("code", code.as_str()),
                    ("state", params.state),
                    ("iss", &state.oauth.issuer),
                ],
            )
        }
        Err(sentinel_store::Error::Forbidden) => refuse(
            state,
            params,
            OAuthErrorCode::AccessDenied,
            "the account cannot grant this access",
        ),
        Err(sentinel_store::Error::InvalidInput(_) | sentinel_store::Error::NotFound) => refuse(
            state,
            params,
            OAuthErrorCode::InvalidRequest,
            "the request can no longer be approved",
        ),
        Err(e) => unavailable(&e),
    }
}

/// The browser session behind this request and its CSRF digest.
fn signed_in(
    state: &State,
    request: &Request,
) -> Option<(Identity, sentinel_auth::secret::Digest)> {
    let who = super::session(state, request)?;
    let csrf = who.csrf?;
    Some((who, csrf))
}

/// Validate an authorization request (query or re-posted form). Refusals
/// before the redirect is trusted are pages; later ones are redirects.
fn validate<'a>(state: &State, form: &'a Form) -> Result<Params<'a>, Reply> {
    let Some(client_id) = form.get("client_id") else {
        return Err(html::error_page(400, "The request names no client."));
    };
    let Some(redirect_uri) = form.get("redirect_uri") else {
        return Err(html::error_page(400, "The request names no redirect URI."));
    };
    let looked_up = state.store.read(|c| {
        let client = grants::client(c, client_id)?;
        let allowed = grants::redirect_allowed(c, &client, redirect_uri)?;
        Ok((client, allowed))
    });
    let client = match looked_up {
        Ok((client, true)) => client,
        Ok((_, false)) => {
            return Err(html::error_page(
                400,
                "The redirect URI is not registered for this client.",
            ));
        }
        Err(sentinel_store::Error::NotFound) => {
            return Err(html::error_page(400, "The client is not registered."));
        }
        Err(e) => return Err(unavailable(&e)),
    };
    // From here on the client and its redirect are trusted with an answer.
    let state_param = form.get("state").filter(|s| s.len() <= MAX_STATE_BYTES);
    let fail = |code: OAuthErrorCode, description: &str| {
        Err(redirect_error(
            state,
            redirect_uri,
            state_param,
            code,
            description,
        ))
    };
    match form.get("response_type") {
        Some("code") => {}
        Some(_) => {
            return fail(
                OAuthErrorCode::UnsupportedResponseType,
                "response_type must be code",
            );
        }
        None => return fail(OAuthErrorCode::InvalidRequest, "response_type is required"),
    }
    let Some(state_value) = state_param else {
        return fail(
            OAuthErrorCode::InvalidRequest,
            "state is required (at most 512 bytes)",
        );
    };
    if form.get("code_challenge_method") != Some("S256") {
        return fail(
            OAuthErrorCode::InvalidRequest,
            "PKCE with code_challenge_method=S256 is required",
        );
    }
    let Some(code_challenge) = form
        .get("code_challenge")
        .filter(|c| pkce::challenge_valid(c))
    else {
        return fail(
            OAuthErrorCode::InvalidRequest,
            "code_challenge must be an S256 challenge",
        );
    };
    let scopes = match form.get("scope") {
        None => Scopes::CLI_DEFAULT.intersect(client.max_scopes),
        Some(text) => match Scopes::parse(text) {
            Ok(scopes) => scopes,
            Err(_) => return fail(OAuthErrorCode::InvalidScope, "unknown scope"),
        },
    };
    if scopes.is_empty() || !client.max_scopes.contains(scopes) {
        return fail(
            OAuthErrorCode::InvalidScope,
            "scope is empty or beyond what this client may hold",
        );
    }
    let resource = form.get("resource");
    if resource.is_some_and(|r| r != state.oauth.api_resource) {
        return fail(
            OAuthErrorCode::InvalidTarget,
            "resource must be this deployment's API",
        );
    }
    Ok(Params {
        client,
        redirect_uri,
        state: state_value,
        code_challenge,
        scopes,
        resource,
    })
}

/// What only the signed-in account decides: `platform:admin` needs a super
/// admin. Membership and repository terms are checked at approval.
fn eligible(state: &State, params: &Params<'_>, who: &Identity) -> Result<(), Reply> {
    if params.scopes.contains(Scopes::PLATFORM_ADMIN) && !who.super_admin {
        return Err(refuse(
            state,
            params,
            OAuthErrorCode::InvalidScope,
            "platform:admin requires a super admin",
        ));
    }
    Ok(())
}

fn refuse(state: &State, params: &Params<'_>, code: OAuthErrorCode, description: &str) -> Reply {
    redirect_error(
        state,
        params.redirect_uri,
        Some(params.state),
        code,
        description,
    )
}

/// An RFC 6749 §4.1.2.1 error redirect with RFC 9207 `iss`.
fn redirect_error(
    state: &State,
    redirect_uri: &str,
    state_param: Option<&str>,
    code: OAuthErrorCode,
    description: &str,
) -> Reply {
    let mut pairs = [
        ("error", code.as_str()),
        ("error_description", description),
        ("iss", &state.oauth.issuer),
        ("state", ""),
    ];
    let used = match state_param {
        Some(value) => {
            pairs[3].1 = value;
            4
        }
        None => 3,
    };
    back(redirect_uri, &pairs[..used])
}

/// `303` to the client's redirect URI with `pairs` appended to its query.
fn back(redirect_uri: &str, pairs: &[(&str, &str)]) -> Reply {
    let mut url = String::with_capacity(redirect_uri.len() + 192);
    url.push_str(redirect_uri);
    url.push(if redirect_uri.contains('?') { '&' } else { '?' });
    let start = url.len();
    let url = form_urlencoded::Serializer::for_suffix(url, start)
        .extend_pairs(pairs)
        .finish();
    html::redirect(&url)
}

/// A store failure while rendering or deciding: busy is 503, else 500.
fn unavailable(e: &sentinel_store::Error) -> Reply {
    match e {
        sentinel_store::Error::WriterUnavailable
        | sentinel_store::Error::Overloaded
        | sentinel_store::Error::WriteAmbiguous => {
            html::error_page(503, "Sentinel is busy. Try again in a moment.")
        }
        _ => html::error_page(500, "Sentinel could not complete this request."),
    }
}

/// `grant_type=authorization_code` at the token endpoint. `client` is the
/// looked-up `client_id`; `resource` has already been checked. A client
/// could only have obtained a code through a redirect it may use, so there
/// is no separate capability flag: the code binds the client.
pub(crate) fn token(state: &State, client: &Client, form: &Form) -> Reply {
    let (Some(code), Some(redirect_uri), Some(verifier)) = (
        form.get("code"),
        form.get("redirect_uri"),
        form.get("code_verifier"),
    ) else {
        return super::error(
            OAuthErrorCode::InvalidRequest,
            "code, redirect_uri and code_verifier are required",
        );
    };
    let Some(code) = forms::parse(Kind::Code, code) else {
        return super::error(OAuthErrorCode::InvalidGrant, "code is not valid");
    };
    let now = UnixMillis::now();
    match codes::exchange(&state.store, &client.id, &code, redirect_uri, verifier, now) {
        Ok(minted) => super::token_reply(&minted, now),
        Err(CodeError::Invalid | CodeError::Replay) => {
            super::error(OAuthErrorCode::InvalidGrant, "code is not valid")
        }
        Err(CodeError::Store(e)) => super::store_failure(e),
    }
}
