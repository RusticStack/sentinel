//! First-run setup and self-service organizations over the API.
//!
//! `GET /api/v1/setup` tells the web interface whether the first-run wizard is
//! open, and nothing else about the instance. `POST /api/v1/setup` completes
//! it with the one-time token the controller showed on the host (see
//! [`sentinel_store::setup`]): one commit creates the administrator, the
//! registration policy, the instance settings and the optional namespaces and
//! closes the bootstrap latch, then signs the administrator in. A second
//! factor is offered, not forced: the session the wizard ends with enrolls one
//! through the account routes like any other. `POST /api/v1/setup/smtp-test`
//! sends one test message through settings the wizard was given; it stores
//! nothing and its failure blocks nothing.
//!
//! `POST /api/v1/orgs` creates an organization for an approved account when
//! the deployment's `tenant_creation` policy allows it, and
//! `GET /api/v1/tenants/{slug}/settings` shows a namespace's kind and where
//! its membership comes from.

use sentinel_auth::{
    cookie,
    password::MAX_LEN as MAX_PASSWORD_BYTES,
    secret::{Secret, wipe_string},
};
use sentinel_core::{TenantId, UnixMillis, auth::Role, auth::Scopes};
use sentinel_mail::{Credentials, Failure, Mail, Smtp, Tls, Transport};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{
    Error as StoreError, email,
    registration::{Registration, TenantCreation},
    setup::{self, Setup},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    JSON, Reply, Route, account::browser_session, err, header, header_value, identify, ok, parse,
    public_body_limit, store_error,
};
use crate::{State, auth, http::Request, oauth::Budget};

/// Largest body any route here takes.
const MAX_BODY_BYTES: usize = 8 << 10;
/// What a refusal says about the setup token: one message for wrong, expired,
/// absent and locked-out.
const TOKEN_REFUSED: &str = "setup token refused";

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", ["api", "v1", "setup"]) => status(state),
        ("POST", ["api", "v1", "setup"]) => complete(state, request),
        ("POST", ["api", "v1", "setup", "smtp-test"]) => smtp_test(state, request),
        ("POST", ["api", "v1", "orgs"]) => create_organization(state, request),
        ("GET", ["api", "v1", "tenants", slug, "settings"]) => settings(state, request, slug),
        _ => return None,
    })
}

/// The wizard's refusals: a token problem is one `forbidden`, a closed setup
/// is `not_found`, anything else is the store's usual mapping.
fn setup_error(error: StoreError) -> ApiError {
    match error {
        StoreError::Forbidden => err(ErrorCode::Forbidden, TOKEN_REFUSED),
        StoreError::NotFound => err(ErrorCode::NotFound, "setup is not available"),
        StoreError::Conflict => err(ErrorCode::Conflict, "that address or name is already taken"),
        other => store_error(other),
    }
}

/// `GET /api/v1/setup`: `{ "open": bool }`. Public and uncached. Closed is
/// permanent (the latch never reopens), so once seen it is remembered and
/// the question never touches the store again.
fn status(state: &State) -> Route {
    use std::sync::atomic::Ordering;
    let open = if state.setup_closed.load(Ordering::Acquire) {
        false
    } else {
        let open = state.store.read(setup::is_open).map_err(store_error)?;
        if !open {
            state.setup_closed.store(true, Ordering::Release);
        }
        open
    };
    Ok(Reply::Json(
        200,
        json!({ "open": open }),
        vec![header("cache-control", "no-store")],
    ))
}

/// The browser-facing checks every public JSON route makes before a body is
/// read: a JSON content type, this deployment's own `Origin`, and an
/// admission slot for the client.
fn public_json(state: &State, request: &mut Request, budget: Budget) -> Result<Vec<u8>, ApiError> {
    let json_body = header_value(request, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(JSON))
    });
    if !json_body {
        return Err(err(
            ErrorCode::InvalidRequest,
            "this route takes an application/json body",
        ));
    }
    if header_value(request, "origin").is_some_and(|origin| origin != state.oauth.origin) {
        return Err(err(
            ErrorCode::Forbidden,
            "requests from another site are refused",
        ));
    }
    if !crate::oauth::admitted(state, request, budget) {
        return Err(
            err(ErrorCode::RateLimited, "too many requests; retry later")
                .with_detail("retry_after_ms", 10_000),
        );
    }
    public_body_limit(request, MAX_BODY_BYTES)
}

/// A presented setup token, or the one refusal. A token of the wrong shape
/// is refused without a store visit and without counting against the lock:
/// the lock bounds guesses of a well-formed token.
fn token_of(text: &str) -> Result<Secret, ApiError> {
    Secret::parse(text.trim()).ok_or_else(|| err(ErrorCode::Forbidden, TOKEN_REFUSED))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    token: String,
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    /// `closed`, `invite-only` or `approval-required`.
    registration: String,
    /// `super-admin-only` (default) or `approved-users`.
    #[serde(default)]
    tenant_creation: Option<String>,
    instance_name: String,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    personal_namespace: Option<String>,
    #[serde(default)]
    organization: Option<String>,
}

fn registration_of(text: &str) -> Result<Registration, ApiError> {
    match text {
        "closed" => Ok(Registration::Closed),
        "invite-only" => Ok(Registration::InviteOnly),
        "approval-required" => Ok(Registration::ApprovalRequired),
        _ => Err(err(ErrorCode::InvalidRequest, "invalid registration")),
    }
}

fn tenant_creation_of(text: Option<&str>) -> Result<TenantCreation, ApiError> {
    match text {
        None | Some("super-admin-only") => Ok(TenantCreation::SuperAdminOnly),
        Some("approved-users") => Ok(TenantCreation::ApprovedUsers),
        Some(_) => Err(err(ErrorCode::InvalidRequest, "invalid tenant_creation")),
    }
}

/// `POST /api/v1/setup`: complete first-run setup with the host's token.
/// `201` with the administrator's session cookie and CSRF secret; `403` for a
/// token that is wrong, expired or locked out; `404` once setup is closed;
/// `409` for a taken address or name; `400` for a bad field. Nothing is
/// created unless everything is.
fn complete(state: &State, request: &mut Request) -> Route {
    let bytes = public_json(state, request, Budget::Setup)?;
    let mut body: SetupBody = parse(&bytes)?;
    // Wiped on every path out, whatever the outcome.
    let outcome = complete_with(state, &body);
    wipe_string(&mut body.password);
    outcome
}

fn complete_with(state: &State, body: &SetupBody) -> Route {
    if body.password.is_empty() || body.password.len() > MAX_PASSWORD_BYTES {
        return Err(err(ErrorCode::InvalidRequest, "invalid password"));
    }
    let token = token_of(&body.token)?;
    let registration = registration_of(&body.registration)?;
    let tenant_creation = tenant_creation_of(body.tenant_creation.as_deref())?;
    let address = email::normalize(&body.email).map_err(store_error)?;
    let display_name = match body.display_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => email::local_part_of(&address).to_owned(),
    };
    let completed = setup::complete(
        &state.store,
        &Setup {
            token: &token,
            email: &address,
            display_name: &display_name,
            password: body.password.as_bytes(),
            registration,
            tenant_creation,
            instance_name: &body.instance_name,
            base_url: body.base_url.as_deref(),
            personal_namespace: body.personal_namespace.as_deref(),
            organization: body.organization.as_deref(),
        },
        state.sessions,
        UnixMillis::now(),
    )
    .map_err(setup_error)?;
    state
        .setup_closed
        .store(true, std::sync::atomic::Ordering::Release);
    let issued = completed.issued;
    let mut csrf = String::new();
    issued.csrf.expose(&mut csrf);
    let set_cookie = cookie::issue(cookie::SESSION_COOKIE, &issued.session, issued.max_age_secs);
    Ok(Reply::Json(
        201,
        json!({
            "user": issued.user.to_string(),
            "csrf": csrf,
            "organization": body.organization.as_ref().filter(|_| completed.organization.is_some()),
            "personal_namespace": body.personal_namespace.as_ref().filter(|_| completed.personal.is_some()),
            // Offered, not forced: enroll with `POST /mfa/enroll` from this
            // session.
            "mfa_enrollment": "available",
        }),
        vec![
            header("set-cookie", &set_cookie),
            header("cache-control", "no-store"),
        ],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpBody {
    token: String,
    host: String,
    port: u16,
    /// `starttls` (default), `implicit` or `none` (a relay on this host).
    #[serde(default)]
    tls: Option<String>,
    from: String,
    /// Where the test message goes.
    to: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// The most of a relay's refusal a client is shown.
const MAX_REASON_CHARS: usize = 200;

/// `POST /api/v1/setup/smtp-test`: send one test message through the given
/// relay settings. Gated by the setup token (a wrong one counts against the
/// same lock), bounded by one outbound slot and the client's own timeouts,
/// and never stored. Always `200` for a judged request: `{ "sent": true }`, or
/// `{ "sent": false, "failure": "invalid_settings" | "transient" |
/// "permanent", "reason": … }`: a failed test blocks nothing.
fn smtp_test(state: &State, request: &mut Request) -> Route {
    let bytes = public_json(state, request, Budget::Setup)?;
    let mut body: SmtpBody = parse(&bytes)?;
    let outcome = smtp_test_with(state, &mut body);
    if let Some(password) = body.password.as_mut() {
        wipe_string(password);
    }
    outcome
}

fn smtp_test_with(state: &State, body: &mut SmtpBody) -> Route {
    let token = token_of(&body.token)?;
    setup::verify(&state.store, &token, UnixMillis::now()).map_err(setup_error)?;
    let not_sent = |failure: &str, reason: String| {
        ok(json!({ "sent": false, "failure": failure, "reason": reason }))
    };
    let Some(_slot) = state.setup_mail.take() else {
        return Err(err(ErrorCode::RateLimited, "busy; retry shortly"));
    };
    let tls = match body.tls.as_deref() {
        None => Tls::StartTls,
        Some(name) => match Tls::parse(name) {
            Some(tls) => tls,
            None => {
                return not_sent(
                    "invalid_settings",
                    "tls must be starttls, implicit or none".into(),
                );
            }
        },
    };
    let credentials = match (body.username.take(), body.password.take()) {
        (None, None) => None,
        (Some(username), Some(password)) => {
            match Credentials::new(username, password.into_bytes()) {
                Ok(credentials) => Some(credentials),
                Err(reason) => return not_sent("invalid_settings", reason),
            }
        }
        _ => {
            return not_sent(
                "invalid_settings",
                "give both username and password, or neither".into(),
            );
        }
    };
    let to = match email::normalize(&body.to) {
        Ok(to) => to,
        Err(_) => return not_sent("invalid_settings", "to must be a plain address".into()),
    };
    let config = match sentinel_mail::Config::new(
        body.host.clone(),
        body.port,
        tls,
        credentials,
        &body.from,
    ) {
        Ok(config) => config,
        Err(reason) => return not_sent("invalid_settings", reason),
    };
    let mut smtp = match Smtp::new(config) {
        Ok(smtp) => smtp,
        Err(reason) => return not_sent("invalid_settings", reason),
    };
    let sent = smtp.send(&Mail {
        id: sentinel_core::MailId::new(),
        to: &to,
        subject: "Sentinel setup: test message",
        body: "This is a test message from your Sentinel setup. If you can read it, \
               mail delivery works with these settings.\r\n",
        now: UnixMillis::now(),
    });
    match sent {
        Ok(()) => ok(json!({ "sent": true })),
        Err(Failure::Transient(reason)) => not_sent("transient", brief(&reason)),
        Err(Failure::Permanent(reason)) => not_sent("permanent", brief(&reason)),
    }
}

fn brief(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgBody {
    slug: String,
}

/// `POST /api/v1/orgs {slug}`: create an organization the caller will
/// administer. A browser session only (it changes what the account owns).
/// `201 {slug, role: "admin"}`; `403` unless the deployment's
/// `tenant_creation` is `approved-users` and the account is approved (a
/// platform administrator always may); `400` for a reserved or malformed
/// name; `409` for a taken one; `429` for the per-client budget and, as
/// `quota_exceeded`, the account's own limit of
/// [`sentinel_store::organizations::MAX_SELF_SERVICE_ORGS`] organizations or
/// [`sentinel_store::organizations::SELF_SERVICE_PER_HOUR`] an hour. Whether
/// a name is taken is inherently what `409` says; the budget bounds probing.
fn create_organization(state: &State, request: &mut Request) -> Route {
    if !crate::oauth::admitted(state, request, Budget::Organization) {
        return Err(
            err(ErrorCode::RateLimited, "too many requests; retry later")
                .with_detail("retry_after_ms", 10_000),
        );
    }
    let (_, session, now) = browser_session(state, request, true)?;
    let bytes = super::body_limit(request, 1 << 10)?;
    let body: OrgBody = parse(&bytes)?;
    let principal = session.principal();
    let tenant = TenantId::new();
    let slug = body.slug.clone();
    state
        .store
        .writer()
        .write(move |tx| {
            sentinel_store::organizations::create_self_service(tx, principal, tenant, &slug, now)
        })
        .map_err(|error| match error {
            StoreError::QuotaExceeded => err(
                ErrorCode::QuotaExceeded,
                "organization limit reached; retry later or ask an administrator",
            ),
            StoreError::Conflict => err(ErrorCode::Conflict, "that name is taken"),
            StoreError::Forbidden => err(
                ErrorCode::Forbidden,
                "creating organizations is not enabled for this account",
            ),
            other => store_error(other),
        })?;
    Ok(Reply::Json(
        201,
        json!({ "slug": body.slug, "role": "admin" }),
        Vec::new(),
    ))
}

/// `GET /api/v1/tenants/{slug}/settings`: a namespace's kind (`personal` or
/// `organization`), where its membership comes from (`app`: invitations,
/// administrators and the operator's auto-join rules; `github`: GitHub
/// confirms it) and whether a GitHub App installation is bound; for a
/// GitHub-backed organization, the caller's own `github_sync`. For an
/// administrator, also whether email-domain auto-join applies (read-only: the
/// rule is the operator's `SENTINEL_AUTO_JOIN_DOMAINS`) and the domains that
/// name this organization. A namespace the caller cannot see is `not_found`,
/// like every slug route.
fn settings(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let principal = who.principal;
    let found = state
        .store
        .read(|c| sentinel_store::organizations::settings(c, principal, slug))
        .map_err(store_error)?;
    let administers = found.role == Some(Role::TenantAdmin) || who.super_admin;
    let github = found.github_backed || found.installation_bound;
    let mut value = json!({
        "slug": found.slug,
        "kind": if found.personal { "personal" } else { "organization" },
        "membership": if found.github_backed { "github" } else { "app" },
        "github_installation": found.installation_bound,
        "role": found.role.map(|role| match role {
            Role::Reader => "reader",
            Role::Operator => "operator",
            Role::TenantAdmin => "admin",
        }),
        "created_ms": found.created_ms,
    });
    if found.github_backed
        && let Value::Object(map) = &mut value
    {
        // The caller's own standing with GitHub, never anyone else's: when
        // GitHub last confirmed it, whether a check is due now, and how many
        // passes in a row GitHub could not answer (unknown keeps what exists
        // for the grace period and grants nothing new).
        let now = UnixMillis::now().0;
        map.insert(
            "github_sync".into(),
            json!({
                "confirmed_ms": found.github_confirmed_ms,
                "check_due": found.github_check_next_ms.is_some_and(|next| next <= now),
                "unanswered": found.github_check_failures.unwrap_or(0),
            }),
        );
    }
    if administers && let Value::Object(map) = &mut value {
        let domains: Vec<&str> = state
            .auto_join
            .iter()
            .filter(|rule| rule.organization == found.slug)
            .map(|rule| rule.domain.as_str())
            .collect();
        map.insert(
            "auto_join".into(),
            json!({
                // Never for a personal namespace or a GitHub-backed
                // organization, whatever the rules say.
                "applies": !found.personal && !github && !domains.is_empty(),
                "domains": domains,
            }),
        );
    }
    ok(value)
}
