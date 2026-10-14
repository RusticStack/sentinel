//! Sign-up by email, email verification and email invitations over the API.
//!
//! Public routes (`register`, `email/verify`, `email/resend`) take only a JSON
//! body with the deployment's own `Origin`, draw on an admission budget before
//! anything is read or hashed, and answer the **same** for a new address, an
//! address that is already registered and one that is unknown: whether an
//! address has an account is never an answer. What does differ is deployment
//! policy (registration closed, an invitation required), which says nothing
//! about the address.
//!
//! Nothing here sends mail. A route that needs a link written writes it to the
//! durable outbox in the same transaction that mints the token; the mail lane
//! delivers it. A deployment without SMTP answers `"verification": "operator"`
//! and the operator hands the link over from the host
//! (`sentinel admin account email-link`).

use sentinel_auth::{secret::Secret, token};
use sentinel_core::{
    InvitationId, UnixMillis,
    auth::{Role, Scopes},
};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{
    Error as StoreError, auth as authz, email,
    registration::{self, Accepted, Admission, Applicant, Refusal, Terms},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    JSON, Reply, Route, account::browser_session, err, header_value, id, identify, ok, parse,
    public_body_limit, store_error,
};
use crate::{State, auth, http::Request, oauth::Budget};

/// Largest body any route here takes: an address, a password, a token.
const MAX_BODY_BYTES: usize = 8 << 10;
/// Passwords longer than this are not hashed (the hash costs memory).
const MAX_PASSWORD_BYTES: usize = sentinel_auth::password::MAX_LEN;

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("POST", ["api", "v1", "register"]) => register(state, request),
        ("POST", ["api", "v1", "email", "verify"]) => verify(state, request),
        ("POST", ["api", "v1", "email", "resend"]) => resend_public(state, request),
        ("POST", ["api", "v1", "me", "email"]) => set_email(state, request),
        ("POST", ["api", "v1", "me", "email", "resend"]) => resend_own(state, request),
        ("POST", ["api", "v1", "invitations", "accept"]) => accept(state, request),
        ("GET", ["api", "v1", "tenants", slug, "invitations"]) => {
            list_invitations(state, request, slug)
        }
        ("POST", ["api", "v1", "tenants", slug, "invitations"]) => invite(state, request, slug),
        ("DELETE", ["api", "v1", "tenants", slug, "invitations", invitation]) => {
            revoke_invitation(state, request, slug, invitation)
        }
        _ => return None,
    })
}

/// How the person is told to expect their link: by mail, or from the
/// operator. Deployment-wide, so it says nothing about any address.
fn delivery_mode(state: &State) -> &'static str {
    let delivered =
        state.secret_key.is_some() && state.store.read(email::delivery_enabled).unwrap_or(false);
    if delivered { "email" } else { "operator" }
}

fn accepted(state: &State) -> Route {
    Ok(Reply::Json(
        202,
        json!({ "status": "accepted", "verification": delivery_mode(state) }),
        Vec::new(),
    ))
}

fn rate_limited() -> ApiError {
    err(ErrorCode::RateLimited, "too many requests; retry later")
        .with_detail("retry_after_ms", 60_000)
}

/// What every public JSON route checks before reading its body, as sign-in
/// does: an `application/json` body (a cross-site form cannot send one without
/// a preflight this server never grants), this deployment's own `Origin`
/// when the browser sends one, and an admission slot for the client.
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
        return Err(rate_limited());
    }
    public_body_limit(request, MAX_BODY_BYTES)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    /// An invitation secret (`sntl_…`), when the deployment requires one or
    /// the person was invited.
    #[serde(default)]
    invitation: Option<String>,
}

/// `POST /api/v1/register {email, password, display_name?, invitation?}`:
/// self-service sign-up by email, when the deployment's registration policy
/// allows it. `202` for every address (new, already registered, or unknown);
/// `403` when registration is closed, an invitation is required or the
/// invitation cannot be used. The account is a claim until the mailbox is
/// proved, and only a verified address signs in.
fn register(state: &State, request: &mut Request) -> Route {
    let bytes = public_json(state, request, Budget::Signup)?;
    let body: RegisterBody = parse(&bytes)?;
    if body.password.is_empty() || body.password.len() > MAX_PASSWORD_BYTES {
        return Err(err(ErrorCode::InvalidRequest, "invalid password"));
    }
    let address = email::normalize(&body.email).map_err(store_error)?;
    let invitation: Option<Secret> = match body.invitation.as_deref() {
        None | Some("") => None,
        // A malformed secret is an unusable invitation, as a wrong one is.
        Some(text) => Some(
            token::parse(text)
                .ok_or_else(|| err(ErrorCode::Forbidden, "the invitation cannot be used"))?,
        ),
    };
    let display_name = match body.display_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => email::local_part_of(&address).to_owned(),
    };
    if display_name.chars().count() > 128 || display_name.chars().any(char::is_control) {
        return Err(err(ErrorCode::InvalidRequest, "invalid display name"));
    }
    let outcome = registration::register_with(
        &state.store,
        Applicant::Email {
            display_name: &display_name,
            email: &address,
            password: body.password.as_bytes(),
        },
        invitation.as_ref(),
        state.secret_key.clone(),
        UnixMillis::now(),
    )
    .map_err(store_error)?;
    match outcome {
        // The same answer whether the address is new or already taken.
        Admission::Admitted(_)
        | Admission::Pending(_)
        | Admission::Refused(Refusal::AlreadyRegistered) => accepted(state),
        Admission::Refused(Refusal::RegistrationClosed) => {
            Err(err(ErrorCode::Forbidden, "registration is closed"))
        }
        Admission::Refused(Refusal::InvitationRequired) => Err(err(
            ErrorCode::Forbidden,
            "registration needs an invitation",
        )),
        Admission::Refused(Refusal::InvitationUnusable) => {
            Err(err(ErrorCode::Forbidden, "the invitation cannot be used"))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    token: String,
}

/// `POST /api/v1/email/verify {token}`: present the link's token. Single-use
/// and expiring; unknown, spent, expired and "another account verified it
/// first" are one `invalid_request`. Needs no session: the link is opened
/// from a mail client.
fn verify(state: &State, request: &mut Request) -> Route {
    let bytes = public_json(state, request, Budget::Mail)?;
    let body: TokenBody = parse(&bytes)?;
    let refused = || {
        err(
            ErrorCode::InvalidRequest,
            "the link is invalid or has expired",
        )
    };
    let secret = Secret::parse(body.token.trim()).ok_or_else(refused)?;
    match email::confirm(&state.store, &secret, UnixMillis::now()).map_err(store_error)? {
        email::Confirmation::Verified { joined, .. } => {
            ok(json!({ "verified": true, "joined": joined.is_some() }))
        }
        email::Confirmation::Refused => Err(refused()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailBody {
    email: String,
}

/// `POST /api/v1/email/resend {email}`: the "I never got it" form. Always
/// `202`: whether the address has a pending claim, how many links it was
/// already sent and whether its allowance is spent are not answers.
fn resend_public(state: &State, request: &mut Request) -> Route {
    let bytes = public_json(state, request, Budget::Mail)?;
    let body: EmailBody = parse(&bytes)?;
    let address = email::normalize(&body.email).map_err(store_error)?;
    let key = state.secret_key.clone();
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| email::resend_for_address(tx, key.as_deref(), &address, now))
        .map_err(store_error)?;
    accepted(state)
}

/// `POST /api/v1/me/email {email}` (browser session): add an address to the
/// account, or ask to change it. The new address is a claim until its link is
/// opened, and the old verified one stays until then. Replacing a **verified**
/// address needs a session that signed in or stepped up recently, since it
/// changes who can sign in. `202` whether or not another account holds the
/// address; `429` when this account's resend allowance is spent.
fn set_email(state: &State, request: &mut Request) -> Route {
    let (_, session, now) = browser_session(state, request, true)?;
    if !crate::oauth::admitted(state, request, Budget::Mail) {
        return Err(rate_limited());
    }
    let body: EmailBody = parse(&super::body_limit(request, MAX_BODY_BYTES)?)?;
    let address = email::normalize(&body.email).map_err(store_error)?;
    let user = session.user;
    let current = state
        .store
        .read(|c| email::account_email(c, user))
        .map_err(store_error)?;
    if let Some((held, true)) = &current
        && *held != address
        && !(session.signed_in_within(state.sessions, now)
            || session.stepped_up_within(state.sessions, now))
    {
        return Err(store_error(StoreError::StepUpRequired));
    }
    let key = state.secret_key.clone();
    state
        .store
        .writer()
        .write(move |tx| email::request(tx, key.as_deref(), user, &address, None, now))
        .map_err(store_error)?;
    // One answer for a claimed, suppressed or throttled address: nothing here
    // may reveal whether another account holds it.
    accepted(state)
}

/// `POST /api/v1/me/email/resend` (browser session): send the link again for
/// the address the account is proving. `409` when nothing is waiting, `429`
/// when the allowance is spent.
fn resend_own(state: &State, request: &mut Request) -> Route {
    let (_, session, now) = browser_session(state, request, true)?;
    if !crate::oauth::admitted(state, request, Budget::Mail) {
        return Err(rate_limited());
    }
    let user = session.user;
    let key = state.secret_key.clone();
    let requested = state
        .store
        .writer()
        .write(move |tx| email::resend(tx, key.as_deref(), user, now))
        .map_err(store_error)?;
    match requested {
        email::Requested::Throttled => Err(rate_limited()),
        email::Requested::Suppressed => Err(err(
            ErrorCode::Conflict,
            "no address is waiting for verification",
        )),
        _ => accepted(state),
    }
}

/// `POST /api/v1/invitations/accept {token}` (browser session): present an
/// invitation as the signed-in account. A link-form invitation joins at once.
/// One addressed to a mailbox needs that mailbox proved: `200 joined` when
/// the account already holds the address verified, otherwise `202
/// verification_sent` and the join happens when its link is opened. Unknown,
/// expired, spent, revoked or addressed elsewhere is one `not_found`.
fn accept(state: &State, request: &mut Request) -> Route {
    let (_, session, now) = browser_session(state, request, true)?;
    if !crate::oauth::admitted(state, request, Budget::Mail) {
        return Err(rate_limited());
    }
    let body: TokenBody = parse(&super::body_limit(request, MAX_BODY_BYTES)?)?;
    let unusable = || err(ErrorCode::NotFound, "invitation not found");
    let secret = token::parse(body.token.trim()).ok_or_else(unusable)?;
    let user = session.user;
    let outcome =
        registration::accept_invitation(&state.store, user, &secret, state.secret_key.clone(), now)
            .map_err(store_error)?;
    match outcome {
        Accepted::Joined(tenant) => {
            let slug = state
                .store
                .read(|c| registration::tenant_slug(c, tenant))
                .map_err(store_error)?;
            ok(json!({ "status": "joined", "tenant": slug }))
        }
        Accepted::Redeemed => ok(json!({ "status": "redeemed" })),
        Accepted::AlreadyMember => ok(json!({ "status": "already_member" })),
        Accepted::VerificationSent => Ok(Reply::Json(
            202,
            json!({ "status": "verification_sent", "verification": delivery_mode(state) }),
            Vec::new(),
        )),
        Accepted::Unusable => Err(unusable()),
    }
}

fn tenant_admin(
    state: &State,
    request: &Request,
    mutation: bool,
) -> Result<auth::Identity, ApiError> {
    let who = identify(state, request, mutation)?;
    auth::require_scope(&who, Scopes::TENANT_ADMIN)?;
    Ok(who)
}

fn parse_role(text: &str) -> Result<Role, ApiError> {
    match text {
        "reader" => Ok(Role::Reader),
        "operator" => Ok(Role::Operator),
        "admin" => Ok(Role::TenantAdmin),
        _ => Err(err(
            ErrorCode::InvalidRequest,
            "role must be reader, operator or admin",
        )),
    }
}

const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Reader => "reader",
        Role::Operator => "operator",
        Role::TenantAdmin => "admin",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteBody {
    email: String,
    /// Defaults to `reader`, the lowest role.
    #[serde(default)]
    role: Option<String>,
    /// Defaults to seven days; at most thirty.
    #[serde(default)]
    expires_in_secs: Option<u64>,
    /// Required (1..=100 characters) with fresh step-up when the caller
    /// reaches the organization by platform scope alone.
    #[serde(default)]
    reason: Option<String>,
}

/// Optional body of the invitation revocation: only the platform-override
/// `reason`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /api/v1/tenants/{slug}/invitations {email, role?, expires_in_secs?}`
/// (tenant admin): invite a person by email to an **app-created**
/// organization. The invitation joins them with `role` (default `reader`)
/// once their mailbox is proved. A GitHub-backed organization is refused:
/// its members come from GitHub. With mail delivery the message is queued
/// (`"delivery": "email"`); without it the response carries the one-time
/// `token` for the inviter to pass on (`"delivery": "link"`).
fn invite(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = tenant_admin(state, request, true)?;
    let body: InviteBody = parse(&super::body_limit(request, MAX_BODY_BYTES)?)?;
    let role = body.role.as_deref().map_or(Ok(Role::Reader), parse_role)?;
    let lifetime_ms = match body.expires_in_secs {
        None => registration::DEFAULT_INVITATION_MS,
        Some(secs) => i64::try_from(secs)
            .ok()
            .and_then(|s| s.checked_mul(1000))
            .filter(|ms| (1..=registration::MAX_INVITATION_MS).contains(ms))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    "expires_in_secs must be 1 second to 30 days",
                )
            })?,
    };
    let (slug, address) = (slug.to_owned(), body.email);
    let (principal, authority, reason) = (who.principal, who.authority(), body.reason);
    let key = state.secret_key.clone();
    let now = UnixMillis::now();
    let invited = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            // A platform administrator who is not an administrator-member
            // needs fresh step-up and an audited reason, as for any other
            // access-granting change.
            authority.require_tenant_access_change(tx, tenant, false, reason.as_deref())?;
            registration::invite_by_email(
                tx,
                authority,
                Terms {
                    tenant: Some(tenant),
                    role: Some(role),
                    identity: None,
                    lifetime_ms,
                },
                &address,
                key.as_deref(),
                now,
            )
        })
        .map_err(|e| match e {
            StoreError::InvalidInput("organization backed by GitHub") => err(
                ErrorCode::InvalidRequest,
                "this organization's members come from GitHub; email invitations do not apply",
            ),
            StoreError::Overloaded => rate_limited(),
            e => store_error(e),
        })?;
    let mut value = json!({
        "id": invited.invitation.id.to_string(),
        "role": role_name(role),
        "expires_ms": invited.invitation.expires.0,
        "delivery": if invited.queued { "email" } else { "link" },
    });
    if !invited.queued {
        value["token"] = Value::String(token::format(&invited.invitation.secret));
    }
    Ok(Reply::Json(201, value, Vec::new()))
}

/// `GET /api/v1/tenants/{slug}/invitations` (tenant admin): the tenant's
/// invitations, newest first. Metadata only: never a secret.
fn list_invitations(state: &State, request: &Request, slug: &str) -> Route {
    let who = tenant_admin(state, request, false)?;
    let (slug, authority, principal) = (slug.to_owned(), who.authority(), who.principal);
    let records = state
        .store
        .read(move |c| {
            let tenant = authz::member_tenant_by_slug(c, principal, &slug)?;
            registration::invitations(c, authority, Some(tenant), 100)
        })
        .map_err(store_error)?;
    let now = UnixMillis::now();
    ok(json!({
        "invitations": records.iter().map(|r| json!({
            "id": r.id.to_string(),
            "email": r.email,
            "role": r.role.map(role_name),
            "expires_ms": r.expires.0,
            "state": if r.redeemed { "redeemed" }
                else if r.revoked { "revoked" }
                else if r.expires <= now { "expired" }
                else { "pending" },
        })).collect::<Vec<_>>(),
    }))
}

/// `DELETE /api/v1/tenants/{slug}/invitations/{id}` (tenant admin): revoke an
/// unspent invitation of this tenant. Another tenant's is `not_found`.
fn revoke_invitation(state: &State, request: &mut Request, slug: &str, invitation: &str) -> Route {
    let who = tenant_admin(state, request, true)?;
    let invitation: InvitationId = id(invitation, "invitation")?;
    let bytes = super::body_limit(request, MAX_BODY_BYTES)?;
    let reason = if bytes.is_empty() {
        None
    } else {
        parse::<RevokeBody>(&bytes)?.reason
    };
    let (slug, authority, principal) = (slug.to_owned(), who.authority(), who.principal);
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            authority.require_tenant_access_change(tx, tenant, false, reason.as_deref())?;
            registration::revoke_tenant_invitation(tx, authority, tenant, invitation, now)
        })
        .map_err(store_error)?;
    ok(json!({ "revoked": true }))
}
