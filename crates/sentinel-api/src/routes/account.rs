//! An account's own security over the API: second-factor enrollment, recovery
//! codes, password change and the state the web interface shows for them.
//!
//! Every route here is for a **browser session** with its CSRF header. A bearer
//! credential or OAuth token — whatever scopes it carries — cannot enroll a
//! factor, reissue codes or change a password: those change who can
//! authenticate, which only the person at a signed-in browser may do.
//!
//! Proof rules, in one place:
//! - Starting an enrollment needs the account's password when it has one, and
//!   otherwise (a GitHub-only account) a session issued within the step-up
//!   window. A stolen cookie alone enrolls nothing on a password account, and
//!   a GitHub-only account is never locked out of its first factor.
//! - Confirming needs the code from the app. It spends the code's time step, so
//!   the same code cannot step up afterwards.
//! - Reissuing recovery codes needs a fresh step-up.
//! - Changing the password needs the current password and, with a second
//!   factor enrolled, a fresh step-up; every session and grant of the account
//!   ends with it.
//!
//! Wrong proofs are one `forbidden` whatever was wrong. Anything that hashes a
//! password draws on the sign-in admission budget first.

use sentinel_auth::cookie;
use sentinel_core::UnixMillis;
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{
    Error as StoreError,
    auth::Authority,
    local_auth,
    local_auth::Session,
    mfa::{self, Proof},
    sign_in,
};
use serde::Deserialize;
use serde_json::json;

use super::{
    Reply, Route, body_limit, err, header, header_value, identify, ok, parse, store_error,
};
use crate::{State, auth::Via, http::Request};

/// Issuer shown by authenticator apps next to the account label.
const ISSUER: &str = "Sentinel";
/// A code from an app is six digits and a recovery code about a dozen
/// characters; nothing longer is a code.
const MAX_CODE_BYTES: usize = 64;
/// Largest body any route here takes: two passwords at most.
const MAX_BODY_BYTES: usize = 4 << 10;

/// Route one request; `None` when the path is not one of these.
pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", ["api", "v1", "me", "security"]) => security(state, request),
        ("POST", ["api", "v1", "mfa", "enroll"]) => enroll(state, request),
        ("POST", ["api", "v1", "mfa", "enroll", "confirm"]) => confirm(state, request),
        ("POST", ["api", "v1", "mfa", "recovery-codes"]) => recovery_codes(state, request),
        ("POST", ["api", "v1", "password"]) => change_password(state, request),
        _ => return None,
    })
}

/// The caller's browser session: the cookie value, the validated session and
/// the instant it was judged at. CSRF was enforced by [`identify`].
pub(crate) fn browser_session(
    state: &State,
    request: &Request,
    mutation: bool,
) -> Result<(sentinel_auth::secret::Secret, Session, UnixMillis), ApiError> {
    let who = identify(state, request, mutation)?;
    if who.via != Via::Session {
        return Err(err(
            ErrorCode::InvalidRequest,
            "only a browser session does this",
        ));
    }
    let unauthenticated = || err(ErrorCode::Unauthenticated, "sign in");
    let presented = header_value(request, "cookie")
        .and_then(|header| cookie::read(cookie::SESSION_COOKIE, header))
        .ok_or_else(unauthenticated)?;
    let now = UnixMillis::now();
    let session = state
        .store
        .read(|c| local_auth::authenticate(c, &presented, now))
        .map_err(|_| unauthenticated())?;
    Ok((presented, session, now))
}

fn master_key(state: &State) -> Result<&sentinel_auth::sealed::Key, ApiError> {
    state.secret_key.as_deref().ok_or_else(|| {
        err(
            ErrorCode::Forbidden,
            "second factors need the deployment master key; initialize it first",
        )
    })
}

/// A body that may be absent: an empty one is the default.
fn optional_body<T: for<'de> Deserialize<'de> + Default>(
    request: &mut Request,
) -> Result<T, ApiError> {
    let bytes = body_limit(request, MAX_BODY_BYTES)?;
    if bytes.is_empty() {
        Ok(T::default())
    } else {
        parse(&bytes)
    }
}

fn admit(state: &State, request: &Request) -> Result<(), ApiError> {
    if crate::oauth::admitted(state, request, crate::oauth::Budget::Login) {
        Ok(())
    } else {
        Err(
            err(ErrorCode::RateLimited, "too many attempts; retry shortly")
                .with_detail("retry_after_ms", 2000),
        )
    }
}

/// `GET /api/v1/me/security`: what the account page shows — whether a local
/// password exists, the second factor's state, and the linked identities.
/// Metadata only: no seed, no code, no subject.
fn security(state: &State, request: &mut Request) -> Route {
    let (_, session, now) = browser_session(state, request, false)?;
    let user = session.user;
    let authority = Authority::session(&session, state.sessions, now);
    let (password, enrolled, pending, remaining, identities) = state
        .store
        .read(|c| {
            Ok((
                local_auth::username_of(c, user)?.is_some(),
                mfa::enrolled(c, user)?,
                mfa::enrollment_pending(c, user)?,
                mfa::recovery_codes_remaining(c, user)?,
                sign_in::identities(c, authority, user)?,
            ))
        })
        .map_err(store_error)?;
    ok(json!({
        "password": password,
        "mfa": {
            "enrolled": enrolled,
            "pending": pending,
            "recovery_codes_remaining": remaining,
        },
        "identities": identities.iter().map(|identity| json!({
            "provider": identity.provider,
            "linked_ms": identity.linked.0,
        })).collect::<Vec<_>>(),
        "github_link": state.github.is_some(),
    }))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EnrollBody {
    /// The account's password; required when it has one.
    password: Option<String>,
}

/// `POST /api/v1/mfa/enroll {password?}`: begin enrolling TOTP. Returns the
/// `otpauth://` URI once; nothing about authentication changes until
/// `…/confirm`. `409` when a factor is already confirmed (replacing one is
/// removal under step-up first), and a second `enroll` supersedes an
/// unconfirmed one.
fn enroll(state: &State, request: &mut Request) -> Route {
    let (presented, session, now) = browser_session(state, request, true)?;
    let key = master_key(state)?;
    let user = session.user;
    let (enrolled, username) = state
        .store
        .read(|c| Ok((mfa::enrolled(c, user)?, local_auth::username_of(c, user)?)))
        .map_err(store_error)?;
    if enrolled {
        return Err(store_error(StoreError::Conflict));
    }
    let proof: EnrollBody = optional_body(request)?;
    match (&username, proof.password) {
        // The password is the proof a password account can give.
        (Some(_), Some(password)) => {
            admit(state, request)?;
            if password.is_empty() || password.len() > sentinel_auth::password::MAX_LEN {
                return Err(err(ErrorCode::InvalidRequest, "invalid password"));
            }
            let accepted = mfa::step_up(
                &state.store,
                key,
                &presented,
                &session,
                Proof::Password(password.as_bytes()),
                now,
            )
            .map_err(store_error)?;
            if !accepted {
                return Err(err(ErrorCode::Forbidden, "enrollment refused"));
            }
        }
        (Some(_), None) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "the account password is required to enroll",
            ));
        }
        // A GitHub-only account has no password: the sign-in itself, within
        // the step-up window, is the proof.
        (None, _) => {
            if !session.signed_in_within(state.sessions, now) {
                return Err(err(
                    ErrorCode::Forbidden,
                    "sign in again to enroll a second factor",
                )
                .with_detail("reauthenticate", true));
            }
        }
    }
    let label = username.unwrap_or_else(|| user.to_string());
    let enrollment = mfa::begin_enrollment(&state.store, key, &session, ISSUER, &label, now)
        .map_err(store_error)?;
    ok(json!({ "provisioning_uri": enrollment.provisioning_uri }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    code: String,
}

/// `POST /api/v1/mfa/enroll/confirm {code}`: a current code from the app
/// proves it holds the seed. Returns the recovery codes **once** and stamps
/// the session as stepped up. A wrong code is `forbidden` and the enrollment
/// stays pending; none begun is `404`; the code's time step is spent, so the
/// same code cannot step up afterwards.
fn confirm(state: &State, request: &mut Request) -> Route {
    let (presented, session, now) = browser_session(state, request, true)?;
    let key = master_key(state)?;
    let code: ConfirmBody = parse(&body_limit(request, MAX_BODY_BYTES)?)?;
    if code.code.is_empty() || code.code.len() > MAX_CODE_BYTES {
        return Err(err(ErrorCode::InvalidRequest, "invalid code"));
    }
    let codes = mfa::confirm_enrollment(&state.store, key, &presented, &session, &code.code, now)
        .map_err(|error| match error {
        StoreError::Forbidden => err(ErrorCode::Forbidden, "code refused"),
        StoreError::NotFound => err(ErrorCode::NotFound, "no enrollment in progress"),
        other => store_error(other),
    })?;
    ok(json!({
        "recovery_codes": codes.iter().map(|c| c.expose()).collect::<Vec<_>>(),
        "stepped_up": true,
        "until_ms": now.0.saturating_add(state.sessions.step_up_ms),
    }))
}

/// `POST /api/v1/mfa/recovery-codes`: a fresh set of ten, replacing the old
/// one entirely, shown once. A fresh step-up first (`forbidden` with
/// `details.step_up`), and `404` without an enrolled factor.
fn recovery_codes(state: &State, request: &mut Request) -> Route {
    let (_, session, now) = browser_session(state, request, true)?;
    let codes = mfa::reissue_recovery_codes(&state.store, &session, state.sessions, now)
        .map_err(store_error)?;
    ok(json!({
        "recovery_codes": codes.iter().map(|c| c.expose()).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current: String,
    new: String,
}

/// `POST /api/v1/password {current, new}`: change the local password. The
/// current password is always needed; with a second factor a fresh step-up is
/// too (`forbidden` with `details.step_up`). Success ends **every** session and
/// OAuth grant of the account, this one included, and the response clears the
/// cookie: sign in again with the new password. Anything wrong with the
/// current password — or no local password at all — is one `forbidden`, and
/// five wrong ones revoke the session.
fn change_password(state: &State, request: &mut Request) -> Route {
    let (presented, session, now) = browser_session(state, request, true)?;
    admit(state, request)?;
    let passwords: PasswordBody = parse(&body_limit(request, MAX_BODY_BYTES)?)?;
    let max = sentinel_auth::password::MAX_LEN;
    if passwords.current.is_empty() || passwords.current.len() > max || passwords.new.len() > max {
        return Err(err(ErrorCode::InvalidRequest, "invalid password"));
    }
    let changed = local_auth::change_password(
        &state.store,
        &presented,
        &session,
        state.sessions,
        passwords.current.as_bytes(),
        passwords.new.as_bytes(),
        now,
    );
    match changed {
        Ok(true) => Ok(Reply::Json(
            200,
            json!({ "ok": true, "signed_out": true }),
            vec![header("set-cookie", &cookie::clear(cookie::SESSION_COOKIE))],
        )),
        Ok(false) | Err(StoreError::NotFound) => {
            Err(err(ErrorCode::Forbidden, "password change refused"))
        }
        Err(other) => Err(store_error(other)),
    }
}
