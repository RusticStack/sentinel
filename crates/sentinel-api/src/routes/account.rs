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

const ISSUER: &str = "Sentinel";
/// Longest code accepted: a TOTP is six digits, a recovery code about a dozen characters.
const MAX_CODE_BYTES: usize = 64;
const MAX_BODY_BYTES: usize = 4 << 10;

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
    password: Option<String>,
}

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
        // A GitHub-only account has no password: a fresh sign-in is its proof.
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

/// The code's time step is spent, so the same code cannot step up afterwards.
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
