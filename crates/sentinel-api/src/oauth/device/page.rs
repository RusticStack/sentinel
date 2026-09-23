//! `GET`/`POST /device`: a signed-in person enters the user code shown by a
//! device, sees what it asks for, and approves (optionally narrowing the
//! scopes, a tenant and a repository) or denies.
//!
//! A session cookie is required; without one the page embeds the ordinary
//! password sign-in. The approval form carries a token keyed to the
//! session's CSRF digest, and an `Origin` header, when sent, must be the
//! issuer's. Five wrong user codes per account within ten minutes lock the
//! account out of the page for the rest of that window, so a code cannot be
//! guessed from a session. The device code never appears here.

use std::{
    fmt::Write as _,
    time::{Duration, Instant},
};

use sentinel_auth::{cookie, oauth as forms, secret::Digest};
use sentinel_core::{RepoId, TenantId, UnixMillis, UserId, auth::Scopes};
use sentinel_protocol::limits::MAX_OAUTH_FORM_BYTES;
use sentinel_store::{
    Error as StoreError, local_auth, lookup,
    oauth::device::{self, Decision, DeviceView},
};

use crate::{
    State,
    auth::Identity,
    http::Request,
    oauth::{Form, html, session},
    routes::{self, Reply, Route},
};

const TITLE: &str = "Connect a device";

/// Wrong user codes an account may enter per window.
const MAX_WRONG_CODES: u8 = 5;
/// The window those are counted in.
const WRONG_CODE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Accounts tracked before stale windows are dropped.
const MAX_TRACKED: usize = 4096;

/// `GET`/`POST /device`.
pub(crate) fn page(state: &State, request: &mut Request, method: &str, query: &str) -> Route {
    let Some((who, csrf)) = session(state, request).and_then(|who| Some((who, who.csrf?))) else {
        return Ok(html::sign_in_page(
            TITLE,
            "Sign in to connect a device to your account.",
        ));
    };
    Ok(if method == "POST" {
        submit(state, request, &who, &csrf)
    } else {
        show(state, &who, &csrf, query)
    })
}

/// Whether the account has used up its wrong codes for this window.
fn locked(state: &State, user: UserId, now: Instant) -> bool {
    state
        .oauth
        .user_code_failures
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&user)
        .is_some_and(|(count, start)| {
            *count >= MAX_WRONG_CODES && now.saturating_duration_since(*start) < WRONG_CODE_WINDOW
        })
}

/// Count one wrong code for the account.
fn wrong_code(state: &State, user: UserId, now: Instant) {
    let mut failures = state
        .oauth
        .user_code_failures
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if failures.len() >= MAX_TRACKED && !failures.contains_key(&user) {
        failures.retain(|_, (_, start)| now.saturating_duration_since(*start) < WRONG_CODE_WINDOW);
    }
    let entry = failures.entry(user).or_insert((0, now));
    if now.saturating_duration_since(entry.1) >= WRONG_CODE_WINDOW {
        *entry = (0, now);
    }
    entry.0 = entry.0.saturating_add(1);
}

fn lockout() -> Reply {
    html::error_page(
        429,
        "Too many wrong codes. Wait ten minutes, then enter the code shown on your device.",
    )
}

/// The user-code entry form, with an optional message.
fn entry(status: u16, message: Option<&str>) -> Reply {
    let mut body = String::with_capacity(512);
    if let Some(message) = message {
        body.push_str("<p class=\"warn\">");
        html::escape_into(&mut body, message);
        body.push_str("</p>\n");
    }
    body.push_str(
        "<p>Enter the code your device shows.</p>\n\
         <form method=\"get\" action=\"/device\">\n\
         <input name=\"user_code\" placeholder=\"XXXX-XXXX\" autocomplete=\"off\" \
         autocapitalize=\"characters\" spellcheck=\"false\" maxlength=\"16\" required autofocus>\n\
         <button>Continue</button>\n</form>",
    );
    html::page(status, TITLE, &body)
}

fn show(state: &State, who: &Identity, csrf: &Digest, query: &str) -> Reply {
    let Some(typed) = form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "user_code")
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
    else {
        return entry(200, None);
    };
    let clock = Instant::now();
    if locked(state, who.user, clock) {
        return lockout();
    }
    let Some(code) = forms::normalize_user_code(&typed) else {
        wrong_code(state, who.user, clock);
        return entry(400, Some("That is not a device code."));
    };
    let now = UnixMillis::now();
    let found = state.store.read(|c| {
        let view = device::view(c, &code, now)?;
        Ok((view, local_auth::username_of(c, who.user)?))
    });
    match found {
        Ok((view, username)) => approval(state, who, csrf, &code, &view, username.as_deref(), now),
        Err(StoreError::NotFound) => {
            wrong_code(state, who.user, clock);
            entry(
                404,
                Some("No pending request has that code. Check it, or start again on the device."),
            )
        }
        Err(_) => html::error_page(503, "The server is busy. Try again."),
    }
}

/// The approval form for one pending request.
fn approval(
    state: &State,
    who: &Identity,
    csrf: &Digest,
    code: &str,
    view: &DeviceView,
    username: Option<&str>,
    now: UnixMillis,
) -> Reply {
    let mut body = String::with_capacity(2048);
    body.push_str("<p><strong>");
    html::escape_into(&mut body, &view.client_name);
    body.push_str("</strong> asks to sign in to <code>");
    html::escape_into(&mut body, &state.oauth.issuer);
    body.push_str("</code> as <strong>");
    match username {
        Some(name) => html::escape_into(&mut body, name),
        None => html::escape_into(&mut body, &who.user.to_string()),
    }
    body.push_str("</strong>.</p>\n<p>Check that your device shows <code>");
    body.push_str(&forms::display_user_code(code));
    let minutes = (view.expires.0.saturating_sub(now.0) + 59_999) / 60_000;
    let _ = write!(
        body,
        "</code>. The request expires in {minutes} minute{}.</p>",
        if minutes == 1 { "" } else { "s" }
    );
    body.push_str("\n<form method=\"post\" action=\"/device\">\n<input type=\"hidden\" name=\"user_code\" value=\"");
    body.push_str(code);
    body.push_str("\">\n<input type=\"hidden\" name=\"form_token\" value=\"");
    body.push_str(&cookie::form_token(&state.oauth.form_key, csrf));
    body.push_str("\">\n<fieldset><legend>Allow</legend>\n");
    for name in view.scopes.names() {
        let _ = write!(
            body,
            "<label><input type=\"checkbox\" name=\"scope_{name}\" value=\"1\" checked> <code>{name}</code>"
        );
        if name == "tenant:admin" || name == "platform:admin" {
            body.push_str(" <span class=\"warn\">administrative access</span>");
        }
        body.push_str("</label><br>\n");
    }
    body.push_str(
        "</fieldset>\n\
         <label>Tenant <input name=\"tenant\" placeholder=\"every tenant\" autocomplete=\"off\"></label>\n\
         <label>Repository <input name=\"repo\" placeholder=\"every repository (needs a tenant)\" autocomplete=\"off\"></label>\n\
         <div class=\"row\"><button name=\"action\" value=\"approve\">Approve</button>\
         <button name=\"action\" value=\"deny\">Deny</button></div>\n</form>\n\
         <p class=\"muted\">Only approve a request you started yourself.</p>",
    );
    html::page(200, TITLE, &body)
}

/// The scopes whose checkbox came back ticked.
fn ticked(form: &Form) -> Scopes {
    let mut name = String::with_capacity(24);
    let mut scopes = Scopes::NONE;
    for (bit, scope) in Scopes::NAMES.iter().enumerate() {
        name.clear();
        name.push_str("scope_");
        name.push_str(scope);
        if form.get(&name).is_some()
            && let Some(one) = Scopes::from_bits(1 << bit)
        {
            scopes = scopes.union(one);
        }
    }
    scopes
}

fn submit(state: &State, request: &mut Request, who: &Identity, csrf: &Digest) -> Reply {
    if routes::header_value(request, "origin").is_some_and(|origin| origin != state.oauth.origin) {
        return html::error_page(403, "This form must be sent from this server's own page.");
    }
    let form = match routes::body_limit(request, MAX_OAUTH_FORM_BYTES)
        .ok()
        .and_then(|bytes| Form::parse(&bytes).ok())
    {
        Some(form) => form,
        None => return html::error_page(400, "The form could not be read."),
    };
    if !cookie::form_token_accepted(&state.oauth.form_key, csrf, form.get("form_token")) {
        return html::error_page(403, "This form has expired. Enter the code again.");
    }
    let clock = Instant::now();
    if locked(state, who.user, clock) {
        return lockout();
    }
    let Some(code) = form.get("user_code").and_then(forms::normalize_user_code) else {
        wrong_code(state, who.user, clock);
        return entry(400, Some("That is not a device code."));
    };
    let decision = match form.get("action") {
        Some("deny") => Decision::Deny,
        Some("approve") => {
            let (tenant, repo) = match narrowing(state, &form) {
                Ok(narrowing) => narrowing,
                Err(reply) => return reply,
            };
            Decision::Approve {
                scopes: ticked(&form),
                tenant,
                repo,
            }
        }
        _ => return html::error_page(400, "Choose approve or deny."),
    };
    match device::decide(&state.store, &code, who.user, decision, UnixMillis::now()) {
        Ok(()) => match decision {
            Decision::Deny => html::page(
                200,
                TITLE,
                "<p>Request denied. The device gets nothing.</p>",
            ),
            Decision::Approve { .. } => html::page(
                200,
                TITLE,
                "<p>Device connected. You can close this window and return to your device.</p>",
            ),
        },
        Err(StoreError::NotFound) => {
            wrong_code(state, who.user, clock);
            entry(
                404,
                Some("No pending request has that code. Check it, or start again on the device."),
            )
        }
        Err(StoreError::Forbidden) => html::error_page(
            403,
            "Your account cannot approve this request with those terms: check the tenant, \
             the repository and the administrative scopes.",
        ),
        Err(StoreError::InvalidInput(_)) => html::error_page(
            400,
            "Allow at least one of the requested scopes, and name a tenant with a repository.",
        ),
        Err(_) => html::error_page(503, "The server is busy. Try again."),
    }
}

/// The optional tenant (by slug) and repository (by name) narrowing. The
/// store re-checks membership and ownership when recording the decision.
fn narrowing(state: &State, form: &Form) -> Result<(Option<TenantId>, Option<RepoId>), Reply> {
    let (slug, name) = (form.get("tenant"), form.get("repo"));
    let Some(slug) = slug else {
        return if name.is_some() {
            Err(html::error_page(400, "A repository needs its tenant."))
        } else {
            Ok((None, None))
        };
    };
    state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, slug)?;
            let repo = name
                .map(|name| lookup::repo_by_name(c, tenant, name))
                .transpose()?;
            Ok((Some(tenant), repo))
        })
        .map_err(|e| match e {
            StoreError::NotFound => {
                html::error_page(403, "No such tenant or repository for your account.")
            }
            _ => html::error_page(503, "The server is busy. Try again."),
        })
}
