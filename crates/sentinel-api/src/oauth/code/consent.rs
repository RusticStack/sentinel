//! The consent page: who is asking, for what, on which deployment, and the
//! narrowing the account may choose. Every dynamic value is escaped; every
//! request parameter rides in a hidden field so `POST` can re-validate it.

use std::fmt::Write as _;

use sentinel_core::auth::Role;
use sentinel_protocol::oauth::AUTHORIZE_PATH;
use sentinel_store::{local_auth, oauth::code as codes};

use super::{Params, unavailable};
use crate::{
    State,
    auth::Identity,
    oauth::html::{self, escape_into},
    routes::Reply,
};

/// The consent page with `200`.
pub(super) fn page(
    state: &State,
    params: &Params<'_>,
    who: &Identity,
    form_token: &str,
    notice: Option<&str>,
) -> Reply {
    page_status(state, params, who, form_token, notice, 200)
}

/// The consent page with `status` (a re-render after a correctable choice).
pub(super) fn page_status(
    state: &State,
    params: &Params<'_>,
    who: &Identity,
    form_token: &str,
    notice: Option<&str>,
    status: u16,
) -> Reply {
    let looked_up = state.store.read(|c| {
        Ok((
            local_auth::username_of(c, who.user)?,
            codes::consent_choices(c, who.user)?,
        ))
    });
    let (username, choices) = match looked_up {
        Ok(found) => found,
        Err(e) => return unavailable(&e),
    };
    let mut body = String::with_capacity(4096);
    if let Some(notice) = notice {
        body.push_str("<p class=\"warn\">");
        escape_into(&mut body, notice);
        body.push_str("</p>\n");
    }
    if params.client.registered {
        // A registered client names itself; nothing here vouches for it.
        body.push_str(
            "<p class=\"warn\">Third-party application: its name and details were supplied \
             by whoever registered it and are not verified by this deployment.</p>\n\
             <p>After you decide, your browser is sent to <strong><code>",
        );
        escape_into(&mut body, redirect_host(params.redirect_uri));
        body.push_str("</code></strong>.</p>\n");
    }
    body.push_str("<p><strong>");
    escape_into(&mut body, &params.client.name);
    body.push_str("</strong> (<code>");
    escape_into(&mut body, &params.client.display_id);
    body.push_str("</code>) asks to use Sentinel at <code>");
    escape_into(&mut body, &state.oauth.issuer);
    body.push_str("</code> as <strong>");
    escape_into(&mut body, username.as_deref().unwrap_or("you"));
    body.push_str("</strong>.</p>\n<p>Resource: <code>");
    escape_into(&mut body, state.oauth.resource(params.audience));
    body.push_str("</code>.</p>\n<p>It will be allowed to:</p>\n<ul>\n");
    for name in params.scopes.names() {
        body.push_str("<li><code>");
        body.push_str(name);
        body.push_str("</code> ");
        body.push_str(describe(name));
        if name == "tenant:admin" || name == "platform:admin" {
            body.push_str(" <span class=\"warn\">Administrative access.</span>");
        }
        body.push_str("</li>\n");
    }
    body.push_str("</ul>\n<p class=\"muted\">Afterwards the browser returns to <code>");
    escape_into(&mut body, params.redirect_uri);
    body.push_str("</code>. Access never exceeds what your account holds.</p>\n");

    body.push_str("<form method=\"post\" action=\"");
    escape_into(&mut body, &state.oauth.issuer);
    body.push_str(AUTHORIZE_PATH);
    body.push_str("\">\n");
    hidden(&mut body, "form_token", form_token);
    hidden(&mut body, "response_type", "code");
    hidden(&mut body, "client_id", &params.client.id);
    hidden(&mut body, "redirect_uri", params.redirect_uri);
    hidden(&mut body, "state", params.state);
    hidden(&mut body, "code_challenge", params.code_challenge);
    hidden(&mut body, "code_challenge_method", "S256");
    // Scope names carry no markup metacharacters.
    body.push_str("<input type=\"hidden\" name=\"scope\" value=\"");
    params.scopes.write_names(&mut body);
    body.push_str("\">\n");
    if let Some(resource) = params.resource {
        hidden(&mut body, "resource", resource);
    }
    body.push_str(
        "<label>Tenant <select name=\"tenant\">\n<option value=\"\">All my tenants</option>\n",
    );
    for choice in &choices {
        body.push_str("<option value=\"");
        let _ = write!(body, "{}", choice.tenant);
        body.push_str("\">");
        escape_into(&mut body, &choice.slug);
        body.push_str(match choice.role {
            Role::Reader => " (reader)",
            Role::Operator => " (operator)",
            Role::TenantAdmin => " (admin)",
        });
        body.push_str("</option>\n");
    }
    body.push_str(
        "</select></label>\n\
         <label>Only this repository (optional) \
         <input name=\"repo\" maxlength=\"128\" autocomplete=\"off\"></label>\n\
         <div class=\"row\">\
         <button name=\"decision\" value=\"approve\">Approve</button>\
         <button name=\"decision\" value=\"deny\">Deny</button></div>\n</form>",
    );
    Reply::Html(
        status,
        html::document("Authorize access", &body),
        Vec::new(),
    )
}

/// `scheme://host[:port]` of a redirect URI: where the browser goes, which
/// the consent page shows prominently for third-party clients.
fn redirect_host(uri: &str) -> &str {
    let Some(at) = uri.find("://") else {
        return uri;
    };
    match uri[at + 3..].find('/') {
        Some(slash) => &uri[..at + 3 + slash],
        None => uri,
    }
}

fn hidden(out: &mut String, name: &str, value: &str) {
    out.push_str("<input type=\"hidden\" name=\"");
    out.push_str(name);
    out.push_str("\" value=\"");
    escape_into(out, value);
    out.push_str("\">\n");
}

/// Plain words for each scope.
fn describe(scope: &str) -> &'static str {
    match scope {
        "runs:read" => "see repositories, runs, workers and the queue",
        "runs:write" => "dispatch, cancel and rerun runs",
        "logs:read" => "read job logs",
        "artifacts:read" => "download artifacts",
        "cache:read" => "read cache records",
        "cache:write" => "write to caches",
        "secrets:metadata" => "list secret names (never values)",
        "secrets:write" => "create and change secrets",
        "tenant:admin" => "administer tenants you administer",
        "platform:admin" => "administer the whole deployment",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::auth::Scopes;

    #[test]
    fn the_redirect_host_is_the_origin_of_the_redirect() {
        assert_eq!(
            redirect_host("https://claude.ai/api/mcp/auth_callback"),
            "https://claude.ai"
        );
        assert_eq!(
            redirect_host("http://127.0.0.1:33418"),
            "http://127.0.0.1:33418"
        );
    }

    #[test]
    fn every_scope_has_words() {
        for name in Scopes::ALL.names() {
            assert!(!describe(name).is_empty(), "{name}");
        }
    }
}
