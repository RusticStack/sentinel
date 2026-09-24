//! Server-rendered pages for the browser half of OAuth (consent, device
//! approval): one escaped page shell, an embedded sign-in form that uses the
//! ordinary password login, and the security headers every HTML reply
//! carries (added by the response layer for each `Reply::Html`).
//!
//! The CSP deliberately has no `form-action`: Chrome enforces it on the
//! redirect a form submission follows, which would block the consent
//! page's `303` to the CLI's loopback listener.

use crate::routes::{self, Reply};

/// Sent with every `Reply::Html`.
pub(crate) const SECURITY_HEADERS: [(&str, &str); 4] = [
    (
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
    ),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
];

/// Append `text` with HTML metacharacters escaped; safe in element content
/// and in double- or single-quoted attribute values.
pub(crate) fn escape_into(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
}

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
  :root { color-scheme: light dark; font: 15px/1.45 system-ui, sans-serif; }
  body { margin: 0 auto; padding: 24px 16px; max-width: 560px; }
  h1 { font-size: 20px; margin: 0 0 16px; }
  form { display: grid; gap: 10px; margin: 16px 0; }
  input, select, button { font: inherit; padding: 7px 9px; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  .muted { opacity: .7; }
  .warn { color: #c33; font-weight: 600; }
  code { font-size: 13px; }
</style>
"#;

/// A complete page: `title` is escaped here; `body` is trusted markup the
/// caller built with [`escape`] around every dynamic value.
pub(crate) fn document(title: &str, body: &str) -> String {
    let mut out = String::with_capacity(HEAD.len() + body.len() + 128);
    out.push_str(HEAD);
    out.push_str("<title>");
    escape_into(&mut out, title);
    out.push_str("</title>\n</head>\n<body>\n<h1>");
    escape_into(&mut out, title);
    out.push_str("</h1>\n");
    out.push_str(body);
    out.push_str("\n</body>\n</html>\n");
    out
}

/// An HTML reply of `status` (security headers are added on the way out).
pub(crate) fn page(status: u16, title: &str, body: &str) -> Reply {
    Reply::Html(status, document(title, body), Vec::new())
}

/// A page stating an error in plain words. Never a redirect: used when the
/// client or redirect URI cannot be trusted with one.
pub(crate) fn error_page(status: u16, message: &str) -> Reply {
    let mut body = String::from("<p>");
    escape_into(&mut body, message);
    body.push_str("</p>");
    page(status, "Sentinel", &body)
}

/// `303 See Other` to `location`, with an empty body.
pub(crate) fn redirect(location: &str) -> Reply {
    Reply::Html(
        303,
        String::new(),
        vec![routes::header("location", location)],
    )
}

/// The embedded sign-in form: a password login through `POST
/// {issuer}/api/v1/login` (which sets the session cookie), then a reload of
/// the same page so the request is re-evaluated with the session. Nothing
/// about the pending request is stored; the URL carries it. The login URL
/// comes from the issuer, so a path-carrying `public_url` posts inside its
/// own mount rather than at the host's root.
const SIGN_IN_HEAD: &str = r#"<form id="sentinel-sign-in">
  <input id="sentinel-username" placeholder="username" autocomplete="username" required>
  <input id="sentinel-password" type="password" placeholder="password" autocomplete="current-password" required>
  <button>Sign in</button>
  <span id="sentinel-sign-in-status" class="muted"></span>
</form>
<script>
document.getElementById("sentinel-sign-in").onsubmit = async (event) => {
  event.preventDefault();
  const status = document.getElementById("sentinel-sign-in-status");
  status.textContent = "";
  try {
    const response = await fetch("#;

const SIGN_IN_TAIL: &str = r#", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "accept": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("sentinel-username").value,
        password: document.getElementById("sentinel-password").value,
      }),
    });
    if (!response.ok) { status.textContent = "Sign-in refused."; return; }
    location.reload();
  } catch (error) { status.textContent = "Sign-in failed."; }
};
</script>"#;

/// A page asking the visitor to sign in first, with `message` explaining
/// why; the form posts to `login_url` (`OAuthState::login_url`). With
/// `github` (the start URL, and the issuer-relative path of this page with
/// its query), a "Sign in with GitHub" link sits next to the form and
/// returns the browser here, parameters intact. It is a plain `GET` link, so
/// the page's CSP (which has no `form-action` and governs no navigation)
/// does not stand in the way of the redirect to GitHub.
pub(crate) fn sign_in_page(
    login_url: &str,
    github: Option<(&str, &str)>,
    title: &str,
    message: &str,
) -> Reply {
    let mut body = String::with_capacity(SIGN_IN_HEAD.len() + SIGN_IN_TAIL.len() + 512);
    body.push_str("<p>");
    escape_into(&mut body, message);
    body.push_str("</p>\n");
    if let Some((start_url, here)) = github {
        body.push_str("<p><a id=\"sentinel-github\" href=\"");
        escape_into(&mut body, &crate::github::start_link(start_url, here));
        body.push_str("\">Sign in with GitHub</a></p>\n");
    }
    body.push_str(SIGN_IN_HEAD);
    script_string_into(&mut body, login_url);
    body.push_str(SIGN_IN_TAIL);
    page(200, title, &body)
}

/// Append `text` as a double-quoted JavaScript string literal that is also
/// safe inside a `<script>` element: quotes, backslashes, `<`, `>` and `&`
/// and every control character are escaped.
fn script_string_into(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' | '\\' | '<' | '>' | '&' | '\'' | '\u{2028}' | '\u{2029}' => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", ch as u32));
            }
            c if c.is_control() => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escape(text: &str) -> String {
        let mut out = String::new();
        escape_into(&mut out, text);
        out
    }

    #[test]
    fn escaping_covers_every_metacharacter() {
        assert_eq!(
            escape(r#"<a href="x" onclick='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(escape("plain text"), "plain text");
        let doc = document("<script>", "<p>ok</p>");
        assert!(doc.contains("<title>&lt;script&gt;</title>"));
        assert!(!doc.contains("<title><script>"));
    }

    #[test]
    fn the_sign_in_posts_inside_the_issuer_and_cannot_break_out_of_its_script() {
        let Reply::Html(_, page, _) = sign_in_page(
            "https://ci.example/sentinel/api/v1/login",
            None,
            "Sign in",
            "why",
        ) else {
            panic!("not a page");
        };
        assert!(page.contains(r#"fetch("https://ci.example/sentinel/api/v1/login", {"#));
        assert!(!page.contains("Sign in with GitHub"));
        let Reply::Html(_, page, _) = sign_in_page(
            "https://ci.example/sentinel/api/v1/login",
            Some((
                "https://ci.example/sentinel/auth/github/start",
                "/device?a=1&b=\"",
            )),
            "Sign in",
            "why",
        ) else {
            panic!("not a page");
        };
        assert!(page.contains(
            r#"href="https://ci.example/sentinel/auth/github/start?return_to=%2Fdevice%3Fa%3D1%26b%3D%22""#
        ));
        let mut out = String::new();
        script_string_into(&mut out, "a\"</script>\\\n");
        let expected = ["\"a", "0022", "003c/script", "003e", "005c", "000a\""].join("\\u");
        assert_eq!(out, expected);
    }

    #[test]
    fn the_policy_forbids_framing_and_foreign_loads_but_not_form_redirects() {
        let csp = SECURITY_HEADERS[0].1;
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("form-action"));
    }
}
