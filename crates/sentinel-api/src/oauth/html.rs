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

/// The embedded sign-in form: a password login through `POST /api/v1/login`
/// (which sets the session cookie), then a reload of the same page so the
/// request is re-evaluated with the session. Nothing about the pending
/// request is stored; the URL carries it.
pub(crate) const SIGN_IN: &str = r#"<form id="sentinel-sign-in">
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
    const response = await fetch("/api/v1/login", {
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

/// A page asking the visitor to sign in first, with `message` explaining why.
pub(crate) fn sign_in_page(title: &str, message: &str) -> Reply {
    let mut body = String::from("<p>");
    escape_into(&mut body, message);
    body.push_str("</p>\n");
    body.push_str(SIGN_IN);
    page(200, title, &body)
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
    fn the_policy_forbids_framing_and_foreign_loads_but_not_form_redirects() {
        let csp = SECURITY_HEADERS[0].1;
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("form-action"));
    }
}
