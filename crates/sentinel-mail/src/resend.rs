//! A bounded client for the Resend email API.
//!
//! One request per message: `POST https://api.resend.com/emails` with
//! `Authorization: Bearer <key>` and a JSON body `{from, to, subject, html,
//! text}`. The host is a constant; no configuration reaches it (a test can
//! point a client elsewhere only when this crate is built with the
//! `test-endpoint` feature, which only dev-dependencies enable). The client
//! follows no redirect (the key would travel with it), ignores proxy
//! environment variables, uses rustls with the bundled web PKI roots, and
//! bounds time (connect and whole request) and the response size. Because the
//! message is a JSON document, a header or line injection through an address
//! or subject is impossible; they are validated anyway.
//!
//! Each message carries an `Idempotency-Key` derived from its outbox row id,
//! so a retry after a lost response is the same send to Resend, never a second
//! message. Replies are classified by status: `2xx` delivered; `429`, `5xx`,
//! `408`, a concurrent-idempotent `409` and every transport failure transient
//! (`Retry-After` honored); any other `4xx` permanent. An error carries the
//! status and Resend's error *name* (a fixed vocabulary, sanitized), never its
//! message (which may quote an address), the key, or the body.

use std::{path::Path, time::Duration};

use sentinel_auth::secret::wipe;

use crate::{Failure, Mail, Transport};

/// The one API endpoint.
const ENDPOINT: &str = "https://api.resend.com/emails";
/// The most of a reply read; a larger one is cut off and only its status used.
pub const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The longest subject accepted.
pub const MAX_SUBJECT_CHARS: usize = 200;
/// The largest plain-text body accepted.
pub const MAX_BODY_BYTES: usize = 32 * 1024;
/// The longest API key accepted.
const MAX_KEY_BYTES: usize = 512;
const MAX_KEY_FILE_BYTES: usize = 4096;
const MAX_DISPLAY_NAME_CHARS: usize = 64;

/// A Resend API key. Never in `Debug` output or an error; wiped when dropped.
pub struct ApiKey(Vec<u8>);

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl ApiKey {
    /// A key of 1-512 visible ASCII characters (it becomes a header value).
    pub fn new(mut bytes: Vec<u8>) -> Result<ApiKey, &'static str> {
        if bytes.is_empty()
            || bytes.len() > MAX_KEY_BYTES
            || !bytes.iter().all(|b| b.is_ascii_graphic())
        {
            wipe(&mut bytes);
            return Err("the Resend API key must be 1-512 visible ASCII characters");
        }
        Ok(ApiKey(bytes))
    }

    /// Read the key from an operator-controlled file: opened once without
    /// following a link and judged on the handle (a regular file owned by this
    /// user, closed to group and others), at most 4 KiB, one trailing newline
    /// dropped. An error names the problem, never the path or the content.
    pub fn from_file(path: &Path) -> Result<ApiKey, &'static str> {
        const REFUSED: &str = "the Resend API key file must be a regular owner-only file of at most 4 KiB holding the key";
        let mut file = sentinel_auth::secret_file::open(path).map_err(|_| REFUSED)?;
        let mut bytes = sentinel_auth::secret_file::read(&mut file, MAX_KEY_FILE_BYTES)
            .map_err(|_| REFUSED)?
            .ok_or(REFUSED)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        ApiKey::new(bytes).map_err(|_| REFUSED)
    }

    fn bearer(&self) -> String {
        // Validated visible ASCII, so this is UTF-8.
        let mut header = String::with_capacity(7 + self.0.len());
        header.push_str("Bearer ");
        header.push_str(std::str::from_utf8(&self.0).unwrap_or_default());
        header
    }
}

/// The validated `from` of every message: `addr@domain` or
/// `Name <addr@domain>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sender {
    header: String,
}

impl Sender {
    /// Parse and validate; the address is normalized like every address in
    /// the store. Errors never echo the input.
    pub fn parse(text: &str) -> Result<Sender, &'static str> {
        const BAD: &str = "the sender must be `addr@example.com` or `Name <addr@example.com>`";
        let text = text.trim();
        let (name, address) = match (text.find('<'), text.strip_suffix('>')) {
            (Some(open), Some(inner)) => (inner[..open].trim(), &inner[open + 1..]),
            (None, _) if !text.contains('>') => ("", text),
            _ => return Err(BAD),
        };
        let name = name
            .strip_prefix('"')
            .and_then(|n| n.strip_suffix('"'))
            .unwrap_or(name);
        let name_ok = name.chars().count() <= MAX_DISPLAY_NAME_CHARS
            && !name
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '\\' | ',' | ';' | '@' | ':'));
        if !name_ok {
            return Err(BAD);
        }
        let address = sentinel_store::email::normalize(address).map_err(|_| BAD)?;
        let header = if name.is_empty() {
            address
        } else {
            format!("{name} <{address}>")
        };
        Ok(Sender { header })
    }

    pub fn as_str(&self) -> &str {
        &self.header
    }
}

/// The Resend transport.
pub struct Resend {
    agent: ureq::Agent,
    endpoint: String,
    key: ApiKey,
    from: Sender,
}

impl std::fmt::Debug for Resend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resend(..)")
    }
}

fn agent(https_only: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(TOTAL_TIMEOUT))
        .max_redirects(0)
        .proxy(None)
        .https_only(https_only)
        .max_response_header_size(MAX_HEADERS)
        // Statuses are data: they are classified, not raised.
        .http_status_as_error(false)
        .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(config)
}

impl Resend {
    pub fn new(key: ApiKey, from: Sender) -> Resend {
        Resend {
            agent: agent(true),
            endpoint: ENDPOINT.to_owned(),
            key,
            from,
        }
    }

    /// A client for a local test server (`http://127.0.0.1:port/emails`).
    #[cfg(feature = "test-endpoint")]
    pub fn with_endpoint(key: ApiKey, from: Sender, endpoint: &str) -> Resend {
        Resend {
            agent: agent(false),
            endpoint: endpoint.to_owned(),
            key,
            from,
        }
    }

    /// Send one message. Shared access: the client holds no per-send state.
    pub fn deliver(&self, mail: &Mail<'_>) -> Result<(), Failure> {
        if mail.subject.is_empty()
            || mail.subject.chars().count() > MAX_SUBJECT_CHARS
            || mail.subject.chars().any(char::is_control)
        {
            return Err(Failure::Permanent("the subject is not acceptable".into()));
        }
        if mail.body.len() > MAX_BODY_BYTES {
            return Err(Failure::Permanent("the message is too large".into()));
        }
        // The recipient was normalized when queued; a second look costs
        // nothing and keeps this client safe on its own.
        if sentinel_store::email::normalize(mail.to).is_err() {
            return Err(Failure::Permanent("the recipient is not an address".into()));
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "from": self.from.as_str(),
            "to": [mail.to],
            "subject": mail.subject,
            "html": html(mail.body),
            "text": mail.body,
        }))
        .map_err(|_| Failure::Permanent("the message cannot be encoded".into()))?;
        let request = ureq::http::Request::builder()
            .method("POST")
            .uri(self.endpoint.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("authorization", self.key.bearer())
            .header("idempotency-key", idempotency_key(mail))
            .body(body)
            .map_err(|_| Failure::Permanent("the request cannot be built".into()))?;
        let mut response = self.agent.run(request).map_err(transport)?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            // Accepted: the reply carries only an id, and is not read.
            return Ok(());
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        // Only the error's name is used, and only from a reply within bounds.
        let name = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .ok()
            .and_then(|bytes| error_name(&bytes));
        classify(status, retry_after, name.as_deref())
    }
}

impl Transport for Resend {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure> {
        self.deliver(mail)
    }
}

/// The idempotency key of a message: stable across its retries, unique per
/// outbox row (Resend accepts up to 256 characters).
pub fn idempotency_key(mail: &Mail<'_>) -> String {
    format!("sentinel-mail-{}", mail.id)
}

/// The HTML part: the text, escaped, with line breaks kept.
fn html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    out.push_str("<div style=\"font-family:sans-serif;white-space:normal\">");
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\r' => {}
            '\n' => out.push_str("<br>\n"),
            c => out.push(c),
        }
    }
    out.push_str("</div>");
    out
}

/// Resend's error `name` (`validation_error`, `rate_limit_exceeded`, ...)
/// when the body carries one of plausible shape.
fn error_name(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let name = value.get("name")?.as_str()?;
    let plausible = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    plausible.then(|| name.to_owned())
}

/// Sort a non-success status into retry or give up.
pub(crate) fn classify(
    status: u16,
    retry_after: Option<Duration>,
    name: Option<&str>,
) -> Result<(), Failure> {
    let label = |what: &str| match name {
        Some(name) => format!("resend {what} ({status} {name})"),
        None => format!("resend {what} ({status})"),
    };
    match status {
        401 | 403 => Err(Failure::Permanent(label("refused the API key"))),
        // A second request with the same key while the first is in flight:
        // wait it out. Any other 409 is a conflict retrying cannot resolve.
        409 if name == Some("concurrent_idempotent_requests") => Err(Failure::Transient {
            why: label("is still processing the message"),
            retry_after,
        }),
        408 | 429 | 500..=599 => Err(Failure::Transient {
            why: label(if status == 429 {
                "throttled the request"
            } else {
                "is unavailable"
            }),
            retry_after,
        }),
        400..=499 => Err(Failure::Permanent(label("refused the message"))),
        // Anything else (a redirect, an informational status) is not an
        // answer to follow; try again later.
        _ => Err(Failure::Transient {
            why: label("answered unexpectedly"),
            retry_after,
        }),
    }
}

/// Transport failures by kind; `ureq`'s own message can carry the URL.
fn transport(error: ureq::Error) -> Failure {
    Failure::transient(match error {
        ureq::Error::Timeout(_) => "resend did not answer in time",
        ureq::Error::ConnectionFailed => "cannot connect to resend",
        ureq::Error::Tls(_) => "TLS to resend failed",
        ureq::Error::BodyExceedsLimit(_) => "resend's answer was too large",
        ureq::Error::Io(_) => "the connection to resend failed",
        _ => "the request to resend failed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn senders_are_validated_and_normalized() {
        assert_eq!(
            Sender::parse("Sentinel CI <CI@Example.com>").unwrap().as_str(),
            "Sentinel CI <ci@example.com>"
        );
        assert_eq!(Sender::parse("ci@example.com").unwrap().as_str(), "ci@example.com");
        assert_eq!(
            Sender::parse("\"Sentinel\" <ci@example.com>").unwrap().as_str(),
            "Sentinel <ci@example.com>"
        );
        for bad in [
            "",
            "ci",
            "<ci@example.com",
            "ci@example.com>",
            "A\r\nBcc: x@y.z <ci@example.com>",
            "A<B <ci@example.com>",
            "A, B <ci@example.com>",
            "Name <not an address>",
        ] {
            assert!(Sender::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Sender::parse(&format!("{} <ci@example.com>", "n".repeat(65))).is_err());
    }

    #[test]
    fn keys_are_visible_ascii_and_never_printed() {
        assert!(ApiKey::new(b"re_abc123".to_vec()).is_ok());
        for bad in [&b""[..], b"re abc", b"re\r\nabc", b"caf\xc3\xa9"] {
            assert!(ApiKey::new(bad.to_vec()).is_err());
        }
        assert!(ApiKey::new(vec![b'a'; 513]).is_err());
        let key = ApiKey::new(b"re_secret".to_vec()).unwrap();
        assert!(!format!("{key:?}").contains("secret"));
    }

    #[test]
    fn html_escapes_the_text() {
        let out = html("a <b> & \"c\"\nline");
        assert!(out.contains("a &lt;b&gt; &amp; &quot;c&quot;<br>"));
        assert!(!out.contains("<b>"));
    }
}
