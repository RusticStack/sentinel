//! Redirects are not followed and proxies are ignored: the API key must never travel to another host.
//! Errors carry Resend's error name only, never its message, which may quote an address.

use std::{path::Path, time::Duration};

use sentinel_auth::secret::{wipe, wipe_string};

use crate::{Failure, Mail, Transport};

const ENDPOINT: &str = "https://api.resend.com/emails";
pub const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_SUBJECT_CHARS: usize = 200;
pub const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_KEY_BYTES: usize = 512;
const MAX_KEY_FILE_BYTES: usize = 4096;
const MAX_DISPLAY_NAME_CHARS: usize = 64;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sender {
    header: String,
}

impl Sender {
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
            && !name.chars().any(|c| {
                c.is_control() || matches!(c, '<' | '>' | '"' | '\\' | ',' | ';' | '@' | ':')
            });
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

fn agent(https_only: bool, total: Duration) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(total))
        .max_redirects(0)
        .proxy(None)
        .https_only(https_only)
        .max_response_header_size(MAX_HEADERS)
        .http_status_as_error(false)
        .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(config)
}

impl Resend {
    pub fn new(key: ApiKey, from: Sender) -> Resend {
        Resend {
            agent: agent(true, TOTAL_TIMEOUT),
            endpoint: ENDPOINT.to_owned(),
            key,
            from,
        }
    }

    #[cfg(feature = "test-endpoint")]
    pub fn with_endpoint(key: ApiKey, from: Sender, endpoint: &str) -> Resend {
        Resend {
            agent: agent(false, TOTAL_TIMEOUT),
            endpoint: endpoint.to_owned(),
            key,
            from,
        }
    }

    #[cfg(feature = "test-endpoint")]
    pub fn with_total_timeout(mut self, total: Duration) -> Resend {
        self.agent = agent(false, total);
        self
    }

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
        let mut bearer = self.key.bearer();
        let request = ureq::http::Request::builder()
            .method("POST")
            .uri(self.endpoint.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("authorization", bearer.as_str())
            .header("idempotency-key", idempotency_key(mail))
            .body(body);
        // Best effort: the request holds its own copy of the header, which this crate cannot reach.
        wipe_string(&mut bearer);
        let request =
            request.map_err(|_| Failure::Permanent("the request cannot be built".into()))?;
        let mut response = self.agent.run(request).map_err(transport)?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(());
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
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

pub fn idempotency_key(mail: &Mail<'_>) -> String {
    format!("sentinel-mail-{}", mail.id)
}

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

fn error_name(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let name = value.get("name")?.as_str()?;
    let plausible = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    plausible.then(|| name.to_owned())
}

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
        // The same answer for every message: the key or the sender, not this message. A 403 with any other name may be
        // about one resource, so it stays a refusal of this message.
        401 => Err(Failure::Service(label("refused the API key"))),
        403 if matches!(
            name,
            Some("invalid_api_key" | "restricted_api_key" | "missing_api_key" | "validation_error")
        ) =>
        {
            Err(Failure::Service(label("refused the API key or the sender")))
        }
        403 => Err(Failure::Permanent(label("refused the message"))),
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
        _ => Err(Failure::Transient {
            why: label("answered unexpectedly"),
            retry_after,
        }),
    }
}

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
            Sender::parse("Sentinel CI <CI@Example.com>")
                .unwrap()
                .as_str(),
            "Sentinel CI <ci@example.com>"
        );
        assert_eq!(
            Sender::parse("ci@example.com").unwrap().as_str(),
            "ci@example.com"
        );
        assert_eq!(
            Sender::parse("\"Sentinel\" <ci@example.com>")
                .unwrap()
                .as_str(),
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
