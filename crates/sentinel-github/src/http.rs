use std::time::Duration;

use crate::{Error, Result};

const MAX_BODY: u64 = 64 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Client {
    agent: ureq::Agent,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn post_authenticated(
        &self,
        url: &str,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let body = serde_json::to_vec(body).map_err(|_| Error::Config("request body"))?;
        if body.len() > MAX_BODY as usize {
            return Err(Error::Config("request size"));
        }
        let response = self
            .agent
            .post(url)
            .header("accept", "application/vnd.github+json")
            .header("content-type", "application/json")
            .header("x-github-api-version", "2022-11-28")
            .header("authorization", &format!("Bearer {token}"))
            .send(body.as_slice())
            .map_err(transport)?;
        json(response)
    }
    pub fn new() -> Client {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .max_redirects(0)
            .max_response_header_size(MAX_HEADERS)
            // GitHub reports OAuth failures as 200 with a body; statuses are data, not errors.
            .http_status_as_error(false)
            .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
            .build();
        Client {
            agent: ureq::Agent::new_with_config(config),
        }
    }

    /// The secret travels in the body, not in a URL that a log could record.
    pub fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<serde_json::Value> {
        let response = self
            .agent
            .post(url)
            .header("accept", "application/json")
            .send_form(fields.iter().copied())
            .map_err(transport)?;
        json(response)
    }

    pub fn get_authenticated(&self, url: &str, token: &str) -> Result<serde_json::Value> {
        let response = self
            .agent
            .get(url)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("authorization", &format!("Bearer {token}"))
            .call()
            .map_err(transport)?;
        json(response)
    }

    /// An unauthenticated empty `POST` whose answer may carry credentials: the response text is
    /// wiped once parsed, and the caller moves the secrets out of the returned value.
    pub fn post_anonymous(&self, url: &str) -> Result<Reply> {
        let mut response = self
            .agent
            .post(url)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .send_empty()
            .map_err(transport)?;
        let status = response.status().as_u16();
        let mut text = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(transport)?;
        let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        sentinel_auth::secret::wipe_string(&mut text);
        Ok(Reply {
            status,
            retry_after_s: None,
            rate_limit_reset_s: None,
            body,
        })
    }

    pub fn send_json(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply> {
        self.send_json_bounded(method, url, token, body, MAX_BODY)
    }

    pub fn send_json_bounded(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&serde_json::Value>,
        max_body: u64,
    ) -> Result<Reply> {
        let encoded = match body {
            Some(value) => {
                Some(serde_json::to_vec(value).map_err(|_| Error::Config("request body"))?)
            }
            None => None,
        };
        if encoded
            .as_ref()
            .is_some_and(|b| b.len() > MAX_BODY as usize)
        {
            return Err(Error::Config("request size"));
        }
        if !matches!(method, "GET" | "POST" | "PATCH") {
            return Err(Error::Config("request method"));
        }
        let request = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .header("accept", "application/vnd.github+json")
            .header("content-type", "application/json")
            .header("x-github-api-version", "2022-11-28")
            .header("authorization", &format!("Bearer {token}"))
            .body(encoded.unwrap_or_default())
            .map_err(|_| Error::Config("request"))?;
        let response = self.agent.run(request).map_err(transport)?;
        reply(response, max_body)
    }
}

pub struct Reply {
    pub status: u16,
    pub retry_after_s: Option<i64>,
    pub rate_limit_reset_s: Option<i64>,
    pub body: serde_json::Value,
}

fn reply(mut response: ureq::http::Response<ureq::Body>, max_body: u64) -> Result<Reply> {
    let status = response.status().as_u16();
    let header = |name: &str| -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let retry_after_s = header("retry-after").and_then(|v| v.trim().parse::<i64>().ok());
    let remaining_zero = header("x-ratelimit-remaining").as_deref() == Some("0");
    let rate_limit_reset_s = if remaining_zero {
        header("x-ratelimit-reset").and_then(|v| v.trim().parse::<i64>().ok())
    } else {
        None
    };
    let body = response
        .body_mut()
        .with_config()
        .limit(max_body)
        .read_to_string()
        .map_err(transport)?;
    let body = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    Ok(Reply {
        status,
        retry_after_s,
        rate_limit_reset_s,
        body,
    })
}

fn json(mut response: ureq::http::Response<ureq::Body>) -> Result<serde_json::Value> {
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_string()
        .map_err(transport)?;
    if !(200..300).contains(&status) {
        return Err(Error::Transport(format!("status {status}")));
    }
    serde_json::from_str(&body).map_err(|_| Error::Response("body is not JSON"))
}

/// Summarized by kind: ureq messages can include the URL, which may carry a credential.
fn transport(error: impl Into<TransportKind>) -> Error {
    Error::Transport(error.into().0)
}

pub struct TransportKind(String);

impl From<ureq::Error> for TransportKind {
    fn from(error: ureq::Error) -> Self {
        TransportKind(
            match error {
                ureq::Error::Timeout(_) => "timed out",
                ureq::Error::ConnectionFailed => "connection failed",
                ureq::Error::Io(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionReset => "connection reset",
                    std::io::ErrorKind::UnexpectedEof => "connection closed early",
                    std::io::ErrorKind::ConnectionAborted => "connection aborted",
                    _ => "io",
                },
                ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => "redirected",
                ureq::Error::BodyExceedsLimit(_) => "response too large",
                ureq::Error::Tls(_) => "TLS failed",
                _ => "request rejected",
            }
            .to_owned(),
        )
    }
}
