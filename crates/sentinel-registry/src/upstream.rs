//! The upstream side: one request at a time, with the client's credential relayed and never kept.
//!
//! A pull that misses asks the registry it names for exactly what the client asked for, with the same
//! `Authorization` header the client sent (a plaintext credential for the registry's own basic auth, or
//! the bearer token the client obtained from the registry's token service). A `401` is relayed with its
//! `WWW-Authenticate` challenge so the client performs its own token exchange and retries: the cache
//! never mints, decodes or stores a credential.

use std::time::Duration;

use crate::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The upstream's headers for one request. A registry that has not answered by now is not serving this pull.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest a body may stall before the fetch is abandoned; a large layer legitimately takes minutes.
const BODY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HEADER_BYTES: usize = 64 << 10;

pub(crate) struct Upstream {
    agent: ureq::Agent,
}

pub(crate) struct Fetched {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) content_length: Option<u64>,
    pub(crate) challenge: Option<String>,
    body: ureq::Body,
}

impl Fetched {
    pub(crate) fn into_reader(self) -> impl std::io::Read + Send + 'static {
        self.body.into_reader()
    }
}

impl Upstream {
    pub(crate) fn new() -> Result<Upstream> {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_connect(Some(CONNECT_TIMEOUT))
                .timeout_recv_response(Some(RESPONSE_TIMEOUT))
                .timeout_recv_body(Some(BODY_TIMEOUT))
                // A registry answers where it is asked: a redirect is a registry the cache has not been
                // configured for, and it is refused rather than followed.
                .max_redirects(0)
                .http_status_as_error(false)
                .max_response_header_size(MAX_HEADER_BYTES)
                .user_agent(concat!("sentinel-registry/", env!("CARGO_PKG_VERSION")))
                .build(),
        );
        Ok(Upstream { agent })
    }

    pub(crate) fn get(
        &self,
        method: &str,
        url: &str,
        auth: Option<&str>,
        accept: Option<&str>,
    ) -> Result<Fetched> {
        let method = ureq::http::Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::Config("request method".into()))?;
        let mut request = ureq::http::Request::builder().method(method).uri(url);
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let request = request
            .body(())
            .map_err(|_| Error::Config("request shape".into()))?;
        let response = self
            .agent
            .run(request)
            .map_err(|error| Error::Upstream(transport(&error)))?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        Ok(Fetched {
            status: response.status().as_u16(),
            content_type: header("content-type"),
            content_length: header("content-length").and_then(|value| value.trim().parse().ok()),
            challenge: header("www-authenticate"),
            body: response.into_body(),
        })
    }
}

fn transport(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timed out".into(),
        ureq::Error::Io(error) => format!("i/o: {}", error.kind()),
        ureq::Error::HostNotFound => "host not found".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::TooManyRedirects => "too many redirects".into(),
        other => format!("{other:?}").chars().take(64).collect::<String>(),
    }
}
