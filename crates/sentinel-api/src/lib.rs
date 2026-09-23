//! The controller's HTTP API (W08): the one surface the CLI, the web page
//! and later MCP share. Plain HTTP/1.1 on a bounded set of connection
//! threads and handler permits; TLS is the reverse proxy's job (the
//! session cookie is `__Host-`, which a browser accepts from `localhost`
//! or over HTTPS only).
//!
//! Every route authenticates a bearer credential, an OAuth access token or
//! a session cookie into a `Principal` and its scopes, then authorizes
//! through `sentinel-store::auth` — the API never reads a tenant's rows
//! without the predicate that says the caller may. Errors are
//! `sentinel.error/1` under `/api/v1` and RFC 6749 under `/oauth`;
//! mutations take an `Idempotency-Key`; bodies are bounded before they are
//! read. The OAuth authorization server (O01–O06) lives in [`oauth`].

pub mod auth;
mod http;
mod oauth;
mod routes;
mod web;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Duration,
};

use sentinel_link::controller::Handle;
use sentinel_store::{Store, logs::LogStore, objects::Objects};

/// Requests being handled at once; further connections wait on a permit.
pub const WORKERS: usize = 8;
/// How long a `wait=1` log poll holds before answering with nothing new.
pub const LOG_WAIT: Duration = Duration::from_secs(25);
/// Upload/download bodies in flight at once (D02), counted until the last
/// byte is written — a download's slot travels with its streamed body.
/// Beyond this the API answers `rate_limited` rather than queue unbounded
/// transfer work.
pub const TRANSFERS: usize = 3;
/// Long-poll subscribers parked at once — run waits and `wait=1` log polls
/// together. Beyond it a poll is `rate_limited` with
/// `details.retry_after_ms`.
pub const SUBSCRIBERS: usize = 3;
/// Handler permits neither transfers nor long polls can take: however many
/// slow bodies and parked polls there are, this many requests — logins,
/// token refreshes, health checks, run reads — are always served.
pub const RESERVED_HANDLERS: usize = WORKERS - TRANSFERS - SUBSCRIBERS;
const _: () = assert!(
    RESERVED_HANDLERS >= 2,
    "keep handler permits for control requests"
);
/// Largest single upload chunk; resume boundaries let clients pick smaller.
pub const MAX_UPLOAD_CHUNK: usize = 8 << 20;

pub struct Config {
    pub listen: SocketAddr,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    /// Session policy for password logins.
    pub sessions: sentinel_store::local_auth::Policy,
    /// The GitHub App webhook secret, when one is configured. Without it the
    /// GitHub intake route does not exist.
    pub github_webhook_secret: Option<Arc<[u8]>>,
    /// Wakes the resolution lane after an accepted delivery.
    pub intake: Option<sentinel_intake::Waker>,
    /// The deployment-facing base URL (`https://ci.example.com`, no trailing
    /// slash). It is the OAuth issuer; without it the issuer is
    /// `http://{bound address}`, which is right only for direct loopback use.
    pub public_url: Option<String>,
}

pub(crate) struct State {
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    pub sessions: sentinel_store::local_auth::Policy,
    pub github_webhook_secret: Option<Arc<[u8]>>,
    pub intake: Option<sentinel_intake::Waker>,
    /// Upload/download bodies currently in flight. Shared with the body a
    /// download streams after its route returned.
    pub transfers: Arc<AtomicUsize>,
    /// Long-poll subscribers currently parked (run waits and `wait=1` log
    /// polls), bounded so they cannot take every handler permit.
    pub subscribers: Arc<AtomicUsize>,
    /// Set by `Server::shutdown`; the `wait=1` log poll checks it so a
    /// stop does not ride out the full poll interval.
    pub stop: Arc<AtomicBool>,
    /// The OAuth authorization server's issuer, keys and in-memory limits.
    pub oauth: oauth::OAuthState,
}

pub struct Server {
    addr: SocketAddr,
    issuer: String,
    conns: http::Conns,
}

impl Server {
    pub fn start(config: Config) -> std::io::Result<Server> {
        let listener = std::net::TcpListener::bind(config.listen)?;
        let addr = listener.local_addr()?;
        let issuer = match config.public_url {
            Some(url) => url.trim_end_matches('/').to_owned(),
            None => format!("http://{addr}"),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            store: config.store,
            logs: config.logs,
            objects: config.objects,
            controller: config.controller,
            sessions: config.sessions,
            github_webhook_secret: config.github_webhook_secret,
            intake: config.intake,
            transfers: Arc::new(AtomicUsize::new(0)),
            subscribers: Arc::new(AtomicUsize::new(0)),
            stop: Arc::clone(&stop),
            oauth: oauth::OAuthState::new(issuer.clone()),
        });
        let conns = http::listen(
            listener,
            Arc::new(move |request| routes::handle(&state, request)),
            stop,
            http::Tune::DEFAULT,
        )?;
        Ok(Server {
            addr,
            issuer,
            conns,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The OAuth issuer this server publishes in its metadata.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Stop accepting, close live connections and wait out the readers.
    pub fn shutdown(self) {
        self.conns.close();
    }
}
