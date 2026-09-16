//! The controller's HTTP API (W08): the one surface the CLI, the web page
//! and later MCP share. Plain HTTP/1.1 on a bounded set of connection
//! threads and handler permits; TLS is the reverse proxy's job (the
//! session cookie is `__Host-`, which a browser accepts from `localhost`
//! or over HTTPS only).
//!
//! Every route authenticates a bearer credential or a session cookie into
//! a `Principal` and then authorizes through `sentinel-store::auth` — the
//! API never reads a tenant's rows without the predicate that says the
//! caller may. Errors are `sentinel.error/1`; mutations take an
//! `Idempotency-Key`; bodies are bounded before they are read.

pub mod auth;
mod http;
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
/// Upload/download bodies in flight at once (D02). Beyond this the API
/// answers `rate_limited` rather than queue unbounded transfer work.
pub const TRANSFERS: usize = 4;
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
}

pub(crate) struct State {
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    pub sessions: sentinel_store::local_auth::Policy,
    pub github_webhook_secret: Option<Arc<[u8]>>,
    pub intake: Option<sentinel_intake::Waker>,
    /// Upload/download bodies currently in flight.
    pub transfers: AtomicUsize,
    /// Set by `Server::shutdown`; the `wait=1` log poll checks it so a
    /// stop does not ride out the full poll interval.
    pub stop: Arc<AtomicBool>,
}

pub struct Server {
    addr: SocketAddr,
    conns: http::Conns,
}

impl Server {
    pub fn start(config: Config) -> std::io::Result<Server> {
        let listener = std::net::TcpListener::bind(config.listen)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            store: config.store,
            logs: config.logs,
            objects: config.objects,
            controller: config.controller,
            sessions: config.sessions,
            github_webhook_secret: config.github_webhook_secret,
            intake: config.intake,
            transfers: AtomicUsize::new(0),
            stop: Arc::clone(&stop),
        });
        let conns = http::listen(
            listener,
            Arc::new(move |request| routes::handle(&state, request)),
            stop,
            http::Tune::DEFAULT,
        )?;
        Ok(Server { addr, conns })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting, close live connections and wait out the readers.
    pub fn shutdown(self) {
        self.conns.close();
    }
}
