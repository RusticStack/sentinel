//! The controller's HTTP API (W08): the one surface the CLI, the web page
//! and later MCP share. Plain HTTP/1.1 on a bounded thread pool; TLS is
//! the reverse proxy's job (the session cookie is `__Host-`, which a
//! browser accepts from `localhost` or over HTTPS only).
//!
//! Every route authenticates a bearer credential or a session cookie into
//! a `Principal` and then authorizes through `sentinel-store::auth` — the
//! API never reads a tenant's rows without the predicate that says the
//! caller may. Errors are `sentinel.error/1`; mutations take an
//! `Idempotency-Key`; bodies are bounded before they are read.

pub mod auth;
mod routes;
mod web;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_link::controller::Handle;
use sentinel_store::{Store, logs::LogStore};

/// Threads answering requests at once; the rest queue on the listener.
pub const WORKERS: usize = 8;
/// How long a `wait=1` log poll holds before answering with nothing new.
pub const LOG_WAIT: Duration = Duration::from_secs(25);

pub struct Config {
    pub listen: SocketAddr,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub controller: Handle,
    /// Session policy for password logins.
    pub sessions: sentinel_store::local_auth::Policy,
}

pub(crate) struct State {
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub controller: Handle,
    pub sessions: sentinel_store::local_auth::Policy,
    pub stop: AtomicBool,
}

pub struct Server {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    state: Arc<State>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Server {
    pub fn start(config: Config) -> std::io::Result<Server> {
        let server = tiny_http::Server::http(config.listen)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let addr = match server.server_addr() {
            tiny_http::ListenAddr::IP(addr) => addr,
            #[allow(unreachable_patterns)]
            _ => config.listen,
        };
        let server = Arc::new(server);
        let state = Arc::new(State {
            store: config.store,
            logs: config.logs,
            controller: config.controller,
            sessions: config.sessions,
            stop: AtomicBool::new(false),
        });
        let mut threads = Vec::with_capacity(WORKERS);
        for index in 0..WORKERS {
            let (server, state) = (Arc::clone(&server), Arc::clone(&state));
            threads.push(
                thread::Builder::new()
                    .name(format!("sentinel-api-{index}"))
                    .spawn(move || {
                        while !state.stop.load(Ordering::Acquire) {
                            match server.recv_timeout(Duration::from_millis(250)) {
                                Ok(Some(request)) => routes::handle(&state, request),
                                Ok(None) => {}
                                Err(_) => break,
                            }
                        }
                    })?,
            );
        }
        Ok(Server {
            addr,
            server,
            state,
            threads,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting and wait for the worker threads.
    pub fn shutdown(self) {
        self.state.stop.store(true, Ordering::Release);
        self.server.unblock();
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}
