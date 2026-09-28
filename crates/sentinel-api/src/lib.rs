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
mod github;
mod http;
mod mcp;
mod metrics;
mod oauth;
mod routes;
mod secret_routes;

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Duration,
};

use sentinel_core::UserId;
use sentinel_link::controller::Handle;
use sentinel_store::{Store, logs::LogStore, objects::Objects};

pub use github::GithubSignIn;
pub use oauth::limit::TrustedProxy;

/// Requests being handled at once; further connections wait on a permit.
pub const WORKERS: usize = 8;
/// Connections held at once (one reader thread each); further handshakes
/// wait in the listener backlog.
pub const CONNECTIONS: usize = 64;
/// How long a `wait=1` log poll holds before answering with nothing new.
pub const LOG_WAIT: Duration = Duration::from_secs(25);
/// Upload/download bodies in flight at once (D02), counted until the last
/// byte is written — a download's slot travels with its streamed body.
/// Beyond this the API answers `rate_limited` rather than queue unbounded
/// transfer work.
pub const TRANSFERS: usize = 3;
/// Long-poll subscribers parked at once — run waits and `wait=1` log polls
/// together, including every live view of the web interface (U03/U04).
/// A parked poll holds its connection but gives its handler permit back
/// while it waits, so parked polls never starve requests doing work.
/// Beyond it a poll is `rate_limited` with `details.retry_after_ms`.
pub const SUBSCRIBERS: usize = 32;
/// Of those, how many one user (a person or a service account, whatever
/// credential it presents) may hold at once: a single credential looping
/// parked polls can never take every slot from everyone else (P09-12).
pub const SUBSCRIBERS_PER_USER: usize = 8;
const _: () = assert!(
    SUBSCRIBERS_PER_USER >= 1 && SUBSCRIBERS_PER_USER < SUBSCRIBERS,
    "one user must leave a subscriber slot for others"
);
const _: () = assert!(
    CONNECTIONS - SUBSCRIBERS >= 16,
    "parked polls must leave connections for everything else"
);
/// Handler permits transfers cannot take: however many slow bodies there
/// are (parked polls hold none), this many requests — logins, token
/// refreshes, health checks, run reads — are always served.
pub const RESERVED_HANDLERS: usize = WORKERS - TRANSFERS;
const _: () = assert!(
    RESERVED_HANDLERS >= 2,
    "keep handler permits for control requests"
);
/// Handler permits that outbound calls to third parties may hold at once:
/// GitHub sign-in's code exchange (up to two ten-second calls) and Client ID
/// Metadata Document fetches (two seconds) draw on this one budget. A
/// request past it is answered "busy, retry" at once, never queued, so with
/// [`TRANSFERS`] (parked polls hold none) a handler always remains for logins,
/// token refreshes, health checks and run reads — however slow the third
/// party, and however many anonymous or signed-in callers ask.
pub const OUTBOUND: usize = 1;
const _: () = assert!(
    WORKERS - TRANSFERS - OUTBOUND >= 1,
    "keep a handler permit for control requests"
);

/// The [`OUTBOUND`] budget.
#[derive(Default)]
pub(crate) struct Outbound(AtomicUsize);

/// One held outbound slot, released on drop (unwinding included).
pub(crate) struct OutboundSlot<'a>(&'a AtomicUsize);

impl Drop for OutboundSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Outbound {
    /// Take a slot without waiting, or `None` when all are held.
    pub(crate) fn take(&self) -> Option<OutboundSlot<'_>> {
        use std::sync::atomic::Ordering;
        let mut held = self.0.load(Ordering::Acquire);
        loop {
            if held >= OUTBOUND {
                return None;
            }
            match self
                .0
                .compare_exchange_weak(held, held + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(OutboundSlot(&self.0)),
                Err(next) => held = next,
            }
        }
    }
}

/// Largest single upload chunk; resume boundaries let clients pick smaller.
pub const MAX_UPLOAD_CHUNK: usize = 8 << 20;

pub struct Config {
    pub listen: SocketAddr,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    /// Deployment master key for sealed secret values. Secret routes remain
    /// unavailable until the operator has initialized it.
    pub secret_key: Option<Arc<sentinel_auth::sealed::Key>>,
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
    /// GitHub web sign-in (U07). Without it the `/auth/github/*` routes do
    /// not exist and no page offers the button.
    pub github_sign_in: Option<GithubSignIn>,
    /// The reverse proxy's networks: only a request from one of these is
    /// counted under its `X-Forwarded-For` address by the unauthenticated
    /// admission budgets. [`TrustedProxy::loopback`] by default.
    pub trusted_proxies: Vec<TrustedProxy>,
}

pub(crate) struct State {
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    pub secret_key: Option<Arc<sentinel_auth::sealed::Key>>,
    pub sessions: sentinel_store::local_auth::Policy,
    pub github_webhook_secret: Option<Arc<[u8]>>,
    pub intake: Option<sentinel_intake::Waker>,
    /// Upload/download bodies currently in flight. Shared with the body a
    /// download streams after its route returned.
    pub transfers: Arc<AtomicUsize>,
    /// Long-poll subscribers currently parked (run waits and `wait=1` log
    /// polls), bounded in total so they cannot take every handler permit and
    /// per user so one user cannot take every slot.
    pub subscribers: Subscribers,
    /// Set by `Server::shutdown`; the `wait=1` log poll checks it so a
    /// stop does not ride out the full poll interval.
    pub stop: Arc<AtomicBool>,
    /// The OAuth authorization server's issuer, keys and in-memory limits.
    pub oauth: oauth::OAuthState,
    /// Bounded, expiring Streamable HTTP MCP sessions.
    pub mcp_sessions: mcp::Sessions,
    /// GitHub web sign-in, when configured.
    pub github: Option<github::Github>,
    /// Networks whose `X-Forwarded-For` is believed ([`Config::trusted_proxies`]).
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Outbound calls to third parties in flight ([`OUTBOUND`]).
    pub outbound: Outbound,
    /// What every answered request adds to `/metrics` (R06).
    pub requests: metrics::Requests,
}

/// Who holds the parked long-poll slots: at most [`SUBSCRIBERS`] in total
/// and [`SUBSCRIBERS_PER_USER`] per user. A fixed table, never a map: with
/// at most `SUBSCRIBERS` slots held there are at most that many distinct
/// holders, so a take or a release is one short lock and a scan of at most
/// that many entries, and nothing grows with the number of users.
#[derive(Default)]
pub(crate) struct Subscribers {
    held: Mutex<[(Option<UserId>, u8); SUBSCRIBERS]>,
}

/// Why a parked slot was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubscriberRefusal {
    /// Every slot is parked.
    Full,
    /// This user already holds its share.
    UserFull,
}

impl Subscribers {
    /// Slots parked right now.
    pub(crate) fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(_, n)| usize::from(*n))
            .sum()
    }

    /// Take one slot for `user`, released when the guard drops.
    pub(crate) fn take(&self, user: UserId) -> Result<Subscriber<'_>, SubscriberRefusal> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        let total: usize = held.iter().map(|(_, n)| usize::from(*n)).sum();
        if total >= SUBSCRIBERS {
            return Err(SubscriberRefusal::Full);
        }
        let entry = match held.iter().position(|(u, _)| *u == Some(user)) {
            Some(i) => i,
            // Fewer than SUBSCRIBERS slots are held, so fewer holders than
            // entries: a free entry exists.
            None => held
                .iter()
                .position(|(_, n)| *n == 0)
                .ok_or(SubscriberRefusal::Full)?,
        };
        let (holder, count) = &mut held[entry];
        if usize::from(*count) >= SUBSCRIBERS_PER_USER {
            return Err(SubscriberRefusal::UserFull);
        }
        *holder = Some(user);
        *count += 1;
        Ok(Subscriber { table: self, user })
    }

    fn release(&self, user: UserId) {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((holder, count)) = held.iter_mut().find(|(u, _)| *u == Some(user)) {
            *count -= 1;
            if *count == 0 {
                *holder = None;
            }
        }
    }
}

/// One parked long poll's slot; dropping it frees the slot.
pub(crate) struct Subscriber<'a> {
    table: &'a Subscribers,
    user: UserId,
}

impl Drop for Subscriber<'_> {
    fn drop(&mut self) {
        self.table.release(self.user);
    }
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
        let github = config
            .github_sign_in
            .map(|sign_in| github::Github::new(sign_in, &issuer))
            .transpose()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("GitHub sign-in: {e}"),
                )
            })?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            store: config.store,
            logs: config.logs,
            objects: config.objects,
            controller: config.controller,
            secret_key: config.secret_key,
            sessions: config.sessions,
            github_webhook_secret: config.github_webhook_secret,
            intake: config.intake,
            transfers: Arc::new(AtomicUsize::new(0)),
            subscribers: Subscribers::default(),
            stop: Arc::clone(&stop),
            oauth: oauth::OAuthState::new(issuer.clone()),
            mcp_sessions: mcp::Sessions::default(),
            github,
            trusted_proxies: config.trusted_proxies,
            outbound: Outbound::default(),
            requests: metrics::Requests::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// P09S-1 / P11-2: however many requests want an outbound call at once
    /// (a CIMD fetch or a GitHub exchange), at most [`OUTBOUND`] hold a
    /// handler on a third party; the rest are refused without waiting, and
    /// a slot is returned when its call ends, even by unwinding.
    #[test]
    fn outbound_calls_are_capped_without_queueing() {
        let outbound = Outbound::default();
        let first = outbound.take().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| assert!(outbound.take().is_none()));
            }
        });
        drop(first);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = outbound.take().unwrap();
            panic!("the call failed");
        }));
        assert!(unwound.is_err());
        assert!(outbound.take().is_some());
    }
}
