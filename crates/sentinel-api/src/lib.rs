//! TLS is the reverse proxy's job: the `__Host-` session cookie reaches a browser only over HTTPS or localhost.

pub mod auth;
mod github;
mod github_app;
mod http;
mod login_guard;
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
pub use github_app::{Activation, AppSource, GithubAppSetup, OnActivate};
pub use oauth::limit::TrustedProxy;

pub const WORKERS: usize = 8;
pub const CONNECTIONS: usize = 64;
/// Connections one peer address (an IPv6 /64 counts as one) may hold; a configured reverse proxy is exempt.
pub const CONNECTIONS_PER_PEER: usize = 16;
pub const PUBLIC_BODIES: usize = 4;
pub const LOG_WAIT: Duration = Duration::from_secs(25);
pub const TRANSFERS: usize = 3;
pub const SUBSCRIBERS: usize = 32;
pub const SUBSCRIBERS_PER_USER: usize = 8;
const _: () = assert!(
    SUBSCRIBERS_PER_USER >= 1 && SUBSCRIBERS_PER_USER < SUBSCRIBERS,
    "one user must leave a subscriber slot for others"
);
const _: () = assert!(
    CONNECTIONS - SUBSCRIBERS >= 16,
    "parked polls must leave connections for everything else"
);
pub const RESERVED_HANDLERS: usize = WORKERS - TRANSFERS;
const _: () = assert!(
    RESERVED_HANDLERS >= 2,
    "keep handler permits for control requests"
);
/// Keeps a handler permit free for control requests: a third-party call past the budget is refused, never queued.
pub const OUTBOUND: usize = 1;
const _: () = assert!(
    WORKERS - TRANSFERS - 4 * OUTBOUND >= 1,
    "keep a handler permit for control requests"
);

#[derive(Default)]
pub(crate) struct Outbound(AtomicUsize);

pub(crate) struct OutboundSlot<'a>(&'a AtomicUsize);

impl Drop for OutboundSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Outbound {
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

pub const MAX_UPLOAD_CHUNK: usize = 8 << 20;

pub struct Config {
    pub listen: SocketAddr,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    pub secret_key: Option<Arc<sentinel_auth::sealed::Key>>,
    pub sessions: sentinel_store::local_auth::Policy,
    pub github_webhook_secret: Option<Arc<[u8]>>,
    pub intake: Option<sentinel_intake::Waker>,
    pub public_url: Option<String>,
    pub github_sign_in: Option<GithubSignIn>,
    pub trusted_proxies: Vec<TrustedProxy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoJoinRule {
    pub domain: String,
    pub organization: String,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub auto_join: Vec<AutoJoinRule>,
    pub mail: Option<Arc<sentinel_mail::Resend>>,
    /// The GitHub App in force and the one-click manifest flow ([`GithubAppSetup`]).
    pub github_app: GithubAppSetup,
}

pub(crate) struct State {
    pub auto_join: Vec<AutoJoinRule>,
    pub mail: Option<Arc<sentinel_mail::Resend>>,
    pub setup_mail: Outbound,
    pub setup_closed: AtomicBool,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub objects: Arc<Objects>,
    pub controller: Handle,
    pub secret_key: Option<Arc<sentinel_auth::sealed::Key>>,
    pub sessions: sentinel_store::local_auth::Policy,
    /// Set at most once: at start, or when a manifest conversion puts a new App in force.
    pub github_webhook_secret: std::sync::OnceLock<Arc<[u8]>>,
    pub intake: Option<sentinel_intake::Waker>,
    pub transfers: Arc<AtomicUsize>,
    pub subscribers: Subscribers,
    pub stop: Arc<AtomicBool>,
    pub oauth: oauth::OAuthState,
    pub mcp_sessions: mcp::Sessions,
    pub github: std::sync::OnceLock<github::Github>,
    pub github_app: github_app::Runtime,
    pub trusted_proxies: Vec<TrustedProxy>,
    pub fetches: Outbound,
    pub logins: login_guard::LoginGuard,
    pub exchanges: Outbound,
    pub requests: metrics::Requests,
}

#[derive(Default)]
pub(crate) struct Subscribers {
    held: Mutex<[(Option<UserId>, u8); SUBSCRIBERS]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubscriberRefusal {
    Full,
    UserFull,
}

impl Subscribers {
    pub(crate) fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(_, n)| usize::from(*n))
            .sum()
    }

    pub(crate) fn take(&self, user: UserId) -> Result<Subscriber<'_>, SubscriberRefusal> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        let total: usize = held.iter().map(|(_, n)| usize::from(*n)).sum();
        if total >= SUBSCRIBERS {
            return Err(SubscriberRefusal::Full);
        }
        let entry = match held.iter().position(|(u, _)| *u == Some(user)) {
            Some(i) => i,
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
        Server::start_with(config, Options::default())
    }

    pub fn start_with(config: Config, options: Options) -> std::io::Result<Server> {
        let listener = std::net::TcpListener::bind(config.listen)?;
        let addr = listener.local_addr()?;
        let issuer = match &config.public_url {
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
        let proxies = config.trusted_proxies.clone();
        let github = github.map(std::sync::OnceLock::from).unwrap_or_default();
        let github_webhook_secret = config
            .github_webhook_secret
            .map(std::sync::OnceLock::from)
            .unwrap_or_default();
        let github_app = github_app::Runtime::new(
            options.github_app,
            config
                .public_url
                .as_deref()
                .map(|url| url.trim_end_matches('/')),
        );
        let state = Arc::new(State {
            auto_join: options.auto_join,
            mail: options.mail,
            setup_mail: Outbound::default(),
            setup_closed: AtomicBool::new(false),
            store: config.store,
            logs: config.logs,
            objects: config.objects,
            controller: config.controller,
            secret_key: config.secret_key,
            sessions: config.sessions,
            github_webhook_secret,
            intake: config.intake,
            transfers: Arc::new(AtomicUsize::new(0)),
            subscribers: Subscribers::default(),
            stop: Arc::clone(&stop),
            oauth: oauth::OAuthState::new(issuer.clone()),
            mcp_sessions: mcp::Sessions::default(),
            github,
            github_app,
            trusted_proxies: config.trusted_proxies,
            fetches: Outbound::default(),
            logins: login_guard::LoginGuard::default(),
            exchanges: Outbound::default(),
            requests: metrics::Requests::default(),
        });
        let conns = http::listen(
            listener,
            Arc::new(move |request| routes::handle(&state, request)),
            stop,
            http::Tune::DEFAULT,
            proxies,
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

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn shutdown(self) {
        self.conns.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
