//! A registry pull-through cache for the worker host: one loopback endpoint answers a rootless Podman
//! pull from verified local disk, and only a miss reaches the upstream registry.
//!
//! The endpoint speaks the OCI distribution API's read half — `/v2/`, manifests by tag and by digest,
//! blobs by digest, `GET` and `HEAD`, and single-range blob reads — and refuses everything else with a
//! typed error instead of forwarding it. A manifest and every blob are verified against their digest
//! before they are stored and again while they are served, so a corrupted or partial body never reaches
//! the client as a complete answer. Tags are revalidated every [`TAG_TTL`]; a digest names immutable
//! content and is kept until eviction.
//!
//! Storage is content-addressed under `<data_dir>/registry` and scoped: anonymous pulls share one
//! [`Scope`], and a pull that carries registry credentials uses its own tenant scope, split again by the
//! job's trust class. Credentials are relayed to the upstream for the request that needs them and never
//! written anywhere.

use std::{
    fmt, io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use sentinel_protocol::cache::Trust;

pub mod conf;
pub mod server;
mod spec;
mod store;
mod upstream;

pub use server::Listener;

/// Everything the cache keeps lives under this directory of the worker's data directory.
pub const ROOT_DIR: &str = "registry";

/// How long a tag's recorded digest is served without asking the upstream. A digest is immutable and
/// never revalidated; a tag may name another manifest the moment it is pushed.
pub const TAG_TTL: Duration = Duration::from_secs(60);

/// The floor on the cache's size bound: below this a single common layer would not fit.
pub const MIN_BUDGET_BYTES: u64 = 64 << 20;

/// An entry served within this window is never evicted, so a pull in progress cannot lose a layer it is
/// about to need. A blob that is already open keeps its bytes through an unlink, so this bounds churn
/// rather than correctness.
pub const KEEP_WINDOW: Duration = Duration::from_secs(10 * 60);

/// One upstream registry the cache answers for: the name a job's image reference uses and the endpoint
/// it is fetched from (Docker Hub's canonical name is not its API host).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub host: String,
    pub upstream: String,
}

impl Registry {
    /// The registry's name as the mirror path carries it. A repository path cannot hold a colon, so a
    /// registry that states a port (`127.0.0.1:5000`) writes it with an underscore: the cache maps the
    /// segment back through its own configuration, so the spelling is its own, not a reference's.
    pub fn slug(&self) -> String {
        self.host.replace(':', "_")
    }

    /// The two registries every image reference names by a different host, and the rest by themselves.
    pub fn canonical(host: &str) -> Registry {
        let upstream = match host {
            "docker.io" => "https://registry-1.docker.io".to_owned(),
            // A loopback upstream is a test or a private mirror of the operator's: it speaks plain HTTP
            // and must not be reached over TLS to a certificate nobody can issue. Nothing else is
            // downgraded.
            other if is_loopback_host(other) => format!("http://{other}"),
            other => format!("https://{other}"),
        };
        Registry {
            host: host.to_owned(),
            upstream,
        }
    }
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let name = host.rsplit_once(':').map_or(host, |(name, _port)| name);
    name == "127.0.0.1" || name == "localhost" || name == "[::1]"
}

#[derive(Clone, Debug)]
pub struct Settings {
    /// The directory the cache keeps its blobs, manifests, tag records and pull configurations in.
    pub root: PathBuf,
    /// The most the whole cache may hold on disk, across every scope.
    pub budget_bytes: u64,
    /// The upstreams this cache answers for. A request naming another registry is refused.
    pub registries: Vec<Registry>,
    pub tag_ttl: Duration,
    pub keep_window: Duration,
}

impl Settings {
    pub fn new(root: impl Into<PathBuf>, budget_bytes: u64, registries: Vec<Registry>) -> Settings {
        Settings {
            root: root.into(),
            budget_bytes,
            registries,
            tag_ttl: TAG_TTL,
            keep_window: KEEP_WINDOW,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Config(String),
    Io(io::Error),
    /// The upstream registry could not be reached, or answered something the cache cannot store.
    Upstream(String),
    /// The body the upstream sent does not hash to the digest it was requested by.
    Corrupt(String),
    /// The content would not fit the budget and nothing was left to evict.
    OverBudget {
        need: u64,
        budget: u64,
    },
    /// A request the cache does not implement, or one for a registry it does not cache.
    Refused(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(why) => write!(f, "registry cache: {why}"),
            Error::Io(error) => write!(f, "registry cache: {error}"),
            Error::Upstream(why) => write!(f, "registry cache: upstream {why}"),
            Error::Corrupt(what) => write!(f, "registry cache: {what} does not match its digest"),
            Error::OverBudget { need, budget } => write!(
                f,
                "registry cache: {need} bytes would not fit the {budget}-byte budget and nothing is evictable"
            ),
            Error::Refused(why) => write!(f, "registry cache: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The boundary a cached pull belongs to. Anonymous content is shared by every tenant (it is what any
/// unauthenticated client may fetch); a pull that carries a tenant's registry credential is kept in that
/// tenant's own scope, split by trust class so a fork's pull request can never occupy the scope a
/// protected build reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Anonymous,
    Tenant { tenant: [u8; 16], trust: Trust },
}

impl Scope {
    /// The name a scope's token is kept under on disk.
    fn key(self) -> String {
        match self {
            Scope::Anonymous => "anonymous".to_owned(),
            Scope::Tenant { tenant, trust } => {
                let mut key = String::with_capacity(64);
                key.push_str("tenant-");
                for byte in tenant {
                    key.push_str(&format!("{byte:02x}"));
                }
                key.push('-');
                key.push_str(trust.as_str());
                key
            }
        }
    }

    fn from_key(key: &str) -> Option<Scope> {
        if key == "anonymous" {
            return Some(Scope::Anonymous);
        }
        let rest = key.strip_prefix("tenant-")?;
        let (tenant, trust) = rest.rsplit_once('-')?;
        if tenant.len() != 32 || !tenant.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(tenant.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Scope::Tenant {
            tenant: bytes,
            trust: Trust::of_name(trust)?,
        })
    }
}

pub struct PullThrough {
    inner: Arc<Inner>,
}

impl Clone for PullThrough {
    fn clone(&self) -> PullThrough {
        PullThrough {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner {
    store: store::Store,
    upstream: upstream::Upstream,
    registries: Vec<Registry>,
    scopes: Mutex<store::Scopes>,
    conf_root: PathBuf,
    /// The loopback endpoint, bound once. It is owned here so dropping the cache stops serving.
    listener: OnceLock<Listener>,
}

impl PullThrough {
    pub fn open(settings: Settings) -> Result<PullThrough> {
        if settings.budget_bytes < MIN_BUDGET_BYTES {
            return Err(Error::Config(format!(
                "budget_bytes must be at least {} MiB",
                MIN_BUDGET_BYTES >> 20
            )));
        }
        if settings.registries.is_empty() {
            return Err(Error::Config("at least one registry is required".into()));
        }
        for registry in &settings.registries {
            conf::check_host(&registry.host)?;
        }
        let store = store::Store::open(&settings.root, &settings)?;
        let scopes = store.load_scopes()?;
        Ok(PullThrough {
            inner: Arc::new(Inner {
                store,
                upstream: upstream::Upstream::new()?,
                registries: settings.registries,
                scopes: Mutex::new(scopes),
                conf_root: settings.root.join(conf::CONF_DIR),
                listener: OnceLock::new(),
            }),
        })
    }

    pub fn budget_bytes(&self) -> u64 {
        self.inner.store.budget()
    }

    /// What the cache holds on disk now, bounded by [`PullThrough::budget_bytes`].
    pub fn used_bytes(&self) -> u64 {
        self.inner.store.used_bytes()
    }

    pub fn registries(&self) -> &[Registry] {
        &self.inner.registries
    }

    /// Binds the loopback listener and starts serving, returning its address. The cache answers on
    /// `127.0.0.1` only: a job container has no route to it (an egress container's pasta gateway mapping
    /// is off, a guest is refused every host address), so the only clients are the worker's own pulls.
    pub fn start(&self) -> Result<SocketAddr> {
        let listening = server::bind()?;
        let addr = listening.local_addr()?;
        let serving = Arc::clone(&self.inner);
        let listener = server::Listener::start(listening, addr, move |stream| {
            server::serve(&serving, stream)
        })?;
        self.inner
            .listener
            .set(listener)
            .map_err(|_| Error::Config("the cache is already listening".into()))?;
        Ok(addr)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.listener.get().map(Listener::local_addr)
    }

    /// Writes (once) and returns the `registries.conf` that sends one scope's pulls through this cache.
    pub fn mirror_conf(&self, scope: Scope) -> Result<PathBuf> {
        let port = self
            .local_addr()
            .ok_or_else(|| Error::Config("the cache is not listening yet".into()))?
            .port();
        let token = self.token(scope)?;
        let mut scopes = self.inner.scopes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(path) = scopes.written.get(&*token) {
            return Ok(path.clone());
        }
        let path = conf::write(&self.inner.conf_root, &token, port, &self.inner.registries)?;
        scopes.written.insert(token, path.clone());
        Ok(path)
    }

    fn token(&self, scope: Scope) -> Result<Box<str>> {
        let mut scopes = self.inner.scopes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(token) = scopes.by_scope.get(&scope) {
            return Ok(token.clone());
        }
        // Minted once per scope and kept on disk, so a restarted worker still answers from what the
        // previous one cached and a tenant's pull configuration stays valid for its lifetime.
        let token = store::mint_token()?;
        self.inner.store.save_scope(&scope.key(), &token)?;
        scopes.by_token.insert(token.clone(), scope);
        scopes.by_scope.insert(scope, token.clone());
        Ok(token)
    }
}

impl Inner {
    fn scope_of(&self, token: &str) -> Option<Scope> {
        let scopes = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
        scopes.by_token.get(token).copied()
    }

    fn registry(&self, segment: &str) -> Option<&Registry> {
        self.registries
            .iter()
            .find(|registry| registry.slug() == segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_upstreams_name_the_api_host_and_downgrade_only_loopback() {
        assert_eq!(
            Registry::canonical("docker.io").upstream,
            "https://registry-1.docker.io"
        );
        assert_eq!(Registry::canonical("ghcr.io").upstream, "https://ghcr.io");
        assert_eq!(
            Registry::canonical("127.0.0.1:5000").upstream,
            "http://127.0.0.1:5000"
        );
        assert_eq!(
            Registry::canonical("localhost:5000").upstream,
            "http://localhost:5000"
        );
    }

    #[test]
    fn a_scope_key_names_the_trust_class_so_each_class_keeps_its_own_place() {
        let tenant = [0xab; 16];
        let protected = Scope::Tenant {
            tenant,
            trust: Trust::Protected,
        };
        let fork = Scope::Tenant {
            tenant,
            trust: Trust::PullRequest,
        };
        assert_ne!(protected.key(), fork.key());
        assert!(protected.key().ends_with("-protected"));
        assert_eq!(Scope::Anonymous.key(), "anonymous");
    }
}
