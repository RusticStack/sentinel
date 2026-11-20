//! The listener one sandbox reaches and the routing it serves: TLS with that sandbox's leaf, the cache
//! and artifact services inside the boundary the lease named, and a refusal for everything else.
//!
//! The boundary is a property of the **listener**, not of the conversation. [`Endpoint::bind`] starts a
//! listener that serves nothing, [`Endpoint::bind_scope`] is what the controller's frame does when the
//! job's provenance is known, and every call after it lands in that one scope. A request cannot name
//! its way into another trust, another repository or another run, because nothing it carries is
//! consulted: the same code path answers with the listener's scope or refuses with [`Refusal::Unscoped`].

use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use crate::{
    SCHEMA, SandboxCa, Scope, Store,
    artifact::{self, BLOB, TWIRP},
    cache,
    http::{Conn, Request, Response},
};

/// The most connections one sandbox's endpoint serves at once. A client keeps a handful of agents
/// alive; more than this is a client this endpoint refuses to keep spending threads on.
pub const CONNECTIONS: usize = 16;

/// How long a kept-alive connection waits for its next request before the endpoint closes it.
const IDLE: Duration = Duration::from_secs(30);

/// The reasons an endpoint refuses. Each is a stated refusal rather than a dropped connection, because
/// a client that is refused told its own log why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The path or method is outside the two services the pinned clients call.
    Unimplemented,
    /// The sandbox has not been told its boundary yet — the only safe answer before the job's
    /// provenance is known, because there is no scope that is always right.
    Unscoped,
    /// A `CONNECT` would be a tunnel to somewhere this endpoint will not reach.
    Tunnel,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unimplemented => "not_implemented",
            Self::Unscoped => "unscoped",
            Self::Tunnel => "tunnel_refused",
        }
    }
}

/// What one endpoint has done, which is how a worker's note and the tests read it.
#[derive(Default)]
pub struct Stats {
    pub served: AtomicU64,
    pub refused: AtomicU64,
    pub bytes: AtomicU64,
}

pub struct Endpoint {
    addr: SocketAddr,
    scope: Arc<RwLock<Option<Scope>>>,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Endpoint {
    /// Binds this sandbox's listener on its own address and port. A deployment states the port the
    /// pinned clients dial — 443 — and a test states its own. It serves no route until [`Self::bind_scope`]:
    /// a sandbox that has not been told its provenance has no boundary that is always right.
    pub fn bind(ca: &SandboxCa, store: Arc<Store>, address: SocketAddr) -> crate::Result<Endpoint> {
        Endpoint::bind_with(ca, store, address, None)
    }

    /// A listener that publishes what it seals: the worker's own, whose artifacts are the tenant's rows
    /// in the controller's store rather than files only this host knows about. The publisher is held by
    /// the accept loop for the endpoint's life.
    pub fn bind_with(
        ca: &SandboxCa,
        store: Arc<Store>,
        address: SocketAddr,
        publisher: Option<Arc<dyn crate::Publisher>>,
    ) -> crate::Result<Endpoint> {
        let config = ca.server_config()?;
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let scope: Arc<RwLock<Option<Scope>>> = Arc::new(RwLock::new(None));
        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let live = Arc::new(AtomicU64::new(0));
        let publishing = publisher;
        let join = {
            let scope = Arc::clone(&scope);
            let stats = Arc::clone(&stats);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name(format!("sentinel-actions-{addr}"))
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                if live.load(Ordering::Acquire) as usize >= CONNECTIONS {
                                    drop(stream);
                                    continue;
                                }
                                live.fetch_add(1, Ordering::AcqRel);
                                let config = Arc::clone(&config);
                                let scope = Arc::clone(&scope);
                                let stats = Arc::clone(&stats);
                                let live = Arc::clone(&live);
                                let bound = Arc::clone(&store);
                                let publisher = publishing.clone();
                                let _ = std::thread::Builder::new()
                                    .name("sentinel-actions-conn".to_owned())
                                    .spawn(move || {
                                        serve(stream, config, scope, bound, stats, publisher);
                                        live.fetch_sub(1, Ordering::AcqRel);
                                    });
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return,
                        }
                    }
                })?
        };
        Ok(Endpoint {
            addr,
            scope,
            stats,
            stop,
            join: Some(join),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The authority a sandbox's resolver answers with: the address only, because the clients dial 443.
    pub fn authority(&self) -> String {
        match self.addr.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        }
    }

    /// Tells this listener whose it is. Everything after the call lands in `scope`; nothing in a request
    /// can widen it.
    pub fn bind_scope(&self, scope: Scope) {
        *self.scope.write().unwrap_or_else(|e| e.into_inner()) = Some(scope);
    }

    pub fn scope(&self) -> Option<Scope> {
        *self.scope.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One connection: TLS, then requests until the client closes or the idle bound passes.
fn serve(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    scope: Arc<RwLock<Option<Scope>>>,
    store: Arc<Store>,
    stats: Arc<Stats>,
    publisher: Option<Arc<dyn crate::Publisher>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IDLE));
    let Ok(conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    let mut conn = Conn::new(rustls::StreamOwned::new(conn, stream));
    loop {
        let head = match conn.head() {
            Ok(Some(head)) => head,
            _ => return,
        };
        let Some(mut request) = Request::parse(&mut conn, &head) else {
            return;
        };
        let keep = request.keep_alive();
        let bound = *scope.read().unwrap_or_else(|e| e.into_inner());
        let response = dispatch_with(&mut request, bound.as_ref(), &store, publisher.as_deref());
        if response.status < 300 {
            stats.served.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.refused.fetch_add(1, Ordering::Relaxed);
        }
        if let crate::http::Payload::Bytes(bytes) = &response.body {
            stats.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        if response.write(&mut conn, keep).is_err() || !keep {
            return;
        }
    }
}

/// The whole surface one request may reach. `scope` is the listener's, and `None` means the sandbox has
/// not been told yet: every request is refused rather than served into a guess.
pub fn dispatch<S: Read + Write>(
    request: &mut Request<'_, S>,
    scope: Option<&Scope>,
    store: &Store,
) -> Response {
    dispatch_with(request, scope, store, None)
}

/// The same surface, with the publisher a sealed artifact is offered to. A listener without one keeps
/// its artifacts on its own disk.
pub fn dispatch_with<S: Read + Write>(
    request: &mut Request<'_, S>,
    scope: Option<&Scope>,
    store: &Store,
    publisher: Option<&dyn crate::Publisher>,
) -> Response {
    if request.method == "CONNECT" {
        let _ = request.body.discard();
        return refusal(&request.path, Refusal::Tunnel);
    }
    let Some(scope) = scope else {
        let _ = request.body.discard();
        return refusal(&request.path, Refusal::Unscoped);
    };
    if request.path.starts_with(cache::PREFIX) {
        return cache::serve(request, scope, store);
    }
    if (request.path.starts_with(TWIRP) || request.path.starts_with(BLOB))
        && let Some(response) = artifact::serve(request, scope, store, publisher)
    {
        return response;
    }
    let _ = request.body.discard();
    refusal(&request.path, Refusal::Unimplemented)
}

/// A refusal body names the contract, the reason and the fact that nothing was forwarded.
pub fn refusal(path: &str, why: Refusal) -> Response {
    let status = match why {
        Refusal::Unimplemented => 404,
        Refusal::Unscoped => 403,
        Refusal::Tunnel => 405,
    };
    Response::json(
        status,
        &serde_json::json!({
            "schema": SCHEMA,
            "refusal": why.as_str(),
            "forwarded": false,
            "path": path,
        }),
    )
}

/// The address a sandbox's resolver answers with when no operator states one: the worker's own loopback,
/// because the endpoint listens on the host and the sandbox reaches it through the address the worker's
/// network setup gave it.
pub const DEFAULT_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use sentinel_core::{RepoId, TenantId};
    use sentinel_protocol::{cache::Trust, negotiate::Arch};

    use super::*;

    fn scope(trust: Trust, run: u64) -> Scope {
        Scope::with_job(TenantId::new(), RepoId::new(), trust, Arch::X86_64, run, 5)
    }

    fn once(scope: Option<&Scope>, store: &Store, raw: &[u8]) -> (u16, serde_json::Value) {
        let mut conn = Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let mut request = Request::parse(&mut conn, &head).unwrap();
        let response = dispatch(&mut request, scope, store);
        match &response.body {
            crate::http::Payload::Bytes(bytes) => (
                response.status,
                serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null),
            ),
            _ => (response.status, serde_json::Value::Null),
        }
    }

    #[test]
    fn a_sandbox_that_has_not_been_told_its_boundary_serves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        for raw in [
            &b"GET /_apis/artifactcache/cache?keys=k&version=v HTTP/1.1\r\n\r\n"[..],
            b"POST /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
            b"GET /anything HTTP/1.1\r\n\r\n",
        ] {
            let (status, body) = once(None, &store, raw);
            assert_eq!(status, 403);
            assert_eq!(body["refusal"], "unscoped");
        }
    }

    #[test]
    fn a_connect_is_refused_before_any_route_and_never_tunnelled() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let scope = scope(Trust::Protected, 1);
        let (status, body) = once(
            Some(&scope),
            &store,
            b"CONNECT results-receiver.actions.githubusercontent.com:443 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(status, 405);
        assert_eq!(body["refusal"], "tunnel_refused");
        assert_eq!(body["forwarded"], false);
    }

    /// A request the pinned clients can send, with its own framing stated exactly.
    fn request(method: &str, path: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nContent-Length: {}\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        raw
    }

    fn save(store: &Store, scope: &Scope, key: &str, version: &str, body: &[u8]) {
        let reserve = serde_json::json!({ "key": key, "version": version });
        let (status, reserved) = once(
            Some(scope),
            store,
            &request(
                "POST",
                "/_apis/artifactcache/caches",
                "",
                reserve.to_string().as_bytes(),
            ),
        );
        assert_eq!(status, 200);
        let id = reserved["cacheId"].as_u64().unwrap();
        let patch = request(
            "PATCH",
            &format!("/_apis/artifactcache/caches/{id}"),
            &format!("Content-Range: bytes 0-{}/*\r\n", body.len() - 1),
            body,
        );
        assert_eq!(once(Some(scope), store, &patch).0, 204);
        let commit = format!("{{\"size\":{}}}", body.len());
        let done = request(
            "POST",
            &format!("/_apis/artifactcache/caches/{id}"),
            "",
            commit.as_bytes(),
        );
        assert_eq!(once(Some(scope), store, &done).0, 204);
    }

    fn lookup(store: &Store, scope: &Scope, key: &str, version: &str) -> (u16, serde_json::Value) {
        once(
            Some(scope),
            store,
            request(
                "GET",
                &format!("/_apis/artifactcache/cache?keys={key}&version={version}"),
                "",
                b"",
            )
            .as_slice(),
        )
    }

    /// The boundary is the listener's: a request that names another run's or another trust's data is
    /// answered from its own listener's scope, and a key written in another scope is simply absent.
    #[test]
    fn the_scope_comes_from_the_listener_and_never_from_the_request() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let trusted = scope(Trust::Protected, 10);
        let fork = scope(Trust::PullRequest, 20);
        save(&store, &trusted, "deps", "v", b"trusted");
        save(&store, &fork, "deps", "v", b"fork-owned");
        let (status, body) = lookup(&store, &fork, "deps", "v");
        assert_eq!(status, 200);
        let location = body["archiveLocation"].as_str().unwrap();
        assert!(location.contains("/pull_request/"), "{location}");
        let (status, body) = lookup(&store, &trusted, "deps", "v");
        assert_eq!(status, 200);
        assert!(
            body["archiveLocation"]
                .as_str()
                .unwrap()
                .contains("/protected/")
        );
        // The two archives hold the two bodies: neither listener was steered by the request.
        assert!(store.entry_dir(&fork, "deps", "v").is_dir());
        assert!(store.entry_dir(&trusted, "deps", "v").is_dir());
    }

    /// A fork job never writes a scope a trusted job reads, in either direction.
    #[test]
    fn a_fork_job_never_writes_a_trusted_scope_and_a_trusted_job_never_reads_a_forks() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let trusted = scope(Trust::Protected, 1);
        let fork = scope(Trust::PullRequest, 2);
        assert_eq!(lookup(&store, &fork, "key", "v").0, 204);
        assert_eq!(lookup(&store, &trusted, "key", "v").0, 204);
        save(&store, &fork, "key", "v", b"evil");
        // The fork's bytes are on local disk under pull_request, and nowhere a trusted job looks.
        let fork_dir = store.entry_dir(&fork, "key", "v");
        assert!(fork_dir.is_dir(), "the fork's write did not land on disk");
        assert!(fork_dir.to_string_lossy().contains("pull_request"));
        let trusted_dir = store.entry_dir(&trusted, "key", "v");
        assert!(!trusted_dir.exists(), "a fork wrote a trusted scope");
        assert_eq!(lookup(&store, &trusted, "key", "v").0, 204);
        assert_eq!(lookup(&store, &fork, "key", "v").0, 200);
        // And the other direction: a trusted write is never served to a fork.
        save(&store, &trusted, "key", "v", b"good");
        assert!(trusted_dir.to_string_lossy().contains("protected"));
        let (status, body) = lookup(&store, &trusted, "key", "v");
        assert_eq!(status, 200);
        assert!(
            body["archiveLocation"]
                .as_str()
                .unwrap()
                .contains("/protected/")
        );
        let (_, body) = lookup(&store, &fork, "key", "v");
        assert!(
            body["archiveLocation"]
                .as_str()
                .unwrap()
                .contains("/pull_request/")
        );
    }

    /// The full wire: a real TLS client with the sandbox's anchor, and one without it.
    #[test]
    fn a_client_outside_the_sandbox_cannot_reach_the_endpoint_and_one_inside_can() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(dir.path()));
        let ca = SandboxCa::generate("lease").unwrap();
        let mut endpoint = Endpoint::bind(
            &ca,
            Arc::clone(&store),
            SocketAddr::new(IpAddr::V4(DEFAULT_ADDRESS), 0),
        )
        .unwrap();
        endpoint.bind_scope(scope(Trust::Protected, 3));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_config = |anchor: Option<&[u8]>| {
            let mut roots = rustls::RootCertStore::empty();
            if let Some(pem) = anchor {
                use rustls_pki_types::pem::PemObject;
                let anchor = rustls_pki_types::CertificateDer::from_pem_slice(pem).unwrap();
                roots.add(anchor).unwrap();
            }
            let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls_pki_types::ServerName::try_from(crate::CACHE_HOST).unwrap();
            rustls::ClientConnection::new(Arc::new(config), name).unwrap()
        };
        let ask = |anchor: Option<&[u8]>| -> Option<String> {
            let conn = client_config(anchor);
            let tcp = TcpStream::connect(endpoint.addr()).ok()?;
            let mut conn = Conn::new(rustls::StreamOwned::new(conn, tcp));
            conn.write_all(
                b"GET /_apis/artifactcache/cache?keys=k&version=v HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .ok()?;
            let head = conn.head().ok()??;
            Some(head)
        };

        assert!(
            ask(None).is_none(),
            "a client without the anchor completed a request"
        );
        let head = ask(Some(ca.anchor_pem())).expect("the sandbox's own anchor is served");
        assert!(head.starts_with("HTTP/1.1 204"), "{head}");
        assert_eq!(endpoint.stats().served.load(Ordering::Relaxed), 1);
        endpoint.shutdown();
    }
}
