//! The controller's side of the link: listen, admit, keep the fleet, place
//! work and push offers (W02).
//!
//! Two threads own the loop. The acceptor takes connections and hands each
//! to a session thread that authenticates it against the store, registers
//! it in the fleet and serves it. The dispatcher sleeps on a condition
//! variable and is woken the moment anything changes the answer to "is
//! there work for a connected worker?": a worker arriving, an enqueue, a
//! completion, a decline. A short reconciliation interval is the safety
//! net for a missed wake, and the ack-timeout sweep rides on the same loop.
//! Heartbeats never drive dispatch; they only renew leases.
//!
//! Every decision is one writer transaction on the store: placement takes the
//! lease and reservation together, the ack marks the attempt, a lapse frees
//! it. Nothing here is state the database does not also hold, so a restart
//! reconstructs the queue and the reservations by reading them.

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{AttemptId, Fence, PoolId, UnixMillis, WorkerId};
use sentinel_protocol::negotiate::Hello;
use sentinel_store::{Store, dispatch, workers};

use crate::{
    Error, Result,
    identity::Identity,
    session::{self, Admission, Admitted, Capacity, Offer, Rejection, Sender, SessionHandler},
    tls,
};

/// How long the dispatcher sleeps without a wake before re-checking the
/// queue and sweeping unacknowledged offers. A safety net, not the clock.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// Sessions accepted at once; beyond this a connection is closed unserved.
pub const MAX_SESSIONS: usize = 1024;

/// Counters for diagnostics and tests. Monotonic, never reset.
#[derive(Debug, Default)]
pub struct Stats {
    pub admitted: AtomicU64,
    pub rejected: AtomicU64,
    pub offers: AtomicU64,
    pub acknowledged: AtomicU64,
    pub lapsed: AtomicU64,
    pub sessions_ended: AtomicU64,
}

struct Peer {
    sender: Sender,
    pool: PoolId,
    generation: u64,
    /// When liveness was last written, so a beat costs a write once a minute.
    seen_recorded_ms: AtomicI64,
}

struct Inner {
    store: Arc<Store>,
    config: Arc<rustls::ServerConfig>,
    fleet: Mutex<HashMap<WorkerId, Arc<Peer>>>,
    generation: AtomicU64,
    wake: (Mutex<bool>, Condvar),
    stop: AtomicBool,
    sessions: AtomicUsize,
    stats: Stats,
}

impl Inner {
    fn wake(&self) {
        let (flag, cv) = &self.wake;
        *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_one();
    }

    fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&sentinel_store::Transaction<'_>) -> sentinel_store::Result<T> + Send + 'static,
    ) -> Result<T> {
        self.store
            .writer()
            .write(f)
            .map_err(|_| Error::Internal("store write"))
    }

    fn register(&self, worker: WorkerId, peer: Arc<Peer>) {
        let old = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(worker, peer);
        // A reconnecting worker replaces its previous session; the old socket
        // is closed so its thread ends instead of lingering to its deadline.
        if let Some(old) = old {
            old.sender.close();
        }
    }

    fn unregister(&self, worker: WorkerId, generation: u64) {
        let mut fleet = self.fleet.lock().unwrap_or_else(|p| p.into_inner());
        if fleet
            .get(&worker)
            .is_some_and(|p| p.generation == generation)
        {
            fleet.remove(&worker);
        }
    }

    fn serve(self: &Arc<Self>, socket: TcpStream) {
        let outcome = session::accept(socket, Arc::clone(&self.config), &**self);
        let mut session = match outcome {
            Ok(session) => session,
            Err(_) => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        self.stats.admitted.fetch_add(1, Ordering::Relaxed);
        let Admitted { worker, pool, .. } = session.admitted;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let peer = Arc::new(Peer {
            sender: session.sender(),
            pool,
            generation,
            seen_recorded_ms: AtomicI64::new(0),
        });
        self.register(worker, peer);
        self.wake();
        let _ = session.serve(&**self);
        self.unregister(worker, generation);
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
        // Its unacknowledged offers lapse in the sweep; acknowledged leases
        // run to expiry (W06), so a brief reconnect keeps its work.
    }

    /// One dispatch pass: sweep lapsed offers, then fill every connected
    /// worker until nothing fits. Each placement is its own transaction, so
    /// a failing one never holds up the rest.
    fn dispatch_pass(&self) {
        let now = UnixMillis::now();
        if let Ok(due) = self.store.read(|c| dispatch::unacknowledged(c, now)) {
            for attempt in due {
                if self
                    .write(move |tx| dispatch::lapse(tx, attempt, now))
                    .is_ok()
                {
                    self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let peers: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        for (worker, peer) in peers {
            let pool = peer.pool;
            for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
                let placed = self.write(move |tx| {
                    dispatch::place(
                        tx,
                        worker,
                        pool,
                        dispatch::DEFAULT_LEASE_MS,
                        UnixMillis::now(),
                    )
                });
                let Ok(Some(placed)) = placed else { break };
                let offer = Offer {
                    attempt: placed.attempt,
                    tenant: placed.tenant,
                    run: placed.run,
                    job: placed.job,
                    fence: placed.fence,
                    lease_until: placed.lease_until,
                    cpu_millis: placed.cpu_millis as u64,
                    memory_bytes: placed.memory_bytes as u64,
                    image_digest: placed.image.digest,
                    image_platform: placed.image.platform,
                };
                if session::offer(&peer.sender, &offer).is_err() {
                    // The session is gone: give the job back at once rather
                    // than letting the ack timeout find it.
                    let attempt = offer.attempt;
                    let _ = self.write(move |tx| dispatch::lapse(tx, attempt, UnixMillis::now()));
                    peer.sender.close();
                    break;
                }
                self.stats.offers.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn dispatch_loop(&self) {
        let (flag, cv) = &self.wake;
        loop {
            {
                let mut woken = flag.lock().unwrap_or_else(|p| p.into_inner());
                if !*woken {
                    woken = cv
                        .wait_timeout(woken, RECONCILE_INTERVAL)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                *woken = false;
            }
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            self.dispatch_pass();
        }
    }
}

impl Admission for Inner {
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        let capacity = dispatch::Capacity {
            cpu_millis: i64::try_from(capacity.cpu_millis).map_err(|_| Rejection::Capacity)?,
            memory_bytes: i64::try_from(capacity.memory_bytes).map_err(|_| Rejection::Capacity)?,
        };
        if let Ok(known) = self.store.read(|c| workers::authenticate(c, fingerprint)) {
            let id = known.id;
            self.write(move |tx| dispatch::report_capacity(tx, id, capacity))
                .map_err(|_| Rejection::Unavailable)?;
            return Ok(Admitted {
                worker: known.id,
                pool: known.pool,
                negotiated: known.negotiated,
            });
        }
        let Some(secret) = enrollment else {
            return Err(Rejection::NotEnrolled);
        };
        let (secret, fingerprint, name) = (
            Secret::parse(&{
                let mut t = String::new();
                secret.expose(&mut t);
                t
            })
            .ok_or(Rejection::Enrollment)?,
            *fingerprint,
            name.to_owned(),
        );
        self.store
            .writer()
            .write(move |tx| {
                let enrolled = workers::enroll(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint,
                        name: &name,
                        negotiated,
                    },
                    UnixMillis::now(),
                )?;
                dispatch::report_capacity(tx, enrolled.id, capacity)?;
                Ok(Admitted {
                    worker: enrolled.id,
                    pool: enrolled.pool,
                    negotiated: enrolled.negotiated,
                })
            })
            .map_err(|e| match e {
                sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_) => {
                    Rejection::Identity
                }
                sentinel_store::Error::NotFound => Rejection::Enrollment,
                _ => Rejection::Unavailable,
            })
    }
}

impl SessionHandler for Inner {
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<(UnixMillis, Vec<AttemptId>)> {
        let now = UnixMillis::now();
        let peer = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned();
        let record_seen = peer.as_ref().is_some_and(|p| {
            let last = p.seen_recorded_ms.load(Ordering::Relaxed);
            now.0.saturating_sub(last) >= workers::SEEN_RECORD_INTERVAL_MS
        });
        if held.is_empty() && !record_seen {
            // Nothing to renew and liveness recorded recently: no write.
            return Ok((UnixMillis(now.0 + dispatch::DEFAULT_LEASE_MS), Vec::new()));
        }
        let held = held.to_vec();
        let result = self.write(move |tx| {
            if record_seen {
                workers::seen(tx, worker, now)?;
            }
            dispatch::renew(tx, worker, &held, dispatch::DEFAULT_LEASE_MS, now)
        })?;
        if record_seen && let Some(peer) = peer {
            peer.seen_recorded_ms.store(now.0, Ordering::Relaxed);
        }
        Ok(result)
    }

    fn acknowledged(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        let acked = self
            .write(move |tx| dispatch::acknowledge(tx, worker, attempt, fence, UnixMillis::now()));
        if acked.is_ok() {
            self.stats.acknowledged.fetch_add(1, Ordering::Relaxed);
        }
        // A stale acknowledgement changes nothing; the worker learns the
        // attempt is not its own from the stop list on its next beat.
    }

    fn declined(&self, _worker: WorkerId, attempt: AttemptId, _fence: Fence) {
        if self
            .write(move |tx| dispatch::lapse(tx, attempt, UnixMillis::now()))
            .is_ok()
        {
            self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
            // Deliberately no wake: the job is queued again and the next
            // reconciliation places it, which bounds a worker that keeps
            // refusing to one offer per interval instead of a tight loop.
        }
    }
}

/// A running controller: listener, fleet and dispatcher.
pub struct Controller {
    inner: Arc<Inner>,
    addr: SocketAddr,
    fingerprint: Digest,
    acceptor: Option<thread::JoinHandle<()>>,
    dispatcher: Option<thread::JoinHandle<()>>,
}

impl Controller {
    /// Bind `listen`, present `identity`, and start serving workers of
    /// `store`. Returns once the socket is bound; workers may connect.
    pub fn start(store: Arc<Store>, identity: Identity, listen: SocketAddr) -> Result<Controller> {
        let fingerprint = identity.fingerprint();
        let config = tls::server_config(identity)?;
        let listener = TcpListener::bind(listen)?;
        let addr = listener.local_addr()?;
        let inner = Arc::new(Inner {
            store,
            config,
            fleet: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            wake: (Mutex::new(false), Condvar::new()),
            stop: AtomicBool::new(false),
            sessions: AtomicUsize::new(0),
            stats: Stats::default(),
        });
        let acceptor = {
            let inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("sentinel-link-accept".into())
                .spawn(move || accept_loop(&inner, &listener))?
        };
        let dispatcher = {
            let inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("sentinel-dispatch".into())
                .spawn(move || inner.dispatch_loop())?
        };
        Ok(Controller {
            inner,
            addr,
            fingerprint,
            acceptor: Some(acceptor),
            dispatcher: Some(dispatcher),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// What workers must pin.
    pub fn fingerprint(&self) -> Digest {
        self.fingerprint
    }

    /// Something changed the queue (an enqueue, a completion, a cancel):
    /// dispatch now rather than at the next reconciliation.
    pub fn wake(&self) {
        self.inner.wake();
    }

    /// Workers with a live session, for placement reasons and operators.
    pub fn connected(&self) -> Vec<WorkerId> {
        self.inner
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect()
    }

    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }

    /// Stop accepting, close every session and stop dispatching. Returns
    /// whether every session thread ended within `timeout`; the store is the
    /// caller's to shut down afterwards, and nothing durable is lost either
    /// way — leases and offers are rows, reconciled at the next start.
    pub fn shutdown(mut self, timeout: Duration) -> bool {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake();
        // Unblock the acceptor with one connection to itself.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(handle) = self.acceptor.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.dispatcher.take() {
            let _ = handle.join();
        }
        let peers: Vec<Arc<Peer>> = self
            .inner
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        for peer in peers {
            peer.sender.close();
        }
        let deadline = Instant::now() + timeout;
        while self.inner.sessions.load(Ordering::Acquire) > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

fn accept_loop(inner: &Arc<Inner>, listener: &TcpListener) {
    for socket in listener.incoming() {
        if inner.stop.load(Ordering::Acquire) {
            return;
        }
        let Ok(socket) = socket else { continue };
        if inner.sessions.load(Ordering::Acquire) >= MAX_SESSIONS {
            drop(socket);
            continue;
        }
        inner.sessions.fetch_add(1, Ordering::AcqRel);
        let session = Arc::clone(inner);
        let spawned = thread::Builder::new()
            .name("sentinel-link-session".into())
            .spawn(move || {
                session.serve(socket);
                session.sessions.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            inner.sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("addr", &self.addr)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}
