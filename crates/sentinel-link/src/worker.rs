//! The worker's side of the link: connect, enroll once, serve the session,
//! and reconnect with bounded back-off when the controller is lost (W02).
//!
//! A lost session does not end the work: the executor keeps the attempts it
//! holds and keeps renewing them once the session is back; if it is not back
//! before the lease deadline the executor stops them itself (W06 reconciles
//! the controller's view). A typed rejection is final for this
//! configuration — the loop returns rather than retrying an unchanged hello
//! — except `Unavailable`, the controller's "try again later", which backs
//! off and retries like a lost connection.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::WorkerId;
use sentinel_protocol::negotiate::{Hello, PROFILE_MIN, Profile};

use crate::{
    Error, Result,
    identity::Identity,
    session::{self, Capacity, Executor, Link, Sender, TransportSource, TransportStats},
    tls,
};

/// The process's grip on the loop: `stop` ends the current session at once
/// (the socket is closed from here, so no beat has to elapse first) and
/// keeps [`run`] from starting another.
#[derive(Default)]
pub struct Handle {
    stop: AtomicBool,
    link: Mutex<Option<Sender>>,
    /// Control sessions opened since process start; what Q07 telemetry
    /// reports reconnects from, measured, never estimated.
    sessions: std::sync::atomic::AtomicU64,
    /// The process's live transport measurements (Q07), when it has any;
    /// without one every session reports [`Config::transport`].
    transport: Mutex<Option<TransportSource>>,
}

impl Handle {
    pub fn new() -> Handle {
        Handle::default()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(link) = self.link.lock().unwrap_or_else(|p| p.into_inner()).take() {
            link.close();
        }
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Control sessions this worker has opened (0 before the first).
    pub fn sessions(&self) -> u64 {
        self.sessions.load(Ordering::Acquire)
    }

    /// Report transport telemetry from `source` (the Tailcat helper's latest
    /// probe) instead of the fixed [`Config::transport`]: read at every
    /// session start, and at every telemetry resend within a session, so a
    /// path the helper re-measured reaches the controller (Q07).
    pub fn set_transport_source(&self, source: TransportSource) {
        *self.transport.lock().unwrap_or_else(|p| p.into_inner()) = Some(source);
    }

    fn transport_source(&self) -> Option<TransportSource> {
        self.transport
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Reconnect back-off: doubling from the first to the second, with jitter,
/// reset after a session that lasted at least [`STABLE_SESSION`].
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
pub const STABLE_SESSION: Duration = Duration::from_secs(30);

/// Everything a worker needs to reach its controller.
pub struct Config {
    pub controller: SocketAddr,
    /// The controller fingerprint handed over with the enrollment.
    pub server: Digest,
    pub worker: WorkerId,
    pub name: String,
    pub hello: Hello,
    pub capacity: Capacity,
    /// Protocol 7: what this machine offers the scheduler beyond CPU and
    /// memory (labels, host, disk, availability). Sent right after `Welcome`
    /// when the session negotiated protocol 7; ignored below it.
    pub profile: Profile,
    /// Protocol 7 (Q07): what the process measured about its transport
    /// before the first session — the path and helper version from the
    /// Tailcat probe, or Unknown. The link fills in round-trip time and byte
    /// counters from the live session.
    pub transport: TransportStats,
    /// Whether this worker exposes the remote cache to its executor (Q08);
    /// disabled, every remote lookup is a local miss.
    pub remote_cache: bool,
}

/// What happened on the link, for the process's diagnostics.
#[derive(Debug)]
pub enum Event {
    Connected { worker: WorkerId, enrolled: bool },
    Disconnected(Error),
    Backoff(Duration),
}

/// Cheap jitter without a randomness dependency: the schedule only has to
/// avoid a fleet reconnecting in lockstep, not be unpredictable.
fn jitter(base: Duration, seed: &mut u64) -> Duration {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    // ±25 %.
    let quarter = base.as_millis() as u64 / 4;
    let offset = if quarter == 0 {
        0
    } else {
        *seed % (2 * quarter + 1)
    };
    Duration::from_millis(base.as_millis() as u64 - quarter + offset)
}

/// Connect once and serve until `stop` is set or the session is lost.
/// `enrollment` is presented only on this hello; the caller drops it after
/// the first `Connected { enrolled: true }`.
///
/// A protocol-7 session gets its profile and telemetry reported first, then
/// the second (bulk) connection is dialled and served on its own thread. The
/// bulk connection is best-effort: when it cannot be established, or dies,
/// bulk-class sends fall back to the control connection and the worker keeps
/// working.
pub fn session(
    config: &Config,
    client: Arc<rustls::ClientConfig>,
    enrollment: Option<&Secret>,
    executor: &dyn Executor,
    handle: &Handle,
    welcomed: &AtomicBool,
    on_event: &dyn Fn(Event),
) -> Result<()> {
    let mut link: Link = session::connect(
        config.controller,
        client,
        config.worker,
        &config.name,
        config.hello.clone(),
        enrollment,
        config.capacity,
    )?;
    handle
        .sessions
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    link.set_remote_cache(config.remote_cache);
    if link.negotiated.protocol.0 >= PROFILE_MIN.0 {
        // The profile opens with what the executor holds right now (P07-6):
        // resident images and cache bytes, measured, never the configured
        // placeholder.
        let mut profile = config.profile.clone();
        if let Some((version, availability)) = executor.availability() {
            profile.availability.images = availability.images;
            profile.availability.cache_bytes = availability.cache_bytes;
            link.set_availability_sent(version);
        }
        link.send_profile(&profile)?;
        let source = handle.transport_source();
        let mut transport = match &source {
            Some(source) => source(),
            None => config.transport.clone(),
        };
        if let Some(source) = source {
            link.set_transport_source(source);
        }
        transport.reconnects = handle.sessions().saturating_sub(1);
        link.report_transport(&transport)?;
    }
    welcomed.store(true, Ordering::Release);
    *handle.link.lock().unwrap_or_else(|p| p.into_inner()) = Some(link.sender());
    if handle.stopped() {
        // Stopped between connect and registration: close what we just opened.
        handle.stop();
    }
    on_event(Event::Connected {
        worker: link.worker,
        enrolled: enrollment.is_some(),
    });
    let dialer = link.bulk_dialer();
    let bulk = dialer.as_ref().and_then(|dialer| dialer.open().ok());
    let bulk_close = bulk.as_ref().map(|bulk| bulk.sender());
    let stop_bulk = Arc::new(AtomicBool::new(false));
    let outcome = std::thread::scope(|scope| {
        if let (Some(dialer), Some(bulk)) = (dialer, bulk) {
            let gate = Arc::clone(&stop_bulk);
            // Its own jitter stream: bulk redials of a fleet must not align
            // with each other or with the control reconnects.
            let seed = 0xD1B5_4A32_D192_ED03
                ^ u64::from_le_bytes(config.worker.as_bytes()[8..].try_into().expect("8 bytes"));
            scope.spawn(move || serve_bulk(&dialer, bulk, executor, &gate, seed));
        }
        let outcome = link.run(executor, || handle.stopped());
        stop_bulk.store(true, Ordering::Release);
        if let Some(closer) = bulk_close {
            // End the bulk reader now rather than at its next poll.
            closer.close();
        }
        outcome
    });
    handle.link.lock().unwrap_or_else(|p| p.into_inner()).take();
    outcome
}

/// Sleep up to `wait`, returning early (with `false`) once `stop` is set.
/// Checked every [`STOP_POLL`], so whoever waits on this thread — the
/// control session's teardown joins it — waits at most that long for a stop,
/// never the whole back-off.
fn wait_unless_stopped(stop: &AtomicBool, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(STOP_POLL.min(left));
    }
}

/// How often a back-off wait looks at its stop flag.
const STOP_POLL: Duration = Duration::from_millis(50);

/// Serve the bulk half of a session on its own thread: the first connection
/// is already open, and a lost one is redialled with doubling, jittered
/// back-off until the control session ends. The back-off wait watches the
/// stop flag: the control session joins this thread before it returns, so an
/// uninterruptible sleep here would hold a reconnect for up to
/// [`BACKOFF_MAX`] — longer than a lease (P08-11).
fn serve_bulk(
    dialer: &session::BulkDialer,
    first: session::BulkLink,
    executor: &dyn Executor,
    stop: &AtomicBool,
    mut seed: u64,
) {
    let mut backoff = BACKOFF_MIN;
    let mut next = Some(first);
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        if let Some(mut bulk) = next.take() {
            let _ = bulk.run(executor, || stop.load(Ordering::Acquire));
        }
        if !wait_unless_stopped(stop, jitter(backoff, &mut seed)) {
            return;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
        match dialer.open() {
            Ok(bulk) => {
                next = Some(bulk);
                backoff = BACKOFF_MIN;
            }
            Err(_) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
        }
    }
}

/// The worker's main loop: sessions back to back with bounded back-off,
/// until `stop` is set. Returns the reason only when it is final: a typed
/// rejection other than `Unavailable`, an identity that cannot be used, or
/// the stop.
pub fn run(
    config: Config,
    identity: Identity,
    mut enrollment: Option<Secret>,
    executor: &dyn Executor,
    handle: &Handle,
    on_event: &dyn Fn(Event),
) -> Result<()> {
    let client = tls::client_config(identity, config.server)?;
    let mut backoff = BACKOFF_MIN;
    let mut seed = 0x9E37_79B9_7F4A_7C15
        ^ u64::from_le_bytes(config.worker.as_bytes()[..8].try_into().expect("8 bytes"));
    while !handle.stopped() {
        let started = Instant::now();
        let welcomed = AtomicBool::new(false);
        let outcome = session(
            &config,
            Arc::clone(&client),
            enrollment.as_ref(),
            executor,
            handle,
            &welcomed,
            on_event,
        );
        // Once welcomed, the enrollment is spent: never present it again.
        if welcomed.load(Ordering::Acquire) {
            enrollment = None;
        }
        // A controller's `close_notify` is deliberate whether or not it came
        // after the welcome: a hand-off closes a connection still in its
        // handshake or hello the same way. Encrypted under the handshake the
        // pinned certificate authenticated, it cannot be forged on the path.
        let closed = matches!(outcome, Err(Error::Closed));
        match outcome {
            Ok(()) => return Ok(()),
            // The controller's store was briefly unavailable (a restart
            // herd, a full writer queue): the same hello will be accepted
            // later, so it is retried like a lost connection — with the
            // same jittered back-off, so a fleet does not retry in step.
            Err(Error::Rejected(session::Rejection::Unavailable)) if !handle.stopped() => {
                on_event(Event::Disconnected(Error::Rejected(
                    session::Rejection::Unavailable,
                )));
            }
            Err(Error::Rejected(why)) => return Err(Error::Rejected(why)),
            Err(_) if handle.stopped() => return Ok(()),
            Err(error) => on_event(Event::Disconnected(error)),
        }
        // A session (or connection) the controller closed on purpose (a
        // hand-off to its restarted transport) is not a failure: the next
        // dial waits only the shortest back-off, however short it was.
        if started.elapsed() >= STABLE_SESSION || closed {
            backoff = BACKOFF_MIN;
        }
        let wait = jitter(backoff, &mut seed);
        on_event(Event::Backoff(wait));
        if !wait_unless_stopped(&handle.stop, wait) {
            break;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    Ok(())
}
