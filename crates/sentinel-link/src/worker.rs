//! The worker's side of the link: connect, enroll once, serve the session,
//! and reconnect with bounded back-off when the controller is lost (W02).
//!
//! A lost session does not end the work: the executor keeps the attempts it
//! holds and keeps renewing them once the session is back; if it is not back
//! before the lease deadline the executor stops them itself (W06 reconciles
//! the controller's view). A typed rejection is final for this
//! configuration — the loop returns rather than retrying an unchanged hello.

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
use sentinel_protocol::negotiate::Hello;

use crate::{
    Error, Result,
    identity::Identity,
    session::{self, Capacity, Executor, Link, Sender},
    tls,
};

/// The process's grip on the loop: `stop` ends the current session at once
/// (the socket is closed from here, so no beat has to elapse first) and
/// keeps [`run`] from starting another.
#[derive(Default)]
pub struct Handle {
    stop: AtomicBool,
    link: Mutex<Option<Sender>>,
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
    let outcome = link.run(executor, || handle.stopped());
    handle.link.lock().unwrap_or_else(|p| p.into_inner()).take();
    outcome
}

/// The worker's main loop: sessions back to back with bounded back-off,
/// until `stop` is set. Returns the reason only when it is final: a typed
/// rejection, an identity that cannot be used, or the stop.
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
        match outcome {
            Ok(()) => return Ok(()),
            Err(Error::Rejected(why)) => return Err(Error::Rejected(why)),
            Err(_) if handle.stopped() => return Ok(()),
            Err(error) => on_event(Event::Disconnected(error)),
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = BACKOFF_MIN;
        }
        let wait = jitter(backoff, &mut seed);
        on_event(Event::Backoff(wait));
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline && !handle.stopped() {
            std::thread::sleep(Duration::from_millis(50).min(deadline - Instant::now()));
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    Ok(())
}
