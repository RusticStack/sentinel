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

#[derive(Default)]
pub struct Handle {
    stop: AtomicBool,
    link: Mutex<Option<Sender>>,
    sessions: std::sync::atomic::AtomicU64,
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

    pub fn sessions(&self) -> u64 {
        self.sessions.load(Ordering::Acquire)
    }

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

pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
pub const STABLE_SESSION: Duration = Duration::from_secs(30);

pub struct Config {
    pub controller: SocketAddr,
    pub server: Digest,
    pub also_pinned: Vec<Digest>,
    pub worker: WorkerId,
    pub name: String,
    pub hello: Hello,
    pub capacity: Capacity,
    pub profile: Profile,
    pub transport: TransportStats,
    pub remote_cache: bool,
}

#[derive(Debug)]
pub enum Event {
    Connected { worker: WorkerId, enrolled: bool },
    Disconnected(Error),
    Backoff(Duration),
}

fn jitter(base: Duration, seed: &mut u64) -> Duration {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    let quarter = base.as_millis() as u64 / 4;
    let offset = if quarter == 0 {
        0
    } else {
        *seed % (2 * quarter + 1)
    };
    Duration::from_millis(base.as_millis() as u64 - quarter + offset)
}

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
            let seed = 0xD1B5_4A32_D192_ED03
                ^ u64::from_le_bytes(config.worker.as_bytes()[8..].try_into().expect("8 bytes"));
            scope.spawn(move || serve_bulk(&dialer, bulk, executor, &gate, seed));
        }
        let outcome = link.run(executor, || handle.stopped());
        stop_bulk.store(true, Ordering::Release);
        if let Some(closer) = bulk_close {
            closer.close();
        }
        outcome
    });
    handle.link.lock().unwrap_or_else(|p| p.into_inner()).take();
    outcome
}

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

const STOP_POLL: Duration = Duration::from_millis(50);

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
            let started = Instant::now();
            let _ = bulk.run(executor, || stop.load(Ordering::Acquire));
            // Only a stable session resets the back-off: an accept-then-drop peer must not cause a tight redial loop.
            if started.elapsed() >= STABLE_SESSION {
                backoff = BACKOFF_MIN;
            }
        }
        if !wait_unless_stopped(stop, jitter(backoff, &mut seed)) {
            return;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
        match dialer.open() {
            Ok(bulk) => next = Some(bulk),
            Err(_) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
        }
    }
}

pub fn run(
    config: Config,
    identity: Identity,
    mut enrollment: Option<Secret>,
    executor: &dyn Executor,
    handle: &Handle,
    on_event: &dyn Fn(Event),
) -> Result<()> {
    let pins: Vec<Digest> = std::iter::once(config.server)
        .chain(config.also_pinned.iter().copied())
        .collect();
    let client = tls::client_config_pinned(identity, &pins)?;
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
        if welcomed.load(Ordering::Acquire) {
            enrollment = None;
        }
        // close_notify is trusted as deliberate: it is encrypted under the handshake
        // the pinned certificate authenticated, so it cannot be forged on the path.
        let closed = matches!(outcome, Err(Error::Closed));
        match outcome {
            Ok(()) => return Ok(()),
            Err(Error::Rejected(session::Rejection::Unavailable)) if !handle.stopped() => {
                on_event(Event::Disconnected(Error::Rejected(
                    session::Rejection::Unavailable,
                )));
            }
            Err(Error::Rejected(why)) => return Err(Error::Rejected(why)),
            Err(_) if handle.stopped() => return Ok(()),
            Err(error) => on_event(Event::Disconnected(error)),
        }
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
