//! Framing, hello/negotiation, heartbeat and offers over an established,
//! full-duplex TLS stream.
//!
//! Frames are a big-endian `u32` length followed by a postcard-encoded
//! message, capped at `MAX_CONTROL_MESSAGE_BYTES` before any allocation. The
//! first exchange is `Hello`/`Welcome`; after that the worker sends
//! heartbeats (which carry lease renewals) and offer answers, and the
//! controller sends pongs and offers, in either order. Anything else on the
//! wire is a protocol violation and ends the session.
//!
//! Full duplex on one TLS connection: the rustls state sits behind a mutex
//! that is held only while bytes move between it and a buffer, never across
//! a socket call. One thread reads the socket; any thread may send. An offer
//! therefore reaches a worker the moment it is placed, not at its next beat.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::{ClientConnection, ServerConnection, pki_types::ServerName};
use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{AttemptId, Fence, JobId, RunId, TenantId, UnixMillis, WorkerId};
use sentinel_protocol::{
    limits::{MAX_CONTROL_MESSAGE_BYTES, MAX_LIST_ITEMS},
    negotiate::{Hello, Negotiated, Rejected},
};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, identity::fingerprint_of};

/// How often a worker proves it is still there, and how long the controller
/// waits before deciding it is not. Two missed beats, not one: a single
/// delayed packet must not tear down a session carrying live work.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(15);
/// Bytes read from the socket per call; one TLS record fits.
const TLS_READ_BYTES: usize = 16 * 1024 + 512;

/// What a worker has, as it measures at each hello.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        hello: Hello,
        /// The worker's generated identifier, as raw bytes on the wire.
        worker: [u8; 16],
        name: String,
        /// Present exactly once, on the session that redeems it.
        enrollment: Option<String>,
        capacity: Capacity,
    },
    /// Heartbeat. `held` names the attempts the worker still holds; the
    /// controller renews their leases and answers with what to stop.
    Ping {
        seq: u64,
        held: Vec<[u8; 16]>,
    },
    /// The worker took the offer and owns the attempt under this fence.
    Ack {
        attempt: [u8; 16],
        fence: u64,
    },
    /// The worker will not take the offer; the job returns to the queue.
    Decline {
        attempt: [u8; 16],
        fence: u64,
    },
    Bye,
}

/// A lease on the wire; typed as [`Offer`] on both ends.
#[derive(Debug, Serialize, Deserialize)]
pub struct WireOffer {
    pub attempt: [u8; 16],
    pub tenant: [u8; 16],
    pub run: [u8; 16],
    pub job: [u8; 16],
    pub fence: u64,
    pub lease_until_ms: i64,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub image_digest: String,
    pub image_platform: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    Welcome {
        worker: [u8; 16],
        negotiated: Negotiated,
        heartbeat_interval_ms: u32,
    },
    Reject(Rejection),
    /// Answers a `Ping`: the renewed lease deadline for everything in `held`
    /// that this worker still holds, and the attempts it must stop now.
    Pong {
        seq: u64,
        lease_until_ms: i64,
        stop: Vec<[u8; 16]>,
    },
    Offer(WireOffer),
}

/// An offer as the worker sees it: a fenced lease it must acknowledge within
/// the ack timeout and renew on every heartbeat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub attempt: AttemptId,
    pub tenant: TenantId,
    pub run: RunId,
    pub job: JobId,
    pub fence: Fence,
    pub lease_until: UnixMillis,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub image_digest: String,
    pub image_platform: String,
}

impl Offer {
    pub(crate) fn to_wire(&self) -> WireOffer {
        WireOffer {
            attempt: *self.attempt.as_bytes(),
            tenant: *self.tenant.as_bytes(),
            run: *self.run.as_bytes(),
            job: *self.job.as_bytes(),
            fence: self.fence.0,
            lease_until_ms: self.lease_until.0,
            cpu_millis: self.cpu_millis,
            memory_bytes: self.memory_bytes,
            image_digest: self.image_digest.clone(),
            image_platform: self.image_platform.clone(),
        }
    }

    fn from_wire(wire: WireOffer) -> Result<Offer> {
        Ok(Offer {
            attempt: AttemptId::from_bytes(wire.attempt).map_err(|_| Error::Protocol("id"))?,
            tenant: TenantId::from_bytes(wire.tenant).map_err(|_| Error::Protocol("id"))?,
            run: RunId::from_bytes(wire.run).map_err(|_| Error::Protocol("id"))?,
            job: JobId::from_bytes(wire.job).map_err(|_| Error::Protocol("id"))?,
            fence: Fence(wire.fence),
            lease_until: UnixMillis(wire.lease_until_ms),
            cpu_millis: wire.cpu_millis,
            memory_bytes: wire.memory_bytes,
            image_digest: wire.image_digest,
            image_platform: wire.image_platform,
        })
    }
}

/// Why a hello was refused. A worker must not retry an unchanged hello.
///
/// Wire-flat on purpose: C03's `Rejected` is an internally tagged enum for its
/// JSON API form, which postcard cannot encode, so it is mirrored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    /// No protocol version in common. `upgrade_worker` says which side is behind.
    UnsupportedVersion {
        supported_min: u16,
        supported_max: u16,
        upgrade_worker: bool,
    },
    /// Required capabilities the worker did not advertise, as a bit set.
    MissingCapabilities(u64),
    InvalidRange,
    /// The certificate is not an enrolled, unrevoked worker, and no valid
    /// enrollment was presented.
    NotEnrolled,
    /// The enrollment secret was unknown, spent, expired or for a dead pool.
    Enrollment,
    /// Identity or name refused by policy.
    Identity,
    /// The reported capacity is not representable.
    Capacity,
    /// The controller could not record the admission; try again later.
    Unavailable,
}

impl From<Rejected> for Rejection {
    fn from(rejected: Rejected) -> Self {
        match rejected {
            Rejected::UnsupportedVersion {
                supported_min,
                supported_max,
                upgrade_worker,
            } => Rejection::UnsupportedVersion {
                supported_min: supported_min.0,
                supported_max: supported_max.0,
                upgrade_worker,
            },
            Rejected::MissingCapabilities { missing } => Rejection::MissingCapabilities(missing.0),
            Rejected::InvalidRange => Rejection::InvalidRange,
        }
    }
}

/// What the controller decided about a presenting certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub worker: WorkerId,
    pub pool: sentinel_core::PoolId,
    pub negotiated: Negotiated,
}

/// The controller's admission policy. Implemented by the store glue; the
/// session code never touches the database.
pub trait Admission: Send + Sync {
    /// A known fingerprint, or an enrollment being redeemed with it. The
    /// capacity is recorded with the admission.
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection>;
}

/// What the controller does with an admitted worker's messages.
pub trait SessionHandler: Send + Sync {
    /// A heartbeat naming the attempts the worker holds. Returns the renewed
    /// lease deadline and the attempts the worker must stop.
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<(UnixMillis, Vec<AttemptId>)>;
    fn acknowledged(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    fn declined(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
}

/// The rustls state and the socket it writes to. The lock is held only while
/// bytes move between the connection and a buffer.
struct Shared {
    conn: Mutex<rustls::Connection>,
    sock: TcpStream,
}

/// The sending half: cheap to clone, usable from any thread.
#[derive(Clone)]
pub struct Sender(Arc<Shared>);

impl Sender {
    /// Encode, encrypt and write one frame. Holds the connection lock across
    /// the socket write so frames from different threads never interleave.
    pub(crate) fn send<M: Serialize>(&self, message: &M) -> Result<()> {
        let bytes = postcard::to_allocvec(message).map_err(|_| Error::Protocol("encode"))?;
        if bytes.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(Error::Protocol("frame too large"));
        }
        let mut conn = self.0.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.writer()
            .write_all(&(bytes.len() as u32).to_be_bytes())?;
        conn.writer().write_all(&bytes)?;
        let mut sock = &self.0.sock;
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        Ok(())
    }

    /// Tear the transport down from any thread; the reading side then fails
    /// out of its blocking read. Used by shutdown and by a replacing session.
    pub fn close(&self) {
        let _ = self.0.sock.shutdown(Shutdown::Both);
    }
}

/// The receiving half: exactly one thread reads the socket.
pub struct Receiver {
    shared: Arc<Shared>,
    sock: TcpStream,
    plain: Vec<u8>,
    tls: Box<[u8; TLS_READ_BYTES]>,
    timeout: Option<Duration>,
}

impl Receiver {
    /// Parse one frame out of the plaintext buffer, if a whole one is there.
    fn take_frame<M: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<M>> {
        if self.plain.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.plain[0], self.plain[1], self.plain[2], self.plain[3]])
            as usize;
        if len == 0 || len > MAX_CONTROL_MESSAGE_BYTES {
            return Err(Error::Protocol("frame length"));
        }
        if self.plain.len() < 4 + len {
            return Ok(None);
        }
        let message =
            postcard::from_bytes(&self.plain[4..4 + len]).map_err(|_| Error::Protocol("decode"))?;
        self.plain.drain(..4 + len);
        Ok(Some(message))
    }

    /// Move decrypted bytes out of rustls into the plaintext buffer. Returns
    /// whether anything arrived; `Lost` on the peer's close_notify.
    fn drain_plaintext(&mut self) -> Result<bool> {
        let mut conn = self.shared.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut got = false;
        loop {
            let start = self.plain.len();
            self.plain.resize(start + TLS_READ_BYTES, 0);
            match conn.reader().read(&mut self.plain[start..]) {
                Ok(0) => {
                    self.plain.truncate(start);
                    return Err(Error::Lost);
                }
                Ok(n) => {
                    self.plain.truncate(start + n);
                    got = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.plain.truncate(start);
                    return Ok(got);
                }
                Err(e) => {
                    self.plain.truncate(start);
                    return Err(e.into());
                }
            }
        }
    }

    /// Wait up to `timeout` for the next frame. `Ok(None)` is the timeout;
    /// `Lost` is the peer going away.
    pub(crate) fn recv_timeout<M: for<'de> Deserialize<'de>>(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<M>> {
        loop {
            if let Some(message) = self.take_frame()? {
                return Ok(Some(message));
            }
            if self.drain_plaintext()? {
                continue;
            }
            if self.timeout != Some(timeout) {
                self.sock
                    .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
                self.timeout = Some(timeout);
            }
            let n = match (&self.sock).read(&mut self.tls[..]) {
                Ok(0) => return Err(Error::Lost),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Err(Error::Lost);
                }
                Err(e) => return Err(e.into()),
            };
            let mut conn = self.shared.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut slice = &self.tls[..n];
            while !slice.is_empty() {
                if conn.read_tls(&mut slice)? == 0 {
                    // rustls' buffer is full: decrypt to make room.
                    conn.process_new_packets()
                        .map_err(|e| Error::Tls(e.to_string()))?;
                }
            }
            conn.process_new_packets()
                .map_err(|e| Error::Tls(e.to_string()))?;
            let mut sock = &self.shared.sock;
            while conn.wants_write() {
                conn.write_tls(&mut sock)?;
            }
        }
    }

    /// Wait for the next frame; the peer is `Lost` after `deadline`.
    pub(crate) fn recv<M: for<'de> Deserialize<'de>>(&mut self, deadline: Duration) -> Result<M> {
        self.recv_timeout(deadline)?.ok_or(Error::Lost)
    }
}

fn split(conn: rustls::Connection, sock: TcpStream) -> Result<(Sender, Receiver)> {
    let reader = sock.try_clone()?;
    let shared = Arc::new(Shared {
        conn: Mutex::new(conn),
        sock,
    });
    Ok((
        Sender(Arc::clone(&shared)),
        Receiver {
            shared,
            sock: reader,
            plain: Vec::with_capacity(4096),
            tls: Box::new([0; TLS_READ_BYTES]),
            timeout: None,
        },
    ))
}

/// One accepted, authenticated worker session on the controller.
pub struct WorkerSession {
    rx: Receiver,
    tx: Sender,
    pub admitted: Admitted,
    pub fingerprint: Digest,
}

/// Complete the TLS handshake on an accepted socket, read the hello, ask the
/// admission policy, and answer. Returns the live session or the reason it
/// was refused (after telling the worker so).
pub fn accept(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
) -> Result<WorkerSession> {
    socket.set_read_timeout(Some(HEARTBEAT_DEADLINE))?;
    socket.set_nodelay(true)?;
    let mut conn = ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?;
    let mut sock = &socket;
    // Drive the handshake so the peer certificate is available.
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    let fingerprint = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(fingerprint_of)
        .ok_or(Error::Protocol("no client certificate"))?;
    let (tx, mut rx) = split(rustls::Connection::Server(conn), socket)?;

    let ClientMessage::Hello {
        hello,
        worker,
        name,
        enrollment,
        capacity,
    } = rx.recv(HEARTBEAT_DEADLINE)?
    else {
        return Err(Error::Protocol("expected hello"));
    };
    let worker = WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?;
    let secret = match enrollment.as_deref() {
        Some(text) => {
            Some(sentinel_auth::token::parse(text).ok_or(Error::Protocol("enrollment secret"))?)
        }
        None => None,
    };
    match admission.admit(
        &fingerprint,
        worker,
        &name,
        &hello,
        secret.as_ref(),
        capacity,
    ) {
        Ok(admitted) => {
            tx.send(&ServerMessage::Welcome {
                worker: *admitted.worker.as_bytes(),
                negotiated: admitted.negotiated,
                heartbeat_interval_ms: HEARTBEAT_INTERVAL.as_millis() as u32,
            })?;
            Ok(WorkerSession {
                rx,
                tx,
                admitted,
                fingerprint,
            })
        }
        Err(rejection) => {
            let _ = tx.send(&ServerMessage::Reject(rejection));
            Err(Error::Rejected(rejection))
        }
    }
}

impl WorkerSession {
    /// The half the dispatcher pushes offers through.
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    /// Serve heartbeats and offer answers until the worker says goodbye,
    /// stops answering, or breaks protocol.
    pub fn serve(&mut self, handler: &dyn SessionHandler) -> Result<()> {
        let worker = self.admitted.worker;
        loop {
            match self.rx.recv::<ClientMessage>(HEARTBEAT_DEADLINE)? {
                ClientMessage::Ping { seq, held } => {
                    if held.len() > MAX_LIST_ITEMS {
                        return Err(Error::Protocol("held list"));
                    }
                    let held = ids(&held)?;
                    let (until, stop) = handler.ping(worker, &held)?;
                    self.tx.send(&ServerMessage::Pong {
                        seq,
                        lease_until_ms: until.0,
                        stop: stop.iter().map(|a| *a.as_bytes()).collect(),
                    })?;
                }
                ClientMessage::Ack { attempt, fence } => {
                    let attempt =
                        AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                    handler.acknowledged(worker, attempt, Fence(fence));
                }
                ClientMessage::Decline { attempt, fence } => {
                    let attempt =
                        AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                    handler.declined(worker, attempt, Fence(fence));
                }
                ClientMessage::Bye => return Ok(()),
                ClientMessage::Hello { .. } => return Err(Error::Protocol("second hello")),
            }
        }
    }
}

fn ids(raw: &[[u8; 16]]) -> Result<Vec<AttemptId>> {
    raw.iter()
        .map(|b| AttemptId::from_bytes(*b).map_err(|_| Error::Protocol("id")))
        .collect()
}

/// Push an offer to a worker. The dispatcher's only way in.
pub fn offer(sender: &Sender, offer: &Offer) -> Result<()> {
    sender.send(&ServerMessage::Offer(offer.to_wire()))
}

/// The worker's end of a session.
pub struct Link {
    rx: Receiver,
    tx: Sender,
    pub worker: WorkerId,
    pub negotiated: Negotiated,
    interval: Duration,
    seq: u64,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("worker", &self.worker)
            .field("negotiated", &self.negotiated)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// Connect, present the identity, say hello (redeeming an enrollment on the
/// first connection), and wait for the answer.
pub fn connect(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    worker: WorkerId,
    name: &str,
    hello: Hello,
    enrollment: Option<&Secret>,
    capacity: Capacity,
) -> Result<Link> {
    let socket = TcpStream::connect_timeout(&addr, HEARTBEAT_DEADLINE)?;
    socket.set_read_timeout(Some(HEARTBEAT_DEADLINE))?;
    socket.set_nodelay(true)?;
    // The name is irrelevant with a pinned fingerprint but rustls needs one.
    let server_name = ServerName::try_from("sentinel").expect("static name");
    let mut conn =
        ClientConnection::new(config, server_name).map_err(|e| Error::Tls(e.to_string()))?;
    let mut sock = &socket;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    let (tx, mut rx) = split(rustls::Connection::Client(conn), socket)?;
    let enrollment = enrollment.map(sentinel_auth::token::format);
    tx.send(&ClientMessage::Hello {
        hello,
        worker: *worker.as_bytes(),
        name: name.to_owned(),
        enrollment,
        capacity,
    })?;
    match rx.recv::<ServerMessage>(HEARTBEAT_DEADLINE)? {
        ServerMessage::Welcome {
            worker,
            negotiated,
            heartbeat_interval_ms,
        } => Ok(Link {
            rx,
            tx,
            worker: WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?,
            negotiated,
            interval: Duration::from_millis(u64::from(heartbeat_interval_ms)),
            seq: 0,
        }),
        ServerMessage::Reject(why) => Err(Error::Rejected(why)),
        ServerMessage::Pong { .. } | ServerMessage::Offer(_) => {
            Err(Error::Protocol("message before welcome"))
        }
    }
}

/// What a worker does with the offers and orders it receives. Implemented by
/// the executor (W03); the link owns dedup, acknowledgement and renewal.
pub trait Executor: Send + Sync {
    /// Take the offer or not. Called once per attempt per session.
    fn offered(&self, offer: &Offer) -> bool;
    /// The controller no longer counts this attempt as held: stop it now.
    fn stop(&self, attempt: AttemptId);
    /// Attempts still held, renewed with every heartbeat.
    fn held(&self) -> Vec<AttemptId>;
    /// The controller renewed every held lease to this deadline.
    fn renewed(&self, until: UnixMillis);
}

impl Link {
    pub fn heartbeat_interval(&self) -> Duration {
        self.interval
    }

    fn ping(&mut self, executor: &dyn Executor) -> Result<()> {
        self.seq += 1;
        let held: Vec<[u8; 16]> = executor
            .held()
            .iter()
            .take(MAX_LIST_ITEMS)
            .map(|a| *a.as_bytes())
            .collect();
        self.tx.send(&ClientMessage::Ping {
            seq: self.seq,
            held,
        })
    }

    /// One beat: send a ping and wait for its pong within the deadline.
    /// Offers arriving in between are answered through `executor`.
    pub fn beat(&mut self, executor: &dyn Executor) -> Result<()> {
        self.ping(executor)?;
        let deadline = std::time::Instant::now() + HEARTBEAT_DEADLINE;
        let mut seen = std::collections::HashSet::new();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.rx.recv_timeout::<ServerMessage>(remaining)? {
                None => return Err(Error::Lost),
                Some(message) => {
                    if self.handle(message, executor, &mut seen)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Handle one message; true when it was the awaited pong.
    fn handle(
        &mut self,
        message: ServerMessage,
        executor: &dyn Executor,
        seen: &mut std::collections::HashSet<AttemptId>,
    ) -> Result<bool> {
        match message {
            ServerMessage::Pong {
                seq,
                lease_until_ms,
                stop,
            } => {
                if seq != self.seq {
                    return Err(Error::Protocol("pong sequence"));
                }
                executor.renewed(UnixMillis(lease_until_ms));
                for attempt in ids(&stop)? {
                    executor.stop(attempt);
                }
                Ok(true)
            }
            ServerMessage::Offer(wire) => {
                let offer = Offer::from_wire(wire)?;
                // Dedup within the session: a repeated offer of an attempt
                // already taken is re-acknowledged, never re-executed.
                let take = if seen.insert(offer.attempt) {
                    executor.offered(&offer)
                } else {
                    true
                };
                let (attempt, fence) = (*offer.attempt.as_bytes(), offer.fence.0);
                self.tx.send(&if take {
                    ClientMessage::Ack { attempt, fence }
                } else {
                    ClientMessage::Decline { attempt, fence }
                })?;
                Ok(false)
            }
            ServerMessage::Welcome { .. } | ServerMessage::Reject(_) => {
                Err(Error::Protocol("unexpected message"))
            }
        }
    }

    /// A handle another thread can use to end the session (`Sender::close`);
    /// `run` then returns `Lost` without waiting for a beat.
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    /// Run the session until `until` returns true (checked after every
    /// message and beat) or the controller is lost: beats at the interval,
    /// offers answered the moment they arrive.
    pub fn run(&mut self, executor: &dyn Executor, mut until: impl FnMut() -> bool) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        let mut next_ping = std::time::Instant::now();
        let mut awaiting: Option<std::time::Instant> = None;
        while !until() {
            let now = std::time::Instant::now();
            if let Some(since) = awaiting
                && now.duration_since(since) >= HEARTBEAT_DEADLINE
            {
                return Err(Error::Lost);
            }
            if awaiting.is_none() && now >= next_ping {
                self.ping(executor)?;
                awaiting = Some(now);
                next_ping = now + self.interval;
            }
            let wait = match awaiting {
                Some(since) => (since + HEARTBEAT_DEADLINE).saturating_duration_since(now),
                None => next_ping.saturating_duration_since(now),
            };
            if let Some(message) = self.rx.recv_timeout::<ServerMessage>(wait)?
                && self.handle(message, executor, &mut seen)?
            {
                awaiting = None;
                // Forget answered attempts the executor no longer holds.
                let held = executor.held();
                seen.retain(|a| held.contains(a));
            }
        }
        self.tx.send(&ClientMessage::Bye)
    }
}

/// Bind a listener for tests and the controller alike.
pub fn listen(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}
