//! Framing, hello/negotiation and heartbeat over an established TLS stream.
//!
//! Frames are a big-endian `u32` length followed by a postcard-encoded
//! message, capped at `MAX_CONTROL_MESSAGE_BYTES` before any allocation. The
//! first exchange is `Hello`/`Welcome`; after that only heartbeats flow here.
//! Anything else on the wire is a protocol violation and ends the session.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{ClientConnection, ServerConnection, StreamOwned, pki_types::ServerName};
use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::WorkerId;
use sentinel_protocol::{
    limits::MAX_CONTROL_MESSAGE_BYTES,
    negotiate::{Hello, Negotiated, Rejected},
};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, identity::fingerprint_of};

/// How often a worker proves it is still there, and how long the controller
/// waits before deciding it is not. Two missed beats, not one: a single
/// delayed packet must not tear down a session carrying live work.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        hello: Hello,
        /// The worker's generated identifier, as raw bytes on the wire.
        worker: [u8; 16],
        name: String,
        /// Present exactly once, on the session that redeems it.
        enrollment: Option<String>,
    },
    Ping(u64),
    Bye,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    Welcome {
        worker: [u8; 16],
        negotiated: Negotiated,
        heartbeat_interval_ms: u32,
    },
    Reject(Rejection),
    Pong(u64),
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

/// What the controller decides about a presenting certificate. Implemented by
/// the store glue; this crate never touches the database.
pub trait Admission: Send + Sync {
    /// A known fingerprint, or an enrollment being redeemed with it.
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
    ) -> std::result::Result<(WorkerId, Negotiated), Rejection>;
    /// A heartbeat arrived from an admitted worker.
    fn seen(&self, worker: WorkerId);
}

type ServerStream = StreamOwned<ServerConnection, TcpStream>;
type ClientStream = StreamOwned<ClientConnection, TcpStream>;

fn write_frame<M: Serialize>(stream: &mut impl Write, message: &M) -> Result<()> {
    let bytes = postcard::to_allocvec(message).map_err(|_| Error::Protocol("encode"))?;
    if bytes.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(Error::Protocol("frame too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<M: for<'de> Deserialize<'de>>(stream: &mut impl Read) -> Result<M> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_CONTROL_MESSAGE_BYTES {
        return Err(Error::Protocol("frame length"));
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes)?;
    postcard::from_bytes(&bytes).map_err(|_| Error::Protocol("decode"))
}

/// One accepted, authenticated worker session on the controller.
pub struct WorkerSession {
    stream: ServerStream,
    pub worker: WorkerId,
    pub negotiated: Negotiated,
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
    let conn = ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, socket);
    // Drive the handshake so the peer certificate is available.
    stream.conn.complete_io(&mut stream.sock)?;
    let fingerprint = stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(fingerprint_of)
        .ok_or(Error::Protocol("no client certificate"))?;

    let ClientMessage::Hello {
        hello,
        worker,
        name,
        enrollment,
    } = read_frame(&mut stream)?
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
    match admission.admit(&fingerprint, worker, &name, &hello, secret.as_ref()) {
        Ok((worker, negotiated)) => {
            write_frame(
                &mut stream,
                &ServerMessage::Welcome {
                    worker: *worker.as_bytes(),
                    negotiated,
                    heartbeat_interval_ms: HEARTBEAT_INTERVAL.as_millis() as u32,
                },
            )?;
            Ok(WorkerSession {
                stream,
                worker,
                negotiated,
                fingerprint,
            })
        }
        Err(rejection) => {
            let _ = write_frame(&mut stream, &ServerMessage::Reject(rejection));
            Err(Error::Rejected(rejection))
        }
    }
}

impl WorkerSession {
    /// Serve heartbeats until the worker says goodbye, stops answering, or
    /// breaks protocol. Each beat is reported to the admission policy, which
    /// records liveness at its own bounded cadence.
    pub fn serve(&mut self, admission: &dyn Admission) -> Result<()> {
        loop {
            match read_frame::<ClientMessage>(&mut self.stream) {
                Ok(ClientMessage::Ping(seq)) => {
                    admission.seen(self.worker);
                    write_frame(&mut self.stream, &ServerMessage::Pong(seq))?;
                }
                Ok(ClientMessage::Bye) => return Ok(()),
                Ok(ClientMessage::Hello { .. }) => return Err(Error::Protocol("second hello")),
                Err(Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Error::Lost);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// The worker's end of a session.
pub struct Link {
    stream: ClientStream,
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
) -> Result<Link> {
    let socket = TcpStream::connect_timeout(&addr, HEARTBEAT_DEADLINE)?;
    socket.set_read_timeout(Some(HEARTBEAT_DEADLINE))?;
    socket.set_nodelay(true)?;
    // The name is irrelevant with a pinned fingerprint but rustls needs one.
    let server_name = ServerName::try_from("sentinel").expect("static name");
    let conn = ClientConnection::new(config, server_name).map_err(|e| Error::Tls(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, socket);
    let enrollment = enrollment.map(sentinel_auth::token::format);
    write_frame(
        &mut stream,
        &ClientMessage::Hello {
            hello,
            worker: *worker.as_bytes(),
            name: name.to_owned(),
            enrollment,
        },
    )?;
    match read_frame::<ServerMessage>(&mut stream)? {
        ServerMessage::Welcome {
            worker,
            negotiated,
            heartbeat_interval_ms,
        } => Ok(Link {
            stream,
            worker: WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?,
            negotiated,
            interval: Duration::from_millis(u64::from(heartbeat_interval_ms)),
            seq: 0,
        }),
        ServerMessage::Reject(why) => Err(Error::Rejected(why)),
        ServerMessage::Pong(_) => Err(Error::Protocol("pong before welcome")),
    }
}

impl Link {
    pub fn heartbeat_interval(&self) -> Duration {
        self.interval
    }

    /// One beat: send a ping and wait for its pong within the deadline.
    pub fn beat(&mut self) -> Result<()> {
        self.seq += 1;
        write_frame(&mut self.stream, &ClientMessage::Ping(self.seq))?;
        match read_frame::<ServerMessage>(&mut self.stream) {
            Ok(ServerMessage::Pong(seq)) if seq == self.seq => Ok(()),
            Ok(ServerMessage::Pong(_)) => Err(Error::Protocol("pong sequence")),
            Ok(_) => Err(Error::Protocol("unexpected message")),
            Err(Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Err(Error::Lost)
            }
            Err(e) => Err(e),
        }
    }

    /// Keep beating at the negotiated interval until `until` returns true or
    /// the controller is lost. The worker's main loop; W02 adds offers to it.
    pub fn run(&mut self, mut until: impl FnMut() -> bool) -> Result<()> {
        while !until() {
            let next = Instant::now() + self.interval;
            self.beat()?;
            let remaining = next.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
        write_frame(&mut self.stream, &ClientMessage::Bye)
    }
}

/// Bind a listener for tests and the controller alike.
pub fn listen(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}
