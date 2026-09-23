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
//! From protocol 7 a session has two connections with one identity. The
//! first is the **control** connection: negotiation, heartbeats, offers and
//! reports — everything whose latency decides whether live work survives. A
//! protocol-7 worker then dials a second **bulk** connection (`BulkHello`)
//! and moves logs, spec chunks, artifact streams and cache transfers onto
//! it. Each connection has its own rustls state behind its own mutex, so a
//! bulk write that blocks on a slow reader can never hold up a pong or an
//! offer; the control connection keeps accepting bulk messages as a
//! fallback when the second connection cannot be established.
//!
//! Full duplex on one TLS connection: the rustls state sits behind a mutex
//! that is held only while bytes move between it and a buffer, never across
//! a socket call. One thread reads the socket; any thread may send. An offer
//! therefore reaches a worker the moment it is placed, not at its next beat.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver as Channel, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use rustls::{ClientConnection, ServerConnection, pki_types::ServerName};
use sentinel_auth::secret::{Digest, Secret};
use sentinel_cache::remote::{Chunk, End, Grant, Need, Push, Refusal, Refused, Serving, Upload};
use sentinel_core::{
    AttemptId, Event, FailureClass, Fence, JobId, Outcome, RepoId, RunId, TenantId, UnixMillis,
    WorkerId,
};
use sentinel_protocol::{
    cache::Trust,
    limits::{
        MAX_API_BODY_BYTES, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_NAME_BYTES,
        MAX_ARTIFACT_PATH_BYTES, MAX_CONTROL_MESSAGE_BYTES, MAX_LIST_ITEMS, MAX_LOG_FRAME_BYTES,
    },
    logs::{Frame, MAX_GAPS, Stream},
    negotiate::{CACHE_CANCEL_MIN, Hello, Negotiated, PROFILE_MIN, Profile, Rejected},
    summary::MAX_SUMMARY_BYTES,
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
/// A run spec crosses the link in chunks of this size, reassembled up to
/// [`MAX_SPEC_BYTES`]; a spec is bounded by the pipeline file it came from.
pub const SPEC_CHUNK_BYTES: usize = 48 * 1024;
pub const MAX_SPEC_BYTES: usize = MAX_API_BODY_BYTES;
/// One cache chunk on the wire. The frame cap is
/// [`MAX_CONTROL_MESSAGE_BYTES`], so a chunk's payload has to leave room for
/// its envelope; the link refuses anything larger as `TooLarge` rather than
/// splitting it, because a chunk's running digest cannot be recomputed for a
/// split piece.
pub const MAX_CACHE_CHUNK_BYTES: usize = 48 * 1024;
/// Cache downloads one session streams at a time; beyond this a need is
/// refused `Busy` instead of spawning another transfer thread. Uploads one
/// connection holds open are bounded the same way.
const MAX_CACHE_TRANSFERS: usize = 4;
/// An upload that has not moved for this long is dropped with its staging
/// file and entry lock (P08-C5): a worker that went quiet mid-offer never
/// pins an entry for the life of its connection.
const UPLOAD_IDLE: Duration = Duration::from_secs(60);
/// Control beats between transport telemetry refreshes.
const TRANSPORT_BEATS: u64 = 12;

/// How the worker reached the controller (Q07). `Unknown` is the honest
/// answer when nothing measured the path — no helper running, or one that has
/// not reported — never a guess that a relay is in use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Path {
    #[default]
    Unknown,
    /// A direct TCP/TLS path to the controller.
    Direct,
    /// Through the Tailcat helper (NAT-traversing, possibly DERP-relayed).
    Relay,
}

/// What the worker's process can say about its transport (Q07). Assembled by
/// the worker's process layer when a helper probe exists; every field that
/// nothing measured stays absent, never a zero claim: `path` is `Unknown`,
/// `rtt_ns`/`helper_version` are `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStats {
    pub path: Path,
    /// Round-trip time of the control session (a Ping/Pong pair), nanoseconds;
    /// `None` before the first beat completes.
    pub rtt_ns: Option<u64>,
    /// Control sessions this worker has opened since process start.
    pub reconnects: u64,
    /// The Tailcat helper's version when one is running; `None` without one.
    pub helper_version: Option<String>,
    /// Bytes written to / read from the control connection over this session.
    pub bytes_out: u64,
    pub bytes_in: u64,
}

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
    /// The attempt moved: a worker-side state event under its fence. A
    /// terminal report may carry the attempt's encoded summary.
    Report {
        attempt: [u8; 16],
        fence: u64,
        event: WireEvent,
        summary: Option<Vec<u8>>,
    },
    /// The worker needs the run spec of an attempt it holds.
    NeedSpec {
        attempt: [u8; 16],
    },
    /// One log frame of an attempt the worker holds, in sequence. At most
    /// `MAX_UNACKED_LOG_FRAMES` may be in flight per attempt.
    Log {
        attempt: [u8; 16],
        seq: u64,
        step: u32,
        stream: u8,
        bytes: Vec<u8>,
    },
    /// No more frames will come: the log is complete through `last_seq`,
    /// with the ranges the worker could not deliver declared as gaps.
    LogEnd {
        attempt: [u8; 16],
        last_seq: u64,
        gaps: Vec<(u64, u64)>,
    },
    /// The worker restarted with this attempt in its leftovers and cannot
    /// say what happened: the controller reconciles it under the fence.
    Abandon {
        attempt: [u8; 16],
        fence: u64,
    },
    /// Protocol 4. Begin publishing artifact `name` of the attempt's job;
    /// the controller validates it against the run spec and answers
    /// `ArtifactGrant` or a refusing `ArtifactVerdict`. One artifact is in
    /// flight per attempt at a time.
    ArtifactBegin {
        attempt: [u8; 16],
        name: String,
    },
    /// Protocol 4. The next file of the in-flight artifact: its `ArtifactData`
    /// frames follow with `seq` from 0 and exactly `len` bytes in order.
    ArtifactFile {
        attempt: [u8; 16],
        path: String,
        len: u64,
        mode: u32,
    },
    /// Protocol 4. One ordered chunk of the in-flight file.
    ArtifactData {
        attempt: [u8; 16],
        seq: u32,
        bytes: Vec<u8>,
    },
    /// Protocol 4. The artifact's file set is complete; the controller
    /// commits the objects, manifest and record and answers a verdict.
    ArtifactEnd {
        attempt: [u8; 16],
        name: String,
    },
    /// Protocol 4. No publishable content, also closing an in-flight
    /// artifact: `reason` 0 = no paths matched, 1 = capture failed.
    ArtifactAbsent {
        attempt: [u8; 16],
        name: String,
        reason: u8,
    },
    Bye,
    /// Protocol 7. The scheduling profile, sent immediately after `Welcome`
    /// when the session negotiated protocol 7: what the worker offers the
    /// scheduler beyond raw CPU and memory. Appended last: postcard encodes
    /// enum variants positionally, so every older variant keeps its index.
    Profile(Profile),
    /// Protocol 7. Opens the second connection of this session: this socket
    /// carries the bulk traffic (logs, spec chunks, artifacts, cache
    /// transfers) while the control connection keeps heartbeats, offers and
    /// reports. `worker` must name a live control session presenting the
    /// same certificate; the controller closes the connection otherwise.
    BulkHello {
        worker: [u8; 16],
    },
    /// Protocol 7 (Q07). How the worker reached the controller.
    Transport(TransportStats),
    /// Protocol 7 (Q08). The worker needs a cache object; answered by
    /// `CacheGrant`, `CacheChunk`s and `CacheEnd`, or by `CacheRefused`.
    /// Resuming an interrupted transfer is the same need with a non-zero
    /// `offset` (and the matching `have` digest), never a separate message.
    CacheNeed(Need),
    /// Protocol 7 (Q08). The worker offers an object it holds so the
    /// controller can keep it for the fleet; answered by `CacheGrant`
    /// (stream it), `CacheEnd` (already stored) or `CacheRefused`.
    CacheOffer(Upload),
    /// Protocol 7 (Q08). One pushed chunk of an open offer.
    CachePush(Push),
    /// Protocol 7 (Q08). The offer's stream is complete.
    CachePushEnd(End),
    /// Protocol 8 (P08-C2). The worker abandoned the attempt's transfer —
    /// a fetch past its budget or a failed offer: the controller stops the
    /// serve (answering `CacheRefused` with `aborted` as its terminal) or
    /// drops the upload's staging. Appended last: postcard encodes variants
    /// positionally.
    CacheCancel {
        attempt: [u8; 16],
    },
}

/// `ClientMessage::Log` from borrowed parts: the same postcard bytes (variant
/// index, then the fields in order; a byte slice encodes exactly like a
/// `Vec<u8>`), without copying a log frame into an owned message first.
struct LogRef<'a> {
    attempt: &'a [u8; 16],
    seq: u64,
    step: u32,
    stream: u8,
    bytes: &'a [u8],
}

/// `ClientMessage::Log`'s position in the enum; asserted by a test.
const LOG_VARIANT: u32 = 6;

impl Serialize for LogRef<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        let mut s = serializer.serialize_struct_variant("ClientMessage", LOG_VARIANT, "Log", 5)?;
        s.serialize_field("attempt", self.attempt)?;
        s.serialize_field("seq", &self.seq)?;
        s.serialize_field("step", &self.step)?;
        s.serialize_field("stream", &self.stream)?;
        s.serialize_field("bytes", self.bytes)?;
        s.end()
    }
}

/// A worker's state event on the wire; mirrors the worker-raised half of
/// `sentinel_core::Event` with the failure class as its stored code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireEvent {
    PreparationStarted,
    StepsStarted,
    FinalizationStarted,
    Passed,
    Failed(u8),
}

impl WireEvent {
    /// Only the events a worker may raise are representable; the controller
    /// still runs them through the state machine under the worker's fence.
    pub fn from_event(event: Event) -> Option<WireEvent> {
        Some(match event {
            Event::PreparationStarted => WireEvent::PreparationStarted,
            Event::StepsStarted => WireEvent::StepsStarted,
            Event::FinalizationStarted => WireEvent::FinalizationStarted,
            Event::Passed => WireEvent::Passed,
            Event::Failed(class) => WireEvent::Failed(class as u8),
            _ => return None,
        })
    }

    pub fn to_event(self) -> Result<Event> {
        Ok(match self {
            WireEvent::PreparationStarted => Event::PreparationStarted,
            WireEvent::StepsStarted => Event::StepsStarted,
            WireEvent::FinalizationStarted => Event::FinalizationStarted,
            WireEvent::Passed => Event::Passed,
            WireEvent::Failed(code) => Event::Failed(match code {
                0 => FailureClass::CommandFailed,
                1 => FailureClass::CommandSignaled,
                2 => FailureClass::OutOfMemory,
                3 => FailureClass::ExecutionTimeout,
                5 => FailureClass::Canceled,
                6 => FailureClass::Preparation,
                10 => FailureClass::Publication,
                11 => FailureClass::Runtime,
                _ => return Err(Error::Protocol("failure class")),
            }),
        })
    }
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
    pub job_index: u32,
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
        /// Held attempts whose job has cancellation desired: end them
        /// gracefully and report `Canceled`.
        cancel: Vec<[u8; 16]>,
    },
    Offer(WireOffer),
    /// One chunk of the run spec asked for with `NeedSpec`, in order.
    Spec {
        attempt: [u8; 16],
        seq: u32,
        last: bool,
        bytes: Vec<u8>,
    },
    /// The attempt is not held by this worker or has no spec: stop it.
    NoSpec {
        attempt: [u8; 16],
    },
    /// Precedes the `Spec` chunks: what the worker needs to evaluate the
    /// job's expressions.
    Context(WireContext),
    /// Frames through `through` are durably stored; the worker may drop
    /// them from its spool.
    LogAck {
        attempt: [u8; 16],
        through: u64,
    },
    /// The controller will store no more frames of this attempt (size cap,
    /// or the attempt is not held here); the worker stops sending.
    LogRefused {
        attempt: [u8; 16],
    },
    /// Protocol 5. The attempt's end marker is durable on the controller;
    /// the worker may drop the spool it replayed from.
    LogEndAck {
        attempt: [u8; 16],
    },
    /// Protocol 2 only; follows Context, before spec bytes. Never persisted.
    Source {
        attempt: [u8; 16],
        access: sentinel_protocol::source::Access,
    },
    /// Protocol 4. The artifact named in `ArtifactBegin` was validated
    /// against the run spec and budgets; the worker may stream its files.
    ArtifactGrant {
        attempt: [u8; 16],
        name: String,
    },
    /// Protocol 4. The terminal answer for an artifact: stored, recorded
    /// absent/failed, or refused (`ArtifactCode`); the artifact is closed.
    ArtifactVerdict {
        attempt: [u8; 16],
        name: String,
        code: u8,
    },
    /// Protocol 6. The job context with its cache boundary: the tenant the
    /// run belongs to and the trust class derived from the recorded event.
    /// Sent instead of `Context` to workers that negotiated it; earlier
    /// workers get `Context` and default to the pull-request scope.
    /// Appended last: postcard encodes enum variants positionally.
    Context2(WireContext2),
    /// Protocol 7 (Q08). The accepted start of a cache transfer: the offset
    /// the stream resumes from and the whole object's digest. For a
    /// `CacheOffer` the controller already stores, there is no grant: it
    /// answers `CacheEnd` with no bytes.
    CacheGrant(Grant),
    /// Protocol 7 (Q08). One chunk of a granted transfer, in order, with the
    /// running digest of the stream through it.
    CacheChunk(Chunk),
    /// Protocol 7 (Q08). Terminal both ways: the fetch is complete, or an
    /// offer was stored. Appended last: postcard encodes variants positionally.
    CacheEnd(End),
    /// Protocol 7 (Q08). The transfer is refused; `code` is the cache
    /// owner's stable refusal code.
    CacheRefused(Refused),
}

/// What the controller did with a log frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogVerdict {
    /// Stored and synced through this sequence.
    Acked(u64),
    /// Permanently refused: the attempt is not this worker's, its log has
    /// already ended, or the size cap is reached. `LogRefused` goes out
    /// and the worker stops sending.
    Refused,
    /// A transient controller fault (a store read or write, log I/O):
    /// nothing is answered and the connection that carried the frame is
    /// closed, so the worker rewinds to its last acknowledgement and
    /// resends — a fault never becomes a permanent refusal.
    Retry,
}

/// A file's permission bits inside an artifact manifest; only the low mode
/// bits are meaningful on the wire.
pub const ARTIFACT_MODE_BITS: u32 = 0o7777;

/// The terminal code of an `ArtifactVerdict`: what the controller did with
/// an artifact publication, so the worker learns how it was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCode {
    /// Committed and recorded present.
    Stored,
    /// The job's spec declared no artifact of that name.
    NotDeclared,
    /// Duplicates a finished artifact record for this attempt.
    Duplicate,
    /// Name/path/frame/length/ordering constraint violated.
    Invalid,
    /// The per-artifact or per-run byte budget was exceeded.
    TooLarge,
    /// The artifact holds no matching content (recorded absent).
    Absent,
    /// Recorded as failed: capture or publication could not complete.
    CaptureFailed,
    /// The attempt is not held here under that fence.
    Stale,
    /// Storage faulted; nothing was recorded, the worker may retry once.
    Store,
}

impl ArtifactCode {
    /// The wire code.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::NotDeclared => 1,
            Self::Duplicate => 2,
            Self::Invalid => 3,
            Self::TooLarge => 4,
            Self::Absent => 5,
            Self::CaptureFailed => 6,
            Self::Stale => 7,
            Self::Store => 8,
        }
    }
    /// Decode a verdict code; unrecognised values read as `Stale` — to an
    /// older worker the safest reading is that nothing landed.
    pub fn from_u8(code: u8) -> Self {
        match code {
            0 => Self::Stored,
            1 => Self::NotDeclared,
            2 => Self::Duplicate,
            3 => Self::Invalid,
            4 => Self::TooLarge,
            5 => Self::Absent,
            6 => Self::CaptureFailed,
            _ => Self::Stale,
        }
    }
}

/// The grant-or-verdict answer to `ArtifactBegin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactReply {
    /// Validated; the worker may stream the artifact's files.
    Grant,
    /// Terminal; the artifact is closed on the controller.
    Verdict(ArtifactCode),
}

/// [`JobContext`] on the wire; dependency outcomes as their stored codes.
/// Protocol 3 adds the event facts; older workers are served `NoSpec`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WireContext {
    pub attempt: [u8; 16],
    pub run: [u8; 16],
    pub repo: [u8; 16],
    pub repo_name: String,
    pub job: [u8; 16],
    pub job_name: String,
    pub sha: String,
    pub cancelled: bool,
    pub needs: Vec<(String, u8)>,
    /// What triggered the run: `push`, `tag`, `pull_request` or `manual`.
    pub event: String,
    /// The ref the event concerns, as recorded in the run's provenance.
    pub event_ref: String,
    /// The pull request's base branch, when the run came from one.
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    /// A short, stable key for the event: the branch or tag name, `pr-<n>`,
    /// or `manual`.
    pub event_key: String,
}

/// [`JobContext`] on the wire from protocol 6: everything `WireContext`
/// carries, plus the cache boundary — the run's tenant and the trust class
/// the controller derived from the recorded event (`Trust::of_event`).
/// `tenant` is all-zero when the context carries none; `trust` is a
/// `Trust` wire code, never defaulted: an undecodable byte is a protocol
/// error rather than a guessed boundary.
#[derive(Debug, Serialize, Deserialize)]
pub struct WireContext2 {
    pub attempt: [u8; 16],
    pub run: [u8; 16],
    pub repo: [u8; 16],
    pub repo_name: String,
    pub job: [u8; 16],
    pub job_name: String,
    pub sha: String,
    pub cancelled: bool,
    pub needs: Vec<(String, u8)>,
    /// What triggered the run: `push`, `tag`, `pull_request` or `manual`.
    pub event: String,
    /// The ref the event concerns, as recorded in the run's provenance.
    pub event_ref: String,
    /// The pull request's base branch, when the run came from one.
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    /// A short, stable key for the event: the branch or tag name, `pr-<n>`,
    /// or `manual`.
    pub event_key: String,
    /// The tenant the run belongs to; all-zero encodes "none recorded".
    pub tenant: [u8; 16],
    /// `Trust` wire code for the cache scope this job may use.
    pub trust: u8,
}

/// The event facts a worker may evaluate `event.*` against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    pub name: String,
    pub ref_name: String,
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    pub key: String,
}

/// What the worker evaluates expressions against: identity of the run,
/// repository and job, the event that triggered it, dependency outcomes by
/// name, cancellation. `tenant`/`trust` are the cache boundary (protocol 6;
/// absent on older wires, where the worker defaults to the pull-request
/// scope and no recorded tenant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobContext {
    pub source: Option<sentinel_protocol::source::Access>,
    pub run: RunId,
    pub repo: RepoId,
    pub repo_name: String,
    pub job: JobId,
    pub job_name: String,
    pub sha: String,
    pub event: EventContext,
    pub cancelled: bool,
    pub needs: Vec<(String, Outcome)>,
    /// The tenant the run belongs to; `None` on a protocol <6 context,
    /// which could not carry it.
    pub tenant: Option<TenantId>,
    /// The cache trust class derived from `event` (`Trust::of_event`);
    /// `PullRequest` on a protocol <6 context — the scope that can never
    /// touch protected state.
    pub trust: Trust,
}

const fn outcome_code(outcome: Outcome) -> u8 {
    match outcome {
        Outcome::Passed => 0,
        Outcome::Skipped => 1,
        Outcome::Canceled => 2,
        Outcome::TimedOut => 3,
        Outcome::Failed => 4,
        Outcome::InfraFailed => 5,
    }
}

const fn outcome_from_code(code: u8) -> Option<Outcome> {
    Some(match code {
        0 => Outcome::Passed,
        1 => Outcome::Skipped,
        2 => Outcome::Canceled,
        3 => Outcome::TimedOut,
        4 => Outcome::Failed,
        5 => Outcome::InfraFailed,
        _ => return None,
    })
}

impl JobContext {
    /// The protocol <6 shape: `tenant` and `trust` do not exist on that
    /// wire — the receiver defaults them to `None`/`PullRequest`.
    pub(crate) fn to_wire(&self, attempt: AttemptId) -> WireContext {
        WireContext {
            attempt: *attempt.as_bytes(),
            run: *self.run.as_bytes(),
            repo: *self.repo.as_bytes(),
            repo_name: self.repo_name.clone(),
            job: *self.job.as_bytes(),
            job_name: self.job_name.clone(),
            sha: self.sha.clone(),
            cancelled: self.cancelled,
            needs: self
                .needs
                .iter()
                .map(|(name, outcome)| (name.clone(), outcome_code(*outcome)))
                .collect(),
            event: self.event.name.clone(),
            event_ref: self.event.ref_name.clone(),
            base_ref: self.event.base_ref.clone(),
            pr_number: self.event.pr_number,
            event_key: self.event.key.clone(),
        }
    }

    /// The protocol 6 shape: same facts plus the cache boundary.
    pub(crate) fn to_wire2(&self, attempt: AttemptId) -> WireContext2 {
        WireContext2 {
            attempt: *attempt.as_bytes(),
            run: *self.run.as_bytes(),
            repo: *self.repo.as_bytes(),
            repo_name: self.repo_name.clone(),
            job: *self.job.as_bytes(),
            job_name: self.job_name.clone(),
            sha: self.sha.clone(),
            cancelled: self.cancelled,
            needs: self
                .needs
                .iter()
                .map(|(name, outcome)| (name.clone(), outcome_code(*outcome)))
                .collect(),
            event: self.event.name.clone(),
            event_ref: self.event.ref_name.clone(),
            base_ref: self.event.base_ref.clone(),
            pr_number: self.event.pr_number,
            event_key: self.event.key.clone(),
            tenant: self.tenant.map(|id| *id.as_bytes()).unwrap_or([0; 16]),
            trust: self.trust.to_u8(),
        }
    }

    fn from_wire(wire: WireContext) -> Result<(AttemptId, JobContext)> {
        Ok((
            AttemptId::from_bytes(wire.attempt).map_err(|_| Error::Protocol("id"))?,
            JobContext {
                source: None,
                run: RunId::from_bytes(wire.run).map_err(|_| Error::Protocol("id"))?,
                repo: RepoId::from_bytes(wire.repo).map_err(|_| Error::Protocol("id"))?,
                repo_name: wire.repo_name,
                job: JobId::from_bytes(wire.job).map_err(|_| Error::Protocol("id"))?,
                job_name: wire.job_name,
                sha: wire.sha,
                event: EventContext {
                    name: wire.event,
                    ref_name: wire.event_ref,
                    base_ref: wire.base_ref,
                    pr_number: wire.pr_number,
                    key: wire.event_key,
                },
                cancelled: wire.cancelled,
                needs: decode_needs(wire.needs)?,
                // The wire could not say it: the safest scope is the one a
                // pull request would get.
                tenant: None,
                trust: Trust::PullRequest,
            },
        ))
    }

    fn from_wire2(wire: WireContext2) -> Result<(AttemptId, JobContext)> {
        // A trust byte this build cannot decode is a protocol error, never
        // a guessed boundary.
        let trust = Trust::from_u8(wire.trust).ok_or(Error::Protocol("trust"))?;
        let tenant = if wire.tenant == [0; 16] {
            None
        } else {
            Some(TenantId::from_bytes(wire.tenant).map_err(|_| Error::Protocol("id"))?)
        };
        Ok((
            AttemptId::from_bytes(wire.attempt).map_err(|_| Error::Protocol("id"))?,
            JobContext {
                source: None,
                run: RunId::from_bytes(wire.run).map_err(|_| Error::Protocol("id"))?,
                repo: RepoId::from_bytes(wire.repo).map_err(|_| Error::Protocol("id"))?,
                repo_name: wire.repo_name,
                job: JobId::from_bytes(wire.job).map_err(|_| Error::Protocol("id"))?,
                job_name: wire.job_name,
                sha: wire.sha,
                event: EventContext {
                    name: wire.event,
                    ref_name: wire.event_ref,
                    base_ref: wire.base_ref,
                    pr_number: wire.pr_number,
                    key: wire.event_key,
                },
                cancelled: wire.cancelled,
                needs: decode_needs(wire.needs)?,
                tenant,
                trust,
            },
        ))
    }
}

/// Dependency outcomes as their stored codes; bounded like every list.
fn decode_needs(wire: Vec<(String, u8)>) -> Result<Vec<(String, Outcome)>> {
    if wire.len() > MAX_LIST_ITEMS {
        return Err(Error::Protocol("needs list"));
    }
    let mut needs = Vec::with_capacity(wire.len());
    for (name, code) in wire {
        needs.push((
            name,
            outcome_from_code(code).ok_or(Error::Protocol("outcome"))?,
        ));
    }
    Ok(needs)
}

/// The context message for the negotiated protocol: `Context2` from
/// protocol 6, the original `Context` before it.
pub(crate) fn context_message(
    protocol: u16,
    context: &JobContext,
    attempt: AttemptId,
) -> ServerMessage {
    if protocol >= 6 {
        let mut wire = context.to_wire2(attempt);
        // Before protocol 8 there is no `Unprotected`: such a job gets the
        // pull-request scope, which can never touch protected state.
        wire.trust = context.trust.for_protocol(protocol).to_u8();
        ServerMessage::Context2(wire)
    } else {
        ServerMessage::Context(context.to_wire(attempt))
    }
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
    /// `name@sha256:…` as resolved on the run; what the worker pulls.
    pub image_digest: String,
    pub image_platform: String,
    /// Position of the job in the run's compiled spec.
    pub job_index: u32,
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
            job_index: self.job_index,
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
            job_index: wire.job_index,
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

/// The controller's answer to a heartbeat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beat {
    /// Every held attempt the controller recognises is renewed to this.
    pub lease_until: UnixMillis,
    /// Attempts the controller no longer counts as held: stop at once.
    pub stop: Vec<AttemptId>,
    /// Attempts whose job has cancellation desired: end gracefully.
    pub cancel: Vec<AttemptId>,
}

/// What the controller does with an admitted worker's messages.
pub trait SessionHandler: Send + Sync {
    /// A controller may resolve source access off the heartbeat thread.
    /// True means it owns sending Spec/NoSpec on this exact session.
    fn spec_requested(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _sender: Sender,
        _protocol: u16,
    ) -> bool {
        false
    }
    /// A heartbeat naming the attempts the worker holds.
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<Beat>;
    fn acknowledged(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    fn declined(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    /// A worker-side state event. The handler applies it under the fence;
    /// a stale one changes nothing. `summary` accompanies a terminal event.
    fn reported(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        fence: Fence,
        event: Event,
        summary: Option<Vec<u8>>,
    );
    /// The job context and encoded run spec of an attempt this worker
    /// holds, or `None`.
    fn spec(&self, worker: WorkerId, attempt: AttemptId) -> Option<(JobContext, Vec<u8>)>;
    /// A log frame of an attempt this worker holds. Acknowledged only once
    /// durable; a frame out of sequence or past the size cap is refused.
    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict;
    /// The attempt's log is complete through `last_seq`. `Acked` means the
    /// end marker is durable; the session answers `LogEndAck` when the
    /// negotiated protocol carries it. The default refuses: nothing was
    /// recorded.
    fn log_end(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _last_seq: u64,
        _gaps: &[(u64, u64)],
    ) -> LogVerdict {
        LogVerdict::Refused
    }
    /// The worker found the attempt in its leftovers after a restart.
    fn abandoned(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    /// Protocol 4. Begin publishing artifact `name` of a held attempt:
    /// validate it against the run spec and the byte budgets. `Grant` lets
    /// the worker stream; a verdict closes the artifact at once. The
    /// default answers `Stale`: nothing was granted.
    fn artifact_begin(&self, _worker: WorkerId, _attempt: AttemptId, _name: &str) -> ArtifactReply {
        ArtifactReply::Verdict(ArtifactCode::Stale)
    }
    /// Protocol 4. The next file of the in-flight artifact, `len` bytes of
    /// `ArtifactData` to follow. `Some` fails the artifact at once.
    fn artifact_file(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _path: &str,
        _len: u64,
        _mode: u32,
    ) -> Option<ArtifactCode> {
        Some(ArtifactCode::Stale)
    }
    /// Protocol 4. Ordered chunk `seq` of the in-flight file. `Some` fails
    /// the artifact at once.
    fn artifact_data(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _seq: u32,
        _bytes: &[u8],
    ) -> Option<ArtifactCode> {
        Some(ArtifactCode::Stale)
    }
    /// Protocol 4. Commit the in-flight artifact; the code is terminal.
    fn artifact_end(&self, _worker: WorkerId, _attempt: AttemptId, _name: &str) -> ArtifactCode {
        ArtifactCode::Stale
    }
    /// Protocol 4. Record `name` absent (`reason` 0) or failed (1); also
    /// abandons an in-flight publication of the same name.
    fn artifact_absent(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _name: &str,
        _reason: u8,
    ) -> ArtifactCode {
        ArtifactCode::Stale
    }
    /// Protocol 7. The scheduling profile the worker reported immediately
    /// after `Welcome`, with the capacity it sent in its hello (reported
    /// together so disk and CPU/RAM land in one write). Recording it is what
    /// lets placement see the worker's disk, labels, host and availability;
    /// `Err` ends the session, because a worker whose profile cannot be
    /// recorded must not keep taking work against stale placement data. The
    /// default accepts and records nothing.
    fn profiled(&self, _worker: WorkerId, _profile: &Profile, _capacity: Capacity) -> Result<()> {
        Ok(())
    }
    /// Protocol 7 (Q07). The worker's latest transport telemetry.
    fn transport(&self, _worker: WorkerId, _stats: &TransportStats) {}
    /// Protocol 7 (Q08). Authorizes a cache download. `Some(root)` means the
    /// fence and cache scope checked out and the session may serve the need
    /// from the controller's store under `root`; `None` refuses. The
    /// authorization rule is the fenced attempt: it must be held by the
    /// worker, and the need's tenant, repo and trust class must equal the
    /// attempt's. The default refuses.
    fn cache_need(&self, _worker: WorkerId, _need: &Need) -> Option<PathBuf> {
        None
    }
    /// Protocol 7 (Q08). Authorizes an upload the same way. `Some(root)`
    /// seeds the object under `root` and the session holds the receiving
    /// state for the offer's push frames; `None` refuses.
    fn cache_offer(&self, _worker: WorkerId, _upload: &Upload) -> Option<PathBuf> {
        None
    }
}

/// The rustls state and the socket it writes to. The lock is held only while
/// bytes move between the connection and a buffer.
struct Shared {
    conn: Mutex<rustls::Connection>,
    sock: TcpStream,
    /// Frame bytes written to / socket bytes read from this connection. What
    /// Q07 telemetry reports is measured here, never estimated.
    out: AtomicU64,
    in_: AtomicU64,
}

impl Shared {
    fn bytes(&self) -> (u64, u64) {
        (
            self.out.load(Ordering::Relaxed),
            self.in_.load(Ordering::Relaxed),
        )
    }
}

/// The sending half: cheap to clone, usable from any thread.
#[derive(Clone)]
pub struct Sender(Arc<Shared>);

thread_local! {
    /// Encode scratch, reused by every send on this thread: a frame costs
    /// no allocation once the buffer has grown to the largest one sent.
    static ENCODE: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Sender {
    /// Encode, encrypt and write one frame. Holds the connection lock across
    /// the socket write so frames from different threads never interleave.
    /// A write that fails — including one that ran into the socket's write
    /// timeout because the peer stopped reading — leaves the TLS stream in
    /// an unknown state, so the connection is torn down: the reader fails
    /// out, the session ends, and nothing waits on a dead peer forever.
    pub(crate) fn send<M: Serialize>(&self, message: &M) -> Result<()> {
        ENCODE.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            scratch.clear();
            scratch.extend_from_slice(&[0; 4]);
            let mut buffer = std::mem::take(&mut *scratch);
            let encoded = postcard::to_extend(message, buffer);
            buffer = match encoded {
                Ok(buffer) => buffer,
                Err(_) => return Err(Error::Protocol("encode")),
            };
            let len = buffer.len() - 4;
            let outcome = if len > MAX_CONTROL_MESSAGE_BYTES {
                Err(Error::Protocol("frame too large"))
            } else {
                buffer[..4].copy_from_slice(&(len as u32).to_be_bytes());
                self.write_frame(&buffer)
            };
            *scratch = buffer;
            outcome
        })
    }

    fn write_frame(&self, frame: &[u8]) -> Result<()> {
        let mut conn = self.0.conn.lock().unwrap_or_else(|p| p.into_inner());
        let written = (|| -> Result<()> {
            conn.writer().write_all(frame)?;
            let mut sock = &self.0.sock;
            while conn.wants_write() {
                conn.write_tls(&mut sock)?;
            }
            Ok(())
        })();
        drop(conn);
        match written {
            Ok(()) => {
                // Counted only once the bytes are out: a frame that failed
                // to write never inflates the throughput figure.
                self.0.out.fetch_add(frame.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                self.close();
                Err(match error {
                    Error::Io(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        Error::Lost
                    }
                    error => error,
                })
            }
        }
    }

    /// (bytes written, socket bytes read) on this connection.
    pub fn bytes(&self) -> (u64, u64) {
        self.0.bytes()
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
    /// `Lost` is the peer going away. The bound is on the whole frame, not
    /// on each read: a peer dripping one byte just inside the socket's read
    /// timeout still runs out after at most twice `timeout` (the check runs
    /// between reads, so no per-read timer syscall is spent on it).
    pub(crate) fn recv_timeout<M: for<'de> Deserialize<'de>>(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<M>> {
        let started = Instant::now();
        loop {
            if let Some(message) = self.take_frame()? {
                return Ok(Some(message));
            }
            if self.drain_plaintext()? {
                continue;
            }
            if started.elapsed() >= timeout {
                return Ok(None);
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
            self.shared.in_.fetch_add(n as u64, Ordering::Relaxed);
            while !slice.is_empty() {
                let stalled = match conn.read_tls(&mut slice) {
                    Ok(0) => true,
                    Ok(_) => false,
                    // "message buffer full": rustls holds as much undecrypted
                    // or unread plaintext as it will take.
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => true,
                    Err(e) => return Err(e.into()),
                };
                if stalled {
                    // Decrypt, then move the plaintext out so rustls has room
                    // for the rest of this read: a burst of full frames (a
                    // cache push stream) must never overflow its buffer.
                    conn.process_new_packets()
                        .map_err(|e| Error::Tls(e.to_string()))?;
                    let before = self.plain.len();
                    move_plaintext(&mut conn, &mut self.plain)?;
                    if self.plain.len() == before && conn.read_tls(&mut slice).is_err() {
                        return Err(Error::Protocol("tls buffer"));
                    }
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

/// Move whatever plaintext rustls has decrypted into `plain`. A clean close
/// is left for the next `drain_plaintext` to report.
fn move_plaintext(conn: &mut rustls::Connection, plain: &mut Vec<u8>) -> Result<()> {
    loop {
        let start = plain.len();
        plain.resize(start + TLS_READ_BYTES, 0);
        match conn.reader().read(&mut plain[start..]) {
            Ok(0) => {
                plain.truncate(start);
                return Ok(());
            }
            Ok(n) => plain.truncate(start + n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                plain.truncate(start);
                return Ok(());
            }
            Err(e) => {
                plain.truncate(start);
                return Err(e.into());
            }
        }
    }
}

fn split(conn: rustls::Connection, sock: TcpStream) -> Result<(Sender, Receiver)> {
    let reader = sock.try_clone()?;
    let shared = Arc::new(Shared {
        conn: Mutex::new(conn),
        sock,
        out: AtomicU64::new(0),
        in_: AtomicU64::new(0),
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

/// One answer to an in-flight cache transfer, as it arrived.
enum CacheAnswer {
    Grant(Grant),
    Chunk(Chunk),
    End,
    Refused(Refused),
}

impl CacheAnswer {
    /// `CacheEnd` and `CacheRefused` close a transfer; nothing of it
    /// follows them.
    fn terminal(&self) -> bool {
        matches!(self, Self::End | Self::Refused(_))
    }
}

/// Answers one transfer may have queued before its caller reads them; a
/// transfer whose caller falls further behind (disk or hashing slower than
/// the link) is abandoned rather than buffered without bound (P08-C9).
const ANSWER_QUEUE: usize = 64;

/// One attempt's place in the router.
enum Slot {
    /// A caller is waiting on these answers.
    Live(mpsc::SyncSender<CacheAnswer>),
    /// The caller gave up before the transfer's terminal answer: what the
    /// controller still sends for it is swallowed here until that terminal
    /// arrives, and a new transfer of the attempt is `busy` meanwhile — the
    /// stale tail can never be routed into it (P08-C3).
    Draining,
}

/// Routes cache answers from whichever thread reads the session to the call
/// waiting on that attempt: a transfer is synchronous — the caller sends the
/// need and blocks — but the frames arrive on the session reader, so the two
/// meet here. The reader never blocks on a slow caller: a full queue
/// abandons that transfer.
#[derive(Default)]
pub struct CacheRouter {
    waiting: Mutex<HashMap<AttemptId, Slot>>,
}

impl CacheRouter {
    /// Claim `attempt` for one transfer. A second concurrent transfer for the
    /// same attempt — or one while an abandoned transfer still drains — is
    /// refused `Busy`: the wire routes by attempt alone.
    fn register(&self, attempt: AttemptId) -> std::result::Result<Channel<CacheAnswer>, Refusal> {
        let (tx, rx) = mpsc::sync_channel(ANSWER_QUEUE);
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        if waiting.contains_key(&attempt) {
            return Err(Refusal::Busy);
        }
        waiting.insert(attempt, Slot::Live(tx));
        Ok(rx)
    }

    /// The caller is done: a transfer that saw its terminal answer frees the
    /// attempt, one that did not leaves it draining.
    fn finish(&self, attempt: AttemptId, terminal: bool) {
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        if terminal {
            waiting.remove(&attempt);
        } else if let Some(slot) = waiting.get_mut(&attempt) {
            *slot = Slot::Draining;
        }
    }

    /// Hand an answer to the transfer waiting for it, if any.
    fn route(&self, attempt: AttemptId, answer: CacheAnswer) {
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        let terminal = answer.terminal();
        let drop_slot = match waiting.get_mut(&attempt) {
            None => false,
            Some(Slot::Draining) => terminal,
            Some(Slot::Live(tx)) => match tx.try_send(answer) {
                Ok(()) => false,
                // The caller is too far behind: dropping the sender ends its
                // wait (disconnected), and the rest of the stream drains.
                Err(mpsc::TrySendError::Full(_)) => {
                    waiting.insert(attempt, Slot::Draining);
                    false
                }
                // The caller already left; a terminal closes the attempt.
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    if !terminal {
                        waiting.insert(attempt, Slot::Draining);
                    }
                    terminal
                }
            },
        };
        if drop_slot {
            waiting.remove(&attempt);
        }
    }
}

/// The worker's [`sentinel_cache::remote::Remote`] over the link (Q08):
/// requests go out on the bulk connection when one is attached and on the
/// control connection otherwise, and the session reader routes the answers
/// back to the call that is waiting for them. Cheap to clone a reference to;
/// the executor gets it from [`Reporter::remote_cache`].
pub struct LinkRemote {
    control: Sender,
    bulk: Mutex<BulkSlot>,
    router: Arc<CacheRouter>,
    /// The negotiated protocol: from 8 an abandoned transfer is cancelled
    /// on the controller (`CacheCancel`).
    protocol: u16,
}

/// The live bulk attachment and the route history it has been through.
#[derive(Default)]
struct BulkSlot {
    sender: Option<Sender>,
    route: Route,
}

/// Which route a bulk-class send took, as counts of bulk attachments and
/// detachments over the session. A sender that finds `detached` moved since
/// its last send knows frames it handed to the dead connection may never
/// have arrived and must rewind before anything else goes out; `attached`
/// moving means later frames may overtake ones still in flight on control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub attached: u64,
    pub detached: u64,
}

impl LinkRemote {
    /// Tell the controller this worker abandoned the attempt's transfer
    /// (P08-C2): a serve stops at its next chunk instead of streaming the
    /// rest of the bundle into a dropped channel, and an upload releases its
    /// staging and lock. Best effort, protocol 8 only; the draining slot
    /// swallows whatever is already in flight.
    fn cancel(&self, attempt: AttemptId) {
        if self.protocol >= CACHE_CANCEL_MIN.0 {
            let _ = self.send(&ClientMessage::CacheCancel {
                attempt: *attempt.as_bytes(),
            });
        }
    }

    fn send(&self, message: &impl Serialize) -> Result<Route> {
        let (bulk, route) = {
            let slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
            (slot.sender.clone(), slot.route)
        };
        match bulk {
            Some(bulk) => bulk.send(message)?,
            None => self.control.send(message)?,
        }
        Ok(route)
    }

    fn route(&self) -> Route {
        self.bulk.lock().unwrap_or_else(|p| p.into_inner()).route
    }

    /// The bulk connection is up: bulk-class traffic moves to it.
    fn attach_bulk(&self, bulk: Sender) {
        let mut slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
        slot.sender = Some(bulk);
        slot.route.attached += 1;
    }

    /// The bulk connection ended: the control connection takes the traffic
    /// back until a new one is up.
    fn detach_bulk(&self) {
        let mut slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
        if slot.sender.take().is_some() {
            slot.route.detached += 1;
        }
    }

    /// Route one received cache answer to its waiting transfer.
    fn answer(&self, attempt: AttemptId, answer: CacheAnswer) {
        self.router.route(attempt, answer);
    }
}

impl sentinel_cache::remote::Remote for LinkRemote {
    fn fetch(
        &self,
        need: &Need,
        deadline: Instant,
        sink: &mut dyn sentinel_cache::remote::Sink,
    ) -> std::result::Result<(), Refusal> {
        let attempt = AttemptId::from_bytes(need.attempt).map_err(|_| Refusal::Denied)?;
        let answers = self.router.register(attempt)?;
        // Deregister on every exit, including a sink's early stop — and on
        // an exit before the terminal answer, cancel on the controller and
        // leave the attempt draining.
        let mut claim = Claim {
            remote: self,
            attempt,
            terminal: false,
        };
        self.send(&ClientMessage::CacheNeed(need.clone()))
            .map_err(|_| Refusal::Aborted)?;
        let mut planned = false;
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                return Err(Refusal::Aborted);
            }
            match answers.recv_timeout(wait) {
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Err(Refusal::Aborted);
                }
                Ok(CacheAnswer::Refused(refused)) => {
                    claim.terminal = true;
                    return Err(Refusal::from_code(refused.code).unwrap_or(Refusal::Denied));
                }
                Ok(CacheAnswer::Grant(grant)) => {
                    if planned {
                        return Err(Refusal::Store);
                    }
                    planned = true;
                    sink.plan(&grant)?;
                }
                Ok(CacheAnswer::Chunk(chunk)) => {
                    if !planned {
                        return Err(Refusal::Store);
                    }
                    sink.chunk(&chunk)?;
                }
                // The end marker is terminal; a stream without a plan never
                // opened, so it is a protocol violation, not a completion.
                Ok(CacheAnswer::End) => {
                    claim.terminal = true;
                    return if planned { Ok(()) } else { Err(Refusal::Store) };
                }
            }
        }
    }

    fn offer(
        &self,
        upload: &Upload,
        deadline: Instant,
        source: &mut dyn Read,
    ) -> std::result::Result<(), Refusal> {
        let attempt = AttemptId::from_bytes(upload.attempt).map_err(|_| Refusal::Denied)?;
        let answers = self.router.register(attempt)?;
        let mut claim = Claim {
            remote: self,
            attempt,
            terminal: false,
        };
        self.send(&ClientMessage::CacheOffer(upload.clone()))
            .map_err(|_| Refusal::Aborted)?;
        // The controller either grants a stream (it does not store this
        // digest yet), answers `CacheEnd` (it already stores it) or refuses.
        let start = match wait_answer(&answers, deadline)? {
            CacheAnswer::Refused(refused) => {
                claim.terminal = true;
                return Err(Refusal::from_code(refused.code).unwrap_or(Refusal::Denied));
            }
            CacheAnswer::End => {
                claim.terminal = true;
                return Ok(());
            }
            CacheAnswer::Grant(grant) => grant,
            CacheAnswer::Chunk(_) => return Err(Refusal::Store),
        };
        let mut offset = 0u64;
        // A granted offset is where the controller wants the stream to start;
        // today it is always 0, but skipping is cheap and keeps the contract.
        let mut skip = start.offset;
        let mut buffer = vec![0u8; MAX_CACHE_CHUNK_BYTES];
        let mut sent = 0u64;
        loop {
            if Instant::now() >= deadline {
                return Err(Refusal::Aborted);
            }
            let read = source.read(&mut buffer).map_err(|_| Refusal::Aborted)?;
            if read == 0 {
                break;
            }
            let mut piece = &buffer[..read];
            if skip > 0 {
                let drop = skip.min(piece.len() as u64) as usize;
                skip -= drop as u64;
                piece = &piece[drop..];
            }
            if piece.is_empty() {
                continue;
            }
            self.send(&ClientMessage::CachePush(Push {
                attempt: upload.attempt,
                offset,
                bytes: piece.to_vec(),
            }))
            .map_err(|_| Refusal::Aborted)?;
            offset += piece.len() as u64;
            sent += piece.len() as u64;
            if sent > upload.total {
                return Err(Refusal::Aborted);
            }
        }
        if sent != upload.total {
            // The source ended before the declared length: never claim a
            // complete stream the bytes do not back.
            return Err(Refusal::Aborted);
        }
        self.send(&ClientMessage::CachePushEnd(End {
            attempt: upload.attempt,
            digest: upload.digest,
        }))
        .map_err(|_| Refusal::Aborted)?;
        let answer = wait_answer(&answers, deadline)?;
        claim.terminal = answer.terminal();
        match answer {
            CacheAnswer::End => Ok(()),
            CacheAnswer::Refused(refused) => {
                Err(Refusal::from_code(refused.code).unwrap_or(Refusal::Denied))
            }
            CacheAnswer::Grant(_) | CacheAnswer::Chunk(_) => Err(Refusal::Store),
        }
    }
}

/// Answers one transfer waits for, bounded by `deadline`.
fn wait_answer(
    answers: &Channel<CacheAnswer>,
    deadline: Instant,
) -> std::result::Result<CacheAnswer, Refusal> {
    let wait = deadline.saturating_duration_since(Instant::now());
    if wait.is_zero() {
        return Err(Refusal::Aborted);
    }
    match answers.recv_timeout(wait) {
        Ok(answer) => Ok(answer),
        Err(_) => Err(Refusal::Aborted),
    }
}

/// Settles a transfer's claim when it ends, however it ends: a transfer
/// that saw its terminal answer frees the attempt; one that did not is
/// cancelled on the controller and left draining.
struct Claim<'a> {
    remote: &'a LinkRemote,
    attempt: AttemptId,
    terminal: bool,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.remote.cancel(self.attempt);
        }
        self.remote.router.finish(self.attempt, self.terminal);
    }
}

/// One accepted, authenticated worker session on the controller.
pub struct WorkerSession {
    rx: Receiver,
    tx: Sender,
    pub admitted: Admitted,
    pub fingerprint: Digest,
    /// The capacity the hello reported, kept so the protocol-7 profile is
    /// recorded together with it, not after a second read.
    capacity: Capacity,
    profiled: bool,
}

/// One accepted connection, before it is clear which half of a session it
/// carries: the control connection opens with `Hello`, the bulk connection
/// with `BulkHello`.
pub enum Accepted {
    Control(WorkerSession),
    /// A second connection of a session whose control half must be live:
    /// the caller checks that `fingerprint` matches, and only then serves it.
    Bulk(BulkSession),
}

/// How long an accepted connection may take to finish its TLS handshake and
/// send its first message, all told. Before that the peer has proved
/// nothing, so it must not hold a session slot for longer.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// Drive a TLS handshake to completion, bounded in absolute time: every
/// read or write waits at most `deadline`, and the loop gives up once the
/// whole handshake has taken that long.
fn handshake(conn: &mut rustls::Connection, socket: &TcpStream, deadline: Duration) -> Result<()> {
    let started = Instant::now();
    let mut sock = socket;
    while conn.is_handshaking() {
        if started.elapsed() >= deadline {
            return Err(Error::Lost);
        }
        conn.complete_io(&mut sock)?;
    }
    Ok(())
}

/// Socket options every link connection carries: no Nagle delay, and a
/// write timeout so a peer that stops reading cannot block a sender (and
/// with it the connection lock and its reader) forever.
fn configure(socket: &TcpStream, read: Duration) -> Result<()> {
    socket.set_read_timeout(Some(read))?;
    socket.set_write_timeout(Some(HEARTBEAT_DEADLINE))?;
    socket.set_nodelay(true)?;
    Ok(())
}

/// Complete the TLS handshake on an accepted socket, read the first message,
/// and answer on the control connection (which runs the admission policy),
/// all within [`HANDSHAKE_DEADLINE`].
pub fn accept(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
) -> Result<Accepted> {
    accept_within(socket, config, admission, HANDSHAKE_DEADLINE)
}

/// [`accept`] under a caller-chosen handshake-plus-hello deadline.
pub fn accept_within(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
    deadline: Duration,
) -> Result<Accepted> {
    let started = Instant::now();
    configure(&socket, deadline.min(HEARTBEAT_DEADLINE))?;
    let mut conn = rustls::Connection::Server(
        ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?,
    );
    // Drive the handshake so the peer certificate is available.
    handshake(&mut conn, &socket, deadline)?;
    let fingerprint = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(fingerprint_of)
        .ok_or(Error::Protocol("no client certificate"))?;
    let (tx, mut rx) = split(conn, socket)?;
    let remaining = deadline.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(Error::Lost);
    }
    match rx.recv::<ClientMessage>(remaining)? {
        ClientMessage::Hello {
            hello,
            worker,
            name,
            enrollment,
            capacity,
        } => {
            let worker = WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?;
            let secret = match enrollment.as_deref() {
                Some(text) => Some(
                    sentinel_auth::token::parse(text)
                        .ok_or(Error::Protocol("enrollment secret"))?,
                ),
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
                    Ok(Accepted::Control(WorkerSession {
                        rx,
                        tx,
                        admitted,
                        fingerprint,
                        capacity,
                        profiled: false,
                    }))
                }
                Err(rejection) => {
                    let _ = tx.send(&ServerMessage::Reject(rejection));
                    Err(Error::Rejected(rejection))
                }
            }
        }
        ClientMessage::BulkHello { worker } => {
            let worker = WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?;
            Ok(Accepted::Bulk(BulkSession {
                rx,
                tx,
                worker,
                fingerprint,
            }))
        }
        _ => Err(Error::Protocol("expected hello")),
    }
}

/// The bulk half of a protocol-7 session: the worker's second connection,
/// carrying logs, spec chunks, artifacts and cache transfers. It is admitted
/// only when a live control session with the same certificate exists; the
/// controller checks that before calling [`BulkSession::serve`].
pub struct BulkSession {
    rx: Receiver,
    tx: Sender,
    pub worker: WorkerId,
    pub fingerprint: Digest,
}

impl BulkSession {
    /// The half the controller pushes bulk answers through.
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    /// Serve bulk messages until the worker says goodbye, breaks protocol,
    /// or `alive` says its control session is gone. `protocol` is the
    /// control session's negotiated version: the bulk connection carries no
    /// negotiation of its own. Bulk has no heartbeat — the control session
    /// is the liveness signal — so an idle bulk connection is kept for as
    /// long as its control session lives rather than torn down and redialled
    /// every heartbeat deadline.
    pub fn serve(
        &mut self,
        handler: &dyn SessionHandler,
        protocol: u16,
        alive: &dyn Fn() -> bool,
    ) -> Result<()> {
        // Bulk connections carry no negotiation and cannot report a profile;
        // the capacity is only ever read by the control connection.
        let mut profiled = true;
        serve_connection(
            handler,
            self.worker,
            protocol,
            Some(alive),
            &mut profiled,
            Capacity::default(),
            &mut self.rx,
            &self.tx,
        )
    }
}

impl WorkerSession {
    /// The half the dispatcher pushes offers through.
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    /// The capacity the worker reported in its hello.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// Serve heartbeats and offer answers until the worker says goodbye,
    /// stops answering, or breaks protocol. Bulk-class messages are accepted
    /// here too: a protocol-7 worker whose second connection cannot be
    /// established falls back to this one.
    pub fn serve(&mut self, handler: &dyn SessionHandler) -> Result<()> {
        let worker = self.admitted.worker;
        let protocol = self.admitted.negotiated.protocol.0;
        serve_connection(
            handler,
            worker,
            protocol,
            None,
            &mut self.profiled,
            self.capacity,
            &mut self.rx,
            &self.tx,
        )
    }
}

/// Serve one connection's inbound messages until `Bye`, a protocol violation
/// or loss. `bulk` is `None` on the control connection: it carries
/// heartbeats, offer answers and reports, accepts bulk-class messages as the
/// fallback path, and is lost after a heartbeat deadline of silence. A bulk
/// connection (`Some(alive)`) carries the bulk classes only and refuses
/// control-class messages, so a misrouted offer can never surface as a
/// silently dropped heartbeat; its silence is fine for as long as `alive`
/// says the control session is.
#[allow(clippy::too_many_arguments)]
fn serve_connection(
    handler: &dyn SessionHandler,
    worker: WorkerId,
    protocol: u16,
    bulk: Option<&dyn Fn() -> bool>,
    profiled: &mut bool,
    capacity: Capacity,
    rx: &mut Receiver,
    tx: &Sender,
) -> Result<()> {
    let control = bulk.is_none();
    // In-flight artifact per attempt (protocol 4): set when a begin is
    // granted, cleared by every verdict. Names the verdict a mid-flight
    // failure answers with and orders begin/file/data/end.
    let mut artifacts: HashMap<AttemptId, String> = HashMap::new();
    // In-flight upload per attempt (protocol 7): the receiving state a
    // `CacheOffer` opened, fed by its `CachePush` frames until `CachePushEnd`,
    // with the time it last moved. Bounded per connection, and one idle
    // past `UPLOAD_IDLE` is dropped — its staging file and entry lock with
    // it (P08-C5).
    let mut uploads: HashMap<AttemptId, (sentinel_cache::remote::Receiving, Instant)> =
        HashMap::new();
    // Downloads this connection is streaming right now, bounded so a worker
    // cannot make the controller spawn threads without limit.
    let transfers = Arc::new(AtomicUsize::new(0));
    // The cancel flag of each download in flight (protocol 8, P08-C2).
    let serving: Arc<Mutex<HashMap<AttemptId, Arc<AtomicBool>>>> = Arc::default();
    loop {
        let received = rx.recv_timeout::<ClientMessage>(HEARTBEAT_DEADLINE)?;
        if !uploads.is_empty() {
            let now = Instant::now();
            uploads.retain(|_, (_, moved)| now.duration_since(*moved) < UPLOAD_IDLE);
        }
        let Some(message) = received else {
            if bulk.is_some_and(|alive| alive()) {
                continue;
            }
            return Err(Error::Lost);
        };
        match message {
            ClientMessage::Ping { seq, held } => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                if held.len() > MAX_LIST_ITEMS {
                    return Err(Error::Protocol("held list"));
                }
                let held = ids(&held)?;
                let beat = handler.ping(worker, &held)?;
                tx.send(&ServerMessage::Pong {
                    seq,
                    lease_until_ms: beat.lease_until.0,
                    stop: beat.stop.iter().map(|a| *a.as_bytes()).collect(),
                    cancel: beat.cancel.iter().map(|a| *a.as_bytes()).collect(),
                })?;
            }
            ClientMessage::Ack { attempt, fence } => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                handler.acknowledged(worker, attempt, Fence(fence));
            }
            ClientMessage::Decline { attempt, fence } => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                handler.declined(worker, attempt, Fence(fence));
            }
            ClientMessage::Report {
                attempt,
                fence,
                event,
                summary,
            } => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if summary
                    .as_ref()
                    .is_some_and(|s| s.len() > MAX_SUMMARY_BYTES)
                {
                    return Err(Error::Protocol("summary size"));
                }
                handler.reported(worker, attempt, Fence(fence), event.to_event()?, summary);
            }
            ClientMessage::NeedSpec { attempt } => {
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if handler.spec_requested(worker, id, tx.clone(), protocol) {
                    continue;
                }
                // The synchronous fallback (a handler that resolves inline)
                // still owes the protocol gate.
                if protocol < 3 {
                    tx.send(&ServerMessage::NoSpec { attempt })?;
                    continue;
                }
                match handler.spec(worker, id) {
                    Some((context, bytes)) if bytes.len() <= MAX_SPEC_BYTES => {
                        tx.send(&context_message(protocol, &context, id))?;
                        if let Some(access) = context.source {
                            tx.send(&ServerMessage::Source { attempt, access })?;
                        }
                        let chunks = bytes.chunks(SPEC_CHUNK_BYTES);
                        let count = chunks.len().max(1);
                        if bytes.is_empty() {
                            tx.send(&ServerMessage::Spec {
                                attempt,
                                seq: 0,
                                last: true,
                                bytes: Vec::new(),
                            })?;
                        }
                        for (seq, chunk) in chunks.enumerate() {
                            tx.send(&ServerMessage::Spec {
                                attempt,
                                seq: seq as u32,
                                last: seq + 1 == count,
                                bytes: chunk.to_vec(),
                            })?;
                        }
                    }
                    _ => tx.send(&ServerMessage::NoSpec { attempt })?,
                }
            }
            ClientMessage::Log {
                attempt,
                seq,
                step,
                stream,
                bytes,
            } => {
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if bytes.len() > MAX_LOG_FRAME_BYTES {
                    return Err(Error::Protocol("log frame size"));
                }
                let stream = Stream::from_code(stream).ok_or(Error::Protocol("stream"))?;
                let frame = Frame {
                    seq,
                    step,
                    stream,
                    bytes,
                };
                match handler.log(worker, id, frame) {
                    LogVerdict::Acked(through) => {
                        tx.send(&ServerMessage::LogAck { attempt, through })?;
                    }
                    LogVerdict::Refused => {
                        tx.send(&ServerMessage::LogRefused { attempt })?;
                    }
                    LogVerdict::Retry => return Err(Error::Internal("log store")),
                }
            }
            ClientMessage::LogEnd {
                attempt,
                last_seq,
                gaps,
            } => {
                if gaps.len() > MAX_GAPS {
                    return Err(Error::Protocol("gap list"));
                }
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                match handler.log_end(worker, id, last_seq, &gaps) {
                    // Protocol 5 names the durable-end boundary;
                    // earlier versions sent nothing here.
                    LogVerdict::Acked(_) if protocol >= 5 => {
                        tx.send(&ServerMessage::LogEndAck { attempt })?;
                    }
                    LogVerdict::Acked(_) => {}
                    LogVerdict::Refused => {
                        tx.send(&ServerMessage::LogRefused { attempt })?;
                    }
                    LogVerdict::Retry => return Err(Error::Internal("log store")),
                }
            }
            ClientMessage::Abandon { attempt, fence } => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                handler.abandoned(worker, attempt, Fence(fence));
            }
            ClientMessage::ArtifactBegin { attempt, name } => {
                if protocol < 4 {
                    return Err(Error::Protocol("artifact needs protocol 4"));
                }
                if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_BYTES {
                    return Err(Error::Protocol("artifact name"));
                }
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if artifacts.contains_key(&id) {
                    return Err(Error::Protocol("artifact in flight"));
                }
                match handler.artifact_begin(worker, id, &name) {
                    ArtifactReply::Grant => {
                        artifacts.insert(id, name.clone());
                        tx.send(&ServerMessage::ArtifactGrant { attempt, name })?;
                    }
                    ArtifactReply::Verdict(code) => {
                        tx.send(&ServerMessage::ArtifactVerdict {
                            attempt,
                            name,
                            code: code.to_u8(),
                        })?;
                    }
                }
            }
            ClientMessage::ArtifactFile {
                attempt,
                path,
                len,
                mode,
            } => {
                if path.is_empty()
                    || path.len() > MAX_ARTIFACT_PATH_BYTES
                    || len > MAX_ARTIFACT_BYTES
                {
                    return Err(Error::Protocol("artifact file"));
                }
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                let name = artifacts
                    .get(&id)
                    .cloned()
                    .ok_or(Error::Protocol("artifact file without begin"))?;
                if let Some(code) = handler.artifact_file(worker, id, &path, len, mode) {
                    artifacts.remove(&id);
                    tx.send(&ServerMessage::ArtifactVerdict {
                        attempt,
                        name,
                        code: code.to_u8(),
                    })?;
                }
            }
            ClientMessage::ArtifactData {
                attempt,
                seq,
                bytes,
            } => {
                if bytes.len() > MAX_ARTIFACT_CHUNK_BYTES {
                    return Err(Error::Protocol("artifact chunk"));
                }
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                let name = artifacts
                    .get(&id)
                    .cloned()
                    .ok_or(Error::Protocol("artifact data without begin"))?;
                if let Some(code) = handler.artifact_data(worker, id, seq, &bytes) {
                    artifacts.remove(&id);
                    tx.send(&ServerMessage::ArtifactVerdict {
                        attempt,
                        name,
                        code: code.to_u8(),
                    })?;
                }
            }
            ClientMessage::ArtifactEnd { attempt, name } => {
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if artifacts.get(&id) != Some(&name) {
                    return Err(Error::Protocol("artifact end without begin"));
                }
                artifacts.remove(&id);
                let code = handler.artifact_end(worker, id, &name);
                tx.send(&ServerMessage::ArtifactVerdict {
                    attempt,
                    name,
                    code: code.to_u8(),
                })?;
            }
            ClientMessage::ArtifactAbsent {
                attempt,
                name,
                reason,
            } => {
                if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_BYTES {
                    return Err(Error::Protocol("artifact name"));
                }
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if let Some(open) = artifacts.get(&id)
                    && open != &name
                {
                    return Err(Error::Protocol("artifact absent of another"));
                }
                artifacts.remove(&id);
                let code = handler.artifact_absent(worker, id, &name, reason);
                tx.send(&ServerMessage::ArtifactVerdict {
                    attempt,
                    name,
                    code: code.to_u8(),
                })?;
            }
            ClientMessage::Profile(profile) => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("profile needs protocol 7"));
                }
                // From protocol 8 a later profile is an availability refresh
                // (P07-6): the worker re-reports what it holds as it changes.
                if *profiled && protocol < CACHE_CANCEL_MIN.0 {
                    return Err(Error::Protocol("second profile"));
                }
                if let Some(what) = profile.invalid() {
                    return Err(Error::Protocol(what));
                }
                handler.profiled(worker, &profile, capacity)?;
                *profiled = true;
            }
            ClientMessage::Transport(stats) => {
                if !control {
                    return Err(Error::Protocol("control message on bulk"));
                }
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("transport needs protocol 7"));
                }
                handler.transport(worker, &stats);
            }
            ClientMessage::BulkHello { .. } => {
                return Err(Error::Protocol(if control {
                    "bulk hello on control"
                } else {
                    "second bulk hello"
                }));
            }
            ClientMessage::CacheNeed(need) => {
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("cache needs protocol 7"));
                }
                let attempt = need.attempt;
                match handler.cache_need(worker, &need) {
                    None => send_cache_refused(tx, attempt, Refusal::Denied)?,
                    Some(root) => {
                        if transfers.load(Ordering::Acquire) >= MAX_CACHE_TRANSFERS {
                            send_cache_refused(tx, attempt, Refusal::Busy)?;
                        } else {
                            let id = attempt_id(attempt)?;
                            let cancel = Arc::new(AtomicBool::new(false));
                            serving
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert(id, Arc::clone(&cancel));
                            transfers.fetch_add(1, Ordering::AcqRel);
                            let sender = tx.clone();
                            let counter = Arc::clone(&transfers);
                            let registry = Arc::clone(&serving);
                            let spawned = thread::Builder::new()
                                .name("sentinel-cache-serve".into())
                                .spawn(move || {
                                    let _permit = TransferPermit(counter);
                                    let _ = serve_cache_need(&root, &need, &sender, &cancel);
                                    let mut live =
                                        registry.lock().unwrap_or_else(|p| p.into_inner());
                                    if live.get(&id).is_some_and(|c| Arc::ptr_eq(c, &cancel)) {
                                        live.remove(&id);
                                    }
                                });
                            if spawned.is_err() {
                                transfers.fetch_sub(1, Ordering::AcqRel);
                                serving
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&id);
                                send_cache_refused(tx, attempt, Refusal::Store)?;
                            }
                        }
                    }
                }
            }
            ClientMessage::CacheOffer(upload) => {
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("cache needs protocol 7"));
                }
                let attempt = upload.attempt;
                let id = attempt_id(attempt)?;
                if uploads.contains_key(&id) || uploads.len() >= MAX_CACHE_TRANSFERS {
                    // One upload per attempt, a few per connection: an
                    // abandoned one cannot pin more than its share.
                    send_cache_refused(tx, attempt, Refusal::Busy)?;
                    continue;
                }
                match handler.cache_offer(worker, &upload) {
                    None => send_cache_refused(tx, attempt, Refusal::Denied)?,
                    Some(root) => match sentinel_cache::remote::Receiving::begin(&root, &upload) {
                        // Already stored: no grant, no bytes, done.
                        Ok(None) => {
                            tx.send(&ServerMessage::CacheEnd(End {
                                attempt,
                                digest: upload.digest,
                            }))?;
                        }
                        Ok(Some(receiving)) => {
                            tx.send(&ServerMessage::CacheGrant(receiving.grant(&upload)))?;
                            uploads.insert(id, (receiving, Instant::now()));
                        }
                        Err(code) => send_cache_refused(tx, attempt, code)?,
                    },
                }
            }
            ClientMessage::CachePush(push) => {
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("cache needs protocol 7"));
                }
                let attempt = push.attempt;
                let Some(id) = well_formed_attempt(&attempt) else {
                    send_cache_refused(tx, attempt, Refusal::Store)?;
                    continue;
                };
                let pushed = match uploads.get_mut(&id) {
                    Some((receiving, moved)) => {
                        *moved = Instant::now();
                        Some(receiving.push(push.offset, &push.bytes))
                    }
                    None => None,
                };
                // A push for an upload already failed, cancelled or reaped
                // is dropped: its refusal was sent once, never per frame.
                if let Some(Err(code)) = pushed {
                    uploads.remove(&id);
                    send_cache_refused(tx, attempt, code)?;
                }
            }
            ClientMessage::CachePushEnd(end) => {
                if protocol < PROFILE_MIN.0 {
                    return Err(Error::Protocol("cache needs protocol 7"));
                }
                let attempt = end.attempt;
                let digest = end.digest;
                let Some(id) = well_formed_attempt(&attempt) else {
                    send_cache_refused(tx, attempt, Refusal::Store)?;
                    continue;
                };
                let Some((mut receiving, _)) = uploads.remove(&id) else {
                    send_cache_refused(tx, attempt, Refusal::Store)?;
                    continue;
                };
                match receiving.end(digest) {
                    Ok(()) => {
                        tx.send(&ServerMessage::CacheEnd(End { attempt, digest }))?;
                    }
                    Err(code) => send_cache_refused(tx, attempt, code)?,
                }
            }
            ClientMessage::CacheCancel { attempt } => {
                if protocol < CACHE_CANCEL_MIN.0 {
                    return Err(Error::Protocol("cache cancel needs protocol 8"));
                }
                let Some(id) = well_formed_attempt(&attempt) else {
                    continue;
                };
                // A download stops at its next chunk and sends its own
                // terminal; an upload is dropped here — staging and lock
                // with it — and answered once.
                if let Some(flag) = serving.lock().unwrap_or_else(|p| p.into_inner()).get(&id) {
                    flag.store(true, Ordering::Release);
                }
                if uploads.remove(&id).is_some() {
                    send_cache_refused(tx, attempt, Refusal::Aborted)?;
                }
            }
            ClientMessage::Bye => return Ok(()),
            ClientMessage::Hello { .. } => return Err(Error::Protocol("second hello")),
        }
    }
}

/// The attempt's id when the bytes are well-formed; `None` means a cache
/// frame named an id that cannot exist, which is answered `Store` rather
/// than tearing the session down.
fn well_formed_attempt(raw: &[u8; 16]) -> Option<AttemptId> {
    AttemptId::from_bytes(*raw).ok()
}

fn attempt_id(raw: [u8; 16]) -> Result<AttemptId> {
    AttemptId::from_bytes(raw).map_err(|_| Error::Protocol("id"))
}

fn send_cache_refused(sender: &Sender, attempt: [u8; 16], code: Refusal) -> Result<()> {
    sender.send(&ServerMessage::CacheRefused(Refused {
        attempt,
        code: code.code(),
    }))
}

/// Counts one download this connection is streaming, released on every exit.
struct TransferPermit(Arc<AtomicUsize>);

impl Drop for TransferPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Stream one authorized download (Q08) off the session thread: grant,
/// ordered chunks, end — or, once the worker cancelled it (protocol 8),
/// `CacheRefused` with `aborted` as the terminal at the next chunk. One
/// chunk buffer serves the whole transfer. The chunk size is checked here
/// because the frame cap is the link's, and a running digest cannot be
/// recomputed for a split piece.
fn serve_cache_need(
    root: &std::path::Path,
    need: &Need,
    sender: &Sender,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut serving = match Serving::open(root, need) {
        Ok(serving) => serving,
        Err(code) => return send_cache_refused(sender, need.attempt, code),
    };
    let plan = serving.plan();
    let digest = plan.digest;
    sender.send(&ServerMessage::CacheGrant(plan))?;
    let mut message = ServerMessage::CacheChunk(Chunk {
        attempt: need.attempt,
        offset: 0,
        bytes: Vec::with_capacity(MAX_CACHE_CHUNK_BYTES),
        prefix: [0; 32],
    });
    loop {
        if cancel.load(Ordering::Acquire) {
            return send_cache_refused(sender, need.attempt, Refusal::Aborted);
        }
        let ServerMessage::CacheChunk(chunk) = &mut message else {
            return send_cache_refused(sender, need.attempt, Refusal::Store);
        };
        match serving.next_chunk_into(chunk) {
            Ok(true) => {
                if chunk.bytes.len() > MAX_CACHE_CHUNK_BYTES {
                    return send_cache_refused(sender, need.attempt, Refusal::TooLarge);
                }
                sender.send(&message)?;
            }
            Ok(false) => {
                return sender.send(&ServerMessage::CacheEnd(End {
                    attempt: need.attempt,
                    digest,
                }));
            }
            Err(code) => return send_cache_refused(sender, need.attempt, code),
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
    /// Where the bulk connection dials back to, and with which identity.
    addr: SocketAddr,
    client: Arc<rustls::ClientConfig>,
    /// The session's remote side: the live bulk attachment and the cache
    /// transfer router. Shared with the reader threads.
    remote: Arc<LinkRemote>,
    /// Process telemetry to refresh on the control connection (Q07).
    transport: Option<TransportStats>,
    beats: u64,
    /// When the last heartbeat left: what the lease the pong renews is
    /// measured from, monotonically.
    ping_sent: Instant,
    /// Whether [`Reporter::remote_cache`] hands the executor a handle (Q08):
    /// off by configuration, every remote lookup is a local miss.
    remote_cache: bool,
    /// The profile this session reported last (protocol 7), the base a
    /// protocol-8 availability refresh amends.
    profile: Option<Profile>,
    /// The executor's availability version that profile carried.
    availability_sent: u64,
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
    configure(&socket, HEARTBEAT_DEADLINE)?;
    // The name is irrelevant with a pinned fingerprint but rustls needs one.
    let server_name = ServerName::try_from("sentinel").expect("static name");
    let mut conn = rustls::Connection::Client(
        ClientConnection::new(Arc::clone(&config), server_name)
            .map_err(|e| Error::Tls(e.to_string()))?,
    );
    handshake(&mut conn, &socket, HEARTBEAT_DEADLINE)?;
    let (tx, mut rx) = split(conn, socket)?;
    let enrollment = enrollment.map(sentinel_auth::token::format);
    let range = hello.protocol_min.0..=hello.protocol_max.0;
    tx.send(&ClientMessage::Hello {
        hello,
        worker: *worker.as_bytes(),
        name: name.to_owned(),
        enrollment,
        capacity,
    })?;
    match rx.recv::<ServerMessage>(HEARTBEAT_DEADLINE)? {
        // A welcome at a version this worker did not offer is one it cannot
        // speak: refuse it here rather than fail on the first frame.
        ServerMessage::Welcome { negotiated, .. } if !range.contains(&negotiated.protocol.0) => {
            Err(Error::Protocol(
                "negotiated version outside the hello's range",
            ))
        }
        ServerMessage::Welcome {
            worker,
            negotiated,
            heartbeat_interval_ms,
        } => Ok(Link {
            rx,
            tx: tx.clone(),
            worker: WorkerId::from_bytes(worker).map_err(|_| Error::Protocol("worker id"))?,
            negotiated,
            interval: Duration::from_millis(u64::from(heartbeat_interval_ms)),
            seq: 0,
            addr,
            client: config,
            remote: Arc::new(LinkRemote {
                control: tx,
                bulk: Mutex::new(BulkSlot::default()),
                router: Arc::new(CacheRouter::default()),
                protocol: negotiated.protocol.0,
            }),
            transport: None,
            beats: 0,
            ping_sent: Instant::now(),
            remote_cache: true,
            profile: None,
            availability_sent: 0,
        }),
        ServerMessage::Reject(why) => Err(Error::Rejected(why)),
        ServerMessage::Pong { .. }
        | ServerMessage::Offer(_)
        | ServerMessage::Spec { .. }
        | ServerMessage::NoSpec { .. }
        | ServerMessage::Context(_)
        | ServerMessage::Context2(_)
        | ServerMessage::Source { .. }
        | ServerMessage::LogAck { .. }
        | ServerMessage::LogRefused { .. }
        | ServerMessage::LogEndAck { .. }
        | ServerMessage::ArtifactGrant { .. }
        | ServerMessage::ArtifactVerdict { .. }
        | ServerMessage::CacheGrant(_)
        | ServerMessage::CacheChunk(_)
        | ServerMessage::CacheEnd(_)
        | ServerMessage::CacheRefused(_) => Err(Error::Protocol("message before welcome")),
    }
}

/// The executor's way to speak on the session from its own threads: state
/// events under the attempt's fence, spec requests, log frames and artifact
/// publication. Sending fails once the session is gone; the executor keeps
/// the event and resends it when it is attached to the next session.
///
/// From protocol 7 the bulk-class messages (spec requests, logs, artifacts)
/// prefer the bulk connection and fall back to the control one when no bulk
/// connection is up; reports and abandons always go control, because their
/// latency is what keeps a lease alive.
#[derive(Clone)]
pub struct Reporter {
    control: Sender,
    /// Protocol 7: the session's remote side, which owns the live bulk
    /// attachment. `None` below protocol 7, where everything is control.
    bulk: Option<Arc<LinkRemote>>,
    /// Whether the remote cache is exposed to the executor at all (Q08):
    /// protocol 7 and not disabled by configuration.
    remote_cache: bool,
    protocol: u16,
}

impl Reporter {
    fn bulk_class(&self, message: &ClientMessage) -> Result<()> {
        self.bulk_routed(message).map(|_| ())
    }

    fn bulk_routed(&self, message: &impl Serialize) -> Result<Route> {
        match &self.bulk {
            Some(remote) => remote.send(message),
            None => self.control.send(message).map(|()| Route::default()),
        }
    }

    /// The route bulk-class sends take now. Constant below protocol 7,
    /// where everything is control.
    pub fn route(&self) -> Route {
        self.bulk.as_ref().map(|r| r.route()).unwrap_or_default()
    }

    /// Protocol 7 (Q08). The session's remote cache: fetch and offer objects
    /// over the link. `None` below protocol 7 or when the operator disabled
    /// remote cache in this process's configuration; the executor must then
    /// treat every remote lookup as a local miss, never as a failure.
    pub fn remote_cache(&self) -> Option<Arc<dyn sentinel_cache::remote::Remote>> {
        if !self.remote_cache {
            return None;
        }
        self.bulk
            .as_ref()
            .map(|remote| Arc::clone(remote) as Arc<dyn sentinel_cache::remote::Remote>)
    }

    pub fn report(&self, attempt: AttemptId, fence: Fence, event: Event) -> Result<()> {
        let event = WireEvent::from_event(event).ok_or(Error::Protocol("not a worker event"))?;
        self.control.send(&ClientMessage::Report {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
            event,
            summary: None,
        })
    }

    /// The terminal report with the attempt's encoded summary.
    pub fn finish(
        &self,
        attempt: AttemptId,
        fence: Fence,
        event: Event,
        summary: Vec<u8>,
    ) -> Result<()> {
        let event = WireEvent::from_event(event).ok_or(Error::Protocol("not a worker event"))?;
        if summary.len() > MAX_SUMMARY_BYTES {
            return Err(Error::Protocol("summary size"));
        }
        self.control.send(&ClientMessage::Report {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
            event,
            summary: Some(summary),
        })
    }

    pub fn need_spec(&self, attempt: AttemptId) -> Result<()> {
        self.bulk_class(&ClientMessage::NeedSpec {
            attempt: *attempt.as_bytes(),
        })
    }

    /// One frame from the spool. The executor keeps at most
    /// `MAX_UNACKED_LOG_FRAMES` in flight per attempt.
    pub fn log(&self, attempt: AttemptId, frame: &Frame) -> Result<()> {
        self.log_frame(attempt, frame.seq, frame.step, frame.stream, &frame.bytes)
            .map(|_| ())
    }

    /// [`Reporter::log`] from borrowed parts, encoded straight into the
    /// frame buffer (no owned copy of the bytes), returning the route the
    /// frame took so the log pipe can tell when frames may have been lost
    /// with a bulk connection.
    pub fn log_frame(
        &self,
        attempt: AttemptId,
        seq: u64,
        step: u32,
        stream: Stream,
        bytes: &[u8],
    ) -> Result<Route> {
        if bytes.len() > MAX_LOG_FRAME_BYTES {
            return Err(Error::Protocol("log frame size"));
        }
        self.bulk_routed(&LogRef {
            attempt: attempt.as_bytes(),
            seq,
            step,
            stream: stream as u8,
            bytes,
        })
    }

    /// Hand back an attempt this worker acknowledged but never started (its
    /// run spec never arrived, or was refused): the controller requeues it,
    /// or settles it canceled when that is desired. Control class: it
    /// decides a lease.
    pub fn decline(&self, attempt: AttemptId, fence: Fence) -> Result<()> {
        self.control.send(&ClientMessage::Decline {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
        })
    }

    /// The protocol this session negotiated; the log pipe uses it to
    /// know whether `LogEnd` is answered by `LogEndAck`.
    pub fn protocol(&self) -> u16 {
        self.protocol
    }

    /// The attempt was in this worker's leftovers after a restart.
    pub fn abandon(&self, attempt: AttemptId, fence: Fence) -> Result<()> {
        self.control.send(&ClientMessage::Abandon {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
        })
    }

    pub fn log_end(&self, attempt: AttemptId, last_seq: u64, gaps: &[(u64, u64)]) -> Result<()> {
        self.bulk_class(&ClientMessage::LogEnd {
            attempt: *attempt.as_bytes(),
            last_seq,
            gaps: gaps.to_vec(),
        })
    }

    /// Whether this session can publish artifacts at all. A worker on an
    /// older protocol records every capture `failed` without sending.
    pub fn artifacts(&self) -> bool {
        self.protocol >= 4
    }

    /// Begin publishing artifact `name`; the answer arrives as
    /// `Executor::artifact_granted` or `artifact_verdict`.
    pub fn artifact_begin(&self, attempt: AttemptId, name: &str) -> Result<()> {
        if self.protocol < 4 {
            return Err(Error::Protocol("artifact needs protocol 4"));
        }
        if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_BYTES {
            return Err(Error::Protocol("artifact name"));
        }
        self.bulk_class(&ClientMessage::ArtifactBegin {
            attempt: *attempt.as_bytes(),
            name: name.to_string(),
        })
    }

    /// The next file of the granted artifact; `len` bytes of `artifact_data`
    /// follow it, seq from 0.
    pub fn artifact_file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> Result<()> {
        if path.is_empty() || path.len() > MAX_ARTIFACT_PATH_BYTES || len > MAX_ARTIFACT_BYTES {
            return Err(Error::Protocol("artifact file"));
        }
        self.bulk_class(&ClientMessage::ArtifactFile {
            attempt: *attempt.as_bytes(),
            path: path.to_string(),
            len,
            mode,
        })
    }

    /// One ordered chunk of the in-flight file.
    pub fn artifact_data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_ARTIFACT_CHUNK_BYTES {
            return Err(Error::Protocol("artifact chunk"));
        }
        self.bulk_class(&ClientMessage::ArtifactData {
            attempt: *attempt.as_bytes(),
            seq,
            bytes: bytes.to_vec(),
        })
    }

    /// The artifact's file set is complete; the verdict is terminal.
    pub fn artifact_end(&self, attempt: AttemptId, name: &str) -> Result<()> {
        self.bulk_class(&ClientMessage::ArtifactEnd {
            attempt: *attempt.as_bytes(),
            name: name.to_string(),
        })
    }

    /// No publishable content for `name`: `reason` 0 no match, 1 capture
    /// failed. Also abandons an in-flight publication of the same name.
    pub fn artifact_absent(&self, attempt: AttemptId, name: &str, reason: u8) -> Result<()> {
        if self.protocol < 4 {
            return Err(Error::Protocol("artifact needs protocol 4"));
        }
        self.bulk_class(&ClientMessage::ArtifactAbsent {
            attempt: *attempt.as_bytes(),
            name: name.to_string(),
            reason,
        })
    }
}

/// What a worker does with the offers and orders it receives. Implemented by
/// the executor (W03); the link owns dedup, acknowledgement and renewal.
pub trait Executor: Send + Sync {
    /// Called after the acknowledgement is on the wire.
    fn accepted(&self, _attempt: AttemptId) {}
    /// Take the offer or not. Called once per attempt per session.
    fn offered(&self, offer: &Offer) -> bool;
    /// The controller no longer counts this attempt as held: stop it now.
    fn stop(&self, attempt: AttemptId);
    /// Cancellation is desired for this attempt's job: end it gracefully
    /// (TERM, then KILL after the grace period) and report `Canceled`.
    fn cancel(&self, attempt: AttemptId);
    /// Attempts still held, renewed with every heartbeat.
    fn held(&self) -> Vec<AttemptId>;
    /// The controller renewed every held lease to this deadline.
    fn renewed(&self, until: UnixMillis);
    /// The same renewal with the monotonic instant the answered heartbeat
    /// left this worker. The renewal happened after that instant, so the
    /// lease lasts at least `LEASE_MS` from it on this machine's own clock —
    /// the deadline an executor should act on, with no wall-clock
    /// comparison between two hosts. The default forwards to `renewed`.
    fn renewed_at(&self, until: UnixMillis, _sent: Instant) {
        self.renewed(until);
    }
    /// A session is live: reports and spec requests go through `reporter`
    /// until `detached`. Pending reports from a lost session are resent here.
    fn attached(&self, reporter: Reporter);
    fn detached(&self);
    /// The run spec asked for with `Reporter::need_spec`, whole, with the
    /// job context that precedes it.
    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>);
    /// The controller will not serve the attempt's spec: it is not held
    /// here, it was settled canceled, or its source or spec was refused for
    /// good. A transient controller fault is never answered this way — the
    /// request is queued or simply unanswered, and the executor asks again.
    fn no_spec(&self, attempt: AttemptId);
    /// The bulk connection ended: frames handed to it may never have
    /// arrived. Log senders rewind to their last acknowledgement before
    /// anything else goes out on the fallback route.
    fn bulk_detached(&self) {}
    /// Frames through `through` are durable on the controller.
    fn log_acked(&self, attempt: AttemptId, through: u64);
    /// The controller stores no more frames of this attempt.
    fn log_refused(&self, attempt: AttemptId);
    /// Protocol 5. The attempt's end marker is durable on the controller:
    /// the spool may be dropped.
    fn log_ended(&self, _attempt: AttemptId) {}
    /// The artifact named in `artifact_begin` was granted; the executor may
    /// stream its files.
    fn artifact_granted(&self, _attempt: AttemptId, _name: &str) {}
    /// The artifact's terminal answer; the publication is over either way.
    fn artifact_verdict(&self, _attempt: AttemptId, _name: &str, _code: ArtifactCode) {}
    /// K08/P07-6: what this worker holds right now for placement — resident
    /// image keys and cache bytes — with a version that moves whenever it
    /// changes. The session reports it in the profile it opens with and,
    /// from protocol 8, refreshes the profile when the version moves.
    /// `None` (the default) reports nothing measured.
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        None
    }
}

impl Link {
    pub fn heartbeat_interval(&self) -> Duration {
        self.interval
    }

    /// Protocol 7: report the scheduling profile, immediately after
    /// `Welcome`. A no-op on an older session: the controller negotiated
    /// what it can decode, and a lower version means the extras do not
    /// travel. Refuses a profile outside its bounds rather than truncating.
    pub fn send_profile(&mut self, profile: &Profile) -> Result<()> {
        if self.negotiated.protocol.0 < PROFILE_MIN.0 {
            return Ok(());
        }
        if let Some(what) = profile.invalid() {
            return Err(Error::Protocol(what));
        }
        self.tx.send(&ClientMessage::Profile(profile.clone()))?;
        self.profile = Some(profile.clone());
        Ok(())
    }

    /// The availability version the opening profile already carried; a
    /// later refresh is sent only once the executor's version moves.
    pub fn set_availability_sent(&mut self, version: u64) {
        self.availability_sent = version;
    }

    /// Protocol 8 (P07-6): resend the profile when the executor's
    /// availability changed since it was last reported — at most once per
    /// heartbeat, and only when something moved.
    fn refresh_profile(&mut self, executor: &dyn Executor) -> Result<()> {
        if self.negotiated.protocol.0 < CACHE_CANCEL_MIN.0 {
            return Ok(());
        }
        let Some((version, availability)) = executor.availability() else {
            return Ok(());
        };
        if version == self.availability_sent {
            return Ok(());
        }
        let Some(mut profile) = self.profile.clone() else {
            return Ok(());
        };
        profile.availability.images = availability.images;
        profile.availability.cache_bytes = availability.cache_bytes;
        if profile.invalid().is_some() {
            return Ok(());
        }
        self.tx.send(&ClientMessage::Profile(profile.clone()))?;
        self.profile = Some(profile);
        self.availability_sent = version;
        Ok(())
    }

    /// Protocol 7 (Q07): report transport telemetry and keep refreshing it
    /// (round-trip time and byte counters) every `TRANSPORT_BEATS` beats. A
    /// no-op on an older session.
    pub fn report_transport(&mut self, stats: &TransportStats) -> Result<()> {
        if self.negotiated.protocol.0 < PROFILE_MIN.0 {
            return Ok(());
        }
        self.transport = Some(stats.clone());
        self.tx.send(&ClientMessage::Transport(stats.clone()))
    }

    /// Frame bytes written to / socket bytes read from the control
    /// connection (Q07).
    pub fn bytes(&self) -> (u64, u64) {
        self.tx.bytes()
    }

    /// Whether this session exposes the remote cache to the executor (Q08).
    /// Disabled, [`Reporter::remote_cache`] answers `None` and the executor
    /// treats every remote lookup as a local miss — the link still carries
    /// whatever the other side asks for, since that is their decision.
    pub fn set_remote_cache(&mut self, enabled: bool) {
        self.remote_cache = enabled;
    }

    /// Protocol 7: how the bulk connection is dialled, or `None` below it.
    /// Detached from the control `Link` so the bulk thread can redial on its
    /// own after its connection dies.
    pub fn bulk_dialer(&self) -> Option<BulkDialer> {
        (self.negotiated.protocol.0 >= PROFILE_MIN.0).then(|| BulkDialer {
            addr: self.addr,
            client: Arc::clone(&self.client),
            worker: self.worker,
            remote: Arc::clone(&self.remote),
        })
    }

    fn ping(&mut self, executor: &dyn Executor) -> Result<()> {
        self.refresh_profile(executor)?;
        self.seq += 1;
        let held: Vec<[u8; 16]> = executor
            .held()
            .iter()
            .take(MAX_LIST_ITEMS)
            .map(|a| *a.as_bytes())
            .collect();
        // Taken before the send: the renewal cannot precede it.
        self.ping_sent = Instant::now();
        self.tx.send(&ClientMessage::Ping {
            seq: self.seq,
            held,
        })
    }

    /// Refresh the telemetry a completed beat makes measurable: the
    /// round-trip time of the ping/pong pair and the connection's byte
    /// counters, resent every `TRANSPORT_BEATS` beats.
    fn beat_recorded(&mut self, rtt: Duration) -> Result<()> {
        self.beats += 1;
        let Some(stats) = self.transport.as_mut() else {
            return Ok(());
        };
        stats.rtt_ns = Some(rtt.as_nanos().min(u64::MAX as u128) as u64);
        let (out, bytes_in) = self.tx.bytes();
        stats.bytes_out = out;
        stats.bytes_in = bytes_in;
        if self.beats.is_multiple_of(TRANSPORT_BEATS) {
            self.tx.send(&ClientMessage::Transport(stats.clone()))?;
        }
        Ok(())
    }

    /// One beat: send a ping and wait for its pong within the deadline.
    /// Offers arriving in between are answered through `executor`.
    pub fn beat(&mut self, executor: &dyn Executor) -> Result<()> {
        self.ping(executor)?;
        let sent = std::time::Instant::now();
        let deadline = sent + HEARTBEAT_DEADLINE;
        let mut state = Inbound::default();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.rx.recv_timeout::<ServerMessage>(remaining)? {
                None => return Err(Error::Lost),
                Some(message) => {
                    if self.handle(message, executor, &mut state)? {
                        self.beat_recorded(sent.elapsed())?;
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Handle one message on the control connection; true when it was the
    /// awaited pong. Bulk-class messages are accepted here as the fallback
    /// path when the worker has no second connection up.
    fn handle(
        &mut self,
        message: ServerMessage,
        executor: &dyn Executor,
        state: &mut Inbound,
    ) -> Result<bool> {
        match message {
            ServerMessage::Pong {
                seq,
                lease_until_ms,
                stop,
                cancel,
            } => {
                if seq != self.seq {
                    return Err(Error::Protocol("pong sequence"));
                }
                executor.renewed_at(UnixMillis(lease_until_ms), self.ping_sent);
                for attempt in ids(&stop)? {
                    executor.stop(attempt);
                }
                for attempt in ids(&cancel)? {
                    executor.cancel(attempt);
                }
                Ok(true)
            }
            ServerMessage::Offer(wire) => {
                let offer = Offer::from_wire(wire)?;
                // Dedup within the session: a repeated offer of an attempt
                // already taken is re-acknowledged, never re-executed.
                let seen = &mut state.seen;
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
                if take {
                    executor.accepted(offer.attempt);
                }
                Ok(false)
            }
            ServerMessage::Welcome { .. } | ServerMessage::Reject(_) => {
                Err(Error::Protocol("unexpected message"))
            }
            bulk => {
                handle_bulk_message(bulk, executor, state, &self.remote)?;
                Ok(false)
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
        executor.attached(Reporter {
            control: self.tx.clone(),
            bulk: (self.negotiated.protocol.0 >= PROFILE_MIN.0).then(|| Arc::clone(&self.remote)),
            remote_cache: self.remote_cache && self.negotiated.protocol.0 >= PROFILE_MIN.0,
            protocol: self.negotiated.protocol.0,
        });
        let outcome = self.serve(executor, &mut until);
        executor.detached();
        outcome
    }

    fn serve(&mut self, executor: &dyn Executor, until: &mut impl FnMut() -> bool) -> Result<()> {
        let mut state = Inbound::default();
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
                && self.handle(message, executor, &mut state)?
            {
                let rtt = awaiting.map_or(HEARTBEAT_INTERVAL, |since| {
                    std::time::Instant::now().duration_since(since)
                });
                self.beat_recorded(rtt)?;
                awaiting = None;
                // Forget answered attempts the executor no longer holds.
                let held = executor.held();
                state.seen.retain(|a| held.contains(a));
            }
        }
        self.tx.send(&ClientMessage::Bye)
    }
}

/// Handle one bulk-class answer on either connection (the bulk one normally,
/// the control one as a fallback) and hand cache answers to the transfer
/// waiting for them.
fn handle_bulk_message(
    message: ServerMessage,
    executor: &dyn Executor,
    state: &mut Inbound,
    remote: &LinkRemote,
) -> Result<()> {
    match message {
        ServerMessage::Spec {
            attempt,
            seq,
            last,
            bytes,
        } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            let buffer = state.specs.entry(attempt).or_default();
            if seq as usize != buffer.1 || buffer.0.len() + bytes.len() > MAX_SPEC_BYTES {
                return Err(Error::Protocol("spec chunk"));
            }
            buffer.0.extend_from_slice(&bytes);
            buffer.1 += 1;
            if last {
                let (bytes, _) = state.specs.remove(&attempt).expect("just inserted");
                let context = state
                    .contexts
                    .remove(&attempt)
                    .ok_or(Error::Protocol("spec without context"))?;
                executor.spec(attempt, context, bytes);
            }
        }
        ServerMessage::Context(wire) => {
            let (attempt, context) = JobContext::from_wire(wire)?;
            state.contexts.insert(attempt, context);
        }
        // Protocol 6 shape: carries the tenant and the cache trust
        // class; same in-flight bookkeeping as `Context`.
        ServerMessage::Context2(wire) => {
            let (attempt, context) = JobContext::from_wire2(wire)?;
            state.contexts.insert(attempt, context);
        }
        ServerMessage::Source { attempt, access } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            if !access.validate(UnixMillis::now().0) {
                return Err(Error::Protocol("source access"));
            }
            let context = state
                .contexts
                .get_mut(&attempt)
                .ok_or(Error::Protocol("source without context"))?;
            if context.source.replace(access).is_some() {
                return Err(Error::Protocol("duplicate source"));
            }
        }
        ServerMessage::LogAck { attempt, through } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            executor.log_acked(attempt, through);
        }
        ServerMessage::LogRefused { attempt } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            executor.log_refused(attempt);
        }
        ServerMessage::LogEndAck { attempt } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            executor.log_ended(attempt);
        }
        ServerMessage::ArtifactGrant { attempt, name } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            executor.artifact_granted(attempt, &name);
        }
        ServerMessage::ArtifactVerdict {
            attempt,
            name,
            code,
        } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            executor.artifact_verdict(attempt, &name, ArtifactCode::from_u8(code));
        }
        ServerMessage::NoSpec { attempt } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            state.specs.remove(&attempt);
            state.contexts.remove(&attempt);
            executor.no_spec(attempt);
        }
        ServerMessage::CacheGrant(grant) => {
            let attempt =
                AttemptId::from_bytes(grant.attempt).map_err(|_| Error::Protocol("id"))?;
            remote.answer(attempt, CacheAnswer::Grant(grant));
        }
        ServerMessage::CacheChunk(chunk) => {
            let attempt =
                AttemptId::from_bytes(chunk.attempt).map_err(|_| Error::Protocol("id"))?;
            remote.answer(attempt, CacheAnswer::Chunk(chunk));
        }
        ServerMessage::CacheEnd(end) => {
            let attempt = AttemptId::from_bytes(end.attempt).map_err(|_| Error::Protocol("id"))?;
            remote.answer(attempt, CacheAnswer::End);
        }
        ServerMessage::CacheRefused(refused) => {
            let attempt =
                AttemptId::from_bytes(refused.attempt).map_err(|_| Error::Protocol("id"))?;
            remote.answer(attempt, CacheAnswer::Refused(refused));
        }
        ServerMessage::Welcome { .. }
        | ServerMessage::Reject(_)
        | ServerMessage::Pong { .. }
        | ServerMessage::Offer(_) => return Err(Error::Protocol("control message on bulk")),
    }
    Ok(())
}

/// How long a bulk reader waits for the next frame before checking whether
/// the session ended; bulk has no heartbeat of its own, the control
/// connection is the liveness signal.
const BULK_POLL: Duration = Duration::from_millis(500);

/// How the bulk connection is dialled: the session's address, identity and
/// remote state, detached from the control `Link` so the bulk thread can
/// redial after its connection dies.
#[derive(Clone)]
pub struct BulkDialer {
    addr: SocketAddr,
    client: Arc<rustls::ClientConfig>,
    worker: WorkerId,
    remote: Arc<LinkRemote>,
}

impl BulkDialer {
    /// Dial the second connection and announce it with `BulkHello`. The
    /// controller attaches it to the live control session with the same
    /// certificate; no answer is sent — the bulk path is usable as soon as
    /// this returns.
    pub fn open(&self) -> Result<BulkLink> {
        let socket = TcpStream::connect_timeout(&self.addr, HEARTBEAT_DEADLINE)?;
        configure(&socket, HEARTBEAT_DEADLINE)?;
        let server_name = ServerName::try_from("sentinel").expect("static name");
        let mut conn = rustls::Connection::Client(
            ClientConnection::new(Arc::clone(&self.client), server_name)
                .map_err(|e| Error::Tls(e.to_string()))?,
        );
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE)?;
        let (tx, rx) = split(conn, socket)?;
        tx.send(&ClientMessage::BulkHello {
            worker: *self.worker.as_bytes(),
        })?;
        // Bulk-class sends move here now; the control connection stays the
        // fallback until this connection ends.
        self.remote.attach_bulk(tx.clone());
        Ok(BulkLink {
            rx,
            tx,
            worker: self.worker,
            remote: Arc::clone(&self.remote),
        })
    }
}

/// The worker's bulk connection: anyone may send on it, exactly one thread
/// reads it, and the cache router is fed from that read.
pub struct BulkLink {
    rx: Receiver,
    tx: Sender,
    worker: WorkerId,
    remote: Arc<LinkRemote>,
}

impl BulkLink {
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// End the connection from here; the reader fails out of its read.
    pub fn close(&self) {
        self.tx.close();
    }

    /// Serve the controller's bulk answers until `until` returns true, the
    /// connection is lost, or the peer breaks protocol. Detaches the bulk
    /// attachment on the way out, so senders fall back to the control
    /// connection instead of writing into a dead socket.
    pub fn run(&mut self, executor: &dyn Executor, mut until: impl FnMut() -> bool) -> Result<()> {
        let mut state = Inbound::default();
        let outcome = loop {
            if until() {
                break Ok(());
            }
            match self.rx.recv_timeout::<ServerMessage>(BULK_POLL) {
                Ok(None) => continue,
                Ok(Some(message)) => {
                    if let Err(error) =
                        handle_bulk_message(message, executor, &mut state, &self.remote)
                    {
                        break Err(error);
                    }
                }
                Err(error) => break Err(error),
            }
        };
        self.remote.detach_bulk();
        executor.bulk_detached();
        outcome
    }
}

/// Per-session inbound state: offers already answered, specs in flight.
#[derive(Default)]
struct Inbound {
    seen: std::collections::HashSet<AttemptId>,
    specs: std::collections::HashMap<AttemptId, (Vec<u8>, usize)>,
    contexts: std::collections::HashMap<AttemptId, JobContext>,
}

/// The machine identity a worker reports in its protocol-7 profile: 16 bytes
/// derived from the host's machine id, so sibling worker processes on one
/// host agree on it — a host-level failure or drain can then be told apart
/// from one process's. All zero when the host has no readable machine id:
/// an unknown host, never a shared one.
pub fn host_id() -> [u8; 16] {
    let mut out = [0u8; 16];
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim();
            if !text.is_empty() {
                out.copy_from_slice(&blake3::hash(text.as_bytes()).as_bytes()[..16]);
                return out;
            }
        }
    }
    out
}

/// Bind a listener for tests and the controller alike.
pub fn listen(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The borrowed log frame is byte-for-byte the owned message: the
    /// variant index and field order of `ClientMessage::Log` are the wire.
    #[test]
    fn a_borrowed_log_frame_encodes_exactly_like_the_owned_message() {
        let attempt = AttemptId::new();
        let bytes = vec![7u8; 300];
        let owned = postcard::to_allocvec(&ClientMessage::Log {
            attempt: *attempt.as_bytes(),
            seq: 1 << 40,
            step: 3,
            stream: Stream::Stderr as u8,
            bytes: bytes.clone(),
        })
        .unwrap();
        let borrowed = postcard::to_allocvec(&LogRef {
            attempt: attempt.as_bytes(),
            seq: 1 << 40,
            step: 3,
            stream: Stream::Stderr as u8,
            bytes: &bytes,
        })
        .unwrap();
        assert_eq!(owned, borrowed);
        assert!(matches!(
            postcard::from_bytes::<ClientMessage>(&borrowed).unwrap(),
            ClientMessage::Log { seq, .. } if seq == 1 << 40
        ));
    }

    /// P04-17: a peer that stops reading cannot hold a sender forever. The
    /// write times out, the send fails and the connection is torn down so
    /// its reader ends too.
    #[test]
    fn a_send_to_a_peer_that_never_reads_fails_within_the_write_timeout() {
        let server_identity = crate::identity::Identity::generate("controller").unwrap();
        let pin = server_identity.fingerprint();
        let server = crate::tls::server_config(server_identity).unwrap();
        let client =
            crate::tls::client_config(crate::identity::Identity::generate("worker").unwrap(), pin)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // The client completes the handshake and then never reads again.
        let peer = thread::spawn(move || {
            let socket = TcpStream::connect(addr).unwrap();
            let mut conn = rustls::Connection::Client(
                ClientConnection::new(client, ServerName::try_from("sentinel").unwrap()).unwrap(),
            );
            handshake(&mut conn, &socket, HEARTBEAT_DEADLINE).unwrap();
            thread::sleep(Duration::from_secs(10));
            drop(socket);
        });
        let (socket, _) = listener.accept().unwrap();
        let mut conn = rustls::Connection::Server(ServerConnection::new(server).unwrap());
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (tx, _rx) = split(conn, socket).unwrap();
        let started = Instant::now();
        let big = vec![0u8; 48 * 1024];
        let failed = loop {
            if let Err(error) = tx.send(&ServerMessage::Spec {
                attempt: [1; 16],
                seq: 0,
                last: false,
                bytes: big.clone(),
            }) {
                break error;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "never blocked");
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(failed, Error::Lost | Error::Io(_)), "{failed}");
        // Torn down: the next send fails at once rather than blocking.
        let again = Instant::now();
        assert!(
            tx.send(&ServerMessage::NoSpec { attempt: [1; 16] })
                .is_err()
        );
        assert!(again.elapsed() < Duration::from_millis(150));
        drop(peer);
    }

    fn context(tenant: Option<TenantId>, trust: Trust) -> JobContext {
        JobContext {
            source: None,
            run: RunId::new(),
            repo: RepoId::new(),
            repo_name: "org/repo".to_string(),
            job: JobId::new(),
            job_name: "test".to_string(),
            sha: "0".repeat(40),
            event: EventContext {
                name: "push".to_string(),
                ref_name: "refs/heads/main".to_string(),
                base_ref: None,
                pr_number: None,
                key: "main".to_string(),
            },
            cancelled: false,
            needs: vec![("build".to_string(), Outcome::Passed)],
            tenant,
            trust,
        }
    }

    #[test]
    fn context2_round_trip_keeps_tenant_and_trust() {
        let attempt = AttemptId::new();
        let tenant = TenantId::new();
        for trust in Trust::ALL {
            let expected = context(Some(tenant), trust);
            let (decoded_attempt, decoded) =
                JobContext::from_wire2(expected.to_wire2(attempt)).unwrap();
            assert_eq!(decoded_attempt, attempt);
            assert_eq!(decoded, expected);
        }
    }

    /// P07-2: an unprotected job reaches a protocol-8 worker as itself and
    /// an older one as the pull-request scope — never as protected.
    #[test]
    fn unprotected_jobs_downgrade_for_older_peers() {
        let job = context(None, Trust::Unprotected);
        for (protocol, want) in [
            (8u16, Trust::Unprotected),
            (7, Trust::PullRequest),
            (6, Trust::PullRequest),
        ] {
            let ServerMessage::Context2(wire) = context_message(protocol, &job, AttemptId::new())
            else {
                panic!("protocol {protocol} sends Context2");
            };
            assert_eq!(wire.trust, want.to_u8(), "protocol {protocol}");
        }
    }

    #[test]
    fn context2_absent_tenant_stays_absent() {
        let (.., decoded) =
            JobContext::from_wire2(context(None, Trust::PullRequest).to_wire2(AttemptId::new()))
                .unwrap();
        assert_eq!(decoded.tenant, None);
        assert_eq!(decoded.trust, Trust::PullRequest);
    }

    #[test]
    fn context2_rejects_unknown_trust_code() {
        let attempt = AttemptId::new();
        for bad in [3u8, 9, 255] {
            let mut wire = context(Some(TenantId::new()), Trust::Protected).to_wire2(attempt);
            wire.trust = bad;
            assert!(
                JobContext::from_wire2(wire).is_err(),
                "trust {bad} must not decode"
            );
        }
    }

    #[test]
    fn context2_rejects_oversized_needs() {
        let mut wire = context(None, Trust::Protected).to_wire2(AttemptId::new());
        wire.needs = vec![("x".to_string(), 0); MAX_LIST_ITEMS + 1];
        assert!(JobContext::from_wire2(wire).is_err());
    }

    #[test]
    fn context_v5_decode_defaults_to_pr_scope() {
        // A protocol <6 context carries no tenant/trust: the decode must
        // land the worker in the scope that cannot touch protected state.
        let wire_attempt = AttemptId::new();
        let (attempt, decoded) = JobContext::from_wire(
            context(Some(TenantId::new()), Trust::Protected).to_wire(wire_attempt),
        )
        .unwrap();
        assert_eq!(attempt, wire_attempt);
        assert_eq!(decoded.tenant, None);
        assert_eq!(decoded.trust, Trust::PullRequest);
        assert_eq!(decoded.needs, vec![("build".to_string(), Outcome::Passed)]);
    }

    #[test]
    fn context_message_follows_the_negotiated_protocol() {
        let attempt = AttemptId::new();
        let context = context(Some(TenantId::new()), Trust::Protected);
        for protocol in 1..=5 {
            assert!(
                matches!(
                    context_message(protocol, &context, attempt),
                    ServerMessage::Context(_)
                ),
                "protocol {protocol}"
            );
        }
        assert!(matches!(
            context_message(6, &context, attempt),
            ServerMessage::Context2(_)
        ));
        // A future version still gets the newer shape.
        assert!(matches!(
            context_message(7, &context, attempt),
            ServerMessage::Context2(_)
        ));
    }

    #[test]
    fn wire_context2_survives_postcard() {
        // The variant index is positional: Context2 must remain the last
        // variant or every older peer breaks.
        let attempt = AttemptId::new();
        let message = context_message(
            6,
            &context(Some(TenantId::new()), Trust::Protected),
            attempt,
        );
        let bytes = postcard::to_allocvec(&message).unwrap();
        match postcard::from_bytes::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::Context2(wire) => {
                let (decoded_attempt, decoded) = JobContext::from_wire2(wire).unwrap();
                assert_eq!(decoded_attempt, attempt);
                assert_eq!(decoded.trust, Trust::Protected);
                assert!(decoded.tenant.is_some());
            }
            _ => panic!("Context2 must decode"),
        }
    }
}
