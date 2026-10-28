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
use sentinel_cache::remote::{
    Chunk, DIGEST_AT_END, End, Grant, Need, Push, Refusal, Refused, Serving, Upload,
};
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
    negotiate::{
        CACHE_CANCEL_MIN, CANCEL_PUSH_MIN, DIGEST_AT_END_MIN, Hello, MAX_CANCEL_PUSH,
        MAX_PREFETCH_IMAGES, MAX_PREFETCH_REFERENCE_BYTES, Negotiated, PREFETCH_MIN, PROFILE_MIN,
        Profile, Rejected,
    },
    summary::MAX_SUMMARY_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, identity::fingerprint_of};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(15);
pub const HEARTBEAT_MIN_INTERVAL: Duration = Duration::from_secs(1);
pub const HEARTBEAT_MAX_INTERVAL: Duration = Duration::from_millis(7_500);
const _: () = assert!(HEARTBEAT_MAX_INTERVAL.as_millis() * 2 <= HEARTBEAT_DEADLINE.as_millis());

fn clamp_heartbeat(announced_ms: u32) -> Duration {
    Duration::from_millis(u64::from(announced_ms))
        .clamp(HEARTBEAT_MIN_INTERVAL, HEARTBEAT_MAX_INTERVAL)
}
const TLS_READ_BYTES: usize = 16 * 1024 + 512;
pub const SPEC_CHUNK_BYTES: usize = 48 * 1024;
pub const MAX_SPEC_BYTES: usize = MAX_API_BODY_BYTES;
const MAX_IN_FLIGHT_SECRET_BYTES: usize = 8 * sentinel_protocol::secrets::MAX_DELIVERY_BYTES;
pub const MAX_CACHE_CHUNK_BYTES: usize = 48 * 1024;
const MAX_CACHE_TRANSFERS: usize = 4;
const UPLOAD_IDLE: Duration = Duration::from_secs(60);
const TRANSPORT_BEATS: u64 = 12;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Path {
    #[default]
    Unknown,
    Direct,
    Relay,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStats {
    pub path: Path,
    pub rtt_ns: Option<u64>,
    pub reconnects: u64,
    pub helper_version: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

pub type TransportSource = Arc<dyn Fn() -> TransportStats + Send + Sync>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        hello: Hello,
        worker: [u8; 16],
        name: String,
        enrollment: Option<String>,
        capacity: Capacity,
    },
    Ping {
        seq: u64,
        held: Vec<[u8; 16]>,
    },
    Ack {
        attempt: [u8; 16],
        fence: u64,
    },
    Decline {
        attempt: [u8; 16],
        fence: u64,
    },
    Report {
        attempt: [u8; 16],
        fence: u64,
        event: WireEvent,
        summary: Option<Vec<u8>>,
    },
    NeedSpec {
        attempt: [u8; 16],
    },
    Log {
        attempt: [u8; 16],
        seq: u64,
        step: u32,
        stream: u8,
        bytes: Vec<u8>,
    },
    LogEnd {
        attempt: [u8; 16],
        last_seq: u64,
        gaps: Vec<(u64, u64)>,
    },
    Abandon {
        attempt: [u8; 16],
        fence: u64,
    },
    ArtifactBegin {
        attempt: [u8; 16],
        name: String,
    },
    ArtifactFile {
        attempt: [u8; 16],
        path: String,
        len: u64,
        mode: u32,
    },
    ArtifactData {
        attempt: [u8; 16],
        seq: u32,
        bytes: Vec<u8>,
    },
    ArtifactEnd {
        attempt: [u8; 16],
        name: String,
    },
    ArtifactAbsent {
        attempt: [u8; 16],
        name: String,
        reason: u8,
    },
    Bye,
    Profile(Profile),
    BulkHello {
        worker: [u8; 16],
    },
    Transport(TransportStats),
    CacheNeed(Need),
    CacheOffer(Upload),
    CachePush(Push),
    CachePushEnd(End),
    CacheCancel {
        attempt: [u8; 16],
    },
}

struct LogRef<'a> {
    attempt: &'a [u8; 16],
    seq: u64,
    step: u32,
    stream: u8,
    bytes: &'a [u8],
}

const LOG_VARIANT: u32 = 6;

struct PushRef<'a> {
    attempt: &'a [u8; 16],
    offset: u64,
    bytes: &'a [u8],
}

const CACHE_PUSH_VARIANT: u32 = 20;

impl Serialize for PushRef<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        struct Body<'b>(&'b PushRef<'b>);
        impl Serialize for Body<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut s = serializer.serialize_struct("Push", 3)?;
                s.serialize_field("attempt", self.0.attempt)?;
                s.serialize_field("offset", &self.0.offset)?;
                s.serialize_field("bytes", self.0.bytes)?;
                s.end()
            }
        }
        serializer.serialize_newtype_variant(
            "ClientMessage",
            CACHE_PUSH_VARIANT,
            "CachePush",
            &Body(self),
        )
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireEvent {
    PreparationStarted,
    StepsStarted,
    FinalizationStarted,
    Passed,
    Failed(u8),
}

impl WireEvent {
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
    Pong {
        seq: u64,
        lease_until_ms: i64,
        stop: Vec<[u8; 16]>,
        cancel: Vec<[u8; 16]>,
    },
    Offer(WireOffer),
    Spec {
        attempt: [u8; 16],
        seq: u32,
        last: bool,
        bytes: Vec<u8>,
    },
    NoSpec {
        attempt: [u8; 16],
    },
    Context(WireContext),
    LogAck {
        attempt: [u8; 16],
        through: u64,
    },
    LogRefused {
        attempt: [u8; 16],
    },
    LogEndAck {
        attempt: [u8; 16],
    },
    Source {
        attempt: [u8; 16],
        access: sentinel_protocol::source::Access,
    },
    ArtifactGrant {
        attempt: [u8; 16],
        name: String,
    },
    ArtifactVerdict {
        attempt: [u8; 16],
        name: String,
        code: u8,
    },
    /// Appended last: postcard encodes enum variants positionally.
    Context2(WireContext2),
    CacheGrant(Grant),
    CacheChunk(Chunk),
    CacheEnd(End),
    CacheRefused(Refused),
    Prefetch {
        images: Vec<String>,
    },
    SecretBegin {
        attempt: [u8; 16],
        fence: u64,
        length: u32,
    },
    SecretChunk {
        attempt: [u8; 16],
        fence: u64,
        seq: u32,
        last: bool,
        bytes: sentinel_protocol::secrets::SecretBytes,
    },
    /// Protocol 11: cancellation pushed when it commits; the heartbeat's `cancel` still repeats it.
    Cancel {
        attempts: Vec<[u8; 16]>,
    },
}

pub(crate) trait SensitiveFrame {
    fn is_sensitive(&self) -> bool;
}

impl SensitiveFrame for ClientMessage {
    fn is_sensitive(&self) -> bool {
        false
    }
}

impl SensitiveFrame for ServerMessage {
    fn is_sensitive(&self) -> bool {
        matches!(self, ServerMessage::SecretChunk { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogVerdict {
    Acked(u64),
    /// Not yet durable: the session calls log_sync before acknowledging, so one fsync covers a burst of frames.
    Stored(u64),
    Refused,
    Retry,
}

/// Setuid, setgid and sticky are never carried: an artifact is data, not a privileged executable.
pub const ARTIFACT_MODE_BITS: u32 = 0o777;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCode {
    Stored,
    NotDeclared,
    Duplicate,
    Invalid,
    TooLarge,
    Absent,
    CaptureFailed,
    Stale,
    Store,
}

impl ArtifactCode {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactReply {
    Grant,
    Verdict(ArtifactCode),
}

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
    pub event: String,
    pub event_ref: String,
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    pub event_key: String,
}

/// `trust` is never defaulted: an undecodable byte is a protocol error, not a guessed cache boundary.
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
    pub event: String,
    pub event_ref: String,
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    pub event_key: String,
    pub tenant: [u8; 16],
    pub trust: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    pub name: String,
    pub ref_name: String,
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    pub key: String,
}

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
    pub tenant: Option<TenantId>,
    pub trust: Trust,
}

pub const SOURCE_ACCESS_WINDOW_MS: i64 = 12 * 60 * 1000;

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
                // The wire could not say it: the safest scope is the one a pull request would get.
                tenant: None,
                trust: Trust::PullRequest,
            },
        ))
    }

    fn from_wire2(wire: WireContext2) -> Result<(AttemptId, JobContext)> {
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

pub(crate) fn context_message(
    protocol: u16,
    context: &JobContext,
    attempt: AttemptId,
) -> ServerMessage {
    if protocol >= 6 {
        let mut wire = context.to_wire2(attempt);
        wire.trust = context.trust.for_protocol(protocol).to_u8();
        ServerMessage::Context2(wire)
    } else {
        ServerMessage::Context(context.to_wire(attempt))
    }
}

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

/// Wire-flat on purpose: postcard cannot encode the internally tagged `Rejected`, so it is mirrored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    UnsupportedVersion {
        supported_min: u16,
        supported_max: u16,
        upgrade_worker: bool,
    },
    MissingCapabilities(u64),
    InvalidRange,
    NotEnrolled,
    Enrollment,
    Identity,
    Capacity,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub worker: WorkerId,
    pub pool: sentinel_core::PoolId,
    pub negotiated: Negotiated,
}

pub trait Admission: Send + Sync {
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection>;

    #[allow(clippy::too_many_arguments)]
    fn admit_from(
        &self,
        _source: Option<std::net::IpAddr>,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection> {
        self.admit(fingerprint, worker, name, hello, enrollment, capacity)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beat {
    pub lease_until: UnixMillis,
    pub stop: Vec<AttemptId>,
    pub cancel: Vec<AttemptId>,
}

pub trait SessionHandler: Send + Sync {
    fn spec_requested(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _sender: Sender,
        _protocol: u16,
    ) -> bool {
        false
    }
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<Beat>;
    fn acknowledged(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    fn declined(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    fn reported(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        fence: Fence,
        event: Event,
        summary: Option<Vec<u8>>,
    );
    fn spec(&self, worker: WorkerId, attempt: AttemptId) -> Option<(JobContext, Vec<u8>)>;
    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict;
    fn log_sync(&self, _worker: WorkerId, _attempt: AttemptId) -> bool {
        true
    }
    fn log_end(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _last_seq: u64,
        _gaps: &[(u64, u64)],
    ) -> LogVerdict {
        LogVerdict::Refused
    }
    fn abandoned(&self, worker: WorkerId, attempt: AttemptId, fence: Fence);
    fn artifact_begin(&self, _worker: WorkerId, _attempt: AttemptId, _name: &str) -> ArtifactReply {
        ArtifactReply::Verdict(ArtifactCode::Stale)
    }
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
    fn artifact_data(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _seq: u32,
        _bytes: &[u8],
    ) -> Option<ArtifactCode> {
        Some(ArtifactCode::Stale)
    }
    fn artifact_end(&self, _worker: WorkerId, _attempt: AttemptId, _name: &str) -> ArtifactCode {
        ArtifactCode::Stale
    }
    fn artifact_absent(
        &self,
        _worker: WorkerId,
        _attempt: AttemptId,
        _name: &str,
        _reason: u8,
    ) -> ArtifactCode {
        ArtifactCode::Stale
    }
    fn profiled(&self, _worker: WorkerId, _profile: &Profile, _capacity: Capacity) -> Result<()> {
        Ok(())
    }
    fn transport(&self, _worker: WorkerId, _stats: &TransportStats) {}
    /// The need's tenant, repo and trust class must equal the attempt's, and the worker must hold the attempt.
    fn cache_need(&self, _worker: WorkerId, _need: &Need) -> Option<PathBuf> {
        None
    }
    fn cache_offer(&self, _worker: WorkerId, _upload: &Upload) -> Option<PathBuf> {
        None
    }
}

/// Held only while bytes move between the connection and a buffer, never across a socket call.
struct Shared {
    conn: Mutex<rustls::Connection>,
    sock: TcpStream,
    out: AtomicU64,
    in_: AtomicU64,
    closing: std::sync::atomic::AtomicBool,
}

impl Shared {
    fn bytes(&self) -> (u64, u64) {
        (
            self.out.load(Ordering::Relaxed),
            self.in_.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone)]
pub struct Sender(Arc<Shared>);

thread_local! {
    static ENCODE: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Sender {
    pub(crate) fn send<M: Serialize>(&self, message: &M) -> Result<()> {
        self.send_inner(message, false, None, false)
    }

    pub(crate) fn send_bounded<M: Serialize>(&self, message: &M, within: Duration) -> Result<()> {
        self.send_inner(message, false, Some(within), false)
    }

    fn send_waiting<M: Serialize>(&self, message: &M, within: Duration) -> Result<()> {
        self.send_inner(message, false, Some(within), true)
    }

    #[cfg(feature = "controller")]
    pub(crate) fn send_sensitive<M: Serialize>(&self, message: &M) -> Result<()> {
        self.send_inner(message, true, None, false)
    }

    fn send_inner<M: Serialize>(
        &self,
        message: &M,
        sensitive: bool,
        bound: Option<Duration>,
        wait: bool,
    ) -> Result<()> {
        ENCODE.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            scratch.clear();
            scratch.extend_from_slice(&[0; 4]);
            let mut buffer = std::mem::take(&mut *scratch);
            let outcome = if sensitive {
                match postcard::to_allocvec(message) {
                    Err(_) => Err(Error::Protocol("encode")),
                    Ok(mut payload) => {
                        buffer.extend_from_slice(&payload);
                        payload.fill(0);
                        let len = buffer.len() - 4;
                        if len > MAX_CONTROL_MESSAGE_BYTES {
                            Err(Error::Protocol("frame too large"))
                        } else {
                            buffer[..4].copy_from_slice(&(len as u32).to_be_bytes());
                            self.write_frame(&buffer, bound, wait)
                        }
                    }
                }
            } else {
                let encoded = postcard::to_extend(message, buffer);
                buffer = match encoded {
                    Ok(encoded) => encoded,
                    Err(_) => return Err(Error::Protocol("encode")),
                };
                let len = buffer.len() - 4;
                if len > MAX_CONTROL_MESSAGE_BYTES {
                    Err(Error::Protocol("frame too large"))
                } else {
                    buffer[..4].copy_from_slice(&(len as u32).to_be_bytes());
                    self.write_frame(&buffer, bound, wait)
                }
            };
            if sensitive {
                buffer.fill(0);
            }
            *scratch = buffer;
            outcome
        })
    }

    fn write_frame(&self, frame: &[u8], bound: Option<Duration>, wait: bool) -> Result<()> {
        if self.0.closing.load(Ordering::Acquire) {
            // A failed write here would reset the socket before the peer reads the close alert, so the frame is dropped.
            return Ok(());
        }
        let mut conn = match (bound, wait) {
            (None, _) | (Some(_), true) => self.0.conn.lock().unwrap_or_else(|p| p.into_inner()),
            (Some(_), false) => match self.0.conn.try_lock() {
                Ok(conn) => conn,
                Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return Err(Error::Internal(BUSY)),
            },
        };
        if let Some(within) = bound {
            let _ = self.0.sock.set_write_timeout(Some(within));
        }
        let written = (|| -> Result<()> {
            conn.writer().write_all(frame)?;
            let mut sock = &self.0.sock;
            while conn.wants_write() {
                conn.write_tls(&mut sock)?;
            }
            Ok(())
        })();
        if bound.is_some() {
            let _ = self.0.sock.set_write_timeout(Some(HEARTBEAT_DEADLINE));
        }
        drop(conn);
        match written {
            Ok(()) => {
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

    pub fn bytes(&self) -> (u64, u64) {
        self.0.bytes()
    }

    pub fn close(&self) {
        let _ = self.0.sock.shutdown(Shutdown::Both);
    }

    pub fn close_notify(&self) {
        self.0.closing.store(true, Ordering::Release);
        let deadline = Instant::now() + CLOSE_WRITE_TIMEOUT;
        let conn = loop {
            match self.0.conn.try_lock() {
                Ok(conn) => break Some(conn),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    break Some(poisoned.into_inner());
                }
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::WouldBlock) => break None,
            }
        };
        if let Some(mut conn) = conn {
            conn.send_close_notify();
            let _ = self.0.sock.set_write_timeout(Some(CLOSE_WRITE_TIMEOUT));
            let mut sock = &self.0.sock;
            while conn.wants_write() {
                if conn.write_tls(&mut sock).is_err() {
                    break;
                }
            }
        }
        let _ = self.0.sock.shutdown(Shutdown::Write);
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.sock.peer_addr()
    }
}

const CLOSE_WRITE_TIMEOUT: Duration = Duration::from_millis(50);

pub struct Receiver {
    shared: Arc<Shared>,
    sock: TcpStream,
    plain: Vec<u8>,
    tls: Box<[u8; TLS_READ_BYTES]>,
    timeout: Option<Duration>,
}

impl Receiver {
    fn take_frame<M: for<'de> Deserialize<'de> + SensitiveFrame>(&mut self) -> Result<Option<M>> {
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
        let message: M =
            postcard::from_bytes(&self.plain[4..4 + len]).map_err(|_| Error::Protocol("decode"))?;
        if message.is_sensitive() {
            self.plain[..4 + len].fill(0);
        }
        self.plain.drain(..4 + len);
        Ok(Some(message))
    }

    fn drain_plaintext(&mut self) -> Result<bool> {
        let mut conn = self.shared.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut got = false;
        loop {
            let start = self.plain.len();
            self.plain.resize(start + TLS_READ_BYTES, 0);
            match conn.reader().read(&mut self.plain[start..]) {
                Ok(0) => {
                    self.plain.truncate(start);
                    return Err(Error::Closed);
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

    pub(crate) fn recv_timeout<M: for<'de> Deserialize<'de> + SensitiveFrame>(
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
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => true,
                    Err(e) => return Err(e.into()),
                };
                if stalled {
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

    pub(crate) fn recv<M: for<'de> Deserialize<'de> + SensitiveFrame>(
        &mut self,
        deadline: Duration,
    ) -> Result<M> {
        self.recv_timeout(deadline)?.ok_or(Error::Lost)
    }
}

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
        closing: std::sync::atomic::AtomicBool::new(false),
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

enum CacheAnswer {
    Grant(Grant),
    Chunk(Chunk),
    End,
    Refused(Refused),
}

impl CacheAnswer {
    fn terminal(&self) -> bool {
        matches!(self, Self::End | Self::Refused(_))
    }
}

const ANSWER_QUEUE: usize = 64;

enum Slot {
    Live(mpsc::SyncSender<CacheAnswer>),
    Draining,
}

#[derive(Default)]
pub struct CacheRouter {
    waiting: Mutex<HashMap<AttemptId, Slot>>,
}

impl CacheRouter {
    fn register(&self, attempt: AttemptId) -> std::result::Result<Channel<CacheAnswer>, Refusal> {
        let (tx, rx) = mpsc::sync_channel(ANSWER_QUEUE);
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        if waiting.contains_key(&attempt) {
            return Err(Refusal::Busy);
        }
        waiting.insert(attempt, Slot::Live(tx));
        Ok(rx)
    }

    fn finish(&self, attempt: AttemptId, terminal: bool) {
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        if terminal {
            waiting.remove(&attempt);
        } else if let Some(slot) = waiting.get_mut(&attempt) {
            *slot = Slot::Draining;
        }
    }

    fn route(&self, attempt: AttemptId, answer: CacheAnswer) {
        let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        let terminal = answer.terminal();
        let drop_slot = match waiting.get_mut(&attempt) {
            None => false,
            Some(Slot::Draining) => terminal,
            Some(Slot::Live(tx)) => match tx.try_send(answer) {
                Ok(()) => false,
                Err(mpsc::TrySendError::Full(_)) => {
                    waiting.insert(attempt, Slot::Draining);
                    false
                }
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

pub struct LinkRemote {
    control: Sender,
    bulk: Mutex<BulkSlot>,
    fences: Mutex<HashMap<AttemptId, Fence>>,
    router: Arc<CacheRouter>,
    protocol: u16,
}

#[derive(Default)]
struct BulkSlot {
    sender: Option<Sender>,
    route: Route,
    done: (u64, u64),
}

impl BulkSlot {
    fn retire(&mut self) -> bool {
        let Some(sender) = self.sender.take() else {
            return false;
        };
        let (out, in_) = sender.bytes();
        self.done.0 += out;
        self.done.1 += in_;
        true
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub attached: u64,
    pub detached: u64,
}

impl LinkRemote {
    fn set_fence(&self, attempt: AttemptId, fence: Fence) {
        self.fences
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(attempt, fence);
    }

    fn has_fence(&self, attempt: AttemptId, fence: Fence) -> bool {
        self.fences
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
            .copied()
            == Some(fence)
    }

    fn forget_fence(&self, attempt: AttemptId) {
        self.fences
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&attempt);
    }

    fn retain_fences(&self, held: &[AttemptId]) {
        self.fences
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|attempt, _| held.contains(attempt));
    }

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

    fn attach_bulk(&self, bulk: Sender) {
        let mut slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
        slot.retire();
        slot.sender = Some(bulk);
        slot.route.attached += 1;
    }

    fn detach_bulk(&self) {
        let mut slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
        if slot.retire() {
            slot.route.detached += 1;
        }
    }

    fn bulk_bytes(&self) -> (u64, u64) {
        let slot = self.bulk.lock().unwrap_or_else(|p| p.into_inner());
        let (out, in_) = slot.sender.as_ref().map_or((0, 0), Sender::bytes);
        (slot.done.0 + out, slot.done.1 + in_)
    }

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
    ) -> std::result::Result<[u8; 32], Refusal> {
        let at_end = upload.digest == DIGEST_AT_END;
        if at_end && !self.digest_at_end() {
            return Err(Refusal::Store);
        }
        let attempt = AttemptId::from_bytes(upload.attempt).map_err(|_| Refusal::Denied)?;
        let answers = self.router.register(attempt)?;
        let mut claim = Claim {
            remote: self,
            attempt,
            terminal: false,
        };
        self.send(&ClientMessage::CacheOffer(upload.clone()))
            .map_err(|_| Refusal::Aborted)?;
        let start = match wait_answer(&answers, deadline)? {
            CacheAnswer::Refused(refused) => {
                claim.terminal = true;
                return Err(Refusal::from_code(refused.code).unwrap_or(Refusal::Denied));
            }
            CacheAnswer::End if !at_end => {
                claim.terminal = true;
                return Ok(upload.digest);
            }
            CacheAnswer::Grant(grant) => grant,
            CacheAnswer::End | CacheAnswer::Chunk(_) => return Err(Refusal::Store),
        };
        let mut offset = 0u64;
        let mut skip = start.offset;
        let mut buffer = vec![0u8; MAX_CACHE_CHUNK_BYTES];
        let mut sent = 0u64;
        let mut hasher = at_end.then(blake3::Hasher::new);
        loop {
            if Instant::now() >= deadline {
                return Err(Refusal::Aborted);
            }
            let read = source.read(&mut buffer).map_err(|_| Refusal::Aborted)?;
            if read == 0 {
                break;
            }
            let mut piece = &buffer[..read];
            if let Some(hasher) = hasher.as_mut() {
                hasher.update(piece);
            }
            if skip > 0 {
                let drop = skip.min(piece.len() as u64) as usize;
                skip -= drop as u64;
                piece = &piece[drop..];
            }
            if piece.is_empty() {
                continue;
            }
            self.send(&PushRef {
                attempt: &upload.attempt,
                offset,
                bytes: piece,
            })
            .map_err(|_| Refusal::Aborted)?;
            offset += piece.len() as u64;
            sent += piece.len() as u64;
            if sent > upload.total {
                return Err(Refusal::Aborted);
            }
        }
        if sent != upload.total {
            return Err(Refusal::Aborted);
        }
        let digest = match hasher {
            Some(hasher) => *hasher.finalize().as_bytes(),
            None => upload.digest,
        };
        self.send(&ClientMessage::CachePushEnd(End {
            attempt: upload.attempt,
            digest,
        }))
        .map_err(|_| Refusal::Aborted)?;
        let answer = wait_answer(&answers, deadline)?;
        claim.terminal = answer.terminal();
        match answer {
            CacheAnswer::End => Ok(digest),
            CacheAnswer::Refused(refused) => {
                Err(Refusal::from_code(refused.code).unwrap_or(Refusal::Denied))
            }
            CacheAnswer::Grant(_) | CacheAnswer::Chunk(_) => Err(Refusal::Store),
        }
    }

    fn digest_at_end(&self) -> bool {
        self.protocol >= DIGEST_AT_END_MIN.0
    }
}

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

pub struct WorkerSession {
    rx: Receiver,
    tx: Sender,
    pub admitted: Admitted,
    pub fingerprint: Digest,
    capacity: Capacity,
    profiled: bool,
}

pub enum Accepted {
    Control(WorkerSession),
    Bulk(BulkSession),
}

pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

fn handshake(
    conn: &mut rustls::Connection,
    socket: &TcpStream,
    deadline: Duration,
    arrival: Option<&Arrival>,
) -> Result<()> {
    let started = Instant::now();
    let mut sock = socket;
    while conn.is_handshaking() {
        if arrival.is_some_and(Arrival::handed) {
            return Err(Error::Closed);
        }
        if started.elapsed() >= deadline {
            return Err(Error::Lost);
        }
        match conn.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e)
                if arrival.is_some()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub const ARRIVAL_POLL: Duration = Duration::from_millis(20);

#[derive(Debug, Default)]
pub struct Arrival(std::sync::atomic::AtomicU8);

impl Arrival {
    const WAITING: u8 = 0;
    const HANDED: u8 = 1;
    const ADMITTING: u8 = 2;
    const ANSWERED: u8 = 3;
    const UNANSWERED: u8 = 4;
    const LEFT: u8 = 5;

    pub fn hand_off(&self) -> bool {
        self.0
            .compare_exchange(
                Self::WAITING,
                Self::HANDED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn admitting(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::ADMITTING
    }

    pub fn answered(&self) -> Option<bool> {
        match self.0.load(Ordering::Acquire) {
            Self::ANSWERED => Some(true),
            Self::UNANSWERED => Some(false),
            _ => None,
        }
    }

    pub fn leave(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| match state {
                Self::WAITING | Self::ADMITTING => Some(Self::LEFT),
                Self::HANDED => Some(Self::ANSWERED),
                _ => None,
            });
    }

    fn handed(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::HANDED
    }

    fn admit(&self) -> bool {
        self.0
            .compare_exchange(
                Self::WAITING,
                Self::ADMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn close(&self, tx: &Sender, socket: &TcpStream, within: Duration) {
        tx.close_notify();
        let started = Instant::now();
        let _ = socket.set_read_timeout(Some(ARRIVAL_POLL));
        let mut sink = [0u8; 2048];
        let answered = loop {
            match (&*socket).read(&mut sink) {
                Ok(0) => break true,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break true,
            }
            if started.elapsed() >= within {
                break false;
            }
        };
        self.0.store(
            if answered {
                Self::ANSWERED
            } else {
                Self::UNANSWERED
            },
            Ordering::Release,
        );
    }
}

fn configure(socket: &TcpStream, read: Duration) -> Result<()> {
    socket.set_read_timeout(Some(read))?;
    socket.set_write_timeout(Some(HEARTBEAT_DEADLINE))?;
    socket.set_nodelay(true)?;
    Ok(())
}

pub fn accept(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
) -> Result<Accepted> {
    accept_within(socket, config, admission, HANDSHAKE_DEADLINE)
}

pub fn accept_within(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
    deadline: Duration,
) -> Result<Accepted> {
    accept_watched(socket, config, admission, deadline, None)
}

pub fn accept_arriving(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
    deadline: Duration,
    arrival: &Arrival,
    answer_within: Duration,
) -> Result<Accepted> {
    accept_watched(
        socket,
        config,
        admission,
        deadline,
        Some((arrival, answer_within)),
    )
}

fn accept_watched(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    admission: &dyn Admission,
    deadline: Duration,
    arrival: Option<(&Arrival, Duration)>,
) -> Result<Accepted> {
    let started = Instant::now();
    let watched = arrival.map(|(arrival, _)| arrival);
    configure(
        &socket,
        match watched {
            Some(_) => ARRIVAL_POLL.min(deadline),
            None => deadline.min(HEARTBEAT_DEADLINE),
        },
    )?;
    let mut conn = rustls::Connection::Server(
        ServerConnection::new(config).map_err(|e| Error::Tls(e.to_string()))?,
    );
    let handshaken = handshake(&mut conn, &socket, deadline, watched);
    if let (Err(Error::Closed), Some((arrival, within))) = (&handshaken, arrival) {
        let (tx, rx) = split(conn, socket)?;
        arrival.close(&tx, &rx.sock, within);
        return Err(Error::Closed);
    }
    handshaken?;
    let fingerprint = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(fingerprint_of)
        .ok_or(Error::Protocol("no client certificate"))?;
    let source = socket.peer_addr().ok().map(|addr| addr.ip());
    let (tx, mut rx) = split(conn, socket)?;
    let first = loop {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(Error::Lost);
        }
        let Some((arrival, within)) = arrival else {
            break rx.recv::<ClientMessage>(remaining)?;
        };
        if !arrival.handed()
            && let Some(message) = rx.recv_timeout::<ClientMessage>(ARRIVAL_POLL.min(remaining))?
            && arrival.admit()
        {
            break message;
        }
        if arrival.handed() {
            arrival.close(&tx, &rx.sock, within);
            return Err(Error::Closed);
        }
    };
    match first {
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
            match admission.admit_from(
                source,
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

pub struct BulkSession {
    rx: Receiver,
    tx: Sender,
    pub worker: WorkerId,
    pub fingerprint: Digest,
}

impl BulkSession {
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    pub fn serve(
        &mut self,
        handler: &dyn SessionHandler,
        protocol: u16,
        alive: &dyn Fn() -> bool,
    ) -> Result<()> {
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
    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

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

const LOG_SYNC_FRAMES: usize = 64;

fn flush_log_acks(
    handler: &dyn SessionHandler,
    worker: WorkerId,
    tx: &Sender,
    unsynced: &mut Vec<(AttemptId, u64)>,
    frames: &mut usize,
) -> Result<()> {
    *frames = 0;
    for (attempt, through) in unsynced.drain(..) {
        if !handler.log_sync(worker, attempt) {
            return Err(Error::Internal("log store"));
        }
        tx.send(&ServerMessage::LogAck {
            attempt: *attempt.as_bytes(),
            through,
        })?;
    }
    Ok(())
}

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
    let mut artifacts: HashMap<AttemptId, String> = HashMap::new();
    let mut uploads: HashMap<AttemptId, (sentinel_cache::remote::Receiving, Instant)> =
        HashMap::new();
    let transfers = Arc::new(AtomicUsize::new(0));
    let serving: Arc<Mutex<HashMap<AttemptId, Arc<AtomicBool>>>> = Arc::default();
    let mut unsynced: Vec<(AttemptId, u64)> = Vec::new();
    let mut unsynced_frames = 0usize;
    loop {
        let received = if unsynced.is_empty() {
            rx.recv_timeout::<ClientMessage>(HEARTBEAT_DEADLINE)?
        } else {
            match rx.recv_timeout::<ClientMessage>(Duration::ZERO)? {
                Some(message) => Some(message),
                None => {
                    flush_log_acks(handler, worker, tx, &mut unsynced, &mut unsynced_frames)?;
                    rx.recv_timeout::<ClientMessage>(HEARTBEAT_DEADLINE)?
                }
            }
        };
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
        if !unsynced.is_empty() && !matches!(message, ClientMessage::Log { .. }) {
            flush_log_acks(handler, worker, tx, &mut unsynced, &mut unsynced_frames)?;
        }
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
                let summary = summary.filter(|s| s.len() <= MAX_SUMMARY_BYTES);
                handler.reported(worker, attempt, Fence(fence), event.to_event()?, summary);
            }
            ClientMessage::NeedSpec { attempt } => {
                let id = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                if handler.spec_requested(worker, id, tx.clone(), protocol) {
                    continue;
                }
                if protocol < 3 {
                    tx.send(&ServerMessage::NoSpec { attempt })?;
                    continue;
                }
                match handler.spec(worker, id) {
                    Some((context, bytes)) if bytes.len() <= MAX_SPEC_BYTES => {
                        let requires_secrets = sentinel_pipeline::RunSpec::decode(&bytes)
                            .ok()
                            .is_some_and(|spec| {
                                spec.pipeline
                                    .jobs
                                    .iter()
                                    .find(|job| job.name == context.job_name)
                                    .is_some_and(|job| job.spec.requires_secret_delivery())
                            });
                        if requires_secrets {
                            tx.send(&ServerMessage::NoSpec { attempt })?;
                            continue;
                        }
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
                    LogVerdict::Stored(through) => {
                        match unsynced.iter_mut().find(|(a, _)| *a == id) {
                            Some((_, last)) => *last = through,
                            None => unsynced.push((id, through)),
                        }
                        unsynced_frames += 1;
                        if unsynced_frames >= LOG_SYNC_FRAMES {
                            flush_log_acks(
                                handler,
                                worker,
                                tx,
                                &mut unsynced,
                                &mut unsynced_frames,
                            )?;
                        }
                    }
                    LogVerdict::Acked(through) => {
                        flush_log_acks(handler, worker, tx, &mut unsynced, &mut unsynced_frames)?;
                        tx.send(&ServerMessage::LogAck { attempt, through })?;
                    }
                    LogVerdict::Refused => {
                        flush_log_acks(handler, worker, tx, &mut unsynced, &mut unsynced_frames)?;
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
                    LogVerdict::Acked(_) if protocol >= 5 => {
                        tx.send(&ServerMessage::LogEndAck { attempt })?;
                    }
                    LogVerdict::Acked(_) => {}
                    LogVerdict::Refused => {
                        tx.send(&ServerMessage::LogRefused { attempt })?;
                    }
                    LogVerdict::Retry | LogVerdict::Stored(_) => {
                        return Err(Error::Internal("log store"));
                    }
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
                    send_cache_refused(tx, attempt, Refusal::Busy)?;
                    continue;
                }
                if upload.digest == DIGEST_AT_END && protocol < DIGEST_AT_END_MIN.0 {
                    send_cache_refused(tx, attempt, Refusal::Store)?;
                    continue;
                }
                match handler.cache_offer(worker, &upload) {
                    None => send_cache_refused(tx, attempt, Refusal::Denied)?,
                    Some(root) => match sentinel_cache::remote::Receiving::begin(&root, &upload) {
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

struct TransferPermit(Arc<AtomicUsize>);

impl Drop for TransferPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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

pub fn offer(sender: &Sender, offer: &Offer) -> Result<()> {
    let message = ServerMessage::Offer(offer.to_wire());
    let give_up = Instant::now() + OFFER_BUSY_WAIT;
    loop {
        match sender.send_bounded(&message, DISPATCH_WRITE_BOUND) {
            Err(error) if is_busy(&error) && Instant::now() < give_up => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) if is_busy(&error) => {
                // The reader holds this lock only for in-memory TLS processing. Waiting cannot
                // strand a leased offer behind reader contention; socket backpressure stays bounded.
                return sender.send_waiting(&message, DISPATCH_WRITE_BOUND);
            }
            outcome => return outcome,
        }
    }
}

pub const OFFER_BUSY_WAIT: Duration = Duration::from_millis(20);

pub const DISPATCH_WRITE_BOUND: Duration = Duration::from_millis(250);

pub const BUSY: &str = "sender busy";

pub fn is_busy(error: &Error) -> bool {
    matches!(error, Error::Internal(BUSY))
}

pub fn is_free(sender: &Sender) -> bool {
    sender.0.conn.try_lock().is_ok()
}

pub fn prefetch(sender: &Sender, images: &[String]) -> Result<()> {
    if images.len() > MAX_PREFETCH_IMAGES
        || images
            .iter()
            .any(|image| image.is_empty() || image.len() > MAX_PREFETCH_REFERENCE_BYTES)
    {
        return Err(Error::Protocol("prefetch hint"));
    }
    sender.send_bounded(
        &ServerMessage::Prefetch {
            images: images.to_vec(),
        },
        DISPATCH_WRITE_BOUND,
    )
}

pub fn cancel(sender: &Sender, attempts: &[AttemptId]) -> Result<()> {
    if attempts.is_empty() || attempts.len() > MAX_CANCEL_PUSH {
        return Err(Error::Protocol("cancel push"));
    }
    sender.send_bounded(
        &ServerMessage::Cancel {
            attempts: attempts.iter().map(|a| *a.as_bytes()).collect(),
        },
        DISPATCH_WRITE_BOUND,
    )
}

pub struct Link {
    rx: Receiver,
    tx: Sender,
    pub worker: WorkerId,
    pub negotiated: Negotiated,
    interval: Duration,
    seq: u64,
    addr: SocketAddr,
    client: Arc<rustls::ClientConfig>,
    remote: Arc<LinkRemote>,
    transport: Option<TransportStats>,
    transport_source: Option<TransportSource>,
    beats: u64,
    ping_sent: Instant,
    remote_cache: bool,
    profile: Option<Profile>,
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
    let server_name = ServerName::try_from("sentinel").expect("static name");
    let mut conn = rustls::Connection::Client(
        ClientConnection::new(Arc::clone(&config), server_name)
            .map_err(|e| Error::Tls(e.to_string()))?,
    );
    handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None)?;
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
            interval: clamp_heartbeat(heartbeat_interval_ms),
            seq: 0,
            addr,
            client: config,
            remote: Arc::new(LinkRemote {
                control: tx,
                bulk: Mutex::new(BulkSlot::default()),
                fences: Mutex::new(HashMap::new()),
                router: Arc::new(CacheRouter::default()),
                protocol: negotiated.protocol.0,
            }),
            transport: None,
            transport_source: None,
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
        | ServerMessage::CacheRefused(_)
        | ServerMessage::Prefetch { .. }
        | ServerMessage::SecretBegin { .. }
        | ServerMessage::SecretChunk { .. }
        | ServerMessage::Cancel { .. } => Err(Error::Protocol("message before welcome")),
    }
}

#[derive(Clone)]
pub struct Reporter {
    control: Sender,
    bulk: Option<Arc<LinkRemote>>,
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

    pub fn route(&self) -> Route {
        self.bulk.as_ref().map(|r| r.route()).unwrap_or_default()
    }

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

    pub fn log(&self, attempt: AttemptId, frame: &Frame) -> Result<()> {
        self.log_frame(attempt, frame.seq, frame.step, frame.stream, &frame.bytes)
            .map(|_| ())
    }

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

    pub fn decline(&self, attempt: AttemptId, fence: Fence) -> Result<()> {
        self.control.send(&ClientMessage::Decline {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
        })
    }

    pub fn protocol(&self) -> u16 {
        self.protocol
    }

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

    pub fn artifacts(&self) -> bool {
        self.protocol >= 4
    }

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

    pub fn artifact_end(&self, attempt: AttemptId, name: &str) -> Result<()> {
        self.bulk_class(&ClientMessage::ArtifactEnd {
            attempt: *attempt.as_bytes(),
            name: name.to_string(),
        })
    }

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

pub trait Executor: Send + Sync {
    fn accepted(&self, _attempt: AttemptId) {}
    fn offered(&self, offer: &Offer) -> bool;
    fn stop(&self, attempt: AttemptId);
    fn cancel(&self, attempt: AttemptId);
    fn held(&self) -> Vec<AttemptId>;
    fn renewed(&self, until: UnixMillis);
    fn renewed_at(&self, until: UnixMillis, _sent: Instant) {
        self.renewed(until);
    }
    fn attached(&self, reporter: Reporter);
    fn detached(&self);
    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>);
    fn spec_with_secrets(
        &self,
        attempt: AttemptId,
        context: JobContext,
        bytes: Vec<u8>,
        secrets: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        if secrets.is_empty() {
            self.spec(attempt, context, bytes);
        } else {
            self.no_spec(attempt);
        }
    }
    fn fence_of(&self, _attempt: AttemptId) -> Option<Fence> {
        None
    }
    fn no_spec(&self, attempt: AttemptId);
    fn bulk_detached(&self) {}
    fn log_acked(&self, attempt: AttemptId, through: u64);
    fn log_refused(&self, attempt: AttemptId);
    fn log_ended(&self, _attempt: AttemptId) {}
    fn artifact_granted(&self, _attempt: AttemptId, _name: &str) {}
    fn artifact_verdict(&self, _attempt: AttemptId, _name: &str, _code: ArtifactCode) {}
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        None
    }
    /// The scratch disk this host can offer jobs right now, when the worker measures it itself (an operator's
    /// `disk_bytes` is a fixed statement and returns `None`). Measured on the file system, it already excludes
    /// whatever any identity on the host keeps there: workspaces, caches, mirrors, images and spools.
    fn disk_room(&self) -> Option<u64> {
        None
    }
    fn prefetch(&self, _images: &[String]) {}
}

impl Link {
    pub fn heartbeat_interval(&self) -> Duration {
        self.interval
    }

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

    pub fn set_availability_sent(&mut self, version: u64) {
        self.availability_sent = version;
    }

    fn refresh_profile(&mut self, executor: &dyn Executor) -> Result<()> {
        if self.negotiated.protocol.0 < CACHE_CANCEL_MIN.0 {
            return Ok(());
        }
        let availability = executor
            .availability()
            .filter(|(version, _)| *version != self.availability_sent);
        let Some(sent) = self.profile.as_ref().map(|p| p.disk_bytes) else {
            return Ok(());
        };
        let disk = executor.disk_room().filter(|room| disk_moved(sent, *room));
        if availability.is_none() && disk.is_none() {
            return Ok(());
        }
        let Some(mut profile) = self.profile.clone() else {
            return Ok(());
        };
        if let Some((_, availability)) = &availability {
            profile.availability.images = availability.images.clone();
            profile.availability.cache_bytes = availability.cache_bytes;
        }
        if let Some(room) = disk {
            profile.disk_bytes = room;
        }
        if profile.invalid().is_some() {
            return Ok(());
        }
        self.tx.send(&ClientMessage::Profile(profile.clone()))?;
        self.profile = Some(profile);
        if let Some((version, _)) = availability {
            self.availability_sent = version;
        }
        Ok(())
    }

    pub fn report_transport(&mut self, stats: &TransportStats) -> Result<()> {
        if self.negotiated.protocol.0 < PROFILE_MIN.0 {
            return Ok(());
        }
        self.transport = Some(stats.clone());
        self.tx.send(&ClientMessage::Transport(stats.clone()))
    }

    pub fn set_transport_source(&mut self, source: TransportSource) {
        self.transport_source = Some(source);
    }

    pub fn bytes(&self) -> (u64, u64) {
        self.tx.bytes()
    }

    pub fn set_remote_cache(&mut self, enabled: bool) {
        self.remote_cache = enabled;
    }

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
        self.ping_sent = Instant::now();
        self.tx.send(&ClientMessage::Ping {
            seq: self.seq,
            held,
        })
    }

    fn beat_recorded(&mut self, rtt: Duration) -> Result<()> {
        self.beats += 1;
        let Some(stats) = self.transport.as_mut() else {
            return Ok(());
        };
        stats.rtt_ns = Some(rtt.as_nanos().min(u64::MAX as u128) as u64);
        let (out, bytes_in) = self.tx.bytes();
        let (bulk_out, bulk_in) = self.remote.bulk_bytes();
        stats.bytes_out = out + bulk_out;
        stats.bytes_in = bytes_in + bulk_in;
        if self.beats.is_multiple_of(TRANSPORT_BEATS) {
            if let Some(source) = &self.transport_source {
                let fresh = source();
                stats.path = fresh.path;
                stats.helper_version = fresh.helper_version;
            }
            self.tx.send(&ClientMessage::Transport(stats.clone()))?;
        }
        Ok(())
    }

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
                if self.negotiated.protocol.0 >= 10 {
                    self.remote.set_fence(offer.attempt, offer.fence);
                }
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
            ServerMessage::Prefetch { images } => {
                if self.negotiated.protocol.0 < PREFETCH_MIN.0 {
                    return Err(Error::Protocol("prefetch needs protocol 9"));
                }
                if images.len() > MAX_PREFETCH_IMAGES
                    || images
                        .iter()
                        .any(|image| image.is_empty() || image.len() > MAX_PREFETCH_REFERENCE_BYTES)
                {
                    return Err(Error::Protocol("prefetch hint"));
                }
                executor.prefetch(&images);
                Ok(false)
            }
            ServerMessage::Cancel { attempts } => {
                if self.negotiated.protocol.0 < CANCEL_PUSH_MIN.0 {
                    return Err(Error::Protocol("cancel push needs protocol 11"));
                }
                if attempts.is_empty() || attempts.len() > MAX_CANCEL_PUSH {
                    return Err(Error::Protocol("cancel push"));
                }
                for attempt in ids(&attempts)? {
                    executor.cancel(attempt);
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

    pub fn sender(&self) -> Sender {
        self.tx.clone()
    }

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
                let held = executor.held();
                state.seen.retain(|a| held.contains(a));
                if self.negotiated.protocol.0 >= 10 {
                    self.remote.retain_fences(&held);
                }
            }
        }
        self.tx.send(&ClientMessage::Bye)
    }
}

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
                if state.secret_parts.contains_key(&attempt) {
                    return Err(Error::Protocol("spec before secret bundle end"));
                }
                if state.discarded.remove(&attempt) {
                    return Ok(());
                }
                let secrets = state.secret_bundles.remove(&attempt).map_or_else(
                    sentinel_protocol::secrets::DeliveryBundle::empty,
                    |(bundle, length)| {
                        state.secret_bytes = state.secret_bytes.saturating_sub(length);
                        bundle
                    },
                );
                executor.spec_with_secrets(attempt, context, bytes, secrets);
            }
        }
        ServerMessage::SecretBegin {
            attempt,
            fence,
            length,
        } => {
            if remote.protocol < 10 {
                return Err(Error::Protocol("secret delivery needs protocol 10"));
            }
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            let length = length as usize;
            if length == 0
                || length > sentinel_protocol::secrets::MAX_DELIVERY_BYTES
                || state.secret_bytes.saturating_add(length) > MAX_IN_FLIGHT_SECRET_BYTES
                || state.secret_parts.contains_key(&attempt)
                || state.secret_bundles.contains_key(&attempt)
                || state.discarded.contains(&attempt)
                || !state.contexts.contains_key(&attempt)
            {
                return Err(Error::Protocol("secret bundle length or duplicate"));
            }
            if !fence_held(remote, executor, attempt, Fence(fence)) {
                state.discarded.insert(attempt);
                return Ok(());
            }
            state.secret_bytes += length;
            state.secret_parts.insert(
                attempt,
                SecretAssembly {
                    bytes: sentinel_protocol::secrets::SecretBytes::new(Vec::with_capacity(length)),
                    length,
                    fence: Fence(fence),
                    next_seq: 0,
                },
            );
        }
        ServerMessage::SecretChunk {
            attempt,
            fence,
            seq,
            last,
            bytes,
        } => {
            if remote.protocol < 10 {
                return Err(Error::Protocol("secret delivery needs protocol 10"));
            }
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            if bytes.len() > SPEC_CHUNK_BYTES {
                return Err(Error::Protocol("secret chunk size"));
            }
            if state.discarded.contains(&attempt) {
                return Ok(());
            }
            let assembly = state
                .secret_parts
                .get_mut(&attempt)
                .ok_or(Error::Protocol("secret chunk without begin"))?;
            if assembly.fence.0 != fence
                || !fence_held(remote, executor, attempt, Fence(fence))
                || seq != assembly.next_seq
                || assembly.bytes.len().saturating_add(bytes.len()) > assembly.length
            {
                return Err(Error::Protocol("secret chunk order or length"));
            }
            assembly.bytes.extend_from_slice(bytes.as_slice());
            assembly.next_seq += 1;
            if last {
                let assembly = state.secret_parts.remove(&attempt).expect("checked above");
                if assembly.bytes.len() != assembly.length {
                    return Err(Error::Protocol("secret bundle incomplete"));
                }
                let bundle: sentinel_protocol::secrets::DeliveryBundle =
                    postcard::from_bytes(assembly.bytes.as_slice())
                        .map_err(|_| Error::Protocol("secret bundle encoding"))?;
                if !bundle.valid() || bundle.is_empty() {
                    return Err(Error::Protocol("secret bundle invalid"));
                }
                state
                    .secret_bundles
                    .insert(attempt, (bundle, assembly.length));
            } else if assembly.bytes.len() == assembly.length {
                return Err(Error::Protocol("secret bundle missing final marker"));
            }
        }
        ServerMessage::Context(wire) => {
            let (attempt, context) = JobContext::from_wire(wire)?;
            state.contexts.insert(attempt, context);
        }
        ServerMessage::Context2(wire) => {
            let (attempt, context) = JobContext::from_wire2(wire)?;
            state.contexts.insert(attempt, context);
        }
        ServerMessage::Source { attempt, access } => {
            let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
            if !access.well_formed() {
                return Err(Error::Protocol("source access"));
            }
            let access = access.rebased(UnixMillis::now().0, SOURCE_ACCESS_WINDOW_MS);
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
            remote.forget_fence(attempt);
            state.discarded.remove(&attempt);
            if let Some(assembly) = state.secret_parts.remove(&attempt) {
                state.secret_bytes = state.secret_bytes.saturating_sub(assembly.length);
            }
            if let Some((_, length)) = state.secret_bundles.remove(&attempt) {
                state.secret_bytes = state.secret_bytes.saturating_sub(length);
            }
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
        | ServerMessage::Offer(_)
        | ServerMessage::Prefetch { .. }
        | ServerMessage::Cancel { .. } => return Err(Error::Protocol("control message on bulk")),
    }
    Ok(())
}

const BULK_POLL: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct BulkDialer {
    addr: SocketAddr,
    client: Arc<rustls::ClientConfig>,
    worker: WorkerId,
    remote: Arc<LinkRemote>,
}

impl BulkDialer {
    pub fn open(&self) -> Result<BulkLink> {
        let socket = TcpStream::connect_timeout(&self.addr, HEARTBEAT_DEADLINE)?;
        configure(&socket, HEARTBEAT_DEADLINE)?;
        let server_name = ServerName::try_from("sentinel").expect("static name");
        let mut conn = rustls::Connection::Client(
            ClientConnection::new(Arc::clone(&self.client), server_name)
                .map_err(|e| Error::Tls(e.to_string()))?,
        );
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None)?;
        let (tx, rx) = split(conn, socket)?;
        tx.send(&ClientMessage::BulkHello {
            worker: *self.worker.as_bytes(),
        })?;
        self.remote.attach_bulk(tx.clone());
        Ok(BulkLink {
            rx,
            tx,
            worker: self.worker,
            remote: Arc::clone(&self.remote),
        })
    }
}

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

    pub fn close(&self) {
        self.tx.close();
    }

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

struct SecretAssembly {
    bytes: sentinel_protocol::secrets::SecretBytes,
    length: usize,
    fence: Fence,
    next_seq: u32,
}

#[derive(Default)]
struct Inbound {
    seen: std::collections::HashSet<AttemptId>,
    specs: std::collections::HashMap<AttemptId, (Vec<u8>, usize)>,
    contexts: std::collections::HashMap<AttemptId, JobContext>,
    secret_parts: std::collections::HashMap<AttemptId, SecretAssembly>,
    secret_bundles:
        std::collections::HashMap<AttemptId, (sentinel_protocol::secrets::DeliveryBundle, usize)>,
    secret_bytes: usize,
    discarded: std::collections::HashSet<AttemptId>,
}

fn fence_held(
    remote: &LinkRemote,
    executor: &dyn Executor,
    attempt: AttemptId,
    fence: Fence,
) -> bool {
    remote.has_fence(attempt, fence) || executor.fence_of(attempt) == Some(fence)
}

/// A measured disk figure is re-sent only when it moved by this much or by a sixteenth, so a busy host's
/// byte-by-byte churn is not a profile message per heartbeat.
const DISK_REFRESH_MIN_BYTES: u64 = 256 << 20;

fn disk_moved(sent: u64, now: u64) -> bool {
    sent.abs_diff(now) >= DISK_REFRESH_MIN_BYTES.max(sent / 16)
}

/// The key a worker states for the physical host it runs on: identities that state the same key are charged
/// against one machine. It is the machine id joined with this boot's id, so a cloned image that kept the
/// original's `/etc/machine-id` is its own host (its kernel boots with its own id), and a machine without a
/// machine id (a minimal container) is still one host for every identity on its kernel. A reboot changes the
/// key, and every identity of the machine restarts with it. All zeros when neither file can be read.
pub fn host_id() -> [u8; 16] {
    let read = |paths: &[&str]| {
        paths.iter().find_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        })
    };
    host_id_from(
        read(&["/etc/machine-id", "/var/lib/dbus/machine-id"]).as_deref(),
        read(&["/proc/sys/kernel/random/boot_id"]).as_deref(),
    )
}

/// `host_id` over already-read machine and boot ids.
pub fn host_id_from(machine: Option<&str>, boot: Option<&str>) -> [u8; 16] {
    let mut out = [0u8; 16];
    let digest = match (machine, boot) {
        (Some(machine), Some(boot)) => {
            let mut hasher = blake3::Hasher::new_derive_key("sentinel host id machine+boot v1");
            hasher.update(&(machine.len() as u64).to_le_bytes());
            hasher.update(machine.as_bytes());
            hasher.update(boot.as_bytes());
            hasher.finalize()
        }
        (Some(machine), None) => blake3::hash(machine.as_bytes()),
        (None, Some(boot)) => {
            let mut hasher = blake3::Hasher::new_derive_key("sentinel host id boot v1");
            hasher.update(boot.as_bytes());
            hasher.finalize()
        }
        (None, None) => return out,
    };
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

pub fn listen(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_announced_heartbeat_interval_is_clamped() {
        assert_eq!(clamp_heartbeat(0), HEARTBEAT_MIN_INTERVAL);
        assert_eq!(clamp_heartbeat(1), HEARTBEAT_MIN_INTERVAL);
        assert_eq!(clamp_heartbeat(5_000), HEARTBEAT_INTERVAL);
        assert_eq!(clamp_heartbeat(u32::MAX), HEARTBEAT_MAX_INTERVAL);
    }

    #[test]
    fn a_measured_disk_is_resent_only_when_it_moved_enough() {
        const GIB: u64 = 1 << 30;
        assert!(!disk_moved(100 * GIB, 100 * GIB + (1 << 20)));
        assert!(!disk_moved(100 * GIB, 100 * GIB - 5 * GIB));
        assert!(disk_moved(100 * GIB, 100 * GIB - 7 * GIB));
        assert!(disk_moved(100 * GIB, 100 * GIB + 7 * GIB));
        assert!(!disk_moved(2 * GIB, 2 * GIB - (200 << 20)));
        assert!(disk_moved(2 * GIB, 2 * GIB - (300 << 20)));
        assert!(disk_moved(0, GIB));
    }

    #[test]
    fn a_host_key_separates_clones_and_joins_identities_on_one_boot() {
        let machine = Some("0123456789abcdef0123456789abcdef");
        let one = host_id_from(machine, Some("boot-a"));
        // Identities of one machine in one boot state the same key.
        assert_eq!(one, host_id_from(machine, Some("boot-a")));
        // A clone keeps the machine id but boots its own kernel.
        assert_ne!(one, host_id_from(machine, Some("boot-b")));
        // A machine id alone is the key older workers stated; a boot id alone covers a container with no
        // machine id, and the two never collide with each other or with the joined key.
        let keys = [
            one,
            host_id_from(machine, None),
            host_id_from(None, Some("boot-a")),
        ];
        assert!(keys.iter().all(|k| *k != [0u8; 16]));
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2]);
        assert_ne!(keys[1], keys[2]);
        // Nothing readable is the unreported host, never a shared key.
        assert_eq!(host_id_from(None, None), [0u8; 16]);
        // The joined key cannot be forged by moving bytes between the two ids.
        assert_ne!(
            host_id_from(Some("ab"), Some("c")),
            host_id_from(Some("a"), Some("bc"))
        );
    }

    fn tls_pair() -> (Sender, Receiver) {
        let server_identity = crate::identity::Identity::generate("controller").unwrap();
        let pin = server_identity.fingerprint();
        let server = crate::tls::server_config(server_identity).unwrap();
        let client =
            crate::tls::client_config(crate::identity::Identity::generate("worker").unwrap(), pin)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut conn = rustls::Connection::Server(ServerConnection::new(server).unwrap());
            handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
            split(conn, socket).unwrap().1
        });
        let socket = TcpStream::connect(addr).unwrap();
        let mut conn = rustls::Connection::Client(
            ClientConnection::new(client, ServerName::try_from("sentinel").unwrap()).unwrap(),
        );
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
        let (tx, _) = split(conn, socket).unwrap();
        (tx, accept.join().unwrap())
    }

    #[test]
    fn transport_bytes_count_every_bulk_connection_of_the_session() {
        let (control, _control_peer) = tls_pair();
        let remote = LinkRemote {
            control,
            bulk: Mutex::new(BulkSlot::default()),
            fences: Mutex::new(HashMap::new()),
            router: Arc::new(CacheRouter::default()),
            protocol: CACHE_CANCEL_MIN.0,
        };
        let cancel = ClientMessage::CacheCancel { attempt: [3; 16] };
        let (first, _first_peer) = tls_pair();
        remote.attach_bulk(first.clone());
        remote.send(&cancel).unwrap();
        remote.send(&cancel).unwrap();
        let first_out = first.bytes().0;
        assert!(first_out > 0);
        assert_eq!(remote.bulk_bytes().0, first_out);
        assert_eq!(remote.control.bytes().0, 0, "bulk-class sends went bulk");
        remote.detach_bulk();
        remote.send(&cancel).unwrap();
        assert_eq!(remote.bulk_bytes().0, first_out);
        let (second, _second_peer) = tls_pair();
        remote.attach_bulk(second.clone());
        remote.send(&cancel).unwrap();
        let second_out = second.bytes().0;
        assert!(second_out > 0);
        assert_eq!(remote.bulk_bytes().0, first_out + second_out);
    }

    #[test]
    fn a_borrowed_cache_push_encodes_exactly_like_the_owned_message() {
        let attempt = AttemptId::new();
        let bytes: Vec<u8> = (0..MAX_CACHE_CHUNK_BYTES as u32).map(|i| i as u8).collect();
        let owned = postcard::to_allocvec(&ClientMessage::CachePush(Push {
            attempt: *attempt.as_bytes(),
            offset: 3 << 33,
            bytes: bytes.clone(),
        }))
        .unwrap();
        let borrowed = postcard::to_allocvec(&PushRef {
            attempt: attempt.as_bytes(),
            offset: 3 << 33,
            bytes: &bytes,
        })
        .unwrap();
        assert_eq!(owned, borrowed);
        assert!(matches!(
            postcard::from_bytes::<ClientMessage>(&borrowed).unwrap(),
            ClientMessage::CachePush(push) if push.offset == 3 << 33 && push.bytes == bytes
        ));
    }

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
        let peer = thread::spawn(move || {
            let socket = TcpStream::connect(addr).unwrap();
            let mut conn = rustls::Connection::Client(
                ClientConnection::new(client, ServerName::try_from("sentinel").unwrap()).unwrap(),
            );
            handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
            thread::sleep(Duration::from_secs(10));
            drop(socket);
        });
        let (socket, _) = listener.accept().unwrap();
        let mut conn = rustls::Connection::Server(ServerConnection::new(server).unwrap());
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
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
        let again = Instant::now();
        assert!(
            tx.send(&ServerMessage::NoSpec { attempt: [1; 16] })
                .is_err()
        );
        assert!(again.elapsed() < Duration::from_millis(150));
        drop(peer);
    }

    fn sender_to_a_peer_that_never_reads() -> (Sender, thread::JoinHandle<()>) {
        let server_identity = crate::identity::Identity::generate("controller").unwrap();
        let pin = server_identity.fingerprint();
        let server = crate::tls::server_config(server_identity).unwrap();
        let client =
            crate::tls::client_config(crate::identity::Identity::generate("worker").unwrap(), pin)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let socket = TcpStream::connect(addr).unwrap();
            let mut conn = rustls::Connection::Client(
                ClientConnection::new(client, ServerName::try_from("sentinel").unwrap()).unwrap(),
            );
            handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
            thread::sleep(Duration::from_secs(10));
        });
        let (socket, _) = listener.accept().unwrap();
        let mut conn = rustls::Connection::Server(ServerConnection::new(server).unwrap());
        handshake(&mut conn, &socket, HEARTBEAT_DEADLINE, None).unwrap();
        (split(conn, socket).unwrap().0, peer)
    }

    #[test]
    fn a_bounded_send_to_a_peer_that_never_reads_fails_fast_and_closes() {
        let (tx, peer) = sender_to_a_peer_that_never_reads();
        let big = vec![0u8; 48 * 1024];
        let overall = Instant::now();
        let (failed, took) = loop {
            let started = Instant::now();
            if let Err(error) = tx.send_bounded(
                &ServerMessage::Spec {
                    attempt: [1; 16],
                    seq: 0,
                    last: false,
                    bytes: big.clone(),
                },
                DISPATCH_WRITE_BOUND,
            ) {
                break (error, started.elapsed());
            }
            assert!(overall.elapsed() < Duration::from_secs(10), "never blocked");
        };
        assert!(matches!(failed, Error::Lost | Error::Io(_)), "{failed}");
        assert!(!is_busy(&failed));
        assert!(took < Duration::from_secs(2), "{took:?}");
        let again = Instant::now();
        let next = tx
            .send_bounded(
                &ServerMessage::NoSpec { attempt: [1; 16] },
                DISPATCH_WRITE_BOUND,
            )
            .unwrap_err();
        assert!(!is_busy(&next));
        assert!(again.elapsed() < Duration::from_millis(200));
        drop(peer);
    }

    #[test]
    fn a_bounded_send_skips_a_busy_connection_without_closing_it() {
        let (tx, _rx) = tls_pair();
        let held = tx.0.conn.lock().unwrap();
        assert!(!is_free(&tx));
        let started = Instant::now();
        let refused = tx
            .send_bounded(
                &ServerMessage::NoSpec { attempt: [2; 16] },
                DISPATCH_WRITE_BOUND,
            )
            .unwrap_err();
        assert!(is_busy(&refused), "{refused}");
        assert!(started.elapsed() < Duration::from_millis(100));
        drop(held);
        assert!(is_free(&tx));
        tx.send_bounded(
            &ServerMessage::NoSpec { attempt: [2; 16] },
            DISPATCH_WRITE_BOUND,
        )
        .expect("busy must not have closed the connection");
    }

    #[test]
    fn an_offer_waits_out_reader_contention_instead_of_returning_busy() {
        let (tx, mut rx) = tls_pair();
        let expected = Offer {
            attempt: AttemptId::new(),
            tenant: TenantId::new(),
            run: RunId::new(),
            job: JobId::new(),
            fence: Fence(7),
            lease_until: UnixMillis(123_456),
            cpu_millis: 2_000,
            memory_bytes: 4 << 30,
            image_digest: "sha256:test".into(),
            image_platform: "linux/amd64".into(),
            job_index: 3,
        };
        let message = ServerMessage::Offer(expected.to_wire());
        let held = tx.0.conn.lock().unwrap();
        let busy = tx.send_bounded(&message, DISPATCH_WRITE_BOUND).unwrap_err();
        assert!(is_busy(&busy), "{busy}");

        let (started_tx, started_rx) = mpsc::channel();
        let (sent_tx, sent_rx) = mpsc::channel();
        let sending = {
            let tx = tx.clone();
            let outgoing = expected.clone();
            thread::spawn(move || {
                started_tx.send(()).unwrap();
                sent_tx.send(offer(&tx, &outgoing)).unwrap();
            })
        };
        started_rx.recv().unwrap();
        assert!(
            matches!(
                sent_rx.recv_timeout(OFFER_BUSY_WAIT * 2),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "the offer must wait for the reader rather than expire as BUSY"
        );
        drop(held);
        sent_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        sending.join().unwrap();
        let ServerMessage::Offer(wire) = rx.recv(Duration::from_secs(1)).unwrap() else {
            panic!("the delivered frame must be the offer");
        };
        assert_eq!(Offer::from_wire(wire).unwrap(), expected);
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
        assert!(matches!(
            context_message(7, &context, attempt),
            ServerMessage::Context2(_)
        ));
    }

    #[test]
    fn wire_context2_survives_postcard() {
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

    struct Awaiting {
        attempt: AttemptId,
        fence: Fence,
        delivered: std::sync::Mutex<Vec<(AttemptId, usize)>>,
    }
    impl Executor for Awaiting {
        fn offered(&self, _: &Offer) -> bool {
            true
        }
        fn stop(&self, _: AttemptId) {}
        fn cancel(&self, _: AttemptId) {}
        fn held(&self) -> Vec<AttemptId> {
            vec![self.attempt]
        }
        fn renewed(&self, _: UnixMillis) {}
        fn attached(&self, _: Reporter) {}
        fn detached(&self) {}
        fn spec(&self, attempt: AttemptId, _: JobContext, _: Vec<u8>) {
            self.delivered.lock().unwrap().push((attempt, 0));
        }
        fn spec_with_secrets(
            &self,
            attempt: AttemptId,
            _: JobContext,
            _: Vec<u8>,
            secrets: sentinel_protocol::secrets::DeliveryBundle,
        ) {
            self.delivered
                .lock()
                .unwrap()
                .push((attempt, secrets.values.len()));
        }
        fn fence_of(&self, attempt: AttemptId) -> Option<Fence> {
            (attempt == self.attempt).then_some(self.fence)
        }
        fn no_spec(&self, _: AttemptId) {}
        fn log_acked(&self, _: AttemptId, _: u64) {}
        fn log_refused(&self, _: AttemptId) {}
    }

    fn secret_answer(attempt: AttemptId, fence: u64) -> Vec<ServerMessage> {
        use sentinel_protocol::secrets::{
            DeliveryBundle, DeliveryTarget, DeliveryValue, SecretBytes, TargetKind,
        };
        let bundle = DeliveryBundle {
            values: vec![DeliveryValue::new(b"token-value".to_vec())],
            targets: vec![DeliveryTarget {
                step: 0,
                name: "TOKEN".into(),
                value: 0,
                target: TargetKind::Environment,
            }],
        };
        let payload = postcard::to_allocvec(&bundle).unwrap();
        vec![
            context_message(
                10,
                &context(Some(TenantId::new()), Trust::Protected),
                attempt,
            ),
            ServerMessage::SecretBegin {
                attempt: *attempt.as_bytes(),
                fence,
                length: payload.len() as u32,
            },
            ServerMessage::SecretChunk {
                attempt: *attempt.as_bytes(),
                fence,
                seq: 0,
                last: true,
                bytes: SecretBytes::copy_from(&payload),
            },
            ServerMessage::Spec {
                attempt: *attempt.as_bytes(),
                seq: 0,
                last: true,
                bytes: b"spec".to_vec(),
            },
        ]
    }

    #[test]
    fn a_secret_transfer_survives_a_new_session_between_ack_and_spec() {
        let (control, _peer) = tls_pair();
        let remote = LinkRemote {
            control,
            bulk: Mutex::new(BulkSlot::default()),
            fences: Mutex::new(HashMap::new()),
            router: Arc::new(CacheRouter::default()),
            protocol: 10,
        };
        let attempt = AttemptId::new();
        let executor = Awaiting {
            attempt,
            fence: Fence(7),
            delivered: std::sync::Mutex::new(Vec::new()),
        };
        let mut state = Inbound::default();
        for message in secret_answer(attempt, 7) {
            handle_bulk_message(message, &executor, &mut state, &remote).unwrap();
        }
        assert_eq!(*executor.delivered.lock().unwrap(), vec![(attempt, 1)]);
        assert_eq!(state.secret_bytes, 0);

        executor.delivered.lock().unwrap().clear();
        for message in secret_answer(attempt, 6) {
            handle_bulk_message(message, &executor, &mut state, &remote).unwrap();
        }
        assert!(executor.delivered.lock().unwrap().is_empty());
        assert!(state.discarded.is_empty() && state.contexts.is_empty());
        assert_eq!(state.secret_bytes, 0);
    }
}
