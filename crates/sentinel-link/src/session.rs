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
    negotiate::{Hello, Negotiated, Rejected},
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
}

/// What the controller did with a log frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogVerdict {
    /// Stored and synced through this sequence.
    Acked(u64),
    Refused,
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
        ServerMessage::Context2(context.to_wire2(attempt))
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
        // In-flight artifact per attempt (protocol 4): set when a begin is
        // granted, cleared by every verdict. Names the verdict a mid-flight
        // failure answers with and orders begin/file/data/end.
        let mut artifacts: std::collections::HashMap<AttemptId, String> =
            std::collections::HashMap::new();
        loop {
            match self.rx.recv::<ClientMessage>(HEARTBEAT_DEADLINE)? {
                ClientMessage::Ping { seq, held } => {
                    if held.len() > MAX_LIST_ITEMS {
                        return Err(Error::Protocol("held list"));
                    }
                    let held = ids(&held)?;
                    let beat = handler.ping(worker, &held)?;
                    self.tx.send(&ServerMessage::Pong {
                        seq,
                        lease_until_ms: beat.lease_until.0,
                        stop: beat.stop.iter().map(|a| *a.as_bytes()).collect(),
                        cancel: beat.cancel.iter().map(|a| *a.as_bytes()).collect(),
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
                ClientMessage::Report {
                    attempt,
                    fence,
                    event,
                    summary,
                } => {
                    let attempt =
                        AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
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
                    if handler.spec_requested(
                        worker,
                        id,
                        self.tx.clone(),
                        self.admitted.negotiated.protocol.0,
                    ) {
                        continue;
                    }
                    // The synchronous fallback (a handler that resolves inline)
                    // still owes the protocol gate.
                    if self.admitted.negotiated.protocol.0 < 3 {
                        self.tx.send(&ServerMessage::NoSpec { attempt })?;
                        continue;
                    }
                    match handler.spec(worker, id) {
                        Some((context, bytes)) if bytes.len() <= MAX_SPEC_BYTES => {
                            self.tx.send(&context_message(
                                self.admitted.negotiated.protocol.0,
                                &context,
                                id,
                            ))?;
                            if let Some(access) = context.source {
                                self.tx.send(&ServerMessage::Source { attempt, access })?;
                            }
                            let chunks = bytes.chunks(SPEC_CHUNK_BYTES);
                            let count = chunks.len().max(1);
                            if bytes.is_empty() {
                                self.tx.send(&ServerMessage::Spec {
                                    attempt,
                                    seq: 0,
                                    last: true,
                                    bytes: Vec::new(),
                                })?;
                            }
                            for (seq, chunk) in chunks.enumerate() {
                                self.tx.send(&ServerMessage::Spec {
                                    attempt,
                                    seq: seq as u32,
                                    last: seq + 1 == count,
                                    bytes: chunk.to_vec(),
                                })?;
                            }
                        }
                        _ => self.tx.send(&ServerMessage::NoSpec { attempt })?,
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
                            self.tx.send(&ServerMessage::LogAck { attempt, through })?;
                        }
                        LogVerdict::Refused => {
                            self.tx.send(&ServerMessage::LogRefused { attempt })?;
                        }
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
                        LogVerdict::Acked(_) if self.admitted.negotiated.protocol.0 >= 5 => {
                            self.tx.send(&ServerMessage::LogEndAck { attempt })?;
                        }
                        LogVerdict::Acked(_) => {}
                        LogVerdict::Refused => {
                            self.tx.send(&ServerMessage::LogRefused { attempt })?;
                        }
                    }
                }
                ClientMessage::Abandon { attempt, fence } => {
                    let attempt =
                        AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                    handler.abandoned(worker, attempt, Fence(fence));
                }
                ClientMessage::ArtifactBegin { attempt, name } => {
                    if self.admitted.negotiated.protocol.0 < 4 {
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
                            self.tx
                                .send(&ServerMessage::ArtifactGrant { attempt, name })?;
                        }
                        ArtifactReply::Verdict(code) => {
                            self.tx.send(&ServerMessage::ArtifactVerdict {
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
                        self.tx.send(&ServerMessage::ArtifactVerdict {
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
                        self.tx.send(&ServerMessage::ArtifactVerdict {
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
                    self.tx.send(&ServerMessage::ArtifactVerdict {
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
                    self.tx.send(&ServerMessage::ArtifactVerdict {
                        attempt,
                        name,
                        code: code.to_u8(),
                    })?;
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
        | ServerMessage::ArtifactVerdict { .. } => Err(Error::Protocol("message before welcome")),
    }
}

/// The executor's way to speak on the session from its own threads: state
/// events under the attempt's fence, and spec requests. Sending fails once
/// the session is gone; the executor keeps the event and resends it when it
/// is attached to the next session.
#[derive(Clone)]
pub struct Reporter {
    tx: Sender,
    protocol: u16,
}

impl Reporter {
    pub fn report(&self, attempt: AttemptId, fence: Fence, event: Event) -> Result<()> {
        let event = WireEvent::from_event(event).ok_or(Error::Protocol("not a worker event"))?;
        self.tx.send(&ClientMessage::Report {
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
        self.tx.send(&ClientMessage::Report {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
            event,
            summary: Some(summary),
        })
    }

    pub fn need_spec(&self, attempt: AttemptId) -> Result<()> {
        self.tx.send(&ClientMessage::NeedSpec {
            attempt: *attempt.as_bytes(),
        })
    }

    /// One frame from the spool. The executor keeps at most
    /// `MAX_UNACKED_LOG_FRAMES` in flight per attempt.
    pub fn log(&self, attempt: AttemptId, frame: &Frame) -> Result<()> {
        if frame.bytes.len() > MAX_LOG_FRAME_BYTES {
            return Err(Error::Protocol("log frame size"));
        }
        self.tx.send(&ClientMessage::Log {
            attempt: *attempt.as_bytes(),
            seq: frame.seq,
            step: frame.step,
            stream: frame.stream as u8,
            bytes: frame.bytes.clone(),
        })
    }

    /// The protocol this session negotiated; the log pipe uses it to
    /// know whether `LogEnd` is answered by `LogEndAck`.
    pub fn protocol(&self) -> u16 {
        self.protocol
    }

    /// The attempt was in this worker's leftovers after a restart.
    pub fn abandon(&self, attempt: AttemptId, fence: Fence) -> Result<()> {
        self.tx.send(&ClientMessage::Abandon {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
        })
    }

    pub fn log_end(&self, attempt: AttemptId, last_seq: u64, gaps: &[(u64, u64)]) -> Result<()> {
        self.tx.send(&ClientMessage::LogEnd {
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
        self.tx.send(&ClientMessage::ArtifactBegin {
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
        self.tx.send(&ClientMessage::ArtifactFile {
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
        self.tx.send(&ClientMessage::ArtifactData {
            attempt: *attempt.as_bytes(),
            seq,
            bytes: bytes.to_vec(),
        })
    }

    /// The artifact's file set is complete; the verdict is terminal.
    pub fn artifact_end(&self, attempt: AttemptId, name: &str) -> Result<()> {
        self.tx.send(&ClientMessage::ArtifactEnd {
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
        self.tx.send(&ClientMessage::ArtifactAbsent {
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
    /// A session is live: reports and spec requests go through `reporter`
    /// until `detached`. Pending reports from a lost session are resent here.
    fn attached(&self, reporter: Reporter);
    fn detached(&self);
    /// The run spec asked for with `Reporter::need_spec`, whole, with the
    /// job context that precedes it.
    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>);
    /// The controller has no spec for the attempt: it is not held here.
    fn no_spec(&self, attempt: AttemptId);
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
        let mut state = Inbound::default();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.rx.recv_timeout::<ServerMessage>(remaining)? {
                None => return Err(Error::Lost),
                Some(message) => {
                    if self.handle(message, executor, &mut state)? {
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
        state: &mut Inbound,
    ) -> Result<bool> {
        let seen = &mut state.seen;
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
                executor.renewed(UnixMillis(lease_until_ms));
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
                Ok(false)
            }
            ServerMessage::Context(wire) => {
                let (attempt, context) = JobContext::from_wire(wire)?;
                state.contexts.insert(attempt, context);
                Ok(false)
            }
            // Protocol 6 shape: carries the tenant and the cache trust
            // class; same in-flight bookkeeping as `Context`.
            ServerMessage::Context2(wire) => {
                let (attempt, context) = JobContext::from_wire2(wire)?;
                state.contexts.insert(attempt, context);
                Ok(false)
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
                Ok(false)
            }
            ServerMessage::LogAck { attempt, through } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                executor.log_acked(attempt, through);
                Ok(false)
            }
            ServerMessage::LogRefused { attempt } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                executor.log_refused(attempt);
                Ok(false)
            }
            ServerMessage::LogEndAck { attempt } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                executor.log_ended(attempt);
                Ok(false)
            }
            ServerMessage::ArtifactGrant { attempt, name } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                executor.artifact_granted(attempt, &name);
                Ok(false)
            }
            ServerMessage::ArtifactVerdict {
                attempt,
                name,
                code,
            } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                executor.artifact_verdict(attempt, &name, ArtifactCode::from_u8(code));
                Ok(false)
            }
            ServerMessage::NoSpec { attempt } => {
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Protocol("id"))?;
                state.specs.remove(&attempt);
                state.contexts.remove(&attempt);
                executor.no_spec(attempt);
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
        executor.attached(Reporter {
            tx: self.tx.clone(),
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
                awaiting = None;
                // Forget answered attempts the executor no longer holds.
                let held = executor.held();
                state.seen.retain(|a| held.contains(a));
            }
        }
        self.tx.send(&ClientMessage::Bye)
    }
}

/// Per-session inbound state: offers already answered, specs in flight.
#[derive(Default)]
struct Inbound {
    seen: std::collections::HashSet<AttemptId>,
    specs: std::collections::HashMap<AttemptId, (Vec<u8>, usize)>,
    contexts: std::collections::HashMap<AttemptId, JobContext>,
}

/// Bind a listener for tests and the controller alike.
pub fn listen(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for bad in [2u8, 9, 255] {
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
