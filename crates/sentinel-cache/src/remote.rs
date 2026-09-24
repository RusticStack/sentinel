//! Q08 — remote cache hydration: portable, checksummed, resumable
//! transfer of sealed generations through the controller. See
//! `docs/cache.md`.
//!
//! A *bundle* is the canonical byte stream of one sealed generation: a
//! fixed head, the exact `manifest` bytes, the exact `files` bytes, then
//! every payload file concatenated in listing order. The stream's BLAKE3
//! digest is its identity — content addressing, dedup and resume
//! validation in one value — and every chunk carries the running digest
//! of the prefix it extends, so corruption is caught at the chunk that
//! caused it, never at the end of a long transfer.
//!
//! The worker-side driver ([`hydrate`]) runs only on a local miss. It
//! resumes the partial at `<entry>/writing/remote.part` when one is
//! there, aborts as `unavailable` when the estimated remaining transfer
//! exceeds the budget (`min(5 s, job timeout / 4)`, docs/cache.md), and
//! installs what it received by building a staging generation and
//! renaming it into the entry — the same atomic promotion a publication
//! uses. A bundle that fails the *local* lookup (wrong scope, wrong key,
//! corrupt) is never served, whatever the controller said.
//!
//! The controller-side store ([`Serving`], [`Receiving`]) keeps one
//! bundle per entry, addressed by the same scope path the workers use:
//! `<root>/<repo>/<class>/<trust>/<platform>/<toolchain16>/<name>/<entry>/`
//! with `<bundle-id>.bundle` files and `current` naming the bundle id a
//! fetch is served. Transfers are bounded; one live writer per entry is
//! `busy`, and an upload that is refused costs nothing but its own
//! bytes. Nothing here ever changes a verdict: an offer is background
//! work after the attempt already reported.

use std::{
    fmt, fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sentinel_core::{RepoId, TenantId};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};
use serde::{Deserialize, Serialize};

use crate::{
    attach::{self, Attached},
    lease::{self, Lease},
    manifest::{FileEntry, FilesBlob, MAX_FILES_BLOB_BYTES, MAX_MANIFEST_BYTES, Manifest, Request},
    outcome::{Hit, Miss},
    publish,
    restore::{self, Context},
    scope::{self, Os, Platform, Scope},
};

/// The canonical stream's head: a 12-byte magic, the format byte, three
/// reserved zero bytes, then `manifest_len`, `files_len` and
/// `payload_len` as big-endian `u64`.
const STREAM_MAGIC: &[u8; 12] = b"snc.cache.b1";
const STREAM_FORMAT: u8 = 1;
const STREAM_HEAD: usize = 40;
/// One read block while hashing or copying a bundle.
const BLOCK_BYTES: usize = 256 << 10;
/// What one hydration may spend at most, however long the job's own
/// timeout is — the restore-cost bound `docs/cache.md` states.
pub const BUDGET_MAX: Duration = Duration::from_secs(5);
/// No bundle larger than this is ever transferred; the stream head is
/// decoded before anything is allocated, and this is the sanity bound on
/// what it may name.
pub const MAX_BUNDLE_BYTES: u64 = 64 << 30;
/// One wire chunk carries at most this many bytes; the receiver's own
/// bound, above what the link frames today.
pub const MAX_CHUNK_BYTES: usize = 1 << 20;
/// A serve hands the link one chunk per call: 48 KiB, because the bulk
/// frame carries exactly one chunk and a split chunk could not carry the
/// running digest its pieces extend.
const CHUNK_BYTES: usize = 48 << 10;
/// An offer is optional post-verdict work: bounded like the publish batch
/// that fed it, never the job's decision.
pub const OFFER_BUDGET: Duration = Duration::from_secs(30);
/// The transfer's own rate estimate is ignored until this much of it has
/// been measured — an early burst must not promise more than the link
/// can hold.
const RATE_SAMPLE: Duration = Duration::from_millis(250);
/// The staging generation a hydration streams into and resumes: one per
/// entry, written and resumed only under `writing/.lock`, promoted into
/// the entry by rename once complete.
const STAGE_NAME: &str = "remote.stage";
/// Inside the staging generation: the head, manifest and listing while
/// they are still arriving. Replaced by the generation's own `manifest`
/// and `files` once whole.
const PREFIX_NAME: &str = "prefix.part";
/// The single-file partial hydrations resumed from before the stream was
/// staged in place; an upgraded worker drops it and restarts cold.
const LEGACY_PART: &str = "remote.part";
/// The longest prefix a serve hashes to prove a resume point; beyond it
/// the transfer restarts cold. A hydration budget of at most 5 s never
/// leaves a partial anywhere near this.
pub const MAX_RESUME_HASH: u64 = 1 << 30;
/// The controller store's byte budget (`sweep_store`): past it, whole
/// entries go least recently served first.
pub const STORE_BUDGET_BYTES: u64 = 50 << 30;
/// An upload staging file (`writing/*.part`) untouched this long belongs
/// to a transfer that ended without its end; the sweep removes it.
pub const STALE_UPLOAD: Duration = Duration::from_secs(60 * 60);
/// Free space an upload always leaves on the store's filesystem: 5 % of
/// it, at most this much.
pub const STORE_FREE_RESERVE: u64 = 1 << 30;

/// `os` wire code for the only executor OS. The code, not the enum, is
/// the wire form: a newer OS can only arrive as a value this build
/// refuses.
pub const OS_LINUX: u8 = 0;
pub const ARCH_X86_64: u8 = 0;
pub const ARCH_AARCH64: u8 = 1;

/// The wire form of a platform: `(os, arch)` codes.
pub fn platform_code(platform: Platform) -> (u8, u8) {
    let os = match platform.os {
        Os::Linux => OS_LINUX,
    };
    let arch = match platform.arch {
        Arch::X86_64 => ARCH_X86_64,
        Arch::Aarch64 => ARCH_AARCH64,
    };
    (os, arch)
}

/// Decode a platform; `None` for anything this build does not know — a
/// request that names another OS is refused, never guessed.
pub fn platform_of(os: u8, arch: u8) -> Option<Platform> {
    if os != OS_LINUX {
        return None;
    }
    let arch = match arch {
        ARCH_X86_64 => Arch::X86_64,
        ARCH_AARCH64 => Arch::Aarch64,
        _ => return None,
    };
    Some(Platform {
        os: Os::Linux,
        arch,
    })
}

/// A hydration request, worker → controller: which entry, from where.
///
/// `key` is the *entry* key (`attach::entry_key`: the stem for
/// `downloads`/`compiler`, the whole rendered key for `dependencies`) —
/// exactly what names the entry directory on both sides. `offset` and
/// `have` are the resume request: the prefix length the worker already
/// holds and its BLAKE3 digest (the empty digest at offset 0). The
/// controller answers with the offset it will actually serve from — 0
/// when its bundle does not extend the worker's prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    /// The attempt the request is fenced by; the controller authorizes
    /// against it (`dispatch::attempt_scope`) before serving.
    pub attempt: [u8; 16],
    pub tenant: [u8; 16],
    pub repo: [u8; 16],
    pub class: u8,
    pub trust: u8,
    pub os: u8,
    pub arch: u8,
    pub toolchain: [u8; 32],
    pub name: String,
    pub key: String,
    pub offset: u64,
    pub have: [u8; 32],
}

impl Need {
    /// The request for `scope`'s entry, resumed from `offset`/`have`.
    pub fn of(attempt: [u8; 16], scope: &Scope, key: &str, offset: u64, have: [u8; 32]) -> Need {
        let (os, arch) = platform_code(scope.platform);
        Need {
            attempt,
            tenant: *scope.tenant.as_bytes(),
            repo: *scope.repo.as_bytes(),
            class: scope.class.to_u8(),
            trust: scope.trust.to_u8(),
            os,
            arch,
            toolchain: scope.toolchain,
            name: scope.name.clone(),
            key: key.to_owned(),
            offset,
            have,
        }
    }
}

/// A sealed generation offered for remote storage, worker → controller.
/// `total` and `digest` are the canonical stream's length and BLAKE3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    pub attempt: [u8; 16],
    pub tenant: [u8; 16],
    pub repo: [u8; 16],
    pub class: u8,
    pub trust: u8,
    pub os: u8,
    pub arch: u8,
    pub toolchain: [u8; 32],
    pub name: String,
    pub key: String,
    pub total: u64,
    pub digest: [u8; 32],
}

impl Upload {
    /// The offer for `scope`'s entry.
    pub fn of(attempt: [u8; 16], scope: &Scope, key: &str, total: u64, digest: [u8; 32]) -> Upload {
        let (os, arch) = platform_code(scope.platform);
        Upload {
            attempt,
            tenant: *scope.tenant.as_bytes(),
            repo: *scope.repo.as_bytes(),
            class: scope.class.to_u8(),
            trust: scope.trust.to_u8(),
            os,
            arch,
            toolchain: scope.toolchain,
            name: scope.name.clone(),
            key: key.to_owned(),
            total,
            digest,
        }
    }
}

/// The controller's grant, controller → worker: where the transfer starts
/// and what it must add up to. For a fetch, `offset`/`prefix` are the
/// accepted resume point and the digest of the stream through it; for an
/// offer, they describe the controller's partial (offset 0 today).
/// `digest` is the whole bundle either way — the value the terminal
/// [`End`] must name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub attempt: [u8; 16],
    pub total: u64,
    pub offset: u64,
    pub prefix: [u8; 32],
    pub digest: [u8; 32],
}

/// One ordered download chunk, controller → worker. `prefix` is the
/// BLAKE3 of the stream through `offset + bytes.len()`; a receiver checks
/// it before accepting the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub attempt: [u8; 16],
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub prefix: [u8; 32],
}

/// One ordered upload chunk, worker → controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    pub attempt: [u8; 16],
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// The terminal marker, both directions: the stream through `digest` is
/// complete (fetch) or stored (offer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct End {
    pub attempt: [u8; 16],
    pub digest: [u8; 32],
}

/// A refusal with a stable code, controller → worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub attempt: [u8; 16],
    pub code: u8,
}

/// Why a transfer did not happen. The codes are the wire vocabulary;
/// `Aborted` is worker-internal (a sink that stopped its own transfer)
/// and is never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The entry has no bundle that can serve the request.
    NoBundle = 1,
    /// The attempt is not held by this worker, or tenant, repo or trust
    /// disagree with the job's context.
    Denied = 2,
    /// The request itself does not decode: unknown class, trust, platform,
    /// or an out-of-bounds key/name.
    WrongScope = 3,
    /// A live writer holds the entry's staging area.
    Busy = 4,
    /// Larger than the store or the transfer bound allows.
    TooLarge = 5,
    /// A storage failure on either side.
    Store = 6,
    /// The receiver stopped the transfer itself (budget, deadline, a
    /// broken prefix). Worker-internal; never a wire code.
    Aborted = 7,
}

impl Refusal {
    /// The wire code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode a wire code; `None` for anything this build does not know —
    /// the caller refuses rather than guesses.
    pub const fn from_code(code: u8) -> Option<Refusal> {
        match code {
            1 => Some(Self::NoBundle),
            2 => Some(Self::Denied),
            3 => Some(Self::WrongScope),
            4 => Some(Self::Busy),
            5 => Some(Self::TooLarge),
            6 => Some(Self::Store),
            7 => Some(Self::Aborted),
            _ => None,
        }
    }

    /// The stable lowercase spelling for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBundle => "no_bundle",
            Self::Denied => "denied",
            Self::WrongScope => "wrong_scope",
            Self::Busy => "busy",
            Self::TooLarge => "too_large",
            Self::Store => "store",
            Self::Aborted => "aborted",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The worker-side transport seam: what the link provides to hydration
/// and offering. Implementations block on the caller's thread; every wait
/// is bounded by `deadline`, and an `Err` from a [`Sink`] stops the
/// exchange and is returned verbatim.
pub trait Remote: Send + Sync {
    /// Request the bundle for `need`. The implementation sends
    /// `CacheNeed`, relays the controller's grant through [`Sink::plan`],
    /// then its chunks through [`Sink::chunk`], and returns once the
    /// controller ended the stream — or the controller
    /// (`NoBundle`/`Denied`/`Busy`/…) or the sink (`Aborted`) refused.
    fn fetch(&self, need: &Need, deadline: Instant, sink: &mut dyn Sink) -> Result<(), Refusal>;

    /// Offer `upload`'s canonical stream, read from `source` in order.
    /// The implementation sends `CacheOffer`, pushes the stream in `Push`
    /// chunks from the granted offset, ends with `CachePushEnd`, and
    /// answers once the controller stored it (or refused), with the digest
    /// it stored.
    ///
    /// `upload.digest` is the stream's digest, or [`DIGEST_AT_END`] when
    /// [`Remote::digest_at_end`] said the peer takes it in the end marker:
    /// the implementation then hashes the bytes as it sends them, so the
    /// stream is read once rather than hashed in a pass of its own first.
    fn offer(
        &self,
        upload: &Upload,
        deadline: Instant,
        source: &mut dyn Read,
    ) -> Result<[u8; 32], Refusal>;

    /// Whether the controller takes an offer's digest in its end marker
    /// (protocol 9). An older one needs it up front.
    fn digest_at_end(&self) -> bool {
        false
    }
}

/// `Upload::digest` of an offer whose digest is named only by its
/// `CachePushEnd` (protocol 9). The stream's content address is BLAKE3, so
/// no real stream has this digest.
pub const DIGEST_AT_END: [u8; 32] = [0; 32];

/// The receiving half of one fetch. Both calls run on the fetch's thread,
/// in order: one `plan`, then ordered `chunk`s.
pub trait Sink {
    /// The controller's grant. A sink may refuse here (budget, bounds).
    fn plan(&mut self, grant: &Grant) -> Result<(), Refusal>;
    /// One ordered chunk; `chunk.offset` must equal everything accepted
    /// so far.
    fn chunk(&mut self, chunk: &Chunk) -> Result<(), Refusal>;
}

/// What one attempt's restores may spend on remote hydration, and who the
/// transfers are fenced by. Present only when the worker's link offers a
/// remote source; then a local miss may hydrate.
#[derive(Clone, Copy)]
pub struct Policy<'a> {
    pub source: &'a dyn Remote,
    /// The attempt the request is authorized under — the id the
    /// controller fences against (`dispatch::cache_scope`).
    pub attempt: [u8; 16],
    /// When every hydration of this attempt must be done — resuming,
    /// transferring and installing alike (P08-C6). One deadline per job,
    /// fixed before its first restore ([`Policy::deadline_for`]), so N
    /// caches share one budget instead of each taking their own.
    pub deadline: Instant,
}

impl Policy<'_> {
    /// `min(BUDGET_MAX, job_timeout / 4)` — the whole job's hydration
    /// allowance.
    pub fn budget(job_timeout: Duration) -> Duration {
        (job_timeout / 4).min(BUDGET_MAX)
    }

    /// The job-level deadline a policy carries: now plus [`Policy::budget`].
    pub fn deadline_for(job_timeout: Duration) -> Instant {
        Instant::now() + Self::budget(job_timeout)
    }
}

/// What remote hydration decided for one restore.
pub(crate) enum Hydro {
    /// A verified bundle was materialized into the targets and promoted
    /// into the entry: the hit, its generation and the pin that keeps it.
    Served(Box<Hydrated>),
    /// The controller had nothing to serve (or refused the request
    /// itself): the local miss stands unchanged.
    Nothing,
    /// A transfer ran and cannot serve: this is the miss to report.
    Refused(Miss),
}

/// A served hydration.
pub(crate) struct Hydrated {
    pub hit: Hit,
    pub generation: String,
    pub lease: Lease,
}

/// The miss a transfer-level failure reports: transient, distinct from
/// the local lookup's own reason, and worth retrying (docs/cache.md).
const TRANSFER_MISS: Miss = Miss::Unavailable;

/// Hydrate `attached`'s entry from the controller. Called only when the
/// local lookup missed; a local hit never reaches this.
///
/// Bounded as one transfer: one staging generation, one staging writer
/// per entry (`writing/.lock`), one lease for the whole flow. The stream
/// is demultiplexed as it arrives — head, manifest and listing checked
/// against *this* request before a payload byte is written, every payload
/// file written once, straight into the staging generation, and verified
/// against its listing entry as it completes (P08-C8). The local listing
/// checks run once more before a byte reaches the job — corrupt or
/// wrong-scope content can never serve.
pub(crate) fn hydrate(
    env: &Context<'_>,
    attached: &mut Attached,
    owner: &str,
    policy: Policy<'_>,
) -> Hydro {
    // The clock is the job's: it started before the first restore and
    // covers resuming the staged prefix, the transfer and the install.
    let deadline = policy.deadline;
    let started = Instant::now();
    if started >= deadline {
        return Hydro::Nothing;
    }
    let entry_key = attach::entry_key(attached.scope.class, &attached.key);
    let entry = attached.scope.entry_dir(env.cache_root, entry_key);
    // One staging writer per entry: a live publisher or another hydrator
    // is a skip, never a wait — the attempt rebuilds instead.
    let Ok(Some(_staging)) = lease::WriteLock::acquire(&entry, owner) else {
        return Hydro::Nothing;
    };
    // The pin: nothing inside the entry is collected while this runs, and
    // the promoted generation stays put after it.
    let Ok(lease) = Lease::acquire(&entry, owner, lease::DEFAULT_TTL) else {
        return Hydro::Nothing;
    };
    let writing = entry.join(scope::WRITING_NAME);
    // A single-file partial from before streaming installs cannot be
    // resumed into a staging generation: it restarts cold.
    let _ = fs::remove_file(writing.join(LEGACY_PART));
    let stage = writing.join(STAGE_NAME);
    let request = Req {
        scope: attached.scope.clone(),
        key: attached.key.clone(),
        compat: attached.compat.clone(),
        targets: attached.targets.len(),
    };
    let copies = env.backend == crate::clone::Backend::Copy;
    let Ok(mut sink) = Stager::open(stage.clone(), request, copies, deadline, started) else {
        // Unreadable, or resuming the staged prefix ran out of budget: it
        // is kept for an attempt with more time.
        return Hydro::Nothing;
    };
    let need = Need::of(
        policy.attempt,
        &attached.scope,
        entry_key,
        sink.offset,
        sink.have(),
    );
    let fetched = policy.source.fetch(&need, deadline, &mut sink);
    attached.stats.remote_ns = Some(ns(started));
    attached.stats.remote_bytes = sink.received;
    // Where the transfer really resumed: the controller's granted offset,
    // not the one this side asked for (P08-C7).
    attached.stats.remote_from = sink.grant.map(|g| g.offset).filter(|o| *o > 0);
    let halt = sink.halt;
    let drop_stage = || {
        let _ = fs::remove_dir_all(&stage);
    };

    match fetched {
        Ok(()) => {}
        // The controller has no bundle for the entry: whatever was staged
        // can never complete, so it goes.
        Err(Refusal::NoBundle) => {
            drop(sink);
            drop_stage();
            return Hydro::Nothing;
        }
        // Refused for now (`denied`, `busy`): the local lookup's own reason
        // is the honest answer, and a valid staged prefix stays for later
        // (P08-C7); an empty one is no resume point.
        Err(Refusal::Denied) | Err(Refusal::Busy) => {
            let empty = sink.offset == 0;
            drop(sink);
            if empty {
                drop_stage();
            }
            return Hydro::Nothing;
        }
        // A transfer whose bytes cannot be the promised stream — or whose
        // head is not this request's — is dropped whole; a budget or
        // deadline abort keeps what it staged, and the next attempt
        // resumes it.
        Err(_) => {
            return match halt {
                Some(Halt::Corrupt) => {
                    drop(sink);
                    drop_stage();
                    Hydro::Refused(Miss::Corrupt)
                }
                Some(Halt::Refused(miss)) => {
                    drop(sink);
                    drop_stage();
                    Hydro::Refused(miss)
                }
                Some(Halt::Budget | Halt::Io) | None => Hydro::Refused(TRANSFER_MISS),
            };
        }
    }
    let complete = sink.grant.is_some_and(|grant| {
        sink.offset == grant.total && sink.hasher.clone().finalize().as_bytes() == &grant.digest
    });
    let layout = sink.finished();
    let (true, Some(layout)) = (complete, layout) else {
        // A transport that "succeeded" without a plan, or bytes that are
        // not the stream that was promised: staging that can never verify
        // is worse than none.
        drop_stage();
        return Hydro::Refused(Miss::Corrupt);
    };

    if Instant::now() >= deadline {
        // Complete but out of time to install: the verified staging stays,
        // and the next attempt installs it without a byte on the wire.
        return Hydro::Refused(TRANSFER_MISS);
    }
    // The local listing checks run again over the staged tree, then the
    // clone into the job's private view — the materialization a local hit
    // gets, from the generation this transfer just staged.
    attached.stats.reflink = env.backend == crate::clone::Backend::Reflink;
    let blob = match restore::materialize(
        &stage,
        &layout.manifest,
        &attached.targets,
        env.backend,
        &mut attached.stats,
    ) {
        Ok(blob) => blob,
        Err(miss) => {
            drop_stage();
            return Hydro::Refused(miss);
        }
    };
    attached.stats.first_touch_ns = restore::first_touch(&blob, &attached.targets);
    let generation = scope::gen_name(layout.manifest.sealed_ms as i64, lease::rand_u32());
    // Promotion is best-effort: the served bytes are already verified and
    // materialized, so a store failure here is a lost local copy, not a
    // lost restore — and staging that did not land is not kept either.
    if promote(&entry, &stage, &generation).is_err() {
        drop_stage();
    }
    let bytes = layout.bytes;
    Hydro::Served(Box::new(Hydrated {
        hit: Hit {
            manifest: layout.manifest,
            bytes,
        },
        generation,
        lease,
    }))
}

fn ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

/// The empty-prefix digest: what `have` is at offset 0.
fn empty_digest() -> [u8; 32] {
    *blake3::Hasher::new().finalize().as_bytes()
}

/// Hash `len` bytes from the start, leaving the cursor at `len` — the
/// running state a resume continues from. Past `deadline` it stops with
/// `TimedOut`: resuming a large partial is part of the restore's budget.
fn hash_prefix(
    file: &mut fs::File,
    len: u64,
    deadline: Option<Instant>,
) -> io::Result<blake3::Hasher> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    hash_into(file, len, &mut hasher, None, deadline)?;
    Ok(hasher)
}

/// Feed the next `len` bytes of `file` into `hasher` (and `also`, when
/// given). Past `deadline` it stops with `TimedOut`.
fn hash_into(
    file: &mut fs::File,
    len: u64,
    hasher: &mut blake3::Hasher,
    mut also: Option<&mut blake3::Hasher>,
    deadline: Option<Instant>,
) -> io::Result<()> {
    let mut buf = vec![0u8; BLOCK_BYTES.min(usize::try_from(len).unwrap_or(BLOCK_BYTES))];
    let mut left = len;
    while left > 0 {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "resume hash out of budget",
            ));
        }
        let want = left.min(buf.len() as u64) as usize;
        let read = file.read(&mut buf[..want])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "partial ended early",
            ));
        }
        hasher.update(&buf[..read]);
        if let Some(also) = also.as_deref_mut() {
            also.update(&buf[..read]);
        }
        left -= read as u64;
    }
    Ok(())
}

/// Why a sink stopped its own transfer. `Budget` is the restore-cost or
/// deadline bound doing its job; `Corrupt` means the bytes are not the
/// stream the controller promised; `Refused` is a head that decoded but
/// cannot serve this request (wrong scope, unsealed, unknown format) — the
/// same typed miss the local lookup would answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Halt {
    Budget,
    /// A staging write failed: the transfer stops, what is staged stays,
    /// and a resume re-derives its offset from the disk.
    Io,
    Corrupt,
    Refused(Miss),
}

/// What the stream must answer: the lookup a local generation would face.
struct Req {
    scope: Scope,
    key: String,
    compat: crate::manifest::Compat,
    /// Declared paths: a listing may only name `payload/<i>` below this.
    targets: usize,
}

/// A staged stream's decoded head: the sealed manifest and the listing in
/// stream order (sorted by path, as offers write it).
struct Layout {
    manifest: Manifest,
    entries: Vec<FileEntry>,
    /// Logical bytes the hit reports (`Manifest::compatible`'s answer).
    bytes: u64,
    /// Head, manifest and listing: where the payload starts.
    prefix: u64,
    /// Total payload bytes the listing promises.
    payload: u64,
}

/// The payload file being written.
struct Cursor {
    index: usize,
    file: Option<fs::File>,
    /// Bytes of this file still to come.
    left: u64,
    /// This file's own digest, checked against its listing entry when the
    /// last byte lands.
    hasher: Box<blake3::Hasher>,
}

enum Phase {
    /// Head, manifest and listing still arriving: held in memory (bounded
    /// by the head's own limits) and appended to `prefix.part` so a resume
    /// can continue it.
    Prefix { buf: Vec<u8>, file: fs::File },
    /// Payload bytes go straight into their files in the staging
    /// generation.
    Payload(Box<Layout>, Cursor),
    /// Every byte the head promised is staged and verified.
    Done(Box<Layout>),
    /// A failed write left the phase unknown; the transfer stops.
    Broken,
}

/// The receiving side of one fetch: a staging generation under
/// `writing/remote.stage` that the stream is written into exactly once,
/// its running digest, and the budget checks. Every refusal is the
/// driver's too — the transport stops and returns it verbatim.
struct Stager {
    dir: PathBuf,
    request: Req,
    phase: Phase,
    hasher: blake3::Hasher,
    offset: u64,
    total: u64,
    grant: Option<Grant>,
    /// The job's view will be byte-copied from staging (no reflink): the
    /// budget estimate charges that copy at the measured rate.
    copies: bool,
    deadline: Instant,
    started: Instant,
    /// Bytes this attempt received — the measured rate's numerator.
    received: u64,
    /// Set when the sink aborted for a reason the driver reports.
    halt: Option<Halt>,
}

impl Stager {
    /// Open `dir` for this request, resuming whatever a previous attempt
    /// staged: the prefix it holds is re-hashed (within `deadline`) and
    /// the transfer asks to continue from its end. Staging that cannot be
    /// read as a stream prefix of this request is dropped, never trusted:
    /// a cold start is always safe, a guessed resume is not.
    fn open(
        dir: PathBuf,
        request: Req,
        copies: bool,
        deadline: Instant,
        started: Instant,
    ) -> io::Result<Stager> {
        fs::create_dir_all(&dir)?;
        let mut stager = Stager {
            dir,
            request,
            phase: Phase::Broken,
            hasher: blake3::Hasher::new(),
            offset: 0,
            total: 0,
            grant: None,
            copies,
            deadline,
            started,
            received: 0,
            halt: None,
        };
        match stager.resume() {
            Ok(true) => {}
            Ok(false) => stager.reset()?,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(e),
            Err(_) => stager.reset()?,
        }
        Ok(stager)
    }

    /// The running digest of everything staged.
    fn have(&self) -> [u8; 32] {
        *self.hasher.clone().finalize().as_bytes()
    }

    /// Rebuild the running state from what is on disk. `Ok(false)` means
    /// the staging is not a usable prefix and must restart empty.
    fn resume(&mut self) -> io::Result<bool> {
        let manifest_path = self.dir.join(scope::MANIFEST_NAME);
        let files_path = self.dir.join(scope::FILES_NAME);
        if !manifest_path.exists() || !files_path.exists() {
            // Only the head so far, if anything.
            let mut file = fs::OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(self.dir.join(PREFIX_NAME))?;
            let len = file.metadata()?.len();
            if len > STREAM_HEAD as u64 + MAX_MANIFEST_BYTES + MAX_FILES_BLOB_BYTES {
                return Ok(false);
            }
            let mut buf = Vec::with_capacity(len as usize);
            file.read_to_end(&mut buf)?;
            self.hasher.update(&buf);
            self.offset = buf.len() as u64;
            self.phase = Phase::Prefix { buf, file };
            return Ok(true);
        }
        // A crash between writing the head's files and dropping the raw
        // prefix leaves both: the files are the authority.
        let _ = fs::remove_file(self.dir.join(PREFIX_NAME));
        let manifest_raw = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let files_raw = read_bounded(&files_path, MAX_FILES_BLOB_BYTES)?;
        let Ok(layout) = self.layout(&manifest_raw, &files_raw) else {
            return Ok(false);
        };
        let head = head_bytes(
            manifest_raw.len() as u64,
            files_raw.len() as u64,
            layout.payload,
        );
        self.hasher.update(&head);
        self.hasher.update(&manifest_raw);
        self.hasher.update(&files_raw);
        self.offset = layout.prefix;
        let deadline = Some(self.deadline);
        for index in 0..layout.entries.len() {
            let entry = &layout.entries[index];
            let path = self.dir.join(&entry.path);
            let len = match fs::metadata(&path) {
                Ok(meta) => meta.len(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    self.phase = Phase::Payload(
                        Box::new(layout),
                        Cursor {
                            index,
                            file: None,
                            left: 0,
                            hasher: Box::default(),
                        },
                    );
                    return Ok(true);
                }
                Err(e) => return Err(e),
            };
            if len > entry.size {
                return Ok(false);
            }
            let mut file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
            if len == entry.size {
                // Complete files were verified against their listing entry
                // when they landed; the stream digest proves them again.
                hash_into(&mut file, len, &mut self.hasher, None, deadline)?;
                self.offset += len;
                continue;
            }
            let mut own = blake3::Hasher::new();
            hash_into(&mut file, len, &mut self.hasher, Some(&mut own), deadline)?;
            self.offset += len;
            let left = entry.size - len;
            self.phase = Phase::Payload(
                Box::new(layout),
                Cursor {
                    index,
                    file: Some(file),
                    left,
                    hasher: Box::new(own),
                },
            );
            return Ok(true);
        }
        self.phase = Phase::Done(Box::new(layout));
        Ok(true)
    }

    /// Restart empty: the staging directory is recreated and the running
    /// digest is the empty prefix's.
    fn reset(&mut self) -> io::Result<()> {
        self.phase = Phase::Broken;
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::create_dir_all(&self.dir)?;
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(PREFIX_NAME))?;
        self.phase = Phase::Prefix {
            buf: Vec::new(),
            file,
        };
        self.hasher = blake3::Hasher::new();
        self.offset = 0;
        Ok(())
    }

    /// Decode and check a complete head against this request: the same
    /// checks, in the same order, a local lookup of the generation runs.
    fn layout(&self, manifest_raw: &[u8], files_raw: &[u8]) -> Result<Layout, Miss> {
        let manifest = Manifest::decode(manifest_raw)?;
        if !manifest.sealed() {
            return Err(Miss::Unsealed);
        }
        // Wrong scope, wrong key or wrong compat never serves, whatever
        // the controller claimed — and is known before a payload byte.
        let bytes = manifest.compatible(&Request {
            scope: &self.request.scope,
            key: &self.request.key,
            compat: &self.request.compat,
        })?;
        if blake3::hash(files_raw).as_bytes() != &manifest.files_digest {
            return Err(Miss::Corrupt);
        }
        let blob = FilesBlob::decode(files_raw)?;
        if blob.entries.len() as u32 != manifest.files {
            return Err(Miss::Corrupt);
        }
        let mut entries = blob.entries;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut payload = 0u64;
        for entry in &entries {
            if !sentinel_pipeline::schema::valid_relative_path(&entry.path) {
                return Err(Miss::Invalid);
            }
            // A listing may only name `payload/<i>` for a declared path.
            if !payload_index(&entry.path).is_some_and(|index| index < self.request.targets) {
                return Err(Miss::Invalid);
            }
            payload = payload.checked_add(entry.size).ok_or(Miss::Corrupt)?;
        }
        let prefix = STREAM_HEAD as u64 + manifest_raw.len() as u64 + files_raw.len() as u64;
        Ok(Layout {
            manifest,
            entries,
            bytes,
            prefix,
            payload,
        })
    }

    /// The staged layout once every promised byte landed.
    fn finished(&mut self) -> Option<Layout> {
        match std::mem::replace(&mut self.phase, Phase::Broken) {
            Phase::Done(layout) => Some(*layout),
            _ => None,
        }
    }

    /// Write `bytes` — already proven to extend the promised stream — into
    /// the staging generation.
    fn feed(&mut self, mut bytes: &[u8]) -> Result<(), Halt> {
        while !bytes.is_empty() {
            match &mut self.phase {
                Phase::Prefix { buf, file } => {
                    let want = prefix_want(buf, self.total)?;
                    let take = want.min(bytes.len());
                    buf.extend_from_slice(&bytes[..take]);
                    file.write_all(&bytes[..take]).map_err(|_| Halt::Io)?;
                    bytes = &bytes[take..];
                    if buf.len() >= STREAM_HEAD && prefix_want(buf, self.total)? == 0 {
                        self.enter_payload()?;
                    }
                }
                Phase::Payload(layout, cursor) => {
                    let entry = &layout.entries[cursor.index];
                    if cursor.file.is_none() {
                        let path = self.dir.join(&entry.path);
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent).map_err(|_| Halt::Io)?;
                        }
                        cursor.file = Some(fs::File::create(&path).map_err(|_| Halt::Io)?);
                        cursor.left = entry.size;
                        cursor.hasher.reset();
                    }
                    let take = usize::try_from(cursor.left)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    if let Some(file) = cursor.file.as_mut() {
                        file.write_all(&bytes[..take]).map_err(|_| Halt::Io)?;
                    }
                    cursor.hasher.update(&bytes[..take]);
                    cursor.left -= take as u64;
                    bytes = &bytes[take..];
                    if cursor.left == 0 {
                        self.close_file()?;
                    }
                }
                // The plan bounds the stream to the head's total, so a
                // finished layout never sees more bytes.
                Phase::Done(_) | Phase::Broken => return Err(Halt::Corrupt),
            }
        }
        Ok(())
    }

    /// The head is complete: decode and check it, write the generation's
    /// `manifest` and `files`, and start the payload.
    fn enter_payload(&mut self) -> Result<(), Halt> {
        let Phase::Prefix { buf, .. } = std::mem::replace(&mut self.phase, Phase::Broken) else {
            return Err(Halt::Corrupt);
        };
        let manifest_len = u64_at(&buf, 16) as usize;
        let manifest_raw = &buf[STREAM_HEAD..STREAM_HEAD + manifest_len];
        let files_raw = &buf[STREAM_HEAD + manifest_len..];
        let layout = self
            .layout(manifest_raw, files_raw)
            .map_err(Halt::Refused)?;
        if u64_at(&buf, 32) != layout.payload
            || layout.prefix.checked_add(layout.payload) != Some(self.total)
        {
            return Err(Halt::Corrupt);
        }
        fs::write(self.dir.join(scope::MANIFEST_NAME), manifest_raw).map_err(|_| Halt::Io)?;
        fs::write(self.dir.join(scope::FILES_NAME), files_raw).map_err(|_| Halt::Io)?;
        let _ = fs::remove_file(self.dir.join(PREFIX_NAME));
        self.phase = Phase::Payload(
            Box::new(layout),
            Cursor {
                index: 0,
                file: None,
                left: 0,
                hasher: Box::default(),
            },
        );
        self.skip_empty()
    }

    /// The current file's last byte landed: verify it against its listing
    /// entry, apply its mode, move to the next.
    fn close_file(&mut self) -> Result<(), Halt> {
        self.seal_current()?;
        self.skip_empty()
    }

    /// Verify the file at the cursor against its listing entry, apply its
    /// mode and advance.
    fn seal_current(&mut self) -> Result<(), Halt> {
        let Phase::Payload(layout, cursor) = &mut self.phase else {
            return Err(Halt::Corrupt);
        };
        let entry = &layout.entries[cursor.index];
        cursor.file = None;
        if cursor.hasher.finalize().as_bytes() != &entry.digest {
            return Err(Halt::Corrupt);
        }
        publish::stamp_mode(&self.dir.join(&entry.path), entry.mode).map_err(|_| Halt::Io)?;
        cursor.index += 1;
        Ok(())
    }

    /// Land every empty file at the cursor (they carry no stream bytes),
    /// and finish the layout when no file is left.
    fn skip_empty(&mut self) -> Result<(), Halt> {
        loop {
            let Phase::Payload(layout, cursor) = &mut self.phase else {
                return Ok(());
            };
            match layout.entries.get(cursor.index) {
                None => {
                    if let Phase::Payload(layout, _) =
                        std::mem::replace(&mut self.phase, Phase::Broken)
                    {
                        self.phase = Phase::Done(layout);
                    }
                    return Ok(());
                }
                Some(entry) if entry.size > 0 => return Ok(()),
                Some(entry) => {
                    let path = self.dir.join(&entry.path);
                    cursor.hasher.reset();
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(|_| Halt::Io)?;
                    }
                    fs::File::create(&path).map_err(|_| Halt::Io)?;
                    self.seal_current()?;
                }
            }
        }
    }
}

/// How many more head bytes `buf` needs: first the fixed head, then the
/// manifest and listing it announces. Checks the head as soon as it is
/// whole — a foreign format or impossible lengths stop the transfer before
/// anything else is buffered.
fn prefix_want(buf: &[u8], total: u64) -> Result<usize, Halt> {
    if buf.len() < STREAM_HEAD {
        return Ok(STREAM_HEAD - buf.len());
    }
    if &buf[..12] != STREAM_MAGIC || buf[13..16] != [0, 0, 0] {
        return Err(Halt::Corrupt);
    }
    if buf[12] != STREAM_FORMAT {
        return Err(Halt::Refused(Miss::UnsupportedVersion));
    }
    let manifest_len = u64_at(buf, 16);
    let files_len = u64_at(buf, 24);
    if manifest_len > MAX_MANIFEST_BYTES || files_len > MAX_FILES_BLOB_BYTES {
        return Err(Halt::Corrupt);
    }
    let whole = STREAM_HEAD as u64 + manifest_len + files_len;
    if whole > total {
        return Err(Halt::Corrupt);
    }
    Ok((whole - buf.len() as u64) as usize)
}

/// A small metadata file, refused past `limit` rather than read whole.
fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

impl Sink for Stager {
    fn plan(&mut self, grant: &Grant) -> Result<(), Refusal> {
        if grant.total > MAX_BUNDLE_BYTES || grant.offset > grant.total {
            return Err(Refusal::TooLarge);
        }
        // The controller may only continue from a prefix this staging
        // actually holds; a longer one cannot be invented.
        if grant.offset > self.offset {
            self.halt = Some(Halt::Corrupt);
            return Err(Refusal::Aborted);
        }
        if grant.offset < self.offset {
            // Its bundle does not extend what is staged. A controller
            // restarts cold (offset 0); any other point is not a prefix a
            // staging generation can be cut back to.
            if grant.offset != 0 {
                self.halt = Some(Halt::Corrupt);
                return Err(Refusal::Aborted);
            }
            self.reset().map_err(|_| Refusal::Store)?;
        }
        if self.have() != grant.prefix {
            // What is staged is not the prefix the controller is about to
            // continue: abort rather than splice two streams.
            self.halt = Some(Halt::Corrupt);
            return Err(Refusal::Aborted);
        }
        self.total = grant.total;
        self.grant = Some(*grant);
        // A resumed head must still add up to the whole stream.
        let fits = match &self.phase {
            Phase::Payload(layout, _) | Phase::Done(layout) => {
                layout.prefix.checked_add(layout.payload) == Some(grant.total)
            }
            Phase::Prefix { buf, .. } => prefix_want(buf, grant.total).is_ok(),
            Phase::Broken => false,
        };
        if !fits {
            self.halt = Some(Halt::Corrupt);
            return Err(Refusal::Aborted);
        }
        // A head that was staged whole before the cut goes straight on to
        // the payload: no further byte of it will arrive.
        if let Phase::Prefix { buf, .. } = &self.phase
            && buf.len() >= STREAM_HEAD
            && prefix_want(buf, grant.total) == Ok(0)
            && let Err(halt) = self.enter_payload()
        {
            self.halt = Some(halt);
            return Err(Refusal::Aborted);
        }
        Ok(())
    }

    fn chunk(&mut self, chunk: &Chunk) -> Result<(), Refusal> {
        if chunk.offset != self.offset || chunk.bytes.len() > MAX_CHUNK_BYTES {
            return Err(Refusal::Store);
        }
        let next = self
            .offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or(Refusal::TooLarge)?;
        if next > self.total {
            return Err(Refusal::Store);
        }
        // Proven before a byte is written: corruption is caught at the
        // chunk that caused it and never reaches the staging generation.
        self.hasher.update(&chunk.bytes);
        if self.have() != chunk.prefix {
            self.halt = Some(Halt::Corrupt);
            return Err(Refusal::Aborted);
        }
        if let Err(halt) = self.feed(&chunk.bytes) {
            // A write failure is transient (`Budget` keeps the staging for
            // a resume, which re-derives its offset from the disk); a head
            // or file that cannot verify drops it.
            self.halt = Some(halt);
            return Err(if halt == Halt::Io {
                Refusal::Store
            } else {
                Refusal::Aborted
            });
        }
        self.offset = next;
        self.received += chunk.bytes.len() as u64;
        let now = Instant::now();
        if now >= self.deadline {
            self.halt = Some(Halt::Budget);
            return Err(Refusal::Aborted);
        }
        // The restore-cost policy: once the transfer has a measured rate,
        // stop when the *estimated* remaining time no longer fits the
        // budget that is left. The deadline above still bounds a link that
        // stalls before the first sample.
        let elapsed = now.duration_since(self.started).as_nanos();
        if elapsed >= RATE_SAMPLE.as_nanos() && self.received > 0 {
            // `remaining / rate > left`, i.e. `remaining * elapsed >
            // left * received`, in `u128` — never an integer ns-per-byte
            // that truncates to zero on a fast link (P08-C7). The install
            // only copies the payload into the job's view when there is no
            // reflink; that copy is estimated at the measured rate too
            // (P08-C6). The stream itself is written once, as it arrives.
            let install = if self.copies { self.total } else { 0 };
            let remaining = u128::from(self.total - self.offset) + u128::from(install);
            let left = self.deadline.saturating_duration_since(now).as_nanos();
            if remaining.saturating_mul(elapsed) > left.saturating_mul(u128::from(self.received)) {
                self.halt = Some(Halt::Budget);
                return Err(Refusal::Aborted);
            }
        }
        Ok(())
    }
}

/// Promote a staging generation exactly as a publication does: the
/// generation lands inside the entry first, then `current` names it — a
/// reader sees the old generation or the new one, never a torn name.
/// Promotion is unconditional, the same rule a commit follows: a
/// hydration only runs when the live pointer did not serve this request,
/// so what it replaces was stale, corrupt or incompatible.
fn promote(entry: &Path, staging: &Path, generation: &str) -> io::Result<()> {
    fs::rename(staging, entry.join(generation))?;
    publish::sync_dir(entry)?;
    let tmp = entry.join(publish::CURRENT_TMP);
    publish::write_synced(&tmp, generation.as_bytes())?;
    fs::rename(&tmp, entry.join(scope::CURRENT_NAME))?;
    publish::sync_dir(entry)?;
    Ok(())
}

/// `payload/<i>/<rel>` → `i`, in the listing's own shape.
fn payload_index(path: &str) -> Option<usize> {
    let rest = path.strip_prefix("payload/")?;
    let (index, rel) = rest.split_once('/')?;
    if rel.is_empty() {
        return None;
    }
    index.parse().ok()
}

/// `u64` from eight big-endian bytes at `at`; the caller has already read
/// the whole head, so the slice is in bounds.
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(raw)
}

// ——— offering ——————————————————————————————————————————————

/// Offer one sealed generation to the controller: offer the metadata,
/// stream the canonical bytes. `Ok` carries the digest the controller
/// stored; every error is a refusal the caller treats as a dropped offer,
/// never a failure of anything else. The attempt's finalization calls
/// this after its terminal report already left (`OFFER_BUDGET` bounds
/// it), so an offer can never change a verdict.
///
/// A controller that takes the digest at the end (protocol 9) gets the
/// stream read once and hashed as it is sent (P08-C8); an older one needs
/// the digest up front, which costs a hashing pass over the generation
/// before the bytes go out.
pub fn offer_generation(
    cache_root: &Path,
    attached: &Attached,
    generation: &str,
    attempt: [u8; 16],
    source: &dyn Remote,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<[u8; 32], Refusal> {
    if !generation.starts_with("gen-") || generation.contains(['/', '\\']) {
        return Err(Refusal::Store);
    }
    let entry = attached.scope.entry_dir(
        cache_root,
        attach::entry_key(attached.scope.class, &attached.key),
    );
    let generation_dir = entry.join(generation);
    let bundle = bundle_of(&generation_dir).map_err(|_| Refusal::Store)?;
    let total = bundle.total().ok_or(Refusal::Store)?;
    let digest = if source.digest_at_end() {
        DIGEST_AT_END
    } else {
        stream_digest(&bundle, &generation_dir, deadline, cancel).map_err(|miss| {
            if miss == Miss::Unavailable {
                // The deadline or the cancel flag stopped the hash.
                Refusal::Aborted
            } else {
                Refusal::Store
            }
        })?
    };
    if cancel() {
        return Err(Refusal::Aborted);
    }
    let key = attach::entry_key(attached.scope.class, &attached.key);
    let upload = Upload::of(attempt, &attached.scope, key, total, digest);
    let mut reader = BundleReader {
        bundle,
        dir: generation_dir,
        part: 0,
        cur: None,
        cancel,
    };
    source.offer(&upload, deadline, &mut reader)
}

/// The canonical stream's digest for a sealed generation: the value the
/// controller must reproduce before it stores anything. Bounded by
/// `deadline` and `cancel` — an offer is optional work and never holds a
/// worker past its budget.
fn stream_digest(
    bundle: &Bundle,
    generation_dir: &Path,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<[u8; 32], Miss> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bundle.head);
    hasher.update(&bundle.manifest);
    hasher.update(&bundle.files);
    let mut buf = vec![0u8; BLOCK_BYTES];
    for entry in &bundle.entries {
        if cancel() || Instant::now() >= deadline {
            return Err(Miss::Unavailable);
        }
        let mut file =
            fs::File::open(generation_dir.join(&entry.path)).map_err(|_| Miss::Corrupt)?;
        let mut left = entry.size;
        while left > 0 {
            if cancel() || Instant::now() >= deadline {
                return Err(Miss::Unavailable);
            }
            let want = left.min(buf.len() as u64) as usize;
            let read = file.read(&mut buf[..want]).map_err(|_| Miss::Corrupt)?;
            if read == 0 {
                return Err(Miss::Corrupt);
            }
            hasher.update(&buf[..read]);
            left -= read as u64;
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// One sealed generation as its canonical stream: head, manifest bytes,
/// files bytes, then each payload file in listing order.
struct Bundle {
    head: [u8; STREAM_HEAD],
    manifest: Vec<u8>,
    files: Vec<u8>,
    entries: Vec<FileEntry>,
    /// Total payload bytes the listing promises.
    payload: u64,
}

impl Bundle {
    /// The canonical stream's length, `None` past [`MAX_BUNDLE_BYTES`].
    fn total(&self) -> Option<u64> {
        (STREAM_HEAD as u64)
            .checked_add(self.manifest.len() as u64)
            .and_then(|total| total.checked_add(self.files.len() as u64))
            .and_then(|total| total.checked_add(self.payload))
            .filter(|total| *total <= MAX_BUNDLE_BYTES)
    }
}

fn bundle_of(generation_dir: &Path) -> Result<Bundle, Miss> {
    let manifest =
        fs::read(generation_dir.join(scope::MANIFEST_NAME)).map_err(|_| Miss::Corrupt)?;
    if manifest.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Miss::Corrupt);
    }
    let files = fs::read(generation_dir.join(scope::FILES_NAME)).map_err(|_| Miss::Corrupt)?;
    if files.len() as u64 > MAX_FILES_BLOB_BYTES {
        return Err(Miss::Corrupt);
    }
    let blob = FilesBlob::decode(&files)?;
    let mut entries = blob.entries;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let payload = entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.size))
        .ok_or(Miss::Corrupt)?;
    let head = head_bytes(manifest.len() as u64, files.len() as u64, payload);
    Ok(Bundle {
        head,
        manifest,
        files,
        entries,
        payload,
    })
}

/// The stream head for three part lengths; the reserved bytes stay zero.
fn head_bytes(manifest_len: u64, files_len: u64, payload_len: u64) -> [u8; STREAM_HEAD] {
    let mut head = [0u8; STREAM_HEAD];
    head[..12].copy_from_slice(STREAM_MAGIC);
    head[12] = STREAM_FORMAT;
    head[16..24].copy_from_slice(&manifest_len.to_be_bytes());
    head[24..32].copy_from_slice(&files_len.to_be_bytes());
    head[32..40].copy_from_slice(&payload_len.to_be_bytes());
    head
}

/// The upload half of a bundle: `Read` yields the canonical stream in
/// order, bounded per call exactly like a file, straight out of the
/// bundle's own buffers and files — nothing is copied aside first. A read
/// after the offer's cancel flag tripped fails, so the transport stops.
struct BundleReader<'a> {
    bundle: Bundle,
    dir: PathBuf,
    part: usize,
    cur: Option<Cur>,
    cancel: &'a dyn Fn() -> bool,
}

enum Cur {
    /// `(part, at)`: part 0 is the head, 1 the manifest, 2 the listing.
    Mem(usize, usize),
    File(fs::File, u64),
}

impl BundleReader<'_> {
    /// Advance to the next stream part; `Ok(false)` when it is done.
    fn next_part(&mut self) -> io::Result<bool> {
        self.cur = match self.part {
            part @ 0..=2 => Some(Cur::Mem(part, 0)),
            n => match self.bundle.entries.get(n - 3) {
                Some(entry) => Some(Cur::File(
                    fs::File::open(self.dir.join(&entry.path))?,
                    entry.size,
                )),
                None => None,
            },
        };
        self.part += 1;
        Ok(self.cur.is_some())
    }

    fn mem(&self, part: usize) -> &[u8] {
        match part {
            0 => &self.bundle.head,
            1 => &self.bundle.manifest,
            _ => &self.bundle.files,
        }
    }
}

impl Read for BundleReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if (self.cancel)() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "offer canceled"));
        }
        loop {
            // `take` moves the part out so a finished one can be dropped
            // without holding a borrow of the slot it came from.
            match self.cur.take() {
                None => {
                    if !self.next_part()? {
                        return Ok(0);
                    }
                }
                Some(Cur::Mem(part, at)) => {
                    let bytes = self.mem(part);
                    if at >= bytes.len() {
                        continue;
                    }
                    let n = (bytes.len() - at).min(buf.len());
                    buf[..n].copy_from_slice(&bytes[at..at + n]);
                    self.cur = Some(Cur::Mem(part, at + n));
                    return Ok(n);
                }
                Some(Cur::File(mut file, left)) => {
                    if left == 0 {
                        continue;
                    }
                    let want = left.min(buf.len() as u64) as usize;
                    let read = file.read(&mut buf[..want])?;
                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "bundle file ended early",
                        ));
                    }
                    self.cur = Some(Cur::File(file, left - read as u64));
                    return Ok(read);
                }
            }
        }
    }
}

// ——— the controller-side store ————————————————————————————

/// The bundle id's spelling on disk: 64 lowercase hex characters.
fn hex32(id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0F) as u32, 16).expect("nibble"));
    }
    out
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = text.as_bytes()[i * 2];
        let lo = text.as_bytes()[i * 2 + 1];
        *byte = (hex_nibble(hi)? << 4) | hex_nibble(lo)?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The fields that identify one entry, exactly as both wire messages
/// spell them. Decode-and-validate in one place, so a fetch and an offer
/// can never disagree about where a bundle lives, and no field the store
/// joins into a path escapes validation.
struct Entry {
    tenant: [u8; 16],
    repo: [u8; 16],
    class: u8,
    trust: u8,
    os: u8,
    arch: u8,
    toolchain: [u8; 32],
    name: String,
    key: String,
}

impl Entry {
    fn of_need(need: &Need) -> Entry {
        Entry {
            tenant: need.tenant,
            repo: need.repo,
            class: need.class,
            trust: need.trust,
            os: need.os,
            arch: need.arch,
            toolchain: need.toolchain,
            name: need.name.clone(),
            key: need.key.clone(),
        }
    }

    fn of_upload(upload: &Upload) -> Entry {
        Entry {
            tenant: upload.tenant,
            repo: upload.repo,
            class: upload.class,
            trust: upload.trust,
            os: upload.os,
            arch: upload.arch,
            toolchain: upload.toolchain,
            name: upload.name.clone(),
            key: upload.key.clone(),
        }
    }

    /// `<root>/<repo>/<class>/<trust>/<platform>/<toolchain16>/<name>/<entry>`
    /// — the same derivation the worker used, rooted at the store. Any
    /// field this build cannot decode is `WrongScope`, never a guessed
    /// path.
    fn dir(&self, root: &Path) -> Result<PathBuf, Refusal> {
        if self.key.is_empty() || self.key.len() > attach::MAX_KEY_BYTES {
            return Err(Refusal::WrongScope);
        }
        let platform = platform_of(self.os, self.arch).ok_or(Refusal::WrongScope)?;
        let tenant = TenantId::from_bytes(self.tenant).map_err(|_| Refusal::WrongScope)?;
        let repo = RepoId::from_bytes(self.repo).map_err(|_| Refusal::WrongScope)?;
        let class = Class::from_u8(self.class).ok_or(Refusal::WrongScope)?;
        let trust = Trust::from_u8(self.trust).ok_or(Refusal::WrongScope)?;
        let scope = Scope::new(
            tenant,
            repo,
            class,
            trust,
            platform,
            self.toolchain,
            &self.name,
        )
        .map_err(|_| Refusal::WrongScope)?;
        Ok(scope.entry_dir(root, &self.key))
    }
}

/// The bundle id `current` names, or `None` for an absent, empty or
/// malformed pointer — a malformed pointer can never select a bundle.
fn read_current(entry: &Path) -> Option<[u8; 32]> {
    let raw = fs::read_to_string(entry.join(scope::CURRENT_NAME)).ok()?;
    unhex32(raw.trim())
}

/// The bundle file for an id.
fn bundle_path(entry: &Path, id: &[u8; 32]) -> PathBuf {
    entry.join(format!("{}.bundle", hex32(id)))
}

/// One fetch being served on the controller: the bundle's bytes from the
/// granted offset, with the running digest each chunk must carry.
pub struct Serving {
    file: fs::File,
    plan: Grant,
    hasher: blake3::Hasher,
    offset: u64,
}

impl Serving {
    /// Open the entry's current bundle for `need`. Reads only; the store
    /// is never created or mutated by a serve.
    pub fn open(store_root: &Path, need: &Need) -> Result<Serving, Refusal> {
        let entry = Entry::of_need(need).dir(store_root)?;
        let id = read_current(&entry).ok_or(Refusal::NoBundle)?;
        let mut file = fs::File::open(bundle_path(&entry, &id)).map_err(|_| Refusal::NoBundle)?;
        let total = file.metadata().map_err(|_| Refusal::Store)?.len();
        if total > MAX_BUNDLE_BYTES {
            return Err(Refusal::Store);
        }
        // The resume request: serve from the worker's prefix only when the
        // stored bundle really extends it; otherwise restart cold, which
        // is always correct. Proving a prefix costs a hash of it, so a
        // claimed prefix past `MAX_RESUME_HASH` is not proven at all — a
        // cold restart — and a worker's `have` can never make the
        // controller hash gigabytes per request (P08-C8).
        let requested = need.offset.min(total);
        let (offset, prefix, hasher) = if requested == 0 || requested > MAX_RESUME_HASH {
            (0, empty_digest(), blake3::Hasher::new())
        } else {
            let hasher = hash_prefix(&mut file, requested, None).map_err(|_| Refusal::Store)?;
            let prefix = *hasher.clone().finalize().as_bytes();
            if prefix == need.have {
                (requested, prefix, hasher)
            } else {
                (0, empty_digest(), blake3::Hasher::new())
            }
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| Refusal::Store)?;
        // A serve is a use: the store's budget evicts least recently served.
        crate::gc::touch(&entry);
        Ok(Serving {
            file,
            plan: Grant {
                attempt: need.attempt,
                total,
                offset,
                prefix,
                digest: id,
            },
            hasher,
            offset,
        })
    }

    /// The plan to answer the request with.
    pub fn plan(&self) -> Grant {
        self.plan
    }

    /// The next ordered chunk; `None` means the stream through
    /// `plan().digest` is complete and the caller sends the terminal
    /// [`End`].
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>, Refusal> {
        let mut chunk = Chunk {
            attempt: self.plan.attempt,
            offset: 0,
            bytes: Vec::new(),
            prefix: [0; 32],
        };
        Ok(self.next_chunk_into(&mut chunk)?.then_some(chunk))
    }

    /// [`Serving::next_chunk`] into a caller-held chunk, reusing its byte
    /// buffer — a serve loop allocates one buffer per transfer, not one
    /// per 48 KiB frame (P08-C8). `false` means the stream is complete.
    pub fn next_chunk_into(&mut self, chunk: &mut Chunk) -> Result<bool, Refusal> {
        if self.offset >= self.plan.total {
            return Ok(false);
        }
        let remaining = usize::try_from(self.plan.total - self.offset).unwrap_or(usize::MAX);
        let want = CHUNK_BYTES.min(remaining);
        chunk.bytes.resize(want, 0);
        let read = loop {
            match self.file.read(&mut chunk.bytes[..want]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other.map_err(|_| Refusal::Store)?,
            }
        };
        if read == 0 {
            // The file is shorter than the plan: a store that lost bytes
            // mid-serve must fail loudly, never end a stream short.
            return Err(Refusal::Store);
        }
        chunk.bytes.truncate(read);
        chunk.attempt = self.plan.attempt;
        chunk.offset = self.offset;
        self.hasher.update(&chunk.bytes);
        self.offset += read as u64;
        chunk.prefix = *self.hasher.clone().finalize().as_bytes();
        Ok(true)
    }
}

/// One offer being received on the controller: the staging file under the
/// entry's `writing/`, held under the entry's single-writer lock.
pub struct Receiving {
    /// The lock is held for the whole transfer; dropping it releases the
    /// entry's staging claim.
    _lock: lease::WriteLock,
    file: fs::File,
    part: PathBuf,
    entry: PathBuf,
    id: [u8; 32],
    total: u64,
    offset: u64,
    /// The running digest of every accepted byte: the stream is verified
    /// as it lands, never re-read at the end on the session's thread.
    hasher: blake3::Hasher,
    /// Promoted: the staging file is now the bundle and must survive.
    done: bool,
}

impl Drop for Receiving {
    /// An upload abandoned mid-stream — a refused chunk, a cancel, an idle
    /// or lost session — takes its staging file with it (P08-C5); the lock
    /// goes with `_lock`.
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.part);
        }
    }
}

impl Receiving {
    /// Begin receiving `upload`, or `Ok(None)` when this exact digest is
    /// already stored — the idempotent answer an offer of known content
    /// deserves. A live writer is `busy`; staging is created lazily.
    ///
    /// An upload whose digest is [`DIGEST_AT_END`] (protocol 9; the session
    /// admits it only there) names its digest in `end`: it is staged under
    /// the attempt's name and verified the same way once the digest is
    /// known. Such an offer cannot be answered "already stored" up front.
    pub fn begin(store_root: &Path, upload: &Upload) -> Result<Option<Receiving>, Refusal> {
        let entry = Entry::of_upload(upload).dir(store_root)?;
        if upload.total > MAX_BUNDLE_BYTES {
            return Err(Refusal::TooLarge);
        }
        let at_end = upload.digest == DIGEST_AT_END;
        if !at_end && bundle_path(&entry, &upload.digest).is_file() {
            return Ok(None);
        }
        // The store shares its disk with SQLite and the object store: an
        // upload that would not leave the reserve free is refused up front
        // (P08-C4), never discovered as ENOSPC halfway through.
        if let Some((free, total)) = store_space(store_root)
            && free
                < upload
                    .total
                    .saturating_add((total / 20).min(STORE_FREE_RESERVE))
        {
            return Err(Refusal::TooLarge);
        }
        let Some(lock) =
            lease::WriteLock::acquire(&entry, "remote-offer").map_err(|_| Refusal::Store)?
        else {
            return Err(Refusal::Busy);
        };
        let name = if at_end {
            let mut attempt = [0u8; 32];
            attempt[..16].copy_from_slice(&upload.attempt);
            format!("offer-{}.part", hex32(&attempt))
        } else {
            format!("{}.part", hex32(&upload.digest))
        };
        let part = entry.join(scope::WRITING_NAME).join(name);
        // A previous attempt's partial is discarded, never resumed: an
        // offer restarts from zero, so no bytes can be spliced into a
        // stream the sender did not reproduce.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part)
            .map_err(|_| Refusal::Store)?;
        Ok(Some(Receiving {
            _lock: lock,
            file,
            part,
            entry,
            id: upload.digest,
            total: upload.total,
            offset: 0,
            hasher: blake3::Hasher::new(),
            done: false,
        }))
    }

    /// The grant the sender is answered with.
    pub fn grant(&self, upload: &Upload) -> Grant {
        Grant {
            attempt: upload.attempt,
            total: self.total,
            offset: self.offset,
            prefix: empty_digest(),
            digest: self.id,
        }
    }

    /// Accept one ordered chunk. Out-of-order, oversized or overflowing
    /// chunks fail the transfer; the partial is dropped with it.
    pub fn push(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Refusal> {
        if offset != self.offset || bytes.len() > MAX_CHUNK_BYTES {
            return Err(Refusal::Store);
        }
        let next = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(Refusal::TooLarge)?;
        if next > self.total {
            return Err(Refusal::Store);
        }
        self.file.write_all(bytes).map_err(|_| Refusal::Store)?;
        self.hasher.update(bytes);
        self.offset = next;
        Ok(())
    }

    /// Verify the completed stream, promote it into the entry and make it
    /// `current`, then drop the bundle it superseded (P08-C4): an entry
    /// keeps one bundle. Until this returns `Ok`, nothing of the transfer
    /// is visible to a serve; a failed end removes the staging file.
    pub fn end(&mut self, digest: [u8; 32]) -> Result<(), Refusal> {
        if self.id == DIGEST_AT_END {
            // The offer stated its digest only now; the running hash below
            // is what proves it.
            if digest == DIGEST_AT_END {
                return Err(Refusal::Store);
            }
            self.id = digest;
        }
        if digest != self.id
            || self.offset != self.total
            || self.hasher.finalize().as_bytes() != &self.id
        {
            return Err(Refusal::Store);
        }
        self.file.sync_all().map_err(|_| Refusal::Store)?;
        let previous = read_current(&self.entry).filter(|id| *id != self.id);
        fs::rename(&self.part, bundle_path(&self.entry, &self.id)).map_err(|_| Refusal::Store)?;
        self.done = true;
        publish::sync_dir(&self.entry).map_err(|_| Refusal::Store)?;
        let tmp = self.entry.join(publish::CURRENT_TMP);
        publish::write_synced(&tmp, hex32(&self.id).as_bytes()).map_err(|_| Refusal::Store)?;
        fs::rename(&tmp, self.entry.join(scope::CURRENT_NAME)).map_err(|_| Refusal::Store)?;
        publish::sync_dir(&self.entry).map_err(|_| Refusal::Store)?;
        // Unlinking is safe for a serve already reading it: an open file
        // outlives its name on unix.
        if let Some(previous) = previous {
            let _ = fs::remove_file(bundle_path(&self.entry, &previous));
        }
        Ok(())
    }
}

/// `(free, total)` bytes of the store's filesystem; `None` where the
/// platform cannot say (the admission check is then skipped).
fn store_space(root: &Path) -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let st = rustix::fs::statvfs(root).ok()?;
        Some((
            st.f_bavail.saturating_mul(st.f_frsize),
            st.f_blocks.saturating_mul(st.f_frsize),
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        None
    }
}

/// What one [`sweep_store`] pass did to the controller's store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSweep {
    /// Entry directories visited.
    pub entries: u64,
    /// Bytes of the `current` bundles kept, after the pass.
    pub bytes: u64,
    /// Superseded (non-`current`) bundles removed.
    pub bundles_removed: u64,
    /// Abandoned upload staging files removed.
    pub parts_removed: u64,
    /// Whole entries evicted under the budget, least recently served first.
    pub entries_evicted: u64,
    pub bytes_freed: u64,
    pub errors: u64,
}

/// One reclamation pass over the controller's remote-cache store (P08-C4):
/// an entry keeps only its `current` bundle, upload staging older than
/// [`STALE_UPLOAD`] goes, and while the kept bundles exceed
/// `budget_bytes` whole entries are evicted least recently served first
/// (`current`'s mtime — every serve touches it). An entry whose upload is
/// live (its `writing/.lock`) is never touched. `max_entries` bounds the
/// walk.
pub fn sweep_store(root: &Path, budget_bytes: u64, max_entries: u64, now_ms: i64) -> StoreSweep {
    let mut out = StoreSweep::default();
    let mut kept: Vec<(i64, u64, PathBuf)> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        if out.entries >= max_entries {
            break;
        }
        if depth == 7 {
            out.entries += 1;
            if lease::writing_lock_live(&dir, now_ms) {
                continue;
            }
            if let Some(entry) = sweep_entry(&dir, now_ms, &mut out) {
                kept.push(entry);
            }
            continue;
        }
        let Ok(children) = fs::read_dir(&dir) else {
            continue;
        };
        for child in children.flatten() {
            if child.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push((child.path(), depth + 1));
            }
        }
    }
    let mut total: u64 = kept.iter().map(|(_, bytes, _)| bytes).sum();
    if total > budget_bytes {
        kept.sort_unstable_by_key(|(used, _, _)| *used);
        for (_, bytes, entry) in kept {
            if total <= budget_bytes {
                break;
            }
            if lease::writing_lock_live(&entry, now_ms) {
                continue;
            }
            match fs::remove_dir_all(&entry) {
                Ok(()) => {
                    out.entries_evicted += 1;
                    out.bytes_freed += bytes;
                    total -= bytes;
                }
                Err(_) => out.errors += 1,
            }
        }
    }
    out.bytes = total;
    out
}

/// One store entry: stale staging and superseded bundles go; returns the
/// entry's last use, `current` bundle size and path when it still serves.
fn sweep_entry(entry: &Path, now_ms: i64, out: &mut StoreSweep) -> Option<(i64, u64, PathBuf)> {
    let stale_ms = STALE_UPLOAD.as_millis() as i64;
    let mtime_ms = |m: &fs::Metadata| {
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as i64)
    };
    if let Ok(parts) = fs::read_dir(entry.join(scope::WRITING_NAME)) {
        for part in parts.flatten() {
            let name = part.file_name();
            let is_part = name.to_str().is_some_and(|n| n.ends_with(".part"));
            if is_part
                && part
                    .metadata()
                    .is_ok_and(|m| mtime_ms(&m) + stale_ms <= now_ms)
            {
                match fs::remove_file(part.path()) {
                    Ok(()) => out.parts_removed += 1,
                    Err(_) => out.errors += 1,
                }
            }
        }
    }
    let current = read_current(entry);
    let mut kept = None;
    for child in fs::read_dir(entry).ok()?.flatten() {
        let name = child.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".bundle"))
            .and_then(unhex32)
        else {
            continue;
        };
        let Ok(meta) = child.metadata() else {
            continue;
        };
        if Some(id) == current {
            kept = Some(meta.len());
            continue;
        }
        match fs::remove_file(child.path()) {
            Ok(()) => {
                out.bundles_removed += 1;
                out.bytes_freed += meta.len();
            }
            Err(_) => out.errors += 1,
        }
    }
    let used = fs::metadata(entry.join(scope::CURRENT_NAME))
        .map(|m| mtime_ms(&m))
        .unwrap_or(0);
    match kept {
        Some(bytes) => Some((used, bytes, entry.to_path_buf())),
        None => {
            // Nothing serves from here: an empty shell goes.
            let _ = fs::remove_dir_all(entry);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_codes_round_trip_and_nothing_new_decodes() {
        for code in [1u8, 2, 3, 4, 5, 6, 7] {
            let refusal = Refusal::from_code(code).unwrap();
            assert_eq!(refusal.code(), code);
        }
        for code in [0u8, 8, 255] {
            assert!(Refusal::from_code(code).is_none());
        }
    }

    #[test]
    fn stream_head_is_big_endian_and_zero_reserved() {
        let head = head_bytes(1, 2, 3);
        assert_eq!(&head[..12], STREAM_MAGIC);
        assert_eq!(head[12], STREAM_FORMAT);
        assert_eq!(&head[13..16], &[0, 0, 0]);
        assert_eq!(u64_at(&head, 16), 1);
        assert_eq!(u64_at(&head, 24), 2);
        assert_eq!(u64_at(&head, 32), 3);
    }

    #[test]
    fn bundle_ids_round_trip_through_hex() {
        let id = *blake3::hash(b"bundle").as_bytes();
        assert_eq!(unhex32(&hex32(&id)), Some(id));
        assert!(unhex32("nope").is_none());
        assert!(unhex32(&"z".repeat(64)).is_none());
    }
}
