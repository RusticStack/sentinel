//! K03 — the write path: what a finished attempt leaves behind. One
//! writer per entry stages the job's private views under
//! `<entry>/writing/gen-*`, seals the generation with its manifest, then
//! promotes it by same-directory rename and swaps `current` atomically —
//! a reader never sees a half-built generation, and a canceled or crashed
//! writer never publishes a partial one.
//!
//! Trust scope is authorization: a publish writes only into the
//! attachment's own scope directory, and `commit` refuses an attachment
//! whose scope trust is not the job's. There is no cross-trust promotion
//! — an untrusted publish can only ever produce entries of its own class.
//!
//! The job's views are read confined (`confined`): every declared target
//! is resolved beneath the worker-owned workspace anchor without following
//! a symlink at any component, and every file is reopened by descriptor
//! with `O_NOFOLLOW` — a job cannot redirect publication at host files by
//! planting or racing a link (P07-1). An entry whose restore was refused
//! (`invalid`) or whose key never rendered publishes nothing.
//!
//! Publication is bounded in bytes as well as files: a generation over
//! [`MAX_GENERATION_BYTES`] of logical payload is refused before a byte is
//! staged, a filesystem without room for the copy plus a reserve is
//! refused the same way, and a sparse file is copied hole-for-hole so a
//! mostly-empty file never amplifies into dense writes (P07-5).
//!
//! Incremental reuse rides the source generation the job cloned from: a
//! file whose digest matches the source's listing is staged by hardlink
//! (one inode, no copy) and re-verified before seal, so a corrupted
//! generation can never poison the next one.

use std::{
    collections::HashMap,
    fs,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sentinel_core::UnixMillis;
use sentinel_pipeline::schema::valid_relative_path;
use sentinel_protocol::cache::Trust;

use crate::{
    attach::{Attached, Target, entry_key},
    confined::{Base, Kind, Meta, Node},
    lease::{Lease, LeaseError, WriteLock, rand_u32},
    manifest::{
        FileEntry, FilesBlob, MAX_FILE_ENTRIES, MAX_FILES_BLOB_BYTES, Manifest, read_files,
    },
    outcome::{Miss, Outcome},
    scope,
};

/// The deadline finalization gives the whole publish batch
/// (docs/cache.md). The verdict's outcome never depends on it; its report
/// waits for it, so the bound is minutes, not the job's own budget.
pub const CACHE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// The most logical payload one generation may carry: a quarter of the
/// store's byte budget (`gc::DEFAULT_BUDGET_BYTES`). Checked against the
/// planned sizes before anything is staged, so neither an honest cache
/// far over budget nor a sparse file claiming terabytes can drive the
/// worker's disk (P07-5).
pub const MAX_GENERATION_BYTES: u64 = crate::gc::DEFAULT_BUDGET_BYTES / 4;

/// Free space a publish always leaves on the store's filesystem beyond
/// what its copy needs — 5 % of the filesystem, at most this much:
/// concurrent attempts, log spools and mirrors share the disk.
pub const FREE_SPACE_RESERVE: u64 = 1 << 30;

/// Cancel and deadline are polled every this many walked or staged files.
const CHECK_EVERY: u32 = 256;
/// The deepest a payload walk descends — the `hash_files` traversal bound,
/// so publish never wanders deeper than the resolver would have hashed.
/// `pub(crate)` for restore: a sealed generation can never hold a tree
/// deeper than a writer could stage, so the read side shares the bound.
pub(crate) const MAX_WALK_DEPTH: usize = 64;
/// Stream block for hashing and copying; hashing rides the copy pass. One
/// buffer per commit, allocated on first use.
const COPY_BYTES: usize = 1 << 20;
/// Copied files whose durability is settled one by one; past this many a
/// commit flushes the store's filesystem once instead (`syncfs`), so a
/// 100k-file generation pays one barrier, not 100k.
const SYNC_FDS: usize = 64;
/// Staging for the `current` swap: `current.tmp` then a rename.
/// `pub(crate)` for the remote path: a hydrated generation is promoted by
/// the same two renames a publication uses.
pub(crate) const CURRENT_TMP: &str = "current.tmp";

/// What a commit did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    /// A new generation was sealed and is now `current`.
    Sealed {
        /// The `gen-*` directory name under the entry.
        generation: String,
        /// Files the sealed `files` blob lists.
        files: u32,
        /// Total payload bytes listed.
        bytes: u64,
        /// Of `bytes`, how much was staged from the source generation
        /// (hardlinked and verified) instead of copied from the job.
        reused_bytes: u64,
        /// Entries the walk saw but did not stage: non-regular files,
        /// symlinks, unencodable paths, files that vanished mid-publish.
        skipped: u64,
    },
    /// Nothing was committed; the reason is stable vocabulary for logs.
    Skipped(SkipReason),
}

/// Why a commit published nothing. Not an error: the job already ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Another writer holds the entry's staging lock.
    Busy,
    /// The attempt's cancel flag or the publish deadline stopped it.
    Canceled,
    /// Every declared path produced zero files — nothing worth keeping.
    Empty,
    /// The staged listing is identical to the source generation's — the
    /// bytes are already published under an older generation.
    Unchanged,
    /// Restore refused the entry (`invalid`: a declared path that cannot
    /// serve, or a key that never rendered) — nothing it left behind is
    /// worth sealing, and a refused path is never walked.
    Refused,
}

impl SkipReason {
    /// The stable lowercase spelling for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Canceled => "canceled",
            Self::Empty => "empty",
            Self::Unchanged => "unchanged",
            Self::Refused => "refused",
        }
    }
}

/// Every failure mode of a commit. Nothing panics; a failed publish is a
/// diagnostic, never a build failure.
#[derive(Debug)]
pub enum PublishError {
    /// The attachment's scope trust is not the job's — refused before a
    /// single directory was made. There is no cross-trust promotion.
    TrustMismatch,
    /// The caller's deadline passed mid-commit; staging was removed.
    TimedOut,
    /// The generation would exceed the `files` blob's bounds or
    /// [`MAX_GENERATION_BYTES`]; refused before staging.
    TooLarge,
    /// The store's filesystem has no room for the copy plus
    /// [`FREE_SPACE_RESERVE`]; refused before staging.
    NoSpace,
    /// The staging lock could not be taken for a reason other than a live
    /// writer (which is `Skipped(Busy)` instead).
    Lock(LeaseError),
    Io(std::io::Error),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustMismatch => f.write_str("scope trust is not the job's"),
            Self::TimedOut => f.write_str("publish exceeded its deadline"),
            Self::TooLarge => f.write_str("generation exceeds the publish bounds"),
            Self::NoSpace => f.write_str("not enough free space for the generation"),
            Self::Lock(e) => write!(f, "write lock: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for PublishError {}
impl From<std::io::Error> for PublishError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<LeaseError> for PublishError {
    fn from(e: LeaseError) -> Self {
        Self::Lock(e)
    }
}

/// How a stage stops short: cancellation is a `Skipped` answer, anything
/// else a typed error. Either way the caller drops the staging dir, so a
/// stopped writer never publishes a partial generation.
enum Stop {
    Canceled,
    Failed(PublishError),
}
impl From<std::io::Error> for Stop {
    fn from(e: std::io::Error) -> Self {
        Self::Failed(e.into())
    }
}
impl From<PublishError> for Stop {
    fn from(e: PublishError) -> Self {
        Self::Failed(e)
    }
}

/// Commit one attached cache: stage the job's writable views as a sealed
/// generation under the entry's scope and make it `current`. `trust` is
/// the job's own — the publish is authorized only where the scope agrees.
/// `deadline` and `cancel` bound the work; both are checked before
/// staging and every `CHECK_EVERY` files inside it.
///
/// The caller is expected to hold `attached.lease`: it pins the source
/// generation the reuse path reads. Without one, a concurrent sweep can
/// still only ever remove a generation that is neither `current` nor the
/// newest spare — the freshly promoted generation is the newest by name,
/// so the swap below cannot lose it.
pub fn commit(
    cache_root: &Path,
    attached: &Attached,
    trust: Trust,
    now: UnixMillis,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<Published, PublishError> {
    if attached.scope.trust != trust {
        return Err(PublishError::TrustMismatch);
    }
    // What restore refused is never walked: a declared path that could not
    // be resolved safely, or a key that never rendered (an entry named for
    // `""` could never serve — `Manifest::validate` refuses an empty key).
    if attached.key.is_empty() || attached.outcome == Outcome::Miss(Miss::Invalid) {
        return Ok(Published::Skipped(SkipReason::Refused));
    }
    if cancel() || Instant::now() >= deadline {
        return Ok(Published::Skipped(SkipReason::Canceled));
    }
    // The same derivation restore uses — publish and restore must name
    // the same entry or the two never meet.
    let entry = attached
        .scope
        .entry_dir(cache_root, entry_key(attached.scope.class, &attached.key));
    // One writer per entry: `create_new` never waits — a live marker is
    // `Busy`, and a marker older than the lease bound is a dead writer's,
    // reaped in place so a crash can never wedge the entry.
    // The commit pins its entry like a reader does: reclamation never takes
    // an entry — its source generation included — out from under a writer,
    // hit or miss.
    let _pin = Lease::acquire(&entry, "publish", crate::lease::DEFAULT_TTL)?;
    let Some(_lock) = WriteLock::acquire(&entry, "publish")? else {
        return Ok(Published::Skipped(SkipReason::Busy));
    };
    let generation = scope::gen_name(now.0, rand_u32());
    let staging = entry.join(scope::WRITING_NAME).join(&generation);
    let out = match stage(
        &entry,
        &staging,
        attached,
        &generation,
        now,
        deadline,
        cancel,
    ) {
        Ok(done) => Ok(done),
        Err(Stop::Canceled) => Ok(Published::Skipped(SkipReason::Canceled)),
        Err(Stop::Failed(e)) => Err(e),
    };
    if !matches!(out, Ok(Published::Sealed { .. })) {
        // A skipped or failed commit leaves no half-built generation:
        // promotion never ran, and whatever was staged is removed now
        // rather than left for a stale-`writing/` pass.
        let _ = fs::remove_dir_all(&staging);
    }
    out
}

/// One file seen in a target, decided but not yet staged.
struct Planned {
    /// Which confined base the file is reopened beneath (`Plan::bases`).
    base: usize,
    /// The file's path beneath that base, `/`-separated.
    rel: String,
    /// The `payload/<i>/<rel>` path — both the `files` entry name and the
    /// path inside the generation.
    entry: String,
    size: u64,
    mode: u32,
    /// Holes carry most of the file: copy it hole-for-hole.
    sparse: bool,
    /// The job file's digest, computed only when the source generation
    /// lists this path at the same size — the reuse proof, `Some` only
    /// then. The staged copy carries its own digest either way.
    digest: Option<[u8; 32]>,
}

/// What the plan stage accumulates.
struct Plan<'a> {
    /// `payload/…` → the source generation's listing entry.
    listed: HashMap<&'a str, &'a FileEntry>,
    planned: Vec<Planned>,
    /// The confined directories planned files are reopened beneath: one
    /// per directory target, or the workspace anchor for a file target.
    bases: Vec<Base>,
    /// Logical payload bytes planned so far — the [`MAX_GENERATION_BYTES`]
    /// bound.
    bytes: u64,
    /// Non-regular, unencodable or vanished entries, for diagnostics.
    skipped: u64,
    /// Walked or staged files since the last cancel/deadline poll.
    since_check: u32,
    /// Every planned file already matches the source listing.
    unchanged: bool,
    /// The one copy/hash block this commit uses, allocated on first use.
    buf: Vec<u8>,
}

impl Plan<'_> {
    /// The periodic guard: cancel before the deadline, so a canceled
    /// writer is a `Skipped(Canceled)` even when it also ran out of time.
    fn check(&self, deadline: Instant, cancel: &dyn Fn() -> bool) -> Result<(), Stop> {
        if cancel() {
            return Err(Stop::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(Stop::Failed(PublishError::TimedOut));
        }
        Ok(())
    }

    fn tick(&mut self, deadline: Instant, cancel: &dyn Fn() -> bool) -> Result<(), Stop> {
        self.since_check += 1;
        if self.since_check >= CHECK_EVERY {
            self.since_check = 0;
            self.check(deadline, cancel)?;
        }
        Ok(())
    }

    fn buf(&mut self) -> &mut [u8] {
        if self.buf.len() < COPY_BYTES {
            self.buf.resize(COPY_BYTES, 0);
        }
        &mut self.buf
    }

    /// Bytes the copy will actually write: everything not provably
    /// reusable from the source generation.
    fn copy_bytes(&self) -> u64 {
        self.planned
            .iter()
            .filter(|p| {
                !matches!(
                    (p.digest, self.listed.get(p.entry.as_str())),
                    (Some(d), Some(l)) if l.digest == d && l.mode == p.mode
                )
            })
            .map(|p| p.size)
            .sum()
    }
}

/// Walk the targets, then — when anything differs — stage, seal and
/// promote. Split in two so an unchanged publish never writes a byte and
/// a canceled plan leaves nothing on disk at all.
fn stage(
    entry: &Path,
    staging: &Path,
    attached: &Attached,
    generation: &str,
    now: UnixMillis,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<Published, Stop> {
    // The generation this job's view was cloned from, if its listing can
    // still be read — the reuse source. A missing or corrupt one simply
    // means no reuse.
    let source = attached
        .generation
        .as_deref()
        .filter(|name| {
            // Defensive: a generation name is a single safe component —
            // anything else is ignored rather than joined into a lookup.
            name.starts_with("gen-") && !name.contains(['/', '\\']) && !name.contains("..")
        })
        .and_then(|name| {
            let dir = entry.join(name);
            read_files(&dir).ok().map(|blob| (dir, blob))
        });
    let listed: HashMap<&str, &FileEntry> = source
        .as_ref()
        .map(|(_, blob)| blob.entries.iter().map(|e| (e.path.as_str(), e)).collect())
        .unwrap_or_default();
    let mut plan = Plan {
        listed,
        planned: Vec::new(),
        bases: Vec::with_capacity(attached.targets.len()),
        bytes: 0,
        skipped: 0,
        since_check: 0,
        unchanged: true,
        buf: Vec::new(),
    };
    for (index, target) in attached.targets.iter().enumerate() {
        plan_target(&mut plan, index, target, deadline, cancel)?;
    }
    if plan.planned.is_empty() {
        return Ok(Published::Skipped(SkipReason::Empty));
    }
    // Cheapest correct skip: when every planned file already exists in the
    // source generation's listing — same path, size, digest and mode, and
    // the listing has no extras — the bytes are published already and a
    // new generation would differ only in its seal time.
    if plan.unchanged
        && let Some((_, blob)) = &source
        && blob.entries.len() == plan.planned.len()
    {
        return Ok(Published::Skipped(SkipReason::Unchanged));
    }
    plan.check(deadline, cancel)?;
    // Room for what will be copied, plus the reserve every other user of
    // the disk keeps — checked before a byte lands, never discovered by an
    // ENOSPC halfway through.
    if let Some((free, total)) = free_bytes(entry)
        && free < plan.copy_bytes().saturating_add(reserve(total))
    {
        return Err(PublishError::NoSpace.into());
    }
    fs::create_dir_all(staging)?;
    let (entries, bytes, reused_bytes) = materialize(
        &mut plan,
        staging,
        source.as_ref().map(|(dir, _)| dir.as_path()),
        deadline,
        cancel,
    )?;
    if entries.is_empty() {
        // Everything vanished between plan and stage — as empty as if the
        // targets had never produced a file.
        return Ok(Published::Skipped(SkipReason::Empty));
    }
    // Writers sort by path so reads and the manifest digest are stable.
    let mut blob = FilesBlob { entries };
    blob.entries.sort_by(|a, b| a.path.cmp(&b.path));
    let encoded = blob.encode();
    if encoded.len() as u64 > MAX_FILES_BLOB_BYTES {
        return Err(PublishError::TooLarge.into());
    }
    write_synced(&staging.join(scope::FILES_NAME), &encoded)?;
    let mut manifest = Manifest::writing(&attached.scope, &attached.key, attached.compat.clone());
    manifest.bytes = bytes;
    manifest.files = entries_len(&blob)?;
    manifest.files_digest = *blake3::hash(&encoded).as_bytes();
    manifest.seal(now);
    write_synced(&staging.join(scope::MANIFEST_NAME), &manifest.encode())?;
    sync_dir(staging)?;
    // Promotion: the sealed generation lands inside the entry first and
    // is durable; only then does `current` learn its name. A reader that
    // resolves `current` sees either the old generation or this one —
    // never a directory still being written.
    fs::rename(staging, entry.join(generation))?;
    sync_dir(entry)?;
    let tmp = entry.join(CURRENT_TMP);
    write_synced(&tmp, generation.as_bytes())?;
    fs::rename(&tmp, entry.join(scope::CURRENT_NAME))?;
    sync_dir(entry)?;
    Ok(Published::Sealed {
        generation: generation.to_owned(),
        files: manifest.files,
        bytes,
        reused_bytes,
        skipped: plan.skipped,
    })
}

/// `rel`'s components joined by `/` — the form a confined reopen takes.
fn slash_path(rel: &Path) -> Option<String> {
    let mut out = String::new();
    for comp in rel.iter() {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(comp.to_str()?);
    }
    (!out.is_empty()).then_some(out)
}

/// Walk one declared path into the plan, confined beneath the target's
/// anchor. A missing target contributes nothing; a target that is — or
/// sits beneath — a symlink or special entry is skipped, never followed.
fn plan_target(
    plan: &mut Plan<'_>,
    index: usize,
    target: &Target,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<(), Stop> {
    let prefix = format!("payload/{index}");
    let Some(rel) = target
        .dir
        .strip_prefix(&target.root)
        .ok()
        .and_then(slash_path)
    else {
        // A target that is not strictly beneath its anchor has no confined
        // form; it is never read.
        plan.skipped += 1;
        return Ok(());
    };
    let anchor = match Base::anchor(&target.root) {
        Ok(anchor) => anchor,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    match anchor.resolve(Path::new(&rel))? {
        // A path the job never made contributes no files.
        Node::Missing => Ok(()),
        Node::Dir(dir) => {
            let base = plan.bases.len();
            let mut walked = String::new();
            let out = plan.walk(&dir, base, &prefix, &mut walked, 0, deadline, cancel);
            plan.bases.push(dir);
            out
        }
        Node::File(meta) => {
            // A declared path that is itself a file stages as `payload/<i>`,
            // reopened beneath the anchor by its own relative path.
            let base = plan.bases.len();
            let out = plan.plan_file(
                base,
                rel.clone(),
                prefix,
                meta,
                || anchor.open(&rel),
                deadline,
                cancel,
            );
            plan.bases.push(anchor);
            out
        }
        Node::Other => {
            plan.skipped += 1;
            Ok(())
        }
    }
}

impl Plan<'_> {
    /// Recursive walk of one target directory, descriptor by descriptor;
    /// depth is capped and every entry is classified without following.
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        dir: &Base,
        base: usize,
        prefix: &str,
        rel: &mut String,
        depth: usize,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<(), Stop> {
        if depth >= MAX_WALK_DEPTH {
            self.skipped += 1;
            return Ok(());
        }
        // Sorted by the listing so the sealed digest never depends on
        // filesystem order.
        let children = dir.entries()?;
        for (name, kind) in children {
            self.tick(deadline, cancel)?;
            let Some(text) = name.to_str() else {
                // Names the `files` blob can never encode are skipped,
                // never mangled.
                self.skipped += 1;
                continue;
            };
            let saved = rel.len();
            if !rel.is_empty() {
                rel.push('/');
            }
            rel.push_str(text);
            let out = match kind {
                Kind::Dir => match dir.dir(&name)? {
                    Some(child) => {
                        self.walk(&child, base, prefix, rel, depth + 1, deadline, cancel)
                    }
                    // Replaced since the listing: not followed, counted.
                    None => {
                        self.skipped += 1;
                        Ok(())
                    }
                },
                Kind::File => match dir.stat(&name)? {
                    Some(meta) => {
                        let entry = format!("{prefix}/{rel}");
                        self.plan_file(
                            base,
                            rel.clone(),
                            entry,
                            meta,
                            || dir.open_child(&name),
                            deadline,
                            cancel,
                        )
                    }
                    None => {
                        self.skipped += 1;
                        Ok(())
                    }
                },
                // Symlinks and special files are never followed and never
                // encoded: counted, then passed over.
                Kind::Other => {
                    self.skipped += 1;
                    Ok(())
                }
            };
            rel.truncate(saved);
            out?;
        }
        Ok(())
    }

    /// Decide one file's place in the listing: hash it only when the
    /// source generation lists the same path at the same size — the
    /// digest is the reuse proof and the unchanged check at once.
    #[allow(clippy::too_many_arguments)]
    fn plan_file(
        &mut self,
        base: usize,
        rel: String,
        entry: String,
        meta: Meta,
        open: impl FnOnce() -> std::io::Result<Option<(fs::File, Meta)>>,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<(), Stop> {
        if self.planned.len() as u32 >= MAX_FILE_ENTRIES {
            return Err(PublishError::TooLarge.into());
        }
        if !valid_relative_path(&entry) {
            self.skipped += 1;
            return Ok(());
        }
        let size = meta.size;
        self.bytes = self.bytes.saturating_add(size);
        if self.bytes > MAX_GENERATION_BYTES {
            return Err(PublishError::TooLarge.into());
        }
        let mode = meta.mode;
        let listed_size = self.listed.get(entry.as_str()).map(|l| l.size);
        let digest = match listed_size {
            Some(listed) if listed == size => match open()? {
                Some((mut file, opened)) if opened.size == size => {
                    Some(hash_reader(&mut file, size, self.buf())?)
                }
                // Vanished or changed shape since the listing.
                _ => {
                    self.skipped += 1;
                    return Ok(());
                }
            },
            _ => None,
        };
        // The unchanged check compares the full entry: a mode change with
        // identical content is still a change worth republishing.
        let same = match (self.listed.get(entry.as_str()), digest) {
            (Some(listed), Some(digest)) => listed.digest == digest && listed.mode == mode,
            _ => false,
        };
        if !same {
            self.unchanged = false;
        }
        self.planned.push(Planned {
            base,
            rel,
            entry,
            size,
            mode,
            sparse: meta.sparse(),
            digest,
        });
        self.tick(deadline, cancel)
    }
}

/// Settles the durability of the files a commit copied before its listing
/// and manifest are written: up to [`SYNC_FDS`] copies are `fdatasync`ed
/// individually; past that one `syncfs` of the store covers them all.
struct Durability {
    pending: Vec<fs::File>,
    whole_fs: bool,
}

impl Durability {
    fn staged(&mut self, file: fs::File) -> std::io::Result<()> {
        if cfg!(not(target_os = "linux")) {
            // No `syncfs` to fall back on: settle each file now.
            return file.sync_data();
        }
        if self.whole_fs {
            return Ok(());
        }
        if self.pending.len() < SYNC_FDS {
            self.pending.push(file);
        } else {
            self.pending.clear();
            self.whole_fs = true;
        }
        Ok(())
    }

    fn settle(self, staging: &Path) -> std::io::Result<()> {
        if self.whole_fs {
            #[cfg(target_os = "linux")]
            rustix::fs::syncfs(fs::File::open(staging)?)?;
            #[cfg(not(target_os = "linux"))]
            let _ = staging;
            return Ok(());
        }
        for file in self.pending {
            file.sync_data()?;
        }
        Ok(())
    }
}

/// Stage every planned file and return its `files` entries with the
/// payload totals. A file listed by the source generation with the same
/// digest and mode is hardlinked out of that generation — one inode, no
/// copy — then re-verified: the staged name is hashed and must match, or
/// the link is dropped and the job's own bytes are copied. A generation
/// whose content drifted can never poison its successor.
fn materialize(
    plan: &mut Plan<'_>,
    staging: &Path,
    source_dir: Option<&Path>,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<(Vec<FileEntry>, u64, u64), Stop> {
    let planned = std::mem::take(&mut plan.planned);
    let mut entries = Vec::with_capacity(planned.len());
    let mut bytes = 0u64;
    let mut reused = 0u64;
    let mut durability = Durability {
        pending: Vec::new(),
        whole_fs: false,
    };
    // Planned files arrive in walk order, so siblings share a parent: the
    // directory is created once per run of them, not once per file.
    let mut made: Option<PathBuf> = None;
    for planned in planned {
        plan.tick(deadline, cancel)?;
        let dst = staging.join(&planned.entry);
        if let Some(parent) = dst.parent()
            && made.as_deref() != Some(parent)
        {
            fs::create_dir_all(parent)?;
            made = Some(parent.to_path_buf());
        }
        let listed = plan.listed.get(planned.entry.as_str()).copied();
        let mut staged: Option<([u8; 32], u64, u32)> = None;
        if let (Some(source_dir), Some(proof), Some(listed)) = (source_dir, planned.digest, listed)
            && proof == listed.digest
            && listed.mode == planned.mode
            && fs::hard_link(source_dir.join(&listed.path), &dst).is_ok()
        {
            // The staged name shares the source's inode, so hashing it
            // verifies the generation's own bytes. A drifted generation
            // fails the check and the job's file is copied instead —
            // after the link is removed, so the copy never truncates the
            // source's inode.
            let verified = fs::File::open(&dst)
                .and_then(|mut f| hash_reader(&mut f, planned.size, plan.buf()));
            match verified {
                Ok(digest) if digest == proof => {
                    staged = Some((proof, planned.size, planned.mode));
                    reused += planned.size;
                }
                _ => {
                    let _ = fs::remove_file(&dst);
                }
            }
        }
        let (digest, size, mode) = match staged {
            Some(staged) => staged,
            // Size, digest and mode recorded are always of the bytes
            // actually staged from the descriptor actually opened: a file
            // rewritten mid-publish can never produce a listing its
            // generation does not satisfy, and a file swapped for a
            // symlink is never opened at all.
            None => match plan.bases[planned.base].open(&planned.rel)? {
                Some((file, opened)) => {
                    let sparse = planned.sparse || opened.sparse();
                    let (digest, written, out) =
                        copy_hashed(file, &dst, planned.size, sparse, plan.buf())?;
                    // The payload file carries the recorded mode: restore
                    // re-applies the staged file's own permission bits
                    // (clone::file). Hardlinked entries share the source
                    // generation's inode, which already carries it.
                    stamp_file_mode(&out, opened.mode)?;
                    durability.staged(out)?;
                    (digest, written, opened.mode)
                }
                None => {
                    plan.skipped += 1;
                    continue;
                }
            },
        };
        bytes += size;
        entries.push(FileEntry {
            path: planned.entry,
            size,
            digest,
            mode,
        });
    }
    durability.settle(staging)?;
    Ok((entries, bytes, reused))
}

/// BLAKE3 of at most `limit` bytes of `reader`, through the caller's block.
fn hash_reader(reader: &mut impl Read, limit: u64, buf: &mut [u8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut left = limit;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let read = match reader.read(&mut buf[..want]) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            other => other?,
        };
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        left -= read as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Copy at most `limit` bytes of `input` to a new file at `to`, hashing
/// them as they land; returns the digest and length of exactly what was
/// staged, and the open output for the durability pass. A sparse input is
/// copied hole-for-hole: an all-zero block becomes a seek, never a write.
fn copy_hashed(
    input: fs::File,
    to: &Path,
    limit: u64,
    sparse: bool,
    buf: &mut [u8],
) -> std::io::Result<([u8; 32], u64, fs::File)> {
    let mut input = input.take(limit);
    let mut output = fs::File::create(to)?;
    let mut hasher = blake3::Hasher::new();
    let mut written = 0u64;
    loop {
        let read = match input.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            other => other?,
        };
        if read == 0 {
            break;
        }
        let block = &buf[..read];
        hasher.update(block);
        if sparse && block.iter().all(|b| *b == 0) {
            output.seek(SeekFrom::Current(read as i64))?;
        } else {
            output.write_all(block)?;
        }
        written += read as u64;
    }
    if sparse {
        // A trailing hole is a length, not bytes.
        output.set_len(written)?;
    }
    Ok((*hasher.finalize().as_bytes(), written, output))
}

/// What a publish leaves free on a filesystem of `total` bytes: 5 % of
/// it, at most [`FREE_SPACE_RESERVE`].
fn reserve(total: u64) -> u64 {
    (total / 20).min(FREE_SPACE_RESERVE)
}

/// `(free, total)` bytes of `path`'s filesystem, free as an unprivileged
/// writer sees it; `None` where the platform cannot say (the check is
/// then skipped).
fn free_bytes(path: &Path) -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let st = rustix::fs::statvfs(path).ok()?;
        Some((
            st.f_bavail.saturating_mul(st.f_frsize),
            st.f_blocks.saturating_mul(st.f_frsize),
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

/// Write a small file durably enough to be renamed over: contents are
/// flushed to the device before the caller links the name into place.
/// `pub(crate)` for the remote path's `current` swap.
pub(crate) fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_data()
}

/// fsync a directory so a rename inside it is durable. No-op off unix —
/// directory fsync is not part of the portable surface (the same reading
/// the object store makes). `pub(crate)` for the remote path.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Stamp a staged payload file with the mode the manifest records for it,
/// minus the bits restore never applies (clone::mode_of keeps 0o777).
/// No-op off unix, where mode is not tracked. `pub(crate)` for the remote
/// path's staged payload.
pub(crate) fn stamp_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// [`stamp_mode`] on an open file: no second path lookup.
fn stamp_file_mode(file: &fs::File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
        Ok(())
    }
}

/// The permission bits worth keeping — the exec bit on tools. Off unix a
/// read-only file reads as `0o444`, anything else `0o644`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) fn file_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        if meta.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

fn entries_len(blob: &FilesBlob) -> Result<u32, PublishError> {
    u32::try_from(blob.entries.len()).map_err(|_| PublishError::TooLarge)
}
