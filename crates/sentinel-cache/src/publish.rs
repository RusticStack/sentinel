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
//! in v1 — a pull-request publish can only ever produce `pull_request`
//! entries.
//!
//! Incremental reuse rides the source generation the job cloned from: a
//! file whose digest matches the source's listing is staged by hardlink
//! (one inode, no copy) and re-verified before seal, so a corrupted
//! generation can never poison the next one.

use std::{
    collections::HashMap,
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sentinel_core::UnixMillis;
use sentinel_pipeline::schema::valid_relative_path;
use sentinel_protocol::cache::Trust;

use crate::{
    attach::{Attached, entry_key},
    lease::{LeaseError, WriteLock, rand_u32},
    manifest::{
        FileEntry, FilesBlob, MAX_FILE_ENTRIES, MAX_FILES_BLOB_BYTES, Manifest, read_files,
    },
    scope,
};

/// The deadline finalization gives the whole publish batch
/// (docs/cache.md). Publication is off the required path: a job's verdict
/// never waits on its cache, so the bound is minutes, not the job's own
/// budget.
pub const CACHE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// Cancel and deadline are polled every this many walked or staged files.
const CHECK_EVERY: u32 = 256;
/// The deepest a payload walk descends — the `hash_files` traversal bound,
/// so publish never wanders deeper than the resolver would have hashed.
/// `pub(crate)` for restore: a sealed generation can never hold a tree
/// deeper than a writer could stage, so the read side shares the bound.
pub(crate) const MAX_WALK_DEPTH: usize = 64;
/// Stream block for hashing and copying; hashing rides the copy pass.
const COPY_BYTES: usize = 1 << 20;
/// Staging for the `current` swap: `current.tmp` then a rename.
const CURRENT_TMP: &str = "current.tmp";

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
        /// unencodable paths, files that vanished mid-publish.
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
}

impl SkipReason {
    /// The stable lowercase spelling for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Canceled => "canceled",
            Self::Empty => "empty",
            Self::Unchanged => "unchanged",
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
    /// The generation would exceed the `files` blob's bounds.
    TooLarge,
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
            Self::TooLarge => f.write_str("generation exceeds the files blob bounds"),
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
    /// The job's file on disk.
    job: PathBuf,
    /// The `payload/<i>/<rel>` path — both the `files` entry name and the
    /// path inside the generation.
    entry: String,
    size: u64,
    mode: u32,
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
    /// Non-regular, unencodable or vanished entries, for diagnostics.
    skipped: u64,
    /// Walked or staged files since the last cancel/deadline poll.
    since_check: u32,
    /// Every planned file already matches the source listing.
    unchanged: bool,
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
        skipped: 0,
        since_check: 0,
        unchanged: true,
    };
    for (index, target) in attached.targets.iter().enumerate() {
        plan_target(&mut plan, index, &target.dir, deadline, cancel)?;
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

/// Walk one declared path into the plan. A missing target contributes
/// nothing; a symlinked or special target root is skipped, never
/// followed.
fn plan_target(
    plan: &mut Plan<'_>,
    index: usize,
    dir: &Path,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<(), Stop> {
    let prefix = format!("payload/{index}");
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        // A path the job never made contributes no files.
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if meta.is_dir() {
        let mut rel = String::new();
        plan.walk(dir, &prefix, &mut rel, 0, deadline, cancel)
    } else if meta.is_file() {
        // A declared path that is itself a file stages as `payload/<i>`.
        plan.plan_file(dir.to_path_buf(), prefix, &meta, deadline, cancel)
    } else {
        plan.skipped += 1;
        Ok(())
    }
}

impl Plan<'_> {
    /// Recursive walk of one target directory; depth is capped and every
    /// entry is classified without following links.
    fn walk(
        &mut self,
        dir: &Path,
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
        let mut children: Vec<fs::DirEntry> = match fs::read_dir(dir) {
            Ok(read) => read.collect::<Result<_, _>>()?,
            // A directory can vanish under a still-running container.
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // Sorted so the listing — and so the sealed digest — never depends
        // on filesystem order.
        children.sort_by_key(|e| e.file_name());
        for child in children {
            self.tick(deadline, cancel)?;
            let kind = match child.file_type() {
                Ok(kind) => kind,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    self.skipped += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Some(name) = child.file_name().to_str().map(str::to_owned) else {
                // Names the `files` blob can never encode are skipped,
                // never mangled.
                self.skipped += 1;
                continue;
            };
            if kind.is_dir() {
                let saved = rel.len();
                if !rel.is_empty() {
                    rel.push('/');
                }
                rel.push_str(&name);
                self.walk(&child.path(), prefix, rel, depth + 1, deadline, cancel)?;
                rel.truncate(saved);
            } else if kind.is_file() {
                let entry = if rel.is_empty() {
                    format!("{prefix}/{name}")
                } else {
                    format!("{prefix}/{rel}/{name}")
                };
                let meta = match child.metadata() {
                    Ok(meta) => meta,
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        self.skipped += 1;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                self.plan_file(child.path(), entry, &meta, deadline, cancel)?;
            } else {
                // Symlinks and special files are never followed and never
                // encoded: counted, then passed over.
                self.skipped += 1;
            }
        }
        Ok(())
    }

    /// Decide one file's place in the listing: hash it only when the
    /// source generation lists the same path at the same size — the
    /// digest is the reuse proof and the unchanged check at once.
    fn plan_file(
        &mut self,
        job: PathBuf,
        entry: String,
        meta: &fs::Metadata,
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
        let size = meta.len();
        let mode = file_mode(meta);
        let digest = match self.listed.get(entry.as_str()) {
            Some(listed) if listed.size == size => match hash_file(&job) {
                Ok(digest) => Some(digest),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    self.skipped += 1;
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
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
            job,
            entry,
            size,
            mode,
            digest,
        });
        self.tick(deadline, cancel)
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
    for planned in planned {
        plan.tick(deadline, cancel)?;
        let dst = staging.join(&planned.entry);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let listed = plan.listed.get(planned.entry.as_str()).copied();
        let mut digest = None;
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
            match hash_file(&dst) {
                Ok(staged) if staged == proof => {
                    digest = Some(proof);
                    reused += planned.size;
                }
                _ => {
                    let _ = fs::remove_file(&dst);
                }
            }
        }
        let (digest, size) = match digest {
            Some(digest) => (digest, planned.size),
            // Size and digest recorded are always of the bytes actually
            // staged: hashing rides the copy, so a file rewritten
            // mid-publish can never produce a listing its generation does
            // not satisfy.
            None => match copy_hashed(&planned.job, &dst) {
                Ok(staged) => {
                    // The payload file itself must carry the recorded
                    // mode: restore re-applies the staged file's own
                    // permission bits (clone::file), so a File::create
                    // default would leak 0666&umask in place of an
                    // executable's 0755. Hardlinked entries are not
                    // stamped — they share the source generation's inode,
                    // which already carries that mode.
                    stamp_mode(&dst, planned.mode)?;
                    staged
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    let _ = fs::remove_file(&dst);
                    plan.skipped += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            },
        };
        bytes += size;
        entries.push(FileEntry {
            path: planned.entry,
            size,
            digest,
            mode: planned.mode,
        });
    }
    Ok((entries, bytes, reused))
}

/// BLAKE3 of one file's content, read in bounded blocks.
fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; COPY_BYTES];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            return Ok(*hasher.finalize().as_bytes());
        }
        hasher.update(&buf[..read]);
    }
}

/// Copy `from` to `to`, hashing the bytes as they are written; returns
/// the size and digest of exactly what landed.
fn copy_hashed(from: &Path, to: &Path) -> std::io::Result<([u8; 32], u64)> {
    let mut input = fs::File::open(from)?;
    let mut output = fs::File::create(to)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; COPY_BYTES];
    let mut written = 0u64;
    loop {
        let read = input.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        output.write_all(&buf[..read])?;
        written += read as u64;
    }
    output.sync_data()?;
    Ok((*hasher.finalize().as_bytes(), written))
}

/// Write a small file durably enough to be renamed over: contents are
/// flushed to the device before the caller links the name into place.
fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_data()
}

/// fsync a directory so a rename inside it is durable. No-op off unix —
/// directory fsync is not part of the portable surface (the same reading
/// the object store makes).
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Stamp a staged payload file with the mode the manifest records for it,
/// minus the bits restore never applies (clone::mode_of keeps 0o777).
/// No-op off unix, where mode is not tracked.
fn stamp_mode(path: &Path, mode: u32) -> std::io::Result<()> {
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

/// The permission bits worth keeping — the exec bit on tools. Off unix a
/// read-only file reads as `0o444`, anything else `0o644`.
fn file_mode(meta: &fs::Metadata) -> u32 {
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
