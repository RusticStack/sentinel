//! Job views are reopened beneath the workspace anchor with `O_NOFOLLOW`, so a job cannot redirect publication at host files.

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

pub const CACHE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(3 * 60);
pub const MAX_GENERATION_BYTES: u64 = crate::gc::DEFAULT_BUDGET_BYTES / 4;
pub const FREE_SPACE_RESERVE: u64 = 1 << 30;
const CHECK_EVERY: u32 = 256;
pub(crate) const MAX_WALK_DEPTH: usize = 64;
const COPY_BYTES: usize = 1 << 20;
const SYNC_FDS: usize = 64;
pub(crate) const CURRENT_TMP: &str = "current.tmp";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    Sealed {
        generation: String,
        files: u32,
        bytes: u64,
        reused_bytes: u64,
        skipped: u64,
    },
    Skipped(SkipReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Busy,
    Canceled,
    Empty,
    Unchanged,
    Refused,
}

impl SkipReason {
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

#[derive(Debug)]
pub enum PublishError {
    TrustMismatch,
    TimedOut,
    TooLarge,
    NoSpace,
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
    if attached.key.is_empty() || attached.outcome == Outcome::Miss(Miss::Invalid) {
        return Ok(Published::Skipped(SkipReason::Refused));
    }
    if cancel() || Instant::now() >= deadline {
        return Ok(Published::Skipped(SkipReason::Canceled));
    }
    let entry = attached
        .scope
        .entry_dir(cache_root, entry_key(attached.scope.class, &attached.key));
    // Collection can move an entry aside while a pin is being taken, so the pin is re-checked under the lock.
    // A pin that went with the old directory is retaken, otherwise it guards nothing.
    let mut turns = 3;
    let (_pin, _lock) = loop {
        let pin = Lease::acquire(&entry, "publish", crate::lease::DEFAULT_TTL)?;
        let Some(lock) = WriteLock::acquire(&entry, "publish")? else {
            return Ok(Published::Skipped(SkipReason::Busy));
        };
        if pin.path().is_file() {
            break (pin, lock);
        }
        turns -= 1;
        if turns == 0 {
            return Err(PublishError::Lock(crate::lease::LeaseError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the entry kept moving under the pin",
                ),
            )));
        }
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
        let _ = fs::remove_dir_all(&staging);
    }
    out
}

struct Planned {
    base: usize,
    rel: String,
    entry: String,
    size: u64,
    mode: u32,
    sparse: bool,
    digest: Option<[u8; 32]>,
}

struct Plan<'a> {
    listed: HashMap<&'a str, &'a FileEntry>,
    planned: Vec<Planned>,
    bases: Vec<Base>,
    bytes: u64,
    skipped: u64,
    since_check: u32,
    unchanged: bool,
    buf: Vec<u8>,
}

impl Plan<'_> {
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

fn stage(
    entry: &Path,
    staging: &Path,
    attached: &Attached,
    generation: &str,
    now: UnixMillis,
    deadline: Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<Published, Stop> {
    let source = attached
        .generation
        .as_deref()
        .filter(|name| {
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
    if plan.unchanged
        && let Some((_, blob)) = &source
        && blob.entries.len() == plan.planned.len()
    {
        return Ok(Published::Skipped(SkipReason::Unchanged));
    }
    plan.check(deadline, cancel)?;
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
        return Ok(Published::Skipped(SkipReason::Empty));
    }
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
        plan.skipped += 1;
        return Ok(());
    };
    let anchor = match Base::anchor(&target.root) {
        Ok(anchor) => anchor,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    match anchor.resolve(Path::new(&rel))? {
        Node::Missing => Ok(()),
        Node::Dir(dir) => {
            let base = plan.bases.len();
            let mut walked = String::new();
            let out = plan.walk(&dir, base, &prefix, &mut walked, 0, deadline, cancel);
            plan.bases.push(dir);
            out
        }
        Node::File(meta) => {
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
        let children = dir.entries()?;
        for (name, kind) in children {
            self.tick(deadline, cancel)?;
            let Some(text) = name.to_str() else {
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
                _ => {
                    self.skipped += 1;
                    return Ok(());
                }
            },
            _ => None,
        };
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

struct Durability {
    pending: Vec<fs::File>,
    whole_fs: bool,
}

impl Durability {
    fn staged(&mut self, file: fs::File) -> std::io::Result<()> {
        if cfg!(not(target_os = "linux")) {
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
            // A drifted link is removed, never copied into: writing through it would truncate the source's inode.
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
            None => match plan.bases[planned.base].open(&planned.rel)? {
                Some((file, opened)) => {
                    let sparse = planned.sparse || opened.sparse();
                    let (digest, written, out) =
                        copy_hashed(file, &dst, planned.size, sparse, plan.buf())?;
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
        output.set_len(written)?;
    }
    Ok((*hasher.finalize().as_bytes(), written, output))
}

fn reserve(total: u64) -> u64 {
    (total / 20).min(FREE_SPACE_RESERVE)
}

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

pub(crate) fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_data()
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

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
