//! The disk half: content-addressed blobs and manifests, tag records, and the size bound.
//!
//! ```text
//! registry/blobs/<scope>/<2 hex>/<62 hex>            one verified blob, by digest
//! registry/manifests/<scope>/<2 hex>/<62 hex>        one verified manifest, by digest
//! registry/manifests/<scope>/<2 hex>/<62 hex>.type   that manifest's media type
//! registry/tags/<scope>/<16 hex>                     <digest> <validated ms> <repository>
//! registry/tmp/<name>.part                           a body being fetched, never served
//! registry/scopes/<scope key>                        the scope's token, kept across restarts
//! registry/conf/<token>/registries.conf              the pull configuration naming that token
//! ```
//!
//! A scope's token is random and minted once, so only a pull configuration the worker wrote for that
//! scope can name it: one tenant's private layers are unreachable from another's pull path. Every file
//! is written under a temporary name and renamed into place after its digest verifies, so a partial
//! fetch is never visible under a digest. `used` counts every stored byte against one budget, and a
//! write that would exceed it evicts by last use before it is refused.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Error, Result, Scope, Settings, spec::Digest};

pub(crate) const BLOBS_DIR: &str = "blobs";
pub(crate) const MANIFESTS_DIR: &str = "manifests";
pub(crate) const TAGS_DIR: &str = "tags";
pub(crate) const TMP_DIR: &str = "tmp";
pub(crate) const SCOPES_DIR: &str = "scopes";

/// A manifest larger than this is refused rather than stored: OCI manifests and indexes are far below
/// it, and a body this size answers a request the cache does not understand.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 4 << 20;

/// The most directory entries one eviction pass reads before it decides with what it has.
const MAX_SCAN: usize = 1 << 16;

pub(crate) struct Store {
    root: PathBuf,
    budget: u64,
    used: AtomicU64,
    tag_ttl_ms: u64,
    keep: Duration,
}

/// The tokens the cache answers to, loaded from disk at open and extended as new scopes appear.
#[derive(Default)]
pub(crate) struct Scopes {
    pub(crate) by_scope: HashMap<Scope, Box<str>>,
    pub(crate) by_token: HashMap<Box<str>, Scope>,
    /// The pull configuration written for a token in this process.
    pub(crate) written: HashMap<Box<str>, PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TagRecord {
    pub(crate) digest: Digest,
    pub(crate) validated_ms: u64,
}

pub(crate) struct ManifestEntry {
    pub(crate) bytes: Vec<u8>,
    pub(crate) media_type: String,
}

impl Store {
    pub(crate) fn open(root: &Path, settings: &Settings) -> Result<Store> {
        for dir in [BLOBS_DIR, MANIFESTS_DIR, TAGS_DIR, TMP_DIR, SCOPES_DIR] {
            private_dir(&root.join(dir))?;
        }
        let store = Store {
            root: root.to_path_buf(),
            budget: settings.budget_bytes,
            used: AtomicU64::new(0),
            tag_ttl_ms: settings.tag_ttl.as_millis() as u64,
            keep: settings.keep_window,
        };
        // A previous process may have died mid-fetch: a part file is never served and never counted.
        if let Ok(entries) = fs::read_dir(store.root.join(TMP_DIR)) {
            for entry in entries.flatten().take(MAX_SCAN) {
                let _ = fs::remove_file(entry.path());
            }
        }
        store.used.store(store.measure(), Ordering::Relaxed);
        Ok(store)
    }

    pub(crate) fn budget(&self) -> u64 {
        self.budget
    }

    pub(crate) fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Every stored byte, walked once at open. `tmp/`, `conf/` and `scopes/` are working state, not cache.
    fn measure(&self) -> u64 {
        let mut total = 0u64;
        for dir in [BLOBS_DIR, MANIFESTS_DIR, TAGS_DIR] {
            let mut seen = 0usize;
            walk(&self.root.join(dir), &mut seen, &mut |_, len| total += len);
        }
        total
    }

    pub(crate) fn load_scopes(&self) -> Result<Scopes> {
        let mut scopes = Scopes::default();
        let dir = self.root.join(SCOPES_DIR);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(scopes),
            Err(error) => return Err(error.into()),
        };
        for entry in entries.flatten().take(MAX_SCAN) {
            let Some(key) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(scope) = Scope::from_key(&key) else {
                continue;
            };
            let Ok(text) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let token = text.trim();
            if !valid_token(token) {
                continue;
            }
            scopes.by_scope.insert(scope, token.into());
            scopes.by_token.insert(token.into(), scope);
        }
        Ok(scopes)
    }

    pub(crate) fn save_scope(&self, key: &str, token: &str) -> Result<()> {
        let path = self.root.join(SCOPES_DIR).join(key);
        write_private(&path, token.as_bytes())
    }

    // Paths are derived, never trusted: a token is 32 hex characters and a digest is 32 bytes, so no
    // stored name can escape its scope directory.

    fn blob_path(&self, token: &str, digest: &Digest) -> PathBuf {
        fanout(&self.root.join(BLOBS_DIR).join(token), digest)
    }

    fn manifest_path(&self, token: &str, digest: &Digest) -> PathBuf {
        fanout(&self.root.join(MANIFESTS_DIR).join(token), digest)
    }

    fn tag_path(&self, token: &str, repo: &str, tag: &str) -> PathBuf {
        let mut hasher = blake3::Hasher::new();
        hasher.update(repo.as_bytes());
        hasher.update(b"\0");
        hasher.update(tag.as_bytes());
        let hash = hasher.finalize().to_hex();
        self.root
            .join(TAGS_DIR)
            .join(token)
            .join(&hash.as_str()[..16])
    }

    pub(crate) fn blob(&self, token: &str, digest: &Digest) -> Option<(PathBuf, u64)> {
        let path = self.blob_path(token, digest);
        let meta = fs::symlink_metadata(&path).ok()?;
        meta.is_file().then_some((path, meta.len()))
    }

    /// A stored manifest, verified again before it is handed out: a manifest is small, and one that does
    /// not hash to its name is a miss and is removed rather than served.
    pub(crate) fn manifest(&self, token: &str, digest: &Digest) -> Option<ManifestEntry> {
        let path = self.manifest_path(token, digest);
        let mut file = File::open(&path).ok()?;
        let mut bytes = Vec::new();
        if std::io::Read::by_ref(&mut file)
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return None;
        }
        if bytes.len() as u64 > MAX_MANIFEST_BYTES || Digest::of(&bytes) != *digest {
            self.remove_manifest(&path, bytes.len() as u64);
            return None;
        }
        let media_type = fs::read_to_string(path.with_extension("type"))
            .unwrap_or_else(|_| String::from("application/vnd.oci.image.manifest.v1+json"));
        let _ = file.set_modified(SystemTime::now());
        Some(ManifestEntry {
            bytes,
            media_type: media_type.trim().to_owned(),
        })
    }

    pub(crate) fn tag(&self, token: &str, repo: &str, tag: &str) -> Option<TagRecord> {
        let path = self.tag_path(token, repo, tag);
        let text = fs::read_to_string(&path).ok()?;
        let mut fields = text.split_ascii_whitespace();
        let digest = Digest::parse(fields.next()?)?;
        let validated_ms = fields.next()?.parse().ok()?;
        // The record names its repository: two repositories whose tag hashes collided could never
        // answer for each other.
        if fields.next()? != repo {
            return None;
        }
        Some(TagRecord {
            digest,
            validated_ms,
        })
    }

    pub(crate) fn fresh(&self, record: &TagRecord, now_ms: u64) -> bool {
        now_ms.saturating_sub(record.validated_ms) < self.tag_ttl_ms
    }

    pub(crate) fn put_tag(
        &self,
        token: &str,
        repo: &str,
        tag: &str,
        digest: &Digest,
    ) -> Result<()> {
        let mut text = String::with_capacity(96 + repo.len());
        text.push_str(&digest.to_string());
        text.push(' ');
        text.push_str(&now_ms().to_string());
        text.push(' ');
        text.push_str(repo);
        text.push('\n');
        let path = self.tag_path(token, repo, tag);
        private_dir_below(&path)?;
        self.reserve(text.len() as u64)?;
        write_private(&path, text.as_bytes()).inspect_err(|_| {
            self.release(text.len() as u64);
        })
    }

    pub(crate) fn put_manifest(
        &self,
        token: &str,
        digest: &Digest,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let path = self.manifest_path(token, digest);
        private_dir_below(&path)?;
        let budgetted = bytes.len() as u64 + media_type.len() as u64;
        self.reserve(budgetted)?;
        let staging = path.with_extension("part");
        if let Err(error) = write_private(&staging, bytes)
            .and_then(|()| write_private(&path.with_extension("type"), media_type.as_bytes()))
            .and_then(|()| fs::rename(&staging, &path).map_err(Error::from))
        {
            let _ = fs::remove_file(&staging);
            self.release(budgetted);
            return Err(error);
        }
        Ok(())
    }

    fn remove_manifest(&self, path: &Path, bytes: u64) {
        let sidecar = fs::symlink_metadata(path.with_extension("type"))
            .map(|meta| meta.len())
            .unwrap_or(0);
        if fs::remove_file(path).is_ok() {
            self.release(bytes + sidecar);
        }
        let _ = fs::remove_file(path.with_extension("type"));
    }

    /// Reserves `bytes` of the budget for a body about to land, evicting by last use when the store is
    /// full. Refused only when nothing evictable remains.
    pub(crate) fn reserve(&self, bytes: u64) -> Result<()> {
        if bytes > self.budget {
            return Err(Error::OverBudget {
                need: bytes,
                budget: self.budget,
            });
        }
        loop {
            let used = self.used.load(Ordering::Relaxed);
            if used.saturating_add(bytes) <= self.budget {
                if self
                    .used
                    .compare_exchange(used, used + bytes, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Ok(());
                }
                continue;
            }
            let short = used.saturating_add(bytes) - self.budget;
            if self.evict(short) == 0 {
                return Err(Error::OverBudget {
                    need: bytes,
                    budget: self.budget,
                });
            }
        }
    }

    pub(crate) fn release(&self, bytes: u64) {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Evicts least recently served content until `want` bytes are free, and returns how many it freed.
    /// Content served within the keep window is skipped; tag records go only after content, because
    /// losing one costs one revalidation while losing a layer costs the whole fetch.
    fn evict(&self, want: u64) -> u64 {
        let cutoff = SystemTime::now()
            .checked_sub(self.keep)
            .unwrap_or(UNIX_EPOCH);
        let mut freed = 0u64;
        let mut candidates = Vec::new();
        for dir in [BLOBS_DIR, MANIFESTS_DIR] {
            let mut seen = 0usize;
            walk(&self.root.join(dir), &mut seen, &mut |path, len| {
                let name = path.as_os_str().to_string_lossy();
                // A sidecar belongs to its manifest, and a staging file belongs to a fetch in flight.
                if name.ends_with(".type") || name.ends_with(".part") {
                    return;
                }
                let Ok(meta) = fs::symlink_metadata(path) else {
                    return;
                };
                let Ok(modified) = meta.modified() else {
                    return;
                };
                if modified >= cutoff {
                    return;
                }
                candidates.push((modified, path.to_path_buf(), len));
            });
        }
        candidates.sort_unstable_by_key(|entry| entry.0);
        for (_, path, len) in candidates {
            if freed >= want {
                break;
            }
            let sidecar = fs::symlink_metadata(path.with_extension("type"))
                .map(|meta| meta.len())
                .unwrap_or(0);
            if fs::remove_file(&path).is_ok() {
                let _ = fs::remove_file(path.with_extension("type"));
                self.release(len + sidecar);
                freed += len + sidecar;
            }
        }
        if freed >= want {
            return freed;
        }
        // Tag records last: they are tiny, and the pull that loses one only revalidates once.
        let mut tags = Vec::new();
        let mut seen = 0usize;
        walk(&self.root.join(TAGS_DIR), &mut seen, &mut |path, len| {
            let Ok(meta) = fs::symlink_metadata(path) else {
                return;
            };
            let Ok(modified) = meta.modified() else {
                return;
            };
            if modified < cutoff {
                tags.push((modified, path.to_path_buf(), len));
            }
        });
        tags.sort_unstable_by_key(|entry| entry.0);
        for (_, path, len) in tags {
            if freed >= want {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                self.release(len);
                freed += len;
            }
        }
        freed
    }

    /// Starts a blob: takes the budget for `declared` bytes (or nothing when the upstream did not say)
    /// and answers a staging file that verifies the body as it lands.
    pub(crate) fn begin(
        &self,
        token: &str,
        digest: Digest,
        declared: Option<u64>,
        name: &str,
    ) -> Result<Staging<'_>> {
        let target = self.blob_path(token, &digest);
        private_dir_below(&target)?;
        let reserved = declared.unwrap_or(0);
        if declared.is_some() {
            self.reserve(reserved)?;
        }
        let part = self.root.join(TMP_DIR).join(name);
        let file = match File::create_new(&part) {
            Ok(file) => file,
            Err(error) => {
                if declared.is_some() {
                    self.release(reserved);
                }
                return Err(error.into());
            }
        };
        Ok(Staging {
            store: self,
            part,
            target,
            file: Some(file),
            digest,
            declared,
            reserved,
            hasher: ring::digest::Context::new(&ring::digest::SHA256),
            written: 0,
            committed: false,
        })
    }
}

/// A body landing under a temporary name. Dropping it without [`Staging::commit`] removes the part and
/// gives the budget back: a refused, interrupted or mismatched fetch leaves nothing behind.
pub(crate) struct Staging<'a> {
    store: &'a Store,
    part: PathBuf,
    target: PathBuf,
    file: Option<File>,
    digest: Digest,
    declared: Option<u64>,
    reserved: u64,
    hasher: ring::digest::Context,
    written: u64,
    committed: bool,
}

impl Staging<'_> {
    pub(crate) fn write(&mut self, chunk: &[u8]) -> Result<()> {
        let total = self.written + chunk.len() as u64;
        if let Some(declared) = self.declared
            && total > declared
        {
            return Err(Error::Upstream(
                "the body is longer than the length it declared".into(),
            ));
        }
        if self.declared.is_none() {
            // A body whose length the upstream did not state still cannot grow past the budget.
            self.store.reserve(chunk.len() as u64)?;
            self.reserved += chunk.len() as u64;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| Error::Config("staging file is closed".into()))?;
        file.write_all(chunk)?;
        self.hasher.update(chunk);
        self.written = total;
        Ok(())
    }

    /// Verifies the body against the digest it was requested by and puts it in place. A body that does
    /// not match, or is shorter than it declared, is removed and never becomes readable.
    pub(crate) fn commit(mut self) -> Result<PathBuf> {
        if let Some(declared) = self.declared
            && self.written != declared
        {
            return Err(Error::Upstream(
                "the body is shorter than the length it declared".into(),
            ));
        }
        let digest = Digest::of_finished(&self.hasher);
        if digest != self.digest {
            return Err(Error::Corrupt(format!("sha256:{}", digest.hex())));
        }
        let file = self.file.take();
        drop(file);
        fs::rename(&self.part, &self.target)?;
        self.committed = true;
        let _ = File::open(&self.target).and_then(|f| f.set_modified(SystemTime::now()));
        Ok(self.target.clone())
    }
}

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.part);
            let reserved = self.reserved.max(self.written);
            if reserved > 0 {
                self.store.release(reserved);
            }
        }
    }
}

pub(crate) fn mint_token() -> Result<Box<str>> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Config("no randomness for a scope token".into()))?;
    Ok(crate::spec::hex_bytes(&bytes).into_boxed_str())
}

pub(crate) fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn fanout(dir: &Path, digest: &Digest) -> PathBuf {
    let hex = digest.hex();
    dir.join(&hex[..2]).join(&hex[2..])
}

fn walk(dir: &Path, seen: &mut usize, visit: &mut impl FnMut(&Path, u64)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *seen >= MAX_SCAN {
            return;
        }
        *seen += 1;
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            walk(&entry.path(), seen, visit);
        } else if meta.is_file() {
            visit(&entry.path(), meta.len());
        }
    }
}

fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

fn private_dir_below(path: &Path) -> Result<()> {
    match path.parent() {
        Some(parent) => private_dir(parent),
        None => Ok(()),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}
