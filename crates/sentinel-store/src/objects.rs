//! ```text
//! objects/<tenant>/<hex[0..2]>/<hex-digest>        committed objects
//! manifests/<tenant>/<kind>/<name-hash>/<version>  manifest files
//! tmp/<unique>                                     staging, never committed
//! ```
//! Files are fsynced and renamed before their row commits, so a crash leaves only orphans.
//! Object bytes go only through [`Objects::discard`] or [`Objects::unlink`], which skip any digest
//! that a live stage or reader pins or a committed row names.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{TenantId, UnixMillis, UploadId};

use crate::{Error, Result, space::Admission};

pub const OBJECTS_DIR: &str = "objects";
pub const MANIFESTS_DIR: &str = "manifests";
pub const TMP_DIR: &str = "tmp";
pub const INCOMING_DIR: &str = "incoming";
const CHUNK: usize = 128 << 10;
const MANIFEST_FORMAT: u16 = 1;
const MANIFEST_MAGIC: &[u8; 4] = b"SNMF";
pub const MAX_MANIFEST_ENTRIES: usize = 65_536;
pub const MAX_ENTRY_PATH: usize = 1024;
pub const MAX_MANIFEST_NAME: usize = 255;
pub const MAX_UPLOAD_RANGES: usize = 256;
pub const MAX_UPLOAD_TTL_MS: i64 = 24 * 3_600_000;
const SWEEP_BATCH: i64 = 256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Digest {
        Digest(bytes)
    }
    pub fn parse(hex: &str) -> Result<Digest> {
        if hex.len() != 64 {
            return Err(Error::InvalidInput("digest"));
        }
        let mut bytes = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or(Error::InvalidInput("digest"))?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or(Error::InvalidInput("digest"))?;
            bytes[i] = ((hi << 4) | lo) as u8;
        }
        Ok(Digest(bytes))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&blake3::Hash::from_bytes(self.0).to_hex())
    }
}
impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Expect {
    pub len: Option<u64>,
    pub digest: Option<Digest>,
}

type Pins = Arc<Mutex<HashMap<(TenantId, Digest), u64>>>;

fn lock_pins(pins: &Pins) -> std::sync::MutexGuard<'_, HashMap<(TenantId, Digest), u64>> {
    pins.lock().unwrap_or_else(|p| p.into_inner())
}

fn unpin(pins: &mut HashMap<(TenantId, Digest), u64>, key: (TenantId, Digest)) {
    if let Some(count) = pins.get_mut(&key) {
        *count -= 1;
        if *count == 0 {
            pins.remove(&key);
        }
    }
}

pub struct Staged {
    tenant: TenantId,
    digest: Digest,
    len: u64,
    pin: Option<Pins>,
    charge: Option<(Arc<Admission>, u64)>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some((admission, bytes)) = self.charge.take() {
            admission.release(self.tenant, bytes);
        }
        if let Some(pins) = self.pin.take() {
            unpin(&mut lock_pins(&pins), (self.tenant, self.digest));
        }
    }
}

pub struct Staging {
    file: File,
    tmp: PathBuf,
    hasher: blake3::Hasher,
    written: u64,
    limit: u64,
    tenant: TenantId,
    admission: Option<Arc<Admission>>,
    charged: u64,
}

impl Staging {
    pub fn written(&self) -> u64 {
        self.written
    }
    fn into_parts(self) -> (File, PathBuf, Option<(Arc<Admission>, u64)>) {
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: every field is read at most once and `this` is never
        // dropped, so nothing is released twice.
        unsafe {
            (
                std::ptr::read(&this.file),
                std::ptr::read(&this.tmp),
                std::ptr::read(&this.admission).map(|a| (a, this.charged)),
            )
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(admission) = &self.admission {
            admission.release(self.tenant, self.charged);
        }
        let _ = fs::remove_file(&self.tmp);
    }
}

impl Staged {
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug)]
pub struct Doomed {
    path: PathBuf,
    owner: Owner,
    aged: bool,
}

#[derive(Debug)]
enum Owner {
    Object(TenantId, Digest),
    Manifest {
        tenant: TenantId,
        kind: Kind,
        name: Vec<u8>,
        version: u64,
    },
    ManifestFile {
        tenant: TenantId,
        kind: Kind,
        name_hash: String,
        version: u64,
    },
    Stray,
}

struct Walk {
    found: Vec<Doomed>,
    seen: u32,
    limit: usize,
    budget: u32,
}

impl Walk {
    fn full(&self) -> bool {
        self.found.len() >= self.limit || self.seen >= self.budget
    }
    fn stray(&mut self, path: PathBuf) {
        if older_than_grace(&path) {
            self.found.push(Doomed {
                path,
                owner: Owner::Stray,
                aged: true,
            });
        }
    }
}

fn sorted_entries(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = read
        .flatten()
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        .collect();
    out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    out
}

fn manifest_owner(tenant: TenantId, path: &Path) -> Owner {
    let parse = || -> Option<Owner> {
        let version = path.file_name()?.to_str()?.parse::<u64>().ok()?;
        let hash_dir = path.parent()?;
        let name_hash = hash_dir.file_name()?.to_str()?.to_owned();
        let kind = hash_dir
            .parent()?
            .file_name()?
            .to_str()?
            .parse::<u8>()
            .ok()?;
        Some(Owner::ManifestFile {
            tenant,
            kind: Kind::from_code(kind).ok()?,
            name_hash,
            version,
        })
    };
    parse().unwrap_or(Owner::Stray)
}

#[doc(hidden)]
pub const RECLAIM_CANDIDATES: &str = "SELECT u.tenant_id, u.digest, o.len
     FROM object_unreferenced u
     JOIN objects o ON o.tenant_id = u.tenant_id AND o.digest = u.digest
     WHERE u.created_ms <= ?1
       AND NOT EXISTS(SELECT 1 FROM manifest_refs r
                      WHERE r.tenant_id = u.tenant_id AND r.digest = u.digest)
       AND NOT EXISTS(SELECT 1 FROM object_leases l
                      WHERE l.tenant_id = u.tenant_id AND l.digest = u.digest
                        AND l.until_ms > ?2)
       AND NOT EXISTS(SELECT 1 FROM manifests m
                      WHERE m.tenant_id = u.tenant_id AND m.refs_indexed = 0)
     ORDER BY u.created_ms
     LIMIT ?3";

impl Doomed {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub enum Touch<T> {
    Ready(T),
    Expired,
}

pub struct ChunkWritten {
    tenant: TenantId,
    id: UploadId,
    start: u64,
    end: u64,
    admitted: u64,
    admission: Option<Arc<Admission>>,
}

impl Drop for ChunkWritten {
    fn drop(&mut self) {
        if let Some(a) = self.admission.take()
            && self.admitted > 0
        {
            a.release_upload_delta(self.id, self.admitted);
        }
    }
}

pub struct SealPlan {
    tenant: TenantId,
    id: UploadId,
    digest: Digest,
    len: u64,
    staged: Option<Staged>,
    dedup: bool,
    done: bool,
}

impl SealPlan {
    pub fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub len: u64,
    pub created_ms: UnixMillis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Artifact = 0,
    Cache = 1,
}

impl Kind {
    fn code(self) -> u8 {
        self as u8
    }
    fn from_code(code: u8) -> Result<Kind> {
        match code {
            0 => Ok(Kind::Artifact),
            1 => Ok(Kind::Cache),
            _ => Err(Error::Corrupt("manifest kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub digest: Digest,
    pub len: u64,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub version: u64,
    pub digest: Digest,
    pub payload_len: u64,
    pub created_ms: UnixMillis,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Default)]
pub struct Recovery {
    pub staged: u32,
    /// Local files of objects marked evicted, left by an eviction that stopped between its mark and its unlink.
    /// The external copy is verified, so they were removed.
    pub evicted_leftovers: u32,
    pub orphans: Vec<PathBuf>,
    pub corrupt: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct Corrupt {
    pub tenant: TenantId,
    pub digest: Digest,
    pub path: PathBuf,
}

pub const UNREFERENCED_GRACE_MS: i64 = 24 * 3_600_000;
pub const FILE_ORPHAN_GRACE_MS: i64 = 3_600_000;
pub const MAX_LEASE_TTL_MS: i64 = 30 * 24 * 3_600_000;
const RECLAIM_BATCH: i64 = 256;

pub const MAX_UPLOAD_BYTES: u64 = sentinel_protocol::limits::MAX_ARTIFACT_BYTES;
const UPLOAD_STRIPES: usize = 64;

#[derive(Debug, Default)]
pub struct Reclaimed {
    pub objects: u32,
    pub bytes: u64,
    pub doomed: Vec<Doomed>,
}

pub struct Objects {
    root: PathBuf,
    durable_dirs: Mutex<HashSet<PathBuf>>,
    tmp_seq: AtomicU64,
    pins: Pins,
    upload_io: [Mutex<()>; UPLOAD_STRIPES],
    sweep_cursor: Mutex<Option<String>>,
    admission: OnceLock<Arc<Admission>>,
    deployment: Mutex<crate::retention::Deployment>,
    remote: OnceLock<Arc<dyn Remote>>,
    rehydrated: Mutex<Vec<(TenantId, Digest)>>,
    replication: OnceLock<Arc<crate::replicate::Status>>,
    maintenance: Mutex<()>,
    backups: OnceLock<Arc<dyn crate::backup::Control>>,
}

pub trait Remote: Send + Sync {
    fn fetch(&self, key: &str, out: &mut dyn Write) -> Result<u64>;
}

pub fn manifest_relpath(tenant: TenantId, kind: u8, name: &[u8], version: u64) -> PathBuf {
    PathBuf::from(MANIFESTS_DIR)
        .join(tenant.to_string())
        .join(kind.to_string())
        .join(blake3::hash(name).to_hex().to_string())
        .join(version.to_string())
}

pub fn object_relpath(tenant: TenantId, digest: &Digest) -> PathBuf {
    let hex = digest.to_string();
    PathBuf::from(OBJECTS_DIR)
        .join(tenant.to_string())
        .join(&hex[..2])
        .join(hex)
}

pub fn remote_key(tenant: TenantId, digest: &Digest) -> String {
    let hex = digest.to_string();
    format!("objects/{tenant}/{}/{hex}", &hex[..2])
}

fn content_matches(path: &Path, len: u64, digest: Digest, buf: &mut [u8]) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut hasher = blake3::Hasher::new();
    let mut got_total = 0u64;
    loop {
        match file.read(buf) {
            Ok(0) => break,
            Ok(got) => {
                got_total += got as u64;
                hasher.update(&buf[..got]);
            }
            Err(_) => return false,
        }
    }
    got_total == len && Digest(*hasher.finalize().as_bytes()) == digest
}

struct Hashing<'a> {
    file: &'a mut File,
    hasher: blake3::Hasher,
    len: u64,
    limit: u64,
}

impl Write for Hashing<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.len + buf.len() as u64 > self.limit {
            return Err(std::io::Error::other("remote object longer than its row"));
        }
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Objects {
    pub fn open(root: impl Into<PathBuf>) -> Result<Objects> {
        let root = root.into();
        for dir in [OBJECTS_DIR, MANIFESTS_DIR, TMP_DIR, INCOMING_DIR] {
            fs::create_dir_all(root.join(dir))?;
        }
        sync_dir(&root)?;
        Ok(Objects {
            root,
            durable_dirs: Mutex::new(HashSet::new()),
            tmp_seq: AtomicU64::new(0),
            pins: Arc::new(Mutex::new(HashMap::new())),
            upload_io: std::array::from_fn(|_| Mutex::new(())),
            sweep_cursor: Mutex::new(None),
            admission: OnceLock::new(),
            deployment: Mutex::new(crate::retention::Deployment::default()),
            remote: OnceLock::new(),
            rehydrated: Mutex::new(Vec::new()),
            replication: OnceLock::new(),
            maintenance: Mutex::new(()),
            backups: OnceLock::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn try_maintenance(&self) -> Option<std::sync::MutexGuard<'_, ()>> {
        match self.maintenance.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    pub fn hold_maintenance(&self) -> std::sync::MutexGuard<'_, ()> {
        self.maintenance.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_backups(&self, backups: Arc<dyn crate::backup::Control>) {
        let _ = self.backups.set(backups);
    }

    pub fn backups(&self) -> Option<&Arc<dyn crate::backup::Control>> {
        self.backups.get()
    }

    pub fn set_replication(&self, status: Arc<crate::replicate::Status>) {
        let _ = self.replication.set(status);
    }

    pub fn replication(&self) -> Option<&Arc<crate::replicate::Status>> {
        self.replication.get()
    }

    pub fn set_remote(&self, remote: Arc<dyn Remote>) {
        let _ = self.remote.set(remote);
    }

    fn open_local(&self, tenant: TenantId, digest: Digest, len: u64) -> Result<File> {
        let path = self.object_path(tenant, &digest);
        match File::open(&path) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
            Err(_) => {}
        }
        let Some(remote) = self.remote.get() else {
            return Err(Error::Corrupt("object missing"));
        };
        let _stripe = self.upload_io[digest.as_bytes()[0] as usize % UPLOAD_STRIPES]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Ok(file) = File::open(&path) {
            return Ok(file);
        }
        let tmp = self.tmp();
        let mut staged = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        let fetched = {
            let mut out = Hashing {
                file: &mut staged,
                hasher: blake3::Hasher::new(),
                len: 0,
                limit: len,
            };
            let got = remote.fetch(&remote_key(tenant, &digest), &mut out);
            got.map(|_| (out.len, Digest(*out.hasher.finalize().as_bytes())))
        };
        let placed = match fetched {
            Ok((got, hashed)) if got == len && hashed == digest => (|| {
                staged.sync_data()?;
                drop(staged);
                if let Some(parent) = path.parent() {
                    self.ensure_dir(parent)?;
                }
                fs::rename(&tmp, &path)?;
                if let Some(parent) = path.parent() {
                    sync_dir(parent)?;
                }
                Ok(())
            })(),
            Ok(_) => Err(Error::Corrupt("remote object content")),
            Err(e) => Err(e),
        };
        if placed.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        placed?;
        self.rehydrated
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((tenant, digest));
        Ok(File::open(&path)?)
    }

    pub fn take_rehydrated(&self) -> Vec<(TenantId, Digest)> {
        std::mem::take(&mut *self.rehydrated.lock().unwrap_or_else(|p| p.into_inner()))
    }

    pub fn evict_files(&self, victims: &[(TenantId, Digest)]) -> Vec<(TenantId, Digest)> {
        let pins = lock_pins(&self.pins);
        victims
            .iter()
            .filter(|key| !pins.contains_key(key))
            .filter(|(tenant, digest)| {
                let path = self.object_path(*tenant, digest);
                match fs::remove_file(&path) {
                    Ok(()) => true,
                    Err(e) => e.kind() == std::io::ErrorKind::NotFound,
                }
            })
            .copied()
            .collect()
    }

    pub fn set_admission(&self, admission: Arc<Admission>) {
        let _ = self.admission.set(admission);
    }
    pub fn admission(&self) -> Option<&Arc<Admission>> {
        self.admission.get()
    }
    pub fn set_default_quota(&self, bytes: u64) {
        self.deployment
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tenant_quota_bytes = bytes;
    }

    pub fn set_deployment(&self, deployment: crate::retention::Deployment) {
        *self.deployment.lock().unwrap_or_else(|p| p.into_inner()) = deployment;
    }

    pub fn deployment(&self) -> crate::retention::Deployment {
        *self.deployment.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn usage(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        Ok(crate::retention::tenant_usage(conn, tenant)?.total())
    }

    pub fn quota(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        Ok(crate::retention::effective(conn, &self.deployment(), tenant, None)?.tenant_quota_bytes)
    }

    fn owed(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        let inflight = self.admission.get().map_or(0, |a| a.inflight(tenant));
        Ok(self.usage(conn, tenant)?.saturating_add(inflight))
    }

    pub fn set_quota(&self, tx: &Transaction<'_>, tenant: TenantId, bytes: u64) -> Result<()> {
        if bytes == 0 || bytes > i64::MAX as u64 {
            return Err(Error::InvalidInput("quota"));
        }
        tx.execute(
            "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, updated_ms)
             VALUES (?1, X'', ?2, ?3)
             ON CONFLICT(tenant_id, repo_id) DO UPDATE SET
                 quota_bytes = excluded.quota_bytes, updated_ms = excluded.updated_ms",
            params![
                tenant.as_bytes().as_slice(),
                bytes as i64,
                UnixMillis::now().0
            ],
        )?;
        Ok(())
    }

    pub fn clear_quota(&self, tx: &Transaction<'_>, tenant: TenantId) -> Result<()> {
        let t = tenant.as_bytes().as_slice();
        tx.execute(
            "UPDATE storage_policies SET quota_bytes = NULL, updated_ms = ?2
             WHERE tenant_id = ?1 AND repo_id = X''",
            params![t, UnixMillis::now().0],
        )?;
        tx.execute(
            "DELETE FROM storage_policies WHERE tenant_id = ?1 AND repo_id = X''
             AND quota_bytes IS NULL AND log_retention_ms IS NULL
             AND artifact_retention_ms IS NULL",
            params![t],
        )?;
        Ok(())
    }

    pub fn lease(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        digest: Digest,
        holder: &str,
        ttl_ms: i64,
        now: UnixMillis,
    ) -> Result<()> {
        if holder.is_empty() || holder.len() > 255 {
            return Err(Error::InvalidInput("lease holder"));
        }
        if ttl_ms <= 0 || ttl_ms > MAX_LEASE_TTL_MS {
            return Err(Error::InvalidInput("lease ttl"));
        }
        tx.execute(
            "INSERT INTO object_leases(tenant_id, digest, holder, until_ms, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(tenant_id, digest, holder)
             DO UPDATE SET until_ms = excluded.until_ms",
            params![
                tenant.as_bytes().as_slice(),
                digest.as_bytes().as_slice(),
                holder,
                now.0 + ttl_ms,
                now.0,
            ],
        )?;
        Ok(())
    }

    pub fn release_lease(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        digest: Digest,
        holder: &str,
    ) -> Result<()> {
        tx.execute(
            "DELETE FROM object_leases
             WHERE tenant_id = ?1 AND digest = ?2 AND holder = ?3",
            params![
                tenant.as_bytes().as_slice(),
                digest.as_bytes().as_slice(),
                holder
            ],
        )?;
        Ok(())
    }

    pub fn sweep_leases(&self, tx: &Transaction<'_>, now: UnixMillis) -> Result<u32> {
        let mut stmt = tx.prepare(
            "SELECT tenant_id, digest, holder FROM object_leases
             WHERE until_ms <= ?1 LIMIT ?2",
        )?;
        let expired: Vec<(Vec<u8>, Vec<u8>, String)> = stmt
            .query_map(params![now.0, RECLAIM_BATCH], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        let mut swept = 0u32;
        for (tenant, digest, holder) in expired {
            swept += tx.execute(
                "DELETE FROM object_leases
                 WHERE tenant_id = ?1 AND digest = ?2 AND holder = ?3",
                params![tenant, digest, holder],
            )? as u32;
        }
        Ok(swept)
    }

    fn objects_root(&self) -> PathBuf {
        self.root.join(OBJECTS_DIR)
    }
    fn manifests_root(&self) -> PathBuf {
        self.root.join(MANIFESTS_DIR)
    }
    fn tmp(&self) -> PathBuf {
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        self.root
            .join(TMP_DIR)
            .join(format!("{:x}.{}.part", std::process::id(), seq))
    }
    fn object_path(&self, tenant: TenantId, digest: &Digest) -> PathBuf {
        let hex = digest.to_string();
        self.objects_root()
            .join(tenant.to_string())
            .join(&hex[..2])
            .join(&hex)
    }
    fn manifest_path(&self, tenant: TenantId, kind: Kind, name: &[u8], version: u64) -> PathBuf {
        self.root
            .join(manifest_relpath(tenant, kind.code(), name, version))
    }
    fn upload_path(&self, upload: UploadId) -> PathBuf {
        self.root.join(INCOMING_DIR).join(upload.to_string())
    }

    fn ensure_dir(&self, dir: &Path) -> Result<()> {
        {
            let known = self.durable_dirs.lock().unwrap_or_else(|p| p.into_inner());
            if known.contains(dir) {
                return Ok(());
            }
        }
        fs::create_dir_all(dir)?;
        let mut known = self.durable_dirs.lock().unwrap_or_else(|p| p.into_inner());
        let mut at = Some(dir);
        while let Some(d) = at {
            if !d.starts_with(&self.root) || !known.insert(d.to_path_buf()) {
                break;
            }
            sync_dir(d)?;
            at = d.parent();
        }
        Ok(())
    }

    pub fn stage(
        &self,
        tenant: TenantId,
        mut reader: impl Read,
        limit: u64,
        expect: Expect,
    ) -> Result<Staged> {
        let admission = self.admission.get().cloned();
        let mut charged = 0u64;
        let tmp = self.tmp();
        let outcome = (|| -> Result<Staged> {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; CHUNK];
            let mut len = 0u64;
            loop {
                let got = reader.read(&mut buf)?;
                if got == 0 {
                    break;
                }
                len += got as u64;
                if len > limit {
                    return Err(Error::InvalidInput("object size"));
                }
                if let Some(a) = &admission {
                    a.admit(tenant, got as u64)?;
                    charged += got as u64;
                }
                hasher.update(&buf[..got]);
                file.write_all(&buf[..got])?;
            }
            let digest = Digest(*hasher.finalize().as_bytes());
            if let Some(declared) = expect.len
                && declared != len
            {
                return Err(Error::InvalidInput("object length"));
            }
            if let Some(declared) = expect.digest
                && declared != digest
            {
                return Err(Error::InvalidInput("object digest"));
            }
            self.place(tenant, digest, len, file, &tmp)
        })();
        match outcome {
            Ok(mut staged) => {
                staged.charge = admission.map(|a| (a, charged));
                Ok(staged)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                if let Some(a) = &admission {
                    a.release(tenant, charged);
                }
                Err(e)
            }
        }
    }

    fn place(
        &self,
        tenant: TenantId,
        digest: Digest,
        len: u64,
        file: File,
        tmp: &Path,
    ) -> Result<Staged> {
        let path = self.object_path(tenant, &digest);
        let dir = path.parent().expect("object path has a parent");
        self.ensure_dir(dir)?;
        let exists = {
            let mut pins = lock_pins(&self.pins);
            let exists = path.exists();
            *pins.entry((tenant, digest)).or_insert(0) += 1;
            exists
        };
        let staged = Staged {
            tenant,
            digest,
            len,
            pin: Some(Arc::clone(&self.pins)),
            charge: None,
        };
        if exists {
            drop(file);
            let _ = fs::remove_file(tmp);
        } else {
            file.sync_data()?;
            drop(file);
            fs::rename(tmp, &path)?;
            sync_dir(dir)?;
        }
        Ok(staged)
    }

    pub fn stage_begin(&self, tenant: TenantId, limit: u64) -> Result<Staging> {
        let tmp = self.tmp();
        let file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        Ok(Staging {
            file,
            tmp,
            hasher: blake3::Hasher::new(),
            written: 0,
            limit,
            tenant,
            admission: self.admission.get().cloned(),
            charged: 0,
        })
    }

    pub fn stage_write(&self, staging: &mut Staging, bytes: &[u8]) -> Result<()> {
        let next = staging
            .written
            .checked_add(bytes.len() as u64)
            .ok_or(Error::InvalidInput("object size"))?;
        if next > staging.limit {
            return Err(Error::InvalidInput("object size"));
        }
        if let Some(a) = &staging.admission {
            a.admit(staging.tenant, bytes.len() as u64)?;
        }
        if let Err(e) = staging.file.write_all(bytes) {
            if let Some(a) = &staging.admission {
                a.release(staging.tenant, bytes.len() as u64);
            }
            return Err(e.into());
        }
        staging.charged += bytes.len() as u64;
        staging.hasher.update(bytes);
        staging.written = next;
        Ok(())
    }

    pub fn stage_seal(&self, tenant: TenantId, staging: Staging, expected: u64) -> Result<Staged> {
        if staging.written != expected {
            return Err(Error::InvalidInput("object length"));
        }
        let digest = Digest(*staging.hasher.finalize().as_bytes());
        let (file, tmp, charge) = staging.into_parts();
        match self.place(tenant, digest, expected, file, &tmp) {
            Ok(mut staged) => {
                staged.charge = charge;
                Ok(staged)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                if let Some((admission, bytes)) = charge {
                    admission.release(tenant, bytes);
                }
                Err(e)
            }
        }
    }

    /// An error leaves the transaction uncommitted; the caller must not swallow it.
    pub fn commit(&self, tx: &Transaction<'_>, staged: &Staged) -> Result<bool> {
        let changed = tx.execute(
            "INSERT OR IGNORE INTO objects(tenant_id, digest, len, created_ms)
             VALUES (?1, ?2, ?3, ?4)",
            (
                staged.tenant.as_bytes().as_slice(),
                staged.digest.as_bytes().as_slice(),
                staged.len as i64,
                UnixMillis::now().0,
            ),
        )?;
        if changed == 1 && staged.charge.is_some() {
            let owned = self.owed(tx, staged.tenant)?.saturating_sub(staged.len);
            crate::retention::check_tenant(tx, &self.deployment(), staged.tenant, owned, 0)?;
        }
        Ok(changed == 1)
    }

    pub fn discard(&self, tx: &Transaction<'_>, mut staged: Staged) -> Result<bool> {
        let key = (staged.tenant, staged.digest);
        let path = self.object_path(key.0, &key.1);
        let mut pins = lock_pins(&self.pins);
        if staged.pin.take().is_some() {
            unpin(&mut pins, key);
        }
        let removed = self.remove_unowned(tx, &pins, &Owner::Object(key.0, key.1), &path, false);
        drop(pins);
        drop(staged);
        removed
    }

    pub fn unlink(&self, tx: &Transaction<'_>, doomed: &[Doomed]) -> Result<u32> {
        let mut removed = 0u32;
        let pins = lock_pins(&self.pins);
        for d in doomed {
            if self.remove_unowned(tx, &pins, &d.owner, &d.path, d.aged)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn remove_unowned(
        &self,
        tx: &Connection,
        pins: &HashMap<(TenantId, Digest), u64>,
        owner: &Owner,
        path: &Path,
        aged: bool,
    ) -> Result<bool> {
        let owned = match owner {
            Owner::Object(tenant, digest) => {
                pins.contains_key(&(*tenant, *digest))
                    || tx
                        .prepare_cached(
                            "SELECT EXISTS(SELECT 1 FROM objects
                             WHERE tenant_id = ?1 AND digest = ?2)",
                        )?
                        .query_row(
                            params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
                            |r| r.get::<_, bool>(0),
                        )?
            }
            Owner::Manifest {
                tenant,
                kind,
                name,
                version,
            } => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM manifests
                     WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3 AND version = ?4)",
                )?
                .query_row(
                    params![
                        tenant.as_bytes().as_slice(),
                        kind.code() as i64,
                        name.as_slice(),
                        *version as i64
                    ],
                    |r| r.get::<_, bool>(0),
                )?,
            Owner::ManifestFile {
                tenant,
                kind,
                name_hash,
                version,
            } => {
                let mut stmt = tx.prepare_cached(
                    "SELECT name FROM manifests
                     WHERE tenant_id = ?1 AND kind = ?2 AND version = ?3",
                )?;
                let mut rows = stmt.query(params![
                    tenant.as_bytes().as_slice(),
                    kind.code() as i64,
                    *version as i64
                ])?;
                let mut named = false;
                while let Some(row) = rows.next()? {
                    if blake3::hash(&row.get::<_, Vec<u8>>(0)?).to_hex().as_str() == name_hash {
                        named = true;
                        break;
                    }
                }
                named
            }
            Owner::Stray => false,
        };
        if owned || (aged && !older_than_grace(path)) {
            return Ok(false);
        }
        Ok(fs::remove_file(path).is_ok())
    }

    pub fn meta(&self, conn: &Connection, tenant: TenantId, digest: Digest) -> Result<Meta> {
        conn.query_row(
            "SELECT len, created_ms FROM objects WHERE tenant_id = ?1 AND digest = ?2",
            (tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()),
            |row| {
                Ok(Meta {
                    len: row.get::<_, i64>(0)? as u64,
                    created_ms: UnixMillis(row.get(1)?),
                })
            },
        )
        .optional()?
        .ok_or(Error::NotFound)
    }

    pub fn open_object(&self, conn: &Connection, tenant: TenantId, digest: Digest) -> Result<File> {
        self.meta(conn, tenant, digest)?;
        File::open(self.object_path(tenant, &digest)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Corrupt("object missing"),
            _ => Error::Io(e),
        })
    }

    pub fn read(
        &self,
        conn: &Connection,
        tenant: TenantId,
        digest: Digest,
        out: &mut impl Write,
    ) -> Result<u64> {
        let meta = self.meta(conn, tenant, digest)?;
        let mut file = self.open_local(tenant, digest, meta.len)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK];
        let mut len = 0u64;
        loop {
            let got = file.read(&mut buf)?;
            if got == 0 {
                break;
            }
            len += got as u64;
            if len > meta.len {
                return Err(Error::Corrupt("object length"));
            }
            hasher.update(&buf[..got]);
            out.write_all(&buf[..got])?;
        }
        if len != meta.len || Digest(*hasher.finalize().as_bytes()) != digest {
            return Err(Error::Corrupt("object content"));
        }
        Ok(len)
    }

    pub fn commit_manifest(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        entries: &[Entry],
    ) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_MANIFEST_NAME {
            return Err(Error::InvalidInput("manifest name"));
        }
        if entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(Error::InvalidInput("manifest entries"));
        }
        let mut payload_len = 0u64;
        let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len());
        for entry in entries {
            if !valid_entry_path(&entry.path) {
                return Err(Error::InvalidInput("entry path"));
            }
            if !seen.insert(entry.path.as_str()) {
                return Err(Error::InvalidInput("duplicate entry path"));
            }
        }
        for entry in entries {
            let mut end = 0;
            while let Some(slash) = entry.path[end..].find('/') {
                end += slash;
                if seen.contains(&entry.path[..end]) {
                    return Err(Error::InvalidInput("entry path is also a directory"));
                }
                end += 1;
            }
        }
        for entry in entries {
            let committed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM objects
                    WHERE tenant_id = ?1 AND digest = ?2 AND len = ?3)",
                (
                    tenant.as_bytes().as_slice(),
                    entry.digest.as_bytes().as_slice(),
                    entry.len as i64,
                ),
                |row| row.get(0),
            )?;
            if !committed {
                return Err(Error::InvalidInput("uncommitted object"));
            }
            payload_len = payload_len.saturating_add(entry.len);
        }
        let version: u64 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM manifests
             WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3",
            (
                tenant.as_bytes().as_slice(),
                kind.code() as i64,
                name.as_bytes(),
            ),
            |row| row.get::<_, i64>(0),
        )? as u64;
        let body = encode_manifest(kind, name, entries);
        let digest = Digest(*blake3::hash(&body).as_bytes());
        let path = self.manifest_path(tenant, kind, name.as_bytes(), version);
        let tmp = self.tmp();
        let admission = self.admission.get().cloned();
        if let Some(a) = &admission {
            a.admit(tenant, body.len() as u64)?;
        }
        let landed = (|| -> Result<()> {
            self.ensure_dir(path.parent().expect("manifest path has a parent"))?;
            {
                let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
                file.write_all(&body).and_then(|()| file.sync_data())?;
            }
            fs::rename(&tmp, &path)?;
            if let Some(dir) = path.parent() {
                sync_dir(dir)?;
            }
            Ok(())
        })();
        if let Err(e) = landed {
            let _ = fs::remove_file(&tmp);
            if let Some(a) = &admission {
                a.release(tenant, body.len() as u64);
            }
            return Err(e);
        }
        if let Some(a) = &admission {
            a.release(tenant, body.len() as u64);
        }
        let written = tx.execute(
            "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries, payload_len, created_ms, refs_indexed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            (
                tenant.as_bytes().as_slice(),
                kind.code() as i64,
                name.as_bytes(),
                version as i64,
                digest.as_bytes().as_slice(),
                entries.len() as i64,
                payload_len as i64,
                UnixMillis::now().0,
            ),
        );
        if written.is_err() {
            let _ = fs::remove_file(&path);
        }
        written?;
        let mut ref_stmt = tx.prepare(
            "INSERT OR IGNORE INTO manifest_refs(tenant_id, kind, name, version, digest)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for entry in entries {
            ref_stmt.execute(params![
                tenant.as_bytes().as_slice(),
                kind.code() as i64,
                name.as_bytes(),
                version as i64,
                entry.digest.as_bytes().as_slice(),
            ])?;
        }
        Ok(version)
    }

    pub fn manifest(
        &self,
        conn: &Connection,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: Option<u64>,
    ) -> Result<Manifest> {
        let (version, digest, payload_len, created_ms) = match version {
            Some(version) => conn
                .query_row(
                    "SELECT version, digest, payload_len, created_ms FROM manifests
                     WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3 AND version = ?4",
                    (
                        tenant.as_bytes().as_slice(),
                        kind.code() as i64,
                        name.as_bytes(),
                        version as i64,
                    ),
                    manifest_row,
                )
                .optional()?,
            None => conn
                .query_row(
                    "SELECT version, digest, payload_len, created_ms FROM manifests
                     WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3
                     ORDER BY version DESC LIMIT 1",
                    (
                        tenant.as_bytes().as_slice(),
                        kind.code() as i64,
                        name.as_bytes(),
                    ),
                    manifest_row,
                )
                .optional()?,
        }
        .ok_or(Error::NotFound)?;
        let path = self.manifest_path(tenant, kind, name.as_bytes(), version);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Corrupt("manifest missing"),
            _ => Error::Io(e),
        })?;
        if Digest(*blake3::hash(&bytes).as_bytes()) != digest {
            return Err(Error::Corrupt("manifest content"));
        }
        let (found_kind, found_name, entries) = decode_manifest(&bytes)?;
        if found_kind != kind || found_name != name.as_bytes() {
            return Err(Error::Corrupt("manifest identity"));
        }
        Ok(Manifest {
            version,
            digest,
            payload_len,
            created_ms,
            entries,
        })
    }

    /// Orphans are reported, never deleted: staged and leaked files look identical.
    pub fn recover(&self, conn: &Connection) -> Result<Recovery> {
        let mut report = Recovery::default();
        let tmp = self.root.join(TMP_DIR);
        for entry in fs::read_dir(&tmp)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
                report.staged += 1;
            }
        }
        let mut committed: HashMap<(TenantId, Digest), (u64, bool)> = HashMap::new();
        let mut rows =
            conn.prepare("SELECT tenant_id, digest, len, evicted_ms IS NOT NULL FROM objects")?;
        let mut query = rows.query([])?;
        while let Some(row) = query.next()? {
            let tenant = tenant_from(row.get::<_, Vec<u8>>(0)?)?;
            let digest = Digest::from_bytes(
                <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(1)?.as_slice())
                    .map_err(|_| Error::Corrupt("object digest"))?,
            );
            committed.insert(
                (tenant, digest),
                (row.get::<_, i64>(2)? as u64, row.get(3)?),
            );
        }
        drop(query);
        drop(rows);
        let mut buf = vec![0u8; CHUNK];
        let objects = self.objects_root();
        for entry in fs::read_dir(&objects)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                report.orphans.push(entry.path());
                continue;
            }
            let Ok(tenant) = entry.file_name().to_string_lossy().parse::<TenantId>() else {
                report.orphans.push(entry.path());
                continue;
            };
            self.walk_objects(&entry.path(), tenant, &mut committed, &mut report, &mut buf)?;
        }
        for ((tenant, digest), (_, evicted)) in committed {
            if !evicted {
                report.missing.push(self.object_path(tenant, &digest));
            }
        }
        self.recover_manifests(conn, &mut report)?;
        let mut open = HashSet::new();
        let mut rows = conn.prepare("SELECT id FROM uploads WHERE state_code = 0")?;
        let mut query = rows.query([])?;
        while let Some(row) = query.next()? {
            if let Ok(id) = <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(0)?.as_slice())
                && let Ok(id) = UploadId::from_bytes(id)
            {
                open.insert(self.upload_path(id));
            }
        }
        drop(query);
        drop(rows);
        for entry in fs::read_dir(self.root.join(INCOMING_DIR))? {
            let entry = entry?;
            if entry.file_type()?.is_file() && !open.contains(&entry.path()) {
                fs::remove_file(entry.path())?;
                report.staged += 1;
            }
        }
        Ok(report)
    }

    fn walk_objects(
        &self,
        dir: &Path,
        tenant: TenantId,
        committed: &mut HashMap<(TenantId, Digest), (u64, bool)>,
        report: &mut Recovery,
        buf: &mut [u8],
    ) -> Result<()> {
        for prefix in fs::read_dir(dir)? {
            let prefix = prefix?;
            if !prefix.file_type()?.is_dir() {
                report.orphans.push(prefix.path());
                continue;
            }
            for entry in fs::read_dir(prefix.path())? {
                let entry = entry?;
                let path = entry.path();
                let name = entry.file_name();
                let valid_name = prefix.file_name().to_string_lossy().len() == 2
                    && name
                        .to_string_lossy()
                        .starts_with(prefix.file_name().to_string_lossy().as_ref());
                let digest = Digest::parse(&name.to_string_lossy());
                match (valid_name, digest) {
                    (true, Ok(digest)) => match committed.remove(&(tenant, digest)) {
                        Some((_, true)) => {
                            // Evicted rows are committed only after the external copy is verified, and nothing reads the file
                            // while the row says so; at startup no fetch is placing one either.
                            fs::remove_file(&path)?;
                            report.evicted_leftovers += 1;
                        }
                        Some((len, false)) if entry.metadata()?.len() == len => {
                            if !content_matches(&path, len, digest, buf) {
                                report.corrupt.push(path);
                            }
                        }
                        Some(_) => report.corrupt.push(path),
                        None => report.orphans.push(path),
                    },
                    _ => report.orphans.push(path),
                }
            }
        }
        Ok(())
    }

    fn recover_manifests(&self, conn: &Connection, report: &mut Recovery) -> Result<()> {
        let mut rows = conn.prepare("SELECT tenant_id, kind, name, version FROM manifests")?;
        let mut query = rows.query([])?;
        let mut committed = HashSet::new();
        while let Some(row) = query.next()? {
            let tenant = tenant_from(row.get::<_, Vec<u8>>(0)?)?;
            let kind = Kind::from_code(row.get::<_, i64>(1)? as u8)?;
            let name = row.get::<_, Vec<u8>>(2)?;
            let version = row.get::<_, i64>(3)? as u64;
            committed.insert(self.manifest_path(tenant, kind, &name, version));
        }
        drop(query);
        drop(rows);
        let root = self.manifests_root();
        if !root.exists() {
            return Ok(());
        }
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    stack.push(path);
                } else if !committed.remove(&path) {
                    report.orphans.push(path);
                }
            }
        }
        for path in committed {
            report.missing.push(path);
        }
        Ok(())
    }

    pub fn verify(&self, conn: &Connection) -> Result<Vec<Corrupt>> {
        let mut rows =
            conn.prepare("SELECT tenant_id, digest, len FROM objects WHERE evicted_ms IS NULL")?;
        let mut query = rows.query([])?;
        let mut listed = Vec::new();
        while let Some(row) = query.next()? {
            listed.push((
                tenant_from(row.get::<_, Vec<u8>>(0)?)?,
                Digest::from_bytes(
                    <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(1)?.as_slice())
                        .map_err(|_| Error::Corrupt("object digest"))?,
                ),
                row.get::<_, i64>(2)? as u64,
            ));
        }
        drop(query);
        drop(rows);
        let mut corrupt = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        for (tenant, digest, len) in listed {
            let path = self.object_path(tenant, &digest);
            if !content_matches(&path, len, digest, &mut buf) {
                corrupt.push(Corrupt {
                    tenant,
                    digest,
                    path,
                });
            }
        }
        Ok(corrupt)
    }

    pub fn open_read(
        &self,
        conn: &Connection,
        tenant: TenantId,
        digest: Digest,
    ) -> Result<(Reader, u64)> {
        let meta = self.meta(conn, tenant, digest)?;
        let file = self.open_local(tenant, digest, meta.len)?;
        *lock_pins(&self.pins).entry((tenant, digest)).or_insert(0) += 1;
        Ok((
            Reader {
                file,
                key: (tenant, digest),
                pins: Arc::clone(&self.pins),
            },
            meta.len,
        ))
    }

    pub fn reader_active(&self, tenant: TenantId, digest: Digest) -> bool {
        lock_pins(&self.pins).contains_key(&(tenant, digest))
    }

    pub fn begin_upload(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        declared_len: u64,
        digest: Option<Digest>,
        ttl_ms: i64,
        now: UnixMillis,
    ) -> Result<UploadId> {
        if ttl_ms <= 0 || ttl_ms > MAX_UPLOAD_TTL_MS {
            return Err(Error::InvalidInput("upload ttl"));
        }
        if declared_len > MAX_UPLOAD_BYTES {
            return Err(Error::InvalidInput("upload length"));
        }
        let owed = self.owed(tx, tenant)?;
        crate::retention::check_tenant(tx, &self.deployment(), tenant, owed, declared_len)?;
        if let Some(a) = self.admission.get() {
            a.check(declared_len)?;
        }
        self.ensure_dir(&self.root.join(INCOMING_DIR))?;
        let id = UploadId::new();
        let path = self.upload_path(id);
        {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            let result = file.set_len(declared_len).and_then(|()| file.sync_data());
            if result.is_err() {
                let _ = fs::remove_file(&path);
            }
            result?;
        }
        let written = tx.execute(
            "INSERT INTO uploads(id, tenant_id, declared_len, digest, ranges, expires_ms, created_ms)
             VALUES (?1, ?2, ?3, ?4, X'', ?5, ?6)",
            params![
                id.as_bytes().as_slice(),
                tenant.as_bytes().as_slice(),
                declared_len as i64,
                digest.map(|d| d.as_bytes().to_vec()),
                now.0 + ttl_ms,
                now.0,
            ],
        );
        if written.is_err() {
            let _ = fs::remove_file(&path);
        }
        written?;
        Ok(id)
    }

    pub fn upload_owner(&self, conn: &Connection, id: UploadId) -> Result<TenantId> {
        conn.query_row(
            "SELECT tenant_id FROM uploads WHERE id = ?1",
            params![id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(tenant_from)
        .transpose()?
        .ok_or(Error::NotFound)
    }

    pub fn upload(
        &self,
        conn: &Connection,
        tenant: TenantId,
        id: UploadId,
    ) -> Result<UploadStatus> {
        let row = upload_row(conn, tenant, id)?.ok_or(Error::NotFound)?;
        Ok(UploadStatus {
            state: row.state,
            declared_len: row.declared_len,
            received: row.received,
            ranges: row.ranges,
            expires_ms: row.expires_ms,
        })
    }

    fn upload_lock(&self, id: UploadId) -> std::sync::MutexGuard<'_, ()> {
        let bytes = id.as_bytes();
        let stripe =
            (u64::from_le_bytes(bytes[8..16].try_into().expect("8")) as usize) % UPLOAD_STRIPES;
        self.upload_io[stripe]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub fn write_chunk(
        &self,
        conn: &Connection,
        tenant: TenantId,
        id: UploadId,
        offset: u64,
        bytes: &[u8],
        now: UnixMillis,
    ) -> Result<Touch<ChunkWritten>> {
        let row = upload_row(conn, tenant, id)?.ok_or(Error::NotFound)?;
        if row.state != UploadState::Open {
            return Err(Error::Conflict);
        }
        if row.expires_ms <= now.0 {
            return Ok(Touch::Expired);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= row.declared_len)
            .ok_or(Error::InvalidInput("chunk range"))?;
        let mut ranges = row.ranges;
        ranges_insert(&mut ranges, offset, end)?;
        let received: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        let admitted = received - row.received;
        let admission = self.admission.get().cloned();
        if let Some(a) = &admission {
            a.admit_untracked(id, admitted)?;
        }
        let chunk = ChunkWritten {
            tenant,
            id,
            start: offset,
            end,
            admitted,
            admission,
        };
        {
            let _io = self.upload_lock(id);
            let mut file = OpenOptions::new().write(true).open(self.upload_path(id))?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(bytes)?;
            file.sync_data()?;
        }
        Ok(Touch::Ready(chunk))
    }

    pub fn record_chunk(&self, tx: &Transaction<'_>, mut chunk: ChunkWritten) -> Result<u64> {
        let row = upload_row(tx, chunk.tenant, chunk.id)?.ok_or(Error::NotFound)?;
        if row.state != UploadState::Open {
            return Err(Error::Conflict);
        }
        let mut ranges = row.ranges;
        ranges_insert(&mut ranges, chunk.start, chunk.end)?;
        let received: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        tx.execute(
            "UPDATE uploads SET ranges = ?2, received = ?3 WHERE id = ?1 AND state_code = 0",
            params![
                chunk.id.as_bytes().as_slice(),
                encode_ranges(&ranges),
                received as i64
            ],
        )?;
        let delta = received - row.received;
        if let Some(a) = chunk.admission.take() {
            let excess = chunk.admitted.saturating_sub(delta);
            if excess > 0 {
                a.release_upload_delta(chunk.id, excess);
            }
        }
        Ok(received)
    }

    pub fn put_chunk(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        id: UploadId,
        offset: u64,
        bytes: &[u8],
        now: UnixMillis,
    ) -> Result<u64> {
        match self.write_chunk(tx, tenant, id, offset, bytes, now)? {
            Touch::Ready(chunk) => self.record_chunk(tx, chunk),
            Touch::Expired => Err(Error::InvalidInput("upload expired")),
        }
    }

    pub fn retire_expired(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        id: UploadId,
        now: UnixMillis,
    ) -> Result<bool> {
        Ok(tx.execute(
            "UPDATE uploads SET state_code = 2
             WHERE id = ?1 AND tenant_id = ?2 AND state_code = 0 AND expires_ms <= ?3",
            params![
                id.as_bytes().as_slice(),
                tenant.as_bytes().as_slice(),
                now.0
            ],
        )? == 1)
    }

    pub fn drop_upload(&self, id: UploadId) {
        if let Some(a) = self.admission.get() {
            a.release_upload(id);
        }
        let _ = fs::remove_file(self.upload_path(id));
    }

    pub fn prepare_seal(
        &self,
        conn: &Connection,
        tenant: TenantId,
        id: UploadId,
        now: UnixMillis,
    ) -> Result<Touch<SealPlan>> {
        let row = upload_row(conn, tenant, id)?.ok_or(Error::NotFound)?;
        if row.state == UploadState::Committed {
            let digest = row.object_digest.ok_or(Error::Corrupt("upload digest"))?;
            return Ok(Touch::Ready(SealPlan {
                tenant,
                id,
                digest,
                len: row.declared_len,
                staged: None,
                dedup: false,
                done: true,
            }));
        }
        if row.state == UploadState::Aborted {
            return Err(Error::Conflict);
        }
        if row.expires_ms <= now.0 {
            return Ok(Touch::Expired);
        }
        let complete = row.ranges.as_slice() == [(0, row.declared_len)]
            || row.declared_len == 0 && row.ranges.is_empty();
        if !complete {
            return Err(Error::InvalidInput("upload incomplete"));
        }
        let path = self.upload_path(id);
        let _io = self.upload_lock(id);
        let recovered = !path.exists();
        let digest = if recovered {
            row.digest.ok_or(Error::Corrupt("upload file"))?
        } else {
            let mut file = File::open(&path)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; CHUNK];
            let mut len = 0u64;
            loop {
                let got = file.read(&mut buf)?;
                if got == 0 {
                    break;
                }
                len += got as u64;
                hasher.update(&buf[..got]);
            }
            if len != row.declared_len {
                return Err(Error::Corrupt("upload length"));
            }
            Digest(*hasher.finalize().as_bytes())
        };
        if row.digest.is_some_and(|declared| declared != digest) {
            return Err(Error::InvalidInput("upload digest"));
        }
        let object = self.object_path(tenant, &digest);
        let dir = object.parent().expect("object path has a parent");
        self.ensure_dir(dir)?;
        let exists = {
            let mut pins = lock_pins(&self.pins);
            let exists = object.exists();
            *pins.entry((tenant, digest)).or_insert(0) += 1;
            exists
        };
        let staged = Staged {
            tenant,
            digest,
            len: row.declared_len,
            pin: Some(Arc::clone(&self.pins)),
            charge: None,
        };
        if !exists {
            if recovered {
                return Err(Error::Corrupt("upload file"));
            }
            fs::rename(&path, &object)?;
            sync_dir(dir)?;
        }
        Ok(Touch::Ready(SealPlan {
            tenant,
            id,
            digest,
            len: row.declared_len,
            staged: Some(staged),
            dedup: exists && !recovered,
            done: false,
        }))
    }

    pub fn finish_seal(&self, tx: &Transaction<'_>, plan: SealPlan) -> Result<Digest> {
        if plan.done {
            return Ok(plan.digest);
        }
        let row = upload_row(tx, plan.tenant, plan.id)?.ok_or(Error::NotFound)?;
        match row.state {
            UploadState::Committed => {
                return row.object_digest.ok_or(Error::Corrupt("upload digest"));
            }
            UploadState::Aborted => return Err(Error::Conflict),
            UploadState::Open => {}
        }
        // Close the upload first: its reservation leaves usage as the object row's length enters it.
        tx.execute(
            "UPDATE uploads SET state_code = 1, object_digest = ?2 WHERE id = ?1",
            params![
                plan.id.as_bytes().as_slice(),
                plan.digest.as_bytes().as_slice()
            ],
        )?;
        let staged = plan.staged.as_ref().ok_or(Error::Corrupt("upload seal"))?;
        debug_assert_eq!(staged.len, plan.len);
        if !self.commit(tx, staged)? {
            // The bytes were already stored. If nothing references them their grace ran from their first creation and may be spent:
            // restart it here, or the next pass could reclaim an object this committed session authorizes reads of.
            tx.prepare_cached(
                "UPDATE object_unreferenced SET created_ms = ?3 WHERE tenant_id = ?1 AND digest = ?2",
            )?
            .execute(params![
                plan.tenant.as_bytes().as_slice(),
                plan.digest.as_bytes().as_slice(),
                UnixMillis::now().0
            ])?;
        }
        if plan.dedup {
            let _ = fs::remove_file(self.upload_path(plan.id));
        }
        if let Some(a) = self.admission.get() {
            a.release_upload(plan.id);
        }
        Ok(plan.digest)
    }

    pub fn seal_upload(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        id: UploadId,
        now: UnixMillis,
    ) -> Result<Digest> {
        match self.prepare_seal(tx, tenant, id, now)? {
            Touch::Ready(plan) => self.finish_seal(tx, plan),
            Touch::Expired => Err(Error::InvalidInput("upload expired")),
        }
    }

    pub fn abort_upload(&self, tx: &Transaction<'_>, tenant: TenantId, id: UploadId) -> Result<()> {
        let row = upload_row(tx, tenant, id)?.ok_or(Error::NotFound)?;
        if row.state != UploadState::Open {
            return Err(Error::Conflict);
        }
        tx.execute(
            "UPDATE uploads SET state_code = 2 WHERE id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        if let Some(a) = self.admission.get() {
            a.release_upload(id);
        }
        let _ = fs::remove_file(self.upload_path(id));
        Ok(())
    }

    pub fn sweep_uploads(&self, tx: &Transaction<'_>, now: UnixMillis) -> Result<u32> {
        let mut stmt = tx
            .prepare("SELECT id FROM uploads WHERE state_code = 0 AND expires_ms <= ?1 LIMIT ?2")?;
        let expired: Vec<UploadId> = stmt
            .query_map(params![now.0, SWEEP_BATCH], |row| row.get::<_, Vec<u8>>(0))?
            .map(|id| {
                UploadId::from_bytes(
                    <[u8; 16]>::try_from(id?.as_slice())
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        let mut swept = 0u32;
        for id in expired {
            tx.execute(
                "UPDATE uploads SET state_code = 2 WHERE id = ?1",
                params![id.as_bytes().as_slice()],
            )?;
            if let Some(a) = self.admission.get() {
                a.release_upload(id);
            }
            let _ = fs::remove_file(self.upload_path(id));
            swept += 1;
        }
        Ok(swept)
    }

    pub fn index_refs(&self, tx: &Transaction<'_>, limit: i64) -> Result<u32> {
        let pending: Vec<(Vec<u8>, i64, Vec<u8>, i64)> = tx
            .prepare(
                "SELECT tenant_id, kind, name, version FROM manifests
                 WHERE refs_indexed = 0 LIMIT ?1",
            )?
            .query_map(params![limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut indexed = 0u32;
        for (tenant, kind, name, version) in pending {
            let tenant = tenant_from(tenant)?;
            let kind = Kind::from_code(kind as u8)?;
            let version = version as u64;
            let path = self.manifest_path(tenant, kind, &name, version);
            let entries = fs::read(&path)
                .ok()
                .and_then(|body| decode_manifest(&body).ok().map(|(_, _, e)| e));
            let Some(entries) = entries else {
                // Its tenant stays unable to reclaim until the manifest reads again, so the skip is reported, not silent.
                crate::skipped::note_blob("manifests", tenant.as_bytes());
                continue;
            };
            {
                let mut ref_stmt = tx.prepare(
                    "INSERT OR IGNORE INTO manifest_refs(tenant_id, kind, name, version, digest)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for entry in &entries {
                    ref_stmt.execute(params![
                        tenant.as_bytes().as_slice(),
                        kind.code() as i64,
                        name.as_slice(),
                        version as i64,
                        entry.digest.as_bytes().as_slice(),
                    ])?;
                }
            }
            tx.execute(
                "UPDATE manifests SET refs_indexed = 1
                 WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3 AND version = ?4",
                params![
                    tenant.as_bytes().as_slice(),
                    kind.code() as i64,
                    name.as_slice(),
                    version as i64
                ],
            )?;
            indexed += 1;
        }
        Ok(indexed)
    }

    pub fn retire_manifest(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: u64,
    ) -> Result<Option<Doomed>> {
        let deleted = tx.execute(
            "DELETE FROM manifests
             WHERE tenant_id = ?1 AND kind = ?2 AND name = ?3 AND version = ?4",
            params![
                tenant.as_bytes().as_slice(),
                kind.code() as i64,
                name.as_bytes(),
                version as i64
            ],
        )?;
        Ok((deleted == 1).then(|| Doomed {
            path: self.manifest_path(tenant, kind, name.as_bytes(), version),
            owner: Owner::Manifest {
                tenant,
                kind,
                name: name.as_bytes().to_vec(),
                version,
            },
            aged: false,
        }))
    }

    pub fn reclaim(&self, tx: &Transaction<'_>, now: UnixMillis, limit: i64) -> Result<Reclaimed> {
        let cutoff = now.0 - UNREFERENCED_GRACE_MS;
        let candidates: Vec<(Vec<u8>, Vec<u8>, i64)> = tx
            .prepare_cached(RECLAIM_CANDIDATES)?
            .query_map(params![cutoff, now.0, limit.min(RECLAIM_BATCH)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut reclaimed = Reclaimed::default();
        for (tenant, digest, len) in candidates {
            let tenant = tenant_from(tenant)?;
            let digest = Digest::from_bytes(
                <[u8; 32]>::try_from(digest.as_slice())
                    .map_err(|_| Error::Corrupt("object digest"))?,
            );
            if self.reader_active(tenant, digest) {
                continue;
            }
            tx.execute(
                "DELETE FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
            )?;
            reclaimed.objects += 1;
            reclaimed.bytes += len as u64;
            reclaimed.doomed.push(Doomed {
                path: self.object_path(tenant, &digest),
                owner: Owner::Object(tenant, digest),
                aged: false,
            });
        }
        Ok(reclaimed)
    }

    pub fn orphans(
        &self,
        conn: &Connection,
        limit: u32,
        budget: u32,
    ) -> Result<(Vec<Doomed>, bool)> {
        let resume = self
            .sweep_cursor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut walk = Walk {
            found: Vec::new(),
            seen: 0,
            limit: limit as usize,
            budget,
        };
        let stopped = self.walk_shards(conn, resume.as_deref(), &mut walk)?;
        let done = stopped.is_none();
        *self.sweep_cursor.lock().unwrap_or_else(|p| p.into_inner()) = stopped;
        Ok((walk.found, done))
    }

    fn walk_shards(
        &self,
        conn: &Connection,
        resume: Option<&str>,
        walk: &mut Walk,
    ) -> Result<Option<String>> {
        let after = |key: &str| resume.is_none_or(|r| key > r);
        for (name, path) in sorted_entries(&self.manifests_root()) {
            let key = format!("m/{name}");
            if !after(&key) {
                continue;
            }
            walk.seen += 1;
            match name.parse::<TenantId>() {
                Ok(tenant) if path.is_dir() => self.manifest_shard(conn, tenant, &path, walk)?,
                _ => walk.stray(path),
            }
            if walk.full() {
                return Ok(Some(key));
            }
        }
        let mut has_row = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM objects WHERE tenant_id = ?1 AND digest = ?2)",
        )?;
        for (name, tenant_path) in sorted_entries(&self.objects_root()) {
            let tenant_key = format!("o/{name}");
            if resume.is_some_and(|r| format!("{tenant_key}/~").as_str() <= r) {
                continue;
            }
            let Ok(tenant) = name.parse::<TenantId>() else {
                walk.seen += 1;
                walk.stray(tenant_path);
                continue;
            };
            let resuming_inside = resume.is_some_and(|r| r.starts_with(&tenant_key));
            for (prefix, prefix_path) in sorted_entries(&tenant_path) {
                let key = format!("{tenant_key}/{prefix}");
                if !after(&key) {
                    continue;
                }
                walk.seen += 1;
                if !prefix_path.is_dir() {
                    if !resuming_inside {
                        walk.stray(prefix_path);
                    }
                    continue;
                }
                for (file, path) in sorted_entries(&prefix_path) {
                    walk.seen += 1;
                    let digest = match Digest::parse(&file) {
                        Ok(digest) if file.starts_with(prefix.as_str()) => digest,
                        _ => {
                            walk.stray(path);
                            continue;
                        }
                    };
                    if self.reader_active(tenant, digest) {
                        continue;
                    }
                    let committed = has_row
                        .query_row(
                            params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(true);
                    if !committed && older_than_grace(&path) {
                        walk.found.push(Doomed {
                            path,
                            owner: Owner::Object(tenant, digest),
                            aged: true,
                        });
                    }
                }
                if walk.full() {
                    return Ok(Some(key));
                }
            }
        }
        if after("t") {
            for (_, path) in sorted_entries(&self.root.join(TMP_DIR)) {
                walk.seen += 1;
                if path.is_file() {
                    walk.stray(path);
                }
                if walk.found.len() >= walk.limit {
                    return Ok(Some("t".into()));
                }
            }
        }
        Ok(None)
    }

    fn manifest_shard(
        &self,
        conn: &Connection,
        tenant: TenantId,
        dir: &Path,
        walk: &mut Walk,
    ) -> Result<()> {
        let mut committed = HashSet::new();
        let mut rows =
            conn.prepare_cached("SELECT kind, name, version FROM manifests WHERE tenant_id = ?1")?;
        let mut query = rows.query([tenant.as_bytes().as_slice()])?;
        while let Some(row) = query.next()? {
            committed.insert(self.manifest_path(
                tenant,
                Kind::from_code(row.get::<_, i64>(0)? as u8)?,
                &row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)? as u64,
            ));
        }
        drop(query);
        drop(rows);
        let mut stack = vec![dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                walk.seen += 1;
                let path = entry.path();
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(path);
                } else if !committed.contains(&path) && older_than_grace(&path) {
                    let owner = manifest_owner(tenant, &path);
                    walk.found.push(Doomed {
                        path,
                        owner,
                        aged: true,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn sweep_orphans(&self, conn: &mut Connection, limit: u32) -> Result<u32> {
        *self.sweep_cursor.lock().unwrap_or_else(|p| p.into_inner()) = None;
        let mut removed = 0u32;
        while removed < limit {
            let (doomed, done) = self.orphans(conn, limit - removed, u32::MAX)?;
            let tx = conn.transaction()?;
            removed += self.unlink(&tx, &doomed)?;
            tx.commit()?;
            if done || doomed.is_empty() {
                break;
            }
        }
        Ok(removed)
    }

    /// Writes a manifest's entries below `dest`. On Unix the walk is descriptor-relative: `dest` is resolved once,
    /// and every component below it is created and opened relative to the directory descriptor before it without
    /// following a symlink, so a destination changed while the extract runs cannot redirect a write outside the
    /// directories this call opened. Elsewhere the checks are path-based.
    ///
    /// On every platform `dest` must be a private directory: mode 0700, owned by the caller and not under a shared
    /// or world-writable directory. The walk defends only against a change made by someone who cannot already
    /// write `dest`. It still follows symlinks in `dest`'s ancestors, opens `dest` itself without refusing a
    /// symlink, enters a subdirectory another user pre-created, and creates directories 0777 and files 0666 (less
    /// the umask) before the entry's mode is applied, which is skipped for mode 0. No controller path calls this;
    /// a new caller creates `dest` itself.
    pub fn materialize(
        &self,
        conn: &Connection,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: Option<u64>,
        dest: &Path,
    ) -> Result<u64> {
        self.materialize_with(conn, tenant, kind, name, version, dest, |_| {})
    }

    /// [`Objects::materialize`] with a call before each entry's file is created, after its directory is open;
    /// tests change the destination there to prove the write cannot follow.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn materialize_with(
        &self,
        conn: &Connection,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: Option<u64>,
        dest: &Path,
        mut before_create: impl FnMut(usize),
    ) -> Result<u64> {
        let manifest = self.manifest(conn, tenant, kind, name, version)?;
        fs::create_dir_all(dest)?;
        self.extract(conn, tenant, &manifest.entries, dest, &mut before_create)
    }

    #[cfg(unix)]
    fn extract(
        &self,
        conn: &Connection,
        tenant: TenantId,
        entries: &[Entry],
        dest: &Path,
        before_create: &mut impl FnMut(usize),
    ) -> Result<u64> {
        use std::os::{
            fd::{AsFd, OwnedFd},
            unix::fs::PermissionsExt,
        };

        use rustix::{
            fs::{Mode, OFlags, mkdirat, openat},
            io::Errno,
        };

        let io = |e: Errno| Error::Io(e.into());
        let root: OwnedFd = rustix::fs::open(
            dest,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        // The directories of the previous entry, reused while the next entry shares their names: a descriptor names
        // one inode, so reuse cannot be redirected either.
        let mut open: Vec<(&str, OwnedFd)> = Vec::new();
        let mut written = 0u64;
        for (index, entry) in entries.iter().enumerate() {
            let (dirs, file_name) = entry
                .path
                .rsplit_once('/')
                .map_or(("", entry.path.as_str()), |(dirs, name)| (dirs, name));
            let mut depth = 0;
            if !dirs.is_empty() {
                for part in dirs.split('/') {
                    if open.get(depth).is_some_and(|(held, _)| *held == part) {
                        depth += 1;
                        continue;
                    }
                    open.truncate(depth);
                    let parent = open.last().map_or(root.as_fd(), |(_, fd)| fd.as_fd());
                    match mkdirat(parent, part, Mode::RWXU | Mode::RWXG | Mode::RWXO) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(e) => return Err(io(e)),
                    }
                    // `O_NOFOLLOW` fails on a symlink (`ELOOP`, or `ENOTDIR` beside `O_DIRECTORY`) and
                    // `O_DIRECTORY` on a file: neither is a directory this extract may descend into.
                    let child = openat(
                        parent,
                        part,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|e| match e {
                        Errno::LOOP | Errno::NOTDIR => Error::InvalidInput("materialize path"),
                        e => io(e),
                    })?;
                    open.push((part, child));
                    depth += 1;
                }
            }
            open.truncate(depth);
            let dir = open.last().map_or(root.as_fd(), |(_, fd)| fd.as_fd());
            before_create(index);
            let fd = openat(
                dir,
                file_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
            )
            .map_err(|e| match e {
                Errno::EXIST => Error::InvalidInput("materialize target"),
                e => io(e),
            })?;
            let mut file = File::from(fd);
            self.read(conn, tenant, entry.digest, &mut file)?;
            file.sync_data()?;
            if entry.mode & 0o777 != 0 {
                file.set_permissions(fs::Permissions::from_mode(entry.mode & 0o777))?;
            }
            written += entry.len;
        }
        File::from(root).sync_all()?;
        Ok(written)
    }

    #[cfg(not(unix))]
    fn extract(
        &self,
        conn: &Connection,
        tenant: TenantId,
        entries: &[Entry],
        dest: &Path,
        before_create: &mut impl FnMut(usize),
    ) -> Result<u64> {
        let mut written = 0u64;
        for (index, entry) in entries.iter().enumerate() {
            let mut path = dest.to_path_buf();
            for part in entry.path.split('/') {
                path.push(part);
                match fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(Error::InvalidInput("materialize path"));
                    }
                    Ok(meta) if !meta.is_dir() && path != *dest => {
                        return Err(Error::InvalidInput("materialize path"));
                    }
                    Ok(_) | Err(_) => {}
                }
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            before_create(index);
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::AlreadyExists => Error::InvalidInput("materialize target"),
                    _ => Error::Io(e),
                })?;
            self.read(conn, tenant, entry.digest, &mut file)?;
            file.sync_data()?;
            written += entry.len;
        }
        sync_dir(dest)?;
        Ok(written)
    }
}

pub struct Reader {
    file: File,
    key: (TenantId, Digest),
    pins: Pins,
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for Reader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        unpin(&mut lock_pins(&self.pins), self.key);
    }
}

struct UploadRow {
    state: UploadState,
    declared_len: u64,
    digest: Option<Digest>,
    received: u64,
    ranges: Vec<(u64, u64)>,
    expires_ms: i64,
    object_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    Open = 0,
    Committed = 1,
    Aborted = 2,
}

#[derive(Clone, Debug)]
pub struct UploadStatus {
    pub state: UploadState,
    pub declared_len: u64,
    pub received: u64,
    pub ranges: Vec<(u64, u64)>,
    pub expires_ms: i64,
}

fn upload_row(conn: &Connection, tenant: TenantId, id: UploadId) -> Result<Option<UploadRow>> {
    conn.query_row(
        "SELECT state_code, declared_len, digest, received, ranges, expires_ms, object_digest
         FROM uploads WHERE id = ?1 AND tenant_id = ?2",
        params![id.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
        |row| {
            let blob = |index: usize| -> std::result::Result<Option<Digest>, rusqlite::Error> {
                row.get::<_, Option<Vec<u8>>>(index)?
                    .map(|d| {
                        <[u8; 32]>::try_from(d.as_slice())
                            .map(Digest::from_bytes)
                            .map_err(|_| rusqlite::Error::InvalidQuery)
                    })
                    .transpose()
            };
            Ok(UploadRow {
                state: match row.get::<_, i64>(0)? {
                    0 => UploadState::Open,
                    1 => UploadState::Committed,
                    _ => UploadState::Aborted,
                },
                declared_len: row.get::<_, i64>(1)? as u64,
                digest: blob(2)?,
                received: row.get::<_, i64>(3)? as u64,
                ranges: decode_ranges(&row.get::<_, Vec<u8>>(4)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                expires_ms: row.get(5)?,
                object_digest: blob(6)?,
            })
        },
    )
    .optional()
    .map_err(Error::from)
}

fn encode_ranges(ranges: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ranges.len() * 16);
    for (start, end) in ranges {
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&end.to_le_bytes());
    }
    out
}

fn decode_ranges(bytes: &[u8]) -> Result<Vec<(u64, u64)>> {
    if !bytes.len().is_multiple_of(16) || bytes.len() / 16 > MAX_UPLOAD_RANGES {
        return Err(Error::Corrupt("upload ranges"));
    }
    Ok(bytes
        .chunks_exact(16)
        .map(|pair| {
            (
                u64::from_le_bytes(pair[..8].try_into().unwrap()),
                u64::from_le_bytes(pair[8..].try_into().unwrap()),
            )
        })
        .collect())
}

fn ranges_insert(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) -> Result<()> {
    if start >= end {
        return Err(Error::InvalidInput("chunk range"));
    }
    let (mut start, mut end) = (start, end);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len() + 1);
    let mut placed = false;
    for &(s, e) in ranges.iter() {
        if e < start {
            out.push((s, e));
        } else if s > end {
            if !placed {
                out.push((start, end));
                placed = true;
            }
            out.push((s, e));
        } else {
            start = start.min(s);
            end = end.max(e);
        }
    }
    if !placed {
        out.push((start, end));
    }
    if out.len() > MAX_UPLOAD_RANGES {
        return Err(Error::InvalidInput("upload fragmentation"));
    }
    *ranges = out;
    Ok(())
}

fn manifest_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(u64, Digest, u64, UnixMillis)> {
    let digest: Vec<u8> = row.get(1)?;
    Ok((
        row.get::<_, i64>(0)? as u64,
        Digest::from_bytes(
            <[u8; 32]>::try_from(digest.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        row.get::<_, i64>(2)? as u64,
        UnixMillis(row.get(3)?),
    ))
}

pub(crate) fn tenant_from(bytes: Vec<u8>) -> Result<TenantId> {
    TenantId::from_bytes(
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("tenant id"))?,
    )
    .map_err(|_| Error::Corrupt("tenant id"))
}

fn older_than_grace(path: &Path) -> bool {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
        - FILE_ORPHAN_GRACE_MS;
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .is_some_and(|age| (age.as_millis() as i64) < cutoff)
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

pub fn valid_entry_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_ENTRY_PATH || path.starts_with('/') {
        return false;
    }
    path.split('/').all(|part| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', ':', '\0'])
    })
}

fn encode_manifest(kind: Kind, name: &str, entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + entries.len() * 48);
    out.extend_from_slice(MANIFEST_MAGIC);
    out.extend_from_slice(&MANIFEST_FORMAT.to_le_bytes());
    out.push(kind.code());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&(entry.path.len() as u16).to_le_bytes());
        out.extend_from_slice(entry.path.as_bytes());
        out.extend_from_slice(entry.digest.as_bytes());
        out.extend_from_slice(&entry.len.to_le_bytes());
        out.extend_from_slice(&entry.mode.to_le_bytes());
    }
    out
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if bytes.len() < n {
        return Err(Error::Corrupt("manifest record"));
    }
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    Ok(head)
}

fn decode_manifest(bytes: &[u8]) -> Result<(Kind, Vec<u8>, Vec<Entry>)> {
    let mut rest = bytes;
    if take(&mut rest, 4)? != MANIFEST_MAGIC {
        return Err(Error::Corrupt("manifest magic"));
    }
    if u16::from_le_bytes(take(&mut rest, 2)?.try_into().unwrap()) != MANIFEST_FORMAT {
        return Err(Error::Corrupt("manifest format"));
    }
    let kind = Kind::from_code(take(&mut rest, 1)?[0])?;
    let name_len = u16::from_le_bytes(take(&mut rest, 2)?.try_into().unwrap()) as usize;
    let name = take(&mut rest, name_len)?.to_vec();
    let count = u32::from_le_bytes(take(&mut rest, 4)?.try_into().unwrap()) as usize;
    if count > MAX_MANIFEST_ENTRIES {
        return Err(Error::Corrupt("manifest entries"));
    }
    let mut entries = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let path_len = u16::from_le_bytes(take(&mut rest, 2)?.try_into().unwrap()) as usize;
        let path = String::from_utf8(take(&mut rest, path_len)?.to_vec())
            .map_err(|_| Error::Corrupt("manifest path"))?;
        let digest = Digest::from_bytes(
            <[u8; 32]>::try_from(take(&mut rest, 32)?)
                .map_err(|_| Error::Corrupt("manifest digest"))?,
        );
        let len = u64::from_le_bytes(take(&mut rest, 8)?.try_into().unwrap());
        let mode = u32::from_le_bytes(take(&mut rest, 4)?.try_into().unwrap());
        if !valid_entry_path(&path) {
            return Err(Error::Corrupt("manifest path"));
        }
        entries.push(Entry {
            path,
            digest,
            len,
            mode,
        });
    }
    if !rest.is_empty() {
        return Err(Error::Corrupt("manifest trailing bytes"));
    }
    Ok((kind, name, entries))
}
