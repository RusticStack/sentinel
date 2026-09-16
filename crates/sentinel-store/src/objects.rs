//! Tenant-scoped immutable objects and versioned manifests (D01).
//!
//! Layout under the controller's data directory, all on one filesystem:
//!
//! ```text
//! objects/<tenant>/<hex[0..2]>/<hex-digest>        committed objects
//! manifests/<tenant>/<kind>/<name-hash>/<version>  manifest files
//! tmp/<unique>                                     staging, never committed
//! ```
//!
//! **Commit order.** [`Objects::stage`] streams the body to `tmp/` hashing
//! as it goes, verifies the declared length/digest, `fdatasync`s the file,
//! atomically renames it into place and `fsync`s the directory chain. Only
//! then does [`Objects::commit`] insert the reference row — so a crash may
//! leave an orphan but can never publish an incomplete object. Objects are
//! addressed by BLAKE3-256 and deduplicated within the tenant; namespaces
//! never cross tenants, so identical content stored by two tenants is two
//! objects and reveals nothing about the other tenant's data.
//!
//! **Manifests** are named, monotonically versioned lists of object
//! references. [`Objects::commit_manifest`] picks the next version inside
//! the reference-commit transaction, refuses references to objects the
//! tenant has not committed, writes and syncs the manifest file, and
//! inserts the row — the same order, so a manifest can never dangle.
//!
//! **Recovery.** [`Objects::recover`] sweeps `tmp/` (a leftover there is an
//! incomplete write, removed), then reconciles the filesystem against the
//! committed rows: files without rows are orphans (reported, not deleted —
//! reclamation is a separate stage), rows without files or with the wrong
//! length are corrupt. [`Objects::verify`] rehashes every committed object
//! for the deeper integrity check.
//!
//! Reads are verified: [`Objects::read`] streams the object while rehashing
//! and compares the committed digest and length before reporting success.

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
/// Resumable upload staging: `incoming/<upl_…>` files sized to the declared
/// length at `begin_upload`. Unlike `tmp/` these survive a restart — an open
/// upload's bytes are how the client resumes.
pub const INCOMING_DIR: &str = "incoming";
/// Bytes per streamed chunk for staging, reads and verification.
const CHUNK: usize = 128 << 10;
/// Manifest format version; bump only under `docs/compatibility.md`.
const MANIFEST_FORMAT: u16 = 1;
const MANIFEST_MAGIC: &[u8; 4] = b"SNMF";
/// A manifest may reference this many entries; the serialized file stays
/// well under a megabyte and the name list cannot be used as an amplifier.
pub const MAX_MANIFEST_ENTRIES: usize = 65_536;
/// Longest stored entry path, in bytes.
pub const MAX_ENTRY_PATH: usize = 1024;
/// Longest manifest name, in bytes (matches the column check).
pub const MAX_MANIFEST_NAME: usize = 255;
/// Distinct byte ranges one upload may accumulate; a client that fragments
/// past this is refused and should send ordered chunks instead.
pub const MAX_UPLOAD_RANGES: usize = 256;
/// Longest an upload session may stay open.
pub const MAX_UPLOAD_TTL_MS: i64 = 24 * 3_600_000;
/// One sweep handles this many expired uploads at a time.
const SWEEP_BATCH: i64 = 256;

/// BLAKE3-256 content digest. Hex text form is 64 lowercase characters.
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
    /// Parse the 64-character lowercase hex form used in file names.
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

/// What the body is declared to be; both halves are verified against the
/// staged bytes before anything is renamed into place.
#[derive(Clone, Copy, Debug, Default)]
pub struct Expect {
    pub len: Option<u64>,
    pub digest: Option<Digest>,
}

/// A staged object: fully written, hashed, synced and renamed into its
/// final path, but not yet referenced. [`Objects::commit`] publishes it;
/// [`Staged::discard`] removes it when the commit is abandoned.
pub struct Staged {
    tenant: TenantId,
    digest: Digest,
    len: u64,
    path: PathBuf,
    /// This stage created the final-path file; a dedup hit did not, so
    /// `discard` must not remove what a concurrent commit may own.
    created: bool,
    /// Bytes admitted while the file sat uncommitted. Released when the
    /// stage leaves scope — commit, discard or drop — since the probe then
    /// accounts the bytes itself (or they are gone).
    charge: Option<(Arc<Admission>, u64)>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some((admission, bytes)) = self.charge.take() {
            admission.release(self.tenant, bytes);
        }
    }
}

/// An open staged write under `tmp/`, for bodies that arrive in pieces —
/// link artifact frames, where no `Read` exists. Dropping without
/// [`Objects::stage_seal`] removes the temp file and releases the admission
/// charge the written bytes held.
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
    /// Bytes accepted so far.
    pub fn written(&self) -> u64 {
        self.written
    }
    /// Consume the handle without the Drop removal firing; the admission
    /// charge moves with the result so [`Objects::stage_seal`] can hand it
    /// to the `Staged` it builds.
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
    /// Remove the staged file — only when this stage created it. A dedup
    /// hit shares its path with an earlier stage or committed object, so
    /// removing it could delete live content.
    pub fn discard(self) {
        if self.created {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A committed object's metadata as the store recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub len: u64,
    pub created_ms: UnixMillis,
}

/// What a manifest may name. `Cache` exists so later phases do not overload
/// the artifact namespace; the wire value is part of the schema.
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

/// One object reference inside a manifest version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Relative archive path: `/`-separated, no `.`/`..` or drive segments.
    pub path: String,
    pub digest: Digest,
    pub len: u64,
    /// Permission bits to restore (unix mode); 0 means unspecified.
    pub mode: u32,
}

/// A committed manifest version.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub version: u64,
    /// Digest of the manifest file itself.
    pub digest: Digest,
    pub payload_len: u64,
    pub created_ms: UnixMillis,
    pub entries: Vec<Entry>,
}

/// What [`Objects::recover`] found. `staged` counts removed `tmp/` files;
/// orphans/corrupt/missing carry the paths so an operator can inspect them.
#[derive(Debug, Default)]
pub struct Recovery {
    /// Incomplete staged writes removed from `tmp/`.
    pub staged: u32,
    /// Files under `objects/` or `manifests/` with no committed row.
    pub orphans: Vec<PathBuf>,
    /// Files whose committed row disagrees (length) or that cannot be read.
    pub corrupt: Vec<PathBuf>,
    /// Committed rows whose file is absent.
    pub missing: Vec<PathBuf>,
}

/// Committed object whose bytes failed verification: absent, wrong length,
/// or content that no longer matches its digest.
#[derive(Debug)]
pub struct Corrupt {
    pub tenant: TenantId,
    pub digest: Digest,
    pub path: PathBuf,
}

/// How long an unreferenced, unleased object row must sit before
/// reclamation may collect it: generous enough that a manifest commit a
/// client is still preparing cannot lose its objects underneath it.
pub const UNREFERENCED_GRACE_MS: i64 = 24 * 3_600_000;
/// A file under the object/manifest/tmp trees with no row and no writer
/// this old is commit-crash garbage and is swept.
pub const FILE_ORPHAN_GRACE_MS: i64 = 3_600_000;
/// Longest a single lease may pin an object.
pub const MAX_LEASE_TTL_MS: i64 = 30 * 24 * 3_600_000;
/// Reclamation and index passes move this many rows per call, so a sweep
/// never holds the writer through a whole-store walk.
const RECLAIM_BATCH: i64 = 256;

/// What one [`Objects::reclaim`] pass removed: rows deleted and the file
/// paths the caller unlinks once the transaction commits.
#[derive(Debug, Default)]
pub struct Reclaimed {
    pub objects: u32,
    pub bytes: u64,
    pub paths: Vec<PathBuf>,
}

/// The object and manifest tree under one data directory. Filesystem work
/// happens here; reference commits happen inside the caller's transaction.
pub struct Objects {
    root: PathBuf,
    /// Directories already created and synced this process. Creating a
    /// tenant's subtree needs one fsync chain, not one per object.
    durable_dirs: Mutex<HashSet<PathBuf>>,
    tmp_seq: AtomicU64,
    /// Live readers per (tenant, digest). Reclamation must never unlink a
    /// file a reader is streaming; [`Objects::reader_active`] is how GC asks.
    readers: std::sync::Arc<Mutex<HashMap<(TenantId, Digest), u64>>>,
    /// Disk admission; unset admits everything (tests and hosts without
    /// watermarks behave exactly as before D06).
    admission: OnceLock<Arc<Admission>>,
    /// Quota applied to tenants without a `tenant_quotas` row; 0 means
    /// unlimited.
    default_quota: AtomicU64,
}

impl Objects {
    /// Open (creating) `objects/`, `manifests/`, `tmp/` and `incoming/`
    /// under `root`. Does not recover; call [`Objects::recover`] at startup.
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
            readers: std::sync::Arc::new(Mutex::new(HashMap::new())),
            admission: OnceLock::new(),
            default_quota: AtomicU64::new(0),
        })
    }

    /// Install the disk admission gate; staged writes and uploads charge
    /// against it. Set once at startup.
    pub fn set_admission(&self, admission: Arc<Admission>) {
        let _ = self.admission.set(admission);
    }
    /// The configured admission gate, when one was installed.
    pub fn admission(&self) -> Option<&Arc<Admission>> {
        self.admission.get()
    }
    /// Quota applied to tenants without their own `tenant_quotas` row;
    /// 0 means unlimited.
    pub fn set_default_quota(&self, bytes: u64) {
        self.default_quota.store(bytes, Ordering::Relaxed);
    }

    /// Committed bytes owed by `tenant`: objects plus the declared length
    /// of its open uploads.
    pub fn usage(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        Ok(conn
            .prepare_cached("SELECT bytes FROM tenant_usage WHERE tenant_id = ?1")?
            .query_row([tenant.as_bytes().as_slice()], |r| r.get::<_, i64>(0))
            .optional()?
            .unwrap_or(0) as u64)
    }

    /// The tenant's quota in bytes: its own row, else the default; 0 means
    /// unlimited.
    pub fn quota(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        Ok(conn
            .prepare_cached("SELECT quota_bytes FROM tenant_quotas WHERE tenant_id = ?1")?
            .query_row([tenant.as_bytes().as_slice()], |r| r.get::<_, i64>(0))
            .optional()?
            .map(|q| q as u64)
            .unwrap_or_else(|| self.default_quota.load(Ordering::Relaxed)))
    }

    /// What the tenant owes against its quota right now: committed usage
    /// plus staged-but-uncommitted bytes the admission gate is holding.
    fn owed(&self, conn: &Connection, tenant: TenantId) -> Result<u64> {
        let inflight = self.admission.get().map_or(0, |a| a.inflight(tenant));
        Ok(self.usage(conn, tenant)?.saturating_add(inflight))
    }

    /// Set or replace a tenant's quota (admin).
    pub fn set_quota(&self, tx: &Transaction<'_>, tenant: TenantId, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Err(Error::InvalidInput("quota"));
        }
        tx.execute(
            "INSERT INTO tenant_quotas(tenant_id, quota_bytes) VALUES (?1, ?2)
             ON CONFLICT(tenant_id) DO UPDATE SET quota_bytes = excluded.quota_bytes",
            params![tenant.as_bytes().as_slice(), bytes as i64],
        )?;
        Ok(())
    }

    /// Remove a tenant's quota row — the default applies again.
    pub fn clear_quota(&self, tx: &Transaction<'_>, tenant: TenantId) -> Result<()> {
        tx.execute(
            "DELETE FROM tenant_quotas WHERE tenant_id = ?1",
            params![tenant.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Pin an object for `holder` until `now + ttl_ms` — reclamation skips
    /// leased objects. Re-issuing renews; [`Objects::release_lease`] frees
    /// early. The object must be committed (the foreign key enforces it).
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

    /// Drop one holder's lease; no row is not an error.
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

    /// Remove expired lease rows; at most [`RECLAIM_BATCH`] per call.
    /// WITHOUT ROWID has no rowid LIMIT trick, so the keys come out first.
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
        // Unique within the process by the counter, across restarts because
        // recovery sweeps tmp/ before anything new stages.
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
        self.manifests_root()
            .join(tenant.to_string())
            .join(kind.code().to_string())
            .join(blake3::hash(name).to_hex().to_string())
            .join(version.to_string())
    }
    fn upload_path(&self, upload: UploadId) -> PathBuf {
        self.root.join(INCOMING_DIR).join(upload.to_string())
    }

    /// Create and fsync `dir` and every ancestor down to `root`, once per
    /// process. The rename that follows is only as durable as these entries.
    fn ensure_dir(&self, dir: &Path) -> Result<()> {
        {
            let known = self.durable_dirs.lock().unwrap_or_else(|p| p.into_inner());
            if known.contains(dir) {
                return Ok(());
            }
        }
        fs::create_dir_all(dir)?;
        // Sync the chain leaf-first; stop at a directory already durable.
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

    /// Stream `reader` to `tmp/`, hash, verify against `expect` and `limit`,
    /// then publish into `objects/<tenant>/` (fsync file, atomic rename,
    /// fsync directory). The returned [`Staged`] is durable but unreachable
    /// until [`Objects::commit`] lands its row.
    ///
    /// `limit` bounds the staged bytes; over it the temp file is removed and
    /// nothing is staged. Deduplication is automatic: a second `stage` of
    /// the same content lands on the same path, and `commit` is a no-op.
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
            let (digest, len) = {
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
                    // Admit before the bytes land so a refused stage leaves
                    // nothing but the temp file it already wrote.
                    if let Some(a) = &admission {
                        a.admit(tenant, got as u64)?;
                        charged += got as u64;
                    }
                    hasher.update(&buf[..got]);
                    file.write_all(&buf[..got])?;
                }
                file.sync_data()?;
                (Digest(*hasher.finalize().as_bytes()), len)
            };
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
            let path = self.object_path(tenant, &digest);
            self.ensure_dir(path.parent().expect("object path has a parent"))?;
            let created = if !path.exists() {
                fs::rename(&tmp, &path)?;
                if let Some(dir) = path.parent() {
                    sync_dir(dir)?;
                }
                true
            } else {
                // Same tenant, same digest: the committed bytes are
                // identical, so the duplicate stage is redundant work.
                let _ = fs::remove_file(&tmp);
                false
            };
            Ok(Staged {
                tenant,
                digest,
                len,
                path,
                created,
                charge: None,
            })
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

    /// Open a staged write under `tmp/` for a body that arrives in pieces —
    /// link artifact frames, where no `Read` exists. `limit` bounds the
    /// total; dropping the [`Staging`] discards the temp file.
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

    /// Append to an open staged write. Over the declared `limit` is refused
    /// without writing; the file keeps what it already holds.
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

    /// Verify the write total is `expected`, `fdatasync`, rename into
    /// `objects/<tenant>/` and fsync the directory: the durable half of the
    /// commit, identical to what [`Objects::stage`] leaves behind. The
    /// returned [`Staged`] publishes through [`Objects::commit`].
    pub fn stage_seal(&self, tenant: TenantId, staging: Staging, expected: u64) -> Result<Staged> {
        if staging.written != expected {
            return Err(Error::InvalidInput("object length"));
        }
        staging.file.sync_data()?;
        let digest = Digest(*staging.hasher.finalize().as_bytes());
        let path = self.object_path(tenant, &digest);
        self.ensure_dir(path.parent().expect("object path has a parent"))?;
        let created = if !path.exists() {
            fs::rename(&staging.tmp, &path)?;
            if let Some(dir) = path.parent() {
                sync_dir(dir)?;
            }
            true
        } else {
            false
        };
        // `into_parts` consumes without the Drop removal firing; the
        // admission charge moves into the `Staged` it becomes.
        let (_, _, charge) = staging.into_parts();
        Ok(Staged {
            tenant,
            digest,
            len: expected,
            path,
            created,
            charge,
        })
    }

    /// Publish a staged object: the reference commit. Idempotent — a second
    /// commit of the same (tenant, digest) reports `false`. Fails `NotFound`
    /// for an unknown tenant via the foreign key. A commit that would take
    /// the tenant over quota fails `QuotaExceeded`; returning `Err` leaves
    /// the transaction uncommitted — the caller must not swallow it.
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
            // A stage-sourced commit: `len` just entered usage and is still
            // counted in-flight, so `owed - len` is what the tenant owns
            // once the charge releases. Upload seals skip the check — they
            // swap a declared reservation for the object, never add usage.
            let quota = self.quota(tx, staged.tenant)?;
            if quota > 0 && self.owed(tx, staged.tenant)?.saturating_sub(staged.len) > quota {
                return Err(Error::QuotaExceeded);
            }
        }
        Ok(changed == 1)
    }

    /// Committed metadata for an object; `NotFound` covers foreign tenants.
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

    /// Open a committed object for reading. A row without its file is
    /// corruption, reported as such rather than `NotFound`.
    pub fn open_object(&self, conn: &Connection, tenant: TenantId, digest: Digest) -> Result<File> {
        self.meta(conn, tenant, digest)?;
        File::open(self.object_path(tenant, &digest)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Corrupt("object missing"),
            _ => Error::Io(e),
        })
    }

    /// Stream a committed object into `out`, rehashing as it goes; the
    /// digest and length must match the committed row or `Corrupt` is
    /// returned and the bytes already written are the caller's to discard.
    pub fn read(
        &self,
        conn: &Connection,
        tenant: TenantId,
        digest: Digest,
        out: &mut impl Write,
    ) -> Result<u64> {
        let meta = self.meta(conn, tenant, digest)?;
        let mut file =
            File::open(self.object_path(tenant, &digest)).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::Corrupt("object missing"),
                _ => Error::Io(e),
            })?;
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

    /// Commit a new manifest version. The version is chosen inside the
    /// transaction (`MAX(version)+1`), every referenced object must already
    /// be committed for this tenant, the manifest file is staged, synced and
    /// renamed, and the row is inserted — all or nothing visible.
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
        for entry in entries {
            if !valid_entry_path(&entry.path) {
                return Err(Error::InvalidInput("entry path"));
            }
            // A manifest may only point at bytes the tenant already owns:
            // the object row is the reference commit, so its absence would
            // make the manifest dangle.
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
        // Manifest files are small but real bytes: admit them so a burst of
        // manifests cannot race the watermark either. The charge releases
        // once the file is durable — the probe accounts it from then on.
        let admission = self.admission.get().cloned();
        if let Some(a) = &admission {
            a.admit(tenant, body.len() as u64)?;
        }
        let landed = (|| -> Result<()> {
            // Write the manifest through the same stage discipline as objects.
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

    /// Read a manifest: the given version, or the latest when `None`. The
    /// file is parsed and verified against the committed digest.
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

    /// Startup reconciliation: sweep incomplete staged writes, then compare
    /// the `objects/` and `manifests/` trees against committed rows.
    /// Orphans are reported, never deleted — a staged-but-uncommitted file
    /// and a leaked file look identical, and reclamation is a separate stage.
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
        // Committed objects: (tenant, digest) -> len.
        let mut committed: HashMap<(TenantId, Digest), u64> = HashMap::new();
        let mut rows = conn.prepare("SELECT tenant_id, digest, len FROM objects")?;
        let mut query = rows.query([])?;
        while let Some(row) = query.next()? {
            let tenant = tenant_from(row.get::<_, Vec<u8>>(0)?)?;
            let digest = Digest::from_bytes(
                <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(1)?.as_slice())
                    .map_err(|_| Error::Corrupt("object digest"))?,
            );
            committed.insert((tenant, digest), row.get::<_, i64>(2)? as u64);
        }
        drop(query);
        drop(rows);
        // Walk the object tree; unknown files are orphans, wrong lengths are
        // corrupt, then rows with no file are missing.
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
            self.walk_objects(&entry.path(), tenant, &mut committed, &mut report)?;
        }
        for ((tenant, digest), _) in committed {
            report.missing.push(self.object_path(tenant, &digest));
        }
        self.recover_manifests(conn, &mut report)?;
        // Staging files for resumable uploads: an open row keeps its file;
        // anything else under incoming/ is swept — no committed object can
        // have come from it, since sealing renames the file away.
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
        committed: &mut HashMap<(TenantId, Digest), u64>,
        report: &mut Recovery,
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
                        Some(len) if entry.metadata()?.len() == len => {}
                        Some(_) => report.corrupt.push(path),
                        None => report.orphans.push(path),
                    },
                    _ => report.orphans.push(path),
                }
            }
        }
        Ok(())
    }

    /// Manifest files are keyed by name hash; a row check joins through the
    /// stored name so a file under a foreign hash is an orphan even when a
    /// same-version manifest exists.
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

    /// Rehash every committed object. The deep check [`Objects::recover`]
    /// does not do: it catches content rot, not just missing or truncated
    /// files. Bounded by store size — run it as a drill, not per request.
    pub fn verify(&self, conn: &Connection) -> Result<Vec<Corrupt>> {
        let mut rows = conn.prepare("SELECT tenant_id, digest, len FROM objects")?;
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
            let bad = match File::open(&path) {
                Err(_) => true,
                Ok(mut file) => {
                    let mut hasher = blake3::Hasher::new();
                    let mut got_total = 0u64;
                    let mut failed = false;
                    loop {
                        match file.read(&mut buf) {
                            Ok(0) => break,
                            Ok(got) => {
                                got_total += got as u64;
                                hasher.update(&buf[..got]);
                            }
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    failed || got_total != len || Digest(*hasher.finalize().as_bytes()) != digest
                }
            };
            if bad {
                corrupt.push(Corrupt {
                    tenant,
                    digest,
                    path,
                });
            }
        }
        Ok(corrupt)
    }

    /// Open a committed object for ranged reads while registering a live
    /// reader. The returned guard keeps the object counted until it is
    /// dropped; reclamation must consult [`Objects::reader_active`].
    pub fn open_read(
        &self,
        conn: &Connection,
        tenant: TenantId,
        digest: Digest,
    ) -> Result<(Reader, u64)> {
        let meta = self.meta(conn, tenant, digest)?;
        let file = File::open(self.object_path(tenant, &digest)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Corrupt("object missing"),
            _ => Error::Io(e),
        })?;
        let mut readers = self.readers.lock().unwrap_or_else(|p| p.into_inner());
        *readers.entry((tenant, digest)).or_insert(0) += 1;
        Ok((
            Reader {
                file,
                key: (tenant, digest),
                readers: std::sync::Arc::clone(&self.readers),
            },
            meta.len,
        ))
    }

    /// Whether any reader currently holds this object. Reclamation checks
    /// this before unlinking; the check and the unlink are the GC stage's
    /// responsibility to serialize.
    pub fn reader_active(&self, tenant: TenantId, digest: Digest) -> bool {
        self.readers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&(tenant, digest))
    }

    /// Begin a resumable upload: the row and a staging file sized to the
    /// declared length, in the same transaction. `digest` may be omitted;
    /// `seal_upload` then reports whatever the content hashed to.
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
        // The declared length is reserved in `tenant_usage` the moment the
        // row inserts, so the projected total is what the tenant will owe.
        let quota = self.quota(tx, tenant)?;
        if quota > 0 && self.owed(tx, tenant)?.saturating_add(declared_len) > quota {
            return Err(Error::QuotaExceeded);
        }
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

    /// The tenant that owns an upload row. The API resolves this before
    /// checking the caller's membership so a foreign id is indistinguishable
    /// from a missing one.
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

    /// A resumable upload's durable state: what the client still owes.
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

    /// Write one chunk at `offset` into the staging file, then record the
    /// range — bytes before bookkeeping, so a crash can never claim bytes it
    /// does not have. Re-sending an identical range is idempotent (the
    /// ranges merge; `received` counts bytes once).
    pub fn put_chunk(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        id: UploadId,
        offset: u64,
        bytes: &[u8],
        now: UnixMillis,
    ) -> Result<u64> {
        let row = upload_row(tx, tenant, id)?.ok_or(Error::NotFound)?;
        if row.state != UploadState::Open {
            return Err(Error::Conflict);
        }
        if row.expires_ms <= now.0 {
            // Touching an expired session retires it: the row can no longer
            // be resumed and the staged bytes become recoverable garbage.
            tx.execute(
                "UPDATE uploads SET state_code = 2 WHERE id = ?1 AND state_code = 0",
                params![id.as_bytes().as_slice()],
            )?;
            if let Some(a) = self.admission.get() {
                a.release_upload(id);
            }
            let _ = fs::remove_file(self.upload_path(id));
            return Err(Error::InvalidInput("upload expired"));
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= row.declared_len)
            .ok_or(Error::InvalidInput("chunk range"))?;
        // Admit only the bytes this chunk actually adds — resent ranges
        // merge to a zero delta and stay free.
        let mut ranges = row.ranges.clone();
        ranges_insert(&mut ranges, offset, end)?;
        let received: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        let delta = received - row.received;
        if let Some(a) = self.admission.get() {
            a.admit_untracked(id, delta)?;
        }
        let landed = (|| -> Result<()> {
            let mut file = OpenOptions::new().write(true).open(self.upload_path(id))?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(bytes)?;
            file.sync_data()?;
            tx.execute(
                "UPDATE uploads SET ranges = ?2, received = ?3 WHERE id = ?1 AND state_code = 0",
                params![
                    id.as_bytes().as_slice(),
                    encode_ranges(&ranges),
                    received as i64
                ],
            )?;
            Ok(())
        })();
        if landed.is_err()
            && let Some(a) = self.admission.get()
        {
            // The ranges row never recorded them, so a retry charges the
            // same delta again — return this one rather than double-count.
            a.release_upload_delta(id, delta);
        }
        landed?;
        Ok(received)
    }

    /// Finish the upload: the ranges must tile the declared length, the
    /// content must match the declared digest when one was given, then the
    /// file is renamed into `objects/` and the reference committed — all
    /// inside the caller's transaction. Sealing twice answers the same
    /// digest; sealing an aborted upload is a conflict. An expired session
    /// is retired rather than published.
    pub fn seal_upload(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        id: UploadId,
        now: UnixMillis,
    ) -> Result<Digest> {
        let row = upload_row(tx, tenant, id)?.ok_or(Error::NotFound)?;
        if row.state == UploadState::Committed {
            return row.object_digest.ok_or(Error::Corrupt("upload digest"));
        }
        if row.state == UploadState::Aborted {
            return Err(Error::Conflict);
        }
        if row.expires_ms <= now.0 {
            tx.execute(
                "UPDATE uploads SET state_code = 2 WHERE id = ?1 AND state_code = 0",
                params![id.as_bytes().as_slice()],
            )?;
            if let Some(a) = self.admission.get() {
                a.release_upload(id);
            }
            let _ = fs::remove_file(self.upload_path(id));
            return Err(Error::InvalidInput("upload expired"));
        }
        let path = self.upload_path(id);
        let complete = row.ranges.as_slice() == [(0, row.declared_len)]
            || row.declared_len == 0 && row.ranges.is_empty();
        if !complete {
            return Err(Error::InvalidInput("upload incomplete"));
        }
        // A previous seal may have renamed into objects/ and then lost its
        // transaction: the staging file is gone but the upload row stayed
        // open. Recover through the declared digest rather than wedging —
        // without one the computed destination is unknowable and the
        // upload is genuinely unrecoverable.
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
        // A mismatch is not fatal: the staged bytes stay, so the client can
        // rewrite whichever ranges were wrong and seal again.
        if row.digest.is_some_and(|declared| declared != digest) {
            return Err(Error::InvalidInput("upload digest"));
        }
        let object = self.object_path(tenant, &digest);
        self.ensure_dir(object.parent().expect("object path has a parent"))?;
        let created = if object.exists() {
            let _ = fs::remove_file(&path);
            false
        } else if recovered {
            return Err(Error::Corrupt("upload file"));
        } else {
            fs::rename(&path, &object)?;
            if let Some(dir) = object.parent() {
                sync_dir(dir)?;
            }
            true
        };
        // Close the upload first: its declared-length reservation leaves
        // `tenant_usage` as the object row's length enters it, so the seal
        // is net-zero against the tenant's quota rather than double-counted.
        tx.execute(
            "UPDATE uploads SET state_code = 1, object_digest = ?2 WHERE id = ?1",
            params![id.as_bytes().as_slice(), digest.as_bytes().as_slice()],
        )?;
        self.commit(
            tx,
            &Staged {
                tenant,
                digest,
                len: row.declared_len,
                path: object,
                created,
                charge: None,
            },
        )?;
        if let Some(a) = self.admission.get() {
            a.release_upload(id);
        }
        Ok(digest)
    }

    /// Give up on an open upload and remove its staging file. A committed
    /// upload cannot be aborted — its object is already reachable.
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

    /// Abort open uploads past their expiry and drop their staging files.
    /// Returns how many were retired; at most [`SWEEP_BATCH`] per call.
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

    /// Backfill `manifest_refs` for manifests committed before the edges
    /// existed (`refs_indexed = 0`). Reads each manifest file, inserts its
    /// edges and flips the flag — all inside the caller's transaction, at
    /// most `limit` manifests per call. A manifest that will not decode is
    /// skipped: its tenant's objects stay unreclaimable until it is fixed.
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
                // Corrupt or missing: leave unindexed — reclamation refuses
                // to collect objects under a tenant it cannot fully see.
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

    /// Delete one manifest version's row; its `manifest_refs` edges cascade.
    /// Returns the file path for the caller to unlink once the transaction
    /// commits — a crash between commit and unlink leaves an orphan the
    /// file sweep later collects.
    pub fn retire_manifest(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: u64,
    ) -> Result<Option<PathBuf>> {
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
        Ok((deleted == 1).then(|| self.manifest_path(tenant, kind, name.as_bytes(), version)))
    }

    /// Collect reclaimable objects: committed past `UNREFERENCED_GRACE_MS`,
    /// not referenced by any indexed manifest, not leased, not still
    /// decodable through an unindexed manifest (a tenant with any
    /// `refs_indexed = 0` row is skipped entirely), and not being streamed
    /// by a live reader. Rows are deleted in this transaction; the caller
    /// unlinks the returned paths after commit.
    pub fn reclaim(&self, tx: &Transaction<'_>, now: UnixMillis, limit: i64) -> Result<Reclaimed> {
        let cutoff = now.0 - UNREFERENCED_GRACE_MS;
        let candidates: Vec<(Vec<u8>, Vec<u8>, i64)> = tx
            .prepare(
                "SELECT o.tenant_id, o.digest, o.len FROM objects o
                 WHERE o.created_ms <= ?1
                   AND NOT EXISTS(SELECT 1 FROM manifest_refs r
                                  WHERE r.tenant_id = o.tenant_id
                                    AND r.digest = o.digest)
                   AND NOT EXISTS(SELECT 1 FROM object_leases l
                                  WHERE l.tenant_id = o.tenant_id
                                    AND l.digest = o.digest
                                    AND l.until_ms > ?2)
                   AND NOT EXISTS(SELECT 1 FROM manifests m
                                  WHERE m.tenant_id = o.tenant_id
                                    AND m.refs_indexed = 0)
                 LIMIT ?3",
            )?
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
            reclaimed.paths.push(self.object_path(tenant, &digest));
        }
        Ok(reclaimed)
    }

    /// Sweep files with no row: objects or manifests a commit orphaned, and
    /// `tmp/` leftovers a restart's `recover` never saw. Only files whose
    /// mtime is older than `FILE_ORPHAN_GRACE_MS` go — an in-flight commit's
    /// just-renamed file is younger than its row insert by milliseconds.
    /// Returns the number unlinked, at most `limit`.
    pub fn sweep_orphans(&self, conn: &Connection, limit: u32) -> Result<u32> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
            - FILE_ORPHAN_GRACE_MS;
        let mut swept = 0u32;
        let gone = |path: &Path, swept: &mut u32, limit: u32| -> bool {
            if *swept >= limit {
                return false;
            }
            let old = fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .is_some_and(|age| (age.as_millis() as i64) < cutoff);
            if old && fs::remove_file(path).is_ok() {
                *swept += 1;
            }
            true
        };
        // Committed manifest files: the path set is small enough to hold.
        let mut manifests = HashSet::new();
        let mut rows = conn.prepare("SELECT tenant_id, kind, name, version FROM manifests")?;
        let mut query = rows.query([])?;
        while let Some(row) = query.next()? {
            manifests.insert(self.manifest_path(
                tenant_from(row.get::<_, Vec<u8>>(0)?)?,
                Kind::from_code(row.get::<_, i64>(1)? as u8)?,
                &row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)? as u64,
            ));
        }
        drop(query);
        drop(rows);
        let root = self.manifests_root();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(path);
                } else if !manifests.contains(&path) && !gone(&path, &mut swept, limit) {
                    return Ok(swept);
                }
            }
        }
        // Object files check their row directly — one prepared statement,
        // no whole-table materialization.
        let mut has_row = conn
            .prepare("SELECT EXISTS(SELECT 1 FROM objects WHERE tenant_id = ?1 AND digest = ?2)")?;
        let objects = self.objects_root();
        let Ok(tenants) = fs::read_dir(&objects) else {
            return Ok(swept);
        };
        for tenant_dir in tenants.flatten() {
            let Ok(tenant) = tenant_dir.file_name().to_string_lossy().parse::<TenantId>() else {
                if tenant_dir.path().is_file() && !gone(&tenant_dir.path(), &mut swept, limit) {
                    return Ok(swept);
                }
                continue;
            };
            let Ok(prefixes) = fs::read_dir(tenant_dir.path()) else {
                continue;
            };
            for prefix in prefixes.flatten() {
                if prefix.file_type().is_ok_and(|t| t.is_file()) {
                    // Stray file directly under objects/<tenant>/ — no row
                    // can own a path outside the prefix layout.
                    if !gone(&prefix.path(), &mut swept, limit) {
                        return Ok(swept);
                    }
                    continue;
                }
                let Ok(entries) = fs::read_dir(prefix.path()) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !entry.file_type().is_ok_and(|t| t.is_file()) {
                        continue;
                    }
                    let Ok(digest) = Digest::parse(&entry.file_name().to_string_lossy()) else {
                        if !gone(&path, &mut swept, limit) {
                            return Ok(swept);
                        }
                        continue;
                    };
                    let committed = has_row
                        .query_row(
                            params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(true);
                    if !committed && !gone(&path, &mut swept, limit) {
                        return Ok(swept);
                    }
                }
            }
        }
        // `tmp/` leftovers: no row can ever claim them — the grace alone
        // decides (a live stage's file is always fresh).
        let tmp = self.root.join(TMP_DIR);
        if let Ok(entries) = fs::read_dir(&tmp) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file())
                    && !gone(&entry.path(), &mut swept, limit)
                {
                    return Ok(swept);
                }
            }
        }
        Ok(swept)
    }
    /// are re-validated, every ancestor under `dest` is checked for symlinks
    /// and the file itself is created `O_EXCL`-style (existing targets are
    /// refused), so a prepared directory cannot redirect the extract outside
    /// itself. Content is verified while streaming.
    pub fn materialize(
        &self,
        conn: &Connection,
        tenant: TenantId,
        kind: Kind,
        name: &str,
        version: Option<u64>,
        dest: &Path,
    ) -> Result<u64> {
        let manifest = self.manifest(conn, tenant, kind, name, version)?;
        fs::create_dir_all(dest)?;
        let mut written = 0u64;
        for entry in &manifest.entries {
            let mut path = dest.to_path_buf();
            for part in entry.path.split('/') {
                path.push(part);
                // A symlinked component could redirect the write outside
                // dest; refuse it and anything else that is not a directory
                // before descending.
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
            #[cfg(unix)]
            if entry.mode != 0 {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(entry.mode))?;
            }
            written += entry.len;
        }
        sync_dir(dest)?;
        Ok(written)
    }
}

/// A live object reader: the file plus the registration that keeps GC from
/// reclaiming it. Drops itself out of the count.
pub struct Reader {
    file: File,
    key: (TenantId, Digest),
    readers: std::sync::Arc<Mutex<HashMap<(TenantId, Digest), u64>>>,
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
        let mut readers = self.readers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = readers.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                readers.remove(&self.key);
            }
        }
    }
}

/// Durable upload session state (the `uploads` row decoded).
struct UploadRow {
    state: UploadState,
    declared_len: u64,
    /// The digest the client declared at `begin_upload`; verified at seal.
    digest: Option<Digest>,
    received: u64,
    ranges: Vec<(u64, u64)>,
    expires_ms: i64,
    object_digest: Option<Digest>,
}

/// Where an upload session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    Open = 0,
    Committed = 1,
    Aborted = 2,
}

/// What a resuming client needs to know.
#[derive(Clone, Debug)]
pub struct UploadStatus {
    pub state: UploadState,
    pub declared_len: u64,
    pub received: u64,
    /// Sorted, disjoint, non-adjacent byte ranges the controller holds.
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

/// Merge `[start, end)` into a sorted disjoint range set, coalescing
/// overlaps and adjacency. Refuses once the set would exceed
/// [`MAX_UPLOAD_RANGES`] — a fragmented upload is a client bug to fix by
/// sending ordered chunks, not something the store should track forever.
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

/// fsync a directory so a rename inside it is durable. No-op off unix:
/// the store's durable roles run on Linux and directory fsync is not part
/// of the portable surface.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// A manifest entry path is a relative archive path: `/`-separated, every
/// component non-empty and never `.` or `..`, and free of separators and
/// characters that could escape or reinterpret under extraction (`\`, `:`,
/// NUL, a leading `/` or drive prefix).
pub fn valid_entry_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_ENTRY_PATH || path.starts_with('/') {
        return false;
    }
    path.split('/').all(|part| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', ':', '\0'])
    })
}

/// Serialize a manifest version. Deterministic: same inputs, same digest.
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
