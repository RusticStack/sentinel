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
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use rusqlite::{Connection, OptionalExtension, Transaction};
use sentinel_core::{TenantId, UnixMillis};

use crate::{Error, Result};

pub const OBJECTS_DIR: &str = "objects";
pub const MANIFESTS_DIR: &str = "manifests";
pub const TMP_DIR: &str = "tmp";
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
    /// Remove the staged file (it is already at its final path; without a
    /// committed row it is an orphan either way).
    pub fn discard(self) {
        let _ = fs::remove_file(&self.path);
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

/// The object and manifest tree under one data directory. Filesystem work
/// happens here; reference commits happen inside the caller's transaction.
pub struct Objects {
    root: PathBuf,
    /// Directories already created and synced this process. Creating a
    /// tenant's subtree needs one fsync chain, not one per object.
    durable_dirs: Mutex<HashSet<PathBuf>>,
    tmp_seq: AtomicU64,
}

impl Objects {
    /// Open (creating) `objects/`, `manifests/` and `tmp/` under `root`.
    /// Does not recover; call [`Objects::recover`] at startup.
    pub fn open(root: impl Into<PathBuf>) -> Result<Objects> {
        let root = root.into();
        for dir in [OBJECTS_DIR, MANIFESTS_DIR, TMP_DIR] {
            fs::create_dir_all(root.join(dir))?;
        }
        sync_dir(&root)?;
        Ok(Objects {
            root,
            durable_dirs: Mutex::new(HashSet::new()),
            tmp_seq: AtomicU64::new(0),
        })
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
        let tmp = self.tmp();
        let (digest, len) = {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
            let result = (|| -> Result<(Digest, u64)> {
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
                    hasher.update(&buf[..got]);
                    file.write_all(&buf[..got])?;
                }
                file.sync_data()?;
                Ok((Digest(*hasher.finalize().as_bytes()), len))
            })();
            if result.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            result?
        };
        if let Some(declared) = expect.len
            && declared != len
        {
            let _ = fs::remove_file(&tmp);
            return Err(Error::InvalidInput("object length"));
        }
        if let Some(declared) = expect.digest
            && declared != digest
        {
            let _ = fs::remove_file(&tmp);
            return Err(Error::InvalidInput("object digest"));
        }
        let path = self.object_path(tenant, &digest);
        self.ensure_dir(path.parent().expect("object path has a parent"))?;
        if !path.exists() {
            fs::rename(&tmp, &path)?;
            if let Some(dir) = path.parent() {
                sync_dir(dir)?;
            }
        } else {
            // Same tenant, same digest: the committed bytes are identical,
            // so the duplicate stage is simply redundant work.
            let _ = fs::remove_file(&tmp);
        }
        Ok(Staged {
            tenant,
            digest,
            len,
            path,
        })
    }

    /// Publish a staged object: the reference commit. Idempotent — a second
    /// commit of the same (tenant, digest) reports `false`. Fails `NotFound`
    /// for an unknown tenant via the foreign key.
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
        // Write the manifest through the same stage discipline as objects.
        self.ensure_dir(path.parent().expect("manifest path has a parent"))?;
        {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
            let result = file.write_all(&body).and_then(|()| file.sync_data());
            if result.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            result?;
        }
        fs::rename(&tmp, &path)?;
        if let Some(dir) = path.parent() {
            sync_dir(dir)?;
        }
        let written = tx.execute(
            "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries, payload_len, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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

fn tenant_from(bytes: Vec<u8>) -> Result<TenantId> {
    TenantId::from_bytes(
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("tenant id"))?,
    )
    .map_err(|_| Error::Corrupt("tenant id"))
}

/// fsync a directory so a rename inside it is durable. No-op off unix:
/// the store's durable roles run on Linux and directory fsync is not part
/// of the portable surface.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// A manifest entry path is a relative archive path: `/`-separated, every
/// component non-empty and never `.` or `..`, and free of separators and
/// characters that could escape or reinterpret under extraction (`\`, `:`,
/// NUL, a leading `/` or drive prefix).
fn valid_entry_path(path: &str) -> bool {
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
