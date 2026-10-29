//! Objects and manifests are immutable and the maintenance lock is held until the last copy, so no named file can be reclaimed mid-backup.
//! ```text
//! <target>/objects/…              committed objects, content-addressed (shared)
//! <target>/manifests/…            manifest versions, immutable (shared)
//! <target>/logs/…                 attempt logs, mirrored incrementally (shared)
//! <target>/<id>/metadata.sqlite   the database at one instant
//! <target>/<id>/config/…          the controller's own files (never the key)
//! <target>/<id>/backup.json       what it holds, with checksums
//! ```

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags};
use sentinel_core::{AttemptId, TenantId, UnixMillis};
use serde_json::{Value, json};

use crate::{
    Error, Result, Store,
    objects::{Digest, Objects, manifest_relpath, object_relpath, sync_dir},
};

pub const FORMAT: &str = "sentinel.backup/1";
const METADATA: &str = "metadata.sqlite";
const MANIFEST: &str = "backup.json";
const CONFIG_DIR: &str = "config";
pub const CONFIG_FILES: &[&str] = &[
    "controller.crt",
    "controller.key",
    "github-app.json",
    "github-webhook.json",
    "github-sign-in.json",
    "source-destinations.json",
    "tailcat-allow",
];
const CONFIG_DIRS: &[&str] = &["tailcat"];
const CHUNK: usize = 1 << 20;

fn io(context: &str, error: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        error.kind(),
        format!("{context}: {error}"),
    ))
}

/// Directories this module creates are owner-only, as the live data directory is: they hold every tenant's objects and the sealed database.
fn private_dir_all(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)
}

/// Files this module creates are owner-only from the first byte, so the key files are never readable between a copy and a chmod.
fn private_file() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// A directory that already existed keeps its mode, so the caller is told when others can open it.
#[cfg(unix)]
fn open_to_others(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(dir).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

#[cfg(not(unix))]
fn open_to_others(_dir: &Path) -> bool {
    false
}

fn note_dirs(dirty: &mut BTreeSet<PathBuf>, from: &Path, root: &Path) {
    let mut dir = from;
    loop {
        if dirty.contains(dir) {
            return;
        }
        dirty.insert(dir.to_path_buf());
        match dir.parent() {
            Some(parent) if dir != root && parent.starts_with(root) => dir = parent,
            _ => return,
        }
    }
}

fn sync_dirs(dirty: &BTreeSet<PathBuf>) -> Result<()> {
    for dir in dirty {
        sync_dir(dir)?;
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> Result<(Digest, u64)> {
    let mut dirty = BTreeSet::new();
    let copied = copy_file_into(src, dst, dst.parent().unwrap_or(dst), &mut dirty)?;
    sync_dirs(&dirty)?;
    Ok(copied)
}

fn copy_file_into(
    src: &Path,
    dst: &Path,
    root: &Path,
    dirty: &mut BTreeSet<PathBuf>,
) -> Result<(Digest, u64)> {
    let mut input = File::open(src).map_err(|e| io(&src.display().to_string(), e))?;
    if let Some(parent) = dst.parent() {
        private_dir_all(parent)?;
        note_dirs(dirty, parent, root);
    }
    let tmp = dst.with_extension("part");
    let mut out = private_file()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut len = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        len += n as u64;
    }
    out.sync_data()?;
    drop(out);
    fs::rename(&tmp, dst)?;
    Ok((Digest::from_bytes(*hasher.finalize().as_bytes()), len))
}

// A prune from another process would delete shared objects that no kept backup names yet.
const LOCK: &str = ".lock";

fn lock_target(target: &Path) -> Result<File> {
    let file = private_file()
        .create(true)
        .truncate(false)
        .write(true)
        .open(target.join(LOCK))?;
    match file.lock() {
        Ok(()) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => Ok(file),
        Err(e) => Err(io("backup lock", e)),
    }
}

fn hash_file(path: &Path) -> Result<(Digest, u64)> {
    let mut input = File::open(path).map_err(|e| io(&path.display().to_string(), e))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut len = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((Digest::from_bytes(*hasher.finalize().as_bytes()), len))
}

fn open_snapshot(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

fn tenant(bytes: Vec<u8>) -> Result<TenantId> {
    TenantId::from_bytes(
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("tenant_id"))?,
    )
    .map_err(|_| Error::Corrupt("tenant_id"))
}

fn digest(bytes: Vec<u8>) -> Result<Digest> {
    Ok(Digest::from_bytes(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("digest"))?,
    ))
}

struct ObjectRow {
    rel: PathBuf,
    digest: Digest,
    len: u64,
    remote_only: bool,
}

fn object_rows(snapshot: &Connection) -> Result<Vec<ObjectRow>> {
    let mut stmt =
        snapshot.prepare("SELECT tenant_id, digest, len, evicted_ms IS NOT NULL FROM objects")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let t = tenant(row.get(0)?)?;
        let d = digest(row.get(1)?)?;
        out.push(ObjectRow {
            rel: object_relpath(t, &d),
            digest: d,
            len: row.get::<_, i64>(2)?.max(0) as u64,
            remote_only: row.get(3)?,
        });
    }
    Ok(out)
}

fn manifest_rows(snapshot: &Connection) -> Result<Vec<(PathBuf, Digest)>> {
    let mut stmt =
        snapshot.prepare("SELECT tenant_id, kind, name, version, digest FROM manifests")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let t = tenant(row.get(0)?)?;
        let kind: i64 = row.get(1)?;
        let name: Vec<u8> = row.get(2)?;
        let version: i64 = row.get(3)?;
        out.push((
            manifest_relpath(t, kind as u8, &name, version.max(0) as u64),
            digest(row.get(4)?)?,
        ));
    }
    Ok(out)
}

fn kept_logs(snapshot: &Connection) -> Result<HashSet<AttemptId>> {
    let mut stmt = snapshot.prepare("SELECT id FROM attempts WHERE log_expired_ms IS NULL")?;
    let mut rows = stmt.query([])?;
    let mut out = HashSet::new();
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice())
            && let Ok(id) = AttemptId::from_bytes(id)
        {
            out.insert(id);
        }
    }
    Ok(out)
}

pub fn backup_id(now: UnixMillis) -> String {
    let secs = now.0.max(0) as u64 / 1_000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3_600,
        (rem / 60) % 60,
        rem % 60
    )
}

fn valid_id(id: &str) -> bool {
    id.len() == 16
        && id.as_bytes()[8] == b'T'
        && id.ends_with('Z')
        && id.bytes().filter(|b| b.is_ascii_digit()).count() == 14
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub id: String,
    pub metadata_bytes: u64,
    pub objects: u64,
    pub objects_copied: u64,
    pub object_bytes_copied: u64,
    pub objects_recopied: u64,
    pub manifests_recopied: u64,
    pub objects_remote: u64,
    pub objects_corrupt: Vec<String>,
    pub objects_missing: Vec<String>,
    pub partials_removed: u64,
    /// The target directory already existed and group or other accounts can open it: its mode is the operator's to tighten.
    pub target_open_to_others: bool,
    pub manifests: u64,
    pub manifests_copied: u64,
    pub log_files_copied: u64,
    pub log_bytes_copied: u64,
    pub config_files: Vec<String>,
    pub key_ids: BTreeSet<u32>,
    pub took_ms: i64,
}

pub fn create(
    store: &Store,
    objects: &Objects,
    data_dir: &Path,
    target: &Path,
    version: &str,
) -> Result<Report> {
    let started = UnixMillis::now();
    private_dir_all(target)?;
    let _writer = lock_target(target)?;
    let mut id = backup_id(started);
    if target.join(&id).exists() {
        std::thread::sleep(std::time::Duration::from_millis(1_000));
        id = backup_id(UnixMillis::now());
    }
    let _maintenance = objects.hold_maintenance();
    let partials_removed = remove_partials(target)?;
    let staging = target.join(format!(".{id}.partial"));
    private_dir_all(&staging)?;

    let snapshot_path = staging.join(METADATA);
    store.snapshot_into(&snapshot_path)?;
    // The staging directory is closed to others already; the file is restricted too in case the backup is ever moved out of it.
    restrict(&snapshot_path)?;
    File::open(&snapshot_path)?.sync_all()?;
    let (metadata_digest, metadata_bytes) = hash_file(&snapshot_path)?;
    let snapshot = open_snapshot(&snapshot_path)?;
    let schema: i64 =
        snapshot.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })?;
    let mut report = Report {
        id: id.clone(),
        metadata_bytes,
        key_ids: crate::reseal::key_ids(&snapshot)?,
        partials_removed,
        target_open_to_others: open_to_others(target),
        ..Report::default()
    };

    let mut dirty = BTreeSet::new();
    for row in object_rows(&snapshot)? {
        report.objects += 1;
        if row.remote_only {
            report.objects_remote += 1;
            continue;
        }
        let dst = target.join(&row.rel);
        // A length match proves nothing about rot, so a reused copy is rehashed.
        if fs::metadata(&dst).is_ok_and(|m| m.len() == row.len) {
            if hash_file(&dst).is_ok_and(|(d, len)| d == row.digest && len == row.len) {
                continue;
            }
            report.objects_recopied += 1;
        }
        let (got, len) = match copy_file_into(&data_dir.join(&row.rel), &dst, target, &mut dirty) {
            Ok(copied) => copied,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                report.objects_missing.push(row.rel.display().to_string());
                continue;
            }
            Err(e) => return Err(e),
        };
        if got != row.digest || len != row.len {
            let _ = fs::remove_file(&dst);
            report.objects_corrupt.push(row.rel.display().to_string());
            continue;
        }
        report.objects_copied += 1;
        report.object_bytes_copied += len;
    }
    for (rel, want) in manifest_rows(&snapshot)? {
        report.manifests += 1;
        let dst = target.join(&rel);
        if dst.exists() {
            if hash_file(&dst).is_ok_and(|(d, _)| d == want) {
                continue;
            }
            report.manifests_recopied += 1;
        }
        let (got, _) = copy_file_into(&data_dir.join(&rel), &dst, target, &mut dirty)?;
        if got != want {
            let _ = fs::remove_file(&dst);
            return Err(Error::Corrupt("manifest content"));
        }
        report.manifests_copied += 1;
    }
    drop(snapshot);

    let logs = data_dir.join(crate::logs::LOGS_DIR);
    if logs.exists() {
        let mut stack = vec![logs.clone()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir)?.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else { continue };
                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".tmp") {
                    continue;
                }
                let rel = path
                    .strip_prefix(data_dir)
                    .map_err(|_| Error::Corrupt("log path"))?;
                let dst = target.join(rel);
                let current = fs::metadata(&dst).ok();
                let changed = current.is_none_or(|d| {
                    d.len() != meta.len() || d.modified().ok() < meta.modified().ok()
                });
                if !changed {
                    continue;
                }
                match copy_file_into(&path, &dst, target, &mut dirty) {
                    Ok((_, len)) => {
                        report.log_files_copied += 1;
                        report.log_bytes_copied += len;
                    }
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }

    sync_dirs(&dirty)?;

    let config = staging.join(CONFIG_DIR);
    private_dir_all(&config)?;
    // The controller's link identity decides whether workers reconnect, so it is checksummed like the database.
    let mut config_sums = BTreeMap::new();
    for name in CONFIG_FILES {
        let src = data_dir.join(name);
        if src.is_file() {
            let (sum, _) = copy_file(&src, &config.join(name))?;
            restrict(&config.join(name))?;
            config_sums.insert((*name).to_owned(), sum.to_string());
            report.config_files.push((*name).to_owned());
        }
    }
    for name in CONFIG_DIRS {
        let src = data_dir.join(name);
        if src.is_dir() {
            for entry in fs::read_dir(&src)?.flatten() {
                if entry.metadata().is_ok_and(|m| m.is_file()) {
                    let dst = config.join(name).join(entry.file_name());
                    let (sum, _) = copy_file(&entry.path(), &dst)?;
                    restrict(&dst)?;
                    let rel = format!("{name}/{}", entry.file_name().to_string_lossy());
                    config_sums.insert(rel.clone(), sum.to_string());
                    report.config_files.push(rel);
                }
            }
        }
    }

    report.took_ms = UnixMillis::now().0 - started.0;
    let manifest = json!({
        "format": FORMAT,
        "id": id,
        "version": version,
        "schema": schema,
        "started_ms": started.0,
        "took_ms": report.took_ms,
        "metadata": { "file": METADATA, "bytes": metadata_bytes, "blake3": metadata_digest.to_string() },
        "objects": {
            "rows": report.objects,
            "remote_only": report.objects_remote,
            "copied": report.objects_copied,
            "bytes_copied": report.object_bytes_copied,
            "recopied": report.objects_recopied,
            "corrupt": report.objects_corrupt,
            "missing": report.objects_missing,
        },
        "manifests": { "rows": report.manifests, "copied": report.manifests_copied, "recopied": report.manifests_recopied },
        "logs": { "files_copied": report.log_files_copied, "bytes_copied": report.log_bytes_copied },
        "config": report.config_files,
        "config_blake3": config_sums,
        "key": {
            "required": !report.key_ids.is_empty(),
            "key_ids": report.key_ids,
            "note": "the master key is not in the backup; restore with the key file whose ids include these",
        },
    });
    let body =
        serde_json::to_vec_pretty(&manifest).map_err(|_| Error::Corrupt("backup manifest"))?;
    let mut file = private_file()
        .create(true)
        .truncate(true)
        .write(true)
        .open(staging.join(MANIFEST))?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    sync_dir(&staging)?;
    fs::rename(&staging, target.join(&id))?;
    sync_dir(target)?;
    Ok(report)
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

fn remove_partials(target: &Path) -> Result<u64> {
    let mut removed = 0;
    for entry in fs::read_dir(target)?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(id) = name
            .strip_prefix('.')
            .and_then(|n| n.strip_suffix(".partial"))
            && valid_id(id)
            && entry.metadata().is_ok_and(|m| m.is_dir())
        {
            fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn list(target: &Path) -> Result<Vec<String>> {
    let mut ids: Vec<String> = match fs::read_dir(target) {
        Ok(read) => read
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| valid_id(n) && target.join(n).join(MANIFEST).is_file())
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    ids.sort();
    Ok(ids)
}

pub fn manifest(target: &Path, id: &str) -> Result<Value> {
    if !valid_id(id) {
        return Err(Error::InvalidInput("backup id"));
    }
    let body = fs::read(target.join(id).join(MANIFEST)).map_err(|_| Error::NotFound)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| Error::Corrupt("backup manifest"))?;
    if value["format"] != FORMAT {
        return Err(Error::Corrupt("backup format"));
    }
    Ok(value)
}

/// What a loss at `now` would cost, read from the backups' own `started_ms` and `took_ms`.
///
/// A backup is the database at the instant it started but becomes the newest one only when it is listed, `took_ms` later. A
/// loss just before that rolls back to the previous backup, so the longest window between two kept backups is
/// `started(k+1) + took(k+1) - started(k)`, and a loss right now costs `now - started(newest)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exposure {
    pub backups: usize,
    pub newest_id: Option<String>,
    /// Data lost if the data directory vanished at `now`.
    pub age_ms: Option<i64>,
    /// The longest loss any moment between the oldest kept backup and `now` would have cost.
    pub worst_ms: Option<i64>,
}

pub fn exposure(target: &Path, now: UnixMillis) -> Result<Exposure> {
    let mut out = Exposure::default();
    let mut previous: Option<i64> = None;
    for id in list(target)? {
        let m = manifest(target, &id)?;
        let started = m["started_ms"]
            .as_i64()
            .ok_or(Error::Corrupt("backup manifest"))?;
        let took = m["took_ms"].as_i64().unwrap_or(0).max(0);
        if let Some(before) = previous {
            out.worst_ms = out.worst_ms.max(Some(started + took - before));
        }
        previous = Some(started);
        out.backups += 1;
        out.newest_id = Some(id);
    }
    if let Some(started) = previous {
        let age = (now.0 - started).max(0);
        out.age_ms = Some(age);
        out.worst_ms = out.worst_ms.max(Some(age));
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verification {
    pub integrity: String,
    pub metadata_matches: bool,
    pub objects_checked: u64,
    pub objects_remote: u64,
    pub missing: Vec<String>,
    pub corrupt: Vec<String>,
    pub manifests_checked: u64,
    pub config_checked: u64,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.integrity == "ok"
            && self.metadata_matches
            && self.missing.is_empty()
            && self.corrupt.is_empty()
    }
}

fn config_sums(manifest: &Value) -> BTreeMap<String, String> {
    manifest["config_blake3"]
        .as_object()
        .map(|sums| {
            sums.iter()
                .filter_map(|(name, sum)| Some((name.clone(), sum.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

pub fn verify(target: &Path, id: &str) -> Result<Verification> {
    let manifest = manifest(target, id)?;
    let dir = target.join(id);
    let mut out = Verification::default();
    // A snapshot that cannot even be read is a failed verification, not an error: the caller is asking whether the backup is usable.
    match hash_file(&dir.join(METADATA)) {
        Ok((got, _)) => {
            out.metadata_matches =
                manifest["metadata"]["blake3"].as_str() == Some(got.to_string().as_str());
        }
        Err(e) => {
            out.integrity = format!("unreadable: {e}");
            return Ok(out);
        }
    }
    let checked = open_snapshot(&dir.join(METADATA)).and_then(|snapshot| {
        let integrity: String = snapshot.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok((snapshot, integrity))
    });
    let snapshot = match checked {
        Ok((snapshot, integrity)) => {
            out.integrity = integrity;
            snapshot
        }
        Err(e) => {
            out.integrity = format!("unreadable: {e}");
            return Ok(out);
        }
    };
    if out.integrity != "ok" {
        // Its rows cannot be trusted to name the files to check.
        return Ok(out);
    }
    for row in object_rows(&snapshot)? {
        if row.remote_only {
            out.objects_remote += 1;
            continue;
        }
        out.objects_checked += 1;
        match hash_file(&target.join(&row.rel)) {
            Ok((d, len)) if d == row.digest && len == row.len => {}
            Ok(_) => out.corrupt.push(row.rel.display().to_string()),
            Err(_) => out.missing.push(row.rel.display().to_string()),
        }
    }
    for (rel, want) in manifest_rows(&snapshot)? {
        out.manifests_checked += 1;
        match hash_file(&target.join(&rel)) {
            Ok((d, _)) if d == want => {}
            Ok(_) => out.corrupt.push(rel.display().to_string()),
            Err(_) => out.missing.push(rel.display().to_string()),
        }
    }
    for (name, want) in config_sums(&manifest) {
        out.config_checked += 1;
        let shown = format!("{CONFIG_DIR}/{name}");
        match hash_file(&dir.join(CONFIG_DIR).join(&name)) {
            Ok((d, _)) if d.to_string() == want => {}
            Ok(_) => out.corrupt.push(shown),
            Err(_) => out.missing.push(shown),
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    pub objects: u64,
    pub objects_remote: u64,
    pub manifests: u64,
    pub log_files: u64,
    pub config_files: Vec<String>,
    pub key_checked: bool,
    /// Objects the backup itself recorded as missing or corrupt at the source: the restore carries on without them and recovery names them.
    pub objects_unavailable: Vec<String>,
    /// The data directory already existed and group or other accounts can open it: its mode is the operator's to tighten.
    pub data_dir_open_to_others: bool,
}

pub fn restore(target: &Path, id: &str, data_dir: &Path, key: Option<&Path>) -> Result<Restored> {
    let manifest = manifest(target, id)?;
    if data_dir.join(METADATA).exists() {
        return Err(Error::InvalidInput(
            "the data directory already holds a database",
        ));
    }
    // A stale journal beside the restored file would be replayed into it when the store opens.
    for suffix in ["-wal", "-shm"] {
        if data_dir.join(format!("{METADATA}{suffix}")).exists() {
            return Err(Error::InvalidInput(
                "the data directory holds the journal of a database that is gone: empty it first",
            ));
        }
    }
    let dir = target.join(id);
    let (got, _) = hash_file(&dir.join(METADATA))?;
    if manifest["metadata"]["blake3"].as_str() != Some(got.to_string().as_str()) {
        return Err(Error::Corrupt("backup metadata checksum"));
    }
    let required = manifest["key"]["required"].as_bool().unwrap_or(false);
    if required && key.is_none() {
        return Err(Error::InvalidInput(
            "the backup holds sealed values: give the master key file that opens them",
        ));
    }
    let loaded = match key {
        Some(path) => Some(
            sentinel_auth::sealed::Key::load(path)
                .map_err(|_| Error::InvalidInput("master key file"))?,
        ),
        None => None,
    };
    let snapshot = open_snapshot(&dir.join(METADATA))?;
    if let Some(key) = &loaded {
        let required = crate::reseal::key_ids(&snapshot)?;
        if !required.iter().all(|id| key.contains(*id)) {
            return Err(Error::InvalidInput(
                "the master key file does not contain every key the backup needs",
            ));
        }
        crate::reseal::verify_key(&snapshot, key)?;
    }
    let existed = data_dir.exists();
    private_dir_all(data_dir)?;
    let mut out = Restored {
        key_checked: loaded.is_some(),
        data_dir_open_to_others: existed && open_to_others(data_dir),
        ..Restored::default()
    };
    let mut dirty = BTreeSet::new();
    // What the backup itself recorded as lost at the source. Restoring everything else beats refusing to restore at all.
    let acknowledged: HashSet<&str> = ["missing", "corrupt"]
        .iter()
        .flat_map(|list| manifest["objects"][list].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .collect();
    for row in object_rows(&snapshot)? {
        if row.remote_only {
            out.objects_remote += 1;
            continue;
        }
        let src = target.join(&row.rel);
        let shown = row.rel.display().to_string();
        if acknowledged.contains(shown.as_str()) && !src.exists() {
            out.objects_unavailable.push(shown);
            continue;
        }
        let (d, len) = copy_file_into(&src, &data_dir.join(&row.rel), data_dir, &mut dirty)?;
        if d != row.digest || len != row.len {
            return Err(Error::Corrupt("backup object content"));
        }
        out.objects += 1;
    }
    for (rel, want) in manifest_rows(&snapshot)? {
        let (d, _) = copy_file_into(
            &target.join(&rel),
            &data_dir.join(&rel),
            data_dir,
            &mut dirty,
        )?;
        if d != want {
            return Err(Error::Corrupt("backup manifest content"));
        }
        out.manifests += 1;
    }
    let kept = kept_logs(&snapshot)?;
    drop(snapshot);
    let logs = target.join(crate::logs::LOGS_DIR);
    if logs.exists() {
        let mut stack = vec![(logs.clone(), false)];
        while let Some((dir, keep)) = stack.pop() {
            for entry in fs::read_dir(&dir)?.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry.metadata().is_ok_and(|m| m.is_dir());
                let attempt = name.trim_end_matches(".log").parse::<AttemptId>().ok();
                let keep_here = keep || attempt.is_some_and(|a| kept.contains(&a));
                if is_dir {
                    stack.push((path, keep_here));
                } else if keep_here {
                    let rel = path
                        .strip_prefix(target)
                        .map_err(|_| Error::Corrupt("log path"))?;
                    copy_file_into(&path, &data_dir.join(rel), data_dir, &mut dirty)?;
                    out.log_files += 1;
                }
            }
        }
    }
    let config = dir.join(CONFIG_DIR);
    let mut sums = config_sums(&manifest);
    if config.exists() {
        let mut stack = vec![config.clone()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d)?.flatten() {
                let path = entry.path();
                if entry.metadata().is_ok_and(|m| m.is_dir()) {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&config)
                    .map_err(|_| Error::Corrupt("config path"))?;
                let (sum, _) = copy_file(&path, &data_dir.join(rel))?;
                let name = rel.to_string_lossy().replace('\\', "/");
                if sums
                    .remove(&name)
                    .is_some_and(|want| want != sum.to_string())
                {
                    return Err(Error::Corrupt("backup config content"));
                }
                restrict(&data_dir.join(rel))?;
                out.config_files.push(name);
            }
        }
    }
    if !sums.is_empty() {
        return Err(Error::Corrupt("backup config content"));
    }
    if let Some(path) = key {
        let dst = data_dir.join(crate::MASTER_KEY_FILE);
        copy_file(path, &dst)?;
        restrict(&dst)?;
    }
    sync_dirs(&dirty)?;
    // The database lands last, so a half-restored directory is never taken for a controller's.
    let (d, _) = copy_file(&dir.join(METADATA), &data_dir.join(METADATA))?;
    if d != got {
        return Err(Error::Corrupt("backup metadata checksum"));
    }
    sync_dir(data_dir)?;
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub backups: Vec<String>,
    pub objects: u64,
    pub manifests: u64,
    pub log_files: u64,
}

pub fn prune(target: &Path, keep: usize) -> Result<Pruned> {
    if keep == 0 {
        return Err(Error::InvalidInput("keep at least one backup"));
    }
    let _writer = match lock_target(target) {
        Ok(lock) => Some(lock),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let ids = list(target)?;
    let mut out = Pruned::default();
    let cut = ids.len().saturating_sub(keep);
    for id in &ids[..cut] {
        fs::remove_dir_all(target.join(id))?;
        out.backups.push(id.clone());
    }
    let kept = &ids[cut..];
    let mut objects = HashSet::new();
    let mut manifests = HashSet::new();
    let mut attempts = HashSet::new();
    for id in kept {
        let snapshot = open_snapshot(&target.join(id).join(METADATA))?;
        objects.extend(object_rows(&snapshot)?.into_iter().map(|r| r.rel));
        manifests.extend(manifest_rows(&snapshot)?.into_iter().map(|(rel, _)| rel));
        attempts.extend(kept_logs(&snapshot)?);
    }
    let mut stack = vec![
        target.join(crate::objects::OBJECTS_DIR),
        target.join(crate::objects::MANIFESTS_DIR),
    ];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if entry.metadata().is_ok_and(|m| m.is_dir()) {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(target)
                .map_err(|_| Error::Corrupt("backup path"))?
                .to_path_buf();
            let is_object = rel.starts_with(crate::objects::OBJECTS_DIR);
            let named = if is_object {
                objects.contains(&rel)
            } else {
                manifests.contains(&rel)
            };
            if !named && fs::remove_file(&path).is_ok() {
                if is_object {
                    out.objects += 1;
                } else {
                    out.manifests += 1;
                }
            }
        }
    }
    let logs = target.join(crate::logs::LOGS_DIR);
    if logs.exists() {
        let mut stack = vec![(logs, false)];
        while let Some((dir, keep)) = stack.pop() {
            let Ok(read) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in read.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                let attempt = name.trim_end_matches(".log").parse::<AttemptId>().ok();
                let keep_here = keep || attempt.is_some_and(|a| attempts.contains(&a));
                if entry.metadata().is_ok_and(|m| m.is_dir()) {
                    if attempt.is_some() && !keep_here {
                        if let Ok(n) = fs::read_dir(&path).map(|r| r.count()) {
                            out.log_files += n as u64;
                        }
                        let _ = fs::remove_dir_all(&path);
                    } else {
                        stack.push((path, keep_here));
                    }
                } else if attempt.is_some() && !keep_here && fs::remove_file(&path).is_ok() {
                    out.log_files += 1;
                }
            }
        }
    }
    Ok(out)
}

/// How long a scheduler starting now waits for its first backup: what is left of the interval after the newest backup, never more than one interval.
///
/// A controller restarted more often than the interval would otherwise never reach its first deadline. No backup, an overdue one
/// or one that cannot be read means a backup at once; a newest backup dated in the future (clock skew) waits one interval at most.
fn first_wait(target: &Path, interval: std::time::Duration) -> std::time::Duration {
    let newest = list(target)
        .ok()
        .and_then(|ids| ids.last().cloned())
        .and_then(|id| manifest(target, &id).ok())
        .and_then(|m| m["started_ms"].as_i64());
    let Some(started) = newest else {
        return std::time::Duration::ZERO;
    };
    let interval_ms = i64::try_from(interval.as_millis()).unwrap_or(i64::MAX);
    let left = started
        .saturating_add(interval_ms)
        .saturating_sub(UnixMillis::now().0);
    std::time::Duration::from_millis(left.clamp(0, interval_ms).unsigned_abs())
}

pub trait Control: Send + Sync {
    fn trigger(&self) -> bool;
    fn status(&self) -> Value;
    fn target(&self) -> &Path;
}

pub struct Scheduler {
    store: std::sync::Weak<Store>,
    objects: std::sync::Weak<Objects>,
    data_dir: PathBuf,
    target: PathBuf,
    interval: std::time::Duration,
    keep: usize,
    version: String,
    state: std::sync::Mutex<SchedulerState>,
    wake: std::sync::Condvar,
}

#[derive(Default)]
struct SchedulerState {
    running: bool,
    requested: bool,
    stop: bool,
    last_success: Option<Report>,
    last_success_ms: Option<i64>,
    last_failure: Option<String>,
    last_failure_ms: Option<i64>,
}

impl Scheduler {
    pub fn new(
        store: std::sync::Arc<Store>,
        objects: std::sync::Arc<Objects>,
        data_dir: PathBuf,
        target: PathBuf,
        interval: std::time::Duration,
        keep: usize,
        version: String,
    ) -> std::sync::Arc<Scheduler> {
        std::sync::Arc::new(Scheduler {
            store: std::sync::Arc::downgrade(&store),
            objects: std::sync::Arc::downgrade(&objects),
            data_dir,
            target,
            interval,
            keep: keep.max(1),
            version,
            state: std::sync::Mutex::new(SchedulerState::default()),
            wake: std::sync::Condvar::new(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SchedulerState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn start(self: &std::sync::Arc<Self>) -> std::io::Result<std::thread::JoinHandle<()>> {
        let me = std::sync::Arc::clone(self);
        std::thread::Builder::new()
            .name("sentinel-backup".into())
            .spawn(move || me.run())
    }

    pub fn stop(&self) {
        self.state().stop = true;
        self.wake.notify_all();
    }

    pub fn once(&self) -> Result<Report> {
        let (Some(store), Some(objects)) = (self.store.upgrade(), self.objects.upgrade()) else {
            return Err(Error::InvalidInput("the controller is shutting down"));
        };
        let report = create(
            &store,
            &objects,
            &self.data_dir,
            &self.target,
            &self.version,
        )?;
        prune(&self.target, self.keep)?;
        Ok(report)
    }

    fn run(&self) {
        let mut next = std::time::Instant::now() + first_wait(&self.target, self.interval);
        loop {
            {
                let mut state = self.state();
                loop {
                    if state.stop {
                        return;
                    }
                    if state.requested || std::time::Instant::now() >= next {
                        break;
                    }
                    let wait = next.saturating_duration_since(std::time::Instant::now());
                    state = self
                        .wake
                        .wait_timeout(state, wait)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                state.requested = false;
                state.running = true;
            }
            // The interval runs from the start of a backup: counting from its end would add its duration to the recovery point.
            let started = std::time::Instant::now();
            let outcome = self.once();
            let now = UnixMillis::now().0;
            let mut state = self.state();
            state.running = false;
            match outcome {
                Ok(report) => {
                    state.last_success = Some(report);
                    state.last_success_ms = Some(now);
                    state.last_failure = None;
                }
                Err(e) => {
                    state.last_failure = Some(e.to_string());
                    state.last_failure_ms = Some(now);
                }
            }
            drop(state);
            next = started + self.interval;
        }
    }
}

impl Control for Scheduler {
    fn trigger(&self) -> bool {
        let mut state = self.state();
        if state.running || state.requested {
            return false;
        }
        state.requested = true;
        drop(state);
        self.wake.notify_all();
        true
    }

    fn status(&self) -> Value {
        let state = self.state();
        json!({
            "target": self.target.display().to_string(),
            "interval_secs": self.interval.as_secs(),
            "keep": self.keep,
            "running": state.running || state.requested,
            "last_success_ms": state.last_success_ms,
            "last_backup": state.last_success.as_ref().map(|r| json!({
                "id": r.id,
                "took_ms": r.took_ms,
                "metadata_bytes": r.metadata_bytes,
                "objects": r.objects,
                "objects_copied": r.objects_copied,
                "object_bytes_copied": r.object_bytes_copied,
                "objects_remote": r.objects_remote,
                "objects_corrupt": r.objects_corrupt.len(),
                "objects_missing": r.objects_missing.len(),
                "log_bytes_copied": r.log_bytes_copied,
                "target_open_to_others": r.target_open_to_others,
            })),
            "last_failure_ms": state.last_failure_ms,
            "last_failure": state.last_failure,
        })
    }

    fn target(&self) -> &Path {
        &self.target
    }
}
