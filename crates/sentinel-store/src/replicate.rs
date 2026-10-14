//! Never deletes the only copy: a local file goes only after its S3 copy is verified, and an S3 copy only after its row is gone.

use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
};

use sentinel_core::UnixMillis;

use crate::{
    Result, Store,
    logs::LogStore,
    objects::{Objects, remote_key},
    offload::{self, Delete, ObjectRef},
};

pub const LOG_SETTLE_MS: i64 = 10 * 60_000;
pub const ABANDONED_UPLOAD_MS: i64 = 24 * 3_600_000;
pub const ABORT_SWEEP_EVERY: u64 = 720;
const OBJECTS_PER_PASS: u32 = 16;
const LOGS_PER_PASS: u32 = 8;
const DELETES_PER_PASS: u32 = 64;
const EVICT_PER_PASS: u32 = 256;
const MAX_LOG_FILE: u64 = 64 << 20;

#[derive(Debug)]
pub struct BucketError {
    pub transient: bool,
    pub message: String,
    pub not_found: bool,
}

impl std::fmt::Display for BucketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type BucketResult<T> = std::result::Result<T, BucketError>;

pub trait Bucket: Send + Sync {
    fn put(&self, key: &str, body: &[u8], blake3: Option<&str>) -> BucketResult<()>;
    fn create_multipart(&self, key: &str, blake3: Option<&str>) -> BucketResult<String>;
    fn upload_part(
        &self,
        key: &str,
        upload: &str,
        number: u32,
        body: &[u8],
    ) -> BucketResult<String>;
    fn list_parts(&self, key: &str, upload: &str) -> BucketResult<Vec<(u32, String, u64)>>;
    fn complete(&self, key: &str, upload: &str, parts: &[(u32, String)]) -> BucketResult<()>;
    fn abort(&self, key: &str, upload: &str) -> BucketResult<()>;
    fn head(&self, key: &str) -> BucketResult<Option<(u64, Option<String>)>>;
    fn get(&self, key: &str, out: &mut dyn Write) -> BucketResult<u64>;
    fn delete(&self, key: &str) -> BucketResult<()>;
    fn list(&self, prefix: &str) -> BucketResult<Vec<String>>;
    fn list_uploads(&self) -> BucketResult<Vec<(String, String, Option<i64>)>>;
}

/// The replicator's settings.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub part_bytes: u64,
    pub local_bytes: u64,
    pub backlog_bytes: u64,
}

#[derive(Debug, Default)]
pub struct Status {
    pub last_success_ms: AtomicI64,
    pub last_failure_ms: AtomicI64,
    pub consecutive_failures: AtomicU64,
    pub backlog_bytes: AtomicU64,
    pub local_bytes: AtomicU64,
    pub oldest_unreplicated_ms: AtomicI64,
    pub unreplicated_logs: AtomicU64,
    pub backlog_full: AtomicBool,
    pub replicated_objects: AtomicU64,
    pub replicated_bytes: AtomicU64,
    pub replicated_logs: AtomicU64,
    pub evicted_objects: AtomicU64,
    pub fetched_objects: AtomicU64,
    pub deleted_copies: AtomicU64,
    pub aborted_uploads: AtomicU64,
    pub local_faults: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    pub last_local_fault: Mutex<Option<String>>,
}

impl Status {
    pub fn state(&self) -> &'static str {
        if self.backlog_full.load(Ordering::Relaxed)
            || self.consecutive_failures.load(Ordering::Relaxed) > 0
        {
            "degraded"
        } else if self.last_success_ms.load(Ordering::Relaxed) > 0 {
            "healthy"
        } else {
            "unknown"
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub replicated: u32,
    pub logs: u32,
    pub deleted: u32,
    pub evicted: u32,
    pub aborted: u32,
    pub local_faults: u32,
    pub more: bool,
}

enum Fault {
    Local(String),
    Bucket(BucketError),
}

impl From<BucketError> for Fault {
    fn from(e: BucketError) -> Fault {
        Fault::Bucket(e)
    }
}

pub struct Replicator {
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    bucket: Arc<dyn Bucket>,
    settings: Settings,
    status: Arc<Status>,
    passes: AtomicU64,
    buffer: Mutex<Vec<u8>>,
    recorded: AtomicBool,
}

const RETAINED_BUFFER_BYTES: usize = 16 << 20;

fn fill(reader: &mut impl Read, len: u64, buffer: &mut Vec<u8>) -> std::io::Result<()> {
    buffer.clear();
    buffer.reserve(len as usize);
    reader.by_ref().take(len).read_to_end(buffer)?;
    if buffer.len() as u64 != len {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn now_ms() -> i64 {
    UnixMillis::now().0
}

impl Replicator {
    pub fn new(
        store: Arc<Store>,
        objects: Arc<Objects>,
        logs: Arc<LogStore>,
        bucket: Arc<dyn Bucket>,
        settings: Settings,
    ) -> Replicator {
        Replicator {
            store,
            objects,
            logs,
            bucket,
            settings,
            status: Arc::new(Status::default()),
            passes: AtomicU64::new(0),
            buffer: Mutex::new(Vec::new()),
            recorded: AtomicBool::new(false),
        }
    }

    pub fn status(&self) -> Arc<Status> {
        Arc::clone(&self.status)
    }

    fn failed(&self, what: &str, error: &dyn std::fmt::Display) {
        self.recorded.store(true, Ordering::Relaxed);
        self.status
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed);
        self.status
            .last_failure_ms
            .store(now_ms(), Ordering::Relaxed);
        *self
            .status
            .last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(format!("{what}: {error}"));
    }

    pub fn pass(&self) -> std::result::Result<Pass, String> {
        let mut pass = Pass::default();
        self.recorded.store(false, Ordering::Relaxed);
        let outcome = self.stages(&mut pass);
        self.measure();
        self.passes.fetch_add(1, Ordering::Relaxed);
        match outcome {
            Ok(()) => {
                self.status.consecutive_failures.store(0, Ordering::Relaxed);
                self.status
                    .last_success_ms
                    .store(now_ms(), Ordering::Relaxed);
                *self
                    .status
                    .last_error
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
                Ok(pass)
            }
            Err(why) => {
                // Store errors still count as failures, or health would read healthy while nothing replicates.
                if !self.recorded.load(Ordering::Relaxed) {
                    self.failed("pass", &why);
                }
                Err(why)
            }
        }
    }

    fn stages(&self, pass: &mut Pass) -> std::result::Result<(), String> {
        self.rehydrated().map_err(|e| e.to_string())?;
        self.deletes(pass)?;
        self.replicate_objects(pass)?;
        self.replicate_logs(pass)?;
        self.evict(pass).map_err(|e| e.to_string())?;
        if self
            .passes
            .load(Ordering::Relaxed)
            .is_multiple_of(ABORT_SWEEP_EVERY)
        {
            self.abort_abandoned(pass)?;
        }
        Ok(())
    }

    fn rehydrated(&self) -> Result<()> {
        let back = self.objects.take_rehydrated();
        if !back.is_empty() {
            self.status
                .fetched_objects
                .fetch_add(back.len() as u64, Ordering::Relaxed);
            self.store
                .writer()
                .write(move |tx| offload::local_again(tx, &back))?;
        }
        Ok(())
    }

    fn deletes(&self, pass: &mut Pass) -> std::result::Result<(), String> {
        let due = self
            .store
            .read(|c| offload::deletes(c, DELETES_PER_PASS))
            .map_err(|e| e.to_string())?;
        pass.more |= due.len() as u32 == DELETES_PER_PASS;
        for delete in due {
            let result = match delete {
                Delete::Object { id, tenant, digest } => {
                    // A digest queued for deletion may be committed again meanwhile; the recheck and dropping the delete are one transaction.
                    let live = self
                        .store
                        .writer()
                        .write(move |tx| offload::keep_if_live(tx, id, tenant, &digest))
                        .map_err(|e| e.to_string())?;
                    if live {
                        continue;
                    }
                    self.bucket.delete(&remote_key(tenant, &digest))
                }
                Delete::Log {
                    run, job, attempt, ..
                } => {
                    let prefix = offload::log_prefix(run, job, attempt);
                    self.bucket
                        .list(&prefix)
                        .and_then(|keys| keys.iter().try_for_each(|k| self.bucket.delete(k)))
                }
            };
            if let Err(e) = result {
                self.failed("delete", &e);
                return Err(e.message);
            }
            let id = delete.id();
            self.store
                .writer()
                .write(move |tx| offload::delete_done(tx, id))
                .map_err(|e| e.to_string())?;
            self.status.deleted_copies.fetch_add(1, Ordering::Relaxed);
            pass.deleted += 1;
        }
        Ok(())
    }

    fn replicate_objects(&self, pass: &mut Pass) -> std::result::Result<(), String> {
        let due = self
            .store
            .read(|c| offload::unreplicated(c, OBJECTS_PER_PASS))
            .map_err(|e| e.to_string())?;
        pass.more |= due.len() as u32 == OBJECTS_PER_PASS;
        for object in due {
            match self.replicate(&object) {
                Ok(()) => {}
                Err(Fault::Local(why)) => {
                    self.status.local_faults.fetch_add(1, Ordering::Relaxed);
                    *self
                        .status
                        .last_local_fault
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = Some(format!(
                        "{}: {why}",
                        remote_key(object.tenant, &object.digest)
                    ));
                    pass.local_faults += 1;
                    continue;
                }
                Err(Fault::Bucket(e)) => {
                    self.failed("replicate", &e);
                    return Err(e.message);
                }
            }
            let now = UnixMillis::now();
            let kept = self
                .store
                .writer()
                .write(move |tx| {
                    let kept = offload::replicated(tx, &object, now)?;
                    if !kept {
                        offload::queue_object_delete(tx, object.tenant, &object.digest, now)?;
                    }
                    Ok(kept)
                })
                .map_err(|e| e.to_string())?;
            if kept {
                self.status
                    .replicated_objects
                    .fetch_add(1, Ordering::Relaxed);
                self.status
                    .replicated_bytes
                    .fetch_add(object.len, Ordering::Relaxed);
                pass.replicated += 1;
            }
        }
        Ok(())
    }

    /// The local bytes are hashed before anything is sent: a copy that does not match its digest is never uploaded under the digest's name.
    fn replicate(&self, object: &ObjectRef) -> std::result::Result<(), Fault> {
        let local = |e: &dyn std::fmt::Display| Fault::Local(format!("local object: {e}"));
        let key = remote_key(object.tenant, &object.digest);
        let blake3 = object.digest.to_string();
        let (mut reader, len) = self
            .store
            .read(|c| self.objects.open_read(c, object.tenant, object.digest))
            .map_err(|e| local(&e))?;
        let mut buffer = self.buffer.lock().unwrap_or_else(|p| p.into_inner());
        let outcome = self.upload(&key, &blake3, object, &mut reader, len, &mut buffer);
        if buffer.capacity() > RETAINED_BUFFER_BYTES {
            *buffer = Vec::new();
        }
        drop(buffer);
        outcome?;
        match self.bucket.head(&key)? {
            Some((got, meta)) if got == len && meta.as_deref().is_none_or(|m| m == blake3) => {
                Ok(())
            }
            _ => Err(Fault::Bucket(BucketError {
                transient: true,
                not_found: false,
                message: "the stored copy does not match the object".into(),
            })),
        }
    }

    fn upload(
        &self,
        key: &str,
        blake3: &str,
        object: &ObjectRef,
        reader: &mut (impl Read + Seek),
        len: u64,
        buffer: &mut Vec<u8>,
    ) -> std::result::Result<(), Fault> {
        let local = |e: &dyn std::fmt::Display| Fault::Local(format!("local object: {e}"));
        let matches = |hash: blake3::Hash| {
            crate::objects::Digest::from_bytes(*hash.as_bytes()) == object.digest
        };
        if len <= self.settings.part_bytes {
            fill(reader, len, buffer).map_err(|e| local(&e))?;
            let mut extra = [0u8; 1];
            if reader.read(&mut extra).map_err(|e| local(&e))? != 0
                || !matches(blake3::hash(buffer))
            {
                return Err(Fault::Local("does not match its digest".into()));
            }
            self.bucket.put(key, buffer, Some(blake3))?;
        } else {
            let mut hasher = blake3::Hasher::new();
            let mut total = 0u64;
            buffer.clear();
            buffer.resize(self.settings.part_bytes.min(8 << 20) as usize, 0);
            loop {
                let n = reader.read(&mut buffer[..]).map_err(|e| local(&e))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                total += n as u64;
            }
            if total != len || !matches(hasher.finalize()) {
                return Err(Fault::Local("does not match its digest".into()));
            }
            self.multipart(key, blake3, len, reader, buffer)?;
        }
        Ok(())
    }

    fn multipart(
        &self,
        key: &str,
        blake3: &str,
        len: u64,
        reader: &mut (impl Read + Seek),
        buffer: &mut Vec<u8>,
    ) -> BucketResult<()> {
        let db = |e: crate::Error| BucketError {
            transient: true,
            not_found: false,
            message: format!("metadata: {e}"),
        };
        let part = self.settings.part_bytes.max(len.div_ceil(10_000));
        let recorded = self.store.read(|c| offload::upload(c, key)).map_err(db)?;
        let mut held = Vec::new();
        let upload = match recorded {
            Some((id, bytes)) if bytes == part => match self.bucket.list_parts(key, &id) {
                Ok(parts) => {
                    held = parts;
                    id
                }
                Err(e) if e.not_found => self.start_multipart(key, blake3, part)?,
                Err(e) => return Err(e),
            },
            Some((id, _)) => {
                let _ = self.bucket.abort(key, &id);
                self.start_multipart(key, blake3, part)?
            }
            None => self.start_multipart(key, blake3, part)?,
        };
        let count = len.div_ceil(part) as u32;
        let mut done = Vec::with_capacity(count as usize);
        for number in 1..=count {
            let offset = u64::from(number - 1) * part;
            let size = part.min(len - offset);
            if let Some((_, etag, _)) = held.iter().find(|(n, _, l)| *n == number && *l == size) {
                done.push((number, etag.clone()));
                continue;
            }
            reader
                .seek(SeekFrom::Start(offset))
                .and_then(|_| fill(reader, size, buffer))
                .map_err(|e| BucketError {
                    transient: false,
                    not_found: false,
                    message: format!("local object: {e}"),
                })?;
            let etag = self.bucket.upload_part(key, &upload, number, buffer)?;
            done.push((number, etag));
        }
        self.bucket.complete(key, &upload, &done)?;
        let key = key.to_owned();
        self.store
            .writer()
            .write(move |tx| offload::forget_upload(tx, &key))
            .map_err(db)?;
        Ok(())
    }

    fn start_multipart(&self, key: &str, blake3: &str, part: u64) -> BucketResult<String> {
        let id = self.bucket.create_multipart(key, Some(blake3))?;
        let (k, i) = (key.to_owned(), id.clone());
        let now = UnixMillis::now();
        self.store
            .writer()
            .write(move |tx| offload::record_upload(tx, &k, &i, part, now))
            .map_err(|e| BucketError {
                transient: true,
                not_found: false,
                message: format!("metadata: {e}"),
            })?;
        Ok(id)
    }

    fn replicate_logs(&self, pass: &mut Pass) -> std::result::Result<(), String> {
        let settled = UnixMillis(now_ms() - LOG_SETTLE_MS);
        let due = self
            .store
            .read(|c| offload::unreplicated_logs(c, settled, LOGS_PER_PASS))
            .map_err(|e| e.to_string())?;
        pass.more |= due.len() as u32 == LOGS_PER_PASS;
        for log in due {
            let prefix = offload::log_prefix(log.run, log.job, log.attempt);
            let dir = self.logs.attempt_dir(log.run, log.job, log.attempt);
            let mut sent = HashSet::new();
            let files = match std::fs::read_dir(&dir) {
                Ok(read) => read.flatten().collect::<Vec<_>>(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(format!("log directory: {e}")),
            };
            for entry in files {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() || name.ends_with(".tmp") || meta.len() > MAX_LOG_FILE {
                    continue;
                }
                let body = std::fs::read(entry.path()).map_err(|e| format!("log file: {e}"))?;
                let key = format!("{prefix}{name}");
                let blake3 = blake3::hash(&body).to_hex().to_string();
                if let Err(e) = self.bucket.put(&key, &body, Some(&blake3)) {
                    self.failed("log", &e);
                    return Err(e.message);
                }
                sent.insert(key);
            }
            match self.bucket.list(&prefix) {
                Ok(keys) => {
                    for stale in keys.iter().filter(|k| !sent.contains(*k)) {
                        if let Err(e) = self.bucket.delete(stale) {
                            self.failed("log", &e);
                            return Err(e.message);
                        }
                    }
                }
                Err(e) => {
                    self.failed("log", &e);
                    return Err(e.message);
                }
            }
            let attempt = log.attempt;
            let now = UnixMillis::now();
            if self
                .store
                .writer()
                .write(move |tx| offload::log_replicated(tx, attempt, now))
                .map_err(|e| e.to_string())?
            {
                self.status.replicated_logs.fetch_add(1, Ordering::Relaxed);
                pass.logs += 1;
            }
        }
        Ok(())
    }

    fn evict(&self, pass: &mut Pass) -> Result<()> {
        let Some(_maintenance) = self.objects.try_maintenance() else {
            return Ok(());
        };
        let totals = self.store.read(offload::totals)?;
        let pressure = self.objects.admission().is_some_and(|a| !a.is_open())
            && !self.status.backlog_full.load(Ordering::Relaxed);
        let over = if self.settings.local_bytes > 0 {
            totals.local_bytes.saturating_sub(self.settings.local_bytes)
        } else {
            0
        };
        if over == 0 && !pressure {
            return Ok(());
        }
        let candidates = self.store.read(|c| offload::evictable(c, EVICT_PER_PASS))?;
        let mut chosen = Vec::new();
        let mut freed = 0u64;
        for c in candidates {
            if !pressure && freed >= over {
                break;
            }
            if self.objects.reader_active(c.tenant, c.digest) {
                continue;
            }
            freed += c.len;
            chosen.push((c.tenant, c.digest));
        }
        if chosen.is_empty() {
            return Ok(());
        }
        let marked = chosen.clone();
        let now = UnixMillis::now();
        self.store
            .writer()
            .write(move |tx| offload::evicted(tx, &marked, now))?;
        let removed = self.objects.evict_files(&chosen);
        let kept: Vec<_> = chosen
            .iter()
            .filter(|k| !removed.contains(k))
            .copied()
            .collect();
        if !kept.is_empty() {
            self.store
                .writer()
                .write(move |tx| offload::local_again(tx, &kept))?;
        }
        self.status
            .evicted_objects
            .fetch_add(removed.len() as u64, Ordering::Relaxed);
        pass.evicted += removed.len() as u32;
        Ok(())
    }

    fn abort_abandoned(&self, pass: &mut Pass) -> std::result::Result<(), String> {
        let now = now_ms();
        let recorded = self
            .store
            .read(offload::recorded_uploads)
            .map_err(|e| e.to_string())?;
        for (key, id, created) in &recorded {
            if now - created > ABANDONED_UPLOAD_MS {
                let _ = self.bucket.abort(key, id);
                let key = key.clone();
                self.store
                    .writer()
                    .write(move |tx| offload::forget_upload(tx, &key))
                    .map_err(|e| e.to_string())?;
                self.status.aborted_uploads.fetch_add(1, Ordering::Relaxed);
                pass.aborted += 1;
            }
        }
        let open = match self.bucket.list_uploads() {
            Ok(open) => open,
            Err(e) => {
                self.failed("abort sweep", &e);
                return Err(e.message);
            }
        };
        let ours: HashSet<&str> = recorded.iter().map(|(_, id, _)| id.as_str()).collect();
        for (key, id, initiated) in open {
            let old = initiated.is_some_and(|at| now - at > ABANDONED_UPLOAD_MS);
            if !ours.contains(id.as_str()) && old && self.bucket.abort(&key, &id).is_ok() {
                self.status.aborted_uploads.fetch_add(1, Ordering::Relaxed);
                pass.aborted += 1;
            }
        }
        Ok(())
    }

    fn measure(&self) {
        let Ok(totals) = self.store.read(offload::totals) else {
            return;
        };
        let s = &self.status;
        s.backlog_bytes
            .store(totals.unreplicated_bytes, Ordering::Relaxed);
        s.local_bytes.store(totals.local_bytes, Ordering::Relaxed);
        s.oldest_unreplicated_ms.store(
            totals.oldest_unreplicated_ms.unwrap_or(0),
            Ordering::Relaxed,
        );
        s.unreplicated_logs
            .store(totals.unreplicated_logs, Ordering::Relaxed);
        let budget = self.settings.backlog_bytes;
        if budget == 0 {
            return;
        }
        let admission = self.objects.admission();
        let full = admission.map_or(s.backlog_full.load(Ordering::Relaxed), |a| a.backlog_full());
        let now_full = if full {
            totals.unreplicated_bytes > budget / 10 * 9
        } else {
            totals.unreplicated_bytes > budget
        };
        s.backlog_full.store(now_full, Ordering::Relaxed);
        if let Some(admission) = admission
            && now_full != full
        {
            admission.set_backlog_full(now_full);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn fill_replaces_the_buffer_with_exactly_the_requested_bytes() {
        let mut buffer = vec![9u8; 64];
        let mut reader = Cursor::new((0..=255u8).collect::<Vec<_>>());
        fill(&mut reader, 10, &mut buffer).unwrap();
        assert_eq!(buffer, (0..10u8).collect::<Vec<_>>());
        fill(&mut reader, 3, &mut buffer).unwrap();
        assert_eq!(buffer, vec![10, 11, 12]);
        fill(&mut reader, 0, &mut buffer).unwrap();
        assert!(buffer.is_empty());
    }

    #[test]
    fn fill_reports_a_short_read_as_a_truncated_object() {
        let mut buffer = Vec::new();
        let mut reader = Cursor::new(vec![1u8, 2, 3]);
        let error = fill(&mut reader, 4, &mut buffer).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
