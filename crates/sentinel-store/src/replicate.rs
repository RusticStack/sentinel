//! Never deletes the only copy: a local file goes only after its S3 copy is verified, and an S3 copy only after its row is gone.
//!
//! One item that cannot be copied or deleted never holds the rest back. A locally damaged object, or an item the
//! bucket refuses for good while it accepts everything else, is parked in memory with a growing delay and the pass
//! goes on. A refusal with no success of its kind in the same pass is a credential or endpoint problem, not an
//! item: the pass fails as one and nothing is parked.

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, TenantId, UnixMillis};

use crate::{
    Result, Store,
    logs::LogStore,
    objects::{Digest, Objects, remote_key},
    offload::{self, Delete, LogCopy, ObjectRef},
};

pub const LOG_SETTLE_MS: i64 = 10 * 60_000;
pub const ABANDONED_UPLOAD_MS: i64 = 24 * 3_600_000;
pub const ABORT_SWEEP_EVERY: u64 = 720;
/// The first delay before a parked item is tried again; it doubles on each failure up to `PARK_MAX`.
pub const PARK_MIN: Duration = Duration::from_secs(15 * 60);
pub const PARK_MAX: Duration = Duration::from_secs(6 * 3_600);
/// Parked items remembered at most. Past it an item is no longer parked: a damaged object is counted and tried again
/// next pass, and a refused one fails the pass.
pub const MAX_PARKED: usize = 1024;
/// Multipart uploads are only ever started under this key family, so the abort sweep touches nothing else.
const OBJECT_KEYS: &str = "objects/";
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
    /// Distinct objects and logs found damaged or missing locally since start, each counted when first parked.
    pub local_faults: AtomicU64,
    /// Items parked now: damaged locally, or refused by the bucket for good while it accepted others.
    pub parked_items: AtomicU64,
    /// Objects parked now and their bytes. These bytes still count in the backlog: they are not in S3.
    pub parked_objects: AtomicU64,
    pub parked_bytes: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    pub last_local_fault: Mutex<Option<String>>,
    pub last_refusal: Mutex<Option<String>>,
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
    /// Faults found this pass, including a parked item tried again; `Status::local_faults` counts each item once.
    pub local_faults: u32,
    /// Items the bucket refused for good this pass and that were parked.
    pub parked: u32,
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

/// What a parked item is.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Item {
    Object(TenantId, Digest),
    Delete(i64),
    Log(AttemptId),
}

struct Parked {
    retry_at: Instant,
    delay: Duration,
    bytes: u64,
    /// The bucket's answer when a pass judged this item's refusal to be its own, not the credential's.
    refusal: Option<String>,
}

enum Shelved {
    New,
    Again,
    Full,
}

/// Items set aside so the rest of the queue moves, retried after a delay that doubles on each failure.
/// It lives in memory: a restart tries every item once more, which is how a repaired file is found anyway.
struct Shelf {
    items: HashMap<Item, Parked>,
    min: Duration,
    max: Duration,
    limit: usize,
}

impl Shelf {
    fn held(&self, item: &Item, now: Instant) -> bool {
        self.items.get(item).is_some_and(|p| p.retry_at > now)
    }

    fn park(&mut self, item: Item, bytes: u64, now: Instant) -> Shelved {
        if let Some(parked) = self.items.get_mut(&item) {
            parked.delay = (parked.delay * 2).min(self.max);
            parked.retry_at = now + parked.delay;
            return Shelved::Again;
        }
        if self.items.len() >= self.limit {
            return Shelved::Full;
        }
        self.items.insert(
            item,
            Parked {
                retry_at: now + self.min,
                delay: self.min,
                bytes,
                refusal: None,
            },
        );
        Shelved::New
    }

    /// Entries for rows a complete read of the queue no longer returns are stale: the row was replicated or removed.
    fn forget_unseen(&mut self, seen: &HashSet<Item>, kind: fn(&Item) -> bool) {
        self.items
            .retain(|item, _| !kind(item) || seen.contains(item));
    }

    fn holds(&self, kind: fn(&Item) -> bool) -> bool {
        self.items.keys().any(kind)
    }
}

fn is_object(item: &Item) -> bool {
    matches!(item, Item::Object(..))
}
fn is_delete(item: &Item) -> bool {
    matches!(item, Item::Delete(_))
}
fn is_log(item: &Item) -> bool {
    matches!(item, Item::Log(_))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Put,
    Delete,
    /// A listing is judged by other listings: a key may be allowed to write and delete yet not to list.
    List,
}

struct Refusal {
    item: Item,
    class: Class,
    what: &'static str,
    message: String,
    /// The item was parked by an earlier pass for this same answer: an item retried alone is still that item's.
    repeat: bool,
}

/// What one pass learned about the bucket: which kinds of request it accepted, and what it refused for good.
#[derive(Default)]
struct Run {
    put_ok: bool,
    delete_ok: bool,
    list_ok: bool,
    refused: Vec<Refusal>,
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
    parking: Mutex<Shelf>,
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

fn store_failed(e: crate::Error) -> BucketError {
    BucketError {
        transient: true,
        not_found: false,
        message: format!("metadata: {e}"),
    }
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
            parking: Mutex::new(Shelf {
                items: HashMap::new(),
                min: PARK_MIN,
                max: PARK_MAX,
                limit: MAX_PARKED,
            }),
        }
    }

    /// Sets how long a parked item waits before its first retry, and the longest it ever waits.
    #[must_use]
    pub fn with_park_delays(self, min: Duration, max: Duration) -> Replicator {
        {
            let mut parking = self.parking();
            parking.min = min;
            parking.max = max.max(min);
        }
        self
    }

    /// Sets how many items may wait at once; past it a damaged item is tried every pass and a refused one fails the pass.
    #[must_use]
    pub fn with_park_limit(self, limit: usize) -> Replicator {
        self.parking().limit = limit;
        self
    }

    pub fn status(&self) -> Arc<Status> {
        Arc::clone(&self.status)
    }

    fn parking(&self) -> MutexGuard<'_, Shelf> {
        self.parking.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Rows to read so that, after the parked ones are skipped, a full pass of unparked work is still in the window.
    fn window(&self, base: u32) -> u32 {
        base.saturating_add(self.parking().items.len() as u32)
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
        let mut run = Run::default();
        let outcome = self.run_stages(pass, &mut run);
        // Judged even when a stage failed: parked items must not outlive a pass that decided they were not theirs.
        let refused = self.settle_refusals(pass, run);
        match (outcome, refused) {
            (Err(why), _) => Err(why),
            (Ok(()), Some((what, message))) => {
                self.failed(what, &message);
                Err(message)
            }
            (Ok(()), None) => Ok(()),
        }
    }

    fn run_stages(&self, pass: &mut Pass, run: &mut Run) -> std::result::Result<(), String> {
        self.rehydrated().map_err(|e| e.to_string())?;
        self.deletes(pass, run)?;
        self.replicate_objects(pass, run)?;
        self.replicate_logs(pass, run)?;
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

    /// A bucket error on one item. A transient one is the bucket, not the item: the pass fails. A permanent one
    /// parks the item and the stage goes on; whether it was the item or the credential is judged at the pass's end.
    fn refused(
        &self,
        run: &mut Run,
        what: &'static str,
        class: Class,
        item: Item,
        bytes: u64,
        error: BucketError,
    ) -> std::result::Result<(), String> {
        if error.transient {
            self.failed(what, &error);
            return Err(error.message);
        }
        let repeat = {
            let mut parking = self.parking();
            let repeat = parking
                .items
                .get(&item)
                .is_some_and(|p| p.refusal.as_deref() == Some(error.message.as_str()));
            if matches!(parking.park(item, bytes, Instant::now()), Shelved::Full) {
                drop(parking);
                self.failed(what, &error);
                return Err(error.message);
            }
            repeat
        };
        run.refused.push(Refusal {
            item,
            class,
            what,
            message: error.message,
            repeat,
        });
        Ok(())
    }

    /// Permanent refusals are an item's own only if the bucket accepted other requests of that kind in the same pass,
    /// or an earlier pass already judged the same answer to be the item's. Otherwise a replaced credential or a corrected endpoint must catch up at once, so nothing stays parked and
    /// the pass fails as one.
    fn settle_refusals(&self, pass: &mut Pass, run: Run) -> Option<(&'static str, String)> {
        let mut global: Option<(&'static str, String)> = None;
        let mut parked = 0u32;
        let mut latest = None;
        {
            let mut parking = self.parking();
            for refusal in run.refused {
                let accepted = refusal.repeat
                    || match refusal.class {
                        Class::Put => run.put_ok,
                        Class::Delete => run.delete_ok,
                        Class::List => run.list_ok,
                    };
                if accepted {
                    parked += 1;
                    if let Some(entry) = parking.items.get_mut(&refusal.item) {
                        entry.refusal = Some(refusal.message.clone());
                    }
                    latest = Some(refusal.message);
                } else {
                    parking.items.remove(&refusal.item);
                    global.get_or_insert((refusal.what, refusal.message));
                }
            }
        }
        pass.parked += parked;
        if let Some(message) = latest {
            *self
                .status
                .last_refusal
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(message);
        }
        global
    }

    fn deletes(&self, pass: &mut Pass, run: &mut Run) -> std::result::Result<(), String> {
        let window = self.window(DELETES_PER_PASS);
        let rows = self
            .store
            .read(|c| offload::deletes(c, window))
            .map_err(|e| e.to_string())?;
        let now = Instant::now();
        let due: Vec<Delete> = {
            let mut parking = self.parking();
            if (rows.len() as u32) < window && parking.holds(is_delete) {
                let seen: HashSet<Item> = rows.iter().map(|d| Item::Delete(d.id())).collect();
                parking.forget_unseen(&seen, is_delete);
            }
            rows.into_iter()
                .filter(|d| !parking.held(&Item::Delete(d.id()), now))
                .collect()
        };
        let full = due.len() >= DELETES_PER_PASS as usize;
        let mut progressed = false;
        for delete in due.into_iter().take(DELETES_PER_PASS as usize) {
            let result: std::result::Result<(), (Class, BucketError)> = match delete {
                Delete::Object { id, tenant, digest } => {
                    // A digest queued for deletion may be committed again meanwhile; the recheck and dropping the delete are one transaction.
                    let live = self
                        .store
                        .writer()
                        .write(move |tx| offload::keep_if_live(tx, id, tenant, &digest))
                        .map_err(|e| e.to_string())?;
                    if live {
                        self.parking().items.remove(&Item::Delete(id));
                        progressed = true;
                        continue;
                    }
                    self.bucket
                        .delete(&remote_key(tenant, &digest))
                        .map(|()| run.delete_ok = true)
                        .map_err(|e| (Class::Delete, e))
                }
                Delete::Log {
                    run: run_id,
                    job,
                    attempt,
                    ..
                } => {
                    let prefix = offload::log_prefix(run_id, job, attempt);
                    match self.bucket.list(&prefix) {
                        Err(e) => Err((Class::List, e)),
                        Ok(keys) => {
                            run.list_ok = true;
                            keys.iter()
                                .try_for_each(|k| {
                                    self.bucket.delete(k)?;
                                    run.delete_ok = true;
                                    Ok::<(), BucketError>(())
                                })
                                .map_err(|e| (Class::Delete, e))
                        }
                    }
                }
            };
            let id = delete.id();
            if let Err((class, e)) = result {
                self.refused(run, "delete", class, Item::Delete(id), 0, e)?;
                progressed = true;
                continue;
            }
            self.store
                .writer()
                .write(move |tx| offload::delete_done(tx, id))
                .map_err(|e| e.to_string())?;
            self.parking().items.remove(&Item::Delete(id));
            self.status.deleted_copies.fetch_add(1, Ordering::Relaxed);
            pass.deleted += 1;
            progressed = true;
        }
        pass.more |= full && progressed;
        Ok(())
    }

    /// Counts a local fault once per item and remembers the latest. Returns whether the item is newly parked.
    fn local_fault(&self, item: Item, bytes: u64, what: &str, pass: &mut Pass) -> bool {
        pass.local_faults += 1;
        let parking = self.parking().park(item, bytes, Instant::now());
        match parking {
            // A full shelf cannot remember the item, so counting it on every pass would never settle.
            Shelved::Again | Shelved::Full => {}
            Shelved::New => {
                self.status.local_faults.fetch_add(1, Ordering::Relaxed);
            }
        }
        *self
            .status
            .last_local_fault
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(what.to_owned());
        matches!(parking, Shelved::New)
    }

    fn replicate_objects(&self, pass: &mut Pass, run: &mut Run) -> std::result::Result<(), String> {
        let window = self.window(OBJECTS_PER_PASS);
        let rows = self
            .store
            .read(|c| offload::unreplicated(c, window))
            .map_err(|e| e.to_string())?;
        let now = Instant::now();
        let due: Vec<ObjectRef> = {
            let mut parking = self.parking();
            if (rows.len() as u32) < window && parking.holds(is_object) {
                let seen: HashSet<Item> = rows
                    .iter()
                    .map(|o| Item::Object(o.tenant, o.digest))
                    .collect();
                parking.forget_unseen(&seen, is_object);
            }
            rows.into_iter()
                .filter(|o| !parking.held(&Item::Object(o.tenant, o.digest), now))
                .collect()
        };
        let full = due.len() >= OBJECTS_PER_PASS as usize;
        let mut progressed = false;
        for object in due.into_iter().take(OBJECTS_PER_PASS as usize) {
            let item = Item::Object(object.tenant, object.digest);
            match self.replicate(&object) {
                Ok(()) => {
                    run.put_ok = true;
                    self.parking().items.remove(&item);
                }
                Err(Fault::Local(why)) => {
                    let described = format!("{}: {why}", remote_key(object.tenant, &object.digest));
                    progressed |= self.local_fault(item, object.len, &described, pass);
                    continue;
                }
                Err(Fault::Bucket(e)) => {
                    self.refused(run, "replicate", Class::Put, item, object.len, e)?;
                    progressed = true;
                    continue;
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
            progressed = true;
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
        // A window of faulty or refused rows is not more work: those rows are parked now and the next pass skips them.
        pass.more |= full && progressed;
        Ok(())
    }

    /// The local bytes are hashed before the object is complete in the bucket: a copy that does not match its digest
    /// is never made visible under the digest's name, whatever its size.
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
            Some((got, Some(meta))) if got == len && meta == blake3 => Ok(()),
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
        reader: &mut impl Read,
        len: u64,
        buffer: &mut Vec<u8>,
    ) -> std::result::Result<(), Fault> {
        let local = |e: &dyn std::fmt::Display| Fault::Local(format!("local object: {e}"));
        if len <= self.settings.part_bytes {
            fill(reader, len, buffer).map_err(|e| local(&e))?;
            let mut extra = [0u8; 1];
            if reader.read(&mut extra).map_err(|e| local(&e))? != 0
                || !digest_is(blake3::hash(buffer), object)
            {
                return Err(Fault::Local("does not match its digest".into()));
            }
            self.bucket.put(key, buffer, Some(blake3))?;
            Ok(())
        } else {
            self.multipart(key, blake3, object, len, reader, buffer)
        }
    }

    /// Every part is read once, in order, and hashed as it is read: the bytes that go into the upload are the bytes
    /// checked. A part the bucket already holds from an earlier try is read and hashed but not sent. The upload
    /// completes only when the whole digest matches, and is aborted otherwise.
    fn multipart(
        &self,
        key: &str,
        blake3: &str,
        object: &ObjectRef,
        len: u64,
        reader: &mut impl Read,
        buffer: &mut Vec<u8>,
    ) -> std::result::Result<(), Fault> {
        let local = |e: &dyn std::fmt::Display| Fault::Local(format!("local object: {e}"));
        let part = self.settings.part_bytes.max(len.div_ceil(10_000));
        let recorded = self
            .store
            .read(|c| offload::upload(c, key))
            .map_err(store_failed)?;
        let mut held = Vec::new();
        let upload = match recorded {
            Some((id, bytes)) if bytes == part => match self.bucket.list_parts(key, &id) {
                Ok(parts) => {
                    held = parts;
                    id
                }
                Err(e) if e.not_found => self.start_multipart(key, blake3, part)?,
                Err(e) => return Err(e.into()),
            },
            Some((id, _)) => {
                let _ = self.bucket.abort(key, &id);
                self.start_multipart(key, blake3, part)?
            }
            None => self.start_multipart(key, blake3, part)?,
        };
        let count = len.div_ceil(part) as u32;
        let mut done = Vec::with_capacity(count as usize);
        let mut hasher = blake3::Hasher::new();
        for number in 1..=count {
            let offset = u64::from(number - 1) * part;
            let size = part.min(len - offset);
            fill(reader, size, buffer).map_err(|e| local(&e))?;
            hasher.update(buffer);
            if let Some((_, etag, _)) = held.iter().find(|(n, _, l)| *n == number && *l == size) {
                done.push((number, etag.clone()));
                continue;
            }
            let etag = self.bucket.upload_part(key, &upload, number, buffer)?;
            done.push((number, etag));
        }
        let mut extra = [0u8; 1];
        if reader.read(&mut extra).map_err(|e| local(&e))? != 0
            || !digest_is(hasher.finalize(), object)
        {
            // Nothing was made visible: the parts stay invisible until `complete`, and they are discarded now.
            let _ = self.bucket.abort(key, &upload);
            let owned = key.to_owned();
            let _ = self
                .store
                .writer()
                .write(move |tx| offload::forget_upload(tx, &owned));
            return Err(Fault::Local("does not match its digest".into()));
        }
        self.bucket.complete(key, &upload, &done)?;
        let key = key.to_owned();
        self.store
            .writer()
            .write(move |tx| offload::forget_upload(tx, &key))
            .map_err(store_failed)?;
        Ok(())
    }

    fn start_multipart(&self, key: &str, blake3: &str, part: u64) -> BucketResult<String> {
        let id = self.bucket.create_multipart(key, Some(blake3))?;
        let (k, i) = (key.to_owned(), id.clone());
        let now = UnixMillis::now();
        self.store
            .writer()
            .write(move |tx| offload::record_upload(tx, &k, &i, part, now))
            .map_err(store_failed)?;
        Ok(id)
    }

    fn replicate_logs(&self, pass: &mut Pass, run: &mut Run) -> std::result::Result<(), String> {
        let settled = UnixMillis(now_ms() - LOG_SETTLE_MS);
        let window = self.window(LOGS_PER_PASS);
        let rows = self
            .store
            .read(|c| offload::unreplicated_logs(c, settled, window))
            .map_err(|e| e.to_string())?;
        let now = Instant::now();
        let due: Vec<offload::LogRef> = {
            let mut parking = self.parking();
            if (rows.len() as u32) < window && parking.holds(is_log) {
                let seen: HashSet<Item> = rows.iter().map(|l| Item::Log(l.attempt)).collect();
                parking.forget_unseen(&seen, is_log);
            }
            rows.into_iter()
                .filter(|l| !parking.held(&Item::Log(l.attempt), now))
                .collect()
        };
        let full = due.len() >= LOGS_PER_PASS as usize;
        let mut progressed = false;
        'logs: for log in due.into_iter().take(LOGS_PER_PASS as usize) {
            let item = Item::Log(log.attempt);
            let prefix = offload::log_prefix(log.run, log.job, log.attempt);
            let dir = self.logs.attempt_dir(log.run, log.job, log.attempt);
            let named = |why: String| format!("{prefix}: {why}");
            let mut sent = HashSet::new();
            let mut missing = false;
            let files = match std::fs::read_dir(&dir) {
                Ok(read) => read.flatten().collect::<Vec<_>>(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing = true;
                    Vec::new()
                }
                Err(e) => {
                    progressed |= self.local_fault(
                        item,
                        0,
                        &named(format!("log directory: {}", e.kind())),
                        pass,
                    );
                    continue;
                }
            };
            for entry in files {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() || name.ends_with(".tmp") || meta.len() > MAX_LOG_FILE {
                    continue;
                }
                let body = match std::fs::read(entry.path()) {
                    Ok(body) => body,
                    Err(e) => {
                        progressed |= self.local_fault(
                            item,
                            0,
                            &named(format!("log file: {}", e.kind())),
                            pass,
                        );
                        continue 'logs;
                    }
                };
                let key = format!("{prefix}{name}");
                let blake3 = blake3::hash(&body).to_hex().to_string();
                if let Err(e) = self.bucket.put(&key, &body, Some(&blake3)) {
                    self.refused(run, "log", Class::Put, item, 0, e)?;
                    progressed = true;
                    continue 'logs;
                }
                run.put_ok = true;
                sent.insert(key);
            }
            let keys = match self.bucket.list(&prefix) {
                Ok(keys) => {
                    run.list_ok = true;
                    keys
                }
                Err(e) => {
                    self.refused(run, "log", Class::List, item, 0, e)?;
                    progressed = true;
                    continue;
                }
            };
            if missing && !keys.is_empty() {
                // The local files are gone while a copy exists: that copy may be the only one, so it stays.
                progressed |= self.local_fault(
                    item,
                    0,
                    &named("the log directory is gone; the external copy is kept".into()),
                    pass,
                );
                continue;
            }
            for stale in keys.iter().filter(|k| !sent.contains(*k)) {
                if let Err(e) = self.bucket.delete(stale) {
                    self.refused(run, "log", Class::Delete, item, 0, e)?;
                    progressed = true;
                    continue 'logs;
                }
                run.delete_ok = true;
            }
            let now = UnixMillis::now();
            let copied = self
                .store
                .writer()
                .write(move |tx| offload::log_replicated(tx, &log, now))
                .map_err(|e| e.to_string())?;
            self.parking().items.remove(&item);
            match copied {
                LogCopy::Recorded => {
                    self.status.replicated_logs.fetch_add(1, Ordering::Relaxed);
                    pass.logs += 1;
                    progressed = true;
                }
                // Copied again next pass, or deleted by the delete this queued.
                LogCopy::Changed | LogCopy::Expired => progressed = true,
            }
        }
        pass.more |= full && progressed;
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
            // With no prefix configured the bucket may be shared: only this engine's own key family is ever swept.
            let old = initiated.is_some_and(|at| now - at > ABANDONED_UPLOAD_MS);
            if key.starts_with(OBJECT_KEYS)
                && !ours.contains(id.as_str())
                && old
                && self.bucket.abort(&key, &id).is_ok()
            {
                self.status.aborted_uploads.fetch_add(1, Ordering::Relaxed);
                pass.aborted += 1;
            }
        }
        Ok(())
    }

    fn measure(&self) {
        let s = &self.status;
        {
            let parking = self.parking();
            let (mut objects, mut bytes) = (0u64, 0u64);
            for (item, parked) in &parking.items {
                if is_object(item) {
                    objects += 1;
                    bytes += parked.bytes;
                }
            }
            s.parked_items
                .store(parking.items.len() as u64, Ordering::Relaxed);
            s.parked_objects.store(objects, Ordering::Relaxed);
            s.parked_bytes.store(bytes, Ordering::Relaxed);
        }
        let Ok(totals) = self.store.read(offload::totals) else {
            return;
        };
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

fn digest_is(hash: blake3::Hash, object: &ObjectRef) -> bool {
    Digest::from_bytes(*hash.as_bytes()) == object.digest
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

    fn parking(min: u64, max: u64) -> Shelf {
        Shelf {
            items: HashMap::new(),
            min: Duration::from_secs(min),
            max: Duration::from_secs(max),
            limit: MAX_PARKED,
        }
    }

    #[test]
    fn a_parked_item_waits_longer_after_each_failure_up_to_a_limit() {
        let mut parking = parking(10, 35);
        let start = Instant::now();
        let item = Item::Delete(7);
        assert!(matches!(parking.park(item, 0, start), Shelved::New));
        assert!(parking.held(&item, start + Duration::from_secs(9)));
        assert!(!parking.held(&item, start + Duration::from_secs(10)));
        for (expected, delay) in [(20, 20), (35, 40), (35, 80)] {
            assert!(matches!(parking.park(item, 0, start), Shelved::Again));
            assert!(
                parking.held(&item, start + Duration::from_secs(expected - 1)),
                "{delay}"
            );
            assert!(
                !parking.held(&item, start + Duration::from_secs(expected)),
                "{delay}"
            );
        }
    }

    #[test]
    fn parking_is_bounded_and_forgets_rows_a_full_read_no_longer_returns() {
        let mut parking = parking(10, 10);
        let now = Instant::now();
        for id in 0..MAX_PARKED as i64 {
            assert!(matches!(
                parking.park(Item::Delete(id), 0, now),
                Shelved::New
            ));
        }
        assert!(matches!(
            parking.park(Item::Delete(-1), 0, now),
            Shelved::Full
        ));
        assert!(
            matches!(parking.park(Item::Delete(3), 0, now), Shelved::Again),
            "an item already parked is still tracked when the set is full"
        );
        let seen: HashSet<Item> = (0..10).map(Item::Delete).collect();
        parking.forget_unseen(&seen, is_delete);
        assert_eq!(parking.items.len(), 10);
        assert!(parking.holds(is_delete));
        assert!(!parking.holds(is_object));
    }
}
