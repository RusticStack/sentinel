pub mod artifacts;
pub mod auth;
pub mod auto_join;
pub mod backup;
pub mod bundle;
pub mod checks;
pub mod codec;
pub mod dispatch;
pub mod email;
pub mod github_app;
pub mod github_events;
pub mod github_members;
pub mod idempotency;
pub mod intake;
pub mod jobs;
pub mod local_auth;
pub mod logs;
pub mod lookup;
pub mod mfa;
pub mod oauth;
pub mod objects;
pub mod offload;
pub mod operations;
pub mod organizations;
pub mod poll;
pub mod provenance;
pub mod registration;
pub mod replicate;
pub mod reseal;
pub mod retention;
pub mod runs;
pub mod schema;
pub mod secrets;
pub mod setup;
pub mod sign_in;
pub mod sources;
pub mod sources_forge;
pub mod space;
pub mod status;
pub mod tenancy;
pub mod tokens;
pub mod upgrade;
pub mod views;
pub mod workers;

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

pub use rusqlite::Connection;
pub use rusqlite::Transaction;
use rusqlite::{OpenFlags, TransactionBehavior};

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    Conflict,
    NotFound,
    Forbidden,
    StepUpRequired,
    InvalidInput(&'static str),
    Transition(sentinel_core::TransitionError),
    Corrupt(&'static str),
    Spec(sentinel_pipeline::run::SpecError),
    WriterUnavailable,
    WriteAmbiguous,
    WriterPanicked,
    Overloaded,
    AlreadyOwned,
    Unresolved,
    StorageFull,
    QuotaExceeded,
    IdempotencyMismatch,
    Io(std::io::Error),
    MigrationFailed {
        from: u32,
        reached: u32,
        snapshot: Option<String>,
        cause: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::Conflict => f.write_str("concurrent modification; retry from a fresh read"),
            Self::NotFound => f.write_str("not found"),
            Self::Forbidden => f.write_str("forbidden"),
            Self::StepUpRequired => f.write_str("step-up required"),
            Self::InvalidInput(what) => write!(f, "invalid {what}"),
            Self::Transition(e) => write!(f, "transition rejected: {e:?}"),
            Self::Corrupt(what) => write!(f, "corrupt {what}"),
            Self::Spec(e) => write!(f, "run spec: {e:?}"),
            Self::WriterUnavailable => f.write_str("writer unavailable"),
            Self::WriteAmbiguous => f.write_str("write outcome unknown; re-read before retrying"),
            Self::WriterPanicked => f.write_str("write closure panicked; transaction rolled back"),
            Self::Overloaded => f.write_str("reader pool exhausted"),
            Self::AlreadyOwned => f.write_str("database is owned by another process"),
            Self::Unresolved => f.write_str("image digest and platform not yet resolved"),
            Self::StorageFull => f.write_str("storage admission refused: disk below watermark"),
            Self::QuotaExceeded => f.write_str("tenant storage quota exceeded"),
            Self::IdempotencyMismatch => {
                f.write_str("idempotency key reused for a different request")
            }
            Self::Io(e) => write!(f, "io: {e}"),
            Self::MigrationFailed {
                from,
                reached,
                snapshot,
                cause,
            } => {
                write!(
                    f,
                    "upgrading the database from schema {from} failed at migration {}: {cause};                      it is at schema {reached}",
                    reached + 1
                )?;
                match snapshot {
                    Some(path) => write!(
                        f,
                        "; to roll back, stop, replace metadata.sqlite with {path} and start the previous release"
                    ),
                    None => f.write_str("; restore the last backup to roll back"),
                }
            }
        }
    }
}
impl std::error::Error for Error {}

impl Error {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::WriterUnavailable | Self::WriteAmbiguous | Self::Overloaded => true,
            Self::Sqlite(rusqlite::Error::SqliteFailure(failure, _)) => matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ),
            _ => false,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::StepUpRequired => "step_up_required",
            Self::InvalidInput(_) => "invalid_input",
            Self::Transition(_) => "transition",
            Self::Corrupt(_) => "corrupt",
            Self::Spec(_) => "spec",
            Self::WriterUnavailable => "writer_unavailable",
            Self::WriteAmbiguous => "write_ambiguous",
            Self::WriterPanicked => "writer_panicked",
            Self::Overloaded => "overloaded",
            Self::AlreadyOwned => "already_owned",
            Self::Unresolved => "unresolved",
            Self::StorageFull => "storage_full",
            Self::QuotaExceeded => "quota_exceeded",
            Self::IdempotencyMismatch => "idempotency_mismatch",
            Self::Io(_) => "io",
            Self::MigrationFailed { .. } => "migration_failed",
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<sentinel_core::TransitionError> for Error {
    fn from(e: sentinel_core::TransitionError) -> Self {
        Self::Transition(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Only Full is safe for state transitions; Normal is for replayable data and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Full,
    Normal,
}

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn configure(conn: &Connection, durability: Durability) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let sync = match durability {
        Durability::Full => "FULL",
        Durability::Normal => "NORMAL",
    };
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous={sync}; PRAGMA foreign_keys=ON;
         PRAGMA temp_store=MEMORY;"
    ))?;
    register_functions(conn)
}

pub fn register_functions(conn: &Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "sentinel_labels_subset",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let job = ctx.get_raw(0).as_blob_or_null()?.unwrap_or_default();
            let worker = ctx.get_raw(1).as_blob_or_null()?.unwrap_or_default();
            Ok(dispatch::labels_subset(job, worker))
        },
    )?;
    Ok(())
}

pub fn migrate(conn: &mut Connection) -> Result<u32> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(
            version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL)",
    )?;
    let mut current: u32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    if current > schema::LATEST {
        let needs: Option<u32> = conn
            .query_row(
                "SELECT MAX(COALESCE(readable_by, version)) FROM schema_migrations
                 WHERE version > ?1",
                [schema::LATEST],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        return match needs {
            Some(needs) if needs <= schema::LATEST => Ok(current),
            _ => Err(Error::Corrupt("unsupported database version")),
        };
    }
    for &(version, sql) in schema::MIGRATIONS {
        if version <= current {
            continue;
        }
        if version != current + 1 {
            return Err(Error::Corrupt("migration order"));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        if version >= schema::READABLE_BY_SINCE {
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_ms, readable_by) VALUES (?1, ?2, ?3)",
                (version, sentinel_core::UnixMillis::now().0, schema::readable_by(version)),
            )?;
        } else {
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_ms) VALUES (?1, ?2)",
                (version, sentinel_core::UnixMillis::now().0),
            )?;
        }
        tx.commit()?;
        current = version;
    }
    Ok(current)
}

type Job = Box<dyn FnOnce(&mut Connection, &Changes) + Send>;

#[derive(Debug, Default)]
pub struct Changes {
    generation: AtomicU64,
    waiters: AtomicUsize,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Changes {
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn wait_past(&self, seen: u64, deadline: Instant) -> u64 {
        // Register before reading the generation: committed() checks waiters after bumping it, so no wakeup is lost.
        self.waiters.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let generation = loop {
            let now = self.generation.load(Ordering::SeqCst);
            if now != seen {
                break now;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break now;
            }
            guard = self
                .cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        };
        drop(guard);
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        generation
    }

    pub fn nudge(&self) {
        self.committed();
    }

    #[inline]
    fn committed(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if self.waiters.load(Ordering::SeqCst) != 0 {
            let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            self.cv.notify_all();
        }
    }
}

pub const READER_LIMIT: usize = 8;
pub const READ_ADMISSION: Duration = Duration::from_secs(2);
pub const WRITE_WAIT: Duration = Duration::from_secs(10);

pub const WRITER_QUEUE: usize = 256;

pub const METADATA_FILE: &str = "metadata.sqlite";

pub const MASTER_KEY_FILE: &str = "master.key";

fn lock_path(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

pub struct Writer {
    sender: SyncSender<Job>,
    thread: Option<thread::JoinHandle<()>>,
    drained: Arc<(Mutex<bool>, Condvar)>,
    changes: Arc<Changes>,
}

impl Writer {
    fn start(mut conn: Connection, capacity: usize) -> Writer {
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let drained = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&drained);
        let changes = Arc::new(Changes::default());
        let notifier = Arc::clone(&changes);
        let thread = thread::Builder::new()
            .name("sentinel-store-writer".into())
            .spawn(move || {
                for job in receiver {
                    job(&mut conn, &notifier);
                }
                let (flag, wake) = &*signal;
                *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
                wake.notify_all();
            })
            .expect("spawn writer thread");
        Writer {
            sender,
            thread: Some(thread),
            drained,
            changes,
        }
    }

    pub fn write<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>) -> Result<T> + Send + 'static,
    {
        self.raw(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let value = f(&tx)?;
            tx.commit()?;
            Ok(value)
        })
    }

    pub fn raw<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, done) = mpsc::sync_channel::<Result<T>>(1);
        let job: Job = Box::new(move |conn, changes| {
            let before = conn.total_changes();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(conn)))
                .unwrap_or(Err(Error::WriterPanicked));
            // Notify before the reply: a caller must never see a generation older than its own write.
            if result.is_ok() && conn.total_changes() != before {
                changes.committed();
            }
            let _ = reply.send(result);
        });
        match self.sender.try_send(job) {
            Ok(()) => match done.recv_timeout(WRITE_WAIT) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => Err(Error::WriteAmbiguous),
                Err(RecvTimeoutError::Disconnected) => Err(Error::WriterUnavailable),
            },
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                Err(Error::WriterUnavailable)
            }
        }
    }

    fn drain(&mut self, timeout: Duration) -> bool {
        let (dead, _) = mpsc::sync_channel(0);
        drop(std::mem::replace(&mut self.sender, dead));
        let (flag, wake) = &*self.drained;
        let guard = flag.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, _) = wake
            .wait_timeout_while(guard, timeout, |done| !*done)
            .unwrap_or_else(|p| p.into_inner());
        let drained = *guard;
        drop(guard);
        if drained && let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        drained
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.drain(WRITE_WAIT);
    }
}

struct Readers {
    idle: Vec<Connection>,
    open: usize,
}

pub struct Store {
    path: PathBuf,
    durability: Durability,
    writer: Writer,
    readers: Mutex<Readers>,
    freed: Condvar,
    _owner: std::fs::File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    Drained,
    Stalled,
}

impl Store {
    pub fn snapshot_into(&self, dest: &Path) -> Result<()> {
        let dest = dest
            .to_str()
            .ok_or(Error::InvalidInput("snapshot path must be UTF-8"))?
            .to_owned();
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute("VACUUM INTO ?1", [dest])?;
        Ok(())
    }

    pub fn metadata_bytes(&self) -> u64 {
        let mut wal = self.path.clone().into_os_string();
        wal.push("-wal");
        [self.path.as_path(), Path::new(&wal)]
            .into_iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    pub fn open(path: impl AsRef<Path>, durability: Durability) -> Result<Store> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        let owner = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(&path))
            .map_err(Error::Io)?;
        match owner.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(Error::AlreadyOwned),
            Err(std::fs::TryLockError::Error(e)) => return Err(Error::Io(e)),
        }
        let mut conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn, durability)?;
        migrate(&mut conn)?;
        Ok(Store {
            path,
            durability,
            writer: Writer::start(conn, WRITER_QUEUE),
            readers: Mutex::new(Readers {
                idle: Vec::new(),
                open: 0,
            }),
            freed: Condvar::new(),
            _owner: owner,
        })
    }

    pub fn writer(&self) -> &Writer {
        &self.writer
    }

    pub fn changes(&self) -> &Changes {
        &self.writer.changes
    }

    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.admit()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&conn)));
        self.readers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .idle
            .push(conn);
        self.freed.notify_one();
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn admit(&self) -> Result<Connection> {
        let mut pool = self.readers.lock().unwrap_or_else(|p| p.into_inner());
        let deadline = std::time::Instant::now() + READ_ADMISSION;
        loop {
            if let Some(conn) = pool.idle.pop() {
                return Ok(conn);
            }
            if pool.open < READER_LIMIT {
                pool.open += 1;
                drop(pool);
                return self.open_reader().inspect_err(|_| {
                    self.readers.lock().unwrap_or_else(|p| p.into_inner()).open -= 1;
                    self.freed.notify_one();
                });
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Overloaded);
            }
            let (guard, _) = self
                .freed
                .wait_timeout(pool, remaining)
                .unwrap_or_else(|p| p.into_inner());
            pool = guard;
        }
    }

    fn open_reader(&self) -> Result<Connection> {
        let c = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&c, self.durability)?;
        c.execute_batch("PRAGMA query_only=ON")?;
        Ok(c)
    }

    pub fn shutdown(self, timeout: Duration) -> Shutdown {
        let Store {
            mut writer, _owner, ..
        } = self;
        if writer.drain(timeout) {
            return Shutdown::Drained;
        }
        // Keep the lock: unfinished work still runs here, and a second controller must not open the database beneath it.
        std::mem::forget(_owner);
        std::mem::forget(writer);
        Shutdown::Stalled
    }

    pub fn checkpoint(&self) -> Result<Checkpointed> {
        self.writer.raw(|conn| {
            conn.busy_timeout(CHECKPOINT_BUDGET)?;
            let outcome = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                r.get::<_, i64>(0)
            });
            conn.busy_timeout(BUSY_TIMEOUT)?;
            match outcome {
                Ok(0) => Ok(Checkpointed::Complete),
                Ok(_) => Ok(Checkpointed::Partial),
                Err(rusqlite::Error::SqliteFailure(failure, _))
                    if matches!(
                        failure.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    Ok(Checkpointed::Partial)
                }
                Err(e) => Err(e.into()),
            }
        })
    }
}

pub const CHECKPOINT_BUDGET: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checkpointed {
    Complete,
    Partial,
}

#[cfg(test)]
mod transient_tests {
    use super::Error;

    #[test]
    fn only_unavailability_is_transient() {
        for error in [
            Error::WriterUnavailable,
            Error::WriteAmbiguous,
            Error::Overloaded,
        ] {
            assert!(error.is_transient(), "{}", error.kind());
        }
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        );
        assert!(Error::Sqlite(busy).is_transient());
        let constraint = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            None,
        );
        for error in [
            Error::Conflict,
            Error::NotFound,
            Error::Forbidden,
            Error::WriterPanicked,
            Error::Corrupt("x"),
            Error::Sqlite(constraint),
        ] {
            assert!(!error.is_transient(), "{}", error.kind());
        }
    }
}
