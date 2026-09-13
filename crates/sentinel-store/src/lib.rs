//! Local SQLite metadata store.
//!
//! One process owns the database. All writes go through a single dedicated
//! thread that holds the only write connection ([`Writer`]); callers submit a
//! closure and block for the result, which is returned only after `COMMIT`
//! has completed with `synchronous=FULL`, so **an acknowledged write is on
//! disk**. Reads use separate connections in WAL mode and never block the
//! writer. Every query is tenant-scoped by predicate.
//!
//! Chosen after measuring redb and SQLite on the same dispatch workload: both
//! are fsync-bound at ~0.5 ms per durable commit; SQLite adds constraints,
//! indexes, migrations and ad-hoc queries at no extra cost.

pub mod codec;
pub mod idempotency;
pub mod jobs;
pub mod runs;
pub mod schema;

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    /// Compare-and-set failed: the row changed between read and write.
    Conflict,
    /// Row does not exist for this tenant (also returned for other tenants' rows).
    NotFound,
    /// The state machine rejected the event.
    Transition(sentinel_core::TransitionError),
    /// Persisted value could not be decoded; the database is corrupt or newer.
    Corrupt(&'static str),
    /// A run specification could not be built or encoded.
    Spec(sentinel_pipeline::run::SpecError),
    /// Writer queue is full or the writer has stopped.
    WriterUnavailable,
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::Conflict => f.write_str("concurrent modification; retry from a fresh read"),
            Self::NotFound => f.write_str("not found"),
            Self::Transition(e) => write!(f, "transition rejected: {e:?}"),
            Self::Corrupt(what) => write!(f, "corrupt {what}"),
            Self::Spec(e) => write!(f, "run spec: {e:?}"),
            Self::WriterUnavailable => f.write_str("writer unavailable"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<sentinel_core::TransitionError> for Error {
    fn from(e: sentinel_core::TransitionError) -> Self {
        Self::Transition(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Durability of acknowledged writes. `Full` is the only setting for state
/// transitions; `Normal` exists for replayable data and tests.
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
    Ok(())
}

/// Apply pending migrations. Idempotent; each version commits separately.
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
    for &(version, sql) in schema::MIGRATIONS {
        if version <= current {
            continue;
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_ms) VALUES (?1, ?2)",
            (version, sentinel_core::UnixMillis::now().0),
        )?;
        tx.commit()?;
        current = version;
    }
    Ok(current)
}

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// The single write path. Dropping it stops the thread after queued work.
pub struct Writer {
    sender: SyncSender<Job>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Writer {
    fn start(mut conn: Connection, capacity: usize) -> Writer {
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let thread = thread::Builder::new()
            .name("sentinel-store-writer".into())
            .spawn(move || {
                for job in receiver {
                    job(&mut conn);
                }
            })
            .expect("spawn writer thread");
        Writer {
            sender,
            thread: Some(thread),
        }
    }

    /// Run `f` inside one `BEGIN IMMEDIATE` transaction on the writer thread and
    /// block until it has committed (or rolled back). Returns
    /// [`Error::WriterUnavailable`] immediately if the bounded queue is full:
    /// callers must apply back-pressure rather than pile up requests.
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

    /// Run `f` on the writer thread outside any transaction (checkpoints,
    /// maintenance). Same queue and back-pressure as `write`.
    pub fn raw<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, done) = mpsc::sync_channel::<Result<T>>(1);
        let job: Job = Box::new(move |conn| {
            // A caller that stopped waiting is not an error for the writer.
            let _ = reply.send(f(conn));
        });
        match self.sender.try_send(job) {
            Ok(()) => done.recv().unwrap_or(Err(Error::WriterUnavailable)),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                Err(Error::WriterUnavailable)
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Close the queue; the thread drains what was accepted, then exits.
        let (dead, _) = mpsc::sync_channel(0);
        drop(std::mem::replace(&mut self.sender, dead));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Handle to one database: the writer plus a pool of read connections.
pub struct Store {
    path: PathBuf,
    durability: Durability,
    writer: Writer,
    readers: Mutex<Vec<Connection>>,
}

/// Bounded writer queue: enough for a burst of webhook intake, small enough
/// that a stalled disk surfaces as `WriterUnavailable` within milliseconds.
pub const WRITER_QUEUE: usize = 256;

impl Store {
    /// Open or create the database at `path`, apply migrations, start the writer.
    pub fn open(path: impl AsRef<Path>, durability: Durability) -> Result<Store> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
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
            readers: Mutex::new(Vec::new()),
        })
    }

    pub fn writer(&self) -> &Writer {
        &self.writer
    }

    /// Run a read-only closure on a pooled connection. Reads see the last
    /// committed state and never wait for the writer.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = match self.readers.lock().unwrap_or_else(|p| p.into_inner()).pop() {
            Some(c) => c,
            None => {
                let c = Connection::open_with_flags(
                    &self.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                configure(&c, self.durability)?;
                c.execute_batch("PRAGMA query_only=ON")?;
                c
            }
        };
        let result = f(&conn);
        self.readers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(conn);
        result
    }

    /// Fold the WAL back into the main file; call at quiet moments and on shutdown.
    pub fn checkpoint(&self) -> Result<()> {
        self.writer.raw(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            Ok(())
        })
    }
}
