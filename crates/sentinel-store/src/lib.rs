//! Local SQLite metadata store.
//!
//! One process owns the database. All writes go through a single dedicated
//! thread that holds the only write connection ([`Writer`]); callers submit a
//! closure and block for the result, which is returned only after `COMMIT`
//! has completed with `synchronous=FULL`. Reads use separate WAL snapshots.
//! Controller primitives are tenant-scoped; client operations in [`auth`]
//! additionally enforce live identity, scope, memberships and repository grants.
//!
//! Chosen after measuring redb and SQLite on the same dispatch workload: both
//! are fsync-bound at ~0.5 ms per durable commit; SQLite adds constraints,
//! indexes, migrations and ad-hoc queries at no extra cost.

pub mod auth;
pub mod codec;
pub mod dispatch;
pub mod idempotency;
pub mod jobs;
pub mod local_auth;
pub mod lookup;
pub mod mfa;
pub mod registration;
pub mod runs;
pub mod schema;
pub mod sign_in;
pub mod tenancy;
pub mod tokens;
pub mod workers;

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

/// The transaction type writer closures receive; re-exported so callers
/// outside this crate can name it without depending on rusqlite.
pub use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    /// Compare-and-set failed: the row changed between read and write.
    Conflict,
    /// Row does not exist for this tenant (also returned for other tenants' rows).
    NotFound,
    Forbidden,
    /// Allowed in principle, but the session must first prove presence with a
    /// second factor (A06). Distinct from `Forbidden` so a client can prompt.
    StepUpRequired,
    InvalidInput(&'static str),
    /// The state machine rejected the event.
    Transition(sentinel_core::TransitionError),
    /// Persisted value could not be decoded; the database is corrupt or newer.
    Corrupt(&'static str),
    /// A run specification could not be built or encoded.
    Spec(sentinel_pipeline::run::SpecError),
    /// Writer queue is full or the writer has stopped. Nothing was attempted.
    WriterUnavailable,
    /// The writer accepted the work but did not answer within [`WRITE_WAIT`].
    /// The transaction may still commit later: treat the outcome as unknown
    /// and re-read before retrying anything that is not idempotent.
    WriteAmbiguous,
    /// The closure panicked. Its transaction was rolled back and the writer
    /// keeps serving; the caller's own invariants are what to check.
    WriterPanicked,
    /// Every reader is busy and none freed up within [`READ_ADMISSION`].
    /// Back-pressure, not corruption: retry later or shed the request.
    Overloaded,
    /// Another process holds this database. One controller owns the metadata
    /// store; a second one is a deployment error, never a peer.
    AlreadyOwned,
    /// A job cannot be admitted to execution because its image digest and
    /// platform have not been durably resolved (C05/W03 gate).
    Unresolved,
    Io(std::io::Error),
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
    if current > schema::MIGRATIONS.last().map_or(0, |m| m.0) {
        return Err(Error::Corrupt("unsupported database version"));
    }
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

/// Readers admitted at once. Each holds a WAL snapshot and a file descriptor;
/// beyond this many, a request waits briefly and is then shed rather than
/// opening connections without bound.
pub const READER_LIMIT: usize = 8;
/// How long a read waits for a pooled reader before reporting `Overloaded`.
pub const READ_ADMISSION: Duration = Duration::from_secs(2);
/// How long a caller waits for the writer's answer before reporting the
/// outcome as ambiguous. Long enough for a slow fsync, short enough that a
/// stalled disk surfaces as a bounded error rather than a hung request.
pub const WRITE_WAIT: Duration = Duration::from_secs(10);

/// Bounded writer queue: enough for a burst of webhook intake, small enough
/// that a stalled disk surfaces as `WriterUnavailable` within milliseconds.
pub const WRITER_QUEUE: usize = 256;

/// The controller's metadata database inside its data directory. One file name
/// for every role and tool, so a host-local command cannot open a second,
/// accidentally empty database beside the real one.
pub const METADATA_FILE: &str = "metadata.sqlite";

/// The sealing key for values that must be recoverable (A06 TOTP seeds). Lives
/// beside the database by default, but it is the operator's secret: keep it
/// out of database backups, and treat losing it as losing every sealed value.
pub const MASTER_KEY_FILE: &str = "master.key";

/// The ownership lock beside the database. Advisory, held open for the life of
/// the process, released by the OS on exit — including a crash.
fn lock_path(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// The single write path. Dropping it stops the thread after queued work.
pub struct Writer {
    sender: SyncSender<Job>,
    thread: Option<thread::JoinHandle<()>>,
    drained: Arc<(Mutex<bool>, Condvar)>,
}

impl Writer {
    fn start(mut conn: Connection, capacity: usize) -> Writer {
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let drained = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&drained);
        let thread = thread::Builder::new()
            .name("sentinel-store-writer".into())
            .spawn(move || {
                for job in receiver {
                    job(&mut conn);
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
    ///
    /// A panic inside `f` is caught on the writer thread: the transaction it
    /// was in unwinds and rolls back, the caller gets `WriterPanicked`, and
    /// the writer keeps serving everybody else. Waiting is bounded by
    /// [`WRITE_WAIT`]; past it the answer is `WriteAmbiguous`, which is the
    /// truth — the work is still queued or running and may yet commit.
    pub fn raw<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, done) = mpsc::sync_channel::<Result<T>>(1);
        let job: Job = Box::new(move |conn| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(conn)))
                .unwrap_or(Err(Error::WriterPanicked));
            // A caller that stopped waiting is not an error for the writer.
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

    /// Close the queue and wait up to `timeout` for accepted work to finish.
    /// Returns whether it did. A stalled writer is left to finish on its own
    /// rather than joined forever; nothing accepted is discarded either way.
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
        // Accepted work is durable intent: give it the same bound as a write.
        self.drain(WRITE_WAIT);
    }
}

/// Idle read connections plus how many exist in total, so admission is
/// bounded by connections opened, not by connections currently idle.
struct Readers {
    idle: Vec<Connection>,
    open: usize,
}

/// Handle to one database: the writer plus a bounded pool of read connections.
pub struct Store {
    path: PathBuf,
    durability: Durability,
    writer: Writer,
    readers: Mutex<Readers>,
    freed: Condvar,
    /// Held for the life of the store. One controller owns the metadata
    /// database; the lock is what makes a second one fail at startup instead
    /// of at the first conflicting write.
    _owner: std::fs::File,
}

/// Whether an orderly shutdown finished its accepted work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    Drained,
    /// Work was still running when the bound expired. It was not discarded;
    /// the process should report the stall rather than claim a clean stop.
    Stalled,
}

impl Store {
    /// Open or create the database at `path`, apply migrations, start the writer.
    ///
    /// Fails with [`Error::AlreadyOwned`] if another live process holds the
    /// database: SQLite serializes writes, but it does not make two
    /// controllers one scheduler.
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

    /// Run a read-only closure on a pooled connection using committed WAL
    /// snapshots. At most [`READER_LIMIT`] connections exist; a caller that
    /// finds them all busy waits up to [`READ_ADMISSION`] and is then shed
    /// with `Overloaded`.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.admit()?;
        let result = f(&conn);
        self.readers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .idle
            .push(conn);
        self.freed.notify_one();
        result
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

    /// Stop accepting writes and wait up to `timeout` for accepted ones to
    /// finish, then release ownership. Consumes the store, so no request can
    /// observe a half-stopped handle.
    pub fn shutdown(self, timeout: Duration) -> Shutdown {
        let Store {
            mut writer, _owner, ..
        } = self;
        if writer.drain(timeout) {
            return Shutdown::Drained;
        }
        // The writer thread is still this process's, and so is the database:
        // keep the lock until the process exits rather than inviting a second
        // controller in underneath unfinished work. Leaking one descriptor and
        // one handle is the cost of not lying about ownership.
        std::mem::forget(_owner);
        std::mem::forget(writer);
        Shutdown::Stalled
    }

    /// Fold the WAL back into the main file; call at quiet moments and on shutdown.
    pub fn checkpoint(&self) -> Result<()> {
        self.writer.raw(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            Ok(())
        })
    }
}
