//! Active-use leases: the pin that keeps garbage collection away from a
//! generation while it is being read, cloned or published.
//!
//! A lease is one file under `<entry>/lease/<id>` containing
//! `<expires_unix_ms> <owner>`. Acquisition is `create_new`, so two
//! holders can never share a name; release deletes it. A crashed holder's
//! lease expires on its own — collection treats a lease as active while
//! `min(declared expiry, mtime + MAX_TTL)` is in the future, so a torn
//! write reads as fresh, never as collectible, until it is provably stale.
//!
//! A lease lives exactly as long as its holder does (P07-13): every held
//! lease is registered with this process's keeper, which renews each one
//! to its own TTL every [`RENEW_EVERY`] — so an attempt that runs for
//! hours keeps its pin, while a process that dies stops renewing and its
//! markers age out within the TTL.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};

use crate::scope::{LEASE_NAME, WRITING_NAME};

/// A lease's declared expiry may never exceed this far past its file's
/// mtime — the bound that lets a corrupt lease age out.
pub const MAX_TTL: Duration = Duration::from_secs(30 * 60);
/// The default pin a materialization takes; clones have their own
/// deadlines, this outlasts them.
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
/// Lease file bodies are one line; a larger file is treated as corrupt.
const MAX_BODY: usize = 256;
/// Owner strings identify the holder for diagnostics: ids and short
/// descriptions, `a-zA-Z0-9_-`, 1..=64 bytes.
const MAX_OWNER: usize = 64;

#[derive(Debug)]
pub enum LeaseError {
    /// The owner string is empty, overlong or carries unsafe bytes.
    BadOwner,
    Io(std::io::Error),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadOwner => write!(f, "lease owner is not [a-zA-Z0-9_-]{{1,64}}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for LeaseError {}
impl From<std::io::Error> for LeaseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= MAX_OWNER
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// How often the keeper renews every lease this process holds. A quarter
/// of the default pin: a renewal can be late by a whole period and the
/// lease is still live.
pub const RENEW_EVERY: Duration = Duration::from_secs(DEFAULT_TTL.as_secs() / 4);

/// The leases this process holds: marker path → (owner, ttl).
fn held() -> &'static Mutex<HashMap<PathBuf, (String, Duration)>> {
    static HELD: OnceLock<Mutex<HashMap<PathBuf, (String, Duration)>>> = OnceLock::new();
    HELD.get_or_init(|| {
        // One keeper thread per process, started with the first lease.
        let _ = std::thread::Builder::new()
            .name("sentinel-cache-leases".into())
            .spawn(|| {
                loop {
                    std::thread::sleep(RENEW_EVERY);
                    renew_held();
                }
            });
        Mutex::new(HashMap::new())
    })
}

/// Renew every lease this process holds, each to its own TTL; returns
/// how many markers were rewritten. The keeper calls this every
/// [`RENEW_EVERY`]; tests call it directly. A marker that is already gone
/// (released, or reaped after an outage) is never recreated.
#[doc(hidden)]
pub fn renew_held() -> usize {
    let held = held().lock().unwrap_or_else(|p| p.into_inner());
    held.iter()
        .filter(|(file, (owner, ttl))| rewrite(file, owner, *ttl).is_ok())
        .count()
}

/// Rewrite an existing marker's body — and so its mtime — with a fresh
/// expiry. `create(false)`: renewal never resurrects a removed lease.
fn rewrite(file: &Path, owner: &str, ttl: Duration) -> std::io::Result<()> {
    use std::io::Write;
    let expires = unix_ms() + ttl.min(MAX_TTL).as_millis() as i64;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file)?;
    f.write_all(format!("{expires} {owner}").as_bytes())
}

/// A held pin on `entry`. Dropping it removes the marker; a process that
/// dies first leaves it to expire.
pub struct Lease {
    file: PathBuf,
    owner: String,
}

impl Lease {
    /// Pin `entry` for `owner` for up to `ttl`. `owner` is diagnostic —
    /// an attempt id or subsystem name, never secrets.
    pub fn acquire(entry: &Path, owner: &str, ttl: Duration) -> Result<Lease, LeaseError> {
        if !valid_owner(owner) {
            return Err(LeaseError::BadOwner);
        }
        let dir = entry.join(LEASE_NAME);
        fs::create_dir_all(&dir)?;
        let expires = unix_ms() + ttl.min(MAX_TTL).as_millis() as i64;
        // create_new makes a duplicate name a retryable collision rather
        // than a silent share. Two attempts is generous: names carry an
        // attempt/random tail.
        for attempt in 0..2 {
            let id = format!("l{}-{:08x}", unix_ms(), rand_u32().wrapping_add(attempt));
            let file = dir.join(id);
            match fs::File::create_new(&file) {
                Ok(mut f) => {
                    use std::io::Write;
                    f.write_all(format!("{expires} {owner}").as_bytes())?;
                    f.sync_data()?;
                    held()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(file.clone(), (owner.to_owned(), ttl));
                    return Ok(Lease {
                        file,
                        owner: owner.to_owned(),
                    });
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(LeaseError::Io(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "lease name collision",
        )))
    }

    /// Extend the pin now, and have the keeper keep extending it to `ttl`;
    /// a failed renew keeps the old expiry — callers that still need the
    /// pin must re-acquire rather than assume it.
    pub fn renew(&self, ttl: Duration) -> Result<(), LeaseError> {
        rewrite(&self.file, &self.owner, ttl)?;
        if let Some(slot) = held()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&self.file)
        {
            slot.1 = ttl;
        }
        Ok(())
    }

    /// The marker path, for diagnostics.
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// Release early. A failed remove is safe: the lease still expires.
    pub fn release(self) -> Result<(), LeaseError> {
        forget(&self.file);
        fs::remove_file(&self.file)?;
        Ok(())
    }
}

/// Stop renewing a marker: deregistered first, so the keeper can never
/// rewrite a lease whose holder has let go.
fn forget(file: &Path) {
    held()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(file);
}

impl Drop for Lease {
    fn drop(&mut self) {
        forget(&self.file);
        let _ = fs::remove_file(&self.file);
    }
}

/// The writer-ownership marker inside `<entry>/writing/` (K03). One
/// writer per entry: the marker is `create_new`, so acquisition can never
/// share or wait — a held marker is `Busy`, a stale one is a dead
/// writer's and is reaped in place.
pub const WRITE_LOCK_NAME: &str = ".lock";

/// A held claim on `entry`'s staging area. The marker is not a lease and
/// does not pin the entry against collection — its body carries the same
/// `<expires> <owner>` shape so `live()` reads it with the same
/// conservative staleness rule, and GC removes the `writing/` tree only
/// once the marker provably aged out.
pub struct WriteLock {
    file: PathBuf,
}

impl WriteLock {
    /// Take exclusive staging ownership of `entry` for `owner`. `Ok(None)`
    /// is a live writer already holding it — callers skip, they never
    /// block a job on cache publication. A marker whose declared expiry or
    /// mtime bound has passed is removed and the acquisition retried.
    pub fn acquire(entry: &Path, owner: &str) -> Result<Option<WriteLock>, LeaseError> {
        if !valid_owner(owner) {
            return Err(LeaseError::BadOwner);
        }
        let dir = entry.join(WRITING_NAME);
        let file = dir.join(WRITE_LOCK_NAME);
        // Three turns: the first can race the directory's absence or a
        // stale marker, the second reaps either, the third takes it.
        for _ in 0..3 {
            match fs::File::create_new(&file) {
                Ok(mut f) => {
                    use std::io::Write;
                    let expires = unix_ms() + MAX_TTL.as_millis() as i64;
                    f.write_all(format!("{expires} {owner}").as_bytes())?;
                    f.sync_data()?;
                    return Ok(Some(WriteLock { file }));
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if live(&file, unix_ms()) {
                        return Ok(None);
                    }
                    // A dead writer's marker: reap and retry. Reaping is a
                    // rename, and what was moved is judged again (P07-14):
                    // when two writers race to reap the same dead marker,
                    // the slower one moves the faster one's *fresh* marker
                    // — it finds it live, puts it back and answers busy,
                    // instead of deleting it and staging alongside.
                    let dead = dir.join(format!("{WRITE_LOCK_NAME}.{:08x}.dead", rand_u32()));
                    match fs::rename(&file, &dead) {
                        Ok(()) => {
                            if live(&dead, unix_ms()) {
                                let _ = fs::hard_link(&dead, &file);
                                let _ = fs::remove_file(&dead);
                                return Ok(None);
                            }
                            let _ = fs::remove_file(&dead);
                        }
                        // Another reaper moved it first; the retry decides.
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    // `writing/` is not there yet (or was removed under
                    // us); make it and retry the marker.
                    fs::create_dir_all(&dir)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(LeaseError::Io(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "write lock did not settle",
        )))
    }

    /// The marker path, for diagnostics.
    pub fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        // The staging dir itself goes only while empty: a next writer's
        // fresh marker or staging inside it fails this remove, so the
        // release can never pull `writing/` out from under a live writer.
        if let Some(dir) = self.file.parent() {
            let _ = fs::remove_dir(dir);
        }
    }
}

/// Whether `entry`'s staging area is held by a live writer at `now_ms`.
/// The marker reads live while `min(declared expiry, mtime + MAX_TTL)` is
/// in the future — the same conservative reading a lease marker gets, so
/// a torn lock file pins until it is provably old.
pub fn writing_lock_live(entry: &Path, now_ms: i64) -> bool {
    live(&entry.join(WRITING_NAME).join(WRITE_LOCK_NAME), now_ms)
}

/// What a sweep found of `entry`'s leases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Leases {
    /// Unexpired pins — the generations their holders use stay.
    pub active: usize,
    /// Expired markers removed this pass.
    pub expired: usize,
}

/// Count `entry`'s live pins, removing expired markers. A marker is live
/// while `min(declared expiry, mtime + MAX_TTL)` is in the future, so a
/// half-written or corrupt lease still pins until it is provably old.
pub fn sweep(entry: &Path) -> Result<Leases, LeaseError> {
    let dir = entry.join(LEASE_NAME);
    let mut found = Leases::default();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e.into()),
    };
    let now = unix_ms();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if live(&path, now) {
            found.active += 1;
        } else {
            match fs::remove_file(&path) {
                Ok(()) => found.expired += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(found)
}

/// Is the marker at `path` still pinning? Corrupt bodies fall back to the
/// mtime bound — a lease we cannot read is assumed alive until it ages out.
fn live(path: &Path, now_ms: i64) -> bool {
    let declared = fs::read(path)
        .ok()
        .filter(|b| b.len() <= MAX_BODY)
        .and_then(|body| {
            body.split(|b| *b == b' ')
                .next()
                .and_then(|t| std::str::from_utf8(t).ok())
                .and_then(|t| t.parse::<i64>().ok())
        });
    let mtime_bound = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64 + MAX_TTL.as_millis() as i64);
    let expiry = match (declared, mtime_bound) {
        (Some(d), Some(m)) => d.min(m),
        (Some(d), None) => d,
        (None, Some(m)) => m,
        (None, None) => return false,
    };
    expiry > now_ms
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn rand_u32() -> u32 {
    // Cheap uniqueness, not entropy: pid xor a per-call counter.
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0x9e3779b9);
    NEXT.fetch_add(0x9e3779b9, Ordering::Relaxed) ^ (std::process::id()).rotate_left(13)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_pins_until_released_then_expired_ones_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let lease = Lease::acquire(entry, "attempt-1", DEFAULT_TTL).unwrap();
        assert_eq!(
            sweep(entry).unwrap(),
            Leases {
                active: 1,
                expired: 0
            }
        );
        let file = lease.path().to_path_buf();
        lease.release().unwrap();
        assert!(!file.exists());
        assert_eq!(sweep(entry).unwrap(), Leases::default());
    }

    #[test]
    fn an_expired_marker_sweeps_and_a_fresh_one_stays() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let _pin = Lease::acquire(entry, "attempt-1", Duration::ZERO).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(
            sweep(entry).unwrap(),
            Leases {
                active: 0,
                expired: 1
            }
        );
    }

    #[test]
    fn a_corrupt_marker_still_pins_until_it_ages() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let lease_dir = entry.join(LEASE_NAME);
        fs::create_dir_all(&lease_dir).unwrap();
        // Not a parseable lease, but just written: conservative-live.
        fs::write(lease_dir.join("torn"), b"\xff\xfe").unwrap();
        assert_eq!(sweep(entry).unwrap().active, 1);
    }

    /// P07-13: a held lease is renewed to its own TTL for as long as it is
    /// held, and a released one is never resurrected by the keeper.
    #[test]
    fn a_held_lease_is_renewed_and_a_released_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let lease = Lease::acquire(entry, "attempt-1", Duration::from_millis(50)).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        // Past its TTL: a sweep now would take it — unless renewed.
        assert!(!live(lease.path(), unix_ms()));
        assert!(renew_held() >= 1);
        lease.renew(DEFAULT_TTL).unwrap();
        assert_eq!(sweep(entry).unwrap().active, 1, "renewed, still pinning");
        let file = lease.path().to_path_buf();
        drop(lease);
        renew_held();
        assert!(
            !file.exists(),
            "the keeper never recreates a released lease"
        );
    }

    /// P07-14: a reaper that moves a marker which turned out to be live
    /// puts it back and answers busy — it never deletes a fresh claim.
    #[test]
    fn a_racing_reaper_never_deletes_a_fresh_marker() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let held = WriteLock::acquire(entry, "writer-b").unwrap().unwrap();
        // Writer C judged an older marker stale and now tries to take the
        // slot: the marker it finds is B's fresh one.
        assert!(WriteLock::acquire(entry, "writer-c").unwrap().is_none());
        assert!(held.path().is_file(), "B's claim survives");
        let leftovers: Vec<_> = fs::read_dir(entry.join(WRITING_NAME))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "no reaped copies linger: {leftovers:?}");
    }

    #[test]
    fn owner_names_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["", "has space", "has/slash", &"a".repeat(65)] {
            assert!(matches!(
                Lease::acquire(dir.path(), bad, DEFAULT_TTL),
                Err(LeaseError::BadOwner)
            ));
        }
    }
}
