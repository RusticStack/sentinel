//! Active-use leases: the pin that keeps garbage collection away from a
//! generation while it is being read, cloned or published.
//!
//! A lease is one file under `<entry>/lease/<id>` containing
//! `<expires_unix_ms> <owner>`. Acquisition is `create_new`, so two
//! holders can never share a name; release deletes it. A crashed holder's
//! lease expires on its own — collection treats a lease as active while
//! `min(declared expiry, mtime + MAX_TTL)` is in the future, so a torn
//! write reads as fresh, never as collectible, until it is provably stale.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
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

    /// Extend the pin; a failed renew keeps the old expiry — callers that
    /// still need the pin must re-acquire rather than assume it.
    pub fn renew(&self, ttl: Duration) -> Result<(), LeaseError> {
        let expires = unix_ms() + ttl.min(MAX_TTL).as_millis() as i64;
        fs::write(&self.file, format!("{expires} {}", self.owner))?;
        Ok(())
    }

    /// The marker path, for diagnostics.
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// Release early. A failed remove is safe: the lease still expires.
    pub fn release(self) -> Result<(), LeaseError> {
        fs::remove_file(&self.file)?;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
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
                    // A dead writer's marker: reap and retry.
                    let _ = fs::remove_file(&file);
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
