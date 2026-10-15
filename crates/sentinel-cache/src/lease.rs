use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};

use crate::scope::{LEASE_NAME, WRITING_NAME};

pub const MAX_TTL: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_BODY: usize = 256;
const MAX_OWNER: usize = 64;

#[derive(Debug)]
pub enum LeaseError {
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

pub const RENEW_EVERY: Duration = Duration::from_secs(DEFAULT_TTL.as_secs() / 4);

fn held() -> &'static Mutex<HashMap<PathBuf, (String, Duration)>> {
    static HELD: OnceLock<Mutex<HashMap<PathBuf, (String, Duration)>>> = OnceLock::new();
    HELD.get_or_init(|| {
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

#[doc(hidden)]
pub fn renew_held() -> usize {
    let held = held().lock().unwrap_or_else(|p| p.into_inner());
    held.iter()
        .filter(|(file, (owner, ttl))| rewrite(file, owner, *ttl).is_ok())
        .count()
}

/// Renewal never resurrects a removed lease: the marker is opened without create.
fn rewrite(file: &Path, owner: &str, ttl: Duration) -> std::io::Result<()> {
    use std::io::Write;
    let expires = unix_ms() + ttl.min(MAX_TTL).as_millis() as i64;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file)?;
    f.write_all(format!("{expires} {owner}").as_bytes())
}

const DIR_RACE_TURNS: u32 = 4;

fn make_dir(dir: &Path) -> std::io::Result<()> {
    let mut turns = DIR_RACE_TURNS;
    loop {
        match fs::create_dir_all(dir) {
            Err(e)
                if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::AlreadyExists)
                    && turns > 1 =>
            {
                turns -= 1
            }
            done => return done,
        }
    }
}

pub struct Lease {
    file: PathBuf,
    owner: String,
}

impl Lease {
    pub fn acquire(entry: &Path, owner: &str, ttl: Duration) -> Result<Lease, LeaseError> {
        if !valid_owner(owner) {
            return Err(LeaseError::BadOwner);
        }
        let dir = entry.join(LEASE_NAME);
        make_dir(&dir)?;
        let expires = unix_ms() + ttl.min(MAX_TTL).as_millis() as i64;
        for attempt in 0..DIR_RACE_TURNS {
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
                Err(e) if e.kind() == ErrorKind::NotFound => make_dir(&dir)?,
                Err(e) => return Err(e.into()),
            }
        }
        Err(LeaseError::Io(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "lease did not settle",
        )))
    }

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

    pub fn path(&self) -> &Path {
        &self.file
    }

    pub fn release(self) -> Result<(), LeaseError> {
        forget(&self.file);
        fs::remove_file(&self.file)?;
        Ok(())
    }
}

/// Deregistered before the file is removed, so the keeper never rewrites a released lease.
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

pub const WRITE_LOCK_NAME: &str = ".lock";

pub struct WriteLock {
    file: PathBuf,
}

impl WriteLock {
    pub fn acquire(entry: &Path, owner: &str) -> Result<Option<WriteLock>, LeaseError> {
        if !valid_owner(owner) {
            return Err(LeaseError::BadOwner);
        }
        let dir = entry.join(WRITING_NAME);
        let file = dir.join(WRITE_LOCK_NAME);
        for _ in 0..DIR_RACE_TURNS {
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
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    make_dir(&dir)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(LeaseError::Io(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "write lock did not settle",
        )))
    }

    pub fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        if let Some(dir) = self.file.parent() {
            let _ = fs::remove_dir(dir);
        }
    }
}

pub fn writing_lock_live(entry: &Path, now_ms: i64) -> bool {
    live(&entry.join(WRITING_NAME).join(WRITE_LOCK_NAME), now_ms)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Leases {
    pub active: usize,
    pub expired: usize,
}

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

/// Liveness is min(declared expiry, mtime + MAX_TTL): a torn or corrupt marker pins until provably stale.
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
        fs::write(lease_dir.join("torn"), b"\xff\xfe").unwrap();
        assert_eq!(sweep(entry).unwrap().active, 1);
    }

    #[test]
    fn a_held_lease_is_renewed_and_a_released_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let lease = Lease::acquire(entry, "attempt-1", Duration::from_millis(50)).unwrap();
        std::thread::sleep(Duration::from_millis(80));
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

    #[test]
    fn a_racing_reaper_never_deletes_a_fresh_marker() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path();
        let held = WriteLock::acquire(entry, "writer-b").unwrap().unwrap();
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
