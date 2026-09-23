//! The owner-only file store, `credentials/<profile>.json`, and the private
//! file helpers the profile module shares: on Unix, directories are created
//! `0700` and files `0600`, and a directory or file another user can reach
//! (`mode & 0o077 != 0`) or that another user owns is refused with the
//! command that fixes it. Files are replaced atomically (write a sibling,
//! `fsync`, rename), so a reader never sees half a credential and a crash
//! never loses a rotated refresh token that was reported written. On
//! Windows the configuration directory inherits the per-user ACL of
//! `%APPDATA%`.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::client::Error;

/// The largest credential or profiles file read back (a credential blob is
/// about 250 bytes; `profiles.json` a few hundred per profile).
const MAX_FILE: u64 = 1 << 20;

pub fn credentials_dir(dir: &Path) -> PathBuf {
    dir.join("credentials")
}

/// `credentials/<profile>.json` (profile names are validated by the caller
/// to a safe file-name alphabet).
pub fn path(dir: &Path, profile: &str) -> PathBuf {
    let mut path = credentials_dir(dir);
    path.push(format!("{profile}.json"));
    path
}

pub fn read(dir: &Path, profile: &str) -> Result<Option<Vec<u8>>, Error> {
    let creds = credentials_dir(dir);
    match fs::metadata(&creds) {
        Ok(meta) => check_meta(&creds, &meta, true)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read", &creds, &e)),
    }
    read_private(&path(dir, profile))
}

pub fn write(dir: &Path, profile: &str, blob: &[u8]) -> Result<(), Error> {
    ensure_private_dir(dir)?;
    ensure_private_dir(&credentials_dir(dir))?;
    write_private(&path(dir, profile), blob)
}

pub fn delete(dir: &Path, profile: &str) -> Result<(), Error> {
    let path = path(dir, profile);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error("delete", &path, &e)),
    }
}

/// Read a private file, checking the opened file itself (no race between
/// the check and the read). `Ok(None)` when it does not exist.
pub fn read_private(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read", path, &e)),
    };
    let meta = file.metadata().map_err(|e| io_error("read", path, &e))?;
    check_meta(path, &meta, false)?;
    if meta.len() > MAX_FILE {
        return Err(Error::usage(format!(
            "{} is larger than a Sentinel file can be",
            path.display()
        )));
    }
    // The length check above is a fast refusal; the read is what is bounded,
    // since the file can grow after `metadata`.
    match crate::bounded::read(file, MAX_FILE) {
        Ok(data) => Ok(Some(data)),
        Err(crate::bounded::ReadError::Io(e)) => Err(io_error("read", path, &e)),
        Err(_) => Err(Error::usage(format!(
            "{} is larger than a Sentinel file can be",
            path.display()
        ))),
    }
}

/// Create `path` (and missing parents) owner-only, or check an existing one.
pub fn ensure_private_dir(path: &Path) -> Result<(), Error> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => check_meta(path, &meta, true),
        Ok(_) => Err(Error::usage(format!(
            "{} is not a directory",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(path)
                .map_err(|e| io_error("create", path, &e))
        }
        Err(e) => Err(io_error("read", path, &e)),
    }
}

/// Check that `path` is owner-only and owned by this user (Unix; always
/// accepted elsewhere).
pub fn check_private(path: &Path) -> Result<(), Error> {
    let meta = fs::metadata(path).map_err(|e| io_error("read", path, &e))?;
    check_meta(path, &meta, meta.is_dir())
}

/// [`check_private`] as if the effective user were `euid`: lets tests
/// exercise the foreign-owner refusal without a second account.
#[cfg(unix)]
#[doc(hidden)]
pub fn check_private_as(path: &Path, euid: u32) -> Result<(), Error> {
    let meta = fs::metadata(path).map_err(|e| io_error("read", path, &e))?;
    check_unix(path, &meta, meta.is_dir(), euid)
}

#[cfg(unix)]
fn check_meta(path: &Path, meta: &fs::Metadata, dir: bool) -> Result<(), Error> {
    check_unix(path, meta, dir, rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
fn check_meta(_path: &Path, _meta: &fs::Metadata, _dir: bool) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn check_unix(path: &Path, meta: &fs::Metadata, dir: bool, euid: u32) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    if meta.uid() != euid {
        return Err(Error::usage(format!(
            "{} is owned by uid {}, not by you (uid {euid}); fix: sudo chown \"$(id -u)\" '{}' (or remove it)",
            path.display(),
            meta.uid(),
            path.display()
        )));
    }
    if mode & 0o077 != 0 {
        return Err(Error::usage(format!(
            "{} is accessible to other users (mode {mode:03o}); fix: chmod {} '{}'",
            path.display(),
            if dir { "700" } else { "600" },
            path.display()
        )));
    }
    Ok(())
}

/// Open (creating owner-only) a file for locking.
pub fn open_lock(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map_err(|e| io_error("open", path, &e))
}

/// Replace `path` atomically with `data`, owner-only and durable before the
/// rename.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok::<(), io::Error>(())
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error("write", path, &e)
    })
}

fn io_error(what: &str, path: &Path, error: &io::Error) -> Error {
    Error::usage(format!("cannot {what} {}: {error}", path.display()))
}
