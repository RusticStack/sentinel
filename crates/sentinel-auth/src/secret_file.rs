//! Opening an operator-controlled secret file safely: the one place that
//! decides what "owner-only" means, shared by the master key, the GitHub App
//! key, the webhook secret and the sign-in client secret.
//!
//! The file is opened once and the *handle* is judged, so the file checked is
//! the file read — a path swapped between a check and a read changes nothing.
//! On Unix the open refuses a symbolic link (`O_NOFOLLOW`), and the handle must
//! be a regular file owned by this user with no group or other access.
//! Windows is a development platform only: a link is refused by name and the
//! opened handle must be a regular file; its ACLs are the OS's business.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use zeroize::Zeroize;

/// Why a secret file was refused. Never carries the path or any content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A link, a directory, a device: anything but a regular file.
    NotRegular,
    /// Could not be opened or inspected.
    Unreadable,
    /// Readable or writable by group or others.
    GroupOrOtherAccess,
    /// Owned by another user.
    WrongOwner,
}

/// Open `path` for reading and verify the opened handle.
pub fn open(path: &Path) -> Result<File, Refusal> {
    let file = open_nofollow(path)?;
    let metadata = file.metadata().map_err(|_| Refusal::Unreadable)?;
    if !metadata.is_file() {
        return Err(Refusal::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(Refusal::GroupOrOtherAccess);
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(Refusal::WrongOwner);
        }
    }
    Ok(file)
}

/// Read at most `limit` bytes of a verified secret file into a buffer that is
/// sized up front, so no reallocation leaves an unwiped copy behind, and is
/// wiped by its owner's `zeroize`. `None` content means longer than `limit`.
pub fn read(file: &mut File, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::with_capacity(limit + 1);
    let read = file.take(limit as u64 + 1).read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > limit {
        bytes.zeroize();
        read?;
        return Ok(None);
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<File, Refusal> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                Refusal::NotRegular
            } else {
                Refusal::Unreadable
            }
        })
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> Result<File, Refusal> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unreadable)?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::NotRegular);
    }
    File::open(path).map_err(|_| Refusal::Unreadable)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    fn secret(dir: &Path, mode: u32) -> std::path::PathBuf {
        let path = dir.join("secret");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"s3cret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn an_owner_only_regular_file_opens_and_reads_within_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret(dir.path(), 0o600);
        let mut file = open(&path).unwrap();
        assert_eq!(
            read(&mut file, 64).unwrap().as_deref(),
            Some(&b"s3cret\n"[..])
        );
        let mut file = open(&path).unwrap();
        assert_eq!(read(&mut file, 3).unwrap(), None);
    }

    #[test]
    fn group_or_other_access_a_link_and_a_directory_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o660] {
            let path = secret(dir.path(), mode);
            assert_eq!(
                open(&path).unwrap_err(),
                Refusal::GroupOrOtherAccess,
                "{mode:o}"
            );
        }
        let real = secret(dir.path(), 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(open(&link).unwrap_err(), Refusal::NotRegular);
        assert_eq!(open(dir.path()).unwrap_err(), Refusal::NotRegular);
        assert_eq!(
            open(&dir.path().join("missing")).unwrap_err(),
            Refusal::Unreadable
        );
    }
}
