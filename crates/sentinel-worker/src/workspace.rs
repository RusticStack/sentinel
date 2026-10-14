//! Fresh per-attempt workspaces under `<data_dir>/workspaces/<attempt>`.
//!
//! A workspace is created empty exactly once and destroyed after the attempt
//! finalizes. It is never reused: a second attempt of the same job is a new
//! attempt with a new directory, so nothing from a previous run — files,
//! Git state, a half-written cache — can leak into the next.

use std::{
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

use sentinel_core::AttemptId;

use crate::{Error, Result};

pub const WORKSPACES_DIR: &str = "workspaces";

pub struct Workspace {
    path: PathBuf,
    attempt: AttemptId,
}

impl Workspace {
    /// Create `<root>/workspaces/<attempt>`, refusing if anything is already
    /// there: a leftover is a reconciliation matter (W07), not a workspace.
    pub fn create(root: &Path, attempt: AttemptId) -> Result<Workspace> {
        // The directory that holds every workspace is owner-only. The
        // attempt's own directory keeps the umask's mode: a container user
        // other than the worker's mapped root must be able to enter its
        // bind-mounted `/workspace`, and only the path to it is guarded.
        let parent = root.join(WORKSPACES_DIR);
        crate::private_dir_all(&parent)?;
        let path = parent.join(attempt.to_string());
        match fs::create_dir(&path) {
            Ok(()) => Ok(Workspace { path, attempt }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::Workspace(
                format!("{} already exists", path.display()),
            )),
            Err(e) => Err(e.into()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Remove everything. Files a container created are owned by this user
    /// (rootless mapping), so no privilege is needed. Read-only bits set by
    /// a build are cleared first so the removal cannot stall on them.
    pub fn destroy(self) -> Result<()> {
        remove_tree(&self.path)
    }

    /// Attempt directories left behind by an earlier process, for W07.
    pub fn leftovers(root: &Path) -> Result<Vec<AttemptId>> {
        let parent = root.join(WORKSPACES_DIR);
        let mut found = Vec::new();
        let entries = match fs::read_dir(&parent) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<AttemptId>().ok())
            {
                found.push(id);
            }
        }
        Ok(found)
    }
}

/// Deepest directory level the permission pass descends; one descriptor is
/// held per level. A tree nested deeper keeps its deeper read-only
/// directories, and the removal then reports the failure.
const MAX_WALK_DEPTH: usize = 128;

/// Remove a tree we own, restoring write permission on directories so
/// read-only checkouts do not leave orphans.
///
/// The job controls what is in its workspace, so nothing here may follow a
/// link it plants: each directory is opened `O_NOFOLLOW` relative to its
/// parent's descriptor, and its mode is changed through that descriptor, not
/// through a path the job could re-point between the check and the change.
pub fn remove_tree(path: &Path) -> Result<()> {
    if let Ok(root) = std::ffi::CString::new(path.as_os_str().as_bytes())
        && let Some(root) = open_dir_nofollow(libc::AT_FDCWD, &root)
    {
        make_walkable(&root, 0);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A path-only descriptor for the directory `name` under `parent`: a
/// symlink in the last component is not followed, and a non-directory is
/// refused. `O_PATH` needs no read permission, so a directory whose mode
/// was cleared can still be named.
fn open_dir_nofollow(parent: libc::c_int, name: &std::ffi::CStr) -> Option<OwnedFd> {
    // SAFETY: `name` is NUL-terminated and `parent` is a live descriptor or
    // `AT_FDCWD`; the flags only open, never create.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    // SAFETY: a non-negative `openat` result is a descriptor this call owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Give `dir` and every directory below it owner read/write/search, so the
/// removal that follows can list and unlink them. Errors are not fatal
/// here: a directory the pass could not open or change is left for the
/// removal to report.
fn make_walkable(dir: &OwnedFd, depth: usize) {
    let fd = dir.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is open and `stat` is a writable `stat`.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: `fstat` returned 0, so it filled the structure.
    let mode = unsafe { stat.assume_init() }.st_mode;
    // The magic link names the very inode `fd` holds, so the change cannot
    // land elsewhere, whatever happens to the path meanwhile.
    let through = format!("/proc/self/fd/{fd}");
    if mode & 0o700 != 0o700 {
        let _ = fs::set_permissions(&through, fs::Permissions::from_mode(0o700));
    }
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(&through) else {
        return;
    };
    let children: Vec<std::ffi::CString> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| std::ffi::CString::new(entry.file_name().as_bytes()).ok())
        .collect();
    for name in &children {
        if let Some(child) = open_dir_nofollow(fd, name) {
            make_walkable(&child, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read-only, nested checkout (a build's `chmod -R a-w`) is removed
    /// whole.
    #[test]
    fn a_read_only_tree_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let deep = root.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("file"), b"x").unwrap();
        for sub in [&deep, &root.join("a/b"), &root.join("a"), &root] {
            fs::set_permissions(sub, fs::Permissions::from_mode(0o500)).unwrap();
        }
        remove_tree(&root).unwrap();
        assert!(!root.exists());
    }

    /// A link a job planted to a directory outside its workspace is removed
    /// as a link: the directory it names keeps its mode and its contents.
    #[test]
    fn a_planted_link_never_changes_what_it_points_at() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o500)).unwrap();
        let root = dir.path().join("ws");
        fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub/link")).unwrap();
        remove_tree(&root).unwrap();
        assert!(!root.exists());
        let mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o500, "the link's target was chmodded");
        assert!(outside.join("keep").exists());
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// A tree that is already gone is already removed.
    #[test]
    fn removing_nothing_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        remove_tree(&dir.path().join("absent")).unwrap();
    }
}
