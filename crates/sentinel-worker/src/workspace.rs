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
    pub fn create(root: &Path, attempt: AttemptId) -> Result<Workspace> {
        // Only the parent is owner-only: a container user must enter the attempt's bind-mounted /workspace.
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

    pub fn destroy(self) -> Result<()> {
        remove_tree(&self.path)
    }

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

/// Held descriptors cost one per level, so the walk stops here and deeper read-only directories are left to fail removal.
const MAX_WALK_DEPTH: usize = 128;

/// The job controls the tree, so nothing may follow a link it plants: each step is relative to a held descriptor.
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

fn make_walkable(dir: &OwnedFd, depth: usize) {
    let fd = dir.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is open and `stat` is a writable `stat`.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: `fstat` returned 0, so it filled the structure.
    let mode = unsafe { stat.assume_init() }.st_mode;
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

    #[test]
    fn removing_nothing_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        remove_tree(&dir.path().join("absent")).unwrap();
    }
}
