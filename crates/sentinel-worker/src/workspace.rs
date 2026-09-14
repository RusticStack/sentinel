//! Fresh per-attempt workspaces under `<data_dir>/workspaces/<attempt>`.
//!
//! A workspace is created empty exactly once and destroyed after the attempt
//! finalizes. It is never reused: a second attempt of the same job is a new
//! attempt with a new directory, so nothing from a previous run — files,
//! Git state, a half-written cache — can leak into the next.

use std::{
    fs,
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
        let parent = root.join(WORKSPACES_DIR);
        fs::create_dir_all(&parent)?;
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

/// Remove a tree we own, restoring write permission on directories so
/// read-only checkouts do not leave orphans.
pub fn remove_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.is_dir() && meta.permissions().mode() & 0o700 != 0o700 {
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        if meta.is_dir() {
            for entry in fs::read_dir(&dir)?.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
