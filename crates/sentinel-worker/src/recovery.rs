use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use sentinel_core::{AttemptId, Fence, WorkerId};

use crate::{Result, podman, spool::Spool, workspace};

pub const ATTEMPTS_DIR: &str = "attempts";
const SECRET_DELIVERY_DIR: &str = "secret-delivery";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub attempt: AttemptId,
    pub fence: Fence,
    pub ended: bool,
}

#[derive(Debug)]
pub struct Leftover {
    pub attempt: AttemptId,
    pub fence: Fence,
    pub spooled: bool,
    pub ended: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    pub leftovers: Vec<(AttemptId, Fence)>,
    pub containers_removed: usize,
    pub workspaces_removed: usize,
}

fn marker_path(root: &Path, attempt: AttemptId) -> PathBuf {
    root.join(ATTEMPTS_DIR).join(attempt.to_string())
}

// Synced to disk: a marker lost to a power cut would make recovery discard a spool that was never reported.
pub fn mark(root: &Path, attempt: AttemptId, fence: Fence) -> Result<()> {
    let dir = root.join(ATTEMPTS_DIR);
    crate::private_dir_all(&dir)?;
    let mut marker = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(marker_path(root, attempt))?;
    marker.write_all(format!("{}\n", fence.0).as_bytes())?;
    marker.sync_data()?;
    crate::sync_dir(&dir)?;
    crate::sync_dir(root)?;
    Ok(())
}

pub fn mark_ended(root: &Path, attempt: AttemptId) {
    if let Ok(mut marker) = OpenOptions::new()
        .append(true)
        .open(marker_path(root, attempt))
        && marker.write_all(b"ended\n").is_ok()
    {
        let _ = marker.sync_data();
    }
}

pub fn unmark(root: &Path, attempt: AttemptId) {
    let _ = fs::remove_file(marker_path(root, attempt));
}

pub fn leftovers(root: &Path) -> Result<Vec<Marker>> {
    let dir = root.join(ATTEMPTS_DIR);
    let mut found = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e.into()),
    };
    for entry in entries.flatten() {
        let Some(attempt) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<AttemptId>().ok())
        else {
            continue;
        };
        let text = fs::read_to_string(entry.path()).unwrap_or_default();
        let mut lines = text.lines();
        let fence = lines
            .next()
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map(Fence)
            .unwrap_or(Fence::NONE);
        let ended = lines.any(|l| l.trim() == "ended");
        found.push(Marker {
            attempt,
            fence,
            ended,
        });
    }
    found.sort_by_key(|m| *m.attempt.as_bytes());
    Ok(found)
}

// Reaping must not be best-effort: abandoning an attempt whose container still runs would let unobserved steps continue.
pub fn recover(root: &Path, worker: WorkerId) -> Result<(Recovered, Vec<Leftover>)> {
    let mut done = Recovered::default();
    for store in podman::Store::all(root) {
        for (_, name) in podman::owned_in(worker, &store)? {
            podman::remove_named(&name, &store)?;
            done.containers_removed += 1;
        }
    }
    for attempt in workspace::Workspace::leftovers(root)? {
        let path = root
            .join(workspace::WORKSPACES_DIR)
            .join(attempt.to_string());
        if workspace::remove_tree(&path).is_ok() {
            done.workspaces_removed += 1;
        }
        let _ = fs::remove_dir_all(path.with_extension("askpass"));
    }
    reap_secret_directories(root)?;
    if let Ok(entries) = fs::read_dir(root.join(sentinel_git::mirror::MIRRORS_DIR)) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".askpass"))
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
    let spooled: Vec<AttemptId> = Spool::leftovers(root)?;
    let markers = leftovers(root)?;
    let mut pending = Vec::with_capacity(markers.len());
    for marker in &markers {
        pending.push(Leftover {
            attempt: marker.attempt,
            fence: marker.fence,
            spooled: spooled.contains(&marker.attempt),
            ended: marker.ended,
        });
    }
    for attempt in spooled {
        if !markers.iter().any(|m| m.attempt == attempt)
            && let Ok(spool) = Spool::open(root, attempt)
        {
            let _ = spool.remove();
        }
    }
    done.leftovers = markers.into_iter().map(|m| (m.attempt, m.fence)).collect();
    Ok((done, pending))
}

// A crash skips RAII cleanup, so secret scratch is removed before any work is accepted.
fn reap_secret_directories(root: &Path) -> Result<()> {
    reap_secret_dir(&root.join(SECRET_DELIVERY_DIR))?;
    reap_secret_dir(&crate::attempt::secret_root(root))
}

fn reap_secret_dir(dir: &Path) -> Result<()> {
    let dir = dir.to_path_buf();
    let metadata = match fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(crate::Error::Preparation(
            "secret recovery directory".into(),
        ));
    }
    let mut count = 0usize;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        count += 1;
        if count > sentinel_protocol::limits::MAX_LIST_ITEMS {
            return Err(crate::Error::Preparation("secret recovery bound".into()));
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_reaps_secret_scratch_before_work_resumes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("worker");
        let attempt = root.join(SECRET_DELIVERY_DIR).join("abandoned-attempt");
        fs::create_dir_all(attempt.join("files")).unwrap();
        fs::write(attempt.join("files/token"), b"secret-value").unwrap();
        fs::write(root.join(SECRET_DELIVERY_DIR).join("orphan"), b"orphan").unwrap();

        let staged = crate::attempt::secret_root(&root).join("live-attempt");
        fs::create_dir_all(staged.join("env")).unwrap();
        fs::write(staged.join("env/step-0.sh"), b"export T='v'\n").unwrap();

        reap_secret_directories(&root).unwrap();
        assert!(!staged.exists());
        assert!(!attempt.exists());
        assert!(!root.join(SECRET_DELIVERY_DIR).join("orphan").exists());
        assert!(root.join(SECRET_DELIVERY_DIR).is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn restart_refuses_a_secret_root_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("worker");
        fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join(SECRET_DELIVERY_DIR)).unwrap();
        assert!(matches!(
            reap_secret_directories(&root),
            Err(crate::Error::Preparation(_))
        ));
        assert!(outside.is_dir());
    }
}
