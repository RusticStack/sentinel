//! Worker restart reconciliation (W07): what the previous process left
//! behind, settled before a single new offer is taken.
//!
//! An attempt in progress is recorded on disk the moment it is spawned —
//! `<data_dir>/attempts/<attempt>` holding its fence — and removed when
//! its report has gone out. On start, every marker still there is an
//! attempt whose end this process never saw. Its container is removed
//! (it must not keep running unobserved), its workspace destroyed (a
//! fresh attempt gets a fresh one), and its spool is kept: whatever it
//! printed is still delivered and closed. Once the session is up the
//! attempt is **abandoned** to the controller, which reconciles it as an
//! infrastructure failure — the steps are never run again, because whether
//! they had side effects is unknown. Containers the runtime still holds
//! under this worker's label without a marker are stale and reaped too.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use sentinel_core::{AttemptId, Fence, WorkerId};

use crate::{Result, podman, spool::Spool, workspace};

pub const ATTEMPTS_DIR: &str = "attempts";
const SECRET_DELIVERY_DIR: &str = "secret-delivery";

/// A marker an earlier process left: the attempt and its fence, plus
/// whether its log end had already gone out before the end report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub attempt: AttemptId,
    pub fence: Fence,
    /// `complete` had the log's end out (acked under protocol 5, sent on
    /// earlier protocols) when the marker outlived the spool — a crash in
    /// that window is a completed delivery, not a loss.
    pub ended: bool,
}

/// One attempt the previous process did not finish.
#[derive(Debug)]
pub struct Leftover {
    pub attempt: AttemptId,
    pub fence: Fence,
    /// Whether a spool with unsent frames exists for it.
    pub spooled: bool,
    /// Whether its log end was already delivered when no spool remains.
    pub ended: bool,
}

/// What the reconciliation found and did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    pub leftovers: Vec<(AttemptId, Fence)>,
    pub containers_removed: usize,
    pub workspaces_removed: usize,
}

fn marker_path(root: &Path, attempt: AttemptId) -> PathBuf {
    root.join(ATTEMPTS_DIR).join(attempt.to_string())
}

/// Record that this process holds `attempt` under `fence`. Synced — the
/// file and the directory entries leading to it: a marker lost to a power
/// cut would leave a spool recovery discards as already reported.
pub fn mark(root: &Path, attempt: AttemptId, fence: Fence) -> Result<()> {
    let dir = root.join(ATTEMPTS_DIR);
    fs::create_dir_all(&dir)?;
    let mut marker = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(marker_path(root, attempt))?;
    marker.write_all(format!("{}\n", fence.0).as_bytes())?;
    marker.sync_data()?;
    // The marker's entry, then `attempts` in the data directory: the second
    // is a no-op commit once the directory exists durably.
    crate::sync_dir(&dir)?;
    crate::sync_dir(root)?;
    Ok(())
}

/// The log's end went out as far as this protocol can prove: `LogEndAck`
/// under protocol 5, handed to the session on earlier ones. If the marker
/// then outlives the spool — removal raced a crash — recovery reports a
/// completed delivery rather than a loss.
pub fn mark_ended(root: &Path, attempt: AttemptId) {
    if let Ok(mut marker) = OpenOptions::new()
        .append(true)
        .open(marker_path(root, attempt))
        && marker.write_all(b"ended\n").is_ok()
    {
        let _ = marker.sync_data();
    }
}

/// The attempt's end has been reported: nothing to reconcile for it.
pub fn unmark(root: &Path, attempt: AttemptId) {
    let _ = fs::remove_file(marker_path(root, attempt));
}

/// Markers left by an earlier process, with their fences.
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

/// Settle the disk and the runtime: remove every container this worker
/// owns, destroy every workspace, and return the attempts that still have
/// to be abandoned to the controller (their spools are kept for delivery).
///
/// Reaping is not best-effort: if the runtime cannot list what this worker
/// owns, or a container of it cannot be removed, recovery fails and the
/// executor does not start. Abandoning attempts whose containers may still
/// be running would let unobserved steps go on after the controller
/// recorded them reconciled.
pub fn recover(root: &Path, worker: WorkerId) -> Result<(Recovered, Vec<Leftover>)> {
    let mut done = Recovered::default();
    for (_, name) in podman::owned(worker)? {
        podman::remove_named(&name)?;
        done.containers_removed += 1;
    }
    for attempt in workspace::Workspace::leftovers(root)? {
        let path = root
            .join(workspace::WORKSPACES_DIR)
            .join(attempt.to_string());
        if workspace::remove_tree(&path).is_ok() {
            done.workspaces_removed += 1;
        }
        // The askpass helper of a checkout that was under way, if any.
        let _ = fs::remove_dir_all(path.with_extension("askpass"));
    }
    reap_secret_directories(root)?;
    // The same for a mirror fetch the previous process died inside: its
    // credential helper is a `<repo>.askpass` sibling of the mirror.
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
    // A spool without a marker belongs to an attempt whose end was reported
    // (the marker went first) but whose spool removal did not complete: the
    // controller has its end record or never will; nothing to send.
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

/// Secret scratch is outside workspace and artifact roots. A process crash
/// skips RAII cleanup, so remove its attempt trees before accepting work.
fn reap_secret_directories(root: &Path) -> Result<()> {
    let dir = root.join(SECRET_DELIVERY_DIR);
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

        reap_secret_directories(&root).unwrap();
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
