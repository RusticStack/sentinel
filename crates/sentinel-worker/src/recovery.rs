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
    fs,
    path::{Path, PathBuf},
};

use sentinel_core::{AttemptId, Fence, WorkerId};

use crate::{Result, podman, spool::Spool, workspace};

pub const ATTEMPTS_DIR: &str = "attempts";

/// One attempt the previous process did not finish.
#[derive(Debug)]
pub struct Leftover {
    pub attempt: AttemptId,
    pub fence: Fence,
    /// Whether a spool with unsent frames exists for it.
    pub spooled: bool,
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

/// Record that this process holds `attempt` under `fence`.
pub fn mark(root: &Path, attempt: AttemptId, fence: Fence) -> Result<()> {
    fs::create_dir_all(root.join(ATTEMPTS_DIR))?;
    fs::write(marker_path(root, attempt), format!("{}\n", fence.0))?;
    Ok(())
}

/// The attempt's end has been reported: nothing to reconcile for it.
pub fn unmark(root: &Path, attempt: AttemptId) {
    let _ = fs::remove_file(marker_path(root, attempt));
}

/// Markers left by an earlier process, with their fences.
pub fn leftovers(root: &Path) -> Result<Vec<(AttemptId, Fence)>> {
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
        let fence = fs::read_to_string(entry.path())
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map(Fence)
            .unwrap_or(Fence::NONE);
        found.push((attempt, fence));
    }
    found.sort_by_key(|(a, _)| *a.as_bytes());
    Ok(found)
}

/// Settle the disk and the runtime: remove every container this worker
/// owns, destroy every workspace, and return the attempts that still have
/// to be abandoned to the controller (their spools are kept for delivery).
pub fn recover(root: &Path, worker: WorkerId) -> Result<(Recovered, Vec<Leftover>)> {
    let mut done = Recovered::default();
    if let Ok(owned) = podman::owned(worker) {
        for (_, name) in owned {
            if podman::remove_named(&name).is_ok() {
                done.containers_removed += 1;
            }
        }
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
    let spooled: Vec<AttemptId> = Spool::leftovers(root)?;
    let markers = leftovers(root)?;
    let mut pending = Vec::with_capacity(markers.len());
    for (attempt, fence) in &markers {
        pending.push(Leftover {
            attempt: *attempt,
            fence: *fence,
            spooled: spooled.contains(attempt),
        });
    }
    // A spool without a marker belongs to an attempt whose end was reported
    // (the marker went first) but whose spool removal did not complete: the
    // controller has its end record or never will; nothing to send.
    for attempt in spooled {
        if !markers.iter().any(|(a, _)| *a == attempt)
            && let Ok(spool) = Spool::open(root, attempt)
        {
            let _ = spool.remove();
        }
    }
    done.leftovers = markers;
    Ok((done, pending))
}
