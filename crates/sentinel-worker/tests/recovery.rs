//! W07 worker-side reconciliation against an empty container runtime (a
//! shim that owns nothing): markers
//! record attempts in flight with their fence, leftover workspaces are
//! destroyed, a spool without a marker is discarded, a spool with one is
//! kept for delivery, and the result names what was found.

#![cfg(target_os = "linux")]

use std::fs;

use sentinel_core::{AttemptId, Fence, WorkerId};
use sentinel_protocol::logs::Stream;
use sentinel_worker::{
    recovery::{self, Marker},
    spool::Spool,
    workspace::Workspace,
};

/// A `podman` on `PATH` that owns nothing: recovery now requires a runtime
/// that answers (it refuses to guess), and these cases are about the disk.
fn empty_runtime() {
    use std::os::unix::fs::PermissionsExt;
    static SHIM: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SHIM.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("podman");
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let joined = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // SAFETY: set once, before either test of this binary runs a
        // helper; `OnceLock` serializes the first call.
        unsafe {
            std::env::set_var("PATH", joined);
        }
    });
}

#[test]
fn leftovers_are_settled_on_disk_and_kept_for_the_controller() {
    empty_runtime();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (running, finished, unmarked) = (AttemptId::new(), AttemptId::new(), AttemptId::new());
    // `running`: marker, workspace with a checkout in progress, spool with frames.
    recovery::mark(root, running, Fence(3)).unwrap();
    let ws = Workspace::create(root, running).unwrap();
    fs::write(ws.path().join("partial.txt"), "half").unwrap();
    fs::create_dir(ws.path().with_extension("askpass")).unwrap();
    let mut spool = Spool::open(root, running).unwrap();
    spool
        .append(0, Stream::Stdout, b"before the crash\n")
        .unwrap();
    spool.sync().unwrap();
    drop(spool);
    // `finished`: its report went out (marker removed) but the spool removal
    // did not complete.
    recovery::mark(root, finished, Fence(1)).unwrap();
    recovery::unmark(root, finished);
    Spool::open(root, finished).unwrap();
    // `unmarked`: only a workspace, from before the marker was written.
    Workspace::create(root, unmarked).unwrap();

    assert_eq!(
        recovery::leftovers(root).unwrap(),
        vec![Marker {
            attempt: running,
            fence: Fence(3),
            ended: false,
        }]
    );
    let (recovered, pending) = recovery::recover(root, WorkerId::new()).unwrap();
    assert_eq!(recovered.leftovers, vec![(running, Fence(3))]);
    assert_eq!(recovered.workspaces_removed, 2);
    assert!(Workspace::leftovers(root).unwrap().is_empty());
    assert!(
        !root
            .join("workspaces")
            .join(running.to_string())
            .with_extension("askpass")
            .exists()
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (
            pending[0].attempt,
            pending[0].fence,
            pending[0].spooled,
            pending[0].ended,
        ),
        (running, Fence(3), true, false)
    );
    // The running attempt's spool survives with its frames; the finished
    // attempt's spool is gone.
    assert_eq!(Spool::leftovers(root).unwrap(), vec![running]);
    let mut spool = Spool::open(root, running).unwrap();
    let frames = spool.unacked(0, 10).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].bytes, b"before the crash\n");
    // Nothing left to reconcile once the marker is gone.
    recovery::unmark(root, running);
    assert!(recovery::leftovers(root).unwrap().is_empty());
}

#[test]
fn a_marker_without_a_spool_reports_whether_the_end_was_delivered() {
    empty_runtime();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (lost, done, gone) = (AttemptId::new(), AttemptId::new(), AttemptId::new());
    // `lost`: marker, frames spooled, then the spool itself is lost —
    // recovery must not call that delivered.
    recovery::mark(root, lost, Fence(7)).unwrap();
    let mut spool = Spool::open(root, lost).unwrap();
    spool.append(0, Stream::Stdout, b"work\n").unwrap();
    spool.sync().unwrap();
    drop(spool);
    fs::remove_dir_all(root.join("spool").join(lost.to_string())).unwrap();
    // `done`: the end went out and the spool was removed, then the crash
    // took the marker removal — a completed delivery, not a loss.
    recovery::mark(root, done, Fence(8)).unwrap();
    recovery::mark_ended(root, done);
    // `gone`: marker only, mid-run — nothing was ever spooled.
    recovery::mark(root, gone, Fence(9)).unwrap();

    let markers = recovery::leftovers(root).unwrap();
    assert_eq!(markers.len(), 3);
    assert!(!markers.iter().find(|m| m.attempt == lost).unwrap().ended);
    assert!(markers.iter().find(|m| m.attempt == done).unwrap().ended);

    let (_, pending) = recovery::recover(root, WorkerId::new()).unwrap();
    let flag = |a: AttemptId| {
        let l = pending.iter().find(|l| l.attempt == a).unwrap();
        (l.spooled, l.ended)
    };
    assert_eq!(flag(lost), (false, false));
    assert_eq!(flag(done), (false, true));
    assert_eq!(flag(gone), (false, false));
}
