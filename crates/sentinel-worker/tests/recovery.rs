//! W07 worker-side reconciliation without a container runtime: markers
//! record attempts in flight with their fence, leftover workspaces are
//! destroyed, a spool without a marker is discarded, a spool with one is
//! kept for delivery, and the result names what was found.

#![cfg(target_os = "linux")]

use std::fs;

use sentinel_core::{AttemptId, Fence, WorkerId};
use sentinel_protocol::logs::Stream;
use sentinel_worker::{recovery, spool::Spool, workspace::Workspace};

#[test]
fn leftovers_are_settled_on_disk_and_kept_for_the_controller() {
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
        vec![(running, Fence(3))]
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
        (pending[0].attempt, pending[0].fence, pending[0].spooled),
        (running, Fence(3), true)
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
