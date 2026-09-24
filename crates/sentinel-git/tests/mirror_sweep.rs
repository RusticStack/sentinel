//! P07-22's mirror disk bound, in a process of its own: a sweep skips a
//! mirror whose lock is momentarily held, and git children that other tests
//! fork in the same process can hold an inherited copy of a lock descriptor
//! until they exec — which would make which mirror goes depend on timing.
#![cfg(unix)]

use std::{fs, time::Duration};

use sentinel_core::RepoId;
use sentinel_git::mirror::Mirrors;

mod support;
use support::{repository, source, work};

/// P07-22: the sweep bounds mirror disk — a killed fetch's stale `tmp_*`
/// goes, and over the budget the least recently written mirror goes; a
/// mirror whose writer lock is held is never touched.
#[test]
fn the_sweep_bounds_mirror_disk() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let (old, new) = (RepoId::new(), RepoId::new());
    for (id, name) in [(old, "old"), (new, "new")] {
        mirrors
            .checkout(
                &work(temp.path(), name),
                &id,
                &source(&repo, &repo.first, None),
                None,
                &format!("att_{name}"),
                Duration::from_secs(60),
            )
            .unwrap();
    }
    // `old` was written an hour earlier; a dead fetch left a temp pack.
    let lock = temp.path().join(format!("mirrors/{old}.lock"));
    fs::OpenOptions::new()
        .write(true)
        .open(&lock)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
    let tmp = mirrors.path(&new).join("objects/pack/tmp_pack_dead");
    fs::write(&tmp, b"partial").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&tmp)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200))
        .unwrap();
    let one = {
        let s = mirrors.sweep(u64::MAX);
        assert_eq!(s.removed, 0);
        assert_eq!(s.tmp_removed, 1);
        s.bytes / 2
    };
    assert!(!tmp.exists());
    // Alone in this process, nothing holds a lock here: the sweep sees both
    // mirrors and removes the least recently written.
    let swept = mirrors.sweep(one + one / 2);
    assert_eq!(swept.removed, 1, "{swept:?}");
    assert!(!mirrors.path(&old).exists(), "least recently written goes");
    assert!(mirrors.path(&new).exists());
    assert!(lock.exists(), "the lock file itself stays");
}
