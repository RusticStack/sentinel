//! Runs in its own process: git children forked by other tests can hold an inherited lock descriptor
//! until they exec, which would make which mirror a sweep removes depend on timing.
#![cfg(unix)]

use std::{fs, time::Duration};

use sentinel_core::RepoId;
use sentinel_git::mirror::Mirrors;

mod support;
use support::{repository, source, work};

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
    let swept = mirrors.sweep(one + one / 2);
    assert_eq!(swept.removed, 1, "{swept:?}");
    assert!(!mirrors.path(&old).exists(), "least recently written goes");
    assert!(mirrors.path(&new).exists());
    assert!(lock.exists(), "the lock file itself stays");
}
