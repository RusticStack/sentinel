//! The controller sizes its session cap from the process's open-files limit and neither raises that limit nor starts
//! when it cannot hold a usable number of sessions. One test: `RLIMIT_NOFILE` belongs to the whole process.
#![cfg(target_os = "linux")]

use std::sync::Arc;

use sentinel_link::{
    Error,
    controller::{Controller, MAX_SESSIONS, descriptors_needed},
    identity::Identity,
};
use sentinel_store::{Durability, Store, logs::LogStore, objects::Objects};

fn soft_limit() -> libc::rlimit {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` for the whole call.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit
}

fn set_soft(soft: libc::rlim_t, hard: libc::rlim_t) {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `limit` is a valid `rlimit`; the soft value never exceeds the hard one the caller read.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

#[test]
fn a_low_descriptor_limit_lowers_the_cap_or_refuses_to_start_and_is_never_raised() {
    let original = soft_limit();
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
    let start = || {
        Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            Arc::clone(&objects),
            Identity::generate("controller").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
    };

    // A limit that holds 27 sessions: the cap follows it, and starting does not move the limit.
    let low = 300;
    set_soft(low.min(original.rlim_max), original.rlim_max);
    let controller = start().unwrap();
    // (300 - 192 base) / 4 descriptors per session.
    assert_eq!(controller.session_cap(), 27);
    assert!(controller.session_cap() < MAX_SESSIONS);
    assert_eq!(soft_limit().rlim_cur, low.min(original.rlim_max));
    drop(controller);

    // A limit below the minimum: a clear startup error naming the limit and what is needed, no listener left behind.
    set_soft(100.min(original.rlim_max), original.rlim_max);
    let error = match start() {
        Ok(_) => panic!("a 100-descriptor limit must not start a controller"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Descriptors(_)), "{error}");
    let text = error.to_string();
    assert!(text.contains("100"), "{text}");
    assert!(
        text.contains(&descriptors_needed(MAX_SESSIONS).to_string()),
        "{text}"
    );
    assert_eq!(soft_limit().rlim_cur, 100.min(original.rlim_max));

    // A generous limit admits every session.
    set_soft(original.rlim_cur, original.rlim_max);
    if original.rlim_cur as usize >= descriptors_needed(MAX_SESSIONS) {
        let controller = start().unwrap();
        assert_eq!(controller.session_cap(), MAX_SESSIONS);
    }
}
