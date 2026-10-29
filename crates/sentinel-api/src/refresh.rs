//! Asks for a member's GitHub check off the request path: opening a tenant with a stale confirmation must
//! cost the request a reader at most, never the single writer. A request files the user here and moves on;
//! one background thread drains the filed users in a single transaction. A user filed once is not filed
//! again for the on-demand gap, and a full queue drops the request: the lane's own schedule
//! (`member_recheck_secs`) still reaches that member, only later.

use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

use sentinel_core::{UnixMillis, UserId};
use sentinel_store::{Store, github_members};

/// Users waiting for the thread; a flood of distinct stale members cannot grow the queue past this.
const MAX_QUEUED: usize = 64;
/// Users remembered as recently filed, so one member refreshing a page files one check per gap.
const MAX_RECENT: usize = 1024;
const GAP: Duration = Duration::from_millis(github_members::MIN_ON_DEMAND_GAP_MS as u64);
/// How often an idle thread looks for the end of its owner.
const IDLE: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Inner {
    queued: Vec<UserId>,
    recent: HashMap<UserId, Instant>,
}

#[derive(Default)]
struct Shared {
    inner: Mutex<Inner>,
    wake: Condvar,
}

pub(crate) struct Refresh {
    shared: Arc<Shared>,
}

impl Refresh {
    pub(crate) fn start(store: Weak<Store>) -> std::io::Result<Refresh> {
        let shared = Arc::new(Shared::default());
        let thread = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("sentinel-api-member-refresh".into())
            .spawn(move || run(&thread, &store))?;
        Ok(Refresh { shared })
    }

    /// Never touches the store: the answer is whether the request was filed.
    pub(crate) fn request(&self, user: UserId, now: Instant) -> bool {
        let mut inner = self.shared.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner
            .recent
            .get(&user)
            .is_some_and(|filed| now.saturating_duration_since(*filed) < GAP)
        {
            return false;
        }
        if inner.queued.len() >= MAX_QUEUED {
            return false;
        }
        if inner.recent.len() >= MAX_RECENT {
            inner
                .recent
                .retain(|_, filed| now.saturating_duration_since(*filed) < GAP);
            if inner.recent.len() >= MAX_RECENT {
                return false;
            }
        }
        inner.recent.insert(user, now);
        if !inner.queued.contains(&user) {
            inner.queued.push(user);
        }
        drop(inner);
        self.shared.wake.notify_one();
        true
    }
}

fn run(shared: &Arc<Shared>, store: &Weak<Store>) {
    loop {
        let batch = {
            let mut inner = shared.inner.lock().unwrap_or_else(|p| p.into_inner());
            while inner.queued.is_empty() {
                // The owner dropped its half: nothing can file a request any more.
                if Arc::strong_count(shared) == 1 {
                    return;
                }
                inner = shared
                    .wake
                    .wait_timeout(inner, IDLE)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
            std::mem::take(&mut inner.queued)
        };
        let Some(store) = store.upgrade() else {
            return;
        };
        let now = UnixMillis::now();
        // A failed write is not retried: the member's next request or the lane's schedule asks again.
        let _ = store.writer().write(move |tx| {
            for user in batch {
                github_members::enqueue_user(tx, user, now)?;
            }
            Ok(())
        });
    }
}
