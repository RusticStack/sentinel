//! Looks for a tenant that crossed its storage threshold and tells its administrators, off the request path.
//!
//! Nothing on a request path can notice a crossing without paying for every request: usage is written by triggers
//! from artifact commits, uploads, log stamps and their expiry. So one thread looks once an interval, and does no
//! database work at all when nothing has been committed since its last look. What it finds is written in the writer
//! transaction itself (`sentinel_store::notices::record`), so a restart re-reads the arm state instead of repeating
//! a notice, and a crossing that falls back under 75 % before the next pass is never told.

use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::UnixMillis;
use sentinel_store::{Store, notices, objects::Objects};

/// How often an idle controller looks. A crossing is told within this long, and the pass costs one read.
pub(crate) const EVERY: Duration = Duration::from_secs(60);
/// Crossings and re-arms one round handles; the round repeats while it finds a full batch, so a deployment that
/// crosses many tenants at once catches up within the same pass without holding the writer for all of them.
const BATCH: u32 = 64;
const ROUNDS: u32 = 4;

pub(crate) fn start(
    store: Weak<Store>,
    objects: Arc<Objects>,
    key: Option<Arc<Key>>,
    every: Duration,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("sentinel-api-storage-notices".into())
        .spawn(move || run(&store, &objects, key, every))?;
    Ok(())
}

fn run(store: &Weak<Store>, objects: &Objects, key: Option<Arc<Key>>, every: Duration) {
    // The generation of the last pass: while nothing is committed it cannot have crossed, so the pass is one load.
    let mut seen = u64::MAX;
    loop {
        std::thread::sleep(every);
        let Some(store) = store.upgrade() else {
            return;
        };
        let generation = store.changes().generation();
        if generation == seen {
            continue;
        }
        match pass(&store, objects, key.clone()) {
            Ok(()) => seen = generation,
            Err(error) => tracing::warn!(
                event = "storage_notices_failed",
                %error,
                "the storage-notice pass failed; the next one retries"
            ),
        }
    }
}

fn pass(store: &Store, objects: &Objects, key: Option<Arc<Key>>) -> sentinel_store::Result<()> {
    let deployment = objects.deployment();
    for _ in 0..ROUNDS {
        let crossings = store.read(|c| notices::crossings(c, &deployment, BATCH))?;
        let full = crossings.len() as u32 >= BATCH;
        for crossing in crossings {
            let (key, now) = (key.clone(), UnixMillis::now());
            store.writer().write(move |tx| {
                notices::record(tx, key.as_deref(), &deployment, &crossing, now)
            })?;
        }
        if !full {
            break;
        }
    }
    for _ in 0..ROUNDS {
        let recovered = store.read(|c| notices::recovered(c, &deployment, BATCH))?;
        let full = recovered.len() as u32 >= BATCH;
        if recovered.is_empty() {
            break;
        }
        store
            .writer()
            .write(move |tx| notices::rearm(tx, &recovered))?;
        if !full {
            break;
        }
    }
    Ok(())
}
