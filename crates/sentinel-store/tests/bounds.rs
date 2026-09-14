//! Parts 01–02 audit gates C02/W02: the store's resource bounds and failure
//! behavior before any request loop is attached. Stalled work, a panicking
//! closure, reader saturation, orderly shutdown and single-controller
//! ownership are each exercised for real, with wall-clock bounds asserted.

use std::{
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{TenantId, UnixMillis};
use sentinel_store::{
    Durability, Error, READ_ADMISSION, READER_LIMIT, Shutdown, Store, WRITE_WAIT, jobs,
};

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    (dir, store)
}

fn tenant_count(store: &Store) -> i64 {
    store
        .read(|c| {
            c.query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap()
}

#[test]
fn one_process_owns_the_database_and_ownership_ends_with_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let first = Store::open(&path, Durability::Normal).unwrap();
    assert!(matches!(
        Store::open(&path, Durability::Normal),
        Err(Error::AlreadyOwned)
    ));
    // A different database beside it is a different deployment.
    Store::open(dir.path().join("other.sqlite"), Durability::Normal).unwrap();
    assert_eq!(first.shutdown(Duration::from_secs(5)), Shutdown::Drained);
    Store::open(&path, Durability::Normal).unwrap();
}

#[test]
fn a_panicking_write_rolls_back_and_the_writer_keeps_serving() {
    let (_dir, store) = store();
    let tenant = TenantId::new();
    let outcome = store.writer().write(move |tx| {
        jobs::insert_tenant(tx, tenant, "half", UnixMillis(1))?;
        panic!("closure bug");
        #[allow(unreachable_code)]
        Ok(())
    });
    assert!(matches!(outcome, Err(Error::WriterPanicked)), "{outcome:?}");
    assert_eq!(
        tenant_count(&store),
        0,
        "the partial transaction rolled back"
    );

    // The next write on the same writer works, and so does a checkpoint.
    let tenant = TenantId::new();
    store
        .writer()
        .write(move |tx| jobs::insert_tenant(tx, tenant, "whole", UnixMillis(2)))
        .unwrap();
    assert_eq!(tenant_count(&store), 1);
    store.checkpoint().unwrap();
}

#[test]
fn a_stalled_write_is_reported_as_ambiguous_not_as_failed() {
    let (_dir, store) = store();
    let tenant = TenantId::new();
    let started = Instant::now();
    let outcome = store.writer().write(move |tx| {
        jobs::insert_tenant(tx, tenant, "slow", UnixMillis(1))?;
        // A disk that answers eventually, later than anybody should wait.
        thread::sleep(WRITE_WAIT + Duration::from_millis(500));
        Ok(())
    });
    let waited = started.elapsed();
    assert!(matches!(outcome, Err(Error::WriteAmbiguous)), "{outcome:?}");
    assert!(waited >= WRITE_WAIT && waited < WRITE_WAIT + Duration::from_secs(2));

    // "Ambiguous" was the truth: the write completes, and a re-read sees it.
    thread::sleep(Duration::from_secs(1));
    assert_eq!(tenant_count(&store), 1);
}

#[test]
fn readers_are_bounded_and_an_exhausted_pool_sheds_within_the_admission_window() {
    let (_dir, store) = store();
    let store = Arc::new(store);
    let hold = Arc::new(Barrier::new(READER_LIMIT + 1));
    let release = Arc::new(Barrier::new(READER_LIMIT + 1));
    let holders: Vec<_> = (0..READER_LIMIT)
        .map(|_| {
            let (store, hold, release) =
                (Arc::clone(&store), Arc::clone(&hold), Arc::clone(&release));
            thread::spawn(move || {
                store
                    .read(|_| {
                        hold.wait();
                        release.wait();
                        Ok(())
                    })
                    .unwrap();
            })
        })
        .collect();
    hold.wait();

    // Every reader is occupied: the next request waits its bound, then sheds.
    let started = Instant::now();
    assert!(matches!(
        tenant_count_result(&store),
        Err(Error::Overloaded)
    ));
    let waited = started.elapsed();
    assert!(waited >= READ_ADMISSION && waited < READ_ADMISSION + Duration::from_secs(1));

    release.wait();
    for holder in holders {
        holder.join().unwrap();
    }
    // Freed readers are reused, not reopened: the pool never exceeds the limit.
    assert_eq!(tenant_count(&store), 0);
    let concurrent: Vec<_> = (0..READER_LIMIT * 4)
        .map(|_| {
            let store = Arc::clone(&store);
            thread::spawn(move || tenant_count(&store))
        })
        .collect();
    for c in concurrent {
        assert_eq!(c.join().unwrap(), 0);
    }
}

fn tenant_count_result(store: &Store) -> Result<i64, Error> {
    store.read(|c| {
        c.query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
            .map_err(Error::from)
    })
}

#[test]
fn shutdown_drains_accepted_work_and_reports_a_stall_honestly() {
    let (dir, store) = store();
    let path = dir.path().join("metadata.sqlite");
    let tenant = TenantId::new();
    store
        .writer()
        .write(move |tx| jobs::insert_tenant(tx, tenant, "queued", UnixMillis(1)))
        .unwrap();
    assert_eq!(store.shutdown(Duration::from_secs(5)), Shutdown::Drained);
    let reopened = Store::open(&path, Durability::Normal).unwrap();
    assert_eq!(tenant_count(&reopened), 1);

    // A write that outlives every bound: the caller learns "ambiguous", the
    // shutdown learns "stalled", and the work is still never discarded — it
    // completes once the disk (here, a channel) answers.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let tenant = TenantId::new();
    let outcome = reopened.writer().write(move |tx| {
        jobs::insert_tenant(tx, tenant, "stalled", UnixMillis(2))?;
        let _ = release_rx.recv();
        Ok(())
    });
    assert!(matches!(outcome, Err(Error::WriteAmbiguous)));
    assert_eq!(
        reopened.shutdown(Duration::from_millis(300)),
        Shutdown::Stalled
    );
    release_tx.send(()).unwrap();
    // A stalled shutdown keeps ownership: the writer thread is still this
    // process's, so a second controller must not start until it exits.
    thread::sleep(Duration::from_millis(300));
    assert!(matches!(
        Store::open(&path, Durability::Normal),
        Err(Error::AlreadyOwned)
    ));
}
