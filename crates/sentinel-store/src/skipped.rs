//! Rows a maintenance batch passed over because an id column did not decode.
//!
//! Every id column is a 16-byte blob the store itself wrote, so an undecodable one is outside damage. Failing the whole batch on
//! it would put the same row at the head of the next pass's query and stop every later row for good; the batch skips it instead,
//! counts it here and names it by table and primary key. Only the key is recorded, never another column of the row.

use std::{
    fmt::Write as _,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// The most recent row passed over: the table and its primary key, hexadecimal for a blob and decimal for an integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub table: &'static str,
    pub key: String,
}

static TOTAL: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<Skipped>> = Mutex::new(None);

fn note(table: &'static str, key: String) {
    TOTAL.fetch_add(1, Ordering::Relaxed);
    *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some(Skipped { table, key });
}

/// A row keyed by a blob.
pub(crate) fn note_blob(table: &'static str, key: &[u8]) {
    let mut hex = String::with_capacity(key.len() * 2);
    for byte in key {
        let _ = write!(hex, "{byte:02x}");
    }
    note(table, hex);
}

/// A row keyed by an integer.
pub(crate) fn note_int(table: &'static str, key: i64) {
    note(table, key.to_string());
}

/// Rows passed over since the process started, process-wide across threads; a row that stays damaged is counted again every time a
/// batch meets it (each round of a catch-up, each replicator tick).
pub fn total() -> u64 {
    TOTAL.load(Ordering::Relaxed)
}

pub fn last() -> Option<Skipped> {
    LAST.lock().unwrap_or_else(|p| p.into_inner()).clone()
}
