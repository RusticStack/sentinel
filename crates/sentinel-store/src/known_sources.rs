//! The set of network sources that recently authenticated a worker, kept across controller restarts.
//!
//! The worker link reserves part of its handshake pool for these sources; without a stored copy a restart
//! under load would treat the whole fleet as strangers. Loopback addresses are never stored (a Tailcat
//! helper makes every tunnelled peer one): the link decides those by the authenticated worker instead.

use rusqlite::{Connection, Transaction, params};

use crate::Result;

/// The 16-byte key the link derives from a source address.
pub type Source = [u8; 16];

pub const MAX_SOURCES: i64 = 4096;

/// Live sources, newest first, each with its last-seen wall time in milliseconds.
pub fn load(conn: &Connection, now_ms: i64, ttl_ms: i64) -> Result<Vec<(Source, i64)>> {
    let mut statement = conn.prepare_cached(
        "SELECT source, seen_ms FROM link_known_sources
         WHERE seen_ms > ?1 ORDER BY seen_ms DESC LIMIT ?2",
    )?;
    let mut rows = statement.query(params![now_ms.saturating_sub(ttl_ms), MAX_SOURCES])?;
    let mut live = Vec::new();
    while let Some(row) = rows.next()? {
        let source: Vec<u8> = row.get(0)?;
        if let Ok(source) = Source::try_from(source.as_slice()) {
            live.push((source, row.get(1)?));
        }
    }
    Ok(live)
}

/// Refresh one source, drop what is past `ttl_ms` and keep the newest `MAX_SOURCES` rows.
pub fn record(tx: &Transaction<'_>, source: Source, now_ms: i64, ttl_ms: i64) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO link_known_sources(source, seen_ms) VALUES (?1, ?2)
         ON CONFLICT(source) DO UPDATE SET seen_ms = MAX(seen_ms, excluded.seen_ms)",
    )?
    .execute(params![source, now_ms])?;
    tx.prepare_cached("DELETE FROM link_known_sources WHERE seen_ms <= ?1")?
        .execute([now_ms.saturating_sub(ttl_ms)])?;
    tx.prepare_cached(
        "DELETE FROM link_known_sources WHERE source IN (
             SELECT source FROM link_known_sources ORDER BY seen_ms DESC LIMIT -1 OFFSET ?1)",
    )?
    .execute([MAX_SOURCES])?;
    Ok(())
}
