//! Decide and mutate in one write transaction: the single writer serialises duplicate
//! requests, so the second one sees the first one's record and cannot execute twice.
use rusqlite::{OptionalExtension, Transaction, params};
use sentinel_core::{RunId, TenantId, UnixMillis};
use sentinel_protocol::idempotency::{Decision, Fingerprint, IdempotencyKey, Stored, decide};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug)]
pub struct Scope<'a> {
    pub tenant: TenantId,
    pub principal: &'a str,
    pub route: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begin {
    Execute,
    Replay(RunId),
    Mismatch,
    InFlight,
}

type StoredRow = (Vec<u8>, i64, i64, Option<[u8; 16]>);

pub fn begin(
    tx: &Transaction<'_>,
    scope: Scope<'_>,
    key: IdempotencyKey,
    fingerprint: Fingerprint,
    now: UnixMillis,
) -> Result<Begin> {
    let stored: Option<StoredRow> = tx
        .query_row(
            "SELECT fingerprint, created_ms, completed, run_id FROM idempotency_keys
             WHERE tenant_id = ?1 AND principal = ?2 AND route = ?3 AND key = ?4",
            params![
                scope.tenant.as_bytes(),
                scope.principal,
                scope.route,
                key.as_str()
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let record = match &stored {
        None => None,
        Some((fp, created, completed, _)) => {
            let bytes: [u8; 16] = fp
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("idempotency_keys.fingerprint"))?;
            Some(Stored {
                fingerprint: Fingerprint(u128::from_le_bytes(bytes)),
                stored_at_ms: *created,
                completed: *completed != 0,
            })
        }
    };
    match decide(record, fingerprint, now.0) {
        Decision::Replay => {
            let run = stored
                .and_then(|(_, _, _, run)| run)
                .ok_or(Error::Corrupt("idempotency_keys.run_id"))?;
            Ok(Begin::Replay(
                RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
            ))
        }
        Decision::Mismatch => Ok(Begin::Mismatch),
        Decision::InFlight => Ok(Begin::InFlight),
        Decision::Execute => {
            tx.execute(
                "INSERT INTO idempotency_keys(tenant_id, principal, route, key, fingerprint, created_ms, completed, run_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL)
                 ON CONFLICT(tenant_id, principal, route, key) DO UPDATE SET
                   fingerprint = excluded.fingerprint, created_ms = excluded.created_ms,
                   completed = 0, run_id = NULL",
                params![
                    scope.tenant.as_bytes(),
                    scope.principal,
                    scope.route,
                    key.as_str(),
                    fingerprint.0.to_le_bytes(),
                    now.0
                ],
            )?;
            Ok(Begin::Execute)
        }
    }
}

/// Must share the mutation's transaction so both commit or neither does.
pub fn complete(
    tx: &Transaction<'_>,
    scope: Scope<'_>,
    key: IdempotencyKey,
    run: RunId,
) -> Result<()> {
    let n = tx.execute(
        "UPDATE idempotency_keys SET completed = 1, run_id = ?5
         WHERE tenant_id = ?1 AND principal = ?2 AND route = ?3 AND key = ?4 AND completed = 0",
        params![
            scope.tenant.as_bytes(),
            scope.principal,
            scope.route,
            key.as_str(),
            run.as_bytes()
        ],
    )?;
    if n != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

const PURGE_SQL: &str = "DELETE FROM idempotency_keys WHERE (tenant_id, principal, route, key) IN
     (SELECT tenant_id, principal, route, key FROM idempotency_keys
      WHERE created_ms < ?1 ORDER BY created_ms LIMIT ?2)";

pub fn purge_expired(store: &crate::Store, now: UnixMillis, limit: u32) -> Result<usize> {
    let cutoff = now.0 - sentinel_protocol::idempotency::IDEMPOTENCY_TTL_MS;
    store
        .writer()
        .write(move |tx| Ok(tx.execute(PURGE_SQL, params![cutoff, limit])?))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    #[test]
    fn the_purge_is_an_index_range() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", super::PURGE_SQL))
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map((0i64, 10i64), |r| r.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let plan = plan.join(" | ");
        assert!(plan.contains("idempotency_by_age"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        assert!(!plan.contains("SCAN idempotency_keys"), "{plan}");
    }
}
