//! Durable idempotency records for mutations. The decision (execute,
//! replay, mismatch) is taken inside the same write transaction as the
//! mutation itself, so a duplicate request can never execute twice even if
//! two copies arrive back to back: the single writer serialises them and
//! the second one sees the first one's record.
use rusqlite::{OptionalExtension, Transaction, params};
use sentinel_core::{RunId, TenantId, UnixMillis};
use sentinel_protocol::idempotency::{Decision, Fingerprint, IdempotencyKey, Stored, decide};

use crate::{Error, Result};

/// Where a key applies. Keys are meaningless outside their scope, so the
/// same key from another tenant or route is simply a different record.
#[derive(Clone, Copy, Debug)]
pub struct Scope<'a> {
    pub tenant: TenantId,
    pub principal: &'a str,
    pub route: &'a str,
}

/// Outcome of `begin`: either execute (and later `complete`) or return the
/// stored result without executing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begin {
    Execute,
    /// The earlier request created this run; return it again.
    Replay(RunId),
    /// Same key, different body.
    Mismatch,
    /// First request recorded but not completed (only possible after a crash
    /// between `begin` and `complete` in separate transactions).
    InFlight,
}

/// (fingerprint bytes, created_ms, completed, run_id)
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
            // Replace an expired record or insert a fresh one; completion fills run_id.
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

/// Record the result of an executed request. Must run in the same
/// transaction as the mutation so both commit or neither does.
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

/// Drop records older than the TTL; run periodically.
pub fn expire(tx: &Transaction<'_>, now: UnixMillis) -> Result<usize> {
    let cutoff = now.0 - sentinel_protocol::idempotency::IDEMPOTENCY_TTL_MS;
    Ok(tx.execute(
        "DELETE FROM idempotency_keys WHERE created_ms < ?1",
        [cutoff],
    )?)
}
