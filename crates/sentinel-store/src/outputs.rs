//! Declared outputs in the run's record: plain text, bounded, and public within the tenant.
//!
//! A job's outputs are what its steps wrote and it re-exported; the jobs that need it read them from its context.
//! They are never secrets — the worker refuses a value that repeats a delivered secret — so nothing here redacts
//! them and any member of the tenant reads them with the run.

use rusqlite::{Connection, Transaction, params};
use sentinel_core::{AttemptId, Fence, JobId, TenantId};

use crate::{Error, Result};

/// The column's own bound, as migration 85 states it.
pub const MAX_COLUMN_BYTES: usize = 16384;

/// The bytes the column holds for `outputs`: one `name=value` line each, in declaration order.
pub fn encode(outputs: &[(String, String)]) -> String {
    let mut out = String::with_capacity(outputs.iter().map(|(n, v)| n.len() + v.len() + 2).sum());
    for (name, value) in outputs {
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// The outputs a stored column holds. Values carry no newline, so the split cannot lose an entry.
pub fn decode(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(4);
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

/// Writes the attempt's job outputs, under the fence that reported them: a report from a fence the attempt no
/// longer holds changes nothing.
pub fn record(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    fence: Fence,
    outputs: &[(String, String)],
) -> Result<()> {
    if outputs.is_empty() {
        return Ok(());
    }
    let encoded = encode(outputs);
    if encoded.len() > MAX_COLUMN_BYTES {
        return Err(Error::InvalidInput("job outputs"));
    }
    tx.prepare_cached(
        "UPDATE jobs SET outputs = ?3
         WHERE id = (SELECT job_id FROM attempts WHERE id = ?1 AND fence = ?2)",
    )?
    .execute(params![
        attempt.as_bytes(),
        fence.0 as i64,
        encoded.as_str()
    ])?;
    Ok(())
}

/// The outputs one job published, for the jobs that need it.
pub fn of_job(conn: &Connection, tenant: TenantId, job: JobId) -> Result<Vec<(String, String)>> {
    let text: Option<String> = conn
        .prepare_cached("SELECT outputs FROM jobs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            other => other.into(),
        })?;
    Ok(text.map(|text| decode(&text)).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_output_with_an_equals_sign_survives_the_column() {
        let outputs = vec![
            ("version".to_owned(), "1.4.0".to_owned()),
            ("query".to_owned(), "a=1&b=2".to_owned()),
        ];
        let encoded = encode(&outputs);
        assert_eq!(encoded, "version=1.4.0\nquery=a=1&b=2\n");
        assert_eq!(decode(&encoded), outputs);
        assert!(decode("").is_empty());
    }
}
