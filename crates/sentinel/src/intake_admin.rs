//! Host-local inspection of durable event intake (G02).
//!
//! Deliveries are tenant-owned rows; the operator opening the database reads
//! them the way they read any other record. Listing is metadata only, and
//! purging is bounded and retention-scoped: it never touches a pending
//! delivery, only settled ones older than the retention duration, and it
//! retires GitHub control-event receipts the same way (never inside their
//! replay window).

use sentinel_core::{RepoId, UnixMillis};
use sentinel_store::{Store, github_events, intake, lookup};
use serde_json::json;

use crate::{
    admin::{self, Error, duration_ms, fail},
    cli::{IntakeArgs, IntakeCommand},
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Longest retention the command accepts. Retention policy itself is Part 13.
const MAX_RETENTION_MS: i64 = 366 * DAY_MS;

pub fn run(args: &IntakeArgs) -> Result<(), Error> {
    let store: Store = admin::open(&args.data, true)?;
    match &args.command {
        IntakeCommand::List { repo, state, limit } => {
            let repo: RepoId = repo.parse().map_err(|_| fail("invalid repository ID"))?;
            let state = state
                .as_deref()
                .map(|text| intake::State::parse(text).ok_or_else(|| fail("unknown state")))
                .transpose()?;
            let limit = *limit;
            let deliveries = store
                .read(move |conn| {
                    let tenant = lookup::repo_tenant(conn, repo)?;
                    intake::list(conn, tenant, repo, state, limit)
                })
                .map_err(|error| fail(format!("cannot list deliveries: {error}")))?;
            let deliveries: Vec<_> = deliveries
                .iter()
                .map(|d| {
                    json!({
                        "id": d.id.to_string(),
                        "provider": d.provider,
                        "external_id": d.external_id,
                        "event": d.event,
                        "ref": d.ref_name,
                        "old_sha": d.old_sha,
                        "new_sha": d.new_sha,
                        "state": d.state.as_str(),
                        "reason": d.reason,
                        "attempts": d.attempts,
                        "received_ms": d.received.0,
                        "settled_ms": d.settled.map(|t| t.0),
                        // The run a dispatched delivery produced (G03).
                        "run": d.run.map(|run| run.to_string()),
                    })
                })
                .collect();
            println!(
                "{}",
                json!({ "repo": repo.to_string(), "deliveries": deliveries })
            );
        }
        IntakeCommand::Purge { older_than, limit } => {
            let retention = duration_ms(older_than, MAX_RETENTION_MS)?;
            if !(1..=10_000).contains(limit) {
                return Err(fail("limit must be between 1 and 10000"));
            }
            let limit = *limit;
            let before = UnixMillis(UnixMillis::now().0.saturating_sub(retention));
            let (purged, receipts) = store
                .writer()
                .write(move |tx| {
                    let purged = intake::purge_settled(tx, before, limit)?;
                    // Control-event receipts are retired under the same
                    // bound (never younger than their replay window).
                    let receipts =
                        github_events::purge_receipts(tx, before, UnixMillis::now(), limit)?;
                    Ok((purged, receipts))
                })
                .map_err(|error| fail(format!("cannot purge deliveries: {error}")))?;
            println!(
                "{}",
                json!({
                    "purged": purged,
                    "receipts_purged": receipts,
                    "older_than_ms": retention
                })
            );
        }
    }
    Ok(())
}
