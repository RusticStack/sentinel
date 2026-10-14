-- Keyed indexes for re-applying a retention policy in bounded batches.
-- Indexes only: no statement of an older binary reads or writes anything new,
-- so this migration is declared readable by 48.

-- The tenant's stamped, unexpired logs in row order; the same predicate as
-- `attempts_log_expiry`, so the reapply statements can name it.
CREATE INDEX attempts_log_reapply ON attempts(tenant_id, id)
    WHERE log_expires_ms IS NOT NULL AND log_expired_ms IS NULL;

-- The tenant's artifacts in row order.
CREATE INDEX artifacts_reapply ON artifacts(tenant_id, id);
