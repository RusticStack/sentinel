-- Intake hardening (P05 audit).
--
-- The lanes ask "which open deliveries of one state are due, oldest first"
-- several times a second. `deliveries_due` (019) was keyed on
-- `next_attempt_ms`, which neither the state filter nor the order could use,
-- so every tick scanned the whole table and sorted. This index serves the
-- query directly: equality on the state, then the order — an idle probe
-- reads one index entry and a batch stops at its limit.
DROP INDEX IF EXISTS deliveries_due;
CREATE INDEX deliveries_open ON webhook_deliveries(state, received_ms) WHERE state IN (0, 1);

-- The reordered-event rule reads the newest dispatched delivery of one
-- (repository, ref) stream on every resolution.
CREATE INDEX deliveries_dispatched ON webhook_deliveries(tenant_id, repo_id, ref_name, settled_ms)
    WHERE state = 4;

-- Control-event receipts are retired by age (`admin intake purge`), in
-- bounded batches, instead of growing forever.
CREATE INDEX github_events_by_age ON github_events(created_ms);

-- A check run's create identity (G05). A publication that is re-created
-- after a completed generation must never adopt the older generation's
-- completed run, and a lost answer to a create must always be adoptable,
-- whatever status the run was created with. The generation that performed
-- the outstanding create is recorded here and suffixed to the external id
-- sent to GitHub, so every create names exactly one run.
ALTER TABLE check_publications ADD COLUMN create_seq INTEGER;
