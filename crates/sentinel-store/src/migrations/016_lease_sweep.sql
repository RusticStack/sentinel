-- Lease expiry sweep (W06): the attempts still held, ordered by deadline,
-- so the controller finds expired leases without touching finished rows.
CREATE INDEX attempts_held_by_lease ON attempts(lease_until_ms) WHERE released_ms IS NULL;
-- The job's execution timeout, copied from the spec, for the controller's backstop.
ALTER TABLE jobs ADD COLUMN timeout_ms INTEGER NOT NULL DEFAULT 0 CHECK(timeout_ms >= 0);
-- Queued jobs by the time they entered the queue, for the queue-timeout sweep.
CREATE INDEX jobs_queued_since ON jobs(queued_ms) WHERE state_code = 1;
