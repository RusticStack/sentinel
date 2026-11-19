-- Runner mode's fork pull-request policy (AR09). A `workflow_job` delivery states the pull
-- requests its commit belongs to, and a job of a fork's pull request runs code nobody reviewed
-- into this repository on a machine this deployment operates. Runner mode therefore refuses such
-- a job unless the tenant opts in, and even then a runner is only leased on the hostile-fork pool
-- (M09): a separate pool, no secrets, cache scopes of its own. Nothing else changes: a fork job
-- that is not served stays queued at GitHub, which is the outcome the plan states.
ALTER TABLE tenants ADD COLUMN runner_fork_prs INTEGER NOT NULL DEFAULT 0
    CHECK(runner_fork_prs IN (0, 1));

-- What one `workflow_job` delivery said its commit was: 1 when any pull request it names comes
-- from a fork, 0 when none does.
ALTER TABLE runner_deliveries ADD COLUMN fork_pr INTEGER NOT NULL DEFAULT 0
    CHECK(fork_pr IN (0, 1));

-- The same fact on the job, so placement can tell fork demand from trusted demand without
-- reading the deliveries again.
ALTER TABLE runner_jobs ADD COLUMN fork_pr INTEGER NOT NULL DEFAULT 0
    CHECK(fork_pr IN (0, 1));

-- A pool that takes fork jobs and nothing else: the hostile-fork pool of M09.
ALTER TABLE pools ADD COLUMN fork_prs INTEGER NOT NULL DEFAULT 0
    CHECK(fork_prs IN (0, 1));

-- A delivery's terms are written once: that includes where its commit came from.
CREATE TRIGGER runner_terms_fork_immutable BEFORE UPDATE OF fork_pr ON runner_deliveries
WHEN NEW.fork_pr != OLD.fork_pr
BEGIN
    SELECT RAISE(ABORT, 'runner delivery fork provenance is immutable');
END;

-- A job's fork provenance is decided by the first delivery that describes it; a later delivery
-- that disagrees is a conflict the intake refuses, never a rewrite of what placement reads.
CREATE TRIGGER runner_job_fork_immutable BEFORE UPDATE OF fork_pr ON runner_jobs
WHEN NEW.fork_pr != OLD.fork_pr
BEGIN
    SELECT RAISE(ABORT, 'runner job fork provenance is immutable');
END;

-- Placement's SQL decides which demand a pool serves; this is the invariant no raw write can
-- break: a lease on the fork pool needs a tenant that offers fork jobs.
CREATE TRIGGER runner_lease_fork_pool BEFORE INSERT ON runner_leases
WHEN (SELECT fork_prs FROM pools WHERE id = NEW.pool_id) = 1
  AND (SELECT runner_fork_prs FROM tenants WHERE id = NEW.tenant_id) = 0
BEGIN
    SELECT RAISE(ABORT, 'runner lease on a fork pool without the tenant opt-in');
END;
