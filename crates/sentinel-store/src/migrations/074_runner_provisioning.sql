-- Runner-mode provisioning (AR02). AR01 recorded one durable row per GitHub job and
-- stopped there, because GitHub runs that job itself. This migration carries what a
-- runner is: the capacity of one worker leased for one ephemeral runner of a label's
-- class, the just-in-time configuration GitHub issues for it (sealed at rest, readable
-- once), the moment it must be gone if it never took a job, and the registration that
-- has to be removed again.
--
-- A lease is not bound to a GitHub job when it is placed. GitHub assigns a queued job to
-- whichever idle runner matches its labels, so demand is counted per label set and a
-- lease is placed for an unmet unit of it; the `in_progress` delivery that names the
-- runner we registered (`runner_name`) is what binds the job to its lease.
CREATE TABLE runner_leases(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    -- The label set this lease satisfies, exactly as `runner_jobs.class` spells it.
    class TEXT NOT NULL CHECK(length(class) BETWEEN 1 AND 40),
    pool_id BLOB NOT NULL CHECK(length(pool_id) = 16),
    worker_id BLOB NOT NULL CHECK(length(worker_id) = 16),
    -- Fenced like an attempt: a lease id is never reused, and a worker's answer is only
    -- accepted for the fence it was offered with.
    fence INTEGER NOT NULL CHECK(fence > 0),
    -- 0 offered, 1 accepted (the worker holds it), 2 released (nothing holds anything).
    state_code INTEGER NOT NULL CHECK(state_code BETWEEN 0 AND 2),
    -- What the worker's capacity holds while the lease is live, from the class.
    cpu_millis INTEGER NOT NULL CHECK(cpu_millis >= 0),
    memory_bytes INTEGER NOT NULL CHECK(memory_bytes >= 0),
    -- The name GitHub knows this runner by, unique per tenant while a lease is live, so
    -- the `in_progress` delivery that states it can be matched to exactly one lease.
    runner_name TEXT NOT NULL CHECK(length(runner_name) BETWEEN 1 AND 128),
    -- GitHub's own runner id, from generate-jitconfig; what de-registration names.
    runner_id INTEGER CHECK(runner_id IS NULL OR runner_id > 0),
    -- The GitHub job this runner took, once an `in_progress` delivery names it.
    job_id INTEGER CHECK(job_id IS NULL OR job_id > 0),
    -- The encoded JIT configuration, sealed with the controller's master key: readable
    -- while this column is not NULL and the lease is live, and cleared the moment the
    -- worker that holds the lease reads it, which is what makes delivery single-use.
    sealed_jit BLOB CHECK(sealed_jit IS NULL OR length(sealed_jit) <= 65536),
    jit_ms INTEGER,
    taken_ms INTEGER,
    offered_ms INTEGER NOT NULL,
    -- Renewed on every provisioning pass while the worker's session is alive; a lease whose
    -- deadline passed belongs to a controller that stopped and is released as lapsed.
    lease_until_ms INTEGER NOT NULL,
    accepted_ms INTEGER,
    released_ms INTEGER,
    -- Why the lease ended, from a fixed vocabulary: job_completed, idle, lapsed, declined,
    -- session_lost, revoked, register_failed, cancelled.
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 32),
    -- Set once the runner is no longer registered at GitHub, whichever reason ended it.
    deleted_ms INTEGER,
    CHECK((state_code = 2) = (released_ms IS NOT NULL)),
    CHECK(accepted_ms IS NULL OR accepted_ms >= offered_ms),
    CHECK(lease_until_ms >= offered_ms),
    CHECK(jit_ms IS NULL OR jit_ms >= offered_ms),
    CHECK(taken_ms IS NULL OR jit_ms IS NOT NULL),
    CHECK(released_ms IS NULL OR released_ms >= offered_ms),
    CHECK(jit_ms IS NULL OR sealed_jit IS NOT NULL OR taken_ms IS NOT NULL),
    CHECK(taken_ms IS NULL OR sealed_jit IS NULL)
) WITHOUT ROWID;

-- The capacity a worker still holds: one indexed sum per worker, like `attempts_held_by_worker`.
CREATE INDEX runner_leases_held ON runner_leases(worker_id) WHERE released_ms IS NULL;
-- What one label set of one repository still has live: the demand count subtracts these.
CREATE INDEX runner_leases_live ON runner_leases(tenant_id, repo_id, class)
    WHERE released_ms IS NULL;
-- The runner a delivery named, and the job a lease took.
CREATE UNIQUE INDEX runner_leases_name ON runner_leases(tenant_id, runner_name)
    WHERE released_ms IS NULL;
CREATE INDEX runner_leases_job ON runner_leases(tenant_id, repo_id, job_id)
    WHERE job_id IS NOT NULL;
-- Leases still registered at GitHub, which a stop must de-register whatever ended them.
CREATE INDEX runner_leases_registered ON runner_leases(deleted_ms)
    WHERE runner_id IS NOT NULL AND deleted_ms IS NULL;
-- A lease that never took a job by its idle bound, oldest first.
CREATE INDEX runner_leases_idle ON runner_leases(offered_ms)
    WHERE released_ms IS NULL AND job_id IS NULL;

-- A lease's identity, class and worker are decided at placement; its lifecycle only moves
-- forward, and the JIT configuration is written once and cleared at most once.
CREATE TRIGGER runner_lease_identity BEFORE UPDATE ON runner_leases
WHEN NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.class != OLD.class OR NEW.pool_id != OLD.pool_id OR NEW.worker_id != OLD.worker_id
  OR NEW.fence != OLD.fence OR NEW.runner_name != OLD.runner_name
  OR NEW.cpu_millis != OLD.cpu_millis OR NEW.memory_bytes != OLD.memory_bytes
  OR NEW.offered_ms != OLD.offered_ms OR NEW.state_code < OLD.state_code
  OR (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms)
BEGIN
    SELECT RAISE(ABORT, 'runner lease identity is immutable');
END;

-- The configuration is delivered once: it may be filled while empty, cleared when read,
-- and never written again or re-read after that.
CREATE TRIGGER runner_lease_jit_once BEFORE UPDATE ON runner_leases
WHEN NEW.sealed_jit IS NOT OLD.sealed_jit AND NOT (
    (OLD.sealed_jit IS NULL AND OLD.taken_ms IS NULL AND NEW.sealed_jit IS NOT NULL)
    OR (OLD.sealed_jit IS NOT NULL AND OLD.taken_ms IS NULL
        AND NEW.sealed_jit IS NULL AND NEW.taken_ms IS NOT NULL))
BEGIN
    SELECT RAISE(ABORT, 'a runner JIT configuration is delivered once');
END;

-- GitHub's runner id and the GitHub job a lease took are facts about one runner: neither
-- is rewritten, and the job is only ever bound once.
CREATE TRIGGER runner_lease_binding BEFORE UPDATE ON runner_leases
WHEN (OLD.runner_id IS NOT NULL AND NEW.runner_id IS NOT OLD.runner_id)
  OR (OLD.job_id IS NOT NULL AND NEW.job_id IS NOT OLD.job_id)
  OR (OLD.deleted_ms IS NOT NULL AND NEW.deleted_ms IS NOT OLD.deleted_ms)
BEGIN
    SELECT RAISE(ABORT, 'a runner lease is bound once');
END;

-- A lease names a repository that exists and belongs to the tenant, and a pool that is
-- the owner's or granted to it: unlike an attempt, nothing verified this at insert.
CREATE TRIGGER runner_lease_owner BEFORE INSERT ON runner_leases BEGIN
    SELECT RAISE(ABORT, 'runner lease ownership mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM repos r WHERE r.id = NEW.repo_id AND r.tenant_id = NEW.tenant_id);
    SELECT RAISE(ABORT, 'runner lease pool mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM pools p WHERE p.id = NEW.pool_id AND (
            p.owner_tenant_id = NEW.tenant_id
            OR EXISTS(SELECT 1 FROM pool_grants g
                      WHERE g.pool_id = p.id AND g.tenant_id = NEW.tenant_id)));
END;

-- The demand a lease was placed for: the queued jobs of one label set of one repository.
-- Counting them costs one partial index probe per class, which is what "demand per label
-- set" means when GitHub may hand any matching queued job to any matching runner.
CREATE INDEX runner_jobs_queued ON runner_jobs(tenant_id, repo_id, class)
    WHERE state_code = 0;
