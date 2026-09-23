-- Fleet scheduling (Part 08 audit fixes): repository fairness, pool-scoped
-- reservations, bounded queue listing and revocation fencing.

-- The repository a job belongs to, copied from its run at insert so the fair
-- queue can rank tenant -> repository without joining `runs` per row, and a
-- concurrency group is a (tenant, repository, key) lock as documented.
ALTER TABLE jobs ADD COLUMN repo_id BLOB;
UPDATE jobs SET repo_id = (SELECT r.repo_id FROM runs r WHERE r.id = jobs.run_id);

-- Whether the job's run was triggered by a pull request, copied from the
-- run's provenance when it is recorded (trigger below). Placement's
-- pull-request reserve reads the ready side of this through its own partial
-- index instead of joining provenance to every ready job.
ALTER TABLE jobs ADD COLUMN pull_request INTEGER NOT NULL DEFAULT 0 CHECK(pull_request IN (0, 1));
UPDATE jobs SET pull_request = 1
 WHERE run_id IN (SELECT run_id FROM run_provenance WHERE trigger = 'pull_request');
CREATE TRIGGER provenance_marks_pull_request AFTER INSERT ON run_provenance
WHEN NEW.trigger = 'pull_request' BEGIN
    UPDATE jobs SET pull_request = 1 WHERE run_id = NEW.run_id;
END;

-- The repository an attempt's job belongs to, so the held resources of a
-- tenant and of one of its repositories are index-only sums.
ALTER TABLE attempts ADD COLUMN repo_id BLOB;
UPDATE attempts SET repo_id = (SELECT j.repo_id FROM jobs j WHERE j.id = attempts.job_id);

-- The fair queue: per (tenant, repository), in placement order.
DROP INDEX jobs_ready_tenant;
CREATE INDEX jobs_ready_repo ON jobs(tenant_id, repo_id, priority, queued_ms, created_seq)
    WHERE state_code = 1;
-- Ready pull-request jobs only, in the same fair order: the reserve's probe
-- visits these and nothing else, and a worker whose free room is inside the
-- reserve reads its candidates from here instead of walking every stream.
CREATE INDEX jobs_ready_pr ON jobs(tenant_id, repo_id, priority, queued_ms, created_seq)
    WHERE state_code = 1 AND pull_request = 1;
-- A tenant's waiting jobs (blocked and queued), oldest first, for the bounded
-- queue listing and its count.
CREATE INDEX jobs_waiting ON jobs(tenant_id, queued_ms, created_seq) WHERE state_code IN (0, 1);
-- Concurrency groups are held per repository.
DROP INDEX jobs_conc;
CREATE INDEX jobs_conc ON jobs(tenant_id, repo_id, concurrency_group)
    WHERE concurrency_group IS NOT NULL;

-- Held resources, covering: free capacity, tenant and repository deficits and
-- the dispatcher's per-worker load read no attempt rows.
DROP INDEX attempts_held_by_worker;
CREATE INDEX attempts_held_by_worker ON attempts(worker_id, cpu_millis, memory_bytes, disk_bytes)
    WHERE released_ms IS NULL;
DROP INDEX attempts_held_by_tenant;
CREATE INDEX attempts_held_by_repo ON attempts(tenant_id, repo_id, cpu_millis)
    WHERE released_ms IS NULL;

-- Revoked workers, so the dispatcher notices a revocation made by another
-- process (the host-local admin command) with one probe per pass.
CREATE INDEX workers_revoked ON workers(revoked_ms) WHERE revoked_ms IS NOT NULL;

-- Dead schema from 028/029: never written or never read by any plan. The PR
-- probe now reads `jobs_ready_pr`; per-run fair queueing was never built.
DROP INDEX jobs_fair;
DROP INDEX jobs_ready_run;
DROP INDEX provenance_pr;
ALTER TABLE jobs DROP COLUMN wait_code;
ALTER TABLE jobs DROP COLUMN wait_detail;
