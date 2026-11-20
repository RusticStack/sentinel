-- The source manifest of a run (Part 16 I03): every checkout of a job — the run's own repository and
-- each additional one the pipeline declares — with the revision the controller resolved for it, so what
-- a run built is answerable without re-reading the pipeline or asking a worker.
--
-- Keyed by (run, job, checkout) and never by attempt: a rerun is a new attempt of the same job, so the
-- revision the first attempt resolved is the one every later attempt checks out. The row is written
-- once and has no replacement — a rerun of a past run resolves the recorded revision, or fails saying
-- that revision is gone, and never substitutes the branch's current tip.
CREATE TABLE run_sources(
    tenant_id BLOB NOT NULL REFERENCES tenants(id) CHECK(length(tenant_id) = 16),
    run_id BLOB NOT NULL REFERENCES runs(id) CHECK(length(run_id) = 16),
    -- The job's index in the compiled pipeline: the spec is immutable, so it is the job's identity here.
    job_index INTEGER NOT NULL CHECK(job_index >= 0),
    -- 0 is the run's own checkout at the workspace root; the rest are the job's declared checkouts.
    checkout_index INTEGER NOT NULL CHECK(checkout_index >= 0),
    repo_id BLOB NOT NULL REFERENCES repos(id) CHECK(length(repo_id) = 16),
    -- The repository's name in its tenant, kept as it was at dispatch so a later rename does not
    -- rewrite what a run read.
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 256),
    path TEXT NOT NULL CHECK(length(path) <= 256),
    ref_name TEXT CHECK(length(ref_name) <= 1024),
    revision TEXT NOT NULL CHECK(length(revision) BETWEEN 40 AND 64),
    -- The checkout's history selection; the compiled spec keeps the exact depth and this keeps the fact.
    history TEXT NOT NULL CHECK(length(history) <= 16),
    resolved_ms INTEGER NOT NULL,
    PRIMARY KEY(run_id, job_index, checkout_index)
) WITHOUT ROWID;
CREATE INDEX run_sources_by_run ON run_sources(tenant_id, run_id, job_index);

-- Written once. A second attempt at the same job may not rewrite a recorded revision, and nothing may
-- edit one afterwards: the manifest is what the reruns resolve.
CREATE TRIGGER run_sources_immutable BEFORE UPDATE ON run_sources BEGIN
    SELECT RAISE(ABORT, 'a source manifest row is immutable');
END;
