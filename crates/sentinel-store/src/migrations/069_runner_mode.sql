-- GitHub Actions runner mode, first part (AR01). GitHub keeps orchestrating the
-- workflow and Sentinel supplies the machine for the jobs whose `runs-on:` names one of
-- its labels. This migration carries what the intake needs before any runner exists:
-- the tenant's switch, the permissions an installation snapshot states, the terms of
-- each `workflow_job` delivery, and the job those deliveries describe.

-- Runner mode is a tenant setting, off until an administrator turns it on; an operator
-- who wants Checks alone never grants the App what runner mode needs.
ALTER TABLE tenants ADD COLUMN runner_mode INTEGER NOT NULL DEFAULT 0 CHECK(runner_mode IN (0, 1));

-- What the last installation snapshot said runner mode needs: bit 0 actions read (it
-- delivers `workflow_job`), bit 1 a self-hosted runner may be registered through this
-- installation (organization self-hosted runners write, or repository administration
-- write in a personal namespace). Kept here so a withdrawn permission refuses a queued
-- job at once, without asking GitHub in the intake path.
ALTER TABLE installations ADD COLUMN runner_permissions INTEGER NOT NULL DEFAULT 0
    CHECK(runner_permissions BETWEEN 0 AND 3);

-- What one delivery stated: which job of which run, the labels its `runs-on:` asked
-- for, and what the later activities add (the runner GitHub assigned, the conclusion
-- it reached). Written once with its delivery and immutable, like a pull request's or a
-- merge group's terms.
CREATE TABLE runner_deliveries(
    delivery_id BLOB PRIMARY KEY NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 32),
    job_id INTEGER NOT NULL CHECK(job_id > 0),
    run_id INTEGER NOT NULL CHECK(run_id > 0),
    labels TEXT NOT NULL CHECK(length(labels) <= 512),
    runner TEXT CHECK(runner IS NULL OR length(runner) BETWEEN 1 AND 128),
    conclusion TEXT CHECK(conclusion IS NULL OR length(conclusion) BETWEEN 1 AND 32),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;

-- One row per GitHub job whoever delivers its events and in whatever order: GitHub's
-- job id is the identity, state only moves forward (0 queued, 1 in_progress,
-- 2 completed), and a stamp is absent when the event that would set it was never seen.
-- `class` is the resource class the label named, which no later delivery rewrites.
CREATE TABLE runner_jobs(
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    job_id INTEGER NOT NULL CHECK(job_id > 0),
    run_id INTEGER NOT NULL CHECK(run_id > 0),
    class TEXT NOT NULL CHECK(length(class) BETWEEN 1 AND 40),
    state_code INTEGER NOT NULL CHECK(state_code BETWEEN 0 AND 2),
    runner TEXT CHECK(runner IS NULL OR length(runner) BETWEEN 1 AND 128),
    conclusion TEXT CHECK(conclusion IS NULL OR length(conclusion) BETWEEN 1 AND 32),
    queued_ms INTEGER NOT NULL,
    started_ms INTEGER,
    completed_ms INTEGER,
    CHECK(started_ms IS NULL OR started_ms >= queued_ms),
    CHECK((state_code = 2) = (completed_ms IS NOT NULL)),
    CHECK(completed_ms IS NULL OR completed_ms >= queued_ms),
    PRIMARY KEY(tenant_id, repo_id, job_id),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;

CREATE TRIGGER runner_terms_insert BEFORE INSERT ON runner_deliveries BEGIN
    SELECT RAISE(ABORT, 'runner delivery ownership mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM webhook_deliveries d
        WHERE d.id = NEW.delivery_id AND d.tenant_id = NEW.tenant_id AND d.repo_id = NEW.repo_id);
END;
CREATE TRIGGER runner_terms_immutable BEFORE UPDATE ON runner_deliveries
WHEN NEW.delivery_id != OLD.delivery_id OR NEW.tenant_id != OLD.tenant_id
  OR NEW.repo_id != OLD.repo_id OR NEW.action != OLD.action
  OR NEW.job_id != OLD.job_id OR NEW.run_id != OLD.run_id
  OR NEW.labels != OLD.labels OR NEW.runner IS NOT OLD.runner
  OR NEW.conclusion IS NOT OLD.conclusion
BEGIN
    SELECT RAISE(ABORT, 'runner delivery terms are immutable');
END;
-- A job's class, run and first sighting are decided once; only its lifecycle moves.
CREATE TRIGGER runner_job_identity BEFORE UPDATE ON runner_jobs
WHEN NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.job_id != OLD.job_id OR NEW.run_id != OLD.run_id
  OR NEW.class != OLD.class OR NEW.queued_ms != OLD.queued_ms
  OR NEW.state_code < OLD.state_code
BEGIN
    SELECT RAISE(ABORT, 'runner job identity is immutable');
END;
