-- Artifact records (D03). One row per declared artifact per attempt:
-- `captured` carries the manifest version whose entries name the committed
-- objects; `absent` and `failed` record what the worker reported so a run's
-- output is explainable without guessing. `retain_until_ms` is the declared
-- retention converted to a deadline; reclamation itself is a later stage.
CREATE TABLE artifacts(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    run_id BLOB NOT NULL REFERENCES runs(id),
    job_id BLOB NOT NULL REFERENCES jobs(id),
    attempt_id BLOB NOT NULL REFERENCES attempts(id),
    name TEXT NOT NULL,
    -- 0 captured, 1 absent (no paths matched), 2 failed (capture or
    -- transfer error). Terminal states never reopen.
    state_code INTEGER NOT NULL CHECK(state_code IN (0, 1, 2)),
    manifest_version INTEGER,
    entries INTEGER NOT NULL DEFAULT 0 CHECK(entries >= 0),
    bytes INTEGER NOT NULL DEFAULT 0 CHECK(bytes >= 0),
    retain_until_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    UNIQUE(attempt_id, name),
    -- Only a captured artifact names a manifest.
    CHECK((state_code = 0) = (manifest_version IS NOT NULL))
) WITHOUT ROWID;
CREATE INDEX artifacts_by_run ON artifacts(tenant_id, run_id);
-- Ownership is joined, never asserted: the attempt must belong to the job,
-- the job to the run and all of them to the tenant.
CREATE TRIGGER artifacts_owner BEFORE INSERT ON artifacts BEGIN
    SELECT RAISE(ABORT,'artifact ownership') WHERE NOT EXISTS(
        SELECT 1 FROM attempts a
        JOIN jobs j ON j.id = a.job_id
        JOIN runs r ON r.id = j.run_id
        WHERE a.id = NEW.attempt_id AND a.job_id = NEW.job_id
          AND j.run_id = NEW.run_id AND a.tenant_id = NEW.tenant_id
          AND j.tenant_id = NEW.tenant_id AND r.tenant_id = NEW.tenant_id);
END;
-- Captured rows carry the manifest version committed earlier in the same
-- transaction; manifest immutability is the objects triggers' job.
