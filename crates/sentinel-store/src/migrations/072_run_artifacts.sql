-- Run-level and runner-mode artifacts (E04). An artifact row no longer has to name a native
-- job and its attempt:
--   origin 0  a declared artifact of a native job (what migration 25 stored)
--   origin 1  files an authorized client attached to a run through the existing upload
--             sessions, recorded with their uploader
--   origin 2  what a runner-mode job's `upload-artifact` produced, recorded against the GitHub
--             run and job that produced it
-- Only origin 0 can satisfy a declared required artifact: finalization decides coverage by
-- reading the attempt's rows, and these two origins carry no attempt.
--
-- SQLite cannot relax a NOT NULL in place, so the table is rebuilt: same rows, same class
-- columns migration 68 added, same indexes and triggers, plus the new identity columns. Every
-- older row becomes origin 0, and an older controller refuses this database rather than reading
-- an artifact row it cannot explain.
CREATE TABLE artifacts_v71(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    origin_code INTEGER NOT NULL DEFAULT 0 CHECK(origin_code IN (0, 1, 2)),
    run_id BLOB REFERENCES runs(id),
    job_id BLOB REFERENCES jobs(id),
    attempt_id BLOB REFERENCES attempts(id),
    -- Origin 1: who attached it. The name is read through their live membership, so a former
    -- member's is not handed out.
    uploader_id BLOB REFERENCES users(id),
    -- Origin 2: the repository and the GitHub run and job whose upload-artifact produced it.
    repo_id BLOB REFERENCES repos(id),
    github_run_id INTEGER,
    github_job_id INTEGER,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    -- 0 captured, 1 absent (no paths matched), 2 failed (capture or transfer error). Terminal
    -- states never reopen.
    state_code INTEGER NOT NULL CHECK(state_code IN (0, 1, 2)),
    manifest_version INTEGER,
    entries INTEGER NOT NULL DEFAULT 0 CHECK(entries >= 0),
    bytes INTEGER NOT NULL DEFAULT 0 CHECK(bytes >= 0),
    retain_until_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    -- Migration 70: why a failed artifact is missing, when a controller's refusal made it so.
    failure TEXT
        CHECK(failure IS NULL OR (state_code = 2 AND length(failure) BETWEEN 1 AND 512)),
    -- Migration 68: the class resolved at insert, its bytes times the class weight, and when a
    -- tenant administrator pinned the row.
    class TEXT NOT NULL DEFAULT 'standard' CHECK(length(class) BETWEEN 1 AND 32),
    charged_bytes INTEGER NOT NULL DEFAULT 0 CHECK(charged_bytes >= 0),
    pinned_ms INTEGER,
    -- Only a captured artifact names a manifest, and a job artifact stays unique per attempt.
    CHECK((state_code = 0) = (manifest_version IS NOT NULL)),
    UNIQUE(attempt_id, name),
    -- Every row names exactly one producer and nothing else.
    CHECK(
        (origin_code = 0 AND run_id IS NOT NULL AND job_id IS NOT NULL AND attempt_id IS NOT NULL
             AND uploader_id IS NULL AND repo_id IS NULL
             AND github_run_id IS NULL AND github_job_id IS NULL)
        OR (origin_code = 1 AND run_id IS NOT NULL AND job_id IS NULL AND attempt_id IS NULL
             AND uploader_id IS NOT NULL AND repo_id IS NULL
             AND github_run_id IS NULL AND github_job_id IS NULL)
        OR (origin_code = 2 AND run_id IS NULL AND job_id IS NULL AND attempt_id IS NULL
             AND uploader_id IS NULL AND repo_id IS NOT NULL
             AND github_run_id > 0 AND github_job_id > 0))
) WITHOUT ROWID;

INSERT INTO artifacts_v71(id, tenant_id, origin_code, run_id, job_id, attempt_id, name,
        state_code, manifest_version, entries, bytes, retain_until_ms, created_ms, failure, class,
        charged_bytes, pinned_ms)
    SELECT id, tenant_id, 0, run_id, job_id, attempt_id, name, state_code, manifest_version,
        entries, bytes, retain_until_ms, created_ms, failure, class, charged_bytes, pinned_ms
    FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v71 RENAME TO artifacts;

CREATE INDEX artifacts_by_run ON artifacts(tenant_id, run_id);
CREATE INDEX artifacts_retention ON artifacts(retain_until_ms);
CREATE INDEX artifacts_reapply ON artifacts(tenant_id, id);
CREATE INDEX artifacts_class_reapply ON artifacts(class, id);
-- One run-level artifact per run and name, and one runner-mode artifact per GitHub job and name.
CREATE UNIQUE INDEX artifacts_run_upload ON artifacts(run_id, name) WHERE origin_code = 1;
CREATE UNIQUE INDEX artifacts_runner ON artifacts(tenant_id, repo_id, github_run_id, github_job_id, name)
    WHERE origin_code = 2;

-- Ownership is joined, never asserted: a job artifact's attempt must belong to the job and the
-- job to the run, a run-level artifact's run to the tenant, and a runner-mode artifact's
-- repository to the tenant.
CREATE TRIGGER artifacts_owner BEFORE INSERT ON artifacts BEGIN
    SELECT RAISE(ABORT,'artifact ownership') WHERE
        (NEW.origin_code = 0 AND NOT EXISTS(
            SELECT 1 FROM attempts a
            JOIN jobs j ON j.id = a.job_id
            JOIN runs r ON r.id = j.run_id
            WHERE a.id = NEW.attempt_id AND a.job_id = NEW.job_id
              AND j.run_id = NEW.run_id AND a.tenant_id = NEW.tenant_id
              AND j.tenant_id = NEW.tenant_id AND r.tenant_id = NEW.tenant_id))
     OR (NEW.origin_code = 1 AND NOT EXISTS(
            SELECT 1 FROM runs r WHERE r.id = NEW.run_id AND r.tenant_id = NEW.tenant_id))
     OR (NEW.origin_code = 2 AND NOT EXISTS(
            SELECT 1 FROM repos p WHERE p.id = NEW.repo_id AND p.tenant_id = NEW.tenant_id));
END;

-- Every row names a class the deployment defines, whatever code path inserts it.
CREATE TRIGGER artifacts_class_known BEFORE INSERT ON artifacts
    WHEN NOT EXISTS(SELECT 1 FROM artifact_classes WHERE name = NEW.class) BEGIN
    SELECT RAISE(ABORT, 'artifact class');
END;

-- The repository quota counts an artifact's weight, and a re-application that reweighs a row
-- adjusts the same total by the difference. A runner-mode artifact carries its repository
-- itself; a job or run-level one names its run, whose repository is read by primary key.
CREATE TRIGGER repo_usage_artifact_ins AFTER INSERT ON artifacts
    WHEN NEW.charged_bytes > 0 BEGIN
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, COALESCE(NEW.repo_id, (SELECT repo_id FROM runs WHERE id = NEW.run_id));
    UPDATE repo_usage SET artifact_bytes = artifact_bytes + NEW.charged_bytes
        WHERE tenant_id = NEW.tenant_id
          AND repo_id = COALESCE(NEW.repo_id, (SELECT repo_id FROM runs WHERE id = NEW.run_id));
END;
CREATE TRIGGER repo_usage_artifact_del AFTER DELETE ON artifacts
    WHEN OLD.charged_bytes > 0 BEGIN
    UPDATE repo_usage SET artifact_bytes = artifact_bytes - OLD.charged_bytes
        WHERE tenant_id = OLD.tenant_id
          AND repo_id = COALESCE(OLD.repo_id, (SELECT repo_id FROM runs WHERE id = OLD.run_id));
END;
CREATE TRIGGER repo_usage_artifact_reweigh AFTER UPDATE OF charged_bytes ON artifacts
    WHEN NEW.charged_bytes != OLD.charged_bytes BEGIN
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, COALESCE(NEW.repo_id, (SELECT repo_id FROM runs WHERE id = NEW.run_id));
    UPDATE repo_usage SET artifact_bytes = artifact_bytes + (NEW.charged_bytes - OLD.charged_bytes)
        WHERE tenant_id = NEW.tenant_id
          AND repo_id = COALESCE(NEW.repo_id, (SELECT repo_id FROM runs WHERE id = NEW.run_id));
END;

-- The insert trigger keeps narrowing a new row: the smaller of the effective artifact retention
-- its repository inherits and its class's maximum age, whatever path inserts the row.
CREATE TRIGGER artifacts_retention_cap AFTER INSERT ON artifacts BEGIN
    UPDATE artifacts SET retain_until_ms = MIN(retain_until_ms, COALESCE(created_ms + MIN(
        COALESCE((SELECT MIN(COALESCE(rp.artifact_retention_ms, tp.ms), tp.ms) FROM
            (SELECT COALESCE(
                (SELECT artifact_retention_ms FROM storage_policies
                 WHERE tenant_id = NEW.tenant_id AND repo_id = X''),
                (SELECT artifact_retention_ms FROM storage_defaults WHERE id = 1)) AS ms) tp
            LEFT JOIN storage_policies rp ON rp.tenant_id = NEW.tenant_id
                AND rp.repo_id = COALESCE(NEW.repo_id,
                    (SELECT repo_id FROM runs WHERE id = NEW.run_id))),
            9223372036854775807),
        (SELECT max_age_ms FROM artifact_classes WHERE name = NEW.class)),
        retain_until_ms))
    WHERE id = NEW.id;
END;

-- MCP client scopes: `artifacts:read` (bit 3, from migration 30) joins the set a registered MCP
-- client may be capped at, so the mask becomes 71 | 8 = 79. `artifacts:write` (bit 10) is not added
-- here: every scope column in this schema (`oauth_clients.max_scopes`, and the `scopes` of grants,
-- codes, device codes and refresh tokens) is `CHECK(... BETWEEN 1 AND 1023)`, so a greater bit
-- needs those five tables rebuilt with their triggers, which is its own migration. The triggers are
-- recreated with the wider mask and no other change: the client policy, the enabled-count capacity
-- bound and the refusal of every other scope stay as they were.
DROP TRIGGER oauth_mcp_client_policy;
DROP TRIGGER oauth_mcp_client_policy_update;
CREATE TRIGGER oauth_mcp_client_policy BEFORE INSERT ON oauth_clients
WHEN NEW.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.resource != 2 OR NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        (NEW.max_scopes & ~79) != 0 OR
        (NEW.registration_kind = 1 AND NEW.metadata_url IS NOT NULL) OR
        (NEW.registration_kind = 2 AND NEW.metadata_url IS NULL);
    SELECT RAISE(ABORT, 'MCP OAuth client capacity reached') WHERE
        (SELECT count(*) FROM oauth_clients
         WHERE registration_kind != 0 AND disabled_ms IS NULL) >= 512;
END;
CREATE TRIGGER oauth_mcp_client_policy_update BEFORE UPDATE ON oauth_clients
WHEN OLD.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.client_id != OLD.client_id OR NEW.resource != 2 OR
        NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        NEW.registration_kind != OLD.registration_kind OR
        NEW.metadata_url IS NOT OLD.metadata_url OR
        (NEW.max_scopes & ~79) != 0;
END;
