-- Storage policy per tenant and repository, log accounting and database-
-- driven log expiry (R01).

-- One policy row per tenant (repo_id = X'') or repository. A NULL column
-- inherits: a repository from its tenant, a tenant from the deployment's
-- configuration. The repository row can only narrow its tenant's retention
-- (the effective value is the smaller), and its quota is a separate cap
-- inside the tenant's.
CREATE TABLE storage_policies(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB NOT NULL DEFAULT X'',
    quota_bytes INTEGER CHECK(quota_bytes IS NULL OR quota_bytes > 0),
    log_retention_ms INTEGER CHECK(log_retention_ms IS NULL OR log_retention_ms > 0),
    artifact_retention_ms INTEGER
        CHECK(artifact_retention_ms IS NULL OR artifact_retention_ms > 0),
    updated_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, repo_id)
) WITHOUT ROWID;
CREATE TRIGGER storage_policies_owner BEFORE INSERT ON storage_policies
    WHEN NEW.repo_id != X'' BEGIN
    SELECT RAISE(ABORT,'storage policy ownership') WHERE NOT EXISTS(
        SELECT 1 FROM repos WHERE id = NEW.repo_id AND tenant_id = NEW.tenant_id);
END;
CREATE TRIGGER storage_policies_identity BEFORE UPDATE ON storage_policies BEGIN
    SELECT RAISE(ABORT,'storage policy identity') WHERE
        NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id;
END;
INSERT INTO storage_policies(tenant_id, quota_bytes, updated_ms)
    SELECT tenant_id, quota_bytes, CAST(unixepoch('subsec') * 1000 AS INTEGER)
    FROM tenant_quotas;
DROP TABLE tenant_quotas;

-- The deployment's storage limits, written from configuration at every
-- controller start (`retention::install`), so triggers can apply the
-- effective policy without the caller passing it and host-local tools see
-- what the controller runs with. No row: no cap.
CREATE TABLE storage_defaults(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    quota_bytes INTEGER NOT NULL CHECK(quota_bytes >= 0),
    tenant_quota_bytes INTEGER NOT NULL CHECK(tenant_quota_bytes >= 0),
    log_retention_ms INTEGER NOT NULL CHECK(log_retention_ms > 0),
    artifact_retention_ms INTEGER NOT NULL CHECK(artifact_retention_ms > 0),
    run_artifact_bytes INTEGER NOT NULL CHECK(run_artifact_bytes > 0),
    installed_ms INTEGER NOT NULL
);

-- A pipeline's `retain` is shortened to the repository's effective artifact
-- retention whatever path inserts the row: the smaller of the repository's
-- own value and the tenant's (its policy, else the deployment default).
CREATE TRIGGER artifacts_retention_cap AFTER INSERT ON artifacts BEGIN
    UPDATE artifacts SET retain_until_ms = MIN(retain_until_ms, COALESCE(created_ms + (
        SELECT MIN(COALESCE(rp.artifact_retention_ms, tp.ms), tp.ms) FROM
            (SELECT COALESCE(
                (SELECT artifact_retention_ms FROM storage_policies
                 WHERE tenant_id = NEW.tenant_id AND repo_id = X''),
                (SELECT artifact_retention_ms FROM storage_defaults WHERE id = 1)) AS ms) tp
            LEFT JOIN storage_policies rp ON rp.tenant_id = NEW.tenant_id
                AND rp.repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id)),
        retain_until_ms))
    WHERE id = NEW.id;
END;

-- Log bytes now count toward a tenant's usage beside its object bytes.
ALTER TABLE tenant_usage ADD COLUMN log_bytes INTEGER NOT NULL DEFAULT 0;

-- What each repository holds: the logical bytes of its captured artifacts
-- (before the tenant-wide deduplication, which is the tenant's saving, not
-- the repository's) and of its attempt logs.
CREATE TABLE repo_usage(
    tenant_id BLOB NOT NULL,
    repo_id BLOB NOT NULL,
    artifact_bytes INTEGER NOT NULL DEFAULT 0,
    log_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(tenant_id, repo_id)
) WITHOUT ROWID;
INSERT INTO repo_usage(tenant_id, repo_id, artifact_bytes)
    SELECT a.tenant_id, r.repo_id, SUM(a.bytes)
    FROM artifacts a JOIN runs r ON r.id = a.run_id
    GROUP BY a.tenant_id, r.repo_id;
CREATE TRIGGER repo_usage_artifact_ins AFTER INSERT ON artifacts
    WHEN NEW.bytes > 0 BEGIN
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, repo_id FROM runs WHERE id = NEW.run_id;
    UPDATE repo_usage SET artifact_bytes = artifact_bytes + NEW.bytes
        WHERE tenant_id = NEW.tenant_id
          AND repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id);
END;
CREATE TRIGGER repo_usage_artifact_del AFTER DELETE ON artifacts
    WHEN OLD.bytes > 0 BEGIN
    UPDATE repo_usage SET artifact_bytes = artifact_bytes - OLD.bytes
        WHERE tenant_id = OLD.tenant_id
          AND repo_id = (SELECT repo_id FROM runs WHERE id = OLD.run_id);
END;

-- An attempt's log: its stored bytes and its expiry deadline are stamped by
-- the controller's maintenance pass once the attempt is released (NULL until
-- then); `log_expired_ms` records when retention removed the log. Expiry is
-- a separate column rather than a fourth `log_state` so the state's CHECK and
-- ordering stay as migration 26 defined them.
ALTER TABLE attempts ADD COLUMN log_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attempts ADD COLUMN log_expires_ms INTEGER;
ALTER TABLE attempts ADD COLUMN log_expired_ms INTEGER;
CREATE INDEX attempts_log_unstamped ON attempts(released_ms)
    WHERE released_ms IS NOT NULL AND log_expires_ms IS NULL;
CREATE INDEX attempts_log_expiry ON attempts(log_expires_ms)
    WHERE log_expires_ms IS NOT NULL AND log_expired_ms IS NULL;
CREATE TRIGGER usage_log_bytes AFTER UPDATE OF log_bytes ON attempts
    WHEN NEW.log_bytes != OLD.log_bytes BEGIN
    INSERT OR IGNORE INTO tenant_usage(tenant_id) VALUES(NEW.tenant_id);
    UPDATE tenant_usage SET log_bytes = log_bytes + (NEW.log_bytes - OLD.log_bytes)
        WHERE tenant_id = NEW.tenant_id;
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, NEW.repo_id WHERE NEW.repo_id IS NOT NULL;
    UPDATE repo_usage SET log_bytes = log_bytes + (NEW.log_bytes - OLD.log_bytes)
        WHERE tenant_id = NEW.tenant_id AND repo_id = NEW.repo_id;
END;
-- An expired log never comes back.
DROP TRIGGER attempt_update;
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.job_id != OLD.job_id OR NEW.fence != OLD.fence OR
        NEW.worker_id != OLD.worker_id OR NEW.cpu_millis != OLD.cpu_millis OR
        NEW.memory_bytes != OLD.memory_bytes OR NEW.disk_bytes != OLD.disk_bytes OR
        NEW.offered_ms != OLD.offered_ms OR
        (OLD.acked_ms IS NOT NULL AND NEW.acked_ms IS NOT OLD.acked_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.lease_until_ms != OLD.lease_until_ms) OR
        (OLD.summary IS NOT NULL AND NEW.summary IS NOT OLD.summary) OR
        NEW.log_state < OLD.log_state OR
        (OLD.log_expired_ms IS NOT NULL AND NEW.log_expired_ms IS NOT OLD.log_expired_ms);
END;

-- Aborted upload sessions are kept a while for explanation, then purged.
-- Committed ones stay: they authorize reads of the object they produced.
CREATE INDEX uploads_aborted ON uploads(expires_ms) WHERE state_code = 2;
