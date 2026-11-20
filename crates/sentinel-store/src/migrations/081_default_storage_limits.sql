-- The deployment's default per-tenant storage limit, and a personal namespace's own (L01). An unset
-- `tenant_quota_bytes` is no longer unlimited: it is the deployment's sized default, and a personal
-- namespace answers to `personal_quota_bytes` instead. `0` stays the explicit unlimited, which only a
-- platform administrator may state, on one tenant's policy row — so the policy table has to be able to
-- hold it.
--
-- `storage_defaults` is a copy of the controller's `[storage]` configuration, rewritten from it at every
-- start (`retention::install`), so the new default reaches a populated database when the new controller
-- first starts, not here. The column's default is the personal default this binary sizes on a deployment
-- that states none (`retention::DEFAULT_PERSONAL_QUOTA_BYTES`), so a row an older binary inserts without
-- naming the column is still a valid row.
ALTER TABLE storage_defaults ADD COLUMN personal_quota_bytes INTEGER NOT NULL DEFAULT 10737418240
    CHECK(personal_quota_bytes >= 0);

-- A tenant's explicit unlimited is a stored 0, which the policy row's `quota_bytes > 0` refused. SQLite
-- cannot alter a constraint, so the table is rebuilt with the same shape and the one check relaxed, every
-- row carried over as it is. Two things make that safe in place: `legacy_alter_table` stops the rename
-- from rewriting the artifacts triggers that name the table, and the name exists again before the old
-- table is dropped, so no trigger body is left pointing at nothing. The policy table's own two triggers go
-- with the table they are attached to and are recreated at the end.
DROP TRIGGER storage_policies_owner;
DROP TRIGGER storage_policies_identity;
PRAGMA legacy_alter_table=ON;
ALTER TABLE storage_policies RENAME TO storage_policies_previous;
CREATE TABLE storage_policies(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB NOT NULL DEFAULT X'',
    quota_bytes INTEGER CHECK(quota_bytes IS NULL OR quota_bytes >= 0),
    log_retention_ms INTEGER CHECK(log_retention_ms IS NULL OR log_retention_ms > 0),
    artifact_retention_ms INTEGER
        CHECK(artifact_retention_ms IS NULL OR artifact_retention_ms > 0),
    soft_percent INTEGER CHECK(soft_percent IS NULL OR soft_percent BETWEEN 1 AND 100),
    hard_percent INTEGER CHECK(hard_percent IS NULL OR hard_percent BETWEEN 1 AND 100),
    updated_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, repo_id)
) WITHOUT ROWID;
INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, log_retention_ms,
        artifact_retention_ms, soft_percent, hard_percent, updated_ms)
    SELECT tenant_id, repo_id, quota_bytes, log_retention_ms, artifact_retention_ms,
        soft_percent, hard_percent, updated_ms
    FROM storage_policies_previous;
DROP TABLE storage_policies_previous;
PRAGMA legacy_alter_table=OFF;
CREATE TRIGGER storage_policies_owner BEFORE INSERT ON storage_policies
    WHEN NEW.repo_id != X'' BEGIN
    SELECT RAISE(ABORT,'storage policy ownership') WHERE NOT EXISTS(
        SELECT 1 FROM repos WHERE id = NEW.repo_id AND tenant_id = NEW.tenant_id);
END;
CREATE TRIGGER storage_policies_identity BEFORE UPDATE ON storage_policies BEGIN
    SELECT RAISE(ABORT,'storage policy identity') WHERE
        NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id;
END;
