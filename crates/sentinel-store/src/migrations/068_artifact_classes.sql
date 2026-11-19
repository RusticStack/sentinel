-- Artifact retention classes and pins (E01). A class is a deployment-defined
-- retention ceiling with a quota weight:
--   max_age_ms  the longest an artifact of the class is kept, whatever its pipeline's `retain`
--               asks for (the effective artifact retention can shorten it further, never lengthen it)
--   weight      how many times an artifact's logical bytes count against its repository's quota
-- The deployment writes this table from its configuration at every controller start
-- (`retention::install_classes`), so the trigger below applies the current map without the
-- caller passing it. These rows are the defaults a deployment starts with.
CREATE TABLE artifact_classes(
    name TEXT PRIMARY KEY NOT NULL CHECK(length(name) BETWEEN 1 AND 32),
    max_age_ms INTEGER NOT NULL CHECK(max_age_ms > 0),
    weight INTEGER NOT NULL CHECK(weight BETWEEN 1 AND 100)
) WITHOUT ROWID;
INSERT INTO artifact_classes(name, max_age_ms, weight) VALUES
    ('debug',    604800000, 1),
    ('standard', 2592000000, 1),
    ('evidence', 7776000000, 1),
    ('release',  7776000000, 2);

-- The class an artifact declaration that names none takes.
ALTER TABLE storage_defaults ADD COLUMN default_class TEXT NOT NULL DEFAULT 'standard'
    CHECK(length(default_class) BETWEEN 1 AND 32);

-- `class` is resolved at insert (the declaration's, else the deployment's default) and
-- `charged_bytes` is its bytes times the class weight: the figure the repository quota counts.
-- `pinned_ms` is when a tenant administrator pinned the row; a pinned artifact is never swept and
-- keeps its deadline, so unpinning puts that deadline back into effect.
ALTER TABLE artifacts ADD COLUMN class TEXT NOT NULL DEFAULT 'standard'
    CHECK(length(class) BETWEEN 1 AND 32);
ALTER TABLE artifacts ADD COLUMN charged_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(charged_bytes >= 0);
ALTER TABLE artifacts ADD COLUMN pinned_ms INTEGER;
UPDATE artifacts SET charged_bytes = bytes;

-- A class change re-stamps its own rows in bounded batches without reading another class's.
CREATE INDEX artifacts_class_reapply ON artifacts(class, id);

-- Every row names a class the deployment defines, whatever code path inserts it.
CREATE TRIGGER artifacts_class_known BEFORE INSERT ON artifacts
    WHEN NOT EXISTS(SELECT 1 FROM artifact_classes WHERE name = NEW.class) BEGIN
    SELECT RAISE(ABORT, 'artifact class');
END;

-- The repository quota counts an artifact's weight, and a re-application that reweighs a row
-- adjusts the same total by the difference.
DROP TRIGGER repo_usage_artifact_ins;
DROP TRIGGER repo_usage_artifact_del;
CREATE TRIGGER repo_usage_artifact_ins AFTER INSERT ON artifacts
    WHEN NEW.charged_bytes > 0 BEGIN
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, repo_id FROM runs WHERE id = NEW.run_id;
    UPDATE repo_usage SET artifact_bytes = artifact_bytes + NEW.charged_bytes
        WHERE tenant_id = NEW.tenant_id
          AND repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id);
END;
CREATE TRIGGER repo_usage_artifact_del AFTER DELETE ON artifacts
    WHEN OLD.charged_bytes > 0 BEGIN
    UPDATE repo_usage SET artifact_bytes = artifact_bytes - OLD.charged_bytes
        WHERE tenant_id = OLD.tenant_id
          AND repo_id = (SELECT repo_id FROM runs WHERE id = OLD.run_id);
END;
CREATE TRIGGER repo_usage_artifact_reweigh AFTER UPDATE OF charged_bytes ON artifacts
    WHEN NEW.charged_bytes != OLD.charged_bytes BEGIN
    INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
        SELECT NEW.tenant_id, repo_id FROM runs WHERE id = NEW.run_id;
    UPDATE repo_usage SET artifact_bytes = artifact_bytes + (NEW.charged_bytes - OLD.charged_bytes)
        WHERE tenant_id = NEW.tenant_id
          AND repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id);
END;

-- The insert trigger keeps narrowing a new row: the smaller of the effective artifact retention
-- its repository inherits and its class's maximum age, whatever path inserts the row.
DROP TRIGGER artifacts_retention_cap;
CREATE TRIGGER artifacts_retention_cap AFTER INSERT ON artifacts BEGIN
    UPDATE artifacts SET retain_until_ms = MIN(retain_until_ms, COALESCE(created_ms + MIN(
        COALESCE((SELECT MIN(COALESCE(rp.artifact_retention_ms, tp.ms), tp.ms) FROM
            (SELECT COALESCE(
                (SELECT artifact_retention_ms FROM storage_policies
                 WHERE tenant_id = NEW.tenant_id AND repo_id = X''),
                (SELECT artifact_retention_ms FROM storage_defaults WHERE id = 1)) AS ms) tp
            LEFT JOIN storage_policies rp ON rp.tenant_id = NEW.tenant_id
                AND rp.repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id)),
            9223372036854775807),
        (SELECT max_age_ms FROM artifact_classes WHERE name = NEW.class)),
        retain_until_ms))
    WHERE id = NEW.id;
END;
