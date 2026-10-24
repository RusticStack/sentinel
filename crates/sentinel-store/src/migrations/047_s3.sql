-- The optional external S3 copy of objects and logs (R02/R03). The local
-- disk stays the write path: a committed object or a finished log is
-- replicated afterwards, and a replicated object's local copy may later be
-- evicted and fetched back on read. Metadata never leaves this database.

-- When an object's S3 copy was verified, and when its local file was
-- evicted (NULL while local). Both columns are the only ones an update may
-- touch; `remote_ms` is written once.
ALTER TABLE objects ADD COLUMN remote_ms INTEGER;
ALTER TABLE objects ADD COLUMN evicted_ms INTEGER;
DROP TRIGGER objects_immutable_update;
CREATE TRIGGER objects_immutable_update BEFORE UPDATE ON objects BEGIN
    SELECT RAISE(ABORT,'objects are immutable') WHERE
        NEW.tenant_id != OLD.tenant_id OR NEW.digest != OLD.digest OR
        NEW.len != OLD.len OR NEW.created_ms != OLD.created_ms OR
        (OLD.remote_ms IS NOT NULL AND NEW.remote_ms IS NOT OLD.remote_ms) OR
        (NEW.evicted_ms IS NOT NULL AND NEW.remote_ms IS NULL);
END;
-- The replication queue, oldest first, and the eviction candidates.
CREATE INDEX objects_unreplicated ON objects(created_ms) WHERE remote_ms IS NULL;
CREATE INDEX objects_evictable ON objects(created_ms)
    WHERE remote_ms IS NOT NULL AND evicted_ms IS NULL;

-- Running totals, so neither the backlog nor the local footprint needs a
-- scan: bytes held on the local disk, and bytes not yet in S3.
CREATE TABLE object_totals(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    local_bytes INTEGER NOT NULL DEFAULT 0,
    unreplicated_bytes INTEGER NOT NULL DEFAULT 0
);
INSERT INTO object_totals(id, local_bytes, unreplicated_bytes)
    SELECT 1, COALESCE(SUM(len), 0), COALESCE(SUM(len), 0) FROM objects;
CREATE TRIGGER object_totals_ins AFTER INSERT ON objects BEGIN
    UPDATE object_totals SET local_bytes = local_bytes + NEW.len,
        unreplicated_bytes = unreplicated_bytes + NEW.len WHERE id = 1;
END;
CREATE TRIGGER object_totals_del AFTER DELETE ON objects BEGIN
    UPDATE object_totals SET
        local_bytes = local_bytes - CASE WHEN OLD.evicted_ms IS NULL THEN OLD.len ELSE 0 END,
        unreplicated_bytes = unreplicated_bytes - CASE WHEN OLD.remote_ms IS NULL THEN OLD.len ELSE 0 END
    WHERE id = 1;
END;
CREATE TRIGGER object_totals_upd AFTER UPDATE OF remote_ms, evicted_ms ON objects BEGIN
    UPDATE object_totals SET
        local_bytes = local_bytes
            + CASE WHEN OLD.evicted_ms IS NULL AND NEW.evicted_ms IS NOT NULL THEN -NEW.len
                   WHEN OLD.evicted_ms IS NOT NULL AND NEW.evicted_ms IS NULL THEN NEW.len
                   ELSE 0 END,
        unreplicated_bytes = unreplicated_bytes
            - CASE WHEN OLD.remote_ms IS NULL AND NEW.remote_ms IS NOT NULL THEN NEW.len ELSE 0 END
    WHERE id = 1;
END;

-- Multipart uploads under way, so a restart resumes them from the parts the
-- bucket already holds instead of starting over, and cleanup can abort the
-- abandoned ones.
CREATE TABLE s3_uploads(
    key TEXT PRIMARY KEY NOT NULL,
    upload_id TEXT NOT NULL,
    part_bytes INTEGER NOT NULL CHECK(part_bytes > 0),
    created_ms INTEGER NOT NULL
) WITHOUT ROWID;

-- S3 copies to delete: kind 0 an object (tenant, digest), kind 1 a log (every
-- key under its attempt). Queued by trigger whatever path removes the
-- local record; drained by the replicator.
CREATE TABLE s3_deletes(
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL CHECK(kind IN (0, 1)),
    tenant_id BLOB,
    digest BLOB,
    run_id BLOB,
    job_id BLOB,
    attempt_id BLOB,
    queued_ms INTEGER NOT NULL
);
CREATE TRIGGER s3_delete_object AFTER DELETE ON objects
    WHEN OLD.remote_ms IS NOT NULL BEGIN
    INSERT INTO s3_deletes(kind, tenant_id, digest, queued_ms)
        VALUES (0, OLD.tenant_id, OLD.digest, CAST(unixepoch('subsec') * 1000 AS INTEGER));
END;

-- A finished log's S3 copy: written once its files have settled, reset when
-- a late end changes them, deleted with the log.
ALTER TABLE attempts ADD COLUMN log_remote_ms INTEGER;
CREATE INDEX attempts_log_unreplicated ON attempts(released_ms)
    WHERE log_expires_ms IS NOT NULL AND log_expired_ms IS NULL AND log_remote_ms IS NULL;
CREATE TRIGGER s3_log_changed AFTER UPDATE OF log_state ON attempts
    WHEN NEW.log_state != OLD.log_state AND NEW.log_remote_ms IS NOT NULL BEGIN
    UPDATE attempts SET log_remote_ms = NULL WHERE id = NEW.id;
END;
CREATE TRIGGER s3_delete_log AFTER UPDATE OF log_expired_ms ON attempts
    WHEN OLD.log_expired_ms IS NULL AND NEW.log_expired_ms IS NOT NULL
         AND NEW.log_remote_ms IS NOT NULL BEGIN
    INSERT INTO s3_deletes(kind, run_id, job_id, attempt_id, queued_ms)
        SELECT 1, j.run_id, NEW.job_id, NEW.id, NEW.log_expired_ms
        FROM jobs j WHERE j.id = NEW.job_id;
END;
