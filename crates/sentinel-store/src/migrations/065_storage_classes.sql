-- Per-class storage accounting (L02). A tenant's stored bytes are split by what holds them:
--   artifacts      objects that at least one manifest references (deduplicated, as the quota counts them)
--   uploads        open upload reservations plus objects no manifest references yet (or any more)
--   logs           stamped attempt log bytes (the existing `log_bytes` column)
--   remote_cache   the controller's remote cache bundles, reported by its reclamation pass
--   actions_cache  runner mode's cache entries on worker hosts (nothing writes it before runner mode lands)
--   worker_cache   the local caches of workers in the tenant's dedicated pools, reported by availability
-- artifact_bytes + upload_bytes always equals `bytes`; the cache classes are reported, never part of it.
-- Columns on the existing row keep a class update on the row the usage triggers already write.
ALTER TABLE tenant_usage ADD COLUMN artifact_bytes INTEGER NOT NULL DEFAULT 0 CHECK(artifact_bytes >= 0);
ALTER TABLE tenant_usage ADD COLUMN upload_bytes INTEGER NOT NULL DEFAULT 0 CHECK(upload_bytes >= 0);
ALTER TABLE tenant_usage ADD COLUMN remote_cache_bytes INTEGER NOT NULL DEFAULT 0 CHECK(remote_cache_bytes >= 0);
ALTER TABLE tenant_usage ADD COLUMN actions_cache_bytes INTEGER NOT NULL DEFAULT 0 CHECK(actions_cache_bytes >= 0);
ALTER TABLE tenant_usage ADD COLUMN worker_cache_bytes INTEGER NOT NULL DEFAULT 0 CHECK(worker_cache_bytes >= 0);

-- Tenants with remote cache bytes, so a report can find the ones that dropped to nothing without reading every tenant.
CREATE INDEX tenant_usage_remote ON tenant_usage(tenant_id) WHERE remote_cache_bytes != 0;
-- The open sessions of a tenant, covering the reservation the recount adds up.
CREATE INDEX uploads_open ON uploads(tenant_id, declared_len) WHERE state_code = 0;

-- Backfill: the same sums the triggers below keep.
INSERT OR IGNORE INTO tenant_usage(tenant_id)
    SELECT p.owner_tenant_id FROM pools p JOIN workers w ON w.pool_id = p.id
    WHERE p.kind = 0 AND w.revoked_ms IS NULL AND w.cache_bytes > 0;
UPDATE tenant_usage SET
    artifact_bytes = COALESCE((SELECT SUM(o.len) FROM objects o
        WHERE o.tenant_id = tenant_usage.tenant_id
          AND EXISTS(SELECT 1 FROM manifest_refs r WHERE r.tenant_id = o.tenant_id AND r.digest = o.digest)), 0),
    upload_bytes = COALESCE((SELECT SUM(o.len) FROM objects o
        WHERE o.tenant_id = tenant_usage.tenant_id
          AND NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.tenant_id = o.tenant_id AND r.digest = o.digest)), 0)
        + COALESCE((SELECT SUM(u.declared_len) FROM uploads u
        WHERE u.tenant_id = tenant_usage.tenant_id AND u.state_code = 0), 0),
    worker_cache_bytes = COALESCE((SELECT SUM(MAX(w.cache_bytes, 0)) FROM pools p
        JOIN workers w ON w.pool_id = p.id AND w.revoked_ms IS NULL
        WHERE p.owner_tenant_id = tenant_usage.tenant_id AND p.kind = 0), 0);

-- An object enters as a reference or as an unreferenced upload, by whether an edge to it exists.
CREATE TRIGGER class_usage_object_ins AFTER INSERT ON objects BEGIN
    INSERT INTO tenant_usage(tenant_id, artifact_bytes, upload_bytes) VALUES(
        NEW.tenant_id,
        CASE WHEN EXISTS(SELECT 1 FROM manifest_refs WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest)
            THEN NEW.len ELSE 0 END,
        CASE WHEN EXISTS(SELECT 1 FROM manifest_refs WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest)
            THEN 0 ELSE NEW.len END)
    ON CONFLICT(tenant_id) DO UPDATE SET
        artifact_bytes = artifact_bytes + excluded.artifact_bytes,
        upload_bytes = upload_bytes + excluded.upload_bytes;
END;
CREATE TRIGGER class_usage_object_del AFTER DELETE ON objects BEGIN
    UPDATE tenant_usage SET
        artifact_bytes = artifact_bytes - CASE WHEN EXISTS(
            SELECT 1 FROM manifest_refs WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest)
            THEN OLD.len ELSE 0 END,
        upload_bytes = upload_bytes - CASE WHEN EXISTS(
            SELECT 1 FROM manifest_refs WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest)
            THEN 0 ELSE OLD.len END
    WHERE tenant_id = OLD.tenant_id;
END;
-- The first edge to an existing object moves its bytes from uploads to artifacts; the last edge leaving moves them back.
CREATE TRIGGER class_usage_ref_ins AFTER INSERT ON manifest_refs
    WHEN NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.tenant_id = NEW.tenant_id AND r.digest = NEW.digest
            AND (r.kind != NEW.kind OR r.name != NEW.name OR r.version != NEW.version))
        AND EXISTS(SELECT 1 FROM objects WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest) BEGIN
    UPDATE tenant_usage SET
        artifact_bytes = artifact_bytes + (SELECT len FROM objects WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest),
        upload_bytes = upload_bytes - (SELECT len FROM objects WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest)
    WHERE tenant_id = NEW.tenant_id;
END;
CREATE TRIGGER class_usage_ref_del AFTER DELETE ON manifest_refs
    WHEN NOT EXISTS(SELECT 1 FROM manifest_refs WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest)
        AND EXISTS(SELECT 1 FROM objects WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest) BEGIN
    UPDATE tenant_usage SET
        artifact_bytes = artifact_bytes - (SELECT len FROM objects WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest),
        upload_bytes = upload_bytes + (SELECT len FROM objects WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest)
    WHERE tenant_id = OLD.tenant_id;
END;
-- An open session reserves its declared length until it seals or aborts, as in `bytes`.
CREATE TRIGGER class_usage_upload_ins AFTER INSERT ON uploads WHEN NEW.state_code = 0 BEGIN
    INSERT INTO tenant_usage(tenant_id, upload_bytes) VALUES(NEW.tenant_id, NEW.declared_len)
    ON CONFLICT(tenant_id) DO UPDATE SET upload_bytes = upload_bytes + NEW.declared_len;
END;
CREATE TRIGGER class_usage_upload_close AFTER UPDATE OF state_code ON uploads
    WHEN OLD.state_code = 0 AND NEW.state_code != 0 BEGIN
    UPDATE tenant_usage SET upload_bytes = upload_bytes - OLD.declared_len WHERE tenant_id = OLD.tenant_id;
END;
-- A worker's reported cache counts for the owner of a dedicated pool while the worker is live; a shared pool has no owner.
CREATE TRIGGER class_usage_worker_cache AFTER UPDATE OF cache_bytes, revoked_ms ON workers
    WHEN (CASE WHEN OLD.revoked_ms IS NULL THEN MAX(OLD.cache_bytes, 0) ELSE 0 END)
        != (CASE WHEN NEW.revoked_ms IS NULL THEN MAX(NEW.cache_bytes, 0) ELSE 0 END)
        AND EXISTS(SELECT 1 FROM pools WHERE id = NEW.pool_id AND kind = 0) BEGIN
    INSERT OR IGNORE INTO tenant_usage(tenant_id)
        SELECT owner_tenant_id FROM pools WHERE id = NEW.pool_id;
    UPDATE tenant_usage SET worker_cache_bytes = worker_cache_bytes
        + (CASE WHEN NEW.revoked_ms IS NULL THEN MAX(NEW.cache_bytes, 0) ELSE 0 END)
        - (CASE WHEN OLD.revoked_ms IS NULL THEN MAX(OLD.cache_bytes, 0) ELSE 0 END)
    WHERE tenant_id = (SELECT owner_tenant_id FROM pools WHERE id = NEW.pool_id);
END;

-- One row per tenant and UTC day, kept by the maintenance pass; the newest 90 stay whatever path inserts.
CREATE TABLE storage_class_snapshots(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    day INTEGER NOT NULL CHECK(day >= 0),
    taken_ms INTEGER NOT NULL,
    artifact_bytes INTEGER NOT NULL CHECK(artifact_bytes >= 0),
    upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
    log_bytes INTEGER NOT NULL CHECK(log_bytes >= 0),
    remote_cache_bytes INTEGER NOT NULL CHECK(remote_cache_bytes >= 0),
    actions_cache_bytes INTEGER NOT NULL CHECK(actions_cache_bytes >= 0),
    worker_cache_bytes INTEGER NOT NULL CHECK(worker_cache_bytes >= 0),
    PRIMARY KEY(tenant_id, day)
) WITHOUT ROWID;
CREATE TRIGGER storage_class_snapshots_bound AFTER INSERT ON storage_class_snapshots BEGIN
    DELETE FROM storage_class_snapshots WHERE tenant_id = NEW.tenant_id AND day <= COALESCE((
        SELECT day FROM storage_class_snapshots WHERE tenant_id = NEW.tenant_id
        ORDER BY day DESC LIMIT 1 OFFSET 90), -1);
END;
