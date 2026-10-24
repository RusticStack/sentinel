-- Storage hardening (Part 06 audit): reclamation walks candidates, not the
-- whole object table, and object downloads authorize through the
-- repositories whose artifacts reference the bytes.

-- Objects no manifest references, kept by triggers: a new object enters
-- (its references are written after it, in the same transaction), the
-- first edge to it removes it, and the last edge leaving puts it back.
-- `created_ms` is the object's own, so the reclaim grace is unchanged.
CREATE TABLE object_unreferenced(
    tenant_id BLOB NOT NULL,
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, digest),
    FOREIGN KEY(tenant_id, digest) REFERENCES objects(tenant_id, digest)
        ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX object_unreferenced_age ON object_unreferenced(created_ms);
INSERT INTO object_unreferenced(tenant_id, digest, created_ms)
    SELECT o.tenant_id, o.digest, o.created_ms FROM objects o
    WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r
                     WHERE r.tenant_id = o.tenant_id AND r.digest = o.digest);
CREATE TRIGGER object_unreferenced_new AFTER INSERT ON objects BEGIN
    INSERT OR IGNORE INTO object_unreferenced(tenant_id, digest, created_ms)
    SELECT NEW.tenant_id, NEW.digest, NEW.created_ms
    WHERE NOT EXISTS(SELECT 1 FROM manifest_refs r
                     WHERE r.tenant_id = NEW.tenant_id AND r.digest = NEW.digest);
END;
CREATE TRIGGER object_unreferenced_ref AFTER INSERT ON manifest_refs BEGIN
    DELETE FROM object_unreferenced
    WHERE tenant_id = NEW.tenant_id AND digest = NEW.digest;
END;
-- Fires for a retired manifest's cascaded edges too.
CREATE TRIGGER object_unreferenced_unref AFTER DELETE ON manifest_refs BEGIN
    INSERT OR IGNORE INTO object_unreferenced(tenant_id, digest, created_ms)
    SELECT o.tenant_id, o.digest, o.created_ms FROM objects o
    WHERE o.tenant_id = OLD.tenant_id AND o.digest = OLD.digest
      AND NOT EXISTS(SELECT 1 FROM manifest_refs r
                     WHERE r.tenant_id = OLD.tenant_id AND r.digest = OLD.digest);
END;

-- The per-tenant "any unindexed manifest" probe reclamation and the
-- backfill make: only pre-D06 rows are ever in it.
CREATE INDEX manifests_unindexed ON manifests(tenant_id) WHERE refs_indexed = 0;

-- Download authorization for objects committed through a resumable upload
-- rather than an artifact.
CREATE INDEX uploads_object ON uploads(tenant_id, object_digest) WHERE state_code = 1;
