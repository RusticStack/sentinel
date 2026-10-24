-- Disk admission, storage quotas and reclamation hooks (D06).

-- Per-tenant storage quota in committed bytes. No row means the configured
-- default applies; the default 0 means unlimited.
CREATE TABLE tenant_quotas(
    tenant_id BLOB PRIMARY KEY NOT NULL REFERENCES tenants(id),
    quota_bytes INTEGER NOT NULL CHECK(quota_bytes > 0)
) WITHOUT ROWID;

-- Committed bytes owed per tenant, kept by triggers: an objects row adds
-- its length, deleting one subtracts it; an open upload reserves its
-- declared length until it seals or aborts. Staged-but-uncommitted bytes
-- are the admission controller's in-flight charge, not this table's.
CREATE TABLE tenant_usage(
    tenant_id BLOB PRIMARY KEY NOT NULL REFERENCES tenants(id),
    bytes INTEGER NOT NULL DEFAULT 0 CHECK(bytes >= 0)
) WITHOUT ROWID;
INSERT INTO tenant_usage(tenant_id, bytes)
    SELECT tenant_id, SUM(len) FROM objects GROUP BY tenant_id;
INSERT INTO tenant_usage(tenant_id, bytes)
    SELECT tenant_id, SUM(declared_len) FROM uploads WHERE state_code = 0
    GROUP BY tenant_id
    ON CONFLICT(tenant_id) DO UPDATE SET bytes = bytes + excluded.bytes;
CREATE TRIGGER tenant_usage_object_ins AFTER INSERT ON objects BEGIN
    INSERT INTO tenant_usage(tenant_id, bytes) VALUES(NEW.tenant_id, NEW.len)
    ON CONFLICT(tenant_id) DO UPDATE SET bytes = bytes + NEW.len;
END;
CREATE TRIGGER tenant_usage_object_del AFTER DELETE ON objects BEGIN
    UPDATE tenant_usage SET bytes = bytes - OLD.len
    WHERE tenant_id = OLD.tenant_id;
END;
CREATE TRIGGER tenant_usage_upload_ins AFTER INSERT ON uploads
    WHEN NEW.state_code = 0 BEGIN
    INSERT INTO tenant_usage(tenant_id, bytes) VALUES(NEW.tenant_id, NEW.declared_len)
    ON CONFLICT(tenant_id) DO UPDATE SET bytes = bytes + NEW.declared_len;
END;
CREATE TRIGGER tenant_usage_upload_close AFTER UPDATE OF state_code ON uploads
    WHEN OLD.state_code = 0 AND NEW.state_code != 0 BEGIN
    UPDATE tenant_usage SET bytes = bytes - OLD.declared_len
    WHERE tenant_id = OLD.tenant_id;
END;

-- Reclamation is now a real stage, so the unconditional delete guards come
-- off: rows leave only through retire/reclaim, never through an update.
DROP TRIGGER objects_immutable_delete;
DROP TRIGGER manifests_immutable_delete;

-- The object→manifest reference edge, so reclamation can answer "is any
-- manifest still pointing at this object" without reading manifest files.
-- Rows are written with the manifest's commit or backfilled by
-- Objects::index_refs; deleting a manifest cascades its edges.
CREATE TABLE manifest_refs(
    tenant_id BLOB NOT NULL,
    kind INTEGER NOT NULL,
    name BLOB NOT NULL,
    version INTEGER NOT NULL,
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    PRIMARY KEY(tenant_id, kind, name, version, digest),
    FOREIGN KEY(tenant_id, kind, name, version)
        REFERENCES manifests(tenant_id, kind, name, version)
        ON DELETE CASCADE
) WITHOUT ROWID;
-- The inverse direction: every manifest version pointing at an object.
CREATE INDEX manifest_refs_object ON manifest_refs(tenant_id, digest);
-- Manifests committed before this migration have no edges yet;
-- refs_indexed = 0 marks them for the bounded backfill pass and, while any
-- manifest of a tenant is unindexed, reclamation of that tenant's objects
-- is suspended — an unindexed reference must never be collected under it.
ALTER TABLE manifests ADD COLUMN refs_indexed INTEGER NOT NULL DEFAULT 0;
-- The update guard keeps every identity column sealed; only the one-way
-- 0 -> 1 transition of refs_indexed is permitted.
DROP TRIGGER manifests_immutable_update;
CREATE TRIGGER manifests_immutable_update BEFORE UPDATE ON manifests BEGIN
    SELECT RAISE(ABORT,'manifests are immutable') WHERE
        NEW.tenant_id != OLD.tenant_id OR NEW.kind != OLD.kind OR
        NEW.name != OLD.name OR NEW.version != OLD.version OR
        NEW.digest != OLD.digest OR NEW.entries != OLD.entries OR
        NEW.payload_len != OLD.payload_len OR NEW.created_ms != OLD.created_ms
        OR NEW.refs_indexed < OLD.refs_indexed;
END;

-- A lease pins an object for a named holder until `until_ms`: the
-- reader/lease-safe hook reclamation consults before collecting. Holders
-- renew by re-issuing the lease; expiry or the row's delete frees the pin.
CREATE TABLE object_leases(
    tenant_id BLOB NOT NULL,
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    holder TEXT NOT NULL CHECK(length(holder) BETWEEN 1 AND 255),
    until_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, digest, holder),
    FOREIGN KEY(tenant_id, digest) REFERENCES objects(tenant_id, digest)
        ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX object_leases_expiry ON object_leases(until_ms);

-- Expired artifact rows: the retention deadline D03 already recorded is
-- what the sweep consults.
CREATE INDEX artifacts_retention ON artifacts(retain_until_ms);
