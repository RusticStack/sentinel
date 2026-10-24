-- Tenant-scoped immutable objects and versioned manifests (D01).
-- An objects row is the reference commit: the staged file under
-- objects/<tenant>/<prefix>/<digest> becomes reachable only when this
-- insert commits, so a crash can leave an orphan but never a published
-- incomplete object. Content is addressed by its BLAKE3-256 digest and
-- deduplicated within the tenant only — namespaces never cross tenants.
CREATE TABLE objects(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    len INTEGER NOT NULL CHECK(len >= 0),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, digest)
) WITHOUT ROWID;
-- Content-addressed rows are append-only: the same (tenant, digest) is the
-- same bytes, so an update could only corrupt. Reclamation is a separate
-- stage (D06+); until then nothing deletes a reference.
CREATE TRIGGER objects_immutable_update BEFORE UPDATE ON objects BEGIN
    SELECT RAISE(ABORT,'objects are immutable');
END;
CREATE TRIGGER objects_immutable_delete BEFORE DELETE ON objects BEGIN
    SELECT RAISE(ABORT,'objects are immutable');
END;
-- A manifest is a named, monotonically versioned list of object references
-- (one file per version under manifests/). `digest` is the manifest file's
-- own BLAKE3-256; `payload_len` sums the referenced objects' lengths for
-- quota and retention accounting without reading the file.
CREATE TABLE manifests(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    kind INTEGER NOT NULL,
    name BLOB NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    version INTEGER NOT NULL CHECK(version > 0),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    entries INTEGER NOT NULL CHECK(entries >= 0),
    payload_len INTEGER NOT NULL CHECK(payload_len >= 0),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, kind, name, version)
) WITHOUT ROWID;
-- The head of a (tenant, kind, name): highest version first.
CREATE INDEX manifest_heads ON manifests(tenant_id, kind, name, version DESC);
CREATE TRIGGER manifests_immutable_update BEFORE UPDATE ON manifests BEGIN
    SELECT RAISE(ABORT,'manifests are immutable');
END;
CREATE TRIGGER manifests_immutable_delete BEFORE DELETE ON manifests BEGIN
    SELECT RAISE(ABORT,'manifests are immutable');
END;
