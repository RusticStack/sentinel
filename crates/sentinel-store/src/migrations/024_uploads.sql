-- Resumable object uploads (D02). A row is the durable half of a staging
-- file under incoming/<id>: it records the declared length and digest, the
-- received byte ranges (LE u64 pairs) and the expiry. Ranges are written
-- after the bytes, so a crash can never mark unwritten bytes received.
-- Sealing renames the staging file into objects/ and commits the object
-- row in the same transaction — replay-safe and never dangling.
CREATE TABLE uploads(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    declared_len INTEGER NOT NULL CHECK(declared_len >= 0),
    digest BLOB CHECK(digest IS NULL OR length(digest) = 32),
    -- 0 open, 1 committed, 2 aborted; terminal states never reopen.
    state_code INTEGER NOT NULL DEFAULT 0 CHECK(state_code IN (0, 1, 2)),
    ranges BLOB NOT NULL,
    received INTEGER NOT NULL DEFAULT 0 CHECK(received >= 0),
    object_digest BLOB CHECK(object_digest IS NULL OR length(object_digest) = 32),
    expires_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX uploads_expiry ON uploads(expires_ms) WHERE state_code = 0;
CREATE TRIGGER uploads_immutable BEFORE UPDATE ON uploads BEGIN
    SELECT RAISE(ABORT,'upload identity is immutable') WHERE
        NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id;
END;
