-- First-run setup and self-service organizations.
--
-- `setup_token` is the one-time credential of the first-run wizard: at most one
-- row, only its digest, an expiry and a failure count. It carries no authority
-- beyond completing setup once: the latch that closes setup is the existing
-- `bootstrap` row, and the token row is deleted in the transaction that writes
-- it (or by a host-local bootstrap, which closes the same latch).
CREATE TABLE setup_token(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures >= 0),
    locked_until_ms INTEGER NOT NULL DEFAULT 0
);

-- What the wizard decided about the instance itself. One row, written once by
-- the wizard; the controller's configured `public_url` stays what links are
-- built on, so `base_url` here is the operator's statement of intent shown to
-- administrators, never a second source of links.
CREATE TABLE instance_settings(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
    base_url TEXT CHECK(base_url IS NULL OR length(base_url) BETWEEN 1 AND 255),
    updated_ms INTEGER NOT NULL
);

-- Who created an organization through the self-service route, for the
-- per-account quota. NULL for every earlier tenant and for platform-created
-- ones.
ALTER TABLE tenants ADD COLUMN created_by BLOB REFERENCES users(id);
CREATE INDEX tenants_by_creator ON tenants(created_by, created_ms) WHERE created_by IS NOT NULL;
