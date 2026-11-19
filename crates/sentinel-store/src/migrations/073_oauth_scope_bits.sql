-- `artifacts:write` (bit 10, added by migration 72) is a scope a grant can hold (E04). Every
-- stored scope column in this schema was bounded at 1023 by migration 30, one bit below it, so no
-- OAuth client cap, grant, authorization code, device authorization or access token could carry
-- the bit: an OAuth CLI grant could not be issued the authority an `sntl_` credential already has.
-- SQLite cannot alter a CHECK, so these tables are rebuilt with the same rows, columns, indexes,
-- triggers and foreign keys, and only the scope bound changes.
--
-- The bound is now the whole bit set a `Scopes` can be (`0xFFFF_FFFF`, a scope set is never
-- empty). SQLite has no unsigned integers and `Scopes` is a `u32`, so no value above it can ever be
-- a scope set, while any bit the code has not defined is refused on every read by
-- `Scopes::from_bits` and on every request by name. A bound at today's `Scopes::ALL` (2047) would
-- mean rebuilding these seven tables again for bit 11, which is what this migration exists to stop.
--
-- `oauth_client_redirects` and `oauth_refresh_tokens` hold no scope column of their own, but they
-- are rebuild children of `oauth_clients` and `oauth_grants`: with `foreign_keys=ON` the implicit
-- delete of a `DROP TABLE` fails while any row of a child table still names the parent. Each child
-- is therefore copied into a `_v73` table that names the `_v73` parent, the old tables are dropped
-- child first, and renaming the parents back rewrites each child's `REFERENCES` to the final name.
-- No `PRAGMA foreign_keys` or `defer_foreign_keys` toggling is needed, and a failed rebuild rolls
-- back whole with the migration's transaction.
--
-- The first-party CLI was seeded with 1023, which was every scope that existed then; it is copied
-- at 2047 so the shipped CLI can request the same authority through OAuth that it holds with an
-- API credential. A cap an operator narrowed below 1023 is copied as it is.
CREATE TABLE oauth_clients_v73(
    client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 64),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    first_party INTEGER NOT NULL CHECK(first_party IN (0, 1)),
    loopback INTEGER NOT NULL CHECK(loopback IN (0, 1)),
    redirect_path TEXT CHECK(redirect_path IS NULL OR length(redirect_path) BETWEEN 1 AND 128),
    device INTEGER NOT NULL CHECK(device IN (0, 1)),
    max_scopes INTEGER NOT NULL CHECK(max_scopes BETWEEN 1 AND 4294967295),
    created_ms INTEGER NOT NULL,
    disabled_ms INTEGER,
    resource INTEGER NOT NULL DEFAULT 1 CHECK(resource IN (1, 2)),
    registration_kind INTEGER NOT NULL DEFAULT 0 CHECK(registration_kind IN (0, 1, 2)),
    metadata_url TEXT
        CHECK(metadata_url IS NULL OR (length(metadata_url) BETWEEN 1 AND 2048
            AND registration_kind = 2)),
    registrant BLOB CHECK(registrant IS NULL OR length(registrant) = 16),
    CHECK(loopback = 0 OR redirect_path IS NOT NULL)
) WITHOUT ROWID;
INSERT INTO oauth_clients_v73(client_id, name, first_party, loopback, redirect_path, device,
        max_scopes, created_ms, disabled_ms, resource, registration_kind, metadata_url, registrant)
    SELECT client_id, name, first_party, loopback, redirect_path, device,
        CASE WHEN client_id = 'sentinel-cli' AND max_scopes = 1023 THEN 2047 ELSE max_scopes END,
        created_ms, disabled_ms, resource, registration_kind, metadata_url, registrant
    FROM oauth_clients;

CREATE TABLE oauth_client_redirects_v73(
    client_id TEXT NOT NULL REFERENCES oauth_clients_v73(client_id),
    uri TEXT NOT NULL CHECK(length(uri) BETWEEN 1 AND 512),
    PRIMARY KEY(client_id, uri)
) WITHOUT ROWID;
INSERT INTO oauth_client_redirects_v73(client_id, uri)
    SELECT client_id, uri FROM oauth_client_redirects;

CREATE TABLE oauth_grants_v73(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    user_id BLOB NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES oauth_clients_v73(client_id),
    kind INTEGER NOT NULL CHECK(kind IN (1, 2, 3)),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 4294967295),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    audience INTEGER NOT NULL CHECK(audience IN (1)),
    name TEXT CHECK(name IS NULL OR length(name) BETWEEN 1 AND 128),
    created_by BLOB CHECK(created_by IS NULL OR length(created_by) = 16),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
        CHECK(expires_ms > created_ms AND expires_ms <= created_ms + 7776000000),
    last_used_ms INTEGER,
    revoked_ms INTEGER,
    revoked_reason INTEGER CHECK(revoked_reason IS NULL OR revoked_reason BETWEEN 1 AND 7),
    resource INTEGER NOT NULL DEFAULT 1 CHECK(resource IN (1, 2)),
    created_session BLOB CHECK(created_session IS NULL OR length(created_session) = 16),
    CHECK((revoked_ms IS NULL) = (revoked_reason IS NULL)),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
INSERT INTO oauth_grants_v73(id, user_id, client_id, kind, scopes, tenant_id, repo_id, audience,
        name, created_by, created_ms, expires_ms, last_used_ms, revoked_ms, revoked_reason,
        resource, created_session)
    SELECT id, user_id, client_id, kind, scopes, tenant_id, repo_id, audience, name, created_by,
        created_ms, expires_ms, last_used_ms, revoked_ms, revoked_reason, resource, created_session
    FROM oauth_grants;

CREATE TABLE oauth_codes_v73(
    code_digest BLOB PRIMARY KEY NOT NULL CHECK(length(code_digest) = 32),
    client_id TEXT NOT NULL REFERENCES oauth_clients_v73(client_id),
    redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 512),
    code_challenge TEXT NOT NULL CHECK(length(code_challenge) = 43),
    user_id BLOB NOT NULL REFERENCES users(id),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 4294967295),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    audience INTEGER NOT NULL CHECK(audience IN (1)),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    consumed_ms INTEGER,
    grant_id BLOB REFERENCES oauth_grants_v73(id),
    resource INTEGER NOT NULL DEFAULT 1 CHECK(resource IN (1, 2)),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
INSERT INTO oauth_codes_v73(code_digest, client_id, redirect_uri, code_challenge, user_id, scopes,
        tenant_id, repo_id, audience, created_ms, expires_ms, consumed_ms, grant_id, resource)
    SELECT code_digest, client_id, redirect_uri, code_challenge, user_id, scopes, tenant_id,
        repo_id, audience, created_ms, expires_ms, consumed_ms, grant_id, resource
    FROM oauth_codes;

CREATE TABLE oauth_device_codes_v73(
    device_digest BLOB PRIMARY KEY NOT NULL CHECK(length(device_digest) = 32),
    user_code TEXT NOT NULL UNIQUE
        CHECK(length(user_code) = 8 AND user_code NOT GLOB '*[^BCDFGHJKLMNPQRSTVWXZ]*'),
    client_id TEXT NOT NULL REFERENCES oauth_clients_v73(client_id),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 4294967295),
    audience INTEGER NOT NULL CHECK(audience IN (1)),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    status INTEGER NOT NULL DEFAULT 0 CHECK(status IN (0, 1, 2, 3)),
    user_id BLOB REFERENCES users(id),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    decided_ms INTEGER,
    grant_id BLOB REFERENCES oauth_grants_v73(id),
    resource INTEGER NOT NULL DEFAULT 1 CHECK(resource IN (1, 2)),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
INSERT INTO oauth_device_codes_v73(device_digest, user_code, client_id, scopes, audience,
        created_ms, expires_ms, status, user_id, tenant_id, repo_id, decided_ms, grant_id, resource)
    SELECT device_digest, user_code, client_id, scopes, audience, created_ms, expires_ms, status,
        user_id, tenant_id, repo_id, decided_ms, grant_id, resource
    FROM oauth_device_codes;

CREATE TABLE oauth_refresh_tokens_v73(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    grant_id BLOB NOT NULL REFERENCES oauth_grants_v73(id),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    parent INTEGER CHECK(parent IS NULL OR parent < generation),
    created_ms INTEGER NOT NULL,
    idle_expires_ms INTEGER NOT NULL CHECK(idle_expires_ms > created_ms),
    rotated_ms INTEGER,
    superseded INTEGER NOT NULL DEFAULT 0 CHECK(superseded IN (0, 1)),
    UNIQUE(grant_id, generation)
) WITHOUT ROWID;
INSERT INTO oauth_refresh_tokens_v73(token_digest, grant_id, generation, parent, created_ms,
        idle_expires_ms, rotated_ms, superseded)
    SELECT token_digest, grant_id, generation, parent, created_ms, idle_expires_ms, rotated_ms,
        superseded
    FROM oauth_refresh_tokens;

CREATE TABLE oauth_access_tokens_v73(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    grant_id BLOB NOT NULL REFERENCES oauth_grants_v73(id),
    generation INTEGER NOT NULL,
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 4294967295),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms)
) WITHOUT ROWID;
INSERT INTO oauth_access_tokens_v73(token_digest, grant_id, generation, scopes, created_ms,
        expires_ms)
    SELECT token_digest, grant_id, generation, scopes, created_ms, expires_ms
    FROM oauth_access_tokens;

DROP TABLE oauth_access_tokens;
DROP TABLE oauth_refresh_tokens;
DROP TABLE oauth_device_codes;
DROP TABLE oauth_codes;
DROP TABLE oauth_grants;
DROP TABLE oauth_client_redirects;
DROP TABLE oauth_clients;
ALTER TABLE oauth_clients_v73 RENAME TO oauth_clients;
ALTER TABLE oauth_client_redirects_v73 RENAME TO oauth_client_redirects;
ALTER TABLE oauth_grants_v73 RENAME TO oauth_grants;
ALTER TABLE oauth_codes_v73 RENAME TO oauth_codes;
ALTER TABLE oauth_device_codes_v73 RENAME TO oauth_device_codes;
ALTER TABLE oauth_refresh_tokens_v73 RENAME TO oauth_refresh_tokens;
ALTER TABLE oauth_access_tokens_v73 RENAME TO oauth_access_tokens;

CREATE UNIQUE INDEX oauth_client_metadata_url
    ON oauth_clients(metadata_url) WHERE metadata_url IS NOT NULL;
CREATE INDEX oauth_clients_by_registration
    ON oauth_clients(registration_kind, created_ms) WHERE registration_kind != 0;
CREATE INDEX oauth_clients_by_registrant
    ON oauth_clients(registrant) WHERE registrant IS NOT NULL;
CREATE INDEX oauth_grants_by_user ON oauth_grants(user_id, created_ms);
CREATE INDEX oauth_grants_by_tenant ON oauth_grants(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX oauth_grants_by_expiry ON oauth_grants(expires_ms);
CREATE INDEX oauth_grants_revoked ON oauth_grants(revoked_ms) WHERE revoked_ms IS NOT NULL;
CREATE INDEX oauth_grants_by_client ON oauth_grants(client_id);
CREATE INDEX oauth_grants_by_created_session
    ON oauth_grants(created_by, created_session)
    WHERE created_session IS NOT NULL;
CREATE INDEX oauth_grants_by_unattributed_minter
    ON oauth_grants(created_by, created_ms)
    WHERE kind = 3 AND created_session IS NULL AND revoked_ms IS NULL;
CREATE INDEX oauth_codes_by_expiry ON oauth_codes(expires_ms);
CREATE INDEX oauth_codes_by_grant ON oauth_codes(grant_id) WHERE grant_id IS NOT NULL;
CREATE INDEX oauth_codes_by_client ON oauth_codes(client_id);
CREATE INDEX oauth_device_by_expiry ON oauth_device_codes(expires_ms);
CREATE INDEX oauth_device_pending ON oauth_device_codes(expires_ms) WHERE status = 0;
CREATE INDEX oauth_device_by_grant ON oauth_device_codes(grant_id) WHERE grant_id IS NOT NULL;
CREATE INDEX oauth_device_by_client ON oauth_device_codes(client_id);
CREATE INDEX oauth_refresh_by_parent ON oauth_refresh_tokens(grant_id, parent);
CREATE INDEX oauth_refresh_by_expiry ON oauth_refresh_tokens(idle_expires_ms);
CREATE INDEX oauth_refresh_rotated ON oauth_refresh_tokens(rotated_ms) WHERE rotated_ms IS NOT NULL;
CREATE INDEX oauth_access_by_grant ON oauth_access_tokens(grant_id);
CREATE INDEX oauth_access_by_expiry ON oauth_access_tokens(expires_ms);

-- The triggers are recreated verbatim: `platform:admin` (512) and `tenant:admin` (256) are bit
-- values, and the MCP client mask (79) is a narrower set than a scope column's bound.
CREATE TRIGGER oauth_grant_insert BEFORE INSERT ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grants require an active account') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND active = 1);
    SELECT RAISE(ABORT, 'grants are issued live') WHERE
        NEW.revoked_ms IS NOT NULL OR NEW.last_used_ms IS NOT NULL;
    -- platform:admin (512) only for an actual super admin; tenant:admin (256)
    -- never for a service principal.
    SELECT RAISE(ABORT, 'platform scope requires a super admin') WHERE
        NEW.scopes & 512 != 0 AND NOT EXISTS(
            SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND super_admin = 1);
    SELECT RAISE(ABORT, 'service principals cannot administer tenants') WHERE
        NEW.scopes & 256 != 0 AND EXISTS(SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 1);
    SELECT RAISE(ABORT, 'service grants are confined to their home tenant') WHERE EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 1
        AND (NEW.tenant_id IS NULL OR NEW.tenant_id != service_tenant_id));
    SELECT RAISE(ABORT, 'repository scope requires its owning tenant') WHERE
        NEW.repo_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM repos WHERE id = NEW.repo_id AND tenant_id = NEW.tenant_id);
    SELECT RAISE(ABORT, 'client unknown, disabled or narrower than the scope') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
        AND disabled_ms IS NULL AND (NEW.scopes & ~max_scopes) = 0);
END;
CREATE TRIGGER oauth_grant_update BEFORE UPDATE ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grant terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.user_id != OLD.user_id OR NEW.client_id != OLD.client_id OR
        NEW.kind != OLD.kind OR NEW.scopes != OLD.scopes OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.repo_id IS NOT OLD.repo_id OR
        NEW.audience != OLD.audience OR NEW.resource != OLD.resource OR NEW.name IS NOT OLD.name OR
        NEW.created_by IS NOT OLD.created_by OR NEW.created_session IS NOT OLD.created_session OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'grant revocation is final') WHERE OLD.revoked_ms IS NOT NULL AND
        (NEW.revoked_ms IS NOT OLD.revoked_ms OR NEW.revoked_reason IS NOT OLD.revoked_reason);
END;
CREATE TRIGGER oauth_grant_resource BEFORE INSERT ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grant resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;

CREATE TRIGGER oauth_code_insert BEFORE INSERT ON oauth_codes BEGIN
    SELECT RAISE(ABORT, 'codes are issued unconsumed') WHERE
        NEW.consumed_ms IS NOT NULL OR NEW.grant_id IS NOT NULL;
END;
CREATE TRIGGER oauth_code_update BEFORE UPDATE ON oauth_codes BEGIN
    SELECT RAISE(ABORT, 'code terms are immutable') WHERE
        NEW.code_digest != OLD.code_digest OR NEW.client_id != OLD.client_id OR
        NEW.redirect_uri != OLD.redirect_uri OR NEW.code_challenge != OLD.code_challenge OR
        NEW.user_id != OLD.user_id OR NEW.scopes != OLD.scopes OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.repo_id IS NOT OLD.repo_id OR
        NEW.audience != OLD.audience OR NEW.resource != OLD.resource OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'code consumption is one-way') WHERE
        OLD.consumed_ms IS NOT NULL AND NEW.consumed_ms IS NOT OLD.consumed_ms;
    SELECT RAISE(ABORT, 'code grant is set once') WHERE
        OLD.grant_id IS NOT NULL AND NEW.grant_id IS NOT OLD.grant_id;
END;
CREATE TRIGGER oauth_code_resource BEFORE INSERT ON oauth_codes BEGIN
    SELECT RAISE(ABORT, 'code resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;

CREATE TRIGGER oauth_device_insert BEFORE INSERT ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device requests are issued pending') WHERE NEW.status != 0 OR
        NEW.user_id IS NOT NULL OR NEW.tenant_id IS NOT NULL OR NEW.repo_id IS NOT NULL OR
        NEW.decided_ms IS NOT NULL OR NEW.grant_id IS NOT NULL;
END;
CREATE TRIGGER oauth_device_update BEFORE UPDATE ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device request terms are immutable') WHERE
        NEW.device_digest != OLD.device_digest OR NEW.user_code != OLD.user_code OR
        NEW.client_id != OLD.client_id OR NEW.audience != OLD.audience OR
        NEW.resource != OLD.resource OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'device scopes only narrow, at approval') WHERE
        NEW.scopes != OLD.scopes AND NOT (OLD.status = 0 AND NEW.status = 1
        AND (NEW.scopes & ~OLD.scopes) = 0);
    SELECT RAISE(ABORT, 'invalid device status transition') WHERE NEW.status != OLD.status
        AND NOT ((OLD.status = 0 AND NEW.status IN (1, 2)) OR (OLD.status = 1 AND NEW.status = 3));
    SELECT RAISE(ABORT, 'device decision is written once') WHERE OLD.status != 0 AND (
        NEW.user_id IS NOT OLD.user_id OR NEW.tenant_id IS NOT OLD.tenant_id OR
        NEW.repo_id IS NOT OLD.repo_id OR NEW.decided_ms IS NOT OLD.decided_ms);
    SELECT RAISE(ABORT, 'device grant is set once') WHERE
        OLD.grant_id IS NOT NULL AND NEW.grant_id IS NOT OLD.grant_id;
END;
CREATE TRIGGER oauth_device_resource BEFORE INSERT ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;

CREATE TRIGGER oauth_refresh_insert BEFORE INSERT ON oauth_refresh_tokens BEGIN
    SELECT RAISE(ABORT, 'refresh tokens are issued live') WHERE
        NEW.rotated_ms IS NOT NULL OR NEW.superseded != 0;
END;
CREATE TRIGGER oauth_refresh_update BEFORE UPDATE ON oauth_refresh_tokens BEGIN
    SELECT RAISE(ABORT, 'refresh token terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.grant_id != OLD.grant_id OR
        NEW.generation != OLD.generation OR NEW.parent IS NOT OLD.parent OR
        NEW.created_ms != OLD.created_ms OR NEW.idle_expires_ms != OLD.idle_expires_ms;
    SELECT RAISE(ABORT, 'rotation is one-way') WHERE
        (OLD.rotated_ms IS NOT NULL AND NEW.rotated_ms IS NOT OLD.rotated_ms) OR
        (OLD.superseded = 1 AND NEW.superseded = 0);
END;

CREATE TRIGGER oauth_access_insert BEFORE INSERT ON oauth_access_tokens BEGIN
    SELECT RAISE(ABORT, 'access scope exceeds its grant') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_grants WHERE id = NEW.grant_id AND (NEW.scopes & ~scopes) = 0);
END;
CREATE TRIGGER oauth_access_update BEFORE UPDATE ON oauth_access_tokens BEGIN
    SELECT RAISE(ABORT, 'access tokens are immutable');
END;

CREATE TRIGGER oauth_mcp_client_policy BEFORE INSERT ON oauth_clients
WHEN NEW.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.resource != 2 OR NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        (NEW.max_scopes & ~79) != 0 OR
        (NEW.registration_kind = 1 AND NEW.metadata_url IS NOT NULL) OR
        (NEW.registration_kind = 2 AND NEW.metadata_url IS NULL);
    SELECT RAISE(ABORT, 'MCP OAuth client capacity reached') WHERE
        (SELECT count(*) FROM oauth_clients
         WHERE registration_kind != 0 AND disabled_ms IS NULL) >= 512;
END;
CREATE TRIGGER oauth_mcp_client_policy_update BEFORE UPDATE ON oauth_clients
WHEN OLD.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.client_id != OLD.client_id OR NEW.resource != 2 OR
        NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        NEW.registration_kind != OLD.registration_kind OR
        NEW.metadata_url IS NOT OLD.metadata_url OR
        (NEW.max_scopes & ~79) != 0;
END;
