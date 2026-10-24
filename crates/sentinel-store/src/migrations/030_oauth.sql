-- OAuth 2.0 authorization server (Part 09, O01-O06). Every token is a 256-bit
-- opaque secret stored only as its BLAKE3 digest, exactly like sessions and
-- API credentials: validation is a primary-key probe and a snapshot of this
-- database yields nothing presentable. A grant is one refresh-token family
-- (browser or device login) or one service-account grant; its terms are fixed
-- at issuance and only use and revocation may move afterwards.

-- Registered clients. Public clients only: no client secrets exist. The
-- first-party CLI is seeded; a loopback client may redirect to
-- http://127.0.0.1:PORT<redirect_path> or http://[::1]:PORT<redirect_path>,
-- every other redirect must be listed exactly in oauth_client_redirects.
CREATE TABLE oauth_clients(
    client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 64),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    first_party INTEGER NOT NULL CHECK(first_party IN (0, 1)),
    loopback INTEGER NOT NULL CHECK(loopback IN (0, 1)),
    redirect_path TEXT CHECK(redirect_path IS NULL OR length(redirect_path) BETWEEN 1 AND 128),
    device INTEGER NOT NULL CHECK(device IN (0, 1)),
    max_scopes INTEGER NOT NULL CHECK(max_scopes BETWEEN 1 AND 1023),
    created_ms INTEGER NOT NULL,
    disabled_ms INTEGER,
    CHECK(loopback = 0 OR redirect_path IS NOT NULL)
) WITHOUT ROWID;
INSERT INTO oauth_clients(client_id, name, first_party, loopback, redirect_path, device,
    max_scopes, created_ms, disabled_ms)
    VALUES ('sentinel-cli', 'Sentinel CLI', 1, 1, '/callback', 1, 1023, 0, NULL);

CREATE TABLE oauth_client_redirects(
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    uri TEXT NOT NULL CHECK(length(uri) BETWEEN 1 AND 512),
    PRIMARY KEY(client_id, uri)
) WITHOUT ROWID;

-- One grant: kind 1 authorization code, 2 device, 3 service. Scopes are the
-- stored bits of sentinel_core::auth::Scopes; audience 1 is the API (2 is
-- reserved for MCP). Absolute expiry is mandatory and at most 90 days.
-- revoked_reason: 1 logout/revoke endpoint, 2 refresh replay, 3 code replay,
-- 4 account suspended/rejected/password reset, 5 membership removed,
-- 6 tenant suspended, 7 revoked by an owner or administrator.
CREATE TABLE oauth_grants(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    user_id BLOB NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    kind INTEGER NOT NULL CHECK(kind IN (1, 2, 3)),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 1023),
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
    CHECK((revoked_ms IS NULL) = (revoked_reason IS NULL)),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
CREATE INDEX oauth_grants_by_user ON oauth_grants(user_id, created_ms);
CREATE INDEX oauth_grants_by_tenant ON oauth_grants(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX oauth_grants_by_expiry ON oauth_grants(expires_ms);
CREATE INDEX oauth_grants_revoked ON oauth_grants(revoked_ms) WHERE revoked_ms IS NOT NULL;

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

-- Only use and revocation move; revocation is final.
CREATE TRIGGER oauth_grant_update BEFORE UPDATE ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grant terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.user_id != OLD.user_id OR NEW.client_id != OLD.client_id OR
        NEW.kind != OLD.kind OR NEW.scopes != OLD.scopes OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.repo_id IS NOT OLD.repo_id OR
        NEW.audience != OLD.audience OR NEW.name IS NOT OLD.name OR
        NEW.created_by IS NOT OLD.created_by OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'grant revocation is final') WHERE OLD.revoked_ms IS NOT NULL AND
        (NEW.revoked_ms IS NOT OLD.revoked_ms OR NEW.revoked_reason IS NOT OLD.revoked_reason);
END;

-- Authorization codes: single use, 60 seconds, bound to the client, the
-- exact redirect URI and the PKCE S256 challenge.
CREATE TABLE oauth_codes(
    code_digest BLOB PRIMARY KEY NOT NULL CHECK(length(code_digest) = 32),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 512),
    code_challenge TEXT NOT NULL CHECK(length(code_challenge) = 43),
    user_id BLOB NOT NULL REFERENCES users(id),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 1023),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    audience INTEGER NOT NULL CHECK(audience IN (1)),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    consumed_ms INTEGER,
    grant_id BLOB REFERENCES oauth_grants(id),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
CREATE INDEX oauth_codes_by_expiry ON oauth_codes(expires_ms);
CREATE INDEX oauth_codes_by_grant ON oauth_codes(grant_id) WHERE grant_id IS NOT NULL;

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
        NEW.audience != OLD.audience OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'code consumption is one-way') WHERE
        OLD.consumed_ms IS NOT NULL AND NEW.consumed_ms IS NOT OLD.consumed_ms;
    SELECT RAISE(ABORT, 'code grant is set once') WHERE
        OLD.grant_id IS NOT NULL AND NEW.grant_id IS NOT OLD.grant_id;
END;

-- Device authorization requests (RFC 8628). status: 0 pending, 1 approved,
-- 2 denied, 3 redeemed. The approver may narrow the requested scopes once,
-- at approval; every decision term is written once.
CREATE TABLE oauth_device_codes(
    device_digest BLOB PRIMARY KEY NOT NULL CHECK(length(device_digest) = 32),
    user_code TEXT NOT NULL UNIQUE
        CHECK(length(user_code) = 8 AND user_code NOT GLOB '*[^BCDFGHJKLMNPQRSTVWXZ]*'),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 1023),
    audience INTEGER NOT NULL CHECK(audience IN (1)),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    status INTEGER NOT NULL DEFAULT 0 CHECK(status IN (0, 1, 2, 3)),
    user_id BLOB REFERENCES users(id),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    decided_ms INTEGER,
    grant_id BLOB REFERENCES oauth_grants(id),
    CHECK(repo_id IS NULL OR tenant_id IS NOT NULL)
) WITHOUT ROWID;
CREATE INDEX oauth_device_by_expiry ON oauth_device_codes(expires_ms);
-- The pending-request cap counts only unexpired pending rows.
CREATE INDEX oauth_device_pending ON oauth_device_codes(expires_ms) WHERE status = 0;
CREATE INDEX oauth_device_by_grant ON oauth_device_codes(grant_id) WHERE grant_id IS NOT NULL;

CREATE TRIGGER oauth_device_insert BEFORE INSERT ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device requests are issued pending') WHERE NEW.status != 0 OR
        NEW.user_id IS NOT NULL OR NEW.tenant_id IS NOT NULL OR NEW.repo_id IS NOT NULL OR
        NEW.decided_ms IS NOT NULL OR NEW.grant_id IS NOT NULL;
END;
CREATE TRIGGER oauth_device_update BEFORE UPDATE ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device request terms are immutable') WHERE
        NEW.device_digest != OLD.device_digest OR NEW.user_code != OLD.user_code OR
        NEW.client_id != OLD.client_id OR NEW.audience != OLD.audience OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms;
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

-- Refresh tokens: one row per generation of a grant's family. Presenting a
-- live row rotates it; a rotated row is kept so a replay is recognized (and
-- revokes the grant) instead of looking unknown. `superseded` marks a child
-- abandoned by lost-response recovery.
CREATE TABLE oauth_refresh_tokens(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    grant_id BLOB NOT NULL REFERENCES oauth_grants(id),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    parent INTEGER CHECK(parent IS NULL OR parent < generation),
    created_ms INTEGER NOT NULL,
    idle_expires_ms INTEGER NOT NULL CHECK(idle_expires_ms > created_ms),
    rotated_ms INTEGER,
    superseded INTEGER NOT NULL DEFAULT 0 CHECK(superseded IN (0, 1)),
    UNIQUE(grant_id, generation)
) WITHOUT ROWID;
CREATE INDEX oauth_refresh_by_parent ON oauth_refresh_tokens(grant_id, parent);
CREATE INDEX oauth_refresh_by_expiry ON oauth_refresh_tokens(idle_expires_ms);
CREATE INDEX oauth_refresh_rotated ON oauth_refresh_tokens(rotated_ms) WHERE rotated_ms IS NOT NULL;

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

-- Access tokens: ten minutes, never wider than their grant, never changed.
CREATE TABLE oauth_access_tokens(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    grant_id BLOB NOT NULL REFERENCES oauth_grants(id),
    generation INTEGER NOT NULL,
    scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 1023),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms)
) WITHOUT ROWID;
CREATE INDEX oauth_access_by_grant ON oauth_access_tokens(grant_id);
CREATE INDEX oauth_access_by_expiry ON oauth_access_tokens(expires_ms);

CREATE TRIGGER oauth_access_insert BEFORE INSERT ON oauth_access_tokens BEGIN
    SELECT RAISE(ABORT, 'access scope exceeds its grant') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_grants WHERE id = NEW.grant_id AND (NEW.scopes & ~scopes) = 0);
END;
CREATE TRIGGER oauth_access_update BEFORE UPDATE ON oauth_access_tokens BEGIN
    SELECT RAISE(ABORT, 'access tokens are immutable');
END;
