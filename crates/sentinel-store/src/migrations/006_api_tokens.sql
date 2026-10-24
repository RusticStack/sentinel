-- Scoped, expiring API credentials. Like sessions, the secret is never stored:
-- `token_digest` is BLAKE3 of it, so validation is one primary-key probe and a
-- database snapshot yields nothing presentable. `id` is the public handle used
-- to list and revoke a credential without ever holding its secret.
--
-- Expiry is mandatory: the column is NOT NULL and must be in the future when
-- written. There is no "never expires" representation to opt into by mistake.
CREATE TABLE api_tokens(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    id BLOB NOT NULL UNIQUE CHECK(length(id) = 16),
    user_id BLOB NOT NULL REFERENCES users(id),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    -- Repository bits plus the two administrative bits; never zero, since a
    -- credential that can do nothing is a mistake, not a safe default.
    permissions INTEGER NOT NULL CHECK(permissions BETWEEN 1 AND 31),
    tenant_id BLOB REFERENCES tenants(id),
    repo_id BLOB REFERENCES repos(id),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    last_used_ms INTEGER,
    revoked_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX tokens_by_user ON api_tokens(user_id, created_ms);
CREATE INDEX tokens_by_expiry ON api_tokens(expires_ms);

CREATE TRIGGER token_insert BEFORE INSERT ON api_tokens BEGIN
    SELECT RAISE(ABORT, 'credentials require an active account') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND active = 1);
    -- Platform administration cannot be delegated to an account that does not
    -- hold it, and a service principal can never carry it at all.
    SELECT RAISE(ABORT, 'platform scope requires a super admin') WHERE
        NEW.permissions & 16 != 0 AND NOT EXISTS(
            SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND super_admin = 1);
    -- A service principal's credential is confined to its own home tenant.
    SELECT RAISE(ABORT, 'service credentials are confined to their home tenant') WHERE EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 1
        AND (NEW.tenant_id IS NULL OR NEW.tenant_id != service_tenant_id));
    -- A repository scope must name a repository of the scoped tenant, so the
    -- narrowing filter cannot be made to point across an ownership boundary.
    SELECT RAISE(ABORT, 'repository scope requires its owning tenant') WHERE
        NEW.repo_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM repos WHERE id = NEW.repo_id AND tenant_id = NEW.tenant_id);
END;

-- Only use and revocation may move. Scope, owner, expiry and identity are
-- fixed at issuance: widening a credential means issuing a new one.
CREATE TRIGGER token_update BEFORE UPDATE ON api_tokens BEGIN
    SELECT RAISE(ABORT, 'credential scope is immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.id != OLD.id OR
        NEW.user_id != OLD.user_id OR NEW.permissions != OLD.permissions OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.repo_id IS NOT OLD.repo_id OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;
