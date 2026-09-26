-- MCP is a separate OAuth resource from the REST API. Keep the original
-- `audience` columns at API=1 for old database constraints; `resource` is
-- the authoritative RFC 8707 audience for grants, codes and device codes.
ALTER TABLE oauth_grants ADD COLUMN resource INTEGER NOT NULL DEFAULT 1
    CHECK(resource IN (1, 2));
ALTER TABLE oauth_codes ADD COLUMN resource INTEGER NOT NULL DEFAULT 1
    CHECK(resource IN (1, 2));
ALTER TABLE oauth_device_codes ADD COLUMN resource INTEGER NOT NULL DEFAULT 1
    CHECK(resource IN (1, 2));

DROP TRIGGER oauth_grant_update;
CREATE TRIGGER oauth_grant_update BEFORE UPDATE ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grant terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.user_id != OLD.user_id OR NEW.client_id != OLD.client_id OR
        NEW.kind != OLD.kind OR NEW.scopes != OLD.scopes OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.repo_id IS NOT OLD.repo_id OR
        NEW.audience != OLD.audience OR NEW.resource != OLD.resource OR NEW.name IS NOT OLD.name OR
        NEW.created_by IS NOT OLD.created_by OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms;
    SELECT RAISE(ABORT, 'grant revocation is final') WHERE OLD.revoked_ms IS NOT NULL AND
        (NEW.revoked_ms IS NOT OLD.revoked_ms OR NEW.revoked_reason IS NOT OLD.revoked_reason);
END;

DROP TRIGGER oauth_code_update;
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

DROP TRIGGER oauth_device_update;
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
