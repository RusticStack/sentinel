-- Service grants minted by a browser session retain that session's public ID
-- after the session expires or is purged. There is deliberately no foreign key:
-- provenance must outlive the session row. Legacy rows remain NULL and use the
-- timestamp revocation fallback.
ALTER TABLE oauth_grants ADD COLUMN created_session BLOB
    CHECK(created_session IS NULL OR length(created_session) = 16);

CREATE INDEX oauth_grants_by_created_session
    ON oauth_grants(created_by, created_session)
    WHERE created_session IS NOT NULL;

DROP TRIGGER oauth_grant_update;
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
