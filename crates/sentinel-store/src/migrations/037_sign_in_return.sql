-- GitHub web sign-in from the browser pages (U07).
--
-- A sign-in started on the OAuth consent page must return the browser to that
-- exact page, parameters included, and an authorization request's query
-- (redirect URI, state, PKCE challenge, scopes, resource) can pass the old
-- 512-byte bound on `redirect_to`. The table is rebuilt with a 2048-byte
-- bound; every other rule is unchanged. Rows are copied, so a sign-in in
-- flight across the upgrade still completes.
CREATE TABLE sign_in_states_next(
    state_digest BLOB PRIMARY KEY NOT NULL CHECK(length(state_digest) = 32),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 64),
    redirect_to TEXT CHECK(redirect_to IS NULL OR
        (length(redirect_to) BETWEEN 1 AND 2048 AND substr(redirect_to, 1, 1) = '/'
         AND substr(redirect_to, 1, 2) != '//')),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    consumed_ms INTEGER
) WITHOUT ROWID;
INSERT INTO sign_in_states_next(state_digest, provider, redirect_to, created_ms, expires_ms, consumed_ms)
    SELECT state_digest, provider, redirect_to, created_ms, expires_ms, consumed_ms FROM sign_in_states;
DROP TABLE sign_in_states;
ALTER TABLE sign_in_states_next RENAME TO sign_in_states;
CREATE INDEX sign_in_states_by_expiry ON sign_in_states(expires_ms);

CREATE TRIGGER sign_in_state_update BEFORE UPDATE ON sign_in_states BEGIN
    SELECT RAISE(ABORT, 'sign-in state is single use') WHERE
        NEW.state_digest != OLD.state_digest OR NEW.provider != OLD.provider OR
        NEW.redirect_to IS NOT OLD.redirect_to OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms OR OLD.consumed_ms IS NOT NULL;
END;
