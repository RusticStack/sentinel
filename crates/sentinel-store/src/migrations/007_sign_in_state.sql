-- Pending external sign-in attempts (A04). One row per authorization round
-- trip: single-use, short-lived, and matched against a host-only cookie that
-- the browser holds, so a leaked or guessed `state` parameter alone cannot
-- complete somebody's sign-in.
--
-- Only the digest is stored, like sessions and credentials. `redirect_to` is a
-- validated same-site path, never an absolute URL: an open redirect after a
-- successful login is a phishing primitive.
CREATE TABLE sign_in_states(
    state_digest BLOB PRIMARY KEY NOT NULL CHECK(length(state_digest) = 32),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 64),
    redirect_to TEXT CHECK(redirect_to IS NULL OR
        (length(redirect_to) BETWEEN 1 AND 512 AND substr(redirect_to, 1, 1) = '/'
         AND substr(redirect_to, 1, 2) != '//')),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    consumed_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX sign_in_states_by_expiry ON sign_in_states(expires_ms);

-- A spent or expired attempt cannot be reopened, and its target cannot be moved
-- after the browser has been sent to the provider.
CREATE TRIGGER sign_in_state_update BEFORE UPDATE ON sign_in_states BEGIN
    SELECT RAISE(ABORT, 'sign-in state is single use') WHERE
        NEW.state_digest != OLD.state_digest OR NEW.provider != OLD.provider OR
        NEW.redirect_to IS NOT OLD.redirect_to OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms OR OLD.consumed_ms IS NOT NULL;
END;
