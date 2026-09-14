-- Second factors and step-up (A06).

-- A public handle for a session, so an account can be shown its own sessions
-- and revoke one by name. The cookie digest cannot serve: it is the secret's
-- fingerprint and must never be displayed. Nullable because sessions issued
-- before this migration keep working; they simply cannot be named individually,
-- and logout-all still reaches them.
ALTER TABLE sessions ADD COLUMN id BLOB;
CREATE UNIQUE INDEX sessions_by_id ON sessions(id) WHERE id IS NOT NULL;

-- When this session last proved a second factor. Privileged changes require a
-- recent stamp; it is not an authority of its own, only a freshness record.
ALTER TABLE sessions ADD COLUMN stepped_up_ms INTEGER;

DROP TRIGGER session_update;
CREATE TRIGGER session_update BEFORE UPDATE ON sessions BEGIN
    SELECT RAISE(ABORT, 'session identity is immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.user_id != OLD.user_id OR
        NEW.csrf_digest != OLD.csrf_digest OR NEW.created_ms != OLD.created_ms OR
        NEW.absolute_deadline_ms != OLD.absolute_deadline_ms OR
        (OLD.id IS NOT NULL AND NEW.id IS NOT OLD.id) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL) OR
        NEW.idle_deadline_ms > NEW.absolute_deadline_ms;
    -- Step-up freshness only ever moves forward, and never onto a revoked
    -- session: an expired proof cannot be back-dated into validity.
    SELECT RAISE(ABORT, 'step-up cannot move backwards') WHERE
        NEW.stepped_up_ms IS NOT OLD.stepped_up_ms AND
        (OLD.stepped_up_ms IS NOT NULL AND NEW.stepped_up_ms <= OLD.stepped_up_ms
         OR NEW.stepped_up_ms IS NULL OR OLD.revoked_ms IS NOT NULL);
END;

-- One TOTP registration per account. The seed is the one value here that must
-- be recoverable to be useful, so it is stored sealed under a key that lives
-- outside this database; `last_step` enforces RFC 6238's one-use rule, which
-- the specification leaves to the implementer.
CREATE TABLE mfa_totp(
    user_id BLOB PRIMARY KEY NOT NULL REFERENCES users(id),
    sealed_seed BLOB NOT NULL CHECK(length(sealed_seed) BETWEEN 25 AND 256),
    created_ms INTEGER NOT NULL,
    confirmed_ms INTEGER,
    last_step INTEGER
) WITHOUT ROWID;

CREATE TRIGGER totp_insert BEFORE INSERT ON mfa_totp BEGIN
    SELECT RAISE(ABORT, 'a second factor requires an active human account') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND active = 1);
END;
-- Confirmation and the replay counter move; the account does not, and a
-- confirmed registration cannot be silently re-seeded in place. Replacing a
-- second factor means removing it under step-up and enrolling again.
CREATE TRIGGER totp_update BEFORE UPDATE ON mfa_totp BEGIN
    SELECT RAISE(ABORT, 'second factor identity is immutable') WHERE
        NEW.user_id != OLD.user_id OR NEW.created_ms != OLD.created_ms OR
        (OLD.confirmed_ms IS NOT NULL AND
            (NEW.sealed_seed != OLD.sealed_seed OR NEW.confirmed_ms IS NULL));
    SELECT RAISE(ABORT, 'a time step is accepted once') WHERE
        OLD.last_step IS NOT NULL AND NEW.last_step IS NOT NULL
        AND NEW.last_step < OLD.last_step;
END;

-- Hashed one-use recovery codes. A set is issued together and replaces any
-- previous set, so codes written down long ago stop working when new ones are
-- handed out.
CREATE TABLE mfa_recovery_codes(
    code_digest BLOB PRIMARY KEY NOT NULL CHECK(length(code_digest) = 32),
    user_id BLOB NOT NULL REFERENCES users(id),
    created_ms INTEGER NOT NULL,
    used_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX recovery_codes_by_user ON mfa_recovery_codes(user_id) WHERE used_ms IS NULL;

CREATE TRIGGER recovery_code_update BEFORE UPDATE ON mfa_recovery_codes BEGIN
    SELECT RAISE(ABORT, 'a recovery code is spent once') WHERE
        NEW.code_digest != OLD.code_digest OR NEW.user_id != OLD.user_id OR
        OLD.used_ms IS NOT NULL;
END;
