-- Local login records. A user row alone authenticates nobody: a credential is
-- an explicit, separately provisioned admission fact. Service principals and
-- deactivated accounts cannot hold one, and the username is the only unique
-- login identity (display names stay bounded metadata).
CREATE TABLE local_credentials(
    user_id BLOB PRIMARY KEY NOT NULL REFERENCES users(id),
    username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 1 AND 63),
    phc TEXT NOT NULL CHECK(length(phc) BETWEEN 16 AND 512),
    updated_ms INTEGER NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures >= 0),
    locked_until_ms INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TRIGGER credential_insert BEFORE INSERT ON local_credentials BEGIN
    SELECT RAISE(ABORT, 'local credentials require an active human user') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND active = 1);
    SELECT RAISE(ABORT, 'invalid username') WHERE
        NEW.username GLOB '*[^a-z0-9._-]*' OR substr(NEW.username, 1, 1) GLOB '[^a-z0-9]';
END;
CREATE TRIGGER credential_update BEFORE UPDATE ON local_credentials BEGIN
    SELECT RAISE(ABORT, 'login identity is immutable') WHERE
        NEW.username != OLD.username OR NEW.user_id != OLD.user_id;
END;

-- Opaque server-side sessions. The cookie value is never stored: `token_digest`
-- is BLAKE3 of the secret, so validation is one primary-key probe and a stolen
-- database snapshot yields no usable cookie. Both deadlines are absolute
-- instants; expiry is a query predicate, not a background job's promise.
CREATE TABLE sessions(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    user_id BLOB NOT NULL REFERENCES users(id),
    csrf_digest BLOB NOT NULL CHECK(length(csrf_digest) = 32),
    created_ms INTEGER NOT NULL,
    idle_deadline_ms INTEGER NOT NULL,
    absolute_deadline_ms INTEGER NOT NULL,
    revoked_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX sessions_by_user ON sessions(user_id) WHERE revoked_ms IS NULL;
CREATE INDEX sessions_by_deadline ON sessions(absolute_deadline_ms);

CREATE TRIGGER session_insert BEFORE INSERT ON sessions BEGIN
    SELECT RAISE(ABORT, 'sessions require an active human user') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND active = 1);
    SELECT RAISE(ABORT, 'session deadlines must be ordered') WHERE
        NEW.idle_deadline_ms > NEW.absolute_deadline_ms OR NEW.created_ms > NEW.idle_deadline_ms;
END;
-- Only expiry may move, and only inward; a session cannot be un-revoked or
-- extended past the absolute deadline it was issued with.
CREATE TRIGGER session_update BEFORE UPDATE ON sessions BEGIN
    SELECT RAISE(ABORT, 'session identity is immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.user_id != OLD.user_id OR
        NEW.csrf_digest != OLD.csrf_digest OR NEW.created_ms != OLD.created_ms OR
        NEW.absolute_deadline_ms != OLD.absolute_deadline_ms OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL) OR
        NEW.idle_deadline_ms > NEW.absolute_deadline_ms;
END;

-- Append-only authentication/administration record. Holds decisions and
-- subjects, never passwords, cookie values, digests or reset material.
CREATE TABLE auth_audit(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    event INTEGER NOT NULL,
    actor_user_id BLOB REFERENCES users(id),
    subject_user_id BLOB REFERENCES users(id),
    host_local INTEGER NOT NULL CHECK(host_local IN (0, 1)),
    detail TEXT CHECK(detail IS NULL OR length(detail) <= 128)
);
CREATE INDEX audit_by_time ON auth_audit(at_ms);
CREATE TRIGGER audit_immutable BEFORE UPDATE ON auth_audit BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;
CREATE TRIGGER audit_undeletable BEFORE DELETE ON auth_audit BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;

-- Single-row latch: the first admin is admitted host-locally, exactly once.
-- Its presence, not a configuration flag, is what disables bootstrap.
CREATE TABLE bootstrap(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    completed_ms INTEGER NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id)
);
CREATE TRIGGER bootstrap_once BEFORE UPDATE ON bootstrap BEGIN
    SELECT RAISE(ABORT, 'bootstrap is already complete');
END;
CREATE TRIGGER bootstrap_undeletable BEFORE DELETE ON bootstrap BEGIN
    SELECT RAISE(ABORT, 'bootstrap is already complete');
END;

-- The deployment must keep one reachable super admin. Enforced here as well as
-- in the API so no raw controller statement, migration or repair can empty it.
CREATE TRIGGER last_super_admin_update BEFORE UPDATE OF super_admin, active ON users
WHEN OLD.kind = 0 AND OLD.super_admin = 1 AND OLD.active = 1
AND (NEW.super_admin = 0 OR NEW.active = 0) BEGIN
    SELECT RAISE(ABORT, 'the last active super admin cannot be removed') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id != OLD.id AND kind = 0 AND super_admin = 1 AND active = 1);
END;
CREATE TRIGGER last_super_admin_delete BEFORE DELETE ON users
WHEN OLD.kind = 0 AND OLD.super_admin = 1 AND OLD.active = 1 BEGIN
    SELECT RAISE(ABORT, 'the last active super admin cannot be removed') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id != OLD.id AND kind = 0 AND super_admin = 1 AND active = 1);
END;
