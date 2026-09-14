-- Worker enrollment and identity (W01).

-- One-time, expiring enrollment. The secret is delivered to the machine out
-- of band and stored here only as a digest; redeeming it binds a worker to
-- exactly the pool the operator chose. A worker never picks its own pool.
CREATE TABLE worker_enrollments(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    id BLOB NOT NULL UNIQUE CHECK(length(id) = 16),
    pool_id BLOB NOT NULL REFERENCES pools(id),
    created_by BLOB REFERENCES users(id),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    redeemed_ms INTEGER,
    redeemed_worker BLOB REFERENCES workers(id),
    revoked_ms INTEGER,
    CHECK((redeemed_ms IS NULL) = (redeemed_worker IS NULL))
) WITHOUT ROWID;
CREATE INDEX worker_enrollments_by_pool ON worker_enrollments(pool_id, created_ms);

CREATE TRIGGER worker_enrollment_update BEFORE UPDATE ON worker_enrollments BEGIN
    SELECT RAISE(ABORT, 'enrollment terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.id != OLD.id OR
        NEW.pool_id != OLD.pool_id OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms OR
        (OLD.redeemed_ms IS NOT NULL AND NEW.redeemed_ms IS NULL) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;

-- A worker's identity is generated on the worker: a self-signed TLS
-- certificate whose fingerprint is recorded at enrollment. Sessions are then
-- mutually authenticated TLS, and the fingerprint is the only thing the
-- controller ever needs to know about the key. No private material is stored.
CREATE TABLE workers(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    pool_id BLOB NOT NULL REFERENCES pools(id),
    fingerprint BLOB NOT NULL UNIQUE CHECK(length(fingerprint) = 32),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    arch TEXT NOT NULL CHECK(arch IN ('x86_64', 'aarch64')),
    capabilities INTEGER NOT NULL CHECK(capabilities >= 0),
    protocol INTEGER NOT NULL CHECK(protocol >= 1),
    enrolled_ms INTEGER NOT NULL,
    last_seen_ms INTEGER,
    revoked_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX workers_by_pool ON workers(pool_id) WHERE revoked_ms IS NULL;

-- Identity and pool are fixed at enrollment: a worker that should serve a
-- different pool is revoked and enrolled again, never moved.
CREATE TRIGGER worker_update BEFORE UPDATE ON workers BEGIN
    SELECT RAISE(ABORT, 'worker identity is immutable') WHERE
        NEW.id != OLD.id OR NEW.pool_id != OLD.pool_id OR
        NEW.fingerprint != OLD.fingerprint OR NEW.enrolled_ms != OLD.enrolled_ms OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;
