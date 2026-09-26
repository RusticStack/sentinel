-- Part 10 audit (secrets cluster).
--
-- P10S-1: secret retry records carried an unkeyed FNV digest of the written
-- value. Fingerprints are now a keyed MAC under a subkey of the master key,
-- and an old row cannot be converted without its value, so they are purged.
-- A retry of a write made before the upgrade re-executes under its
-- If-Match version and answers `conflict` if the first attempt committed.
DELETE FROM secret_idempotency;

-- P10S-6: the secret audit is append-only, and delivery refusals are
-- recorded. A refusal whose binding is missing names no secret, so
-- `secret_id` is nullable only for such a row and the target name is kept.
CREATE TABLE secret_audit_v2(
    seq INTEGER PRIMARY KEY,
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB,
    secret_id BLOB REFERENCES secrets(id),
    name TEXT CHECK(name IS NULL OR length(name) BETWEEN 1 AND 64),
    version INTEGER NOT NULL CHECK(version>=0),
    actor BLOB REFERENCES users(id),
    attempt_id BLOB,
    step TEXT CHECK(step IS NULL OR length(step)<=64),
    action TEXT NOT NULL CHECK(action IN ('create','rotate','delete','allow','deny','bind','unbind','revoke','use')),
    result TEXT NOT NULL CHECK(result IN ('ok','denied','missing')),
    at_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id,repo_id) REFERENCES repos(tenant_id,id),
    CHECK(secret_id IS NOT NULL OR (action='use' AND result!='ok' AND name IS NOT NULL))
);
INSERT INTO secret_audit_v2(seq,tenant_id,repo_id,secret_id,version,actor,attempt_id,step,action,result,at_ms)
    SELECT seq,tenant_id,repo_id,secret_id,version,actor,attempt_id,step,action,result,at_ms FROM secret_audit;
DROP TABLE secret_audit;
ALTER TABLE secret_audit_v2 RENAME TO secret_audit;
CREATE INDEX secret_audit_by_secret ON secret_audit(secret_id,seq);
CREATE TRIGGER secret_audit_immutable BEFORE UPDATE ON secret_audit BEGIN
    SELECT RAISE(ABORT,'secret audit is append-only');
END;
CREATE TRIGGER secret_audit_undeletable BEFORE DELETE ON secret_audit BEGIN
    SELECT RAISE(ABORT,'secret audit is append-only');
END;

-- P10S-5: `admin key reseal` moves ciphertext to the active key so retired
-- keys can be dropped. A version's sealed bytes may change only to a
-- format-2 value under a strictly newer key ID (big-endian, so the blob
-- comparison is numeric); revoked versions are resealed too, so a retired
-- key opens nothing. Everything else about a version stays immutable.
DROP TRIGGER secret_version_immutable;
CREATE TRIGGER secret_version_immutable BEFORE UPDATE OF secret_id,version,created_ms ON secret_versions BEGIN
    SELECT RAISE(ABORT,'secret version is immutable');
END;
CREATE TRIGGER secret_version_reseal BEFORE UPDATE OF sealed ON secret_versions
WHEN NOT (substr(OLD.sealed,1,1)=x'02' AND substr(NEW.sealed,1,1)=x'02'
          AND substr(NEW.sealed,2,4) > substr(OLD.sealed,2,4)) BEGIN
    SELECT RAISE(ABORT,'secret version is immutable');
END;

-- The same rule for a confirmed second factor: its seed can be resealed
-- forward (legacy format 1 to format 2, or to a newer key ID), never
-- replaced.
DROP TRIGGER totp_update;
CREATE TRIGGER totp_update BEFORE UPDATE ON mfa_totp BEGIN
    SELECT RAISE(ABORT, 'second factor identity is immutable') WHERE
        NEW.user_id != OLD.user_id OR NEW.created_ms != OLD.created_ms OR
        (OLD.confirmed_ms IS NOT NULL AND (NEW.confirmed_ms IS NULL OR
            (NEW.sealed_seed != OLD.sealed_seed AND NOT (
                substr(NEW.sealed_seed,1,1)=x'02' AND (
                    substr(OLD.sealed_seed,1,1)=x'01' OR
                    (substr(OLD.sealed_seed,1,1)=x'02'
                     AND substr(NEW.sealed_seed,2,4) > substr(OLD.sealed_seed,2,4)))))));
    SELECT RAISE(ABORT, 'a time step is accepted once') WHERE
        OLD.last_step IS NOT NULL AND NEW.last_step IS NOT NULL
        AND NEW.last_step < OLD.last_step;
END;
