-- S02: stable secret identities, immutable sealed versions, explicit grants
-- to repositories and jobs/steps. Only ciphertext is stored here.
CREATE TABLE secrets(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    scope_repo_id BLOB,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
    current_version INTEGER NOT NULL DEFAULT 0 CHECK(current_version >= 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id, scope_repo_id) REFERENCES repos(tenant_id,id),
    CHECK(scope_repo_id IS NULL OR length(scope_repo_id)=16)
) WITHOUT ROWID;
CREATE UNIQUE INDEX secrets_tenant_name ON secrets(tenant_id,name) WHERE scope_repo_id IS NULL;
CREATE UNIQUE INDEX secrets_repo_name ON secrets(scope_repo_id,name) WHERE scope_repo_id IS NOT NULL;
CREATE INDEX secrets_by_tenant ON secrets(tenant_id,name);
CREATE TRIGGER secrets_identity BEFORE UPDATE OF id,tenant_id,scope_repo_id,name ON secrets BEGIN
    SELECT RAISE(ABORT,'secret identity is immutable');
END;
CREATE TRIGGER secrets_version_forward BEFORE UPDATE OF current_version,active ON secrets
WHEN NEW.current_version < OLD.current_version OR NEW.active > OLD.active BEGIN
    SELECT RAISE(ABORT,'secret version and deletion only move forward');
END;
CREATE TRIGGER secrets_no_delete BEFORE DELETE ON secrets BEGIN
    SELECT RAISE(ABORT,'secret identities are retained');
END;

CREATE TABLE secret_versions(
    secret_id BLOB NOT NULL REFERENCES secrets(id),
    version INTEGER NOT NULL CHECK(version > 0),
    sealed BLOB NOT NULL CHECK(length(sealed) BETWEEN 46 AND 65581 AND substr(sealed,1,1)=x'02'),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(secret_id,version)
) WITHOUT ROWID;
CREATE TRIGGER secret_version_immutable BEFORE UPDATE OF secret_id,version,sealed,created_ms ON secret_versions BEGIN
    SELECT RAISE(ABORT,'secret version is immutable');
END;
CREATE TRIGGER secret_version_revoke BEFORE UPDATE OF revoked ON secret_versions
WHEN NEW.revoked < OLD.revoked BEGIN SELECT RAISE(ABORT,'secret revocation is final'); END;
CREATE TRIGGER secret_version_no_delete BEFORE DELETE ON secret_versions BEGIN
    SELECT RAISE(ABORT,'secret versions are retained');
END;

CREATE TABLE secret_repo_allow(
    secret_id BLOB NOT NULL REFERENCES secrets(id),
    tenant_id BLOB NOT NULL,
    repo_id BLOB NOT NULL,
    granted_ms INTEGER NOT NULL,
    PRIMARY KEY(secret_id,repo_id),
    FOREIGN KEY(tenant_id,repo_id) REFERENCES repos(tenant_id,id)
) WITHOUT ROWID;
CREATE TRIGGER secret_allow_owner BEFORE INSERT ON secret_repo_allow BEGIN
    SELECT RAISE(ABORT,'secret allowlist owner mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM secrets WHERE id=NEW.secret_id AND tenant_id=NEW.tenant_id AND scope_repo_id IS NULL);
END;
CREATE TRIGGER secret_allow_immutable BEFORE UPDATE ON secret_repo_allow BEGIN
    SELECT RAISE(ABORT,'replace secret allowlist entry instead of updating it');
END;

-- Empty job means repo-wide; empty step means every step of the named job.
-- A job/step still must declare the name in its compiled pipeline before S05
-- delivers a value. The binding merely grants eligibility.
CREATE TABLE secret_bindings(
    tenant_id BLOB NOT NULL,
    repo_id BLOB NOT NULL,
    job TEXT NOT NULL CHECK(length(job)<=64),
    step TEXT NOT NULL CHECK(length(step)<=64),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
    secret_id BLOB NOT NULL REFERENCES secrets(id),
    override_tenant INTEGER NOT NULL DEFAULT 0 CHECK(override_tenant IN (0,1)),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(repo_id,job,step,name),
    FOREIGN KEY(tenant_id,repo_id) REFERENCES repos(tenant_id,id),
    CHECK(job!='' OR step='')
) WITHOUT ROWID;
CREATE INDEX secret_bindings_by_secret ON secret_bindings(secret_id);
CREATE TRIGGER secret_binding_owner BEFORE INSERT ON secret_bindings BEGIN
    SELECT RAISE(ABORT,'secret binding owner mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM secrets s WHERE s.id=NEW.secret_id AND s.tenant_id=NEW.tenant_id
        AND (s.scope_repo_id=NEW.repo_id OR (s.scope_repo_id IS NULL AND EXISTS(
            SELECT 1 FROM secret_repo_allow a WHERE a.secret_id=s.id AND a.repo_id=NEW.repo_id))));
END;
CREATE TRIGGER secret_binding_owner_update BEFORE UPDATE ON secret_bindings BEGIN
    SELECT RAISE(ABORT,'replace secret binding instead of updating it');
END;

CREATE TABLE secret_audit(
    seq INTEGER PRIMARY KEY,
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB,
    secret_id BLOB NOT NULL REFERENCES secrets(id),
    version INTEGER NOT NULL CHECK(version>=0),
    actor BLOB REFERENCES users(id),
    attempt_id BLOB,
    step TEXT CHECK(step IS NULL OR length(step)<=64),
    action TEXT NOT NULL CHECK(action IN ('create','rotate','delete','allow','deny','bind','unbind','revoke','use')),
    result TEXT NOT NULL CHECK(result IN ('ok','denied','missing')),
    at_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id,repo_id) REFERENCES repos(tenant_id,id)
);
CREATE INDEX secret_audit_by_secret ON secret_audit(secret_id,seq);
