-- Existing org tenants keep their names and receive no implicit memberships.
CREATE TABLE users(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    kind INTEGER NOT NULL DEFAULT 0 CHECK(kind IN (0, 1)),
    service_tenant_id BLOB REFERENCES tenants(id),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    super_admin INTEGER NOT NULL DEFAULT 0 CHECK(super_admin IN (0, 1)),
    created_ms INTEGER NOT NULL,
    CHECK((kind = 0 AND service_tenant_id IS NULL) OR
          (kind = 1 AND service_tenant_id IS NOT NULL AND super_admin = 0))
) WITHOUT ROWID;
CREATE INDEX users_service_tenant ON users(service_tenant_id) WHERE kind = 1;

ALTER TABLE tenants ADD COLUMN kind INTEGER NOT NULL DEFAULT 0 CHECK(kind IN (0, 1));
ALTER TABLE tenants ADD COLUMN owner_user_id BLOB REFERENCES users(id);
ALTER TABLE tenants ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1));
CREATE UNIQUE INDEX personal_namespace_owner ON tenants(owner_user_id) WHERE kind = 1;

CREATE TABLE external_identities(
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 64),
    subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 255),
    user_id BLOB NOT NULL REFERENCES users(id),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(provider, subject)
) WITHOUT ROWID;
CREATE INDEX identities_by_user ON external_identities(user_id);

CREATE TABLE memberships(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    user_id BLOB NOT NULL REFERENCES users(id),
    role INTEGER NOT NULL CHECK(role IN (1, 2, 3)),
    PRIMARY KEY(tenant_id, user_id)
) WITHOUT ROWID;
CREATE INDEX memberships_by_user ON memberships(user_id, tenant_id);
CREATE UNIQUE INDEX repos_ownership ON repos(tenant_id, id);
CREATE TABLE repo_grants(
    tenant_id BLOB NOT NULL,
    repo_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    permissions INTEGER NOT NULL CHECK(permissions BETWEEN 1 AND 7),
    PRIMARY KEY(tenant_id, user_id, repo_id),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id),
    FOREIGN KEY(tenant_id, user_id) REFERENCES memberships(tenant_id, user_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TRIGGER namespace_insert BEFORE INSERT ON tenants BEGIN
    SELECT RAISE(ABORT, 'invalid namespace') WHERE
        length(NEW.slug) NOT BETWEEN 1 AND 63 OR NEW.slug GLOB '*[^a-z0-9-]*' OR
        substr(NEW.slug, 1, 1) = '-' OR substr(NEW.slug, -1, 1) = '-' OR
        (NEW.kind = 0 AND NEW.owner_user_id IS NOT NULL) OR
        (NEW.kind = 1 AND NOT EXISTS(SELECT 1 FROM users WHERE id = NEW.owner_user_id AND kind = 0 AND active = 1));
END;
CREATE TRIGGER namespace_update BEFORE UPDATE OF slug, kind, owner_user_id ON tenants BEGIN
    SELECT RAISE(ABORT, 'namespace identity is immutable') WHERE
        NEW.slug != OLD.slug OR NEW.kind != OLD.kind OR NEW.owner_user_id IS NOT OLD.owner_user_id;
END;
CREATE TRIGGER user_identity_update BEFORE UPDATE OF kind, service_tenant_id ON users BEGIN
    SELECT RAISE(ABORT, 'principal kind is immutable') WHERE
        NEW.kind != OLD.kind OR NEW.service_tenant_id IS NOT OLD.service_tenant_id;
END;
CREATE TRIGGER membership_insert BEFORE INSERT ON memberships BEGIN
    SELECT RAISE(ABORT, 'invalid service membership') WHERE EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 1
        AND (service_tenant_id != NEW.tenant_id OR NEW.role = 3));
END;
CREATE TRIGGER membership_update BEFORE UPDATE ON memberships BEGIN
    SELECT RAISE(ABORT, 'invalid service membership') WHERE EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 1
        AND (service_tenant_id != NEW.tenant_id OR NEW.role = 3));
    SELECT RAISE(ABORT, 'personal owner membership is required') WHERE OLD.role = 3
        AND EXISTS(SELECT 1 FROM tenants WHERE id = OLD.tenant_id AND owner_user_id = OLD.user_id)
        AND (NEW.role != 3 OR NEW.tenant_id != OLD.tenant_id OR NEW.user_id != OLD.user_id);
END;
CREATE TRIGGER membership_delete BEFORE DELETE ON memberships BEGIN
    SELECT RAISE(ABORT, 'personal owner membership is required') WHERE EXISTS(
        SELECT 1 FROM tenants WHERE id = OLD.tenant_id AND owner_user_id = OLD.user_id);
END;
CREATE TRIGGER identity_insert BEFORE INSERT ON external_identities BEGIN
    SELECT RAISE(ABORT, 'external identity requires human user') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0);
END;
CREATE TRIGGER identity_update BEFORE UPDATE ON external_identities BEGIN
    SELECT RAISE(ABORT, 'external identity link is immutable');
END;

-- Close C02's helper-only ownership gap without rewriting existing tables or
-- their blob formats. Refuse a pre-existing inconsistent graph, never repair
-- ownership by guessing which tenant was intended.
CREATE TEMP TABLE ownership_check(valid INTEGER CHECK(valid = 1));
INSERT INTO ownership_check SELECT 0 FROM pragma_foreign_key_check LIMIT 1;
INSERT INTO ownership_check SELECT 0 WHERE
    EXISTS(SELECT 1 FROM runs c JOIN repos p ON p.id=c.repo_id WHERE c.tenant_id!=p.tenant_id) OR
    EXISTS(SELECT 1 FROM jobs c JOIN runs p ON p.id=c.run_id WHERE c.tenant_id!=p.tenant_id) OR
    EXISTS(SELECT 1 FROM attempts c JOIN jobs p ON p.id=c.job_id WHERE c.tenant_id!=p.tenant_id) OR
    EXISTS(SELECT 1 FROM run_specs c JOIN runs p ON p.id=c.run_id WHERE c.tenant_id!=p.tenant_id) OR
    EXISTS(SELECT 1 FROM idempotency_keys c JOIN runs p ON p.id=c.run_id WHERE c.tenant_id!=p.tenant_id);
DROP TABLE ownership_check;
CREATE TRIGGER repo_owner_update BEFORE UPDATE OF tenant_id ON repos WHEN NEW.tenant_id != OLD.tenant_id BEGIN
    SELECT RAISE(ABORT, 'repository ownership is immutable');
END;
CREATE TRIGGER run_owner_insert BEFORE INSERT ON runs BEGIN
    SELECT RAISE(ABORT, 'run ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM repos WHERE id=NEW.repo_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER run_owner_update BEFORE UPDATE OF tenant_id, repo_id ON runs BEGIN
    SELECT RAISE(ABORT, 'run ownership mismatch') WHERE NEW.tenant_id != OLD.tenant_id OR NOT EXISTS(SELECT 1 FROM repos WHERE id=NEW.repo_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER job_owner_insert BEFORE INSERT ON jobs BEGIN
    SELECT RAISE(ABORT, 'job ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER job_owner_update BEFORE UPDATE OF tenant_id, run_id ON jobs BEGIN
    SELECT RAISE(ABORT, 'job ownership mismatch') WHERE NEW.tenant_id != OLD.tenant_id OR NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER attempt_owner_insert BEFORE INSERT ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE id=NEW.job_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER attempt_owner_update BEFORE UPDATE OF tenant_id, job_id ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE id=NEW.job_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER spec_owner_insert BEFORE INSERT ON run_specs BEGIN
    SELECT RAISE(ABORT, 'spec ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER spec_owner_update BEFORE UPDATE OF tenant_id, run_id ON run_specs BEGIN
    SELECT RAISE(ABORT, 'spec ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER idempotency_owner_insert BEFORE INSERT ON idempotency_keys WHEN NEW.run_id IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'idempotency ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
CREATE TRIGGER idempotency_owner_update BEFORE UPDATE OF tenant_id, run_id ON idempotency_keys WHEN NEW.run_id IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'idempotency ownership mismatch') WHERE NOT EXISTS(SELECT 1 FROM runs WHERE id=NEW.run_id AND tenant_id=NEW.tenant_id);
END;
