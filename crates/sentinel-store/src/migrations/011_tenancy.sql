-- Tenant suspension, revocation propagation and pool grants (A07).

-- A monotonic authorization epoch per tenant. Every query already re-checks
-- membership and grants, but a long-lived subscription (a log stream, an event
-- cursor) cannot re-run its predicate per frame. It records the epoch it was
-- authorized at; any change to who may act in the tenant bumps the epoch, and
-- the holder must re-authorize when it no longer matches. Cheap to compare,
-- impossible to forget: it moves in the same transaction as the change.
ALTER TABLE tenants ADD COLUMN authz_epoch INTEGER NOT NULL DEFAULT 0 CHECK(authz_epoch >= 0);
CREATE TRIGGER tenant_epoch_monotonic BEFORE UPDATE OF authz_epoch ON tenants
WHEN NEW.authz_epoch < OLD.authz_epoch BEGIN
    SELECT RAISE(ABORT, 'authorization epoch only moves forward');
END;

-- Worker pools. A dedicated pool belongs to one tenant and needs no grant; a
-- shared pool is platform-managed and admits only tenants with an explicit
-- grant. Approval of one tenant never makes its code trusted on another's
-- machines, so the owner column and the grants table are the only two ways in.
CREATE TABLE pools(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 64),
    kind INTEGER NOT NULL CHECK(kind IN (0, 1)),
    owner_tenant_id BLOB REFERENCES tenants(id),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    created_ms INTEGER NOT NULL,
    CHECK((kind = 0 AND owner_tenant_id IS NOT NULL) OR (kind = 1 AND owner_tenant_id IS NULL))
) WITHOUT ROWID;
CREATE INDEX pools_by_owner ON pools(owner_tenant_id) WHERE kind = 0;

CREATE TRIGGER pool_update BEFORE UPDATE OF id, name, kind, owner_tenant_id ON pools BEGIN
    SELECT RAISE(ABORT, 'pool identity is immutable');
END;

CREATE TABLE pool_grants(
    pool_id BLOB NOT NULL REFERENCES pools(id),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    granted_by BLOB REFERENCES users(id),
    granted_ms INTEGER NOT NULL,
    PRIMARY KEY(pool_id, tenant_id)
) WITHOUT ROWID;
CREATE INDEX pool_grants_by_tenant ON pool_grants(tenant_id);

-- Grants exist only for shared pools: a dedicated pool is its owner's by
-- construction, and granting it to somebody else would be a second owner.
CREATE TRIGGER pool_grant_insert BEFORE INSERT ON pool_grants BEGIN
    SELECT RAISE(ABORT, 'only a shared pool takes grants') WHERE NOT EXISTS(
        SELECT 1 FROM pools WHERE id = NEW.pool_id AND kind = 1);
END;
CREATE TRIGGER pool_grant_update BEFORE UPDATE ON pool_grants BEGIN
    SELECT RAISE(ABORT, 'a pool grant is added or removed, never edited');
END;
