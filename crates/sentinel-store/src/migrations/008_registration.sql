-- Admission (A05). Four decisions are kept separate, because conflating them is
-- how a CI system ends up granting compute to whoever clicked "install":
-- registering an account, approving it, creating a tenant, and binding a forge
-- installation to that tenant.

-- Pending (0), approved (1), rejected (2). Existing rows are approved: they
-- were admitted before this policy existed, and an upgrade must not lock out
-- the operators who are already using the deployment.
ALTER TABLE users ADD COLUMN status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0, 1, 2));

-- `active` stays the single liveness predicate every authorization query
-- already joins on, so a pending or rejected account cannot authenticate,
-- cannot hold a session, credential or membership, and needs no new check in
-- any existing statement. This trigger is what keeps the two columns honest.
CREATE TRIGGER user_status_insert BEFORE INSERT ON users
WHEN NEW.active = 1 AND NEW.status != 1 BEGIN
    SELECT RAISE(ABORT, 'only an approved account can be active');
END;
CREATE TRIGGER user_status_update BEFORE UPDATE OF active, status ON users
WHEN NEW.active = 1 AND NEW.status != 1 BEGIN
    SELECT RAISE(ABORT, 'only an approved account can be active');
END;

-- A pending account must be able to *hold* the credential it registered with,
-- or approving it would leave it with no way to sign in. Holding one is not
-- using one: every authentication path still requires `active = 1`, so a
-- pending account's password and identity are inert until an admin approves.
-- Rejected accounts keep their claim without being able to re-register.
DROP TRIGGER credential_insert;
CREATE TRIGGER credential_insert BEFORE INSERT ON local_credentials BEGIN
    SELECT RAISE(ABORT, 'local credentials require a human account') WHERE NOT EXISTS(
        SELECT 1 FROM users WHERE id = NEW.user_id AND kind = 0 AND status != 2);
    SELECT RAISE(ABORT, 'invalid username') WHERE
        NEW.username GLOB '*[^a-z0-9._-]*' OR substr(NEW.username, 1, 1) GLOB '[^a-z0-9]';
END;

-- Deployment admission policy: one row, super-admin controlled, audited.
-- Defaults are the safe ones: new accounts need an invitation, only a super
-- admin creates namespaces, and a tenant admin may bind an installation to the
-- tenant they already administer.
CREATE TABLE deployment_policy(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    registration INTEGER NOT NULL CHECK(registration IN (0, 1, 2)),
    tenant_creation INTEGER NOT NULL CHECK(tenant_creation IN (0, 1)),
    installation_binding INTEGER NOT NULL CHECK(installation_binding IN (0, 1)),
    updated_ms INTEGER NOT NULL,
    updated_by BLOB REFERENCES users(id)
);
INSERT INTO deployment_policy(id, registration, tenant_creation, installation_binding, updated_ms)
    VALUES (1, 1, 0, 1, 0);
CREATE TRIGGER policy_single_row BEFORE INSERT ON deployment_policy BEGIN
    SELECT RAISE(ABORT, 'deployment policy is a single row');
END;
CREATE TRIGGER policy_undeletable BEFORE DELETE ON deployment_policy BEGIN
    SELECT RAISE(ABORT, 'deployment policy is a single row');
END;

-- One-time invitations. Digest only, like every other secret here, so the
-- deployment cannot show a link again and a database snapshot yields nothing
-- redeemable. An invitation may bind a verified identity, a tenant and the
-- maximum role granted on acceptance; all three are optional narrowings.
CREATE TABLE invitations(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    id BLOB NOT NULL UNIQUE CHECK(length(id) = 16),
    tenant_id BLOB REFERENCES tenants(id),
    role INTEGER CHECK(role IS NULL OR role IN (1, 2, 3)),
    provider TEXT CHECK(provider IS NULL OR length(provider) BETWEEN 1 AND 64),
    subject TEXT CHECK(subject IS NULL OR length(subject) BETWEEN 1 AND 255),
    created_by BLOB REFERENCES users(id),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    redeemed_ms INTEGER,
    redeemed_by BLOB REFERENCES users(id),
    revoked_ms INTEGER,
    -- A role without a tenant would grant membership of nothing; a bound
    -- subject without its provider is not an identity.
    CHECK((role IS NULL) = (tenant_id IS NULL)),
    CHECK((provider IS NULL) = (subject IS NULL)),
    CHECK((redeemed_ms IS NULL) = (redeemed_by IS NULL))
) WITHOUT ROWID;
CREATE INDEX invitations_by_tenant ON invitations(tenant_id, created_ms);
CREATE INDEX invitations_by_expiry ON invitations(expires_ms);

-- Redemption and revocation are the only movement; an invitation's terms are
-- fixed when it is written, and a spent one never becomes unspent.
CREATE TRIGGER invitation_update BEFORE UPDATE ON invitations BEGIN
    SELECT RAISE(ABORT, 'invitation terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.id != OLD.id OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.role IS NOT OLD.role OR
        NEW.provider IS NOT OLD.provider OR NEW.subject IS NOT OLD.subject OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms OR
        (OLD.redeemed_ms IS NOT NULL AND NEW.redeemed_ms IS NULL) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;

-- Forge installations. Seeing an installation is not the same as trusting it:
-- a row here with `tenant_id IS NULL` is a known, unbound, inactive fact.
-- Installing the App on GitHub cannot create a tenant or allocate compute.
CREATE TABLE installations(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 64),
    external_id TEXT NOT NULL CHECK(length(external_id) BETWEEN 1 AND 64),
    account_login TEXT NOT NULL CHECK(length(account_login) BETWEEN 1 AND 128),
    tenant_id BLOB REFERENCES tenants(id),
    bound_by BLOB REFERENCES users(id),
    bound_ms INTEGER,
    first_seen_ms INTEGER NOT NULL,
    suspended INTEGER NOT NULL DEFAULT 0 CHECK(suspended IN (0, 1)),
    CHECK((tenant_id IS NULL) = (bound_ms IS NULL)),
    UNIQUE(provider, external_id)
) WITHOUT ROWID;
CREATE INDEX installations_by_tenant ON installations(tenant_id) WHERE tenant_id IS NOT NULL;

CREATE TRIGGER installation_update BEFORE UPDATE ON installations BEGIN
    SELECT RAISE(ABORT, 'installation identity is immutable') WHERE
        NEW.id != OLD.id OR NEW.provider != OLD.provider OR
        NEW.external_id != OLD.external_id OR NEW.first_seen_ms != OLD.first_seen_ms;
    -- Rebinding to a different tenant must go through an explicit unbind, so a
    -- repository's owner never changes underneath running work.
    SELECT RAISE(ABORT, 'installation is already bound') WHERE
        OLD.tenant_id IS NOT NULL AND NEW.tenant_id IS NOT NULL
        AND NEW.tenant_id != OLD.tenant_id;
END;
