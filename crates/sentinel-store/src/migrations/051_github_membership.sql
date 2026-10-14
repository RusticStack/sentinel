-- GitHub-backed organization membership.
--
-- A tenant is either app-managed (membership by invitation or administrator,
-- the only kind that existed before this migration) or GitHub-backed: who may
-- act in it is whatever GitHub says about the person's *linked, verified*
-- GitHub account. Nothing is inferred: every existing tenant stays
-- app-managed until an administrator converts it explicitly.
ALTER TABLE tenants ADD COLUMN membership_source INTEGER NOT NULL DEFAULT 0
    CHECK(membership_source IN (0, 1));

-- NULL = managed locally (invitation, administrator, personal owner). A value
-- is the time GitHub last confirmed the row: the row *is* the cache, and a
-- stale value is the explicit "unknown" state the lane expires after its
-- grace period. Authorization queries never read these columns.
ALTER TABLE memberships ADD COLUMN synced_ms INTEGER;
ALTER TABLE repo_grants ADD COLUMN synced_ms INTEGER;

-- Every sign-in asks which tenants are GitHub-backed; most deployments have
-- none, and the partial index keeps that question a probe of an empty set.
CREATE INDEX tenants_github_backed ON tenants(id) WHERE membership_source = 1;

-- A derived row exists only in a GitHub-backed tenant, and never for the
-- personal owner whose admin membership the schema requires.
CREATE TRIGGER membership_derived_insert BEFORE INSERT ON memberships
WHEN NEW.synced_ms IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'derived membership needs a github-backed tenant') WHERE NOT EXISTS(
        SELECT 1 FROM tenants WHERE id = NEW.tenant_id AND membership_source = 1
        AND kind = 0);
END;
CREATE TRIGGER membership_derived_update BEFORE UPDATE OF synced_ms ON memberships
WHEN NEW.synced_ms IS NOT NULL AND NEW.synced_ms IS NOT OLD.synced_ms BEGIN
    SELECT RAISE(ABORT, 'derived membership needs a github-backed tenant') WHERE NOT EXISTS(
        SELECT 1 FROM tenants WHERE id = NEW.tenant_id AND membership_source = 1
        AND kind = 0);
END;

-- Backing is decided by an explicit act and only for an organization tenant;
-- a personal namespace is never GitHub-backed.
CREATE TRIGGER tenant_backing_update BEFORE UPDATE OF membership_source ON tenants
WHEN NEW.membership_source = 1 AND NEW.kind != 0 BEGIN
    SELECT RAISE(ABORT, 'only an organization can be github-backed');
END;

-- The durable list of (tenant, person) pairs the lane owes a GitHub check:
-- a sign-in, a link, a signed webhook or the periodic pass asked for one.
-- `cursor` is the last repository whose permission the walk settled, so a
-- member of a large installation is checked in bounded steps; `seq` fences a
-- pass against a request that arrived while it was on the wire.
CREATE TABLE github_member_checks(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    user_id BLOB NOT NULL REFERENCES users(id),
    next_ms INTEGER NOT NULL,
    checked_ms INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    cursor BLOB CHECK(cursor IS NULL OR length(cursor) = 16),
    seq INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(tenant_id, user_id)
) WITHOUT ROWID;
CREATE INDEX github_member_checks_due ON github_member_checks(next_ms);
CREATE INDEX github_member_checks_user ON github_member_checks(user_id);
