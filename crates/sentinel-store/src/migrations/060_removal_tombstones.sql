-- Removal tombstones and the GitHub organization name probe.
--
-- `membership_removals` remembers that an administrator removed a person from
-- an app-managed organization. `auto_join::apply` consults it, so a person
-- removed while their mail domain stays in SENTINEL_AUTO_JOIN_DOMAINS is not
-- re-added at the next sign-in. It is a veto on automatic joining only: it
-- grants and hides nothing, an administrator who adds the person again simply
-- supersedes it, and the next removal rewrites it. One row per (tenant, user),
-- written by `remove_membership` in the removing transaction.
CREATE TABLE membership_removals(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    user_id BLOB NOT NULL REFERENCES users(id),
    removed_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, user_id)
) WITHOUT ROWID;

-- `organizations::create_self_service` refuses a name that matches the login of
-- a GitHub installation's account (bound or not). GitHub logins are
-- case-insensitive, organization names are lowercase, so the probe is on the
-- lowercase login.
CREATE INDEX installations_by_github_login
    ON installations(lower(account_login)) WHERE provider = 'github';
