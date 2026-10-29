-- The GitHub App registered through GitHub's manifest flow (U17).
--
-- At most one row. Public facts are plain columns; the private key, the OAuth
-- client secret and the webhook secret are sealed with `master.key` under a
-- context naming the column and the App id, so no plaintext credential is
-- ever stored. A deployment configured by files never writes this table.
CREATE TABLE github_app(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    app_id INTEGER NOT NULL CHECK(app_id > 0),
    slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 100),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
    owner_id INTEGER NOT NULL CHECK(owner_id > 0),
    html_url TEXT NOT NULL CHECK(length(html_url) BETWEEN 1 AND 256),
    client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
    sealed_key BLOB NOT NULL,
    sealed_client_secret BLOB NOT NULL,
    sealed_webhook_secret BLOB,
    created_by BLOB NOT NULL REFERENCES users(id),
    created_ms INTEGER NOT NULL
);

-- Nothing about the App changes in place except a forward reseal of its sealed
-- values (to format 2 under a strictly newer key ID), as for every other
-- sealed column.
CREATE TRIGGER github_app_update BEFORE UPDATE ON github_app BEGIN
    SELECT RAISE(ABORT, 'GitHub App identity is immutable') WHERE
        NEW.app_id != OLD.app_id OR NEW.slug != OLD.slug OR NEW.name != OLD.name OR
        NEW.owner != OLD.owner OR NEW.owner_id != OLD.owner_id OR
        NEW.html_url != OLD.html_url OR NEW.client_id != OLD.client_id OR
        NEW.created_by != OLD.created_by OR NEW.created_ms != OLD.created_ms OR
        (NEW.sealed_webhook_secret IS NULL) != (OLD.sealed_webhook_secret IS NULL);
    SELECT RAISE(ABORT, 'sealed values only move forward') WHERE
        (NEW.sealed_key != OLD.sealed_key AND NOT (substr(NEW.sealed_key, 1, 1) = x'02'
            AND substr(NEW.sealed_key, 2, 4) > substr(OLD.sealed_key, 2, 4)))
        OR (NEW.sealed_client_secret != OLD.sealed_client_secret
            AND NOT (substr(NEW.sealed_client_secret, 1, 1) = x'02'
            AND substr(NEW.sealed_client_secret, 2, 4) > substr(OLD.sealed_client_secret, 2, 4)))
        OR (NEW.sealed_webhook_secret != OLD.sealed_webhook_secret
            AND NOT (substr(NEW.sealed_webhook_secret, 1, 1) = x'02'
            AND substr(NEW.sealed_webhook_secret, 2, 4) > substr(OLD.sealed_webhook_secret, 2, 4)));
END;

-- One-time `state` values of the manifest flow (purpose 1) and of an
-- installation for a tenant (purpose 2). Digest only; bound to the account and
-- the session that minted it and, for an installation, to the tenant; spent at
-- most once (`used_ms` never returns to NULL) and dead after `expires_ms`.
CREATE TABLE github_app_states(
    digest BLOB PRIMARY KEY NOT NULL CHECK(length(digest) = 32),
    purpose INTEGER NOT NULL CHECK(purpose IN (1, 2)),
    user_id BLOB NOT NULL REFERENCES users(id),
    session_id BLOB NOT NULL CHECK(length(session_id) = 16),
    tenant_id BLOB REFERENCES tenants(id),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    used_ms INTEGER,
    CHECK((purpose = 2) = (tenant_id IS NOT NULL))
) WITHOUT ROWID;
CREATE INDEX github_app_states_by_user ON github_app_states(user_id, created_ms);
CREATE INDEX github_app_states_by_expiry ON github_app_states(expires_ms);

CREATE TRIGGER github_app_state_update BEFORE UPDATE ON github_app_states BEGIN
    SELECT RAISE(ABORT, 'a GitHub App state is immutable once written') WHERE
        NEW.digest != OLD.digest OR NEW.purpose != OLD.purpose OR
        NEW.user_id != OLD.user_id OR NEW.session_id != OLD.session_id OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms OR
        (OLD.used_ms IS NOT NULL AND NEW.used_ms IS NOT OLD.used_ms);
END;
