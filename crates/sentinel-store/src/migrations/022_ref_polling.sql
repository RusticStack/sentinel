-- Opt-in bounded ref polling (G07): per-repo schedules and durable
-- observation cursors. A cursor never advances without the intake it
-- produced committing in the same transaction.
CREATE TABLE poll_configs(
    repo_id BLOB PRIMARY KEY NOT NULL CHECK(length(repo_id) = 16),
    tenant_id BLOB NOT NULL,
    interval_ms INTEGER NOT NULL CHECK(interval_ms BETWEEN 10000 AND 86400000),
    refs TEXT NOT NULL CHECK(length(refs) <= 8192),
    next_poll_ms INTEGER NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures >= 0),
    last_error TEXT CHECK(last_error IS NULL OR length(last_error) <= 256),
    -- NULL until the first successful poll: initial discovery records the
    -- baseline silently and admits nothing.
    baseline_ms INTEGER,
    updated_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id,id)
) WITHOUT ROWID;
CREATE INDEX poll_due ON poll_configs(next_poll_ms);
CREATE TRIGGER poll_owner_update BEFORE UPDATE ON poll_configs BEGIN
    SELECT RAISE(ABORT,'poll ownership is immutable') WHERE
        NEW.repo_id != OLD.repo_id OR NEW.tenant_id != OLD.tenant_id;
END;
CREATE TABLE poll_observations(
    repo_id BLOB NOT NULL,
    tenant_id BLOB NOT NULL,
    ref_name TEXT NOT NULL CHECK(length(ref_name) BETWEEN 1 AND 1024),
    oid TEXT NOT NULL,
    peeled TEXT,
    -- The delivery this observation admitted, when it produced one;
    -- provenance only, deliveries purge on their own schedule.
    delivery_id BLOB,
    observed_ms INTEGER NOT NULL,
    PRIMARY KEY(repo_id, ref_name),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id,id)
) WITHOUT ROWID;
CREATE TRIGGER poll_observation_update BEFORE UPDATE ON poll_observations BEGIN
    SELECT RAISE(ABORT,'poll observation ownership is immutable') WHERE
        NEW.repo_id != OLD.repo_id OR NEW.tenant_id != OLD.tenant_id;
END;
