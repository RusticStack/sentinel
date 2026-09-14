-- Durable event intake (G02). One authenticated ref-update or provider
-- webhook becomes one row here, deduplicated on (repository, provider,
-- delivery id) and settled by the bounded resolution lane. Nothing in this
-- path allocates compute: a run starts only after resolution (G03).

-- One active hook secret per repository, digest-only like every other
-- credential here. The relay presents the secret; the store keeps BLAKE3().
CREATE TABLE source_intake_tokens(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    created_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX intake_token_by_repo ON source_intake_tokens(repo_id);

-- State: 0 pending (accepted, awaiting resolution), 1 ready (source
-- validated; G03 consumes it), 2 ignored (a valid event that is not a
-- trigger), 3 failed (an explicit outcome). Attempts and next_attempt bound
-- resolution retries; settled rows are never reopened.
CREATE TABLE webhook_deliveries(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 32),
    external_id TEXT NOT NULL CHECK(length(external_id) BETWEEN 1 AND 128),
    event TEXT NOT NULL CHECK(length(event) BETWEEN 1 AND 64),
    ref_name TEXT CHECK(ref_name IS NULL OR length(ref_name) BETWEEN 1 AND 1024),
    old_sha TEXT CHECK(old_sha IS NULL OR length(old_sha) BETWEEN 1 AND 64),
    new_sha TEXT CHECK(new_sha IS NULL OR length(new_sha) BETWEEN 1 AND 64),
    state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2, 3)),
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 128),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_ms INTEGER,
    received_ms INTEGER NOT NULL,
    settled_ms INTEGER,
    CHECK((state = 0) = (settled_ms IS NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id),
    UNIQUE(tenant_id, repo_id, provider, external_id)
) WITHOUT ROWID;
-- The lane's only hot query: due pending rows, oldest first.
CREATE INDEX deliveries_due ON webhook_deliveries(next_attempt_ms) WHERE state = 0;
-- The admission bound: pending work per repository.
CREATE INDEX deliveries_pending_by_repo ON webhook_deliveries(repo_id) WHERE state = 0;
CREATE INDEX deliveries_by_repo ON webhook_deliveries(tenant_id, repo_id, received_ms);
-- Retention sweep over settled rows only.
CREATE INDEX deliveries_by_settled ON webhook_deliveries(settled_ms) WHERE state != 0;

-- What a delivery is cannot be rewritten by a later state change: only the
-- settlement fields move, and a settled delivery never returns to pending.
CREATE TRIGGER delivery_terms_immutable BEFORE UPDATE ON webhook_deliveries
WHEN NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.provider != OLD.provider OR NEW.external_id != OLD.external_id
  OR NEW.event != OLD.event OR NEW.ref_name IS NOT OLD.ref_name
  OR NEW.old_sha IS NOT OLD.old_sha OR NEW.new_sha IS NOT OLD.new_sha
  OR NEW.received_ms != OLD.received_ms
  OR (OLD.state != 0 AND NEW.state != OLD.state)
BEGIN
    SELECT RAISE(ABORT, 'delivery terms are immutable');
END;
