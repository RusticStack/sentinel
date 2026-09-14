-- Event-driven run creation (G03). A resolved delivery either dispatches one
-- immutable run or settles with an explicit reason; the run records exactly
-- which event, which refs and which pipeline revision it came from.

-- `webhook_deliveries` gains `run_id` and the terminal `dispatched` state (4),
-- which SQLite cannot add to an existing CHECK, so the table is rebuilt with
-- its indexes and immutability trigger. Existing rows keep their state.
CREATE TABLE webhook_deliveries_new(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 32),
    external_id TEXT NOT NULL CHECK(length(external_id) BETWEEN 1 AND 128),
    event TEXT NOT NULL CHECK(length(event) BETWEEN 1 AND 64),
    ref_name TEXT CHECK(ref_name IS NULL OR length(ref_name) BETWEEN 1 AND 1024),
    old_sha TEXT CHECK(old_sha IS NULL OR length(old_sha) BETWEEN 1 AND 64),
    new_sha TEXT CHECK(new_sha IS NULL OR length(new_sha) BETWEEN 1 AND 64),
    state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2, 3, 4)),
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 128),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_ms INTEGER,
    received_ms INTEGER NOT NULL,
    settled_ms INTEGER,
    run_id BLOB REFERENCES runs(id),
    CHECK((state = 0) = (settled_ms IS NULL)),
    CHECK((state = 4) = (run_id IS NOT NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id),
    UNIQUE(tenant_id, repo_id, provider, external_id)
) WITHOUT ROWID;
INSERT INTO webhook_deliveries_new(id, tenant_id, repo_id, provider, external_id, event,
        ref_name, old_sha, new_sha, state, reason, attempts, next_attempt_ms, received_ms,
        settled_ms, run_id)
    SELECT id, tenant_id, repo_id, provider, external_id, event, ref_name, old_sha, new_sha,
        state, reason, attempts, next_attempt_ms, received_ms, settled_ms, NULL
    FROM webhook_deliveries;
DROP TABLE webhook_deliveries;
ALTER TABLE webhook_deliveries_new RENAME TO webhook_deliveries;
CREATE INDEX deliveries_due ON webhook_deliveries(next_attempt_ms) WHERE state IN (0, 1);
CREATE INDEX deliveries_pending_by_repo ON webhook_deliveries(repo_id) WHERE state IN (0, 1);
CREATE INDEX deliveries_by_repo ON webhook_deliveries(tenant_id, repo_id, received_ms);
CREATE INDEX deliveries_by_settled ON webhook_deliveries(settled_ms) WHERE state NOT IN (0, 1);
CREATE TRIGGER delivery_terms_immutable BEFORE UPDATE ON webhook_deliveries
WHEN NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.provider != OLD.provider OR NEW.external_id != OLD.external_id
  OR NEW.event != OLD.event OR NEW.ref_name IS NOT OLD.ref_name
  OR NEW.old_sha IS NOT OLD.old_sha OR NEW.new_sha IS NOT OLD.new_sha
  OR NEW.received_ms != OLD.received_ms
  OR (OLD.run_id IS NOT NULL AND NEW.run_id IS NOT OLD.run_id)
  OR (OLD.state NOT IN (0, 1) AND NEW.state != OLD.state)
BEGIN
    SELECT RAISE(ABORT, 'delivery terms are immutable');
END;

-- Pull-request metadata for a delivery. The delivery carries the base ref as
-- its `ref_name` (the branch whose policy the change targets); this table
-- carries what Git refs alone cannot prove: the number, action, head/base/tip
-- SHAs and the head repository, so fork provenance is a fact on record. The
-- row follows its delivery: retention of an ignored or failed delivery takes
-- its terms with it.
CREATE TABLE pr_deliveries(
    delivery_id BLOB PRIMARY KEY NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    number INTEGER NOT NULL CHECK(number > 0),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 32),
    draft INTEGER NOT NULL DEFAULT 0 CHECK(draft IN (0, 1)),
    head_ref TEXT NOT NULL CHECK(length(head_ref) BETWEEN 1 AND 512),
    head_sha TEXT NOT NULL CHECK(length(head_sha) = 40 OR length(head_sha) = 64),
    head_repo_id INTEGER NOT NULL CHECK(head_repo_id > 0),
    base_ref TEXT NOT NULL CHECK(length(base_ref) BETWEEN 1 AND 512),
    base_sha TEXT NOT NULL CHECK(length(base_sha) = 40 OR length(base_sha) = 64),
    merge_sha TEXT CHECK(merge_sha IS NULL OR length(merge_sha) = 40 OR length(merge_sha) = 64),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;
CREATE INDEX pr_deliveries_by_repo ON pr_deliveries(tenant_id, repo_id, number);
-- The terms prove trust; like the delivery they belong to, they are written
-- once and never rewritten, and they leave with the delivery.
CREATE TRIGGER pr_terms_insert BEFORE INSERT ON pr_deliveries BEGIN
    SELECT RAISE(ABORT, 'pull request ownership mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM webhook_deliveries d
        WHERE d.id = NEW.delivery_id AND d.tenant_id = NEW.tenant_id AND d.repo_id = NEW.repo_id);
END;
CREATE TRIGGER pr_terms_immutable BEFORE UPDATE ON pr_deliveries BEGIN
    SELECT RAISE(ABORT, 'pull request terms are immutable');
END;

-- What a run was created from: one immutable row per run, written in the same
-- transaction as the run. Manual dispatch has no delivery and no provider;
-- everything else names the delivery that produced it. `pipeline_sha` is the
-- revision the pipeline file was read from, which may differ from the checked
-- out revision.
CREATE TABLE run_provenance(
    run_id BLOB PRIMARY KEY NOT NULL REFERENCES runs(id),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    trigger TEXT NOT NULL CHECK(length(trigger) BETWEEN 1 AND 32),
    delivery_id BLOB UNIQUE REFERENCES webhook_deliveries(id),
    provider TEXT CHECK(provider IS NULL OR length(provider) BETWEEN 1 AND 32),
    ref_name TEXT CHECK(ref_name IS NULL OR length(ref_name) BETWEEN 1 AND 1024),
    old_sha TEXT CHECK(old_sha IS NULL OR length(old_sha) BETWEEN 1 AND 64),
    new_sha TEXT CHECK(new_sha IS NULL OR length(new_sha) BETWEEN 1 AND 64),
    head_sha TEXT CHECK(head_sha IS NULL OR length(head_sha) BETWEEN 1 AND 64),
    base_sha TEXT CHECK(base_sha IS NULL OR length(base_sha) BETWEEN 1 AND 64),
    merge_sha TEXT CHECK(merge_sha IS NULL OR length(merge_sha) BETWEEN 1 AND 64),
    pipeline_sha TEXT NOT NULL CHECK(length(pipeline_sha) BETWEEN 1 AND 64),
    pipeline_path TEXT CHECK(pipeline_path IS NULL OR length(pipeline_path) BETWEEN 1 AND 1024),
    pipeline_digest BLOB NOT NULL CHECK(length(pipeline_digest) = 16),
    pr_number INTEGER CHECK(pr_number IS NULL OR pr_number > 0),
    created_ms INTEGER NOT NULL,
    CHECK((delivery_id IS NULL) = (provider IS NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;
CREATE INDEX provenance_by_repo ON run_provenance(tenant_id, repo_id, created_ms);
CREATE TRIGGER provenance_owner_insert BEFORE INSERT ON run_provenance BEGIN
    SELECT RAISE(ABORT, 'provenance ownership mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM runs WHERE id = NEW.run_id AND tenant_id = NEW.tenant_id
          AND repo_id = NEW.repo_id);
    SELECT RAISE(ABORT, 'provenance delivery mismatch') WHERE NEW.delivery_id IS NOT NULL
      AND NOT EXISTS(
        SELECT 1 FROM webhook_deliveries d
        WHERE d.id = NEW.delivery_id AND d.tenant_id = NEW.tenant_id AND d.repo_id = NEW.repo_id);
END;
CREATE TRIGGER provenance_immutable BEFORE UPDATE ON run_provenance BEGIN
    SELECT RAISE(ABORT, 'run provenance is written once');
END;
CREATE TRIGGER provenance_undeletable BEFORE DELETE ON run_provenance BEGIN
    SELECT RAISE(ABORT, 'run provenance is written once');
END;
