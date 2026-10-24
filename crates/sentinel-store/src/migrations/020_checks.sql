-- The GitHub Checks outbox (G04). One row per (run, scope) or per refused
-- event: what GitHub should be told, coalesced to the newest desired state,
-- with the publication cursor that makes retries and stale writes safe.
--
-- This table is provider-independent on purpose: `name`, `head_sha` and the
-- output text are generated here, and a publisher turns them into whatever
-- the forge wants. Generic Git runs create no rows at all.

CREATE TABLE check_publications(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    run_id BLOB REFERENCES runs(id),
    delivery_id BLOB REFERENCES webhook_deliveries(id),
    -- 'aggregate' for the stable required check, a job ID for a per-job one.
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 64),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    head_sha TEXT NOT NULL CHECK(length(head_sha) = 40 OR length(head_sha) = 64),
    -- What a rerequest (G05) or a reconciliation scan finds the row by.
    external_id TEXT NOT NULL CHECK(length(external_id) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('queued', 'in_progress', 'completed')),
    conclusion TEXT CHECK(conclusion IS NULL OR length(conclusion) BETWEEN 1 AND 32),
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 128),
    summary TEXT NOT NULL CHECK(length(summary) BETWEEN 1 AND 1024),
    -- The forge's own handle once a check run exists.
    check_run_id INTEGER CHECK(check_run_id IS NULL OR check_run_id > 0),
    -- Desired generation and the one actually delivered; a late publisher can
    -- never overwrite a newer state because its guarded write matches `seq`.
    seq INTEGER NOT NULL CHECK(seq >= 1),
    published_seq INTEGER NOT NULL DEFAULT 0 CHECK(published_seq >= 0 AND published_seq <= seq),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_ms INTEGER,
    -- 0 pending, 1 published at `seq`, 2 refused permanently (with `reason`).
    state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2)),
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 128),
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    settled_ms INTEGER,
    CHECK((conclusion IS NULL) = (status != 'completed')),
    CHECK((state = 0) = (settled_ms IS NULL)),
    CHECK((run_id IS NULL) != (delivery_id IS NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX check_publications_run ON check_publications(run_id, scope) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX check_publications_delivery ON check_publications(delivery_id) WHERE delivery_id IS NOT NULL;
CREATE INDEX check_publications_due ON check_publications(next_attempt_ms) WHERE state = 0;
CREATE INDEX check_publications_repo ON check_publications(tenant_id, repo_id, created_ms);

-- The identity of a check is what a forge and an operator key on: it never
-- changes. Only the desired payload, the attempts and the cursor move.
CREATE TRIGGER check_identity_immutable BEFORE UPDATE ON check_publications
WHEN NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.run_id IS NOT OLD.run_id OR NEW.delivery_id IS NOT OLD.delivery_id
  OR NEW.scope != OLD.scope OR NEW.name != OLD.name OR NEW.head_sha != OLD.head_sha
  OR NEW.external_id != OLD.external_id OR NEW.created_ms != OLD.created_ms
BEGIN
    SELECT RAISE(ABORT, 'check identity is immutable');
END;

-- A publication belongs to the run (or delivery) it names, in the same tenant
-- and repository; nothing else can be published for it.
CREATE TRIGGER check_owner_insert BEFORE INSERT ON check_publications BEGIN
    SELECT RAISE(ABORT, 'check ownership mismatch') WHERE NEW.run_id IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM runs r
        WHERE r.id = NEW.run_id AND r.tenant_id = NEW.tenant_id AND r.repo_id = NEW.repo_id);
    SELECT RAISE(ABORT, 'check ownership mismatch') WHERE NEW.delivery_id IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM webhook_deliveries d
        WHERE d.id = NEW.delivery_id AND d.tenant_id = NEW.tenant_id AND d.repo_id = NEW.repo_id);
END;
