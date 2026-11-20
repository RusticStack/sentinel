-- Named pipelines (084). A delivery may now run every pipeline its document declares for that
-- event, so one delivery no longer produces at most one run: `run_provenance.delivery_id` keeps its
-- reference to the delivery and loses its uniqueness. Everything else about the table, its checks,
-- its indexes and its triggers is what migration 19, 45, 64 and 66 left.
--
-- The rebuild is the only way SQLite drops a column constraint. `DROP TABLE` does not fire the
-- table's own triggers, and every row is copied in the same transaction, so a run keeps exactly the
-- provenance it was written with.

CREATE TABLE run_provenance_084(
    run_id BLOB PRIMARY KEY NOT NULL REFERENCES runs(id),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    trigger TEXT NOT NULL CHECK(length(trigger) BETWEEN 1 AND 32),
    delivery_id BLOB REFERENCES webhook_deliveries(id),
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
    actor_user_id BLOB CHECK(actor_user_id IS NULL OR length(actor_user_id) = 16),
    group_ref TEXT CHECK(group_ref IS NULL OR length(group_ref) BETWEEN 1 AND 1024),
    CHECK((delivery_id IS NULL) = (provider IS NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;

INSERT INTO run_provenance_084(
    run_id, tenant_id, repo_id, trigger, delivery_id, provider, ref_name, old_sha, new_sha,
    head_sha, base_sha, merge_sha, pipeline_sha, pipeline_path, pipeline_digest, pr_number,
    created_ms, actor_user_id, group_ref)
SELECT run_id, tenant_id, repo_id, trigger, delivery_id, provider, ref_name, old_sha, new_sha,
       head_sha, base_sha, merge_sha, pipeline_sha, pipeline_path, pipeline_digest, pr_number,
       created_ms, actor_user_id, group_ref
  FROM run_provenance;

DROP TABLE run_provenance;
ALTER TABLE run_provenance_084 RENAME TO run_provenance;

CREATE INDEX provenance_by_repo ON run_provenance(tenant_id, repo_id, created_ms);
CREATE INDEX provenance_pr ON run_provenance(run_id) WHERE trigger = 'pull_request';
CREATE INDEX provenance_by_ref ON run_provenance(tenant_id, repo_id, ref_name, created_ms)
    WHERE ref_name IS NOT NULL;
CREATE INDEX provenance_by_pr ON run_provenance(tenant_id, repo_id, pr_number, created_ms)
    WHERE pr_number IS NOT NULL;
CREATE INDEX provenance_by_group_ref ON run_provenance(tenant_id, repo_id, group_ref, created_ms)
    WHERE group_ref IS NOT NULL;
-- The runs one delivery produced: every one of them, not only the one the delivery row names.
CREATE INDEX provenance_by_delivery ON run_provenance(delivery_id)
    WHERE delivery_id IS NOT NULL;

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
CREATE TRIGGER provenance_marks_pull_request AFTER INSERT ON run_provenance
WHEN NEW.trigger = 'pull_request' BEGIN
    UPDATE jobs SET pull_request = 1 WHERE run_id = NEW.run_id;
END;

-- The named pipeline a run belongs to. NULL is the document's unnamed pipeline, which is every run
-- created before this migration and every pipeline a document declares without `pipelines:`.
--
-- A run's check identity is derived from this name and its job names — `sentinel / ci` and
-- `sentinel / <job>` unnamed, `sentinel / <name>` and `sentinel / <name> / <job>` named — so the name
-- has to be durable and readable by every statement that records a publication. Its bound matches a
-- pipeline name's own (`[a-z0-9][a-z0-9_-]*`, at most 64 bytes).
ALTER TABLE runs ADD COLUMN pipeline TEXT
    CHECK(pipeline IS NULL OR length(pipeline) BETWEEN 1 AND 64);
