-- GitHub merge-queue deliveries. A `merge_group` event names the commits GitHub
-- has merged into its own queue branch; the delivery carries the base branch as
-- its `ref_name` (whose required checks the group is asked to satisfy), exactly
-- as a pull request does, and this table carries what the payload alone proves:
-- the queue branch the run is read from (which identifies the group, since it
-- embeds the base commit it was built on), the head and base commits GitHub
-- states, and the repository the head commit lives in. The row follows its
-- delivery and is written once; `reason` is the one mutable column, recording
-- why a destroyed group went away without rewriting the terms it came with.
CREATE TABLE merge_deliveries(
    delivery_id BLOB PRIMARY KEY NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 32),
    head_ref TEXT NOT NULL CHECK(length(head_ref) BETWEEN 1 AND 512),
    head_sha TEXT NOT NULL CHECK(length(head_sha) = 40 OR length(head_sha) = 64),
    base_ref TEXT NOT NULL CHECK(length(base_ref) BETWEEN 1 AND 512),
    base_sha TEXT NOT NULL CHECK(length(base_sha) = 40 OR length(base_sha) = 64),
    head_repo_id INTEGER NOT NULL CHECK(head_repo_id > 0),
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 64),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id, id)
) WITHOUT ROWID;
-- A group's deliveries are one range: its queue branch and base commit, which
-- is how a destroyed action answers the delivery that created the run.
CREATE INDEX merge_deliveries_by_group ON merge_deliveries(tenant_id, repo_id, head_ref, base_sha);
CREATE TRIGGER merge_terms_insert BEFORE INSERT ON merge_deliveries BEGIN
    SELECT RAISE(ABORT, 'merge group ownership mismatch') WHERE NOT EXISTS(
        SELECT 1 FROM webhook_deliveries d
        WHERE d.id = NEW.delivery_id AND d.tenant_id = NEW.tenant_id AND d.repo_id = NEW.repo_id);
END;
CREATE TRIGGER merge_terms_immutable BEFORE UPDATE ON merge_deliveries
WHEN NEW.delivery_id != OLD.delivery_id OR NEW.tenant_id != OLD.tenant_id
  OR NEW.repo_id != OLD.repo_id OR NEW.action != OLD.action
  OR NEW.head_ref != OLD.head_ref OR NEW.head_sha != OLD.head_sha
  OR NEW.base_ref != OLD.base_ref OR NEW.base_sha != OLD.base_sha
  OR NEW.head_repo_id != OLD.head_repo_id
  OR (OLD.reason IS NOT NULL AND NEW.reason IS NOT OLD.reason)
BEGIN
    SELECT RAISE(ABORT, 'merge group terms are immutable');
END;

-- The queue branch is provenance of its own: a run of a merge group records
-- where in GitHub's queue its commit came from, which no ref of the repository
-- proves and which ref polling therefore cannot reconstruct.
ALTER TABLE run_provenance ADD COLUMN group_ref TEXT
    CHECK(group_ref IS NULL OR length(group_ref) BETWEEN 1 AND 1024);
CREATE INDEX provenance_by_group_ref ON run_provenance(tenant_id, repo_id, group_ref, created_ms)
    WHERE group_ref IS NOT NULL;
