-- The calling user of a manual run. A webhook run keeps it NULL: the provider's sender is display data
-- the sender chose, not a Sentinel principal. The write-once triggers on run_provenance are untouched;
-- ADD COLUMN does not fire them.
ALTER TABLE run_provenance ADD COLUMN actor_user_id BLOB
    CHECK(actor_user_id IS NULL OR length(actor_user_id) = 16);

-- An object whose PUT may have reached the bucket before its row said so. The replicator marks a window
-- of objects in one write before it sends them; the mark leaves with the row's `remote_ms` (in the
-- same transaction) or with the row itself. A row deleted while marked queues its S3 delete, so a crash
-- between the PUT and its record cannot leave a copy nothing will remove.
CREATE TABLE s3_puts(
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    PRIMARY KEY(tenant_id, digest)
) WITHOUT ROWID;
DROP TRIGGER s3_delete_object;
CREATE TRIGGER s3_delete_object AFTER DELETE ON objects
    WHEN OLD.remote_ms IS NOT NULL
      OR EXISTS(SELECT 1 FROM s3_puts WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest) BEGIN
    INSERT INTO s3_deletes(kind, tenant_id, digest, queued_ms)
        VALUES (0, OLD.tenant_id, OLD.digest, CAST(unixepoch('subsec') * 1000 AS INTEGER));
    DELETE FROM s3_puts WHERE tenant_id = OLD.tenant_id AND digest = OLD.digest;
END;

-- A rerequest finds the runs of a commit by repository and head; before this the lookup walked every row
-- of the repository's external ids on the single writer.
CREATE INDEX check_publications_head ON check_publications(repo_id, head_sha) WHERE run_id IS NOT NULL;
