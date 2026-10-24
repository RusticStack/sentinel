-- Read paths of the human web interface (U02, U04). Indexes only: no table
-- or row changes, so an older controller keeps working on this schema.

-- Run filters inside one repository, newest first: every filter is a range
-- on its own index ending in the page order, never a scan and sort.
-- `run_provenance` is WITHOUT ROWID, so each entry also carries `run_id`,
-- which is the keyset tie-break.
CREATE INDEX provenance_by_ref ON run_provenance(tenant_id, repo_id, ref_name, created_ms)
    WHERE ref_name IS NOT NULL;
CREATE INDEX provenance_by_pr ON run_provenance(tenant_id, repo_id, pr_number, created_ms)
    WHERE pr_number IS NOT NULL;
-- A SHA filter is a prefix range on the pinned commit; `runs` is WITHOUT
-- ROWID, so the entry carries `id` and `created_ms` is read from the index.
CREATE INDEX runs_by_sha ON runs(tenant_id, repo_id, source_sha, created_ms);

-- GitHub synchronization lag per tenant: what is still pending, what was
-- refused, and when each repository last published — each a range over
-- only the rows in that state.
CREATE INDEX check_publications_pending ON check_publications(tenant_id, repo_id, updated_ms)
    WHERE state = 0;
CREATE INDEX check_publications_refused ON check_publications(tenant_id, repo_id, settled_ms)
    WHERE state = 2;
CREATE INDEX check_publications_settled ON check_publications(tenant_id, repo_id, settled_ms)
    WHERE state = 1;

