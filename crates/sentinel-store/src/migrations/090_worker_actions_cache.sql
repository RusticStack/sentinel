-- Runner Mode's actions cache, accounted per tenant (L02 and L03). A worker host serves a job's
-- `actions/cache` and `setup-*` caches from its own NVMe; without a row for them nothing charges the
-- tenant that caused them, and the hard threshold cannot make them give way before its artifacts are
-- refused. One row per (worker, repository): the bytes that worker's `actions/cache` tree holds for
-- that repository, as the worker's own walk measured them.
--
-- A report replaces the rows its worker names and removes the ones it no longer does, so a repository
-- whose entries were evicted reads zero rather than its last figure. `tenant_usage.actions_cache_bytes`
-- is folded from this table in the same writer transaction as the report, because two workers can hold
-- the same tenant's repository and the class is their sum.
CREATE TABLE worker_actions_cache(
    worker_id BLOB NOT NULL CHECK(length(worker_id) = 16),
    repo_id BLOB NOT NULL CHECK(length(repo_id) = 16),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    updated_ms INTEGER NOT NULL,
    PRIMARY KEY(worker_id, repo_id)
) WITHOUT ROWID;

-- A tenant's total is the sum over the repositories it owns, so the fold reads by repository.
CREATE INDEX worker_actions_cache_repo ON worker_actions_cache(repo_id);

-- A report charges a repository only if one of the worker's runner leases ran it, which is one keyed probe.
CREATE INDEX runner_leases_worker_repo ON runner_leases(worker_id, repo_id);
