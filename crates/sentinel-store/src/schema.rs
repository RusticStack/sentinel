//! Versioned schema. Each migration runs once inside its own transaction and
//! is recorded in `schema_migrations`; the list is append-only. Every row
//! carries `tenant_id` so ownership is a column predicate, never a join the
//! caller can forget: all reads and writes filter by tenant.
//!
//! Encoding: IDs are 16-byte BLOBs (the raw UUID); state is one INTEGER
//! (`state_code`, see `codec`); timestamps are UTC milliseconds.

pub const MIGRATIONS: &[(u32, &str)] = &[(
    1,
    "CREATE TABLE tenants(
        id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
        slug TEXT NOT NULL UNIQUE,
        created_ms INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE repos(
        id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        name TEXT NOT NULL,
        created_ms INTEGER NOT NULL,
        UNIQUE(tenant_id, name)
    ) WITHOUT ROWID;

    CREATE TABLE runs(
        id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        repo_id BLOB NOT NULL REFERENCES repos(id),
        source_sha TEXT NOT NULL,
        created_ms INTEGER NOT NULL,
        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0, 1))
    ) WITHOUT ROWID;
    CREATE INDEX runs_by_repo ON runs(tenant_id, repo_id, created_ms);

    CREATE TABLE jobs(
        id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        run_id BLOB NOT NULL REFERENCES runs(id),
        name TEXT NOT NULL,
        state_code INTEGER NOT NULL,
        fence INTEGER NOT NULL DEFAULT 0,
        priority INTEGER NOT NULL,
        created_seq INTEGER NOT NULL,
        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0, 1)),
        failure_class INTEGER,
        queued_ms INTEGER, leased_ms INTEGER, preparing_ms INTEGER,
        running_ms INTEGER, finalizing_ms INTEGER, terminal_ms INTEGER,
        UNIQUE(run_id, name)
    ) WITHOUT ROWID;
    -- The dispatcher's only hot query: smallest (priority, created_seq) among ready jobs.
    CREATE INDEX jobs_ready ON jobs(priority, created_seq) WHERE state_code = 1;
    CREATE INDEX jobs_by_run ON jobs(run_id);

    CREATE TABLE attempts(
        id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        job_id BLOB NOT NULL REFERENCES jobs(id),
        fence INTEGER NOT NULL,
        worker_id BLOB NOT NULL CHECK(length(worker_id) = 16),
        lease_until_ms INTEGER NOT NULL,
        UNIQUE(job_id, fence)
    ) WITHOUT ROWID;
    CREATE INDEX attempts_by_lease ON attempts(lease_until_ms);",
)];
