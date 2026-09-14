//! Versioned schema. Each migration runs once inside its own transaction and
//! is recorded in `schema_migrations`; the list is append-only. Tenant-owned
//! rows carry tenant_id. Global human identities are authorized through live
//! memberships; a caller-supplied tenant predicate alone is not authorization.
//!
//! Encoding: IDs are 16-byte BLOBs (the raw UUID); state is one INTEGER
//! (`state_code`, see `codec`); timestamps are UTC milliseconds.

pub const MIGRATIONS: &[(u32, &str)] = &[
    (
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
    ),
    (
        2,
        "-- The immutable compiled specification of a run: written once with the run,
    -- never updated. `digest` is the pipeline content digest for dedup/diagnostics.
    CREATE TABLE run_specs(
        run_id BLOB PRIMARY KEY NOT NULL REFERENCES runs(id),
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        digest BLOB NOT NULL CHECK(length(digest) = 16),
        format INTEGER NOT NULL,
        spec BLOB NOT NULL
    ) WITHOUT ROWID;
    -- Position of the job in the compiled pipeline; dependencies are read from the spec.
    ALTER TABLE jobs ADD COLUMN spec_index INTEGER NOT NULL DEFAULT 0;",
    ),
    (
        3,
        "-- Mutation idempotency, scoped to (tenant, principal, route); see sentinel-protocol.
    CREATE TABLE idempotency_keys(
        tenant_id BLOB NOT NULL REFERENCES tenants(id),
        principal TEXT NOT NULL,
        route TEXT NOT NULL,
        key TEXT NOT NULL CHECK(length(key) BETWEEN 1 AND 64),
        fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 16),
        created_ms INTEGER NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
        run_id BLOB REFERENCES runs(id),
        PRIMARY KEY(tenant_id, principal, route, key)
    ) WITHOUT ROWID;
    CREATE INDEX idempotency_by_age ON idempotency_keys(created_ms);",
    ),
    (4, include_str!("migrations/004_identity.sql")),
    (5, include_str!("migrations/005_local_auth.sql")),
    (6, include_str!("migrations/006_api_tokens.sql")),
    (7, include_str!("migrations/007_sign_in_state.sql")),
    (8, include_str!("migrations/008_registration.sql")),
    (9, include_str!("migrations/009_mfa.sql")),
    (10, include_str!("migrations/010_step_up_limit.sql")),
    (11, include_str!("migrations/011_tenancy.sql")),
    (12, include_str!("migrations/012_image_resolution.sql")),
    (13, include_str!("migrations/013_workers.sql")),
    (14, include_str!("migrations/014_dispatch.sql")),
    (15, include_str!("migrations/015_attempt_summary.sql")),
    (16, include_str!("migrations/016_lease_sweep.sql")),
    (17, include_str!("migrations/017_sources.sql")),
];
