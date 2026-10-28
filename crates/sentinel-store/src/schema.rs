//! Global human identities are authorized through live memberships; a tenant predicate alone is not authorization.

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
    (18, include_str!("migrations/018_intake.sql")),
    (19, include_str!("migrations/019_dispatch.sql")),
    (20, include_str!("migrations/020_checks.sql")),
    (21, include_str!("migrations/021_github_reconcile.sql")),
    (22, include_str!("migrations/022_ref_polling.sql")),
    (23, include_str!("migrations/023_objects.sql")),
    (24, include_str!("migrations/024_uploads.sql")),
    (25, include_str!("migrations/025_artifacts.sql")),
    (26, include_str!("migrations/026_log_state.sql")),
    (27, include_str!("migrations/027_storage.sql")),
    (28, include_str!("migrations/028_fleet.sql")),
    (29, include_str!("migrations/029_ready_indexes.sql")),
    (30, include_str!("migrations/030_oauth.sql")),
    (31, include_str!("migrations/031_foundation_hardening.sql")),
    (32, include_str!("migrations/032_auth_hardening.sql")),
    (33, include_str!("migrations/033_intake_hardening.sql")),
    (34, include_str!("migrations/034_storage_hardening.sql")),
    (35, include_str!("migrations/035_fleet_scheduling.sql")),
    (36, include_str!("migrations/036_image_prefetch.sql")),
    (37, include_str!("migrations/037_sign_in_return.sql")),
    (38, include_str!("migrations/038_secrets.sql")),
    (39, include_str!("migrations/039_secret_idempotency.sql")),
    (
        40,
        include_str!("migrations/040_secret_delivery_capability.sql"),
    ),
    (41, include_str!("migrations/041_mcp_audience.sql")),
    (
        42,
        include_str!("migrations/042_mcp_client_registration.sql"),
    ),
    (
        43,
        include_str!("migrations/043_oauth_client_lifecycle.sql"),
    ),
    (44, include_str!("migrations/044_secret_hardening.sql")),
    (45, include_str!("migrations/045_web_ui.sql")),
    (46, include_str!("migrations/046_retention.sql")),
    (47, include_str!("migrations/047_s3.sql")),
    (48, include_str!("migrations/048_upgrades.sql")),
    (49, include_str!("migrations/049_reapply_indexes.sql")),
    (50, include_str!("migrations/050_email_identity.sql")),
    (51, include_str!("migrations/051_github_membership.sql")),
    (52, include_str!("migrations/052_setup.sql")),
    (53, include_str!("migrations/053_auto_join.sql")),
    (54, include_str!("migrations/054_job_runtime.sql")),
    (
        55,
        include_str!("migrations/055_session_grant_provenance.sql"),
    ),
    (56, include_str!("migrations/056_reserved_for_merge.sql")),
    (57, include_str!("migrations/057_link_admission.sql")),
];

pub const LATEST: u32 = MIGRATIONS[MIGRATIONS.len() - 1].0;

// List a migration only when an older binary can neither break it nor be broken by it.
pub const READABLE_BY: &[(u32, u32)] = &[(45, 44), (48, 47), (49, 48), (52, 51), (53, 51)];

pub fn readable_by(version: u32) -> u32 {
    READABLE_BY
        .iter()
        .find(|(v, _)| *v == version)
        .map_or(version, |(_, r)| *r)
}

pub const READABLE_BY_SINCE: u32 = 48;

// `migrate` skips entries at or below the database version, so a misnumbered entry never applies there.
pub const fn contiguous_from_one(migrations: &[(u32, &str)]) -> bool {
    let mut i = 0;
    while i < migrations.len() {
        if migrations[i].0 as usize != i + 1 {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    contiguous_from_one(MIGRATIONS),
    "MIGRATIONS must be numbered 1..=N in order"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_versions_are_strictly_ascending_and_contiguous_from_one() {
        assert!(!MIGRATIONS.is_empty());
        assert!(contiguous_from_one(MIGRATIONS));
        for pair in MIGRATIONS.windows(2) {
            assert_eq!(pair[1].0, pair[0].0 + 1, "after {}", pair[0].0);
        }
        assert!(contiguous_from_one(&[]));
        assert!(contiguous_from_one(&[(1, ""), (2, "")]));
        for bad in [
            &[(2, "")][..],
            &[(1, ""), (3, "")],
            &[(1, ""), (1, "")],
            &[(2, ""), (1, "")],
            &[(1, ""), (2, ""), (2, "")],
        ] {
            assert!(
                !contiguous_from_one(bad),
                "{:?}",
                bad.iter().map(|m| m.0).collect::<Vec<_>>()
            );
        }
    }
}
