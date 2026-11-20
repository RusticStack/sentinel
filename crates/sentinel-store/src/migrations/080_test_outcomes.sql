-- Per-test outcomes from a job's own JUnit XML or Go test JSON report, one row per test identity and
-- attempt, for the flaky list (Y06). Bounded per repository when a row is written and expired with the
-- logs the report was parsed beside, so no repository grows without limit.
CREATE TABLE test_outcomes(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB NOT NULL REFERENCES repos(id),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    sha TEXT NOT NULL,
    identity TEXT NOT NULL CHECK(length(identity) BETWEEN 1 AND 514),
    suite TEXT,
    name TEXT NOT NULL,
    status INTEGER NOT NULL CHECK(status IN (0, 1, 2)),
    at_ms INTEGER NOT NULL,
    PRIMARY KEY(attempt_id, identity)
) WITHOUT ROWID;
-- A repository's rows, oldest first: the cap evicts from here and a report reads a window from here.
CREATE INDEX test_outcomes_by_repo ON test_outcomes(tenant_id, repo_id, at_ms);
-- Expiry walks the whole table by age, whatever the repository.
CREATE INDEX test_outcomes_by_age ON test_outcomes(at_ms);

-- One row per finished attempt whose reports the controller has not read yet: the reader's work is this
-- table, never a scan of every attempt a deployment ever ran, and a row leaves with the outcomes it
-- produced in the same transaction.
CREATE TABLE test_outcome_queue(
    attempt_id BLOB PRIMARY KEY NOT NULL CHECK(length(attempt_id) = 16),
    queued_ms INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX test_outcome_queue_due ON test_outcome_queue(queued_ms);
-- The flaky report reads one repository's window in identity and commit order, which this index answers
-- without a sort.
CREATE INDEX test_outcomes_by_test ON test_outcomes(tenant_id, repo_id, identity, sha, at_ms);
