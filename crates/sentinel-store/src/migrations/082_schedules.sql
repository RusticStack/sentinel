-- Durable UTC schedules (Part 16 I02). A schedule is a row, not a timer in a controller's memory:
-- `next_at_ms` is the first occurrence it has not settled yet, so a restart neither loses nor repeats
-- one. The cron is stored as written and parsed by the controller (`sentinel_pipeline::cron`), UTC
-- only, so no daylight-saving gap or repeated hour can move an occurrence.
--
-- An occurrence's instant is its identity: `schedule_occurrences` is keyed by (schedule, at_ms), so two
-- controllers computing the same due instant, a restart, or a clock step that crosses it again insert
-- one row and fire one run. `state` records what became of it — claimed, dispatched with `run_id`,
-- skipped because the previous run was still going, missed while the controller was down (with how
-- many instants the one row covers), or suspended with its tenant — so a skipped occurrence is
-- explained rather than silently absent.
CREATE TABLE schedules(
    repo_id BLOB PRIMARY KEY NOT NULL REFERENCES repos(id) CHECK(length(repo_id) = 16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id) CHECK(length(tenant_id) = 16),
    cron TEXT NOT NULL CHECK(length(cron) BETWEEN 1 AND 128),
    ref_name TEXT NOT NULL CHECK(length(ref_name) BETWEEN 1 AND 1024),
    -- 0 skips an occurrence whose previous run is still going, 1 cancels that run and starts this one.
    overlap INTEGER NOT NULL CHECK(overlap IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    next_at_ms INTEGER NOT NULL,
    last_at_ms INTEGER,
    last_run_id BLOB REFERENCES runs(id),
    updated_ms INTEGER NOT NULL
) WITHOUT ROWID;
-- The lane's only hot query: the next due occurrence among the schedules that are on.
CREATE INDEX schedules_due ON schedules(next_at_ms) WHERE enabled = 1;

CREATE TABLE schedule_occurrences(
    schedule_id BLOB NOT NULL REFERENCES schedules(repo_id),
    at_ms INTEGER NOT NULL,
    tenant_id BLOB NOT NULL REFERENCES tenants(id) CHECK(length(tenant_id) = 16),
    -- 1 claimed, 2 dispatched, 3 skipped for overlap, 4 missed while the controller was down,
    -- 5 suspended with its tenant, 6 failed to dispatch.
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4, 5, 6)),
    claimed_ms INTEGER,
    settled_ms INTEGER,
    run_id BLOB REFERENCES runs(id),
    -- Instants this one row accounts for beyond its own: the older occurrences of a catch-up.
    skipped INTEGER NOT NULL DEFAULT 0 CHECK(skipped >= 0),
    reason TEXT CHECK(length(reason) <= 64),
    PRIMARY KEY(schedule_id, at_ms)
) WITHOUT ROWID;
-- A claim that never settled is reclaimable after a crash: the sweep reads claims by age.
CREATE INDEX schedule_occurrences_by_claim ON schedule_occurrences(state, claimed_ms);
CREATE INDEX schedule_occurrences_by_run ON schedule_occurrences(run_id);
-- Expiry walks settled rows by age, whatever the schedule.
CREATE INDEX schedule_occurrences_by_age ON schedule_occurrences(settled_ms);
