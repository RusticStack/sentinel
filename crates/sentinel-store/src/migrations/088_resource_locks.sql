-- Shared external-resource leases (I05). A job may declare that it needs a named thing outside
-- Sentinel to itself while it runs — a database, a staging host, a device. It is not a concurrency
-- group: a group orders the runs of one repository inside Sentinel, while a resource lives outside it
-- and is held across every repository of the tenant.
--
-- A hold is a lease whose owner is an attempt and whose deadline is that attempt's lease. Nothing
-- writes a second deadline here, so a lock can never outlive the lease that justifies it, and a lease
-- that lapses makes its holds reclaimable with no sweep of its own: the attempt's fence is what
-- refuses the dead owner's later writes.

-- What one job declares: the resource's name and how long the job may wait for it, in milliseconds.
CREATE TABLE job_locks(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    job_id BLOB NOT NULL REFERENCES jobs(id),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    wait_ms INTEGER NOT NULL CHECK(wait_ms > 0),
    PRIMARY KEY(tenant_id, job_id, name)
) WITHOUT ROWID;
-- A waiting job is found from the resource it waits for, never by scanning every job that declares one.
CREATE INDEX job_locks_by_name ON job_locks(tenant_id, name, job_id);

-- The holder of one resource name under one tenant: at most one, which is the mutual exclusion itself.
-- The row outlives the hold, so an acquirer replaces the holder in place rather than growing the table,
-- and the fence it leaves behind names the attempt whose lease was running when the row was taken.
CREATE TABLE resource_locks(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    job_id BLOB NOT NULL REFERENCES jobs(id),
    run_id BLOB NOT NULL REFERENCES runs(id),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    fence INTEGER NOT NULL CHECK(fence > 0),
    acquired_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant_id, name)
) WITHOUT ROWID;

-- How many resources a job declares: the placement statement's guard, so a job that declares none
-- costs one integer compare and never probes the tables above.
ALTER TABLE jobs ADD COLUMN locks INTEGER NOT NULL DEFAULT 0 CHECK(locks >= 0);
-- The resource a job waited out its bound for, named on the job that failed for it and NULL on every
-- other job, so the reason stays readable after the lease that blocked it is gone.
ALTER TABLE jobs ADD COLUMN lock_wait TEXT CHECK(lock_wait IS NULL OR length(lock_wait) BETWEEN 1 AND 128);
