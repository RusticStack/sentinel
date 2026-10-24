-- Fleet placement: disk, labels, arch, concurrency groups and drain (W03).

-- What a job needs beyond cpu/memory (014): the scratch disk it will occupy,
-- the architecture it is built for, the labels it selects workers by, and the
-- exclusion group it serializes within. `state_code = 1` jobs are the only
-- rows the fair queue reads, so the placement columns stay off that path
-- until a job is ready.
ALTER TABLE jobs ADD COLUMN disk_bytes INTEGER NOT NULL DEFAULT 0 CHECK(disk_bytes >= 0);
ALTER TABLE jobs ADD COLUMN arch TEXT;
ALTER TABLE jobs ADD COLUMN labels BLOB NOT NULL DEFAULT X'';
ALTER TABLE jobs ADD COLUMN concurrency_group TEXT;
-- Cancellation is cooperative: the request is recorded at once and the
-- controller reports when the attempt has actually begun winding down, so a
-- cancel that races the worker handoff is not lost.
ALTER TABLE jobs ADD COLUMN cancel_in_progress INTEGER NOT NULL DEFAULT 0 CHECK(cancel_in_progress IN (0, 1));
-- Why a ready job has not been placed: `wait_code` is the reason, `wait_detail`
-- the encoded specifics (the unsatisfied labels, the held group, ...). Both
-- are rewritten by the dispatcher as the reason changes.
ALTER TABLE jobs ADD COLUMN wait_code INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN wait_detail BLOB NOT NULL DEFAULT X'';

-- What a worker has, as reported at its last hello, like cpu_millis and
-- memory_bytes: mutable between sessions, not identity. `host_id` is the
-- machine hosting one or more workers, so a host-level failure can be told
-- apart from a single worker's; `drain_ms` marks a worker that must finish its
-- attempts and take no new offers; `avail_images` and `cache_bytes` describe
-- the images and warm cache it can offer; `load_ns` is its last reported load
-- input to placement.
ALTER TABLE workers ADD COLUMN disk_bytes INTEGER NOT NULL DEFAULT 0 CHECK(disk_bytes >= 0);
ALTER TABLE workers ADD COLUMN labels BLOB NOT NULL DEFAULT X'';
ALTER TABLE workers ADD COLUMN host_id BLOB;
ALTER TABLE workers ADD COLUMN drain_ms INTEGER;
ALTER TABLE workers ADD COLUMN avail_images BLOB NOT NULL DEFAULT X'';
ALTER TABLE workers ADD COLUMN cache_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE workers ADD COLUMN load_ns INTEGER NOT NULL DEFAULT 0;

-- Disk is reserved per attempt exactly as cpu and memory are: held from the
-- lease to the release, released with the attempt.
ALTER TABLE attempts ADD COLUMN disk_bytes INTEGER NOT NULL DEFAULT 0 CHECK(disk_bytes >= 0);

-- Per-run fair queueing inside a tenant: the oldest unplaced job of a run is
-- found without scanning the run's whole ready set.
CREATE INDEX jobs_fair ON jobs(tenant_id, run_id, created_seq) WHERE state_code = 1;
CREATE INDEX jobs_ready_tenant ON jobs(tenant_id, priority, queued_ms, created_seq) WHERE state_code = 1;
CREATE INDEX jobs_ready_large ON jobs(cpu_millis) WHERE state_code = 1 AND cpu_millis >= 8000;
CREATE INDEX attempts_held_by_tenant ON attempts(tenant_id) WHERE released_ms IS NULL;
-- Workers of a host, for host-scoped drain and failure sweeps.
CREATE INDEX workers_host ON workers(host_id) WHERE host_id IS NOT NULL;
-- Who holds an exclusion group, for admission of a job that asks for one.
CREATE INDEX jobs_conc ON jobs(tenant_id, concurrency_group) WHERE concurrency_group IS NOT NULL;

-- The terms trigger is recreated with the attempt's disk reservation guarded
-- alongside its other resources (026 carried the summary and log_state guards).
DROP TRIGGER attempt_update;
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.job_id != OLD.job_id OR NEW.fence != OLD.fence OR
        NEW.worker_id != OLD.worker_id OR NEW.cpu_millis != OLD.cpu_millis OR
        NEW.memory_bytes != OLD.memory_bytes OR NEW.disk_bytes != OLD.disk_bytes OR
        NEW.offered_ms != OLD.offered_ms OR
        (OLD.acked_ms IS NOT NULL AND NEW.acked_ms IS NOT OLD.acked_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.lease_until_ms != OLD.lease_until_ms) OR
        (OLD.summary IS NOT NULL AND NEW.summary IS NOT OLD.summary) OR
        NEW.log_state < OLD.log_state;
END;
