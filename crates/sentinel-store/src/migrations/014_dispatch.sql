-- Durable ready queue, resource reservations and fenced offers (W02).

-- What a job needs, copied from the compiled spec when the run is created so
-- placement never decodes a spec blob on the hot path.
ALTER TABLE jobs ADD COLUMN cpu_millis INTEGER NOT NULL DEFAULT 0 CHECK(cpu_millis >= 0);
ALTER TABLE jobs ADD COLUMN memory_bytes INTEGER NOT NULL DEFAULT 0 CHECK(memory_bytes >= 0);

-- What a worker has, as reported at its last hello. Not identity: it may
-- change between sessions and the immutability trigger does not cover it.
ALTER TABLE workers ADD COLUMN cpu_millis INTEGER NOT NULL DEFAULT 0 CHECK(cpu_millis >= 0);
ALTER TABLE workers ADD COLUMN memory_bytes INTEGER NOT NULL DEFAULT 0 CHECK(memory_bytes >= 0);

-- The reservation is the attempt: while `released_ms` is NULL the attempt
-- holds `cpu_millis`/`memory_bytes` of its worker. It is created with the
-- lease in one transaction and released with the attempt's end in another;
-- there is no separate row to forget.
ALTER TABLE attempts ADD COLUMN cpu_millis INTEGER NOT NULL DEFAULT 0 CHECK(cpu_millis >= 0);
ALTER TABLE attempts ADD COLUMN memory_bytes INTEGER NOT NULL DEFAULT 0 CHECK(memory_bytes >= 0);
ALTER TABLE attempts ADD COLUMN offered_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attempts ADD COLUMN acked_ms INTEGER;
ALTER TABLE attempts ADD COLUMN released_ms INTEGER;
-- Capacity held per worker: one indexed sum, no scan of finished attempts.
CREATE INDEX attempts_held_by_worker ON attempts(worker_id) WHERE released_ms IS NULL;
-- Offers awaiting acknowledgement, oldest first, for the ack-timeout sweep.
CREATE INDEX attempts_pending_ack ON attempts(offered_ms) WHERE acked_ms IS NULL AND released_ms IS NULL;

-- An attempt's identity, worker and reservation are fixed at the lease; an
-- acknowledgement or a release is recorded once and never undone.
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.job_id != OLD.job_id OR NEW.fence != OLD.fence OR
        NEW.worker_id != OLD.worker_id OR NEW.cpu_millis != OLD.cpu_millis OR
        NEW.memory_bytes != OLD.memory_bytes OR NEW.offered_ms != OLD.offered_ms OR
        (OLD.acked_ms IS NOT NULL AND NEW.acked_ms IS NOT OLD.acked_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.lease_until_ms != OLD.lease_until_ms);
END;
