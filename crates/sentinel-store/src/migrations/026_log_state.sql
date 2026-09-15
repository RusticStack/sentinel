-- Attempt log durability at terminal publication (D05). `log_state` records
-- whether the attempt's `end` marker was durable when the job went terminal:
-- `pending` while the attempt is live, `complete` once the marker is durable
-- (written by the controller's `LogEnd` handling, which also holds the
-- protocol-5 acknowledgement until both the marker and this row have
-- committed), and `incomplete` when the terminal transition lands first —
-- worker loss, an acknowledged-but-dropped `LogEnd` on an older protocol, or
-- a flush timeout. `incomplete` may still upgrade to `complete` when a
-- retransmitted end lands from the owning worker, released or not; it never
-- regresses.
ALTER TABLE attempts ADD COLUMN log_state INTEGER NOT NULL DEFAULT 0 CHECK(log_state IN (0, 1, 2));

-- The terms trigger is recreated with the monotonic guard.
DROP TRIGGER attempt_update;
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.job_id != OLD.job_id OR NEW.fence != OLD.fence OR
        NEW.worker_id != OLD.worker_id OR NEW.cpu_millis != OLD.cpu_millis OR
        NEW.memory_bytes != OLD.memory_bytes OR NEW.offered_ms != OLD.offered_ms OR
        (OLD.acked_ms IS NOT NULL AND NEW.acked_ms IS NOT OLD.acked_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.lease_until_ms != OLD.lease_until_ms) OR
        (OLD.summary IS NOT NULL AND NEW.summary IS NOT OLD.summary) OR
        NEW.log_state < OLD.log_state;
END;
