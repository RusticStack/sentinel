-- Attempt summaries (W04): what the worker measured, sent with the terminal
-- report and written once. The trigger is recreated to cover it: the summary
-- of a finished attempt cannot be replaced.
ALTER TABLE attempts ADD COLUMN summary BLOB CHECK(summary IS NULL OR length(summary) <= 32768);

DROP TRIGGER attempt_update;
CREATE TRIGGER attempt_update BEFORE UPDATE ON attempts BEGIN
    SELECT RAISE(ABORT, 'attempt terms are immutable') WHERE
        NEW.id != OLD.id OR NEW.job_id != OLD.job_id OR NEW.fence != OLD.fence OR
        NEW.worker_id != OLD.worker_id OR NEW.cpu_millis != OLD.cpu_millis OR
        NEW.memory_bytes != OLD.memory_bytes OR NEW.offered_ms != OLD.offered_ms OR
        (OLD.acked_ms IS NOT NULL AND NEW.acked_ms IS NOT OLD.acked_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.released_ms IS NOT OLD.released_ms) OR
        (OLD.released_ms IS NOT NULL AND NEW.lease_until_ms != OLD.lease_until_ms) OR
        (OLD.summary IS NOT NULL AND NEW.summary IS NOT OLD.summary);
END;
