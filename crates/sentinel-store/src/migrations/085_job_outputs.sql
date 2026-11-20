-- Declared outputs (I04). A job's steps write named values under a bound, and the job's own `outputs` re-export
-- them to the jobs that need it. The column holds them as plain text, `name=value` per line: an output is never a
-- secret, and every member of the tenant reads it with the run's record.
--
-- The bound is the schema's own: at most 16 outputs per job at most 1 KiB each, plus the names and newlines.
-- Nothing is backfilled, and one statement a controller below this version never reads or writes.
ALTER TABLE jobs ADD COLUMN outputs TEXT
    CHECK(outputs IS NULL OR length(outputs) <= 16384);
