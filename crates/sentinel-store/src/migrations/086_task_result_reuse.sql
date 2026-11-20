-- Task-result reuse (I06). A run may ask for fresh execution of every task it carries, which is a
-- property of the run rather than of its pipeline: the spec is written once and shared by every rerun,
-- so the request lives here and the dispatcher reads it into the job context.
--
-- Default 0: every run created before this migration, and every run that does not ask, behaves exactly
-- as it did. The controller refuses a fresh run's result sealing for this run only; it never touches an
-- entry another run sealed.
ALTER TABLE runs ADD COLUMN reuse_fresh INTEGER NOT NULL DEFAULT 0
    CHECK(reuse_fresh IN (0, 1));
