-- Ready-queue index coverage the placement loop needs (Q09): the
-- pull-request probe joins run_provenance to jobs by run_id, and the
-- provenance side filters by trigger. Both partial indexes stay off the
-- write path for non-ready jobs.
CREATE INDEX jobs_ready_run ON jobs(run_id) WHERE state_code = 1;
CREATE INDEX provenance_pr ON run_provenance(run_id) WHERE trigger = 'pull_request';
