-- AI failure analysis (Part 22 Y05). An analysis is a model's answer decoded against
-- `sentinel.ai-analysis/1`: a summary and bounded claims, each citing evidence of the attempt it was
-- computed from. Its stored form needs no new column — a settled request already holds its answer in
-- `ai_requests.result`, and the cache already holds it in `ai_analyses.text`; the prompt version part
-- of that key moves, so no answer written before this schema is ever read as an analysis. This
-- migration adds only what automatic analysis needs.
--
-- A request is a member's (`origin` 1) or the controller's own for a failed job (`origin` 2). The one
-- unique index keeps a failure to one automatic request however often the sweep that writes it runs;
-- a member's requests are not constrained by it, so asking twice is still two rows.
ALTER TABLE ai_requests ADD COLUMN origin INTEGER NOT NULL DEFAULT 1
    CHECK(origin BETWEEN 1 AND 2);
CREATE UNIQUE INDEX ai_requests_automatic ON ai_requests(attempt_id) WHERE origin = 2;

-- Automatic analysis is off in a fresh deployment and in an upgraded one: the column defaults to 0 and
-- nothing is backfilled, so an administrator opts one tenant in with the AI policy it already sets.
ALTER TABLE tenant_ai ADD COLUMN auto_analysis INTEGER NOT NULL DEFAULT 0
    CHECK(auto_analysis IN (0, 1));

-- The sweep's own read: a job that ended failed and recent, in a tenant that asked for one. Partial,
-- so it holds the failed jobs alone and no write to any other state pays for it.
CREATE INDEX jobs_failed_on ON jobs(terminal_ms) WHERE state_code = 20;

-- The serve route's one read: the newest answered request about an attempt.
CREATE INDEX ai_requests_by_attempt ON ai_requests(attempt_id, settled_ms);
