-- The log-search assistant (Part 22 Y07). A request whose row names a question is answered from a
-- bounded plan of reads the controller already serves rather than from one attempt's bundle: an
-- indexed literal search across the repository's recent runs, and the failure context of attempts in
-- that repository, all executed under the requester's own authority.
--
-- `kind` is 1 for a failure analysis of the row's attempt (Y05) and 2 for a log-search question, and
-- `question` is present exactly when the kind is 2. Both columns default so a row an older binary
-- inserts stays a valid analysis row; nothing is backfilled.
ALTER TABLE ai_requests ADD COLUMN kind INTEGER NOT NULL DEFAULT 1 CHECK(kind IN (1, 2));
ALTER TABLE ai_requests ADD COLUMN question TEXT
    CHECK(question IS NULL OR length(question) BETWEEN 1 AND 512);
