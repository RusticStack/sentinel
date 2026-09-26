-- Keep newly scheduled secret-bearing jobs away from workers that predate
-- protocol 10. Capability-less workers may continue running ordinary jobs.
ALTER TABLE jobs ADD COLUMN requires_secret_delivery INTEGER NOT NULL DEFAULT 0
    CHECK(requires_secret_delivery IN (0, 1));
