-- Durable image resolution before executable admission (audit gate C05/W03).
--
-- A run's spec is immutable and may name an image by tag only. What actually
-- runs is a digest on a platform, and that fact must be written once, durably,
-- before any worker is handed the job — so every attempt of the job, and every
-- rerun, uses the same bytes, and a spec's existence is never mistaken for
-- readiness to execute. Both columns live on the job row so the lease check is
-- a predicate on the row it already reads, not another lookup.
ALTER TABLE jobs ADD COLUMN image_digest TEXT
    CHECK(image_digest IS NULL OR (length(image_digest) = 71 AND image_digest LIKE 'sha256:%'));
ALTER TABLE jobs ADD COLUMN image_platform TEXT
    CHECK(image_platform IS NULL OR length(image_platform) BETWEEN 5 AND 64);

-- Written once. A pinned spec pre-fills the digest at creation; the platform
-- still comes from resolution. Neither ever changes afterwards.
CREATE TRIGGER job_image_written_once BEFORE UPDATE OF image_digest, image_platform ON jobs
WHEN (OLD.image_digest IS NOT NULL AND NEW.image_digest IS NOT OLD.image_digest)
  OR (OLD.image_platform IS NOT NULL AND NEW.image_platform IS NOT OLD.image_platform) BEGIN
    SELECT RAISE(ABORT, 'image resolution is written once');
END;
