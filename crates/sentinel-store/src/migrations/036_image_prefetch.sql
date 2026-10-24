-- K05 bounded image prefetch (B04).
--
-- A worker pulls `name@sha256:…`; the job row held only the digest, and the
-- name lived in the spec blob, which the controller must not decode per
-- queued job to hint a prefetch. The repository part of the job's image
-- reference is copied here at run creation, next to the digest it pairs
-- with. Rows created before this migration keep NULL and are simply never
-- hinted; nothing else reads the column.
ALTER TABLE jobs ADD COLUMN image_name TEXT
    CHECK(image_name IS NULL OR length(image_name) BETWEEN 1 AND 255);
