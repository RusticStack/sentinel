-- Declared rollback compatibility and worker software versions (R05).

-- The oldest schema whose binary may keep running on a database after this
-- migration. A binary opening a database newer than itself runs on it when
-- every migration it does not know declares a `readable_by` it reaches, and
-- refuses it otherwise. Declared conservatively: only a migration that adds
-- nothing an older binary could break or be broken by (an index, a column no
-- older statement touches) is readable by the schema before it. Earlier
-- migrations are recorded as readable by their own version, except 45
-- (indexes only).
ALTER TABLE schema_migrations ADD COLUMN readable_by INTEGER;
UPDATE schema_migrations SET readable_by = version;
UPDATE schema_migrations SET readable_by = 44 WHERE version = 45;

-- The software a worker announced in its hello (`sentinel-worker/0.1.0`),
-- for skew reports; NULL until it next connects.
ALTER TABLE workers ADD COLUMN software TEXT
    CHECK(software IS NULL OR length(software) BETWEEN 1 AND 128);
