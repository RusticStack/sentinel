-- Guided migration's write permissions (H01). A tenant migrates a repository by opening a pull
-- request that changes its `runs-on:` labels, which needs contents, pull requests and workflows
-- write on the one App. A tenant that never starts a migration keeps the base set: the bits are
-- carried here per installation, not asked of GitHub per request, and every base path mints the
-- narrowed tokens it always did.
--
-- The switch is off until an administrator turns it on, which is what asks for the three; while
-- it is off, no write path may use them.
ALTER TABLE tenants ADD COLUMN migration_mode INTEGER NOT NULL DEFAULT 0
    CHECK(migration_mode IN (0, 1));

-- What the last installation snapshot said this installation grants of what a migration writes
-- with: bit 0 contents write, bit 1 pull requests write, bit 2 workflows write. Kept here so a
-- withdrawal refuses the next write at once, without asking GitHub in the write path.
ALTER TABLE installations ADD COLUMN migration_permissions INTEGER NOT NULL DEFAULT 0
    CHECK(migration_permissions BETWEEN 0 AND 7);
