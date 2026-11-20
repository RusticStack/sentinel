-- The switch (H06). A repository that has proven itself in shadow mode moves to Sentinel by a
-- pull request that drops the shadow copies and moves the originals' labels (runner mode) or by
-- disabling the workflow jobs a native pipeline replaced (the native path). The native path also
-- changes the required status checks that gate a merge, and that write is the one thing here a
-- person would otherwise make by hand: it is therefore an opt-in of its own, off until an
-- administrator turns it on, and every settings write reads it in the same statement as the
-- migration switch.
ALTER TABLE tenants ADD COLUMN migration_settings INTEGER NOT NULL DEFAULT 0
    CHECK(migration_settings IN (0, 1));
