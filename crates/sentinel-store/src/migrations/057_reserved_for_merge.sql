-- Reserved number. Migration 57 belongs to another lane of the same release;
-- this empty entry only keeps `MIGRATIONS` contiguous from one while the
-- host-mgmt lane builds on its own migration 60. The merge replaces it with
-- that lane's migration.
SELECT 1;
