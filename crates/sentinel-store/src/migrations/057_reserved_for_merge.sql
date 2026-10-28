-- Reserved number. Migration 57 belongs to another lane of the same release;
-- this empty entry only keeps `MIGRATIONS` contiguous from one while the
-- api-auth lane builds on its own. The merge replaces it with that lane's
-- migration.
SELECT 1;
