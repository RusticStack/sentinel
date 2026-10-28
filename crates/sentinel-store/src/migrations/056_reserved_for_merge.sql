-- Reserved number. Migration 56 belongs to another lane of the same release;
-- this empty entry only keeps `MIGRATIONS` contiguous from one while the
-- dispatch-link lane builds on its own. The merge replaces it with that
-- lane's migration, and 057 stays the link-admission migration.
SELECT 1;
