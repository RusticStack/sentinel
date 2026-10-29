-- Domain auto-join runs when it can change something, not at every sign-in.
--
-- `auto_join_state.generation` names the rule set in force: `auto_join::set_rules`
-- raises it, in the same transaction, only when the stored rules actually change
-- (the controller rewrites them at every start). `users.auto_join_gen` is the
-- generation at which `auto_join::apply` last ran for that person once they were
-- eligible (admitted, active, with a verified address); 0 means never. A session
-- is issued with one conditional UPDATE on that column, and `apply` runs only
-- when the UPDATE changed the row: at a person's first eligible sign-in, and
-- again after the rule set changed. Verifying an address still calls `apply`
-- directly. Both are bookkeeping, never a grant: membership still comes only
-- from `apply` and its tombstone check.
--
-- The generation starts at 1, so every existing person is checked once at their
-- next sign-in after the upgrade.
CREATE TABLE auto_join_state(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    generation INTEGER NOT NULL CHECK(generation >= 1)
);
INSERT INTO auto_join_state(id, generation) VALUES (1, 1);
ALTER TABLE users ADD COLUMN auto_join_gen INTEGER NOT NULL DEFAULT 0;
