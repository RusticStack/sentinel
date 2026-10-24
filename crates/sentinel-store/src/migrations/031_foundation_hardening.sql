-- The compiled run spec is written once with its run and never updated
-- (C05). Ownership triggers already cover tenant_id/run_id; this makes the
-- whole row immutable, as the attempt summary and image digest already are,
-- so no maintenance path or bug can change what an attempt or rerun
-- executes. Deletion (with the run) is unaffected.
CREATE TRIGGER run_spec_immutable BEFORE UPDATE ON run_specs BEGIN
    SELECT RAISE(ABORT, 'run spec is immutable');
END;
