-- Authoritative host policy (Q12). The controller-approved ceilings and the
-- operator priority already live on `workers` (migration 62); what a worker
-- *reports* about its own size is a different fact and is now kept apart from
-- what the controller *effectively* offers (`cpu_millis`, `memory_bytes`,
-- `disk_bytes`), which is always the report held under the ceilings.
--
-- Keeping the report lets a policy change recompute the effective size in both
-- directions at once: a reduction stops new oversubscription immediately and a
-- raise or removal takes effect without waiting for the worker's next capacity
-- report. 0 means the worker has not stated that size (for disk this is the
-- protocol's "unreported"); the effective size is then never raised above what
-- the controller already offers.
ALTER TABLE workers ADD COLUMN reported_cpu_millis INTEGER NOT NULL DEFAULT 0
    CHECK(reported_cpu_millis >= 0);
ALTER TABLE workers ADD COLUMN reported_memory_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(reported_memory_bytes >= 0);
ALTER TABLE workers ADD COLUMN reported_disk_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(reported_disk_bytes >= 0);

-- Existing rows: the effective size is the report only where no ceiling could
-- have reduced it; under a ceiling the report is unknown until the next hello.
UPDATE workers SET
    reported_cpu_millis = CASE WHEN cpu_ceiling_millis IS NULL THEN cpu_millis ELSE 0 END,
    reported_memory_bytes = CASE WHEN memory_ceiling_bytes IS NULL THEN memory_bytes ELSE 0 END,
    reported_disk_bytes = CASE WHEN disk_ceiling_bytes IS NULL THEN disk_bytes ELSE 0 END;

-- Authorizing a worker's Tailcat node key through its enrollment (Q11). An
-- administrator states, once, which worker identifier and which node key the
-- pending Tailcat enrollment is for. The controller admits that key to the
-- Tailcat helper for as long as the enrollment can still be redeemed, and
-- redemption binds exactly that key to exactly that worker identifier. The pair
-- is fixed once set; a withdrawn enrollment releases its key.
ALTER TABLE worker_enrollments ADD COLUMN authorized_worker BLOB
    CHECK(authorized_worker IS NULL OR length(authorized_worker) = 16);
ALTER TABLE worker_enrollments ADD COLUMN authorized_node_key BLOB
    CHECK(authorized_node_key IS NULL
          OR (length(authorized_node_key) = 32 AND authorized_worker IS NOT NULL));

CREATE UNIQUE INDEX worker_enrollments_by_node_key ON worker_enrollments(authorized_node_key)
    WHERE authorized_node_key IS NOT NULL AND revoked_ms IS NULL;
-- The controller's allow-list pass reads the keys of pending enrollments on every tick.
CREATE INDEX worker_enrollments_authorized ON worker_enrollments(expires_ms)
    WHERE authorized_node_key IS NOT NULL AND redeemed_ms IS NULL AND revoked_ms IS NULL;

DROP TRIGGER worker_enrollment_update;
CREATE TRIGGER worker_enrollment_update BEFORE UPDATE ON worker_enrollments BEGIN
    SELECT RAISE(ABORT, 'enrollment terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.id != OLD.id OR
        NEW.pool_id != OLD.pool_id OR NEW.created_ms != OLD.created_ms OR
        NEW.expires_ms != OLD.expires_ms OR
        NEW.cpu_ceiling_millis IS NOT OLD.cpu_ceiling_millis OR
        NEW.memory_ceiling_bytes IS NOT OLD.memory_ceiling_bytes OR
        NEW.disk_ceiling_bytes IS NOT OLD.disk_ceiling_bytes OR
        NEW.priority != OLD.priority OR NEW.tailcat != OLD.tailcat OR
        (OLD.authorized_node_key IS NOT NULL AND
         (NEW.authorized_node_key IS NOT OLD.authorized_node_key OR
          NEW.authorized_worker IS NOT OLD.authorized_worker)) OR
        (OLD.redeemed_ms IS NOT NULL AND NEW.redeemed_ms IS NULL) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;
