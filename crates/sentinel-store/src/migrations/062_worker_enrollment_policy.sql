-- Controller-owned worker enrollment policy (Q11). An enrollment carries the
-- host ceilings and operator priority the controller approves; redeeming it
-- copies them onto the worker, which can never set them itself. Redemption
-- binds the TLS fingerprint and, for a Tailcat enrollment, the Tailcat node
-- key to one worker identity. An uninstall is a recorded request: the worker
-- is drained and revoked once its accepted work has settled.

-- NULL ceiling = the host's own report is the only limit.
ALTER TABLE worker_enrollments ADD COLUMN cpu_ceiling_millis INTEGER
    CHECK(cpu_ceiling_millis IS NULL OR cpu_ceiling_millis > 0);
ALTER TABLE worker_enrollments ADD COLUMN memory_ceiling_bytes INTEGER
    CHECK(memory_ceiling_bytes IS NULL OR memory_ceiling_bytes > 0);
ALTER TABLE worker_enrollments ADD COLUMN disk_ceiling_bytes INTEGER
    CHECK(disk_ceiling_bytes IS NULL OR disk_ceiling_bytes > 0);
ALTER TABLE worker_enrollments ADD COLUMN priority INTEGER NOT NULL DEFAULT 0
    CHECK(priority BETWEEN -100 AND 100);
-- 1: redemption must present the worker's Tailcat node key; 0: direct TLS only.
ALTER TABLE worker_enrollments ADD COLUMN tailcat INTEGER NOT NULL DEFAULT 0
    CHECK(tailcat IN (0, 1));

ALTER TABLE workers ADD COLUMN cpu_ceiling_millis INTEGER
    CHECK(cpu_ceiling_millis IS NULL OR cpu_ceiling_millis > 0);
ALTER TABLE workers ADD COLUMN memory_ceiling_bytes INTEGER
    CHECK(memory_ceiling_bytes IS NULL OR memory_ceiling_bytes > 0);
ALTER TABLE workers ADD COLUMN disk_ceiling_bytes INTEGER
    CHECK(disk_ceiling_bytes IS NULL OR disk_ceiling_bytes > 0);
ALTER TABLE workers ADD COLUMN priority INTEGER NOT NULL DEFAULT 0
    CHECK(priority BETWEEN -100 AND 100);
ALTER TABLE workers ADD COLUMN node_key BLOB
    CHECK(node_key IS NULL OR length(node_key) = 32);
ALTER TABLE workers ADD COLUMN uninstall_ms INTEGER;

-- A node key belongs to one identity for good: revoked rows keep theirs, so a
-- retired key can never be admitted again under another worker.
CREATE UNIQUE INDEX workers_by_node_key ON workers(node_key) WHERE node_key IS NOT NULL;

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
        (OLD.redeemed_ms IS NOT NULL AND NEW.redeemed_ms IS NULL) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;

-- Ceilings and priority change only through the controller's policy call;
-- identity, the node key and the pool stay fixed for the worker's life.
DROP TRIGGER worker_update;
CREATE TRIGGER worker_update BEFORE UPDATE ON workers BEGIN
    SELECT RAISE(ABORT, 'worker identity is immutable') WHERE
        NEW.id != OLD.id OR NEW.pool_id != OLD.pool_id OR
        NEW.fingerprint != OLD.fingerprint OR NEW.enrolled_ms != OLD.enrolled_ms OR
        NEW.node_key IS NOT OLD.node_key OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL) OR
        (OLD.uninstall_ms IS NOT NULL AND NEW.uninstall_ms IS NOT OLD.uninstall_ms);
END;

-- The controller's pass probes for pending uninstalls on every tick.
CREATE INDEX workers_uninstalling ON workers(uninstall_ms)
    WHERE uninstall_ms IS NOT NULL AND revoked_ms IS NULL;
