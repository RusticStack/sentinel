-- Which tenants have been told their storage crossed the soft threshold and
-- have not fallen back under the re-arm line since (L04). A row is the arm
-- state: a controller that restarts reads it and tells nobody twice, and the
-- row's own numbers and channel are what the tenant's storage page shows. It
-- is removed when usage falls back, so the next crossing is told again.
CREATE TABLE storage_notices(
    tenant_id BLOB PRIMARY KEY REFERENCES tenants(id),
    threshold_percent INTEGER NOT NULL CHECK(threshold_percent BETWEEN 1 AND 100),
    used_bytes INTEGER NOT NULL CHECK(used_bytes >= 0),
    limit_bytes INTEGER NOT NULL CHECK(limit_bytes > 0),
    -- 1: queued to the tenant's administrators in the mail outbox; 2: the storage page only.
    delivery INTEGER NOT NULL CHECK(delivery IN (1, 2)),
    notified_ms INTEGER NOT NULL
) WITHOUT ROWID;

-- The outbox carries one more kind: the storage threshold notice (3). Every
-- other rule is unchanged, and rows already queued are copied, so a message in
-- flight across the upgrade is still delivered.
CREATE TABLE mail_outbox_next(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    -- 1 verification, 2 invitation, 3 storage threshold notice
    kind INTEGER NOT NULL CHECK(kind IN (1, 2, 3)),
    recipient TEXT NOT NULL CHECK(length(recipient) BETWEEN 3 AND 254),
    body BLOB CHECK(body IS NULL OR length(body) BETWEEN 1 AND 16384),
    -- 0 pending, 1 delivered to Resend, 2 given up (with `reason`)
    state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2)),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL,
    settled_ms INTEGER,
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 128),
    CHECK((state = 0) = (body IS NOT NULL)),
    CHECK((state = 0) = (settled_ms IS NULL))
) WITHOUT ROWID;
INSERT INTO mail_outbox_next(id, kind, recipient, body, state, attempts, next_attempt_ms,
    created_ms, expires_ms, settled_ms, reason)
    SELECT id, kind, recipient, body, state, attempts, next_attempt_ms, created_ms, expires_ms,
        settled_ms, reason
    FROM mail_outbox;
DROP TABLE mail_outbox;
ALTER TABLE mail_outbox_next RENAME TO mail_outbox;
CREATE INDEX mail_outbox_due ON mail_outbox(next_attempt_ms) WHERE state = 0;
CREATE INDEX mail_outbox_settled ON mail_outbox(settled_ms) WHERE state != 0;
CREATE INDEX mail_outbox_by_recipient ON mail_outbox(recipient, created_ms);
