-- Verified email identity, email invitations and the mail outbox.
--
-- Not declared readable by 49: an older binary inserts `users` and
-- `invitations` rows without knowing these columns, its invitation-update
-- trigger is replaced here, and it would not maintain the new tables.

-- One email per account, normalized by the application (lower-case, IDN
-- domain in punycode). Uniqueness is among VERIFIED addresses only: a plain
-- UNIQUE would let anyone claim a victim's address unverified and lock the
-- owner out of registering it. First to verify wins; verification clears the
-- other accounts' unverified claim to the same address. An account's email
-- changes only by proving the new address (the old one stays until then), and
-- a verification never carries over to a different address.
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN email_verified_ms INTEGER;
CREATE UNIQUE INDEX users_verified_email ON users(email) WHERE email_verified_ms IS NOT NULL;
CREATE INDEX users_by_email ON users(email) WHERE email IS NOT NULL;

CREATE TRIGGER user_email_insert BEFORE INSERT ON users
WHEN NEW.email IS NOT NULL OR NEW.email_verified_ms IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'invalid email') WHERE
        NEW.kind != 0 OR NEW.email IS NULL OR length(NEW.email) NOT BETWEEN 3 AND 254
        OR NEW.email != lower(NEW.email) OR instr(NEW.email, '@') < 2
        OR NEW.email GLOB '*[^ -~]*' OR NEW.email GLOB '* *';
END;
CREATE TRIGGER user_email_update BEFORE UPDATE OF email, email_verified_ms ON users
WHEN NEW.email IS NOT NULL OR NEW.email_verified_ms IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'invalid email') WHERE
        NEW.kind != 0 OR NEW.email IS NULL OR length(NEW.email) NOT BETWEEN 3 AND 254
        OR NEW.email != lower(NEW.email) OR instr(NEW.email, '@') < 2
        OR NEW.email GLOB '*[^ -~]*' OR NEW.email GLOB '* *';
END;

-- Single-use, expiring proof of control of a mailbox. Digest only, like every
-- other secret here. `invitation` is an email-bound invitation that is spent
-- (and its membership granted) only when this very token verifies the address
-- the invitation names: the link token plus the verified mailbox.
CREATE TABLE email_verifications(
    token_digest BLOB PRIMARY KEY NOT NULL CHECK(length(token_digest) = 32),
    user_id BLOB NOT NULL REFERENCES users(id),
    email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
    invitation BLOB REFERENCES invitations(id),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    used_ms INTEGER
) WITHOUT ROWID;
CREATE INDEX email_verifications_by_user ON email_verifications(user_id, created_ms);
CREATE INDEX email_verifications_by_expiry ON email_verifications(expires_ms);
CREATE TRIGGER email_verification_update BEFORE UPDATE ON email_verifications BEGIN
    SELECT RAISE(ABORT, 'verification terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.user_id != OLD.user_id OR
        NEW.email != OLD.email OR NEW.invitation IS NOT OLD.invitation OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms OR
        (OLD.used_ms IS NOT NULL AND NEW.used_ms IS NOT OLD.used_ms);
END;

-- An invitation may be addressed to a mailbox. Immutable like every term.
ALTER TABLE invitations ADD COLUMN email TEXT CHECK(email IS NULL OR length(email) BETWEEN 3 AND 254);
CREATE INDEX invitations_by_email ON invitations(email) WHERE email IS NOT NULL;
DROP TRIGGER invitation_update;
CREATE TRIGGER invitation_update BEFORE UPDATE ON invitations BEGIN
    SELECT RAISE(ABORT, 'invitation terms are immutable') WHERE
        NEW.token_digest != OLD.token_digest OR NEW.id != OLD.id OR
        NEW.tenant_id IS NOT OLD.tenant_id OR NEW.role IS NOT OLD.role OR
        NEW.provider IS NOT OLD.provider OR NEW.subject IS NOT OLD.subject OR
        NEW.email IS NOT OLD.email OR
        NEW.created_ms != OLD.created_ms OR NEW.expires_ms != OLD.expires_ms OR
        (OLD.redeemed_ms IS NOT NULL AND NEW.redeemed_ms IS NULL) OR
        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS NULL);
END;

-- The durable mail queue: written in the transaction that mints the token,
-- drained by the mail lane, never sent from a request handler. The body
-- carries the link, so it is sealed with the master key and deleted the moment
-- the row settles: no readable link outlives its delivery. Rows exist only
-- when SMTP is configured and the master key is present; otherwise the
-- host-local CLI mints a link on demand.
CREATE TABLE mail_outbox(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    -- 1 verification, 2 invitation
    kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
    recipient TEXT NOT NULL CHECK(length(recipient) BETWEEN 3 AND 254),
    body BLOB CHECK(body IS NULL OR length(body) BETWEEN 1 AND 16384),
    -- 0 pending, 1 delivered to the relay, 2 given up (with `reason`)
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
CREATE INDEX mail_outbox_due ON mail_outbox(next_attempt_ms) WHERE state = 0;
CREATE INDEX mail_outbox_settled ON mail_outbox(settled_ms) WHERE state != 0;
CREATE INDEX mail_outbox_by_recipient ON mail_outbox(recipient, created_ms);

-- One row, rewritten by the controller at every start: whether this
-- deployment delivers mail, and the public base URL its links name. Read
-- inside the transaction that mints a token, so a message is queued only when
-- a lane will drain it.
CREATE TABLE mail_settings(
    id INTEGER PRIMARY KEY CHECK(id = 1),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    public_url TEXT CHECK(public_url IS NULL OR length(public_url) BETWEEN 1 AND 512),
    updated_ms INTEGER NOT NULL,
    CHECK(enabled = 0 OR public_url IS NOT NULL)
);
INSERT INTO mail_settings(id, enabled, public_url, updated_ms) VALUES (1, 0, NULL, 0);
