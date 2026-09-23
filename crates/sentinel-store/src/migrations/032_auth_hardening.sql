-- Part 03/09 audit: an account-level limit on second-factor guessing.
--
-- The per-session limit (migration 10) revokes a session after a handful of
-- wrong proofs, but anyone who holds the password can sign in again and
-- guess on. These count wrong TOTP and recovery-code proofs per account,
-- across every session: past the limit, every proof is refused until
-- `locked_until_ms` (even a correct one), and the account's sessions are
-- revoked. A correct proof resets the count; host-local password recovery
-- clears both. The existing `totp_update` trigger leaves them free to move.
ALTER TABLE mfa_totp ADD COLUMN failures INTEGER NOT NULL DEFAULT 0 CHECK(failures >= 0);
ALTER TABLE mfa_totp ADD COLUMN locked_until_ms INTEGER NOT NULL DEFAULT 0;
