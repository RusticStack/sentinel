-- Index for revoking the service grants a user minted without a session.
-- Migration 55 indexed the session-attributed grants (`created_session IS NOT
-- NULL`); the statement for the rest (grants from before 55 and grants minted
-- by a non-session credential, `created_session IS NULL`, inside a time
-- window) had no index on `created_by` and read every unexpired grant through
-- `oauth_grants_by_expiry`. The partial index holds only live, unattributed
-- service grants, so a grant leaves it when it is revoked.
-- Index only: no statement of an older binary reads or writes anything new,
-- so this migration is declared readable by 55.
CREATE INDEX oauth_grants_by_unattributed_minter
    ON oauth_grants(created_by, created_ms)
    WHERE kind = 3 AND created_session IS NULL AND revoked_ms IS NULL;
