-- Operator-configured email-domain auto-join (SENTINEL_AUTO_JOIN_DOMAINS).
--
-- The validated map from a canonical mail domain to the app-created
-- organization its verified members join, rewritten by the controller at every
-- start (like `mail_settings`) so any transaction that verifies an address or
-- opens a session reads the rules with one key probe. The table is the
-- *current* configuration, never a membership record: removing a domain
-- deletes its row and stops new joins, and nobody who already joined is
-- removed. Nothing here grants access by itself; `auto_join::apply` decides
-- per person, per transaction.
CREATE TABLE auto_join_domains(
    domain TEXT PRIMARY KEY NOT NULL CHECK(length(domain) BETWEEN 3 AND 253),
    slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 63)
) WITHOUT ROWID;
