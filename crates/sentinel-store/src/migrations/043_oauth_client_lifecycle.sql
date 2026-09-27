-- Reclaimable, policy-gated OAuth client registration and an audit of run
-- control actions.

-- Which client registration mechanisms the deployment offers:
-- 0 none, 1 Client ID Metadata Documents only (the default), 2 CIMD and
-- RFC 7591 Dynamic Client Registration.
ALTER TABLE deployment_policy ADD COLUMN oauth_client_registration INTEGER NOT NULL DEFAULT 1
    CHECK(oauth_client_registration IN (0, 1, 2));

-- The rate-limit key (IPv4 address or IPv6 /64) that registered a DCR/CIMD
-- client, as a 16-byte BLAKE3 prefix: enough to bound registrations per
-- address, never the address itself.
ALTER TABLE oauth_clients ADD COLUMN registrant BLOB
    CHECK(registrant IS NULL OR length(registrant) = 16);
CREATE INDEX oauth_clients_by_registrant
    ON oauth_clients(registrant) WHERE registrant IS NOT NULL;

-- "Does this client hold anything?" (reclamation, eviction, disabling) and
-- the foreign-key checks of deleting a client are index searches.
CREATE INDEX oauth_grants_by_client ON oauth_grants(client_id);
CREATE INDEX oauth_codes_by_client ON oauth_codes(client_id);
CREATE INDEX oauth_device_by_client ON oauth_device_codes(client_id);

-- Only enabled registrations count toward the hard deployment bound: an
-- operator disabling abusive rows frees their capacity.
DROP TRIGGER oauth_mcp_client_policy;
CREATE TRIGGER oauth_mcp_client_policy BEFORE INSERT ON oauth_clients
WHEN NEW.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.resource != 2 OR NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        (NEW.max_scopes & ~71) != 0 OR
        (NEW.registration_kind = 1 AND NEW.metadata_url IS NOT NULL) OR
        (NEW.registration_kind = 2 AND NEW.metadata_url IS NULL);
    SELECT RAISE(ABORT, 'MCP OAuth client capacity reached') WHERE
        (SELECT count(*) FROM oauth_clients
         WHERE registration_kind != 0 AND disabled_ms IS NULL) >= 512;
END;

-- Append-only record of who cancelled or reran what: the acting account,
-- how it authenticated (1 API credential, 2 session, 3 OAuth access token,
-- 0 host-local administration), and for OAuth the grant and its client.
-- Grants and clients are purged later, so both are copied, not referenced.
-- action: 1 run cancel, 2 job cancel, 3 job rerun.
CREATE TABLE operation_audit(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    action INTEGER NOT NULL CHECK(action IN (1, 2, 3)),
    target BLOB NOT NULL CHECK(length(target) = 16),
    actor_user_id BLOB CHECK(actor_user_id IS NULL OR length(actor_user_id) = 16),
    via INTEGER NOT NULL CHECK(via IN (0, 1, 2, 3)),
    grant_id BLOB CHECK(grant_id IS NULL OR length(grant_id) = 16),
    client_id TEXT CHECK(client_id IS NULL OR length(client_id) BETWEEN 1 AND 64),
    CHECK((via = 3) = (grant_id IS NOT NULL)),
    CHECK((via = 0) = (actor_user_id IS NULL))
);
CREATE INDEX operation_audit_by_tenant ON operation_audit(tenant_id, seq);
CREATE TRIGGER operation_audit_immutable BEFORE UPDATE ON operation_audit BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;
CREATE TRIGGER operation_audit_undeletable BEFORE DELETE ON operation_audit BEGIN
    SELECT RAISE(ABORT, 'audit records are append-only');
END;
