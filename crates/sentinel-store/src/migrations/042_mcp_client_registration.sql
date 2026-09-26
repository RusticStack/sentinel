-- OAuth clients are distinct records from Sentinel users and tenant grants.
-- Static clients remain API clients; DCR and CIMD clients are public MCP clients.
ALTER TABLE oauth_clients ADD COLUMN resource INTEGER NOT NULL DEFAULT 1
    CHECK(resource IN (1, 2));
ALTER TABLE oauth_clients ADD COLUMN registration_kind INTEGER NOT NULL DEFAULT 0
    CHECK(registration_kind IN (0, 1, 2));
ALTER TABLE oauth_clients ADD COLUMN metadata_url TEXT
    CHECK(metadata_url IS NULL OR (length(metadata_url) BETWEEN 1 AND 2048
        AND registration_kind = 2));

CREATE UNIQUE INDEX oauth_client_metadata_url
    ON oauth_clients(metadata_url) WHERE metadata_url IS NOT NULL;
CREATE INDEX oauth_clients_by_registration
    ON oauth_clients(registration_kind, created_ms) WHERE registration_kind != 0;

-- Both registration mechanisms are MCP-only public clients with the limited
-- MCP scope set. Do not permit registration to create users, service clients,
-- device-flow clients, or privileged OAuth clients.
CREATE TRIGGER oauth_mcp_client_policy BEFORE INSERT ON oauth_clients
WHEN NEW.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.resource != 2 OR NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        (NEW.max_scopes & ~71) != 0 OR
        (NEW.registration_kind = 1 AND NEW.metadata_url IS NOT NULL) OR
        (NEW.registration_kind = 2 AND NEW.metadata_url IS NULL);
    SELECT RAISE(ABORT, 'MCP OAuth client capacity reached') WHERE
        (SELECT count(*) FROM oauth_clients WHERE registration_kind != 0) >= 512;
END;

-- A registered MCP client cannot later be converted into an API client or
-- gain device-flow, loopback wildcard, or administrative-scope authority.
-- Name/scope/redirect refreshes from a revalidated CIMD document remain legal.
CREATE TRIGGER oauth_mcp_client_policy_update BEFORE UPDATE ON oauth_clients
WHEN OLD.registration_kind != 0 BEGIN
    SELECT RAISE(ABORT, 'invalid MCP OAuth client policy') WHERE
        NEW.client_id != OLD.client_id OR NEW.resource != 2 OR
        NEW.first_party != 0 OR NEW.loopback != 0 OR
        NEW.redirect_path IS NOT NULL OR NEW.device != 0 OR
        NEW.registration_kind != OLD.registration_kind OR
        NEW.metadata_url IS NOT OLD.metadata_url OR
        (NEW.max_scopes & ~71) != 0;
END;

-- A grant, code or device authorization can only use the resource permitted
-- by its public client. API clients retain the migration-30 behavior.
CREATE TRIGGER oauth_grant_resource BEFORE INSERT ON oauth_grants BEGIN
    SELECT RAISE(ABORT, 'grant resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;
CREATE TRIGGER oauth_code_resource BEFORE INSERT ON oauth_codes BEGIN
    SELECT RAISE(ABORT, 'code resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;
CREATE TRIGGER oauth_device_resource BEFORE INSERT ON oauth_device_codes BEGIN
    SELECT RAISE(ABORT, 'device resource does not match its client') WHERE NOT EXISTS(
        SELECT 1 FROM oauth_clients WHERE client_id = NEW.client_id
            AND disabled_ms IS NULL AND resource = NEW.resource);
END;
