-- AI assistance policy (Part 22 Y01). Advisory model output is off unless two
-- administrators say otherwise: a platform administrator allows AI for the
-- deployment and names the providers it may use, and a tenant administrator then
-- opts one tenant in under a data policy. Neither side is on by default, so a
-- fresh deployment and one upgraded from any earlier schema both start off, and
-- the upgrade inserts nothing.
--
-- `ai_providers` is a set of the providers the deployment allows, one bit each in
-- the order the code names them (bit 0 the OpenAI-compatible local endpoint, 1
-- OpenRouter, 2 Anthropic, 3 OpenAI). Which providers exist belongs to the process
-- that can speak to them, so the column checks only that the value is a bit set: a
-- bit this schema does not know is read as a corrupt row, never as a migration, and
-- adding a provider later changes no stored shape.
ALTER TABLE deployment_policy ADD COLUMN ai_enabled INTEGER NOT NULL DEFAULT 0
    CHECK(ai_enabled IN (0, 1));
ALTER TABLE deployment_policy ADD COLUMN ai_providers INTEGER NOT NULL DEFAULT 0
    CHECK(ai_providers >= 0);

-- A tenant's opt-in and the data policy it commits to. No row is the default and
-- means off, so an upgraded tenant is off without a backfill. Disabling is an
-- update of this row in one transaction: the request queue Y03 adds is dropped in
-- that same transaction, so nothing is left queued waiting to expire.
CREATE TABLE tenant_ai(
    tenant_id BLOB PRIMARY KEY NOT NULL REFERENCES tenants(id)
        CHECK(length(tenant_id) = 16),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    data_policy INTEGER NOT NULL CHECK(data_policy IN (0, 1, 2)),
    updated_ms INTEGER NOT NULL,
    updated_by BLOB CHECK(updated_by IS NULL OR length(updated_by) = 16)
) WITHOUT ROWID;
