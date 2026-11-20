-- Durable AI requests (Part 22 Y03). One row is one question a tenant asked about one failed
-- attempt, and it is the only thing `sentinel-ai` consumes: the process lists, claims and settles
-- rows through the API and never reads a log, a secret or a run on its own account.
--
-- A row moves `queued` → `claimed` → `settled` and never back. `deadline_ms` is the row's own
-- bound: a request that nobody claimed or settled by then is settled `unavailable` by the sweep,
-- so a provider outage, a disabled tenant or a killed AI process leaves nothing in flight.
--
-- `requester_scopes` is the requester's scope set at the moment the row was created. The
-- delegation minted at claim time is that set intersected with the read-only scopes, so the
-- credential the AI process reads evidence with can never exceed the person who asked — see
-- `delegation_id`, which names the `api_tokens` row it minted and is the binding the evidence
-- route checks: a delegation reads its own request's attempt, and nothing after it settles.
CREATE TABLE ai_requests(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    repo_id BLOB NOT NULL REFERENCES repos(id),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    requester_id BLOB NOT NULL REFERENCES users(id),
    requester_scopes INTEGER NOT NULL CHECK(requester_scopes BETWEEN 1 AND 4294967295),
    -- The four providers of `sentinel_store::ai::Provider`, in its order.
    provider INTEGER NOT NULL CHECK(provider BETWEEN 0 AND 3),
    -- The data policy the row was admitted under, which is what a request must carry.
    data_policy INTEGER NOT NULL CHECK(data_policy BETWEEN 0 AND 2),
    -- 1 queued, 2 claimed, 3 settled.
    state_code INTEGER NOT NULL DEFAULT 1 CHECK(state_code IN (1, 2, 3)),
    -- 1 unavailable, 2 completed; present exactly when the row is settled.
    outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 2),
    -- Why there is no answer, or that the answer itself was stored.
    reason TEXT CHECK(reason IS NULL OR length(reason) BETWEEN 1 AND 512),
    -- The skeleton's answer (Y03). Y05 replaces it with a citation-checked analysis.
    result TEXT CHECK(result IS NULL OR length(result) <= 8192),
    delegation_id BLOB CHECK(delegation_id IS NULL OR length(delegation_id) = 16),
    created_ms INTEGER NOT NULL,
    deadline_ms INTEGER NOT NULL CHECK(deadline_ms > created_ms),
    claimed_ms INTEGER,
    lease_until_ms INTEGER,
    settled_ms INTEGER,
    CHECK((state_code = 3) = (outcome IS NOT NULL AND settled_ms IS NOT NULL)),
    CHECK(claimed_ms IS NULL OR claimed_ms >= created_ms)
) WITHOUT ROWID;

-- The consumer's only hot query: the oldest queued row.
CREATE INDEX ai_requests_queued ON ai_requests(state_code, created_ms);
CREATE INDEX ai_requests_by_tenant ON ai_requests(tenant_id, created_ms);
-- The evidence route's check: may this credential read this attempt?
CREATE INDEX ai_requests_by_delegation ON ai_requests(delegation_id)
    WHERE delegation_id IS NOT NULL;
