-- AI budgets and the analysis cache (Part 22 Y04). Advisory model output costs money, so a tenant
-- states what one calendar month may spend, what one request may take, and how many of its
-- requests may be in flight; `sentinel-ai` reserves each request's maximum against that ledger
-- before it contacts a provider and settles it from the usage the provider reports.
--
-- The ledger is `ai_ledger` (settled usage per tenant and month) plus `ai_reservations` (the
-- maximum one claimed request holds, released by its settlement or by its expiry). A reservation
-- expires with its request's deadline, so a killed AI process can hold budget for ten minutes and
-- never longer. `0` in either monthly column is no budget at all, as `tenant_quota_bytes` is no
-- quota; the per-request caps and the concurrency limit are always positive.
ALTER TABLE tenant_ai ADD COLUMN monthly_tokens INTEGER NOT NULL DEFAULT 0
    CHECK(monthly_tokens >= 0);
ALTER TABLE tenant_ai ADD COLUMN monthly_cost_micros INTEGER NOT NULL DEFAULT 0
    CHECK(monthly_cost_micros >= 0);
ALTER TABLE tenant_ai ADD COLUMN input_tokens_cap INTEGER NOT NULL DEFAULT 32000
    CHECK(input_tokens_cap > 0);
ALTER TABLE tenant_ai ADD COLUMN output_tokens_cap INTEGER NOT NULL DEFAULT 4096
    CHECK(output_tokens_cap > 0);
ALTER TABLE tenant_ai ADD COLUMN cost_micros_cap INTEGER NOT NULL DEFAULT 100000
    CHECK(cost_micros_cap > 0);
ALTER TABLE tenant_ai ADD COLUMN concurrency INTEGER NOT NULL DEFAULT 2
    CHECK(concurrency BETWEEN 1 AND 64);

-- What a tenant has been charged: the provider's reported usage, per calendar month (YYYYMM, UTC).
-- A reservation that settles adds here in the same write that releases it, so the ledger never
-- depends on a sweep having run.
CREATE TABLE ai_ledger(
    tenant_id BLOB NOT NULL REFERENCES tenants(id) CHECK(length(tenant_id) = 16),
    month INTEGER NOT NULL CHECK(month BETWEEN 197001 AND 999912),
    input_tokens INTEGER NOT NULL DEFAULT 0 CHECK(input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK(output_tokens >= 0),
    cost_micros INTEGER NOT NULL DEFAULT 0 CHECK(cost_micros >= 0),
    PRIMARY KEY(tenant_id, month)
) WITHOUT ROWID;

-- One claimed request's maximum, held before the provider is contacted. It names the analysis key
-- it will publish on success, so the settlement needs no second call to learn it. `expires_ms` is
-- the request's own deadline: a reservation cannot outlive the request that holds it.
CREATE TABLE ai_reservations(
    request_id BLOB PRIMARY KEY NOT NULL REFERENCES ai_requests(id) CHECK(length(request_id) = 16),
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    month INTEGER NOT NULL CHECK(month BETWEEN 197001 AND 999912),
    input_tokens INTEGER NOT NULL CHECK(input_tokens > 0),
    output_tokens INTEGER NOT NULL CHECK(output_tokens >= 0),
    cost_micros INTEGER NOT NULL CHECK(cost_micros >= 0),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    prompt_version TEXT NOT NULL CHECK(length(prompt_version) BETWEEN 1 AND 64),
    model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms)
) WITHOUT ROWID;

-- The budget check's two reads and the concurrency count's one.
CREATE INDEX ai_reservations_live ON ai_reservations(tenant_id, month, expires_ms);

-- What a repeated question costs nothing to answer: one analysis per tenant, evidence digest,
-- prompt version and model. `fingerprint` is the same failure across reruns — the normalized failed
-- step, test identities and error lines — so a rerun reuses the earlier analysis and says so.
CREATE TABLE ai_analyses(
    tenant_id BLOB NOT NULL CHECK(length(tenant_id) = 16),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    prompt_version TEXT NOT NULL CHECK(length(prompt_version) BETWEEN 1 AND 64),
    model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 8192),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL CHECK(expires_ms > created_ms),
    PRIMARY KEY(tenant_id, digest, prompt_version, model)
) WITHOUT ROWID;

-- The rerun lookup, and the bounded prune the consumer's poll runs.
CREATE INDEX ai_analyses_by_fingerprint ON ai_analyses(tenant_id, fingerprint, prompt_version, model);
CREATE INDEX ai_analyses_by_expiry ON ai_analyses(expires_ms);

-- A settled request says whether its answer was reused from the cache rather than computed here.
ALTER TABLE ai_requests ADD COLUMN reused INTEGER NOT NULL DEFAULT 0 CHECK(reused IN (0, 1));
