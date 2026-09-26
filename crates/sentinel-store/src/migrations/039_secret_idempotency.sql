-- Secret writes retain metadata-only results for safe retries. Request
-- fingerprints are never copied to secret_audit and values are not stored.
CREATE TABLE secret_idempotency(
    tenant_id BLOB NOT NULL REFERENCES tenants(id),
    principal TEXT NOT NULL,
    route TEXT NOT NULL,
    key TEXT NOT NULL CHECK(length(key) BETWEEN 1 AND 64),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=16),
    created_ms INTEGER NOT NULL,
    response_json BLOB NOT NULL CHECK(length(response_json) BETWEEN 2 AND 65536),
    PRIMARY KEY(tenant_id,principal,route,key)
) WITHOUT ROWID;
CREATE INDEX secret_idempotency_by_age ON secret_idempotency(created_ms);
