-- Existing repositories stay unbound; no URL or forge identity is inferred.
ALTER TABLE installations ADD COLUMN account_id INTEGER CHECK(account_id > 0);
ALTER TABLE installations ADD COLUMN account_personal INTEGER CHECK(account_personal IN (0,1));
ALTER TABLE installations ADD COLUMN permissions_valid INTEGER NOT NULL DEFAULT 0 CHECK(permissions_valid IN (0,1));
ALTER TABLE installations ADD COLUMN lifecycle_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE source_bindings(
    repo_id BLOB PRIMARY KEY NOT NULL,
    tenant_id BLOB NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    binding BLOB NOT NULL CHECK(length(binding) <= 32768),
    credential BLOB NOT NULL CHECK(length(credential) <= 32768),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
    installation_id BLOB REFERENCES installations(id),
    forge_repo_id INTEGER CHECK(forge_repo_id > 0),
    updated_ms INTEGER NOT NULL,
    CHECK((installation_id IS NULL) = (forge_repo_id IS NULL)),
    FOREIGN KEY(tenant_id, repo_id) REFERENCES repos(tenant_id,id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX source_forge_repo ON source_bindings(installation_id,forge_repo_id)
    WHERE installation_id IS NOT NULL;
CREATE TRIGGER source_owner_update BEFORE UPDATE ON source_bindings BEGIN
    SELECT RAISE(ABORT,'source ownership is immutable') WHERE
        NEW.repo_id != OLD.repo_id OR NEW.tenant_id != OLD.tenant_id;
END;
CREATE TABLE source_audit(
    seq INTEGER PRIMARY KEY,
    tenant_id BLOB NOT NULL,
    repo_id BLOB NOT NULL,
    version INTEGER NOT NULL,
    actor BLOB,
    action TEXT NOT NULL,
    at_ms INTEGER NOT NULL,
    FOREIGN KEY(tenant_id,repo_id) REFERENCES repos(tenant_id,id)
);
CREATE INDEX source_audit_repo ON source_audit(tenant_id,repo_id,seq);
