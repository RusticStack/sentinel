-- Storage thresholds (L03). A tenant's quota is enforced at a hard threshold and warned at a soft one,
-- both as percentages of the tenant's effective quota, so one policy serves every quota size: the
-- deployment sets the defaults here (80 % and the quota itself) and a tenant may narrow them.
-- The hard threshold is the enforced bound ([retention] `check_tenant`); the soft one refuses nothing.
ALTER TABLE storage_defaults ADD COLUMN soft_percent INTEGER NOT NULL DEFAULT 80
    CHECK(soft_percent BETWEEN 1 AND 100);
ALTER TABLE storage_defaults ADD COLUMN hard_percent INTEGER NOT NULL DEFAULT 100
    CHECK(hard_percent BETWEEN 1 AND 100);

-- One nullable pair per policy row: a repository row never carries them (a threshold is the tenant's),
-- and a tenant row that leaves one unset inherits the deployment's.
ALTER TABLE storage_policies ADD COLUMN soft_percent INTEGER
    CHECK(soft_percent IS NULL OR soft_percent BETWEEN 1 AND 100);
ALTER TABLE storage_policies ADD COLUMN hard_percent INTEGER
    CHECK(hard_percent IS NULL OR hard_percent BETWEEN 1 AND 100);

-- Why a failed artifact is missing: the refusal a controller recorded (the hard threshold's
-- `quota_exceeded` with used, limit and the largest classes). Only a failed row names one, and the
-- existing insert statements omit the column, so an older binary's row carries NULL and stays valid.
ALTER TABLE artifacts ADD COLUMN failure TEXT
    CHECK(failure IS NULL OR (state_code = 2 AND length(failure) BETWEEN 1 AND 512));
