-- The runtime a job states (`runs_on.os`, `runs_on.isolation`), as the worker
-- capability bits it requires (sentinel_protocol::negotiate::Capabilities):
-- 0 when it states neither, which keeps the earlier meaning (Linux, on any
-- executor). Not readable by older binaries: they would place a job that needs
-- a microVM or Windows worker on any worker.
ALTER TABLE jobs ADD COLUMN runtime INTEGER NOT NULL DEFAULT 0;
