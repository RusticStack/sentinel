# Retention and quotas

Every byte Sentinel stores is bounded twice: by **size** (a quota, a budget or a watermark) and, for evidence, by **age** (a retention). This page is the whole map. Planned on top of it: a default tenant limit instead of unlimited, cache classes in tenant usage, soft/hard thresholds and notifications ([plan 16.3](../plan.md#163-default-tenant-storage-limits)), and artifact retention classes and pins ([plan 16.2](../plan.md#162-artifact-storage)). The disk admission gate, object reclamation and the orphan sweep it builds on are in [storage](storage.md#disk-admission-quotas-and-reclamation-d06).

## What is bounded, and by what

| Kind | Where | Size bound | Age bound | Collected by |
|---|---|---|---|---|
| Artifacts | controller objects | run budget, repository quota, tenant quota, deployment cap | the pipeline's `retain`, shortened to the effective artifact retention | artifact sweep, then reference-safe reclaim ([storage](storage.md#disk-admission-quotas-and-reclamation-d06)) |
| Uploads | controller objects | tenant quota, deployment cap; 4 GiB per session | session TTL ≤ 24 h; aborted rows kept 7 days | upload sweep; aborted-row purge |
| Attempt logs | controller `logs/` | `attempt_log_bytes` per attempt; counted in repository, tenant and deployment usage | the effective log retention | database-driven expiry, then the directory sweep |
| External S3 copy ([s3](s3.md)) | the bucket | the backlog budget closes admission; `local_bytes` bounds local copies of replicated objects | follows the local record: deleted after reclamation or log expiry | the replicator |
| Remote cache store | controller `remote-cache/` | `[remote_cache] budget_bytes`, least recently served first | — | its own reclamation thread, every 10 min |
| Local cache | worker `cache/` | `cache_budget_bytes`, least recently used, leased entries skipped | 14 days idle | the cache GC after every attempt ([cache](cache.md)) |
| Git mirrors | worker `mirrors/` | `mirror_budget_bytes`, least recently written, leased mirrors skipped | 14 days idle | the mirror sweep, same cadence ([mirrors](mirrors.md)) |
| Container images | worker image stores | `image_budget_bytes` per store, least recently pulled | — | the image sweep, at most every minute (below) |
| Log spools | worker `spool/` | `spool_quota_bytes`, `spool_reserve_bytes` | until acknowledged | spool delivery ([logs](logs.md)) |
| Everything on the controller disk | data file system | reserve, low/high watermarks, log floor | — | admission closes before the disk fills ([storage](storage.md#disk-admission-quotas-and-reclamation-d06)) |

## Policy at each level

The deployment's `[storage]` configuration ([configuration](configuration.md)) sets the defaults. A **storage policy** — one `storage_policies` row — overrides them for one tenant or one repository; a field left unset inherits:

| Level | Set by | Quota | Log retention | Artifact retention (the longest a pipeline may ask for) |
|---|---|---|---|---|
| Deployment | `[storage]`: `quota_bytes`, `tenant_quota_bytes`, `log_retention_secs`, `artifact_retention_secs`, `run_artifact_bytes`, `attempt_log_bytes` | cap on every tenant together, plus the default per tenant | 14 days | 90 days |
| Tenant | platform administration: `PUT /admin/tenants/{slug}/storage`, `admin tenant storage` | its own cap | any value 1 h – 366 d | any value 1 h – 366 d |
| Repository | the tenant's administration: `PUT /tenants/{slug}/repos/{name}/storage`, `admin tenant storage --repo` | a cap inside the tenant's (never above it) | only shorter than the tenant's | only shorter than the tenant's |
| Run | configuration | `run_artifact_bytes` of artifacts per run | — | — |

Retention only narrows going down: a repository's effective retention is the smaller of its own and its tenant's, so a tenant administrator can shorten how long a repository's evidence is kept but never keep it past what the platform allows the tenant. If the tenant's retention is later lowered below a repository's, the tenant's wins.

**What counts.** A tenant's usage is its committed objects, the declared length of its open uploads, and its stamped log bytes. A repository's is the logical bytes of its captured artifacts (before the tenant-wide deduplication, which is the tenant's saving, not the repository's) and its logs. The deployment's is every tenant's.

**What is refused.** An object or upload that would take a tenant past its quota, or the deployment past its cap, is `quota_exceeded` (403). An artifact whose repository is at its quota, or whose run is at `run_artifact_bytes`, is refused to the worker (`TooLarge`) and recorded as the artifact's failure, as the disk watermarks already did. **Logs are counted, never refused for quota**: a log is the evidence of what ran, and refusing it would hide a failure. They are bounded instead by `attempt_log_bytes` and their retention, and a disk below the log floor still refuses them ([storage](storage.md#disk-admission-quotas-and-reclamation-d06)).

## Log expiry is decided in the database

A log's deadline and its removal are recorded in the database, not read from file ages:

1. **Stamp.** Once an attempt is released, the maintenance pass reads its log's size from disk (off the writer) and stamps the row: `log_bytes` (added to the tenant's and repository's usage by trigger) and `log_expires_ms` — the release time plus the effective retention of its repository. Up to 16 batches of 256 per pass, oldest release first,, so a backlog catches up quickly.
2. **Expire.** Rows past their deadline (`attempts_log_expiry`) get `log_expired_ms` and `log_bytes = 0` in one transaction — the usage drops with it — re-checking the deadline, so a retention raised meanwhile keeps the log. The files are deleted after that commits.
3. **Sweep.** The bounded directory walk (`LogStore::sweep_dirs`) deletes what the rows no longer account for: a directory whose row says expired (a crash between commit and delete) or that no attempt row names at all. Open writers are never touched.

An expired log never comes back: the `attempt_update` trigger refuses to clear `log_expired_ms`, the worker link refuses late frames for it, and the API answers its page and search at once with `expired_ms` and no frames; the web interface says the log was removed by retention and when.

**Changing a policy applies to what is stored.** Setting a tenant's or repository's policy re-stamps the unexpired logs it covers to their new deadline (release plus the new retention — shorter or longer) and shortens artifact deadlines past the new artifact retention. The policy row and the first 512 rows commit in one transaction (`retention::set`); the rest is re-applied by `retention::finish_reapply`, in keyset order by row id and one write per 512 of the tenant's rows (logs first, then artifacts) read through the keyed indexes `attempts_log_reapply` and `artifacts_reapply` (migration 049), so what other tenants hold is never scanned, a policy change on a large tenant never holds the writer for its size, and each step is idempotent (the plans are described under [reapply plans](#reapply-plans)). The API and `sentinel admin tenant storage` run it before they answer; a crash between the set and the end of the re-stamping leaves the remaining rows on their previous deadlines until the policy is set again. A lowered retention therefore frees space on the next maintenance pass, not only for new runs. An artifact deadline is never extended: what a pipeline asked for is not recorded beyond its deadline.

### Reapply plans

A step is two statements built by `retention::reapply_sql`: the cursor bound (`SELECT id ... ORDER BY id LIMIT 1 OFFSET 511`) and the update confined to `(after, bound]`. Both name their index with `INDEXED BY`, which SQLite accepts on the partial index `attempts_log_reapply` as on `artifacts_reapply`, and both plan as `SEARCH ... (tenant_id=? AND id>? ...)`, with no `SCAN` of the data tables, no sort and no temporary set. A repository scope is applied inside that range: for logs a column filter, for artifacts a primary-key probe of the artifact's run (`EXISTS (SELECT 1 FROM runs WHERE id = artifacts.run_id AND ...)`). It was an `IN (SELECT id FROM runs ...)` subquery, which SQLite built into a set of every run of the repository on every batch, so a repository-scoped step cost the repository's runs and not its batch; no behavior changes, the cursor and the result are the same. The rows a step reads are therefore at most one batch of the tenant's candidate rows. A repository-scoped pass still walks the tenant's candidate rows to the end, because the cursor is the tenant's row order, but one write per batch at a time and linear in them once. No `(tenant_id, repo_id, id)` index is added: a policy change is a rare administrative act, and the extra index would cost every attempt write. `tests/retention.rs` asserts the plans and that the work of a two-row batch is the same at 4 and at 60 rows, scoped or not; a reapply measurement on a large table is still unmeasured.

**The artifact cap is a trigger.** The controller writes the deployment's limits to `storage_defaults` at every start, and an `artifacts` insert trigger shortens a new row's `retain_until_ms` to the effective artifact retention — whatever code path inserts it (a captured artifact, a failed one, the terminal publication's missing ones).

## Sizes chosen from the hardware

Fixed sizes fit one disk badly: 1 GiB of reserve is plenty on 50 GB and a rounding error on 2 TB, where one busy hour of logs outruns it. Unset sizes are therefore derived from the data file system (`statvfs` total) at start and logged (`storage_configured` on the controller, `worker_budgets` on a worker):

| Setting | Default | Clamp |
|---|---|---|
| reserve | a 64th of the disk | 1–16 GiB |
| low watermark (free above the reserve) | a 32nd | 2–32 GiB |
| high watermark | twice low | — |
| log floor | an eighth of the reserve | — |
| worker cache | a fifth | 1–50 GiB |
| worker mirrors | a tenth | 1–50 GiB |
| worker images (per store) | a fifth | 2–50 GiB |
| controller remote cache store | a tenth | 1–50 GiB |

The reference host (the verification VPS: 12 vCPU AMD EPYC 9645, 31 GiB, ext4 on a virtio disk) measures **1,080,795,422,720 bytes** (263,866,070 blocks of 4 KiB), which gives a 15.7 GiB reserve, closing at 31.5 GiB free above it and reopening at 63 GiB, a 2.0 GiB log floor, and 50 GiB for each worker and remote store. On 100 GiB a worker keeps 20 GiB of cache, 10 of mirrors and 20 of images, leaving half the disk to workspaces and spools. The worker stores together take at most half the disk by default.

**The reserve grows with the metadata database.** The reserve in force is the configured (or sized) one or twice the database's size on disk (main file plus write-ahead log), whichever is larger: room for the WAL to grow to the database's size before a checkpoint and for the database itself to keep growing, measured on every maintenance pass. `GET /admin/storage` and `admin objects status` report it.

Retention defaults (14 days of logs, 90 of artifacts) are policy, not hardware; 90 days caps what a pipeline's `retain` may ask for.

## Container images

A worker's images live in its shared rootless store and one private store per tenant ([executor](executor.md)). At most once a minute after an attempt, each store over `image_budget_bytes` gives up images least recently pulled first:

- only images no container uses (`podman images` reports the count; removal is never forced, so podman itself refuses one in use — `tests/podman.rs::an_image_a_container_holds_is_never_reclaimed` proves it against the real runtime);
- never a digest pulled for use in the last ten minutes (an attempt pulls, then creates its container) or one being pulled;
- at most 16 per store per pass.

The size is podman's per-image figure; layers shared between images count for each, so a store's sum errs high and it is trimmed early rather than late.

## Metadata housekeeping

- Aborted upload sessions are deleted a week after they expired; committed ones stay, because they authorize reads of the object they produced ([storage](storage.md#resumable-uploads-reads-and-materialization-d02)).
- Run, job and attempt rows and the audit trails are kept: they are the record of what ran and who did what, the audit tables refuse deletes by trigger, and a run's rows are small beside its logs. Their growth is what the metadata reserve tracks.

## Operating it

- `GET /admin/storage` (platform) and the web interface's **Platform → Storage**: the disk, the metadata database, the watermarks and reserve in force, whether admission is open, and everything tenants store against the deployment's limits.
- `GET /tenants/{slug}/storage` (tenant administration) and **Tenant admin → Storage**: the tenant's usage against its quota, its effective retention, and each repository's usage and policy, editable in place. **Platform → Tenants → Storage** edits a tenant's policy.
- Host-locally, beside a stopped controller: `sentinel admin tenant storage --tenant SLUG [--repo NAME] [--quota BYTES] [--log-retention 14d] [--artifact-retention 30d] [--inherit quota|log-retention|artifact-retention|all]` shows or changes a policy (validated against the limits the controller last started with); `admin objects status` reports free and total bytes, the metadata database and the reserve it needs, the watermarks this disk sizes, and per-tenant usage.

## Verification

Run on the verification VPS ([development](development.md#where-tests-run)).

- `crates/sentinel-store/tests/retention.rs`: a tenant's policy is platform administration and neither a member nor the tenant's administrator sets it; the tenant's administrator narrows a repository and a member cannot; a retention above the tenant's, a quota above the tenant's and an out-of-range value are refused; a tenant narrowed below its repository wins; an empty policy removes the row. A released log is stamped once with its bytes and deadline, counted in tenant and repository usage, not due a millisecond early, expired at its deadline with the usage freed, never due again, and cannot be un-expired; an attempt no row names is gone. The deployment cap shortens a year-long `retain` to 90 days on insert; lowering the tenant's retention re-stamps a stored log and shortens a stored artifact; a repository narrows further; raising again extends the log but never the artifact. The tenant quota counts log bytes (a commit and an upload refused), the deployment cap holds whatever the tenant's says, and a repository at its quota refuses another artifact byte. Aborted uploads go after a week and committed ones stay. The log sweep removes an expired log whose files a crash left and a directory no row names, and keeps a live one. The reapply statements plan as keyed index searches and a two-row batch costs the same virtual-machine steps at 4 and at 60 rows.
- `crates/sentinel-api/tests/web.rs`: `storage_policy_is_administered_per_level_and_an_expired_log_says_so` — who may read and set what, the narrowing rules over HTTP, the tenant and deployment reports, and an expired log's page and search; `the_maintenance_pass_stamps_expires_and_deletes_finished_logs` — the controller's own pass stamps a finished log with its measured bytes, and once its deadline passes records it expired, frees the usage and deletes the directory.
- `crates/sentinel/tests/cli.rs::admin_tenant_storage_shows_sets_and_inherits` and the service's `storage_defaults_and_validation` (sizing on 64 GiB, 1 TB, tiny and huge disks; every bound refused).
- Worker: `budgets_follow_the_disk_and_stay_clamped`, `the_image_listing_parses_and_skips_what_it_cannot_trust`, `reclamation_takes_the_least_recently_used_and_spares_what_is_in_use`, and the live `an_image_a_container_holds_is_never_reclaimed` (as the rootless `benchmark` account).
- `web/test/ui.mjs`: both storage pages pass the structure, keyboard, contrast and hydration checks of every other view, and a repository's log retention set from the storage page reaches the API exactly (the check caught the number field snapping 2 days to 2.05).
