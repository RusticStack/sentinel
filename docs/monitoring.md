# Monitoring, readiness and diagnostic bundles (R06)

A controller answers three questions without a log search: *is it serving* (`GET /api/v1/ready`), *how is it doing* (`GET /metrics`), and *what does support need to know* (the diagnostic bundle). A worker can expose its own metrics on a loopback port.

## Readiness and liveness

| Route | Auth | Answers |
|---|---|---|
| `GET /api/v1/health` | none | liveness: the process answers HTTP. Nothing is checked |
| `GET /api/v1/ready` | none | readiness: `200` when not shutting down and the store both reads and commits; `503` otherwise |

`ready` returns codes only, nothing about tenants or data, so a load balancer or orchestrator can call it without a credential:

```json
{ "ready": true,
  "checks": { "stopping": false, "store_reads": true, "store_commits": true },
  "degraded": ["no_workers_connected"] }
```

A **degraded** code does not make the controller unready. It still serves, but an operator should know:

| Code | Means |
|---|---|
| `disk_below_watermark` | admission is closed on free space: new artifacts, uploads and work wait ([retention](retention.md)) |
| `external_copy_backlog` | admission is closed because the external S3 copy's backlog is past its budget ([s3](s3.md)) |
| `external_copy` | the replicator's last pass failed |
| `backup_failing` | the most recent scheduled backup failed ([backup](backup.md)) |
| `no_workers_connected` | no worker holds a control session |

The commit check writes an empty transaction through the single writer, so a stalled writer or a full disk shows as `503` rather than a controller that answers but cannot record anything.

## Controller metrics

`GET /metrics` (or `/api/v1/metrics`) returns the Prometheus text format, version 0.0.4. It needs a credential with `platform:admin` that belongs to a platform administrator: the figures describe the whole deployment. Issue a long-lived scraper token host-locally and give it only that scope:

```sh
sentinel admin token issue --data-dir /var/lib/sentinel --user root --name prometheus \
  --scope platform-admin --expires-in 365d
```

```yaml
scrape_configs:
  - job_name: sentinel
    metrics_path: /metrics
    authorization: { credentials_file: /etc/prometheus/sentinel-token }
    static_configs: [{ targets: ["ci.example.com:8080"] }]
```

No metric has a tenant, repository, user or worker label, so a scrape never names anything and the number of series stays fixed.

| Family | Type | What |
|---|---|---|
| `sentinel_build_info{version,schema}` | gauge | always 1 |
| `sentinel_process_resident_bytes`, `_cpu_seconds_total`, `_open_fds`, `_threads` | gauge/counter | this process, from `/proc/self` |
| `sentinel_http_requests_total{class}` | counter | answered requests by status class (`1xx`…`5xx`) |
| `sentinel_http_request_duration_seconds` | histogram | time until the answer starts (a streamed body's transfer time belongs to the client); buckets 1 ms … 5 s |
| `sentinel_auth_refusals_total{reason}` | counter | `unauthenticated` (401) and `forbidden` (403) answers. A rising rate is a probe or a revoked credential still in use |
| `sentinel_http_rate_limited_total` | counter | 429 answers from the admission budgets |
| `sentinel_http_parked_polls` | gauge | long polls parked right now |
| `sentinel_jobs_waiting{state}` | gauge | `queued` (ready) and `blocked` jobs |
| `sentinel_jobs_oldest_queued_seconds` | gauge | age of the oldest ready job |
| `sentinel_attempts_held` | gauge | attempts not yet released |
| `sentinel_workers{state}` | gauge | `enrolled`, `connected`, `draining` |
| `sentinel_link_events_total{event}` | counter | the worker link's counters: admissions, offers, lapses, expiries, log frames and refusals, placement and sweep errors, revoked sessions … |
| `sentinel_remote_cache_bytes`, `sentinel_log_writers_open` | gauge | the remote cache store and open attempt log writers |
| `sentinel_storage_free_bytes`, `_reserve_bytes`, `_inflight_bytes`, `_admission_open`, `_metadata_bytes`, `_stored_bytes` | gauge | disk, reserve, admission ([retention](retention.md)) |
| `sentinel_s3_healthy`, `_backlog_bytes`, `_backlog_full`, `_replicated_bytes_total`, `_consecutive_failures` | gauge/counter | the external copy, when configured ([s3](s3.md)) |
| `sentinel_backup_last_success_seconds`, `sentinel_backup_last_failed` | gauge | the backup scheduler, when configured ([backup](backup.md)) |
| `sentinel_github_check_publications{state}`, `sentinel_github_oldest_pending_seconds` | gauge | the GitHub Checks outbox: `pending` and `refused` publications, and the age of the oldest pending one ([checks](checks.md)) |

Suggested alerts: `sentinel_storage_admission_open == 0`; `sentinel_s3_healthy == 0` for 15 minutes; `time() - sentinel_backup_last_success_seconds` above twice the backup interval; `sentinel_jobs_oldest_queued_seconds` above your queue objective while `sentinel_workers{state="connected"} > 0`; `sentinel_github_oldest_pending_seconds > 600`; a 5xx rate above zero.

## Worker metrics

A worker exposes its own figures only when `metrics_listen` names a loopback address ([configuration](configuration.md)). Any other address is refused at start, so the listener is never reachable from the network. It answers `GET /metrics`, has no authentication, and names no tenant, repository or attempt. A scraper or agent on the same machine reads it.

| Family | What |
|---|---|
| `sentinel_worker_build_info{version}`, `sentinel_process_*` | version and the process's own figures |
| `sentinel_worker_connected`, `_connects_total`, `_disconnects_total` | the control session |
| `sentinel_worker_attempts_live`, `_attempts_started_total`, `_finished_total`, `_canceled_total`, `_handed_back_total`, `_abandoned_total`, `_leases_lost_total` | attempts |
| `sentinel_worker_spool_bytes`, `_spool_refusals_total`, `_reports_pending` | log spools: bytes held now, and attempts whose output was partly declared as gaps ([logs](logs.md)) |
| `sentinel_worker_cache_bytes`, `_cache_entries`, `_cache_sweeps_total` | the local cache, as its last sweep saw it |
| `sentinel_worker_images_held`, `_images_in_flight`, `_images_reclaimed_total` | the image store |
| `sentinel_worker_disk_free_bytes` | free space on the data directory's file system |

The executor figures (`attempts_live`, `spool_bytes`, `reports_pending`) are missing while the worker has no usable rootless runtime.

## Diagnostic bundles

A support request needs the deployment's shape, not its contents. The bundle (`sentinel.diagnostics-bundle/1`) has:

- the schema and, on request, SQLite's `quick_check`;
- row counts: tenants and suspended tenants, repositories, users, runs, jobs by state, attempts and held attempts, objects, manifests, artifacts by state, open uploads, check publications by state, webhook deliveries, secrets, sessions, API tokens;
- each live worker's operator-given name, architecture, protocol, software, enrolment and last-seen times, and drain state;
- the age of the oldest queued job;
- the last day's audit events, as counts by event code;
- the runtime: version, schema the binary expects, worker protocol range, OS and architecture, process figures, readiness, link and HTTP counters, storage and admission, the external copy's state and the backup scheduler's state (without its target path).

The bundle never includes names of tenants, repositories or people, email addresses, IP addresses, file paths, endpoints or bucket names, credentials or their digests, secret names, pipeline text or log text. `crates/sentinel-api/tests/web.rs` and `crates/sentinel-store/tests/upgrade.rs` check that seeded tenant, repository and person names are absent.

To get it:

- **Online:** `GET /api/v1/admin/diagnostics` as a platform administrator (`?integrity=1` adds the quick check, a full read of the database), for example `curl -H "authorization: Bearer $TOKEN" https://ci.example.com/api/v1/admin/diagnostics > bundle.json`.
- **Stopped controller:** `sentinel admin diagnostics --data-dir /var/lib/sentinel [--integrity]` opens the database read-only (it never migrates) and adds the database, WAL and free-space sizes and whether `master.key` is present.

Read the bundle before sending it: worker names are whatever the operator chose.

## Idle footprint

`bench/r06-idle.sh` starts a controller and one enrolled worker from scratch and lets them settle for a minute. It then measures, over ten idle minutes, each process's resident memory (sampled every 10 s) and the CPU time it and its reaped children used. Last, one scrape of each endpoint confirms both are live. The worker runs as an account with rootless Podman, so its executor, availability sweeps and heartbeats are all running. Results are in `bench/r06-idle.jsonl`:

| Process | Resident memory (max over the window) | CPU (share of one core) | Target |
|---|---|---|---|
| Controller | 21.2 MiB | 0.48 % | < 150 MiB |
| Worker (executor ready) | 15.9 MiB | 0.02 % | < 75 MiB |
| Both | 37.1 MiB | 0.50 % | < 1 % of a core |

Measured on 2026-09-28 on the verification VPS (AMD EPYC 9645, 12 vCPU, Ubuntu 26.04, kernel 7.0), release build, 600 s window. At the end, `/ready` answered ready with nothing degraded, and each process's metrics showed the other connected.

## Verification

`crates/sentinel-api/tests/web.rs` (`metrics_readiness_and_the_diagnostic_bundle`) covers the following:

- a wrong credential and an operator's credential are refused and counted;
- `/ready` answers without a credential and reports `no_workers_connected`;
- `/metrics` has its content type, the refusal, request, histogram, storage and build figures, one `# TYPE` per family, parseable samples and no tenant name;
- the online bundle passes `quick_check`, every count query succeeds, and it names no seeded tenant, repository or person.

`crates/sentinel-store/tests/upgrade.rs` (`the_offline_diagnostic_bundle_counts_without_naming`) checks that the offline bundle counts rows without naming them and leaves the database byte-for-byte unchanged. `worker_metrics::tests` checks that the worker listener answers `/metrics` with its counters and 404 for anything else.
