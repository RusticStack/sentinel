# Release qualification

`scripts/qualify/qualify.sh` runs the whole release-qualification set against one commit and writes a single pass/fail record. It adds no new checks of its own: each stage is a group of existing test binaries and scripts, chosen by the question a release has to answer. A release is qualified when the record says `PASS` for the commit and packages being released, and not otherwise.

Scope is the v0.1 support set: native pipelines on rootless-Podman Linux workers ([release notes](release-notes.md#support-matrix)). Runner mode, microVMs and Windows are not gates of this record.

## Running it

Run it on a verification host ([development](development.md#where-tests-run)), from a **disposable checkout** (a git bundle or clone under `/var/tmp` or `/tmp`), never from a production checkout:

```sh
scripts/release/package.sh build --out /var/tmp/q/dist
scripts/release/package.sh assemble --out /var/tmp/q/dist
mkdir -p /var/tmp/q/pkg && for p in server worker; do tar -xzf /var/tmp/q/dist/sentinel-*-x86_64-linux-$p.tar.gz -C /var/tmp/q/pkg; done
scripts/qualify/qualify.sh --src . --out /var/tmp/q/record \
  --dist /var/tmp/q/dist \
  --server-pkg /var/tmp/q/pkg/sentinel-<version>-x86_64-linux-server \
  --worker-pkg /var/tmp/q/pkg/sentinel-<version>-x86_64-linux-worker
```

Run it as the unprivileged account that has rootless Podman (subordinate ids, a user runtime directory). As root, or on a host where `podman info` fails, the Podman stages are skipped and say why. Other behavior:

- It refuses a `--src` or `--out` under `/srv/sentinel` and an `--out` that is not empty. It writes only below `--out` and the checkout's `CARGO_TARGET_DIR`; it starts no production service and uses no production data.
- It checks `/proc/pressure/cpu` first and exits `4` (postponed, nothing ran) when `avg10` is above `--max-cpu-pressure` (default 25). It runs each stage under `nice -n 19 ionice -c3` with `CARGO_BUILD_JOBS` at most 6, and under `flock -x -o` on `/var/tmp/sentinel-verify.lock` (override with `SENTINEL_VERIFY_LOCK`) when `flock` exists (`-o` keeps a process a stage leaves behind from holding the lock after the stage returns; without `flock` it warns that the run is not serialized), so it serializes with other verification work.
- Long runs belong in the background with a log: `setsid nohup scripts/qualify/qualify.sh ... > run.log 2>&1 < /dev/null &`. Stop it by PID.
- `--only a,b` runs selected stages (`--list` names them). A selective run is `INCOMPLETE` by construction and never qualifies a release; it is for iterating on one stage.
- Fault injection stays where the underlying tests keep it: inside Sentinel's own processes, temporary directories and, for local operation, a private network namespace.

## The record

`--out` receives `qualification.json` (format `sentinel.qualification/1`), `stages.jsonl`, `verdict.txt` and one log per stage under `logs/`. The record names the commit, whether the tree was dirty, the kernel, machine and CPU pressure at start, and for every stage its status, duration and log path.

| Verdict | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | Every stage ran and passed |
| `FAIL` | 1 | A stage failed; the log path is in the record |
| `INCOMPLETE` | 3 | No stage failed, but a stage was skipped for a missing prerequisite (named in the record) or not selected |
| (postponed) | 4 | The host was loaded; nothing ran |

A skip is never a pass. In the Podman stages, a test that returns early because its environment is incomplete prints a `skipped:` line; the harness treats any such line as a failure of that stage.

## Stages

| Stage | Question | What runs |
|---|---|---|
| `manifest` | Do the release archives match the manifest, and does the verifier reject tampering? | `scripts/release/test-verify-manifest.sh`, then `scripts/release/verify-manifest.py` over `--dist` ([releasing](releasing.md#verifying-a-download)) |
| `install-units` | Are the shipped units accepted, and do they start the packaged binaries? | `check-server-unit.sh` and `check-worker-unit.sh` on the packaged binaries ([deployment](deployment.md)) |
| `local-mode` | Does a fresh install from the packages run a job with no network? | `check-local-mode.sh` inside `unshare -rn`: controller, worker and a generic Git remote on loopback |
| `upgrade` | Does a database from each earlier schema migrate, keep its copy and roll back as documented? | `sentinel-store` tests `upgrade`, `authorization`, `storage` ([upgrades](upgrades.md#verification)) |
| `recovery` | Do backup, restore and crash recovery work? | `sentinel-store` `backup`, `backup_drill`, `replicate`; `sentinel-worker` `recovery`, `crash_consistency` ([backup](backup.md), [resilience](resilience.md)) |
| `revocation` | Do suspension, session, grant and worker revocation take effect, and does nothing cross tenants? | `sentinel-store` `tenancy`, `tenant_access`, `tenancy_isolation`, `cross_tenant`, `local_auth`, `oauth_service`, `oauth_tokens`; `sentinel-api` and `sentinel` `tenant_isolation`; `sentinel-link` `fleet` ([tenancy](tenancy.md), [authorization](authorization.md)) |
| `worker-loss` | Are lost workers, expired leases and dropped links settled without duplication? | `sentinel-store` `dispatch`, `execution`, `fleet`, `faults`; `sentinel-link` `link`, `hardening`, `handoff`, `duplicate` ([worker link](worker-link.md), [reconciliation](reconciliation.md)) |
| `secrets` | Are secrets sealed, scoped and delivered only to the attempt, and kept out of logs? | `sentinel-store` `secrets`, `secret_scopes`, `secret_delivery`; `sentinel-worker` `secret_isolation`; `sentinel` `secrets_cli` ([secrets](secrets.md)) |
| `caches` | Do cache keys, trust scopes, publication and collection hold? | `sentinel-cache`; `sentinel-worker` `compiler_cache`, `k09` ([cache](cache.md)) |
| `diagnostics` | Do logs, queues and reads stay bounded and report back-pressure? | `sentinel-store` `logs`, `log_search`, `bounds`, `retention`, `store`; `sentinel-worker` `log_throughput`, `log_write_faults`, `spool_space` ([diagnostics](diagnostics.md), [logs](logs.md)) |
| `egress` | Does operator-granted egress reach out but never the host loopback, and do executor failures settle? | `sentinel-worker` `podman`, `executor_faults`, `runtime_failures` under rootless Podman ([executor](executor.md)) |
| `compat` | Do the API, client, pipeline schema and protocol keep their contracts, and do the docs link? | `sentinel-api` `api`, `oauth_core`; `sentinel` `client`, `cli`, `commands`, `examples`; `sentinel-pipeline`; `scripts/check-doc-links.sh` ([compatibility](compatibility.md)) |

The `secrets`, `caches`, `egress` and `local-mode` stages need rootless Podman and set `SENTINEL_PODMAN_TESTS=1` for their tests.

## What a PASS does not show

- It is single-host. Multi-host enrollment, Tailcat reconnect and host policy are the real-fleet verification (Q11 to Q13), not this record.
- It runs the repository's tests at one commit. The correctness pass (Part 24) must be closed first, because a PASS over known-open findings qualifies nothing.
- It makes no performance claim; benchmarks are recorded separately ([benchmarking](benchmarking.md)) and the [release notes](release-notes.md) quote only committed benchmark records.
- It does not run runner mode, microVM or Windows paths.
- It does not touch production data. A restore or upgrade of a real deployment is rehearsed on a copy, per [backup](backup.md) and [upgrades](upgrades.md).

## Dry-run record

The harness was exercised on the x86_64 verification host from a disposable checkout under `/var/tmp` at the lane commit, as root, so the Podman and package stages were skipped by design and no run could be `PASS`. Observed: a `--src` of `/srv/sentinel` is refused (exit 2); a bad `--dist` fails the `manifest` stage with `FAIL` (exit 1); `upgrade`, `recovery`, `revocation`, `worker-loss` and `diagnostics` passed; `compat` passed its 84 tests and failed its link check on 16 stale anchors in `TODO.md` (links to heading anchors that were renamed), which the tracker owner must reconcile; with Podman unavailable, `secrets` was recorded as skipped with the reason and the run as `INCOMPLETE` (exit 3). The `manifest`, `install-units`, `local-mode`, `secrets`, `caches` and `egress` stages have not yet run through this harness: they need the unprivileged Podman account and built packages. A qualifying run is the one in [Running it](#running-it) on the release commit, and its `qualification.json` is the release evidence.
