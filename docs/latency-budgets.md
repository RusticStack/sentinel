# Latency budgets (B03)

The [plan's latency budgets](../plan.md#12-performance-targets-and-evidence), measured end to end on the reference host through a real controller, a real worker and real git pushes. These are distributions with their sample counts, not a fastest run. Record: [`bench/b03-latency.jsonl`](../bench/b03-latency.jsonl), taken 2026-09-29. The same run on the binary before the two fixes below is [`bench/b03-before-fixes.jsonl`](../bench/b03-before-fixes.jsonl).

## Method

[`bench/b03-setup.sh`](../bench/b03-setup.sh) builds a deployment as the bench user on the reference host (the netcup VPS of the [benchmark contract](benchmark-contracts.md)):

- a controller and a rootless worker on one host, both release builds;
- a small repository bound over loopback HTTPS, with a sealed credential;
- one branch per measurement, each carrying that measurement's `.sentinel.yml`. The image is `golang:1.27.1-trixie` by digest, resident in the worker's store: the warm reference fixture.

[`bench/b03-latency.py`](../bench/b03-latency.py) takes every sample as a fresh commit pushed to a branch and a generic intake event, one at a time, with CPU pressure (avg60) under 2 % before each; the highest was 1.35 %. The controller, the worker and the driver share one host clock, so wall-clock differences between them are meaningful at the millisecond resolution of the store's timestamps.

| Budget | How it is measured |
|---|---|
| Durable webhook ACK | `POST /intake/{repo}` to its `202`, timed by the client, on every sample |
| Ready → offer | `attempts.offered_ms − jobs.queued_ms`, with idle capacity |
| Offer → ack | `attempts.acked_ms − attempts.offered_ms` (loopback link) |
| Ready → first user process | the first step prints `date +%s%N`; that minus `jobs.queued_ms` |
| Log capture → visible | a step prints `t=<ns>` every 100 ms; a client follows `GET /attempts/{id}/logs?wait=1`; receive time minus the printed time |
| Cancel → termination | the step is `exec sleep 600` (it ends on `SIGTERM`); `POST /runs/{id}/cancel` a second after it runs, to the job terminal on the wait API |
| Cache preparation | a fixed fixture of 1,000 files of 64 KiB (64 MiB) in a `dependencies` cache: `lookup + lock_wait + clone` of each hit, seed run excluded |
| Indexed failure query | a step writes 100 MiB of output and then a Go test failure as `go test -json`; `GET /attempts/{id}/failure` 50 times on each of 3 runs |

## Results

| Budget | n | p50 | p95 | p99 | max | Target | Met |
|---|---|---|---|---|---|---|---|
| Durable webhook ACK | 274 | 58.7 ms | 65.8 ms | 68.3 ms | 69.4 ms | p95 < 250 ms | yes |
| Ready → offer | 200 | 8 ms | 10 ms | 17 ms | 26 ms | p95 < 100 ms, p99 < 250 ms | yes |
| Offer → ack | 200 | 5 ms | 6 ms | 7 ms | 10 ms | p95 < 100 ms | yes |
| Ready → first user process | 200 | 661 ms | 720 ms | 739 ms | 777 ms | p95 < 2 s, p99 < 5 s | yes |
| Log capture → visible | 1,000 lines, 10 runs | 51.7 ms | 96.6 ms | 101.0 ms | 102.5 ms | p95 < 250 ms | yes |
| Cache preparation, 64 MiB / 1,000 files, copy (ext4, no reflink) | 30 | 93.5 ms | 100.8 ms | 101.7 ms | 101.7 ms | p95 < 500 ms | yes |
| Indexed failure query, 100 MiB log | 150 | 100.1 ms | 109.3 ms | 134.7 ms | 142.8 ms | p95 < 200 ms, ≤ 8 KiB | latency yes; size **no** (below) |
| Cancel → termination | 30 | 3.27 s | 3.42 s | 4.63 s | 4.63 s | p95 < 2 s, excluding grace | **no** (below) |

The four budgets B03 names are met: dispatch, first process, visible logs and the failure query's latency. The failure query found the failing test in every response. Visible-log latency runs evenly from 0 to 100 ms: the spread matches a flush interval of about 100 ms, not network or storage delay.

### Before and after the two fixes

The first run of this harness measured ready → offer at a p50 of 157 ms (p95 178, p99 192) and ready → first process at 1,628 ms (p95 1,727, p99 1,831). It also failed one job in 187 when Docker Hub refused the host. Both defects were in Sentinel, and both are fixed:

- **Jobs were stamped ready before they existed.** The intake lane captured `now` before resolving the pipeline, which includes a Git fetch of `.sentinel.yml` at the pushed revision, and created the run with it. So `queued_ms` and `created_ms` counted the fetch as queue time: about 150 ms here, and 4.2 s for Lockwell (B02). This skewed the ready → offer measurement, queue age in `/metrics` and fairness aging. The run is now stamped in the write that creates it (`sentinel-intake` `resolve.rs`; test `a_dispatched_job_is_ready_from_its_creation_not_from_resolution_start`). The dispatcher itself was never slow: 8 ms p50.
- **Every job asked the registry about an image it already had.** The worker pulled even a resident digest for an anonymous job, to re-check an authorization that an anonymous pull does not have. That was about 1 s per job, and Docker Hub's anonymous limit (100 manifest requests an hour; `ratelimit-remaining: 0` was observed on the host) failed the 187th job in preparation. An anonymous pull into the shared store now uses a resident digest as it is; a credentialed or private-store pull still asks every time ([executor](executor.md#the-image-pull-k05); `podman::registry_check_needed`).

Together they took ready → first process from 1.63 s to 0.66 s (p50).

### Not met

- **Cancel → termination: 3.3 s p50, 3.4 s p95, against 2 s.** A cancel reaches a running attempt only on the worker's next heartbeat, which lists pending cancels in its `Pong` ([cancellation](cancellation.md)). The heartbeat interval is 5 s (`HEARTBEAT_INTERVAL`), so delivery alone can take up to 5 s. The step here ends on the first `SIGTERM`, so no grace period is involved. Meeting the budget needs the controller to push a cancel to the owning session when it is recorded, rather than waiting for the heartbeat. That is a protocol change and is left to its own task.
- **Failure query size: 10.2 KiB against ≤ 8 KiB.** The route's text budget defaults to 8 KiB, and the whole body may reach 64 KiB ([API](api.md)). With the default budget, the text is 8.3 KiB once JSON-escaped, and the report metadata brings the body to 10.2 KiB. A client that needs the plan's bound passes `budget` of about 6,000 today. Changing the default is an API decision left open.
