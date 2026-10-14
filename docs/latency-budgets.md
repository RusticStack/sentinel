# Latency budgets (B03)

The [plan's latency budgets](../plan.md#12-performance-targets-and-evidence), measured end to end on the reference host through a real controller, a real worker and real git pushes. These are distributions with their sample counts, not a fastest run. Record: [`bench/b03-latency.jsonl`](../bench/b03-latency.jsonl), taken 2026-09-29. The same run on the binary before the two fixes below is [`bench/b03-before-fixes.jsonl`](../bench/b03-before-fixes.jsonl).

**Provenance of these records.** `bench/b03-latency.jsonl` and `bench/b03-before-fixes.jsonl` carry no build commit, dirty flag or host block: the harness did not stamp them. They cannot be filled in afterwards, so the only attribution is the commit that added each file and the host named in the text. From the next run, `b03-latency.py` requires `--source` (the checkout the deployed binary was built from) and puts that commit, its dirty flag, the binary's SHA-256 and a host block (kernel, CPU model, memory, governor) into every record. A re-run on the current tree is pending VPS verification.

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

Four of the plan's budgets are met as measured: dispatch (ready → offer), first process, visible logs and the failure query's latency. **Two are not**: cancel → termination (3.42 s p95 against 2 s) and the failure body's size (10.2 KiB against 8 KiB); see [Not met](#not-met). The failure query found the failing test in every response. Sample counts differ from the headline `n`: the failure query's 150 are 50 queries on each of 3 runs, so they are one connection pattern repeated three times, not 150 independent runs, and the cancel p95 of 30 samples is the second-highest sample.

Visible-log latency runs evenly from 0 to 100 ms. The earlier reading of that spread, a worker flush interval of about 100 ms, was not verified. The controller's parked log poll re-reads an attempt at most once per `LOG_RECHECK` = 100 ms (`routes.rs`), however fast it appends, and a step printing every 100 ms against a 100 ms re-read throttle produces exactly such a uniform spread. Which of the two (or both) sets the figure is open; it is within budget either way, but the number is a property of the throttle and the fixture's 100 ms cadence, not a floor of the pipeline.

### Not covered by any budget: event to ready

`queued_ms` is stamped in the write that creates the run, after the pipeline has been resolved (see the first fix below), so every budget here starts at "ready" and none counts the time from the push event to ready. That time is real work (resolving `.sentinel.yml` at the pushed commit through Git: 0.48 s intake → dispatch on the Lockwell fixture after B04, 4.2 s before it; about 150 ms on this probe repository before the re-stamp) and the user waits for it. The plan states no budget for it; a budget is an open item in `TODO.md` (B03a). `b03-latency.py` now records `intake_to_ready_ms` and `intake_to_first_ms` on its first-process samples (wall clock just before the intake POST to `queued_ms`, and to the first user process) so the next run measures it; no figure exists yet.

### Unexplained: two flat figures

- **Failure query p50 100.1 ms (min 89 ms) on a 100 MiB log**, with p95 109 ms. The route reads bounded windows through a sparse index and has no wait of its own: `LOG_RECHECK` applies only to a parked log poll, not to `/failure`. What does wait 100 ms is the HTTP accept loop: the listener is nonblocking (`http.rs`, `set_nonblocking(true)`) and a poll that finds no connection sleeps `Tune::poll` = 100 ms (`Err(_) => thread::sleep(tune.poll)`). The driver opens a fresh connection for each request, back to back, so each arrives just after the loop began a 100 ms sleep: a phase lock that would put almost every request at about 100 ms regardless of the work. That is consistent with the data and has **not** been tested (no run without the sleep exists). If it holds, the 100 ms is an artificial wait, and every new connection pays up to 100 ms before its request is read; it is recorded as an open item (B03b) rather than fixed here, because the accept loop also gates on the connection pool and the stop flag, and replacing the poll with a blocking accept or `poll(2)` needs a wake-up path that can only be verified on Linux.
- **Follow-up to the failure-query item: the accept poll is removed.** The acceptor now blocks in `accept` instead of sleeping `Tune::poll` between nonblocking attempts, so a new connection is taken the moment it arrives. Shutdown wakes the blocked acceptor with a connection to the listener's own address (loopback for a wildcard bind) after setting `stop`, and the acceptor drops any connection it takes once `stop` is set; the connection and handler permits and the per-peer cap are unchanged. `http::tests::a_new_connection_is_served_without_waiting_for_a_poll` (median of 15 sequential connections under 50 ms with the production 100 ms poll) and `closing_an_idle_server_wakes_its_blocked_acceptor` pin the behaviour. The cause was identified from the code and the phase-lock arithmetic, not from a run without the sleep: whether the flat 100.1 ms failure-query p50 drops, and by how much, is **pending a B03 re-measurement on the VPS** with this change; no number is claimed here.
- **Durable webhook ACK p50 58.7 ms (max 69.4 ms; the 200 first-process samples run from 41.6 ms)** against a store commit of about 0.6 ms. The accept sleep does not explain it: a request arriving at a random phase would spread uniformly over 0–100 ms, and these samples span under 30 ms. What the 202 waits for besides the commit is not identified (candidates, none checked: pipeline resolution through Git before the ACK, the first-use TLS or credential work, process spawn). The budget is met with a wide margin, so this stays a question about where 58 ms goes, tracked with B03b.

### Before and after the two fixes

The first run of this harness measured ready → offer at a p50 of 157 ms (p95 178, p99 192) and ready → first process at 1,628 ms (p95 1,727, p99 1,831). It also failed one job in 187 when Docker Hub refused the host. Both defects were in Sentinel, and both are fixed:

- **Jobs were stamped ready before they existed.** The intake lane captured `now` before resolving the pipeline, which includes a Git fetch of `.sentinel.yml` at the pushed revision, and created the run with it. So `queued_ms` and `created_ms` counted the fetch as queue time: about 150 ms here, and 4.2 s for Lockwell (B02). This skewed the ready → offer measurement, queue age in `/metrics` and fairness aging. The run is now stamped in the write that creates it (`sentinel-intake` `resolve.rs`; test `a_dispatched_job_is_ready_from_its_creation_not_from_resolution_start`). The dispatcher itself was never slow: 8 ms p50.
- **Every job asked the registry about an image it already had.** The worker pulled even a resident digest for an anonymous job, to re-check an authorization that an anonymous pull does not have. That was about 1 s per job, and Docker Hub's anonymous limit (100 manifest requests an hour; `ratelimit-remaining: 0` was observed on the host) failed the 187th job in preparation. An anonymous pull into the shared store now uses a resident digest as it is; a credentialed or private-store pull still asks every time ([executor](executor.md#the-image-pull-k05); `podman::registry_check_needed`).

Together they took ready → first process from 1.63 s to 0.66 s (p50).

### Not met

- **Cancel → termination: 3.3 s p50, 3.4 s p95, against 2 s.** A cancel reaches a running attempt only on the worker's next heartbeat, which lists pending cancels in its `Pong` ([cancellation](cancellation.md)). The heartbeat interval is 5 s (`HEARTBEAT_INTERVAL`), so delivery alone can take up to 5 s. The step here ends on the first `SIGTERM`, so no grace period is involved. Meeting the budget needs the controller to push a cancel to the owning session when it is recorded, rather than waiting for the heartbeat. That is a protocol change and is left to its own task.
- **Failure query size: 10.2 KiB against ≤ 8 KiB.** The route's text budget defaults to 8 KiB, and the whole body may reach 64 KiB ([API](api.md)). With the default budget, the text is 8.3 KiB once JSON-escaped, and the report metadata brings the body to 10.2 KiB. A client that needs the plan's bound passes `budget` of about 6,000 today. Changing the default is an API decision left open.
