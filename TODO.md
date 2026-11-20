# Sentinel TODO

**Goal.** Beat other CI engines on the same hardware. Release gates: **B11**, trigger-to-required-check p95 at most 0.50× Blacksmith's p95 on identical checks; **B08**, warm required-check p95 < 60 s against a ≥300 s same-hardware baseline. No assertion or freshness rule is dropped to get there.

**v0.1 scope:** Parts 00–15, Part 20 (U17, U18), Part 23 (M01–M06, M08) and Part 24. Everything else is the [after-v0.1 backlog](docs/backlog.md).

**How this file works.**
- It lists only open work, grouped into waves by what each item needs (host, window, decision), not by Part.
- Each task's full contract is in the doc its line links and in [plan.md](plan.md).
- Completed tasks, their evidence and the full completion log up to 2026-10-29 are in git: `git show 70f8c80:TODO.md`.
- Task ID prefixes: F (Part 01), C (02), A (03), W (04), G (05), D (06), K (07), Q (08), O (09), S (10), X (11), U (12, 20), R (13), B (14), V (15), M (23), RW (24).

## Next wave

**Wave 1 — verification gate.** Start a session with "Let's now fully implement Wave 1".

| Wave | Needs | State |
|---|---|---|
| [1 Verification gate](#wave-1--verification-gate) | `reference-host` with the Podman account; `arm64-host` | **next** |
| [2 Measurements](#wave-2--measurements-on-reference-host) | Wave 1; a quiet `reference-host` window | waiting |
| [3 KVM host](#wave-3--kvm-host) | Wave 1; a `kvm-host` window with nftables privileges | waiting |
| [4 Real fleet](#wave-4--real-fleet) | Waves 1, 3; all three hosts; X4, X6 | waiting |
| [5 Pilots and Blacksmith](#wave-5--pilots-and-blacksmith) | Waves 2, 3, 4; X1 for B11 | waiting |
| [6 Closure and release](#wave-6--closure-and-release) | all earlier waves | waiting |

Waves 2 and 3 use different hosts and can run in either order or side by side. A wave may take several sessions; stop at an item boundary and mark the finished items `[x]`.

**Running a wave.**
1. Check the wave's **Needs**. If one is missing, say so and stop.
2. Branch `wave-N-<name>`, and commit per item.
3. Tests follow [CLAUDE.md](CLAUDE.md#where-tests-run).
4. A finding the wave cannot fix goes into the wave that can, with its blocker.
5. When the gate passes:
   - Delete the wave's section.
   - Add one row to the [log](#log).
   - Update the table above and **Next wave**.
   - Push and open a PR; merge locally, not with `gh pr merge`.

## Owner prerequisites

What a session cannot supply. Ask early.

| ID | Needed | Blocks | Fallback |
|---|---|---|---|
| X1 | Blacksmith benchmark access | B11, so RW11, Part 24, V06 | none: B11 is a release gate |
| X2 | A Windows verification host | V01's Windows CLI smoke test, O07's Windows leg | ship the CLI unsmoked, listed as a limit |
| X3 | A registered GitHub App on a disposable account (the B10 pilot App works) | U17's real-page flow; whether `members:read` alone can read `/repos/{o}/{r}/collaborators/{login}/permission` (RW05) | record both as unverified limits |
| X4 | Where the pinned Tailcat v0.6.0 helper comes from: the controller, an upstream fetch or the operator, and its licence | the final enrollment flow (Q11, V01) | operator-supplied helper, direct TLS default |
| X5 | Fork-PR secret policy. Today `pull_request` runs get bound secrets, manual runs never do, and fork PRs are refused (`fork_pr`, `crates/sentinel-intake/src/resolve.rs`) | RW05's closure | keep `fork_pr` refused as the v0.1 limit |
| X6 | Approval and a separate disposable host for B09's destructive scenarios; an operator-owned DERP and a pinned Tailcat install for the relay scenario | Wave 4's destructive and relay scenarios | run the rest, record those as blocked |
| X7 | Real MCP clients (X07), hosted S3 buckets (R03a), a GitLab TLS and a Forgejo SSH fixture (G08a), a desktop browser (O07, CLI login launch), a Resend key and domain, a registered GitHub OAuth app for real github.com sign-in, separate real networks for Tailcat NAT traversal | those checks only | list each as an unverified limit in V06 |
| X8 | N00's order (Windows guests before the native executor); whether pre-rule evidence ("Parts 09–11 re-audit", WSL2 runs dated 2026-09-27) is re-run before Wave 1 | nothing in v0.1 | leave as recorded |

## Wave 1 — verification gate

**Goal:** one clean run of the full suites on the Wave 0 tree, which closes the tasks reopened only for current-tree verification.

**Needs:**
- Wave 0 merged.
- `reference-host` with the rootless Podman account, and `arm64-host`.
- `cargo-deny` installed.

**Runs:**
1. On `reference-host`, from a disposable checkout of the Wave 0 commit, detached with a log:
   - `cargo fmt-check`, `lint`, `lint-linux` and `licenses`.
   - `cargo test-linux` and `cargo test-cli`.

   Fix each failure at its cause. A flaky test is fixed, never retried into green. Re-run only the affected binaries.
2. The Podman suites, with `SENTINEL_PODMAN_TESTS=1`:
   - `podman`, `end_to_end`, `images` (the K05 exists fast path), `executor_faults` (the never-renewed-lease test has only compiled), `prefetch`, the vertical slice and secret isolation.
   - The ignored `worker_bootstrap_script` tests.
   - The G08 Git fixtures: Gitea, Forgejo, GitLab and a bare repository.
3. `arm64-host`: the arm64 worker tests and the worker end-to-end test.
4. Web: run `bench/hosts/align-toolchain.sh` (pnpm 12.15), then `pnpm -C web install`, `typecheck`, `build` and `test:unit`. Run the browser test enough times to show the busy-controller scenario is fixed.
5. Pending suites:
   - Email identity, invitations and `sentinel-mail`.
   - First-run setup and self-service organizations.
   - Account security and GitHub linking.
   - On a running controller: setup-token file mode 0600 and token voiding on restart.
   - RW05's `members:read` check, if X3 is available.
6. Carried from Wave 0, tests that could not run there:
   - Worker, rootless Podman: `tests/podman.rs`, `end_to_end`, `a_panicking_attempt_is_torn_down_and_reported`, recovery and the image integration tests against real Podman, the container reaper (`podman container exists` answering 1 for a removed container), and the sealed-directory permission-denial paths as a non-root user (the Wave 0 host account is root). Also reproduce RW04's workspace trees that other in-namespace UIDs made unreadable or undeletable: the storage guard neither counts nor removes them (`crates/sentinel-worker/src/workspace.rs`). The slice test, the only caller of `permit_any_manual_source_for_tests`, was only compile-checked.
   - `power_cut_on_dm_flakey` (`SENTINEL_POWER_LOSS_TESTS=1`, root and dm-flakey): the log index sidecar must be durable before a seal (0.9's `LineSeek.exact`).
   - V02: build the container and web images (`--format docker`), `podman compose --profile web up`, `podman healthcheck run`, SIGTERM, and the Quadlet generator dry run. The web image ships JavaScript dependencies with no licence inventory: decide before release.
   - Bench: the full Python suite, `bench/smoke.sh` with `SMOKE_COMPILE=1` against release binaries, and `web/bench/web-bench.mjs` once against a live `sentinel-web` (its record spread is only syntax-checked).
   - Refresh the generic Git timings in `docs/generic-git-verification.md` on the G08 fixtures: they have no record.

**Closes, each only if its own contract holds:**
- [x] **C08** transitions and parser limits: malformed input, duplicates, rollback, conflicting update, crash-reopen ([compatibility](docs/compatibility.md))
- [x] **A01** tenancy and authorization ([authorization](docs/authorization.md))
- [x] **A05** admission and registration modes ([admission](docs/admission.md))
- [x] **W01** worker enrollment and link, protocol 11 ([worker link](docs/worker-link.md))
- [ ] **W03** checkout and the rootless Podman executor ([executor](docs/executor.md))
- [ ] **W09** vertical slice fault cases ([vertical slice](docs/vertical-slice.md))
- [x] **G04** Checks outbox ([checks](docs/checks.md))
- [ ] **G08** generic Git intake on the fixtures ([generic Git verification](docs/generic-git-verification.md)); Forgejo over SSH and GitLab over HTTPS are G08a (X7)
- [x] **D01**, **D02** objects, uploads and reads ([storage](docs/storage.md))
- [ ] **D04** segmented logs, indexes, replay and spool acknowledgement ([logs](docs/logs.md)); includes `power_cut_on_dm_flakey` (run 6)
- [ ] **Q05** control and bulk priority, reconnect jitter, replay, restart reconciliation
- [x] **Q08** remote cache hydration
- [x] **Q10** the fleet placement stall: `fleet.rs` stress-run clean
- [x] **O02**, **O06** tokens, rotation, service grants, `doctor` ([OAuth](docs/oauth.md))
- [ ] **O07** login, refresh races and logout on the Linux CLI; Windows leg is X2, real browser launch X7
- [x] **S05**, **S06**, **S07** secret binding, redaction and cleanup, the end-to-end provisioning test ([auth and secrets](docs/auth-and-secrets.md))
- [x] **R05** upgrades and skew ([upgrades](docs/upgrades.md)); the compatibility entries and the rollback matrix are in and checked against the code by `tests/compat_doc.rs`
- [x] **R07** failure drills ([resilience](docs/resilience.md))
- [ ] **U01–U07** Part 12, carried by Part 20's React port and its browser test; a real screen reader (U06) is a recorded limit

## Wave 2 — measurements on `reference-host`

**Goal:** every figure the docs quote or a finding depends on has a committed record, or leaves the docs.

**Needs:**
- Wave 1.
- A quiet `reference-host`.

**Method:**
- Check pressure first.
- Take the lock with `flock -o`.
- Run one measurement at a time.
- Record load, build and host with each result, and shuffle with a recorded seed.

**Measure:**
1. **Benches with only smoke records:**
   - log-ack (one `fdatasync` per burst).
   - The checks lane (the commit-notifier wake).
   - S3 hashing and backup rehash.
   - `bench-noop --interleave`, scoped and Podman.
   - The shuffled `bench/f07-storage.sh` and `bench/k02-cache-clone.sh` re-runs.
2. **Store:**
   - Migration 49's reapply indexes and batched reapply on a large table.
   - The `wal_checkpoint` schedule at realistic sizes, and how often `Checkpointed::Partial` happens under read load.
   - The single-aggregate free-capacity read.
   - The queue-explanation figures in `docs/storage.md` (3.7 ms against 5.9 s).
3. **Fleet and link:**
   - Refresh `bench/q09-fleet-load.jsonl` (100 sessions, 10,000 queued jobs).
   - The Tailcat hand-off and allow-list figures in `docs/worker-link.md`. These need rootful Podman for `tailcat_live`.
4. **Other costs:**
   - The `PR_SET_PDEATHSIG` hook per helper.
   - API-credential, Argon2id and session-validation timings (0.13's harness).
   - The `docs/cache.md` hydration and offer-hashing figures against `bench/b04-transfer-copies.jsonl`.
   - Spread for `bench/u01-log-view.jsonl`, which holds medians only.
5. **Carried from Wave 0** (figures the docs now label "no record", and harnesses built but not run):
   - `ranking_cost`, `fleet_sessions` and `fleet_load` on both trees (3c8b8e5 and the Wave 2 tree), shuffled and stamped, then set the `ranking_cost` bounds as a multiple of the recorded baseline ([worker link](docs/worker-link.md)).
   - Whether a newer pinned Tailcat helper than v0.6.0 reloads `--allow` without a restart. It cannot be answered offline: it needs the upstream release notes or a test against that build (X4).
   - A 20k-file cache publish with per-file syncs against one `syncfs` (`docs/cache.md`), and the K07 recipe cases with spread (`docs/benchmarking.md`): the quoted figures are single development runs.
   - The 0.13 harnesses with a quiet-host record: auth-cost (A02/A03), store-cost, spawn-cost, `q09-fleet-load`, queue-explain, backup-drill (R04), remote-cost, the log-ack and checks-lane contracts, and `tailcat_live` (pinned Tailcat build and rootful Podman). M06's cold and restore series run back to back; interleaving them changes the test body and needs an owner decision. Optional `bench/b05_report.py` once a B05 record schema is committed.
   - Store maintenance: backup and prune materialize every object row and rebuild path sets for every kept snapshot each interval (`crates/sentinel-store/src/backup.rs`); the backup holds the maintenance lock through the rehash of the shared store, stalling reclaim, log expiry and pressure eviction. Measure both at scale, then cut them.
   - The checks outbox: a completed create's handle can attach to a newer generation of the row (`crates/sentinel-store/src/checks.rs`); settle it with a check against GitHub.
   - S3 deletes go one request each; batching them (`DeleteObjects`) needs its own measurement (`crates/sentinel-store/src/replicate.rs`).
   - Bench record hygiene: `web-bench.mjs`, `measure-profile.sh` and the m01/k07-microvm recorders keep their own record shapes (listed in `LEGACY_UNSTAMPED`); move them to the common build and host stamp when they are re-run. `p14-pilot.sh`, `b02-sentinel.sh`, `b03-latency.py`, c02, k07, k09 and r06 take no shared lock, and `b01a-github.py` still defaults to `/srv/sentinel/runs/p14.lock`: retire that lock on the hosts and move them onto `/var/tmp/sentinel-verify.lock` with `flock -o` (owner decision). `f07-storage.sh` still hardcodes `/srv/f07` and `/mnt/f07-*`, and `k02-cache-clone.sh`/`f07-storage.sh` drop the host-wide page cache as root: settle on a dedicated idle host or a lock-and-idle check.

**Closes:**
- [ ] **F06** CI baseline on the real CI topology: the Docker/integration lane internals and a concurrent probe during live CI. Without access, it stays `Blocked by` that access ([CI baseline](docs/ci-baseline.md)).
- [ ] **K03** cache generations, leases and promotion. Compare the costly-hit rule (`cost::CostBook`) with B05's rebuild and publication costs.
- [ ] **K08** cache and image metrics, costly-hit tracing.
- [ ] **B03** latency budgets on the final tree. Budgets: dispatch p95 < 100 ms, warm first process < 2 s, visible logs < 250 ms, failure query < 200 ms, cancel → termination < 2 s, failure body ≤ 8 KiB. All were met on 2026-10-22 (`df93bf0`); re-measure ([latency budgets](docs/latency-budgets.md)).
- [ ] **B03a** push → ready p95 < 250 ms and push → first process p95 < 1 s.
- [ ] **B03b** the webhook ACK, failure query and parked-log-follow figures.
- [ ] **B04** critical-path profile with before/after artifacts. The next costs after the partial-clone fix are cache publication (about 3 s) and checkout (1.8 s) ([benchmark contracts](docs/benchmark-contracts.md#b04-the-critical-path-profiled-and-cut)).
- [ ] **B04a** disk wait and CPU throttling per phase, from cgroup `cpu.stat` and PSI. Profiles exist for `cli` and `ripgrep` (`bench/p14-b04a-*.jsonl`, `bench/b04a_profile.py`); assess them and cover the remaining phases and lanes.
- [ ] **B05** cache matrix: Go/Rust/JS/Python/Java/custom workloads, 10 GiB fixtures, first touch, dirty bytes, copy amplification, tail latency (`bench/b05-cache.sh`, `bench/b05-workloads.sh`). No result exists yet.
- [ ] **R01** retention defaults from measured hardware, and the retention query plans ([retention](docs/retention.md)).
- [ ] **R04** the backup drill at the objective: 100 GiB, RPO ≤ 1 h, RTO ≤ 15 min. Needs ≥100 GiB free beyond other work ([backup](docs/backup.md)).
- [ ] **R06** idle RSS and CPU of the controller and worker on the current build ([monitoring](docs/monitoring.md)).

## Wave 3 — KVM host

**Goal:** the microVM path is verified on `kvm-host`, and the same-hardware pilot baseline is complete.

**Needs:**
- Wave 1.
- A `kvm-host` window with nftables privileges. Production services run there, so the [host rules](CLAUDE.md#where-tests-run) apply.

**Closes:**
- [ ] **M01** host detection: KVM detected on `kvm-host`, none on `reference-host`. Windows detection moves to M07.
- [ ] **M02** capacity and idle memory at the full pilot allocation (Linux boot distributions exist in `bench/m02-boot.jsonl`).
- [ ] **M03** the recipe images boot and run their steps; the image digest appears in provenance.
- [ ] **M04** the worker end-to-end suite under the microVM executor (`SENTINEL_MICROVM_TESTS=1`: `end_to_end`, `slice`, `k09`, `secret_isolation`, `microvm`). Covers polite and stubborn cancel, timeouts, OOM, artifacts and caches.
- [ ] **M05** tap and nftables gate: a guest reaches neither the host, the link port nor metadata addresses; egress works only where granted.
- [ ] **M06** snapshot restore: ready → first user process p95 < 2 s, with the cold boot published beside it. The M02 restore record is boot-only and does not count.
- [ ] **RW04 item** replace the guest's fixed 1 GiB `/tmp` tmpfs (`crates/sentinel-agent/src/linux.rs:180`) with the job's disk budget, and run `a_guest_cannot_write_past_its_declared_scratch_disk`.
- [ ] **B01a** complete and assess the revision-4 baseline and Sentinel samples (`bench/b01a-github.py`, `bench/p14-pilot.sh`), recording per lane whether it reaches 300 s ([benchmark contracts](docs/benchmark-contracts.md)).
- [ ] **M08** the pilots' Linux lanes in microVMs against rootless Podman on the same host and caps, cold/warm/small-edit, with B03 re-measured (`bench/contracts/pilots-ci-isolation.json`, `bench/m08_overhead.py`). Publish the overhead per lane; anything beyond B09's 10 % is a bug in M04–M06.
- [ ] **RW10 item** run the feasibility probes on bare metal for a host resource budget.
- [ ] **Carried from Wave 0:**
  - Commit `bench/m04-lifecycle.jsonl` from `SENTINEL_MICROVM_LIFECYCLE_OUT` (stamped with host, commit and date; `observe()` writes only name and ms today), then drop the "no record is committed" wording in [executor](docs/executor.md).
  - Run `tests/microvm.rs` with the new sync-bound and view-clearing tests under `SENTINEL_MICROVM_TESTS=1`.
  - `PR_SET_PDEATHSIG` still has no test of its own (a killed parent kills the helper).
  - M01–M08 measurements: `m06-start` and the M02 boot runs skip elsewhere.

## Wave 4 — real fleet

**Goal:** host management and multi-worker execution verified on real workers.

**Needs:**
- Waves 0, 1 and 3.
- All three hosts in a permitted window.
- Disposable accounts only.
- X4 and X6 for the Tailcat and destructive parts.

**Closes:**
- [ ] **Q13** the real host-management path across the three hosts (`bench/q13-fleet.py run`), with a real executor:
  - UI enrollment and uninstall; Tailcat reconnect and revocation.
  - Duplicate host identities; CPU/RAM/storage ceiling changes.
  - ARM placement; OS/isolation mismatch explanations.
  - Priority overrides and fastest-eligible default placement.
  - Proof that priority never bypasses ownership, capabilities or capacity ([worker enrollment](docs/worker-enrollment.md)).
- [ ] **Q11**, **Q12** close with Q13 ([worker bootstrap](docs/worker-bootstrap.md)).
- [ ] **Q03** placement by expected finish. Per-core speed is not measured, so same-size idle machines tie: measure it, or document the tie.
- [ ] **Q06**, **Q07** Tailcat helper integration and path telemetry. Helper restart, changing endpoints, NAT failure, relay-only and revoked peers, on separate real networks (X6, X7).
- [ ] **Q09** the three-worker fleet with real executors under bursts, partitions, restarts, draining, mixed capacities and noisy tenants.
- [ ] **B09** bursts; 1/3/10 real workers; slow and full disk; direct and relay links; network loss; restarts; noisy tenants. Use `bench/b09-harness.py run --fleet`, with `kvm-host` as controller and `reference-host` and `arm64-host` as workers. Set the noise-aware regression gate: initially 10 % p95 overhead.
- [ ] **Carried from Wave 0:**
  - The B09 and Q13 harnesses were run end to end only against a fake; that rehearsal is not evidence.
  - A real Tailcat address must be absent from a live controller log (the enrollment page's canary covers the direct case; X4, X6).
  - The enrollment page's "pool no longer active" `404` and its Tailcat node-key form have API tests but no browser scenario: the fixture has `api_url` and no way to deactivate a pool.

## Wave 5 — pilots and Blacksmith

**Goal:** the pilots run on Sentinel at parity, and the release targets are demonstrated or published as unmet.

**Needs:**
- Waves 2, 3 and 4.
- X1 for B11.

**Closes:**
- [ ] **B06** confirm the pilots' workflows at the pinned commits. Beyond cli `go.yml`, `lint.yml` and `acceptance.yml`, ripgrep `ci.yml` and gson `build.yml`, the inventory is from file names only. Adapt the PR lanes on the forks, and record the still-external lanes ([pilot repositories](docs/pilot-repositories.md)).
- [ ] **B07** remove false dependencies and redundant builds, with equal assertions and the same total resource budget.
- [ ] **B08** warm required-check p95 < 60 s against a ≥300 s baseline. Revision-4 baselines are all below 300 s:

  | Lane | GitHub baseline | Sentinel warm p95 |
  |---|---|---|
  | cli | 109 s | 64.08 s |
  | gson | 88 s | 44.02 s |
  | ripgrep | 30 s | 21.39 s |

  Publish the unmet outcome without changing the threshold or the workload.
- [ ] **B10** shadow the checks under separate names; commit anonymized per-lane parity evidence; switch required checks, with a documented rollback. The 2026-10-22/24 shadow observations have no committed record.
- [ ] **B11** Sentinel p95 ÷ Blacksmith p95 ≤ 0.50 per lane and condition: identical SHA, commands, assertions and resource envelope; 100 interleaved paired samples; a one-sided 95 % bootstrap upper bound below 0.50; any failed check fails the gate. Freeze a separate contract. **Blocked by X1.**

## Wave 6 — closure and release

**Needs:** every earlier wave.

**Closes:**
- [ ] **RW02–RW10, RW12** each reviewed area is clean or its leftovers are filed.
- [ ] **RW11** final full suites plus the Q13, B09 and B11 results. Re-triage everything still open. Do not close while B11 is blocked.
- [ ] **V01** rebuild and verify the release artifacts at the release commit ([releasing](docs/releasing.md)); smoke-test the Windows CLI on X2 or list it as a limit.
- [ ] **V02** deployment examples, including the web container ([deployment](docs/deployment.md)).
- [ ] **V03** onboarding end to end: bootstrap admin, tenant, App and repos, Q11 enrollment, OAuth CLI and MCP login, a secret, a run, failure inspection, restore.
- [ ] **V04** dogfood Sentinel's own checks, with a recovery path independent of Sentinel.
- [ ] **V05** release qualification with `scripts/qualify/qualify.sh` on a disposable fresh host ([qualification](docs/qualification.md)).
- [ ] **V06** publish the support limits (every X7 item and anything unverified), the `pilots-ci` and B11 benchmarks, and the open blockers; update the [release notes](docs/release-notes.md); tag v0.1. The sub-minute claim stays unmet until B08 qualifies, and "2× Blacksmith" is never claimed before B11 passes.
- [ ] **Wave 0 leftovers** to close or file (RW02–RW12):
  - A webhook run's provider sender is still not stored: the provider's own text, never a Sentinel principal ([intake](docs/intake.md)).
  - Run, job, attempt, run-spec and event rows have no retention, so backup and restore time grow with them ([retention](docs/retention.md); owner decision, default none).
  - A backup's object and manifest row reads fail closed on an undecodable id, by decision ([compatibility](docs/compatibility.md)).
  - Web: the GitHub-only step-up state has no browser check (a session for it needs the GitHub sign-in round trip against the double); the "reconnecting" label after a 5xx is untested; the enrollment page's policy editor has no browser scenario of its own.
  - Optional guard: a test that every `bench/<file>` a doc cites exists or sits in a paragraph that says "no record".

## Log

One row per completed wave. Details go in the PR body.

| Date | Wave | PR / commits | Evidence summary |
|---|---|---|---|
| 2026-11-20 | After-v0.1 code only: Part 21 H06–H07 and Part 22 Y03 | PRs #68–#70, merged as `32877be` … `8b738ec` | Gate on an unprivileged 2-vCPU Linux container: `cargo test-linux` **2821 passed, 0 failed, 36 skipped**, plus `cargo lint-linux`, `cargo fmt-check`, `scripts/check-doc-links.sh` and `pnpm typecheck` clean. Migrations 077 (the tenant's migration switch opt-in, readable by 76) and 078 (durable AI request rows, readable by nothing older) kept contiguous at `LATEST` 78, with the rollback matrix, the compatibility page and the upgrade test's expectations moved to match. H06 switches a migrated repository over: runner mode refuses before any write when a required check names a copy it would drop and then proves the gate held by comparing the protection read after the pull request with the one read before it, and the native path previews the exact required-check change, applies it only with the tenant's opt-in and the installation's `administration` grant, reads the settings back against the preview, and only then opens the pull request that disables the replaced jobs — on top of H07's protection client rather than a second one, with the rule that a context only a ruleset states cannot be removed and each kept check's App binding preserved. Y03 lands `sentinel-ai` as a second pnpm workspace member beside `web`, consuming `ai_requests` rows through the API: a request moves `queued` → `claimed` → `settled` and never back, a deadline ends an unclaimed one `unavailable`, and the delegation minted at claim time is the requester's scopes intersected with `Permissions::READ`, narrowed to the row's tenant and repository, so the credential the AI process reads evidence with can never exceed the person who asked and dies the moment the request settles. Provider policy is tested against a recording fake `HttpClient` that is the only client in the context: a `local_only` request naming a public provider makes **zero** HTTP calls, and `zero_retention`+openrouter sends `provider.zdr: true` and `data_collection: deny`. `crates/sentinel-api/tests/ai_requests.rs` proves the delegation reads its own request's attempt and no other, reads a repository the requester holds no grant on not at all, cannot write, and stops authenticating once the request settles, is disabled or hits its deadline. The workspace move from `web/` to the repository root needed a Setup repair the repository cannot carry: initialize and refresh hashed `web/pnpm-lock.yaml` and `web/pnpm-workspace.yaml`, so a lockfile change would never have refreshed the tree and new machines would have installed against a stale web-only lock — both now hash the root manifests and both members and install with `pnpm install --frozen-lockfile` at the root, proven by a test build and baked as Setup version 5. Still open, unchanged: every host-only leg (Podman, KVM/microVM, arm64, dm-flakey, multi-host fleet, a real GitHub App with a real installation reading a real branch's protection, real S3, a real browser, a real model provider), H06's and H07's pilot gates, and Part 21 from H08, Part 22 from Y04, and the measurement waves |
| 2026-11-20 | After-v0.1 code only: Part 21 H04 and H05, Part 22 Y02, Wave 1 R07 | PRs #61–#66, merged as `92da037` … `70be738` | Gate on an unprivileged 2-vCPU Linux container: `cargo test-linux` **2748 passed, 0 failed, 36 skipped**; `cargo lint-linux` and `cargo fmt-check` clean; `scripts/check-doc-links.sh` clean. No migration: 076 remains `LATEST`. H04 completes guided migration's write half — a `sentinel/migrate` branch built from the bytes GitHub holds, one commit whose parent is the analysed commit and whose tree changes only the rewritten workflows, a pull request against the default branch read rather than assumed, a re-run that fast-forwards and updates instead of opening a second, and every write gated through the migration switch and the installation snapshot in the same transaction that records a refusal. H05 compares a migrated job with its `sentinel / …` shadow over the same commits; a job that reported no test counts is `Unreported`, never a zero-test match, and the five statements the report reads name their indexes in a plan assertion. Y02 serves the bounded, re-redacted evidence bundle under a scope bit no permission implies, with a canary suite that stores a registered value, a `ghp_` token, a PEM block, a cloud key and a JWT in the log and proves none of them reach the bundle. R07 turns `docs/resilience.md` into seven drills that run — a real controller killed mid-attempt and restarted, a real worker killed mid-attempt, the link cut in both directions through a relay, the database held under `BEGIN EXCLUSIVE` while a terminal report arrives, and three refused-write cases — and found one real defect: the deferred queue treated any second report for an attempt as a duplicate of the waiting one, so a terminal verdict could be dropped and the attempt forced to `infra_failed` when its lease expired. The committed-key guard also caught this sweep: Y02's scanner fixtures committed a PEM private key literal, so the fixtures now assemble the header from parts with the same bodies. Still open, unchanged: every host-only leg (Podman, KVM/microVM, arm64, dm-flakey, multi-host fleet, a real GitHub App, real S3, a real browser), Part 21 from H06, Part 22 from Y03, and the measurement waves |
| 2026-11-20 | After-v0.1 code only: Part 25 AR02 and AR09, Part 21 H01–H03, Part 18 E09, Part 19 L05, and the Wave 1 `Closes` audit | PRs #41–#59, merged as `83cc74e` … `17acfbc` | Gate on an unprivileged 2-vCPU Linux container: `cargo test-linux` **2698 passed, 0 failed, 36 skipped**; `cargo lint-linux` and `cargo fmt-check` clean; `scripts/check-doc-links.sh` clean. Migrations 074 (runner leases), 075 (the migration switch and each installation's write permissions) and 076 (fork-PR provenance) kept contiguous at LATEST 76. Defects the audits found and fixed at cause, each with a test that fails on the old code: the Q10 placement stall (a worker mid-frame was dropped from a whole placement round through `session::is_free`'s `try_lock`, and a peer was ranked before it had stated its profile); C08's negative `jobs.fence` wrapping to `u64::MAX`, which made a damaged row look permanently live and stalled the whole placement pass behind it; C08's attempt-summary reader accepting more records than the writer's envelope; D04 sealing a segment's index entry before its data, which a power cut could turn into a `complete` log over an undeclared hole; Q05 discarding a live control session when a bulk write failed, stalling a log to the 60 s flush timeout; A01's `authz_epoch` not moving on invitation redemption, service-account creation or domain auto-join, and a personal namespace's owner removal answering 500; D04's missing line and wall-clock log lookups; and E09's in-flight publication never released when a worker died mid-upload. Records committed: `bench/q10-fleet-stress.jsonl` (30 of 30 clean runs after, 2 of 8 failing before), `bench/e09-archive-download.jsonl` (0.9–1.0 GiB/s median from a 48 MiB artifact) and the digest-first repeat (3.8 KiB against 12.6 MB). Stated rather than claimed: nothing here ran on `kvm-host`, `reference-host` or `arm64-host`, so the Podman, KVM/microVM, arm64, dm-flakey power-cut, multi-host fleet, real-GitHub-App and real-S3 legs stay open with W03, D04, Q05, W09, G08's timings, R07, AR03 and the measurement waves |
| 2026-11-19 | After-v0.1 code only: Part 25 AR01, Part 18 E01–E09, Part 19 L03–L05, Part 22 Y01, the G08 fixtures | PRs #18–#40, merged as `f8a2afd` … `cf928c1` | Seven migrations kept contiguous: 067 AI policy, 068 artifact classes, 069 runner mode, 070 storage thresholds, 071 storage notices, 072 run-level and runner-mode artifacts, 073 OAuth scope columns. Gate on an unprivileged 2-vCPU Linux container rather than the hosts: `cargo test-linux` 2549 of 2551 passed, and both misses were the disk on a 65 GB volume — the 4 GiB archive test failed `StorageFull` and a CLI signals test's server exited 1 — each passing once 9 GB of incremental artifacts were removed; `cargo lint-linux` clean; web `typecheck`, 81 unit tests and the browser suite at 425 checks; `scripts/check-doc-links.sh` clean. Records committed rather than estimated: `bench/digest-transfer.jsonl` (a repeated 12 MiB artifact costs 3,798 link bytes against 12,617,473, 99.97 % saved, loopback and labelled) and `bench/step-publication.jsonl` (48 MiB published behind a step, 79.8 ms median saved, overlap equal to the publication). Flakes fixed at cause rather than retried: a download-link fixture that could feed an intact token back, an admission counter read before the controller's accept task counted it, and the fleet ranking read while a worker was mid-report; `.config/nextest.toml` runs the fleet binaries one test at a time because they measure the machine. E09 also found one real defect: a worker killed mid-upload left its staging file, its admission charge and the run's artifact-budget hold to the hour-long orphan sweep, and both the terminal-report and lease-expiry paths now release the attempt's publication. Two semantic breaks the merge order caused were caught by the gate and fixed: a preview resolving a run-level artifact's manifest through a job, and tests asserting MCP clients cannot hold `artifacts:read` after the client scope mask admitted it. Still open: every host-only gate (arm64 worker tests, the KVM/microVM suites, the multi-host controller), the generic Git timings on the G08 fixtures, Wave 1's `Closes` list, Q10's stress run and Part 25 AR02 onwards |
| 2026-11-18 | Wave 1 slice and after-v0.1 parts, code only | PRs #4–#17, merged as `31ab681` … `2724c80` | Wave 1 evidence produced on an unprivileged x86_64 Linux account rather than the hosts: `cargo test-linux` 2402 passed, 0 failed, 35 skipped; `cargo lint-linux` and `cargo licenses` clean; the Podman suites (`podman`, `images`, `prefetch`, `executor_faults`, `end_to_end`, the vertical slice, secret isolation, k09) pass as a non-root account, including the foreign-UID workspace case RW04 filed; the ignored `worker_bootstrap_script` suite 10/10; `the_web_interface_in_a_real_browser` green in Chromium; web typecheck and unit tests 64/64. Fixes the gate found: a fake App key and a doc line that tripped the committed-key guard, a backup test racing the scheduler's own first backup, an S3 slow-part upload with a 1.5× margin, a snapshot clone that failed outright where the file system reports neither reflinks nor holes, the container runtime's warnings in a job's stderr, and two Podman shims that assumed the subcommand came first. Parts advanced: Q12's enrollment editor and bounded placement listing, run provenance in the answer and the page, Part 19 L02 class accounting (migration 65), U16 history views, Part 18 E05 streamed archives, Part 16 I11 merge-queue groups (migration 66). Still open in Wave 1: the arm64 worker tests, the KVM/microVM suites, the G08 forge fixtures, and every suite that needs a live multi-host fleet |
| 2026-10-29 | Part 24 reconciliation (pre-wave) | `edd1dec`, `5d0a9c9`, `70f8c80` | RW01 closed; code-fixable Part 24 findings fixed; history up to here in `git show 70f8c80:TODO.md` |
| 2026-10-29 | 0 Code-only completion | branch `wave-0-code-only-completion` (migration 64, release 63 readable) | Reviews 0.1–0.6, 0.8, 0.9 fixed with failure-path tests; worker enrollment page, fake GitHub origin and the sentinel-web compose service built; Wave 2–4 harnesses written. Verified on `reference-host`: `cargo lint-linux`, targeted test binaries, `pnpm -C web typecheck` and `test:unit`, the real-browser test 331/331; locally `cargo fmt-check`, `cargo lint`, `scripts/check-doc-links.sh`. Findings that need a later wave moved there with their blockers. |
