# Audit remediation

The state of the fixes made after the 2026-10 audit, one section per work package, as recorded by each package's implementer and reviewer. Each package lists what was left **deferred** (with the reason), what is **pending verification**, and the reviewer's remaining **review notes**. Anything not listed under deferred or review notes was fixed by the package's branch.

The records give each package's open items, not a numbered list of every original finding, so a finding that is in neither a deferred nor a review note is recorded here as fixed. Status words:

- **Fixed**: changed on the branch; whether it ran is under verification.
- **Deferred**: not changed, with the reason.
- **Review note**: a reviewer's remaining concern; not fixed unless said so.
- **Pending verification**: needs a run that has not happened.

## Verification

Branch `audit-fixes-final`, checked 2026-10-14.

| Check | Where | Result |
|---|---|---|
| `cargo fmt-check` | workstation | passed |
| `cargo lint` | workstation | passed |
| `pnpm -C web typecheck` | workstation | exit 0 (the Vue language tools print a `vue-router/volar/sfc-route-blocks` plugin-resolution warning; no type error) |
| `cargo lint-linux` | verification VPS, `nice -n 19 ionice -c3`, `CARGO_BUILD_JOBS=6` | passed (`Finished`, no warnings), after the fixes below; load before the run: CPU pressure `some avg10=0.88 avg60=5.20`, load average 3.37 |
| `cargo test-cli` | verification VPS, same limits | passed: 1,420 tests run, 1,420 passed, 21 skipped |
| `cargo test-linux` | verification VPS, same limits | passed: 1,463 tests run, 1,463 passed, 21 skipped |
| `pnpm -C web test:unit` | verification VPS | pending: not run |
| Web browser test | verification VPS | pending: not run |

The first VPS pass found Linux-only compile and lint failures and 13 failing tests; the local checks could not show either. All were fixed with `fix:` commits and the passes above are the re-runs. The 21 skipped tests are the ones the suites ignore by default (browser and similar); none was skipped by this pass.

Compile and lint errors that only the Linux build showed:

- `sentinel-worker` `attempt.rs` read `compiled.timeout_secs`, a field the compiled job does not have (it is `compiled.spec.timeout_secs`); `executor.rs` had an unneeded `mut`.
- `sentinel` `source_admin.rs` tests called `unwrap()` on a `Result` whose error type has no `Debug`; they now map it to its message first.
- `sentinel` `service.rs` `Role` tripped `clippy::large_enum_variant`. Boxing the worker link only moved the lint to the other variant, so `Role` carries an `allow` with the reason (one value per process).

Test failures (13), with their cause. Each was confirmed by reading the code; none was fixed by weakening an assertion.

| Test | Cause | Fix |
|---|---|---|
| `sentinel-store::secret_delivery` (4 tests) | The fixture worker reported 0 scratch disk on a profile-protocol session, which the store-timing change now treats as "none offered", so nothing was placed | The fixture offers 1 TiB |
| `sentinel-store::execution an_oversized_summary_is_dropped_and_the_pass_stands` | Test reported `Passed` straight after the acknowledgement; a pass is only valid from finalization | The test walks preparation, steps and finalization first |
| `sentinel-store::logs a_deferred_hole_fill_...` | Frames read back in write order (1, 3, 2), and the test compared to sorted order | Sorts the sequence numbers; still asserts the fill is on disk after a reopen and its resend is a duplicate |
| `sentinel-worker redact::the_automaton_matches_the_reference_scan` | Generated 1 to 6 byte secrets; values under the 4-byte floor are refused, so the reference scan redacted what the automaton never held | Generates values of at least `MIN_SECRET_BYTES` |
| `sentinel-pipeline yaml::errors_carry_positions` | Expected the key in the duplicate-key message, which another test requires to be left out | Asserts `duplicate key` only |
| `sentinel-api http::a_client_holds_one_public_body_slot_...` | The request used bare `
` line endings (rejected as 400), and then sent whole bodies, which never take a slot | CRLF, and each request trickles part of its body |
| `sentinel::service_accounts` (2 tests) | The CLI's static credential cannot step up, so `create`, `allow` and `grant` are now forbidden (authz change, documented there as breaking) | The test asserts exit 3 with `step_up` for those commands, provisions the account and grant in the store with a stepped-up authority, and keeps the list, revoke and refresh checks. The administrative-scope validation can no longer be reached through the CLI (the step-up check comes first); the store test covers the rule |
| `sentinel-link::fleet_sessions` | A hundred enrollments from loopback exceed the new enrollment rate limit (link-dos) | The test enrolls the identities in the store, as an operator would, and the sessions connect as known workers |
| `sentinel-link::link queued_work_reaches_a_connected_worker_on_the_wake...` | Product bug, not a test bug: `offer` gave up on the first BUSY refusal, and the session's own reader holds the connection lock while it takes the previous offer's acknowledgement off the wire, so a second ready job waited for the next reconciliation pass (2.01 s observed against a 2 s budget) | `session::offer` waits up to 20 ms (`OFFER_BUSY_WAIT`) for a connection that is busy for a moment; a peer that holds it longer is still refused as BUSY |

The baseline (`main` at a82b85e) was run on the VPS for the nine of these tests that exist there, and all nine passed, so none of the 13 failures is pre-existing. The other four are tests added by the audit branches.

Not run: `pnpm -C web test:unit` and the web browser test. The VPS has pnpm 10 and the web package pins 12.3.4 (`docs/development.md#where-tests-run` records this as pending), so both stay pending.

The documented flow ships the branch as a git bundle, so nothing was pushed to GitHub. The VPS ran a separate checkout (`/srv/sentinel-af`, a clone from the bundle) so the existing `/srv/sentinel` working tree stayed as it was.

How to read the "Pending verification" lines below: they were written before this pass. Where one names a Rust test or `cargo lint`/`lint-linux`, the suites above ran it and it passed. What is not covered and stays pending: anything that is a measurement or benchmark (B03/B04 re-runs, `bench-noop`, index cost on a large table, latency effects), live checks (a public DNS name through the pin, the VPS Git version, Podman behavior beyond what the executor tests exercise, a live transient-store-error run), script runs (`k02`, `f07`, `b03`), and the web tests (`pnpm -C web test:unit`, the browser test).

## secrets-exposure (`fix/secrets-exposure`)

Fixed: secrets are delivered only to runs whose provenance says a non-manual trigger created them; the API refuses a manual dispatch of a pipeline that declares step `secrets`, step `secret_files` or job `registry_auth`.

Deferred:

- No explicit permission for a creator to receive secrets on a manual run. It needs a new permission bit and a compatibility decision; manual runs never get secrets today.
- The gate checks `trigger != 'manual'`, not that a verified delivery exists. Only intake and the manual API write provenance in production, so it is equivalent today, and tightening it needs `webhook_deliveries` rows in existing tests.
- `pull_request` runs still receive bound secrets, as before. Fork-PR secret policy was outside this finding.

Review notes:

- `docs/secrets.md` says the API refuses a pipeline declaring any job `secrets`; the code refuses on step `secrets`, step `secret_files` or job `registry_auth` (a job-level list nothing consumes is accepted and never delivered). Wording too broad.
- The "declares a secret" predicate is written twice (API check and `prepare`); a shared helper next to `declared_targets` would stop drift.

Pending verification: `sentinel-store --test secret_delivery`; `sentinel-api --test api` (the manual-dispatch test); the secret-using tests in `sentinel-worker` `end_to_end` and `sentinel` `oauth_e2e`; confirm no other fixture delivers secrets to a run created without provenance.

## link-dos (`fix/link-dos-r2`)

Fixed: pre-admission limits with a known-source reserve, enrollment rate limits, a bounded write for offers (`send_bounded`, a busy skip, `is_free`), and a descriptor-based session cap.

Deferred: the lapse-without-close branch of the bounded write has no test (not observable without reading socket options); the busy-then-send-succeeds test covers the closest behavior.

Review notes:

- (med) Finding 4's failure path was untested at review time: a non-reading peer failing within about 250 ms and closing, BUSY without closing when the lock is held, and `is_free` while locked. The branch added the two `session.rs` tests; the lapse branch stays untested.
- BUSY uses `try_lock` on the mutex the reader thread takes per inbound record, so a streaming worker can lose the race and have its offer lapsed with a durable write; treating BUSY as "skip this pass" would avoid the write and fence bump.
- The known-source set is memory-only, so the reserve gives no protection right after a controller restart. Under Tailcat every peer arrives from loopback, so per-source accounting does nothing there.
- The enrollment limiter caps the rate (20 per minute globally) but not the total; `WorkerEnrollmentRefused` rows grow without bound, and one tailnet peer can exhaust enrollment for everyone.
- The descriptor headroom is a fixed 256 and ignores other descriptor users in the process; `setrlimit` is a process-wide side effect and children inherit the raised soft limit.

Pending verification: the two new `session.rs` tests (loose 2 s bound for loaded hosts); the unix-only `libc` rlimit code under `cargo lint-linux`.

## worker-lifecycle (`fix/worker-lifecycle-r2`)

Fixed: workspace and spool handling, shutdown and keepalive bounds, cgroup freeze, redaction forms (base64 and percent-encoding), identity save ordering.

Deferred:

- Podman checks (`--entrypoint /bin/sh` with the `sh -c` countdown argument `$1`, `--ulimit fsize=N:N`) and the live shutdown test need the VPS.
- `Executor::register_secret` still ignores the refusal for values under 4 bytes on the test and inspect-fixture path; real bound secrets are checked at delivery.

Review notes:

- (med) The redaction floor of 4 bytes is justified by the secret's minimum length at creation, but `docs/secrets.md` allows 1 to 65,536 bytes. A 1 to 3 byte bound secret is still delivered and never redacted, with no log line. Enforce a matching minimum or surface the refusal.
- (med) `docs/secrets.md` still describes short-value redaction as before and omits the base64 and percent-encoding forms; `logs.md` and `executor.md` were updated.
- (med) Linux-only code was uncompiled at review time (the `O_PATH`/`openat` walk, `pre_exec`, cgroup freeze, shutdown, the new `Limits` fields). This round's `cargo lint-linux` found one compile error and one unused `mut` in the worker crate (see Verification) and nothing else.
- `identity()` now deletes a lone surviving `.crt` or `.key` and mints a new identity, which changes the controller fingerprint and breaks pinned workers; recover only when the lone file is the key.
- The `private_dir_all` comment says a symlinked directory is left alone, but the code follows the link and chmods the target.
- The keepalive bound is job timeout plus 5 minutes; an attempt still in prepare at shutdown may create a container afterwards.

## source-access (`fix/source-access`)

Fixed: a manual-remote destination policy (resolve, refuse private and IP-literal destinations, pin the resolved address for https fetches), bound-access validity windows, uniform refusal messages.

Deferred:

- No config file or CLI flag for the manual-destination allowlist; it is an environment variable on controller and worker.
- The mirror path with `access=None` (tests only) is outside the destination policy.
- The worker's validity window uses the wall clock read at receipt, not a monotonic `Instant`, because that would add a `JobContext` field; a clock step during one checkout could expire it.
- The link test cannot simulate a worker clock ahead of the controller; skew is covered by the protocol-level rebase unit test.
- No minimum Git version for bound fetches (the unreadable `HOME` makes it unnecessary); 2.37 applies only to unbound manual remotes.
- Existing tests that might name an IP-literal manual remote were checked by grep only.

Review notes:

- `git_can_pin` caches a transient `git --version` failure for the life of the process, so every unbound https remote is then refused until restart (fails closed, sticky).
- Each manual-remote resolve spawns a detached thread that stays blocked if the resolver hangs.
- Manual-remote admission now refuses https remotes that were accepted before (IP literals, bare hostnames, private suffixes); `docs/compatibility.md` has no entry.
- A fetch failure still returns after the fetch time, so latency distinguishes it from a refusal; the message text is uniform.

Pending verification: `sentinel-protocol`; `sentinel-store --test sources`; `sentinel-git` (unit and `manual_destination`); `sentinel-link --test source_delivery`; `sentinel-worker --test checkout` and `--test mirror`; VPS git is 2.37 or newer; a live check that a public DNS name still fetches through the pin (`curloptResolve` format `host:port:addr`, IPv6 bracketed); an end-to-end test of the 12-minute window and the fallback after a mirror timeout.

## checks-s3 (`fix/checks-s3`)

Fixed: throttle handling that parks a row instead of pausing the lane, quarantine of rows whose store writes keep failing, S3 delete recheck, backup pruning that waits for a running backup, the rerequest job reset as a CAS on state.

Deferred:

- Receipts are still purged after 30 days (justified in `docs/checks.md`: a replayed lifecycle event only triggers an authenticated refresh or revoke, a replayed rerequest reruns at most the newest terminal run, capped at 64).
- `checks::due` still fails the whole read if one row cannot be decoded; row-level quarantine or a schema guarantee is needed.
- The exhausted-final-check re-arm runs only at lane start; a periodic re-arm needs a counter column and so a migration under `docs/compatibility.md`.

Review notes:

- Only `StoreError::Corrupt` parks a row; a row-specific `rusqlite` error maps to `store`, backs the lane off and never settles the row, so it can starve others.
- `store_fault` counts Sqlite, InvalidInput and NotFound toward quarantine; three transient `SQLITE_BUSY` or disk-full failures can park an innocent final check for 1 h.
- The rerequest reset is a CAS on `state_code` only; it still bypasses the attempt, lease and cancel fences.
- `replicate.rs` `deletes()` is safe only because the single replicator runs deletes before uploads; that ordering is not asserted.

Pending verification: `sentinel-store` tests `checks`, `github_events`, `intake`, `replicate`, `backup`; `sentinel-checks` tests `lane`, `delivery`, `reconcile`; `sentinel-s3` unit and compat suites; `File::lock` behavior on the VPS filesystem; throttle timing in the `delivery.rs` rate-limit test. No performance claim was made; the backup rehash cost is unmeasured.

## api-hardening (`fix/api-hardening-r2`)

Fixed: per-client public-body slots with a 10 s deadline, login guard keyed by client and account, canonical OAuth redirect URIs, secret-input handling in `source_admin`.

Deferred:

- No minimum-rate deadline (the reviewer offered it as an alternative); the 10 s total deadline stays.
- Many distinct client addresses can still occupy all 4 slots for up to 10 s each (bounded by admission budgets, documented in `docs/api.md`).
- Behind a trusted proxy that sends no `X-Forwarded-For`, all clients share one key.
- Wiping serde-parsed JSON copies and `creds.password` is best effort, so finding 7 is only partly closed.

Review notes:

- (med, at review time) The 4 slots were one shared pool; the branch added a per-client cap and a test where one peer holding its slot does not block a second. A trusted-proxy peer is still exempt from the cap.
- The login lockout key is (client, account), so a few addresses can still reach the account lock for `root`; the docs overclaim that a stranger cannot lock out the super admin and must state the dependency on a correct `X-Forwarded-For`.
- No HTTP-level test of the new `POST /login` behavior (429 with `retry_after_ms`, locked client without a store call, `Busy` mapping); existing login-heavy tests were not checked against the new budget.
- `valid_redirect_uri` requires the canonical form, so previously accepted registrations (bare host, explicit default port, re-encoded) now fail with `invalid_client_metadata`; no `docs/compatibility.md` entry, and stored non-canonical registrations are not discussed.
- The `OUTBOUND` doc comment in `lib.rs` is a garbled run-on sentence.

Pending verification: the `sentinel-api` `http` tests, including the per-client body-slot test and `stalled_public_bodies_hold_no_handler_permit`.

## authz (`fix/authz-r2`)

Fixed: tenant-membership oracle removed, platform-override audit (event code 57) and `reason`, step-up for minting service credentials, service grants revoked on logout-all, password change and recovery.

Deferred:

- No invitation and accept step (needs a table, route and UI). A non-consensual add is audited as `member-added` and documented; adding a non-member needs the 128-bit `usr_` id.
- The `usr_` id response difference (active non-member succeeds, unknown or inactive is NotFound) is not equalized.
- Grants minted by a session that expired and was purged, or revoked individually before this change, stay outside the revoke window.

Review notes:

- (med) `docs/compatibility.md` has no entry for: audit code 57, the optional `reason` body field on member, repo-grant and service-account routes, `sentinel service-account create|allow|grant` now always failing from the CLI (breaking), `GET /grants` and `DELETE /grants/{id}` needing scope, sign-in names resolving only among tenant members, and revocation of service grants on logout-all, password change and recovery.
- (med) Revoking a single session by name does not review the grants it minted, and a session already expired or revoked falls outside the `revoke_all` window.
- (med) The brief's non-consensual admin grant is only audited, not removed; no audit exists for adding a person who is not yet a member beyond `MembershipSet`.
- `allow_repo` with `Permissions::NONE` (withdrawing access) needs fresh step-up and, for a platform admin, a reason; narrowing access is gated like minting.
- `revoke_minted_since` filters on `created_by`, which has no index; no query plan or timing was checked.
- The web UI adds members by typed username and sends no `reason`, and the CLI service-account commands always fail, so there is no usable path to create a service credential until the UI and CLI packages land; they should ship together.

Pending verification: `sentinel-store` tests (in particular `oauth_service`, `tenant_access`) and `sentinel-api` tests. The Windows `cargo check` did not cover the api crate.

## web-server (`fix/web-server-r2`)

Fixed: proxy path classification and body caps, `clientIpHeader` handling in the Nuxt server.

Deferred: none.

Review notes:

- (high, resolved) `classifyProxyPath` once ran the ambiguity regex on the whole raw target including the query, which would have broken `/oauth/authorize?redirect_uri=...` and GitHub sign-in return paths. On this branch it tests only the path portion (`bare`), and the query is never inspected. Read in this pass, not run; there is still no test with an encoded query on a proxied path.
- The webhook cap is 4 MiB while `sentinel-protocol` defines a 25 MiB `MAX_WEBHOOK_BODY_BYTES`; if the larger is the real limit, large GitHub webhooks get 413 at the web hop. No test ties the two.
- The proxy's broad `catch` turns every `sendProxy` failure into 502; the 413 and 502 branches have no test and `h3` behavior with stream bodies is unverified.
- `clientIpHeader` defaults to `""`, so per-client rate limiting stays collapsed behind the proxy until `NUXT_CLIENT_IP_HEADER` is set and the controller's `trusted_proxies` includes the web hop.

Pending verification: `pnpm -C web test:unit` on the VPS (not run in this pass).

## pipeline-semantics (`fix/pipeline-semantics`)

Fixed: job `if` conditions evaluated by the store (`Event::ConditionFailed`, jobs with an `if` and no `needs` start Blocked), expression typing and status functions, duplicate-key rejection in YAML, artifact manifest and mode handling, `cancel_requested` set on supersede.

Deferred: none.

Review notes:

- The plan and status code report an `if` job that starts Blocked as waiting on a dependency; `docs/compatibility.md` says no reader depends on it.
- Job-level `failure()` counts a skip caused by a failure as a failure while worker step `if` and `needs.<job>.result` see `skipped` (documented in `pipeline-schema.md`).
- The `CompileError::Encoding` path has no test (postcard cannot fail for these types).
- `docs/core-contracts.md` has a stray double blank line.

Pending verification: the new tests (`pipeline_semantics.rs`, the `state.rs` ConditionFailed test, `expr.rs` typing and status tests, the `schema.rs` cpu test, the `yaml.rs` duplicate-key test, `objects.rs` manifest and mode tests, `fixtures/pipelines/invalid/if-type-mismatch.yml`); existing tests that may change (store `dispatch.rs`, `image_resolution.rs`, `secret_delivery.rs`, `checks.rs`, `github_events` rerequest, intake `cancel_in_progress`, and any test expecting a job with an `if` and no `needs` to be Queued).

## bench-evidence (`fix/bench-evidence`)

Fixed: benchmark records carry commit, host and conditions (PSI, steal, governor), ABBA interleaving (`--interleave`), mandatory `--source` for `bench/b03-latency.py`, B03 split into B03a and B03b in `TODO.md`.

Deferred:

- The flat 100.1 ms failure-query p50 is not fixed; probable cause is the nonblocking accept loop's 100 ms sleep (`http.rs`), untested (tracked as B03b).
- The 58.7 ms webhook ACK is not explained by the accept sleep; not identified (B03b).
- The 0 to 100 ms log-visible spread is probably the `LOG_RECHECK` throttle; recorded as unverified.
- Raw data for the unrecorded claims (B04 fetch, 8.5 ms and 15 ms, web-ui resources, 114-check numbers, A02 and A03 timings) was not found, so none was invented; each is marked for re-measurement.
- The Parts 09-11 row dated 2026-09-27 citing WSL2 runs is flagged "for the owner", not rewritten.
- The old `bench/*.jsonl` records are not back-filled with commit or host.
- Re-running K02, F07, B03 and B04 with the new scripts and a `cargo check` of the unix-only `cpu_steal_ns` are pending.

Review notes:

- The warm-podman refusal check is redundant with plan building; `warmup-run` is assigned whenever `warmup>=1`.
- The interleaved group shares one conditions block across runtimes; no end-to-end `--interleave` test (only `abba_order`).
- No caller script shows how to pass `SENTINEL_SRC` and `SENTINEL_BIN` to the now-mandatory `--source`; dirty detection counts untracked files.
- B03 stays `[x]` although cancel to termination (3.42 s vs 2 s) and the failure body size (10.2 KiB vs 8 KiB) miss budget; cancel has no open follow-up item.
- The K02 and F07 scripts were not run; the `shuf` order is not recorded as a seed.

Pending verification: `cargo nextest -p sentinel-bench`; `bench-noop` with `--interleave scoped` and `podman`; `bash -n` and a short run of `k02-cache-clone.sh` and `f07-storage.sh` (root for `drop_caches`); `python3` syntax check of `b03-latency.py`; B03 and B04a re-runs.

## docs-hygiene (`fix/docs-hygiene`)

Fixed: documentation corrections, removal of unused dev-dependencies (and the matching `Cargo.lock` lines), a "Panicking calls in production code" section in `docs/development.md`.

Deferred:

- `TODO.md` X04 row still links `auth-and-secrets.md#3-remote-mcp` (heading is "3. Remote MCP OAuth"); the `TODO.md` owner must change it.
- The three PEM keys in `sentinel-checks` `delivery.rs`, `reconcile.rs` and `sentinel` `intake_e2e.rs` appear to be one test key (only the start of the bodies was compared); if it was ever a real GitHub App key, regenerate and rotate.
- The unwrap/expect site count (149 vs the audit's 152) is approximate; about 38 are Mutex-poison panics in `tailcat.rs`.
- The power-loss/fsync blocker in `docs/parts-01-02-audit.md` is unannotated because no evidence it was closed was found.

Review notes:

- The per-file panicking-call list can drift and does not say which sites are reachable from untrusted input.
- `README.md` and `plan.md` say Part 14 is in progress; `TODO.md` is consistent enough but will drift.

Pending verification: `cargo lint --locked` confirming `Cargo.lock` matches (the workstation `cargo lint` passed with `--locked`); the Linux-only comment-only changes under `cargo lint-linux`.

## auth-flows (`fix/auth-flows-r2`)

Fixed: `GET /me/security`, MFA enroll and confirm, recovery codes, password change, GitHub identity link routes, and the host-local `admin mfa` CLI commands.

Deferred: none.

Review notes:

- (med) `docs/compatibility.md` has no entry for the six new `/api/v1` routes, the three CLI commands and the behavior changes (wrong current passwords count against the session, step-up for a password change when a factor is enrolled, in-memory link state).
- `change_password` verifies the current password before validating the new one, so `invalid_request` vs `forbidden` is a small oracle; validate the new password first.
- `MAX_LINKS=256` lets a stepped-up user evict other users' pending link attempts.
- Beginning an MFA enrollment (superseding a pending one) writes no audit row.
- `sentinel mfa confirm --code` passes the TOTP code in argv.

Pending verification: none recorded by the package; Linux-only `admin.rs` and `tests/mfa_admin.rs` are covered by `cargo lint-linux` and the test runs above.

## store-timing (`fix/store-timing-r2`)

Fixed: batched retention reapply, new indexes (migration 049), a deferred queue so a transient store error keeps a worker report, a worker that holds a verdict until the controller confirms.

Deferred:

- The worker side of issue 2 is tested only for the pure resend and keep selection; an end-to-end test needs a fault seam in the live harness.
- No test with many other-tenant rows; the `EXPLAIN QUERY PLAN` test is the deterministic check, and the latency effect of the indexes is unmeasured.
- Whether SQLite accepts `INDEXED BY` on the partial index `attempts_log_reapply` for the bound SELECT and the UPDATE is unexecuted.
- Migration number 49 may collide with another parallel branch.

Review notes:

- (med) Batching bounds rows updated, not rows scanned; without a `(tenant_id, id)` index the last batch may scan the table in one writer transaction. Not demonstrated either way.
- (med) Finding 2 has no failure-path test (injected `WriterUnavailable`, `WriteAmbiguous` or `Overloaded`, retry order, the 5 min and 256 drop paths).
- A deferred Ack does not shield its attempt, so the offer-ack window can lapse before the retry.
- A cancel-desired `Pong.stop` is taken by a worker as confirmation of a deferred verdict; a controller restart in the (at most 5 min) window loses it.
- The worker's own 5 s resend counts in `stale_reports`; `held` now includes unconfirmed attempts and can exceed `MAX_HELD_ATTEMPTS`.
- A profile-protocol worker that reports disk 0 now takes no work, with no operator-visible signal.

Pending verification: `sentinel-store` (retention, upgrade, schema, the `EXPLAIN QUERY PLAN` test), `sentinel-link --features controller`, `sentinel-worker`; the `INDEXED BY` statements; the cost of the new indexes on a large attempts table; live behavior of a transient store error during a report.

## hotpath-perf (`fix/hotpath-perf-r2`)

Fixed: log-ack batching with deferred sync, a blocking accept loop with loopback wake-up, a rewritten free-capacity statement, a streamed check aggregate, a 2 s default for `Config::idle`; a follow-up commit makes a deferred hole fill durable before the sidecar records the hole closed.

Deferred: the new test, `a_deferred_hole_fill_is_on_disk_before_the_hole_is_recorded_closed`, cannot simulate power loss; it checks visible behavior only.

Review notes:

- (med, addressed by the follow-up commit) `persist_holes` fsynced the sidecar before the fill frame was durable, so a power loss could acknowledge bytes not on disk.
- `Conns::shutdown` can spend about 6 s retrying the loopback self-connect and then leave the acceptor detached with the listener bound; untested.
- `FREE_CAPACITY_SQL` now uses an uncorrelated derived aggregate; whether `placement_statements_plan_their_indexes` and the scan-counter test still pass is unverified.
- `record_aggregate` no longer decodes `failure_class`, so a corrupt value no longer yields `Error::Corrupt` there (harmless).
- No bench was added for log-ack batching, the checks lane or S3 hashing; all performance claims are pending VPS measurement.

Pending verification: `sentinel-store --test logs`; the `sentinel-api` `http` tests for the blocking accept; the placement plan tests.

## auth-ui (`fix/auth-ui-r2`)

Fixed: sign-in and session handling in the web interface, a reason field for platform administrators, step-up dialog, show-once modal.

Deferred: `web/app/middleware/auth.global.ts:8` did not need a change; the base already routes the signed-in `/login` branch through `sameOriginPath` (commit `fc03e3d`), so `//evil.example` and `/%5Cevil.example` fall back to `/`. The reviewer's note below is therefore resolved.

Review notes:

- (med, reviewer) The global middleware checked `next` with `startsWith("/")`. On this branch `auth.global.ts` calls `navigateTo(sameOriginPath(to.query.next))`, as the implementer reported.
- `docs/step-up.md:43` still says the web interface does not collect a reason.
- `ServiceAccounts.vue` shows a spurious "done" toast on a GET (`loadGrants` goes through `useAct`).
- `useStepUp.ts` decides the dialog from `!!me.username` rather than the `password` flag of `GET /me/security`.
- `ShowOnceModal.vue` revokes the blob URL in a 0 ms timeout, which some browsers abort mid-download.
- After a password change an in-flight 401 can set `me` to null first, so sign-in shows "Your session ended" instead of "Password changed".

Pending verification: none recorded by the package; covered by `pnpm -C web typecheck` (passed) and the web tests pending above.

## Cross-cutting items

- `docs/compatibility.md` is missing entries for several packages (authz, auth-flows, source-access, api-hardening); AGENTS.md routes contract changes through that file.
- Several packages renumber or add migrations (store-timing adds 049); the integrator should confirm no collision.
- The web UI and CLI packages should ship together with the authz changes.
