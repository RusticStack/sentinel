# Parts 00–09 audit: requirements, evidence, correctness and bounds

This audit ran on `part-09` at `70398a5`. Eight read-only auditors each took one part: Parts 00–02, 03, 04, 05, 06, 07, 08 and 09. For every task ID they checked:

- every requirement in the task text against the code;
- every completion-log claim against the named tests, docs and records;
- correctness and security: error paths, tenant isolation, credentials in diagnostics, durable transitions and crash recovery;
- bounded resources and rule-one cost;
- regressions from later parts.

They also checked that the fixes from the [Parts 01–02](parts-01-02-audit.md), [Part 03](part-03-audit.md) and [Parts 01–06](parts-01-06-audit.md) audits were still in place. Each finding was marked CONFIRMED (reproduced, or unambiguous from the code) or PLAUSIBLE. Scratch reproductions lived outside the repository and became regression tests in it.

Seven clusters fixed the findings in parallel worktrees. Each fixer re-verified its findings before changing code. Base commits and merge commits (all `--no-ff`):

| Cluster | Base | Merge |
|---|---|---|
| foundation | `70398a5` | `2a33afc` |
| auth | `70398a5` | `e7ca30a` |
| intake | `70398a5` | `678bad6` |
| storage | `211256f` | `4b81a9d` |
| cache | `70398a5` | `0142aba` |
| execution | `cfcba5d` | `84afa74` |
| fleet | `cfcba5d`, which includes the Q10 fix | `5442ca7` |

Ten follow-up commits closed what the merges left open or what verifying the merged tree found (see [Found during integration](#found-during-integration)).

**Migrations** were renumbered into one contiguous sequence at merge time. The fix branches used 037, 031, 034, 032 and 036. The final names are:

1. `031_foundation_hardening`
2. `032_auth_hardening`
3. `033_intake_hardening`
4. `034_storage_hardening`
5. `035_fleet_scheduling`

A compile-time contiguity check added by P02-6 now enforces the order. The **worker protocol maximum is 8**. Only the cache cluster raised it, for `CacheCancel`, `Trust::Unprotected` and availability refreshes. The execution cluster made the lease length a protocol constant (`LEASE_MS`) without a version bump.

The bar was the same as in the Parts 01–06 audit. An operational failure must be one of these:

- returned to the caller;
- durably recorded;
- retried by a lane;
- best-effort cleanup whose residue a sweep reclaims;
- reported in diagnostics that do not claim success.

In addition, every task requirement is met by working code, not a scaffold.

Regression tests are named as `crate/tests/file.rs::test` or as `module::tests::test` for unit tests. "Fails before" means the fixer ran the test on the base tree and it failed there. The fleet, storage and intake reports say which of their tests were checked this way.

## Part 00–02 — groundwork, foundation and contracts (P01–P03, F01–F07, C01–C08)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P02-1 | medium | The API answered `WriteAmbiguous` with retryable `429 rate_limited`. | A client retrying an unkeyed POST after a slow fsync could create a second run. | New code `outcome_unknown` (503, not retryable, `details.retry_with_idempotency_key`). The CLI repeats it only when the request is safe or carries an idempotency key. `ErrorCode::Unknown` lets older builds parse codes they do not know (`737d8e2`, `9138fac`). | `sentinel-protocol` `error::tests::an_ambiguous_write_is_unavailable_and_never_blindly_retryable`, `an_unknown_code_from_a_newer_server_still_parses`; `sentinel-api` `routes::tests::only_a_write_that_may_commit_is_reported_as_outcome_unknown`; `sentinel/tests/client.rs::an_unknown_write_outcome_is_repeated_only_under_its_idempotency_key` |
| P02-2 | medium | Idempotency records were never purged. | The `idempotency_keys` table grew without bound. | `idempotency::purge_expired` deletes up to 1,000 rows per tick, oldest first through `idempotency_by_age`. The maintenance tick runs it (`fde9833`). | `sentinel-store/tests/verification.rs::expired_idempotency_records_are_purged_in_bounded_batches`; `idempotency::tests::the_purge_is_an_index_range` |
| P02-3 | medium | No route used the C03 cursor. A malformed log `after` silently restarted from 0. | A corrupt cursor replayed the whole log. The compatibility contract listed `c1` as a live format. | The log route rejects a malformed `after`, `limit` or `step`. It emits and accepts a tenant-bound `c1` cursor, making it the first route to carry one (`14f4cd0`). The docs were made accurate (`20bbeb1`). | `sentinel-api/tests/api.rs::log_pages_are_bounded_and_positions_are_validated` |
| P02-4 | low | `pipeline validate/explain` checked the file size, then read the file without a cap. | `/dev/zero` or a FIFO grew memory until the process was OOM-killed. | New module `sentinel::bounded` with `take(limit+1)`. Every CLI file reader now uses it (`9138fac`). | `sentinel/tests/cli.rs::pipeline_validate_bounds_the_read_of_an_endless_device` |
| P02-5 | low | `RunSpec::decode` accepted trailing bytes. | Corrupt or concatenated specs went undetected, although the policy said readers reject them. | `take_from_bytes` with an empty remainder required, for v3 and v4 (`27ac95e`). | `run::tests::a_blob_with_trailing_bytes_is_not_a_spec` |
| P02-6 | low | Nothing enforced migration order or contiguity. | A merge that renumbered migrations badly could split schemas across installations. | A `const` contiguity assert, plus `migrate` refuses `version != current+1` (`27ac95e`). | `schema::tests::migration_versions_are_strictly_ascending_and_contiguous_from_one` |
| P02-7 | low | Run-spec immutability was a convention only. | Raw SQL could rewrite what a rerun would execute. | Trigger `run_spec_immutable`, migration `031_foundation_hardening` (`27ac95e`). | `sentinel-store/tests/runs.rs::a_stored_run_spec_cannot_be_rewritten_even_by_raw_sql` |
| P02-8 | low | The general protocol-versioning rule said optional fields need no bump, which contradicts Protocol 7. | Following it would break older workers' decoding. | Rule rewritten: new variants are additive; new or changed struct fields bump the protocol (`20bbeb1`). | None (docs only) |
| P02-9 | low | `GET /tenants/{slug}/repos` answered 200 for a foreign tenant and 404 for a missing one. | Tenant existence oracle. | `auth::member_tenant_by_slug`, the same fix as P03-7 (`b3fc93d`). | `sentinel-api/tests/api.rs::a_foreign_tenant_slug_lists_as_not_found`; `sentinel-store/tests/cross_tenant.rs::slugs_and_names_resolve_only_for_members` |

Evidence corrections (foundation, `20bbeb1` and `cbde766`):

- **F05:** the committed baseline records lack `source.git_commit`, `git_dirty` and `tools.rustc`. The runner now always records them and refuses to write a record without a commit. A correction note in [benchmarking](benchmarking.md) leaves the old values absent rather than filling them in. Test: `sentinel-bench/tests/runner.rs::a_record_names_its_source_and_compiler_even_outside_the_checkout`.
- **C02 engine record:** its provenance is documented, and `bench/c02-engines.sh` is labelled as not reproducing the original numbers.
- **[Storage](storage.md):**
  - The stale "open gates" text was replaced.
  - The commit notifier is now documented.
- **[Compatibility](compatibility.md):**
  - The "marker types" claim was corrected.
  - The crash test is described as proving commit-before-acknowledge ordering, not fsync durability.
- **[Protocol](protocol.md):** the limits table now lists the artifact and OAuth-form limits.
- **`Hello`:** the comment now says `software` is bounded only by the frame.
- **Still open:** README.md line 5 still says the Parts 01–02 audit "records open execution-integration gates". The integrator must correct it; see the TODO edits.

## Part 03 — identity, tenants and registration (A01–A08)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P03-1 | high | Invitations kept their power after the inviter was removed, suspended or demoted. | A departing admin could mint a TenantAdmin invitation first and come back through it. | The redeem statement re-checks the inviter's live authority: `active`, and `super_admin` or tenant admin. Host-local invitations are unaffected (`cde19ef`). | `sentinel-store/tests/registration.rs::an_invitation_dies_with_its_inviters_membership`, `…_suspension`, `…_downgrade_to_reader`, `a_tenantless_invitation_dies_with_super_admin_demotion` |
| P03-2 | high | The step-up failure limit was per session only. | Anyone with the password could guess TOTP indefinitely by logging in again. | Per-account counter in migration `032_auth_hardening`. Ten failures lock second factors for 15 min and revoke every session. Recovery clears the lock (`cde19ef`). | `sentinel-store/tests/mfa.rs::step_up_failures_accumulate_across_sessions`, `an_account_lockout_refuses_even_a_correct_code_until_it_expires`, `host_local_recovery_clears_the_step_up_lockout` |
| P03-3 | medium | `registration::reject` deactivated approved accounts, including super admins, without step-up, and irreversibly. | An unstepped platform bearer could lock out other super admins. | An approved target requires `require_privileged`; rejecting a pending account stays platform-only (`cde19ef`). | `registration.rs::rejecting_an_approved_account_needs_step_up` |
| P03-4 | medium | `POST /api/v1/login` accepted cross-site `text/plain` form posts. | Login CSRF: a victim could be signed in as the attacker. | The route requires `content-type: application/json` and refuses a foreign `Origin` (`b3fc93d`). | `sentinel-api/tests/api.rs::login_refuses_a_text_plain_body`, `login_refuses_a_foreign_origin` |
| P03-5 | medium | The idle deadline never slid, and the cookie expired after 8 h. | Active users were logged out after 8 h. | `identify` refreshes a session when it is due, at most one write per 5 min. The cookie `Max-Age` is now the absolute lifetime (`cde19ef`, `b3fc93d`). | `api.rs::an_active_session_outlives_its_first_idle_deadline` |
| P03-6 | low | After a lockout ended, a single wrong password locked the account again. | One request every 15 min kept any account locked. | An ended lockout window restarts the count in the same UPDATE (`cde19ef`). | `sentinel-store/tests/local_auth.rs::a_single_failure_after_an_ended_lockout_does_not_lock_again` |
| P03-7 | low | Same oracle as P02-9: the repository listing told existing tenants from missing ones. | Any signed-in user could enumerate tenants. | `member_tenant_by_slug`, used by the listing and the four service-account routes. The `lookup` module's contract was rewritten (`b3fc93d`). | `api.rs::a_foreign_tenant_slug_lists_as_not_found`; `sentinel-api/tests/oauth_service.rs::a_foreign_tenant_is_not_found_like_a_missing_one`; `cross_tenant.rs::slugs_and_names_resolve_only_for_members` |

Doc corrections (`cde19ef`, `b3fc93d`):

- **Stale "no HTTP server" text:** removed from [local authentication](local-authentication.md), `cookie.rs` and the [Part 03 audit](part-03-audit.md).
- **`revoke_all_for_user` comment:** corrected.
- **[Step-up](step-up.md) table:** now includes suspend/reactivate, `sign_in::link`, `provision_credential` and the new `reject` rule.
- **Part 03 audit:** the reject rationale and the A08 test locations were corrected.

## Part 04 — first durable server/worker execution (W01–W09)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P04-1 | high | A retryable `Unavailable` refusal stopped the worker link for good. | After a controller restart, a herd of reconnects could leave workers idle until an operator restarted them. | `worker::run` retries `Unavailable` with jittered back-off (`4b6dd39`). | `sentinel-link/tests/hardening.rs::an_unavailable_refusal_is_retried_and_the_worker_connects` |
| P04-2 | high | A reconnecting worker was welcomed at its enrollment-time protocol. | Upgraded workers never sent a `Profile`. Rolled-back workers entered a decode-error loop. | Every hello renegotiates, and the result is saved with capacity. An architecture change is refused. `connect` refuses a `Welcome` outside the hello's range (`414f3ca`, `4b6dd39`). | `hardening.rs::a_reconnecting_worker_is_renegotiated_and_recorded`, `a_welcome_outside_the_hellos_range_is_refused`; `sentinel-store/tests/execution.rs::renegotiation_records_upgrades_and_rollbacks_but_not_a_new_architecture` |
| P04-3 | high | Cancelling one unstarted job never decided its dependents. | The run stayed `active` forever. | `dispatch::cancel` releases dependents in the same transaction (`414f3ca`). | `execution.rs::cancelling_an_unstarted_job_skips_its_dependents_and_ends_the_run`; `api.rs` now asserts the dependent is `skipped` |
| P04-4 | high | `NoSpec`, including the 8-permit overload answer, silently dropped an acknowledged attempt. | Bursts of more than 8 jobs ended in `infra_failed` 30 s later with nothing run. | A bounded `SpecDesk`: 8 resolvers, a per-worker cap, a fleet cap of 4096, and dedup. Transient faults are left for the worker to re-ask; after 60 s it hands the attempt back with `Decline`. A definitive `NoSpec` makes the worker report `Preparation` at once (`414f3ca`, `4b6dd39`, `9d99000`). | `controller` unit `the_spec_desk_serves_a_burst_past_its_resolver_bound_in_order`; `execution.rs::a_decline_is_fenced_and_hands_back_an_acknowledged_attempt_that_never_started` |
| P04-5 | medium | The lease watchdog reported what it killed, and compared two hosts' wall clocks. | Clock skew produced false `canceled` verdicts. | Attempts ended by the watchdog are marked `lost` and not reported. The lease is the protocol constant `LEASE_MS`, measured monotonically from the Ping send and seeded from the offer. A worker `Canceled` without a cancel request is reclassified as `Runtime` (`414f3ca`, `9d99000`). | `execution.rs::a_canceled_report_without_a_request_is_not_recorded_as_a_cancel`. No dedicated skew test; the watchdog runs inside Podman-backed `end_to_end.rs` and `slice.rs`. |
| P04-6 | medium | `Container::destroy` skipped `rm -f` when `stop` failed. | Containers kept running after their verdict was reported. | Removal always runs (`9d99000`). | `sentinel-worker/tests/runtime_failures.rs::teardown_removes_the_container_even_when_its_stop_fails` |
| P04-7 | medium | Worker recovery skipped reaping when `podman ps` failed. | Previous processes kept running while their attempts were abandoned. | Listing and removal errors propagate, and `Executor::start` fails before any offer (`9d99000`). | `runtime_failures.rs::recovery_fails_when_the_runtime_cannot_list_what_it_owns`, `recovery_fails_when_a_leftover_container_cannot_be_removed` |
| P04-8 | medium | One global mutex held every controller log fsync, and the writer waited on it via `has_end`. | Log load stalled placement and reports. | Execution: the writer no longer calls `has_end`, and frames are encoded from borrowed data (`4b6dd39`). Storage: the map lock is only a lookup, and I/O runs under a per-attempt lock (`966062d`). | No contention test. The storage report measured it (see Measurements). |
| P04-9 | medium | Unauthenticated peers could hold all 1024 session slots. | Reconnecting workers could be locked out. | An absolute 10 s `HANDSHAKE_DEADLINE`, plus a `MAX_PENDING` cap of 256 on pre-authentication connections (`4b6dd39`). | `hardening.rs::stalled_handshakes_are_cut_at_their_deadline_and_cannot_lock_workers_out` |
| P04-10 | medium | A failed ack write was swallowed and the spec was still served. | Work could run twice. | `job_context` and `spec_bytes` require `acked_ms` (`414f3ca`, `4b6dd39`). | `execution.rs::the_spec_is_served_only_after_the_acknowledgement` |
| P04-11 | medium | Transient controller faults were answered with a permanent `LogRefused`. | Passing jobs were flipped to `Publication`. | `LogVerdict::Retry` closes the connection instead. The worker clears `refused` on attach (`4b6dd39`, `9d99000`). | `hardening.rs::a_transient_log_fault_closes_the_connection_instead_of_refusing` |
| P04-12 | medium | Redaction registration was executor-global and snapshotted at spawn. | Values could not reach a live attempt. All tenants shared one unbounded list. Prefix probing across tenants was possible. | `register_secret(attempt, value) -> bool`, per attempt, live or pending. The global list is gone (`9d99000`). | `logpipe::tests::registration_is_per_attempt_and_takes_effect_while_it_runs` |
| P04-13 | medium | The protocol-7 bulk connection had no keepalive, and frames lost when it closed were acknowledged past. | Quiet-then-print steps lost log data. | Idle bulk lives as long as its session. On detach, the pipe rewinds to the acknowledged sequence before any fallback send (`4b6dd39`, `9d99000`). | `hardening.rs::an_idle_bulk_connection_lives_as_long_as_its_session`; `spool::tests::rewinds_to_the_acknowledgement_resume_at_the_recorded_offset` |
| P04-14 | medium | A cancel during an offer, followed by a lapse, parked the job `Queued` for 6 h. | The job ended `timed_out`, and supersession was blocked. | `lapse` and `decline` share `give_back`, which applies `CancelBeforeStart` and releases dependents (`414f3ca`). | `execution.rs::a_cancel_recorded_while_offered_ends_the_job_when_the_offer_goes_back` |
| P04-15 | medium | A cancel could be lost for the rest of a step. | Capacity stayed held up to the job timeout. | `step_pids` reads nested cgroups. `canceling` resets on `Gone`/`Err` so the next beat retries (`9d99000`). | None: needs a real exec race or a nested-cgroup runtime. Exercised by the `end_to_end.rs` cancel scenarios. |
| P04-16 | medium | Cancel did not kill `git` or `podman pull` helpers. | A slot could stay "canceling" for about 25 min. | `sentinel_git::cancel_scope` and `process::run_canceled` kill helper process groups. Followers of a cancelled pull re-lead it (`9d99000`). | `process::tests::a_cancel_kills_a_running_helper` |
| P04-17 | medium | Link sockets had no write timeout, and ended sessions kept their sockets. | A peer that stopped reading stalled the dispatcher and held spec permits. | `set_write_timeout(HEARTBEAT_DEADLINE)` on every socket; sessions close their sockets (`4b6dd39`). | `session::tests::a_send_to_a_peer_that_never_reads_fails_within_the_write_timeout` |
| P04-18 | medium | `GET /queue` explained every job before applying `limit`. | Unbounded work per request. | Same as P08-8 (fleet, `972618d`, `476f8ed`). | See P08-8 |
| P04-19 | medium | The log hot path copied each byte about five times, rescanned the spool on rewind, and polled helpers every 20 ms. | Rule-one waste on the worker's throughput path. | Borrowed redaction and encoding, a reused spool scratch buffer, sending from memory when caught up, rewind by the recorded offset, a ring-buffer tail, and a pidfd wait (`4b6dd39`, `9d99000`). | `session::tests::a_borrowed_log_frame_encodes_exactly_like_the_owned_message`; `process::tests::a_quick_helper_is_not_held_by_a_poll_interval`, `the_tail_keeps_the_last_bytes_in_order` |
| P04-20 | low | Unredacted step stderr reached the verdict, the summary and the trace log. | Secret leak. | The detail passes through `Output::redact` (`9d99000`). | `logpipe::tests::registration_is_per_attempt_and_takes_effect_while_it_runs` (redaction assertions) |
| P04-21 | low | Longest-match redaction failed across a chunk boundary, and held-back bytes crossed steps. | A partial secret could leak; bytes were attributed to the wrong step. | Hold back while a longer secret matches; flush at each step's end (`9d99000`). | `redact::tests::the_longest_secret_wins_across_a_chunk_boundary`; `logpipe::tests::held_back_bytes_belong_to_the_step_that_printed_them` |
| P04-22 | low | Spool size-cap gaps were lost across a worker restart. | A truncated log was recorded as complete. | Interior gaps are rederived from sequence jumps, and the tail is kept in a `declared` file (`9d99000`), made atomic and synced when merged with storage's P06-10 in `84afa74`. | `spool::tests::a_full_spool_declares_gaps_and_the_sequences_stay_spent`, `a_reopened_spool_never_reuses_an_acknowledged_sequence` |
| P04-23 | low | Controller log writers for attempts that never ended were never evicted. | Handles and memory grew with uptime. | `LogStore::forget` runs on report, abandon and expiry (`414f3ca`, `4b6dd39`). Storage added the idle/LRU bound (P06-3). | None dedicated. Eviction is covered by `sentinel-store/tests/logs.rs::idle_writers_close_are_capped_and_their_logs_expire`. |
| P04-24 | low | Expiry did not re-check the lease in its write. | A just-renewed attempt could still be expired. | `expire` re-checks. Sweeps run one transaction per pass with a savepoint per row (`414f3ca`, `4b6dd39`). | `execution.rs::expiry_rechecks_the_lease_in_its_write` |
| P04-25 | low | `Decline` ignored the worker and the fence. | Any worker could lapse another worker's offer. | `dispatch::decline` matches worker and fence (`414f3ca`, `4b6dd39`). | `execution.rs::a_decline_is_fenced_and_hands_back_…` |
| P04-26 | low | The audit row for a refused enrollment was rolled back. | Refusals were never recorded. | `workers::redeem` returns `Ok(None)` so the audit row commits (`414f3ca`, `4b6dd39`). | `execution.rs::a_refused_enrollment_is_audited` |
| P04-27 | low | A Pong stop order ran `podman rm -f` inline on the heartbeat thread. | Could miss the 15 s deadline and drop the session. | Removal is spawned off-thread (`9d99000`). | None (thread placement only) |
| P04-28 | low | Log frames were acknowledged before new directory entries were durable. | After power loss an acknowledged frame's file could be missing. | `sync_dir` on a new attempt directory chain and on each new segment (`414f3ca`). | None: needs a fault-injecting filesystem (blocked) |
| P04-29 | low | The log tail route ignored a malformed `after` or `step`. | Clients got wrong data instead of a 400. | `invalid_request` (`5cef78b`); storage's `attempt_logs` kept it at merge. | `api.rs` (after=abc, step=x, after=-1); `log_pages_are_bounded_and_positions_are_validated` |
| P04-30 | low | A panicking attempt thread leaked its container, workspace and lease. | Resources were held until restart. | `catch_unwind` with teardown and a `Failed(Runtime)` report; fallible spawns (`9d99000`). | None: a panic needs a test-only injection hook |

Evidence corrections (execution, `5cef78b` and `b000489`):

- **W08 foreign-tenant test:** it was vacuous because it provisioned a credential for a tenant that did not exist. It now uses a real `globex` tenant, which gets 404 on run, cancel, rerun and log routes.
- **W09 and [vertical slice](vertical-slice.md):** the job count is now seven, not five.
- **[Worker link](worker-link.md):**
  - The `Welcome` description was corrected.
  - "One transaction per placement" was corrected.
  - The duplicated shell block was removed.
- **[Logs](logs.md):** the scope name is now `attempt_log_scope`.
- **[Cancellation](cancellation.md) and [core contracts](core-contracts.md):**
  - The "never cleared" claim now notes the GitHub rerequest exception.
  - The wording about clocks and ownership was corrected.
- **Executor and `podman.rs`:** "only bind mount" was corrected.
- **Duplicate offers:** `Executor::offered` now re-acknowledges a held or awaiting attempt explicitly. There is no Podman-backed test for that path.

## Part 05 — Git sources, event intake and GitHub PR feedback (G01–G08)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P05-1 | high | A suspended tenant, a suspended installation or a revoked App binding stalled intake dispatch and polling for every tenant. | Routine events froze all intake. | `source::classify` returns `Unbound`, `Unusable(reason)` or `Bound`, so such deliveries settle with a reason. Both lanes isolate faults per item (`16171b7`). | `sentinel-intake/tests/isolation.rs::an_unusable_binding_settles_its_delivery_and_never_stalls_another_tenant`, `a_suspended_installation_and_a_revoked_app_binding_settle_with_their_reasons`, `a_store_fault_on_one_delivery_parks_it_and_the_pass_continues`, `a_suspended_tenants_poll_backs_off_without_blocking_others` |
| P05-2 | high | Any spec or credential refusal, including the burst cap, dropped an acknowledged attempt. | App-bound fan-outs of 9 or more jobs ended in `infra_failed`. | Same defect as P04-4 (execution, `414f3ca`, `4b6dd39`, `9d99000`). The merge `84afa74` kept intake's mapping of store faults to `Unavailable`. | See P04-4 |
| P05-3 | high | The reordering policy caught only an adjacent predecessor, and the relay flushed its spool in random order. | Stale pushes dispatched, and under `cancel_in_progress` they cancelled the tip's run. | Ordering rule in `resolve::order`: a push is superseded when `is_ancestor` proves it is in the newest dispatched revision's history. The relay uses time-sortable IDs and delivers oldest first (`16171b7`, `97cb603`). | `sentinel-intake/tests/dispatch.rs::out_of_order_pushes_never_dispatch_behind_or_cancel_the_tip`; `relay.rs::spooled_pushes_are_delivered_oldest_first`, `a_live_push_is_delivered_after_the_events_already_spooled`; `ancestry.rs::an_older_commit_is_in_the_tip_history_and_a_newer_or_unrelated_one_is_not` |
| P05-4 | medium | When the answer to a `completed` check-run create was lost, a duplicate was always created. | G05's "no uncontrolled duplicates" did not hold. | A per-create `external_id` (`create_seq`, migration `033_intake_hardening`), adopted whatever its status (`44cc23e`). | `sentinel-checks/tests/delivery.rs::a_lost_answer_to_a_completed_create_is_adopted_not_duplicated`; `github_events.rs::a_rerequest_names_the_run_by_its_create_identity` |
| P05-5 | medium | The example relay filed 429 answers as permanent failures. | Events were lost under load. | `408` and `429` are retried (`97cb603`). | `relay.rs::a_rate_limited_event_stays_spooled_for_retry` |
| P05-6 | medium | `reason.truncate(256)` could panic on multibyte text and kill the poll thread. | One bad remote answer stopped polling for everyone. | `floor_char_boundary`, and the poll pass runs under `catch_unwind`. A sweep fixed four more byte-offset cuts, one reachable from API dispatch input (`16171b7`, `2f44f78`). | `isolation.rs::a_multibyte_failure_reason_is_bounded_and_the_lane_survives` (fails before); `schema.rs::a_multibyte_core_fraction_is_a_schema_error_not_a_panic` |
| P05-7 | medium | Controller-side fetches ignored the destination allowlist. | The egress policy was only half enforced. | The resolver and poller take the destination list and settle `failed:destination_refused` (`16171b7`). | `isolation.rs::a_binding_outside_the_destination_policy_is_refused_before_any_fetch`, `a_poll_outside_the_destination_policy_is_refused_without_listing` |
| P05-8 | medium | The idle lane ran a full-table-scan writer transaction every 250 ms, and each empty commit woke every watcher. | Rule-one waste, and it undid Part 09's commit notifier. | A partial index `deliveries_open` with a literal predicate. A reader probes before the writer is taken. `Writer::raw` bumps the generation only when rows changed (`16171b7`). | `intake.rs::the_due_queries_are_index_searches_without_a_sort`; `changes.rs::a_write_that_changes_nothing_does_not_advance_the_generation`; `isolation.rs::an_idle_lane_takes_no_writes` (both fail before) |
| P05-9 | medium | Transient store faults during issuance became permanent failures, and `issue` read two snapshots. | Pushes were dropped under load or during a credential rotation. | One-statement read; faults answer `Unavailable` and are retried (`16171b7`). | `isolation.rs::a_rotation_racing_issuance_is_transient` |
| P05-10 | medium | Manual dispatch let a user point the worker's Git at `file://`, a local path, `ssh`, `git` or plain `http` remotes. | Cross-tenant reads, SSRF, and use of the worker's ambient SSH identity. | `sources::validate_manual` admits only an unauthenticated canonical `https://` remote. Every unauthenticated fetch gets `protocol.allow` restrictions and no redirects (`16171b7`). | `api.rs::manual_dispatch_refuses_local_and_ambient_credential_remotes`; `ancestry.rs::an_unauthenticated_fetch_refuses_ambient_credential_and_plaintext_transports` |
| P05-11 | low | Deterministic `poll:` IDs suppressed a legitimate repeat of the same transition. | A re-pushed tip was never rebuilt. | The poll ID digests the cursor state (`16171b7`). | store `poll.rs::a_repeated_transition_after_a_revert_is_a_new_delivery` |
| P05-12 | low | Git's "repository not found" was classified as a pending merge. | A deleted repository retried 8 times and ended with a neutral check. | Only `couldn't find remote ref` counts as a pending merge (`16171b7`). | `unix::tests::only_a_missing_ref_is_a_pending_merge` |
| P05-13 | low | The hook secret was in curl's argv. | Local users could read it with `ps`. | `curl -K -` with the header on stdin (`97cb603`). | `relay.rs::the_hook_secret_never_appears_in_curl_arguments` |
| P05-14 | low | (a) `github_events` receipts were never purged. (b) A store fault was read as tenant suspension. (c) Adoption lookup was limited to one 64 KiB page. | Unbounded growth, a false permanent outcome, and failed adoption after many reruns. | (a) `purge_receipts`, never younger than 30 days. (b) Only `NotFound` counts as suspension. (c) Paged lookup, at most 10 pages (`44cc23e`, `16171b7`). | `github_events.rs::receipts_are_purged_by_age_but_never_inside_the_replay_window`; `intake.rs::a_store_fault_during_validation_retries_instead_of_suspending`; `delivery.rs::adoption_finds_its_run_past_a_large_first_page` |

Doc corrections (`6599622`):

- **[Checks](checks.md):** adoption is described as it now works.
- **[Intake](intake.md):**
  - "By construction" was replaced with the allowlist behavior as enforced.
  - The ordering rule and relay retry are described.
- **[Sources](sources.md):** the manual remote policy is documented.

## Part 06 — local storage, artifacts and log durability (D01–D07)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P06-1 | critical | Dedup races let a creator's discard, the orphan sweep or a reclaim unlink delete a committed object's file. | Silent loss of published evidence. | Each stage pins `(tenant, digest)` until after its commit. Every deletion runs on the writer, and only for a file that is unpinned and has no row (`b779f33`). | `sentinel-store/tests/artifacts.rs::a_creator_discarding_after_a_dedup_commit_keeps_the_object`, `a_discard_before_a_pending_dedup_commit_keeps_the_file`; `faults.rs::the_orphan_sweep_never_takes_a_file_a_stage_adopted`, `a_reclaim_unlink_spares_bytes_staged_again_meanwhile` |
| P06-2 | high | The download transfer slot was released before the body streamed. | Eight slow downloads could take every handler. | The slot is owned by the body (`Held`/`Verified`) until the connection drops it (`14f4cd0`). | `sentinel-api/tests/api.rs::downloads_hold_their_slot_and_control_requests_keep_handlers` |
| P06-3 | high | Log writers for attempts that never ended stayed open for the process lifetime and were exempt from retention. | File descriptors ran out after a few hundred lost attempts. | Per-attempt slots, at most 1,024 open (LRU), closed after 10 min idle; closed logs fall under retention (`966062d`, `b779f33`). | `sentinel-store/tests/logs.rs::idle_writers_close_are_capped_and_their_logs_expire` |
| P06-4 | high | Upload chunks and the full seal rehash ran inside the single writer transaction, with no size bound when the quota was 0. | One upload stalled every durable write. | I/O moved off the writer: chunks are written under a per-upload lock, then recorded on the writer; the seal hashes outside, then finishes on the writer. `MAX_UPLOAD_BYTES` is 4 GiB (`b779f33`, `14f4cd0`). | `sentinel-store/tests/storage.rs::a_large_seal_does_not_hold_the_writer`, `an_upload_past_the_object_bound_is_refused_at_begin` |
| P06-5 | high | Holes in sealed segments were forgotten on reopen. | The end marker claimed no gaps, and a fill was acknowledged without being stored. | A persisted `holes` sidecar, replaced atomically and written before the ack (`966062d`). | `logs.rs::a_hole_in_a_sealed_segment_survives_a_reopen` |
| P06-6 | high | Object downloads skipped repository grants, and a super admin could read any tenant's objects. | Authorization-model violation, plus an existence oracle. | `auth::require_object_read` goes through the artifact edge to a readable repository; there is no super-admin path. Refusal is the same 404 as a missing digest (`14f4cd0`). | `api.rs::artifact_routes_are_authorized_and_scoped` |
| P06-7 | medium | A deduplicated `stage_seal` left its temp file behind and released its admission charge. | `tmp/` filled up while admission undercounted it. | The dedup branch drops the temp file and skips the fsync (`b779f33`). | `artifacts.rs::a_deduped_stage_seal_leaves_nothing_in_tmp` |
| P06-8 | medium | Process-wide mutexes were held across fsyncs on the log and artifact paths. | Fleet log throughput was capped at one flush at a time. | Per-attempt locks; the map lock is used only for lookup (`966062d`, `b779f33`). | `tests/tput.rs` (ignored measurement harness) |
| P06-9 | medium | The storage pass walked the whole store on the dispatch thread, and reclaim scanned without an index inside the writer. | Placement paused and the writer was held for a scan that grew with the store. | Migration `034_storage_hardening`: `object_unreferenced` with an age index. Orphan and log sweeps are bounded and resumable, and the pass runs on its own `sentinel-storage` thread (`b779f33`, `966062d`). | `storage.rs::reclaim_candidates_come_from_the_unreferenced_index` |
| P06-10 | medium | Worker spool gaps were memory-only, and sequences were renumbered after a reopen. | Lost output was recorded as a complete log. | Gaps and the refused-tail high-water mark are persisted (`966062d`, a `spent` file). The merge `84afa74` keeps one mechanism: execution's `declared` file (P04-22), now replaced atomically and synced, never declaring an acknowledged sequence, and persisted before `LogEnd`. | `spool::tests::a_full_spool_declares_gaps_and_the_sequences_stay_spent`, `a_crash_after_a_refused_tail_still_declares_it` |
| P06-11 | medium | A `wait=1` poll with `step=` re-decoded up to 256 MiB every 250 ms. | CPU and I/O amplification from one request. | Pages decode at most 16 MiB. A finished step is answered at once. Polls park on a log-append notifier (`966062d`, `14f4cd0`). | `logs.rs::pages_are_bounded_and_a_finished_step_is_reported` |
| P06-12 | low | Retiring an expired upload on touch was rolled back, but its file and charge were dropped anyway. | The row, file and quota were briefly inconsistent. | `Touch::Expired`; the route retires the upload in its own transaction (`b779f33`, `14f4cd0`). | `api.rs::touching_an_expired_upload_retires_it` |
| P06-13 | low | The server did not verify digests on download. | A rotted file was served under its digest ETag. | Whole-object bodies are rehashed while streaming, and the connection is cut on mismatch. Range reads are documented as unverified (`14f4cd0`). | `api.rs::a_rotted_object_is_never_served_whole` |
| P06-14 | low | `materialize`'s escape check was check-then-act, and the function had no caller. | Only a concurrent attacker could exploit it. | Docs only: the claim now covers directories prepared in advance, not ones changed concurrently (`b779f33`). | None (no caller exists) |

Doc corrections: [api](api.md), [storage](storage.md), [logs](logs.md), [configuration](configuration.md) and [compatibility](compatibility.md) now match the code. That covers the transfer bound (now true: three slots), "a gap can never be silent", "never re-numbered", "sweeps are bounded", "touching an expired session retires it", and the stale D06 and open-gates text. Time and line checkpoints are documented as written but not yet read.

## Part 07 — local cache, compiler and image fast paths (K01–K09)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P07-1 | critical | Publish followed symlinks in intermediate path components while job processes were still alive. | A job could seal host files, including other tenants' data and the worker's key, into its cache and read them back. | A descriptor-rooted walk: per-component `O_NOFOLLOW`, `openat2(BENEATH\|NO_SYMLINKS\|NO_XDEV)`, and sizes taken from the opened fd. The container is stopped before publish (`279432d`). | `sentinel-cache/tests/publish.rs::publish_refuses_a_symlinked_intermediate_component`, `publish_opens_files_nofollow`, `publish_skips_an_entry_restore_refused`; `sentinel-worker/tests/k09.rs::publish_runs_with_the_container_stopped` (fails before) |
| P07-2 | high | Every trigger except `pull_request` wrote protected state, including manual runs and pushes to any branch. | Anyone with `RUN` could poison the protected branch's cache. | `Protected` only for a verified push or tag whose ref the live binding names exactly. Everything else gets `Trust::Unprotected` (wire code 2, protocol 8). Older peers receive the PR scope (`2ead7fa`). | `sentinel-protocol` `only_verified_protected_refs_are_protected`, `older_peers_get_the_pull_request_scope_for_unprotected_jobs`; `sentinel-intake/tests/dispatch.rs::a_push_is_protected_only_for_a_ref_the_binding_names_exactly` |
| P07-3 | high | A stale key's `current` generation could never be reclaimed. | The cache grew without bound, and PR jobs could mint entries at will. | `current` is evictable, least recently used first. Entries idle 14 days are removed. Pins are re-checked, including the pin-race fix (`7025e27`, `d3e3507`). | `sentinel-cache/tests/gc.rs::budget_evicts_idle_currents_lru_and_ttl_removes_idle_entries` |
| P07-4 | high | A truncated GC pass never resumed and never enforced the budget. | Reclamation stopped silently on large stores. | A persisted `gc::Cursor`; the budget is enforced on every pass (`7025e27`). | `gc.rs::truncated_passes_cover_every_entry_and_still_enforce_the_budget` |
| P07-5 | high | Publish had no byte bound, and sparse files were copied densely. | A job could drive the worker's disk to ENOSPC. | `MAX_GENERATION_BYTES` (budget / 4), a free-space reserve check, and hole-preserving copies (`279432d`). | `publish.rs::publish_refuses_a_generation_over_the_byte_cap`, `sparse_file_does_not_amplify` |
| P07-6 | high | K08's availability feed never reached placement: the profile always sent empty images and 0 cache bytes. | Image locality never engaged. | `Executor::availability()` supplies the newest 64 image keys and the swept cache bytes. A protocol-8 `Profile` refreshes them (`27d1135`). The fleet cluster consumes them (`972618d`). | `sentinel-link/tests/remote_cache.rs::the_profile_carries_and_refreshes_measured_availability` |
| P07-7 | high | Cache offers arrived after the terminal report and were refused. The controller's store had no reclamation. | Q08 never filled in production, and fixing only the ordering would have left an unbounded disk sink. | Offers are authorized for an attempt the same worker released within 10 min (`dispatch::cache_scope`). The store keeps one bundle per entry and has a byte budget (`2ead7fa`, `27d1135`). | `remote_cache.rs::an_offer_after_the_terminal_report_is_stored_and_serves_the_next_attempt`; `sentinel-cache/tests/remote.rs::the_controller_store_keeps_one_bundle_per_entry_and_a_byte_budget` |
| P07-8 | medium | A mid-clone failure reported a miss but left partial payload in the targets, and the lease was taken after lookup. | Installers could build on a half-materialized tree. Ordinary races were labelled `corrupt`. | The lease is taken first. Every tree is checked before any clone. A failed clone empties the targets (`279432d`). | `restore::tests::a_failed_materialization_leaves_empty_targets` |
| P07-9 | medium | Publish ignored the restore outcome. | Unservable generations were stored, and P07-1 was widened. | `SkipReason::Refused` (`279432d`). | `publish.rs::an_unrendered_key_publishes_nothing` |
| P07-10 | medium | Publish allocated 1 MiB and ran an fsync per file on the verdict path. | 100k-file caches cost minutes. | One buffer per commit; one `syncfs` beyond 64 files (`279432d`). | Measurement (see Measurements) |
| P07-11 | medium | A GC walk of the whole store ran after every attempt, and every restore walked the payload twice. | Per-attempt cost grew with the store. | GC part fixed with incremental cursor passes (`7025e27`). The per-file `format!` was removed from the restore check (`279432d`). The double walk is kept (see Not a defect). | Covered by the gc and restore tests above |
| P07-12 | medium | K05 had no bounded prefetch. Private-image authorization was worker-wide, and the `image exists` fast path served any tenant. | Tenant B could run tenant A's private image by digest. | **Deferred** (see Deferred). [Executor](executor.md) now says so (`352a5a5`, `eee35e9`). | None |
| P07-13 | low | The restore lease was never renewed (10 min TTL against jobs of up to 24 h). | GC could evict the source generation of a long job. | A process-wide keeper renews held leases every 2.5 min (`279432d`). | `lease::tests::a_held_lease_is_renewed_and_a_released_one_is_not` |
| P07-14 | low | Stale write-lock reaping was racy. | Two writers could stage at once. | Rename the lock aside, then re-judge it. A residual window of three writers within microseconds is documented (`279432d`). | `lease::tests::a_racing_reaper_never_deletes_a_fresh_marker` |
| P07-15 | low | Payloads silently dropped symlinks. | An "exact" dependency tree was not exact. | Fixed by documentation (see Not a defect) (`279432d`, `352a5a5`). | None (docs) |
| P07-16 | low | An absolute cache path containing `:` failed `podman create`. | A cache-path error failed the attempt instead of being a miss. | `:` and `,` are an `invalid` miss. Refused targets are never mounted (`279432d`). | `restore::tests::an_unmountable_absolute_path_is_refused` |
| P07-17 | high | Manual-mode mirrors accepted any remote, so a local mirror path copied another repository's objects in. | Cross-tenant disclosure of private source. | Mirrors serve only bound runs. A mirror records its remote and is rebuilt when the remote changes (`352a5a5`). | `sentinel-worker/tests/mirror.rs::a_manual_run_never_reads_or_feeds_a_mirror`; `sentinel-git/tests/mirror.rs::a_mirror_serves_only_the_remote_that_filled_it` |
| P07-18 | medium | Mirror failure plus fallback could take twice `CHECKOUT_TIMEOUT`, and a timeout never fell back. | Large repositories failed every attempt. | The mirror gets half the deadline; the fallback uses the rest and also covers `Timeout` (`352a5a5`). | `mirror.rs::a_fallback_spends_the_remaining_deadline_not_a_new_one` |
| P07-19 | medium | Corruption the health check missed became a permanent `Preparation` failure. | Every attempt on that worker failed. | The health probe adds `rev-list --no-walk --all` (`352a5a5`). | `sentinel-git/tests/mirror.rs::damage_under_a_ref_tip_is_rebuilt_not_a_permanent_failure` |
| P07-20 | medium | Every attempt copied the entire mirror object store. | Rule-one waste on non-reflink filesystems. | **Deferred to B04** (see Deferred). | None |
| P07-21 | medium | Any materialization failure marked the mirror suspect. | Full refetches repeated. | Suspect only when the health probe fails; a failed marker write is surfaced (`352a5a5`). | Covered by `damage_under_a_ref_tip…` and the existing rebuild test |
| P07-22 | medium | Mirror disk use was unbounded. | The disk filled. | `Mirrors::sweep` removes stale `tmp_*` after 1 h and idle mirrors after 14 d, and enforces a 50 GiB LRU budget. Each removal runs under the mirror lock with no live lease (`352a5a5`). | `sentinel-git/tests/mirror.rs::the_sweep_bounds_mirror_disk` |
| P07-23 | low | The mirror lease TTL was a fixed 20 min, and a crashed temp file blocked retries. | GC could undercut a long reader. | Expiry is the reader's deadline + 60 s; temp files are truncated (`352a5a5`). | `mirror.rs::a_leftover_lease_temp_file_does_not_block_a_retry` |
| P07-24 | low | A failed attempt overwrote the mirror fallback reason. | Diagnostic loss. | `detail` keeps both, bounded to 500; no format bump (`352a5a5`). | `attempt::tests::a_failure_keeps_the_checkout_fallback_reason` |
| P07-25 | low | A manual credential secret was not registered for redaction. | Latent leak (the worker passes `None` today). | Registered in the direct and mirror paths (`352a5a5`, kept at merge `0142aba`). | None dedicated (latent path) |
| P07-26 | low | An authentication failure caused up to three forge fetches. | Needless load on the forge. | Narrower wants are retried only after a want refusal (`352a5a5`, `d3e3507`). | `mirror::tests::only_a_refused_want_is_retried_narrower` |

Evidence corrections (`ac6c0b5`):

- **K09 record:** the committed record is unchanged. A correction note in [benchmarking](benchmarking.md) says:
  - `total` excludes preparation and the restore;
  - the warm path costs about 10.5 ms, not about 5 ms;
  - the file has 38 lines: 1 meta record plus 37 attempts;
  - p95 values are nearest-rank.
- **[Cache](cache.md), [worker link](worker-link.md), [configuration](configuration.md) and [mirrors](mirrors.md):** the stale claims were corrected.

## Part 08 — fleet scheduling, recovery and Tailcat (Q01–Q09)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P08-1 | high | A serializing concurrency group deadlocked every run that shared it. | Two pushes in a row stopped the repository's CI for 6 h. | Only an older run (by `(created_ms, id)`) or an executing job holds a group, per repository. Supersede uses `<=` (`972618d`). | `sentinel-store/tests/fleet.rs::two_queued_runs_of_a_serial_group_both_run_in_order`, `a_concurrency_group_is_held_per_repository`, `same_millisecond_superseding_runs_leave_exactly_one` (all fail before) |
| P08-2 | high | Large-job and PR reservations were global across pools. | Any tenant could idle other tenants' dedicated pools. | The probes use the candidate scan's full eligibility (`972618d`). | `fleet.rs::a_large_job_in_another_pool_reserves_nothing_here`, `an_unrunnable_large_job_reserves_nothing`, `an_unrunnable_pull_request_job_reserves_nothing` (fail before) |
| P08-3 | medium | The PR reserve was multiplied by the number of worker identities on a host. | Four identities reserved the whole machine. | A quarter of the worker's own whole-host report (`972618d`). | `fleet.rs::the_pull_request_reserve_counts_the_host_once` (fails before) |
| P08-4 | high | Label filtering after `LIMIT 32` hid fitting jobs, and the explanation said `Capacity`. | A batch of `gpu` jobs blocked a tenant on every other worker. | Labels are checked in SQL by the allocation-free `sentinel_labels_subset`. Paging continues by keyset. A new `Ready` reason (`972618d`). | `fleet.rs::label_mismatched_jobs_never_hide_a_fitting_one`, `locality_held_jobs_never_hide_a_placeable_one` (fail before) |
| P08-5 | high | Tenant → repository fairness was missing, and the Rust sort discarded priority. | A noisy repository starved its siblings. | (tenant, repository) streams from `jobs_ready_repo`, ranked by held millicpu, then priority, then age. Adds `jobs.repo_id` and `attempts.repo_id` (migration `035_fleet_scheduling`) (`972618d`). | `fleet.rs::a_repository_backlog_does_not_starve_its_siblings` (fails before); `a_noisy_tenant_does_not_crowd_out_a_quiet_one` |
| P08-6 | high | Q03 worker scoring did not exist: placement was fill-first in `HashMap` order, and `load_ns` was never read. | Bursts landed on one arbitrary worker. | Placement runs in rounds, ranking workers by committed share, then `load_ns` per core, then warm cache, then size. "Expected to free" is the offer time plus the job timeout (`972618d`, `476f8ed`). | `sentinel-link/tests/fleet.rs::a_burst_spreads_over_identical_workers` (base result `[3,0,0]`); store `a_busy_warm_worker_with_long_work_does_not_hold_a_cold_job`; `controller` unit `the_sweep_ranks_workers_by_commitment_then_load_then_cache_then_size` |
| P08-7 | high | Revoking a worker did not affect its live session. | A revoked machine could keep renewing leases and falsifying outcomes. | Acknowledge, renew, report, `is_held` and the scope reads refuse a revoked worker. Each pass checks the revoked set, then closes sessions and reconciles (`972618d`, `476f8ed`). Extended to the Part 04 and Q08 paths at merge (see Found during integration). | store `fleet.rs::a_revoked_worker_holds_nothing_and_its_attempts_are_settled` (fails before); link `revoking_a_connected_worker_ends_its_session_and_fences_its_work` |
| P08-8 | high | `GET /queue` explained every queued job before applying `limit`: 9.5 s for 5,000 jobs. | Unbounded work on an API path. | `list_queue` takes the limit and uses the `jobs_waiting` index; invariants are computed once per call (`972618d`, `476f8ed`). | Plan tests for the queued, blocked and count statements; ignored measurement `fleet_load.rs::listing_a_five_thousand_job_queue_explains_only_the_page` |
| P08-9 | medium | The PR probe still scanned the whole ready queue on every placement; migration 029's indexes were unused. | Placement cost was O(ready queue). | New `jobs_ready_pr` index with `INDEXED BY`; 029's unused indexes are dropped (`972618d`). | `dispatch::tests::placement_statements_plan_their_indexes`, `placement_statements_never_scan_the_queue_at_runtime` |
| P08-10 | low | The "bound `?` disables partial indexes" rationale was wrong, and the EXPLAIN test checked compile-time plans. | The test oracle passed a probe that scanned at runtime. | Runtime `FullscanStep`/`Sort` counters. [Storage](storage.md) rationale and the 258 s → 52 s attribution corrected (`972618d`, `6759536`). | Same two tests |
| P08-11 | medium | The bulk redial back-off blocked control teardown for up to 30 s. | Leases expired during reconnect. | The back-off wait checks the stop flag every 50 ms, with its own jitter (`7198f95`). | `priority.rs::a_failing_bulk_redial_never_delays_the_control_teardown` (3.68 s before) |
| P08-12 | low | Host aggregation relied on self-reported `machine-id` and on whole-host capacity reports. | Split overrides were silently cut to one share. | Documented in [configuration](configuration.md) and [storage](storage.md) (`6759536`). | None (docs) |
| P08-13 | low | Expiry was decided outside the write, and `renew` resurrected expired leases. | A late beat revived a lapsed lease. | `renew` requires `lease_until_ms >= now`, and `expire` re-checks. At merge, `expire` answers `Conflict` when a renewal won (`972618d`, `5442ca7`). | `fleet.rs::a_passed_lease_stays_expired_and_a_renewed_one_is_not_expired` (fails before) |
| P08-14 | low | Wasted placement round trips, plus dead schema from migration 028. | About 100 writer round trips per wake. | One `any_ready` probe per pass and one transaction per round. `lease_reserved` does not re-read the job. Migration 035 drops the dead objects (`972618d`, `476f8ed`). | Covered by the fleet and link suites and the load run |
| P08-15 | low | Placement and lapse failures were swallowed silently. | A fleet that stopped placing left no evidence. | `Stats::placement_errors`, `sweep_errors` and `revoked_sessions`, plus a warning at most once a minute per class carrying only `Error::kind()` (`476f8ed`). | `sentinel-link/tests/fleet.rs::a_failing_placement_is_counted_not_swallowed` |
| P08-T1 | high | An empty or missing Tailcat allow list let any peer in. | The tunnel exposure the docs promised was absent. | An empty list serves `--allow=none`; a list is passed as one comma-separated flag (`d106e4b`). | `sentinel-link/tests/tailcat.rs` (fake helper, Linux) |
| P08-T2 | medium | The direct/relay path was guessed, and telemetry was never exposed. | Violated "unmeasured is absent". | Path and latency come from `tailcat ping`; `Unknown` unless measured. `GET /workers` exposes `transport` (`d106e4b`, `2c3917e`). | `sentinel-link/tests/fleet.rs::each_session_reports_the_helpers_latest_transport_measurement`; api unit `transport_telemetry_leaves_unmeasured_fields_out` |
| P08-T3 | medium | Tailcat credentials appeared in the INFO log and the helper inherited the whole environment. | Credential exposure. | The address is written to an owner-only file. The environment is cleared. The argv exposure is documented (`d106e4b`, `fbf72cb`). | `tailcat.rs` |
| P08-T4 | medium | TOCTOU between the helper pin hash and exec, and a full re-hash on every probe. | Code execution by anyone who can replace the binary; rule-one waste. | `O_NOFOLLOW` open, owner and mode checks, hash and exec through the fd, identity cache (`d106e4b`). | `tailcat.rs` |
| P08-T5 | medium | Tailcat revocation was disconnected from worker revocation. | A revoked worker kept its tunnel. | Allow-list lines are `nodekey:<hex> wrk_<id>`; revoked workers' keys are withdrawn within one 10 s tick (`d106e4b`). | `tailcat.rs` |
| P08-T6 | medium | The Q07 live evidence proved less than claimed: vacuous passes, rootful Podman, public DERP only. | The checkpoint "self-hosted relay" was unproven. | A missing prerequisite fails when the gate is set. The controller runs through `start_server`. A local derper case was added. The suite states that it uses rootful Podman (`5471245`). | `tailcat_live.rs` (6/6 per the sub-agent) |
| P08-T7 | medium | The helper restart back-off never reset, and intentional restarts counted as failures. | About 30 s of fleet-wide outage per allow-list change. | Back-off resets after a healthy run; deliberate restarts are immediate (`d106e4b`). | `tailcat.rs` |
| P08-T8 | low | The health probe did not prove the tunnel carried traffic, and it sent a stray byte. | False health and spurious rejections. | The probe is `tailcat ping` only. The worker replaces the helper after 3 failed sessions in a row (`d106e4b`). | `tailcat.rs` |
| P08-T9 | low | The helper was orphaned on SIGKILL, and DERP URLs containing `/files/` or `/all/` were refused. | Leaked process; legitimate configuration refused. | `PR_SET_PDEATHSIG`; the argv check applies only to modes and flags (`d106e4b`). | `tailcat.rs` unit tests |
| P08-C1 | high | Same as P07-7: offers were refused after the terminal report. | Q08 never filled in production. | See P07-7 (`2ead7fa`, `27d1135`); refusals are counted in `Stats::cache_denied`. | `remote_cache.rs::an_offer_after_the_terminal_report_is_stored_and_serves_the_next_attempt` |
| P08-C2 | high | A fetch the worker abandoned was never cancelled on the controller. | Up to 64 GiB streamed for nothing, holding a transfer permit. | Protocol 8 `CacheCancel` (`27d1135`). | `remote_cache.rs` (abandon, then a clean re-fetch) |
| P08-C3 | medium | Orphaned chunks of an aborted stream were routed into the next hydration. | Later caches of the job missed. | An abandoned transfer's attempt stays "draining" until its terminal message; new transfers are `busy`. No nonce needed (`27d1135`). | Same test |
| P08-C4 | high | The controller's remote-cache store had no disk bound and kept superseded bundles. | The disk shared with SQLite and objects filled up. | Superseded bundles are unlinked. Uploads need free space plus a reserve. A budget sweep runs (`27d1135`). | `sentinel-cache/tests/remote.rs::the_controller_store_keeps_one_bundle_per_entry_and_a_byte_budget` |
| P08-C5 | medium | Abandoned uploads leaked their lock, handle and `.part` file. | Other workers got `Busy`; disk leaked. | `Drop for Receiving`, at most 4 uploads per connection, a 60 s idle reap (`27d1135`). | `remote.rs::an_abandoned_upload_leaves_nothing_behind` |
| P08-C6 | medium | The hydration deadline did not bound wall time. | N caches cost N × the budget, plus unbudgeted work. | One job-level deadline covering the resume hash, the transfer and the install (`27d1135`). | `remote.rs::a_spent_job_deadline_never_networks` |
| P08-C7 | low | A valid partial was deleted on `Busy`/`Denied`; the rate estimate truncated to zero; `remote_from` was wrong. | Contradicted [cache](cache.md); the rate policy never aborted on fast links. | Partial kept; u128 cross-multiplication; offset taken from `grant.offset` (`27d1135`). | `remote.rs::a_busy_answer_keeps_a_valid_partial` |
| P08-C8 | medium | Rule-one waste on the transfer path: triple writes, double reads, re-hash on the reader thread, and prefix-hash amplification. | Stalled connections; a worker could force 64 GiB hashes. | Incremental hashing in `push`, one reused buffer, resume proven only up to 1 GiB (`27d1135`). The rest is **deferred to B04**. | `remote.rs::uploads_verify_as_they_land_and_serves_resume_only_proven_prefixes` |
| P08-C9 | low | The worker's cache answer channel was unbounded. | Unbounded memory if disk fell behind. | `sync_channel(64)` with `try_send`: a full queue abandons that transfer (`27d1135`). | Covered by `remote_cache.rs` |

Evidence corrections (`6759536`, `133afca`, `fbf72cb`):

- **[Storage](storage.md):**
  - The fairness and reservation sections now describe the code.
  - The "index probes" rationale was corrected.
- **[Worker link](worker-link.md):** revocation behavior is described.
- **`fleet_load.rs`:** rewritten to hold capacity across 4 tenants, 12 repositories, PR and labeled runs, and paired host identities. It records p50/p95/p99/max placement and queue wait, throughput, CPU, RSS and I/O in `bench/q09-fleet-load.jsonl`.
- **"100 sessions and 10k jobs":** documented as two separate tests.
- **Tailcat:** the docs and `tailcat_live.rs` pointers were corrected.

## Part 09 — OAuth server and developer CLI (O01–O07)

| ID | Severity | Finding | Why it mattered | Fix (commit) | Regression test |
|---|---|---|---|---|---|
| P09-1 | medium | The `/device` approval form told any signed-in account which tenants and repositories exist. | Cross-tenant metadata enumeration. | `auth::narrowing_by_name` resolves names only among the approver's memberships. Every refusal is one identical page and counts as a wrong code. The consent `repo_named` lookup is membership-checked too (`b3fc93d`). | `sentinel-api/tests/oauth_device.rs::foreign_and_missing_narrowings_are_indistinguishable_and_limited`; store `oauth_code.rs::consent_repository_lookup_hides_what_the_account_cannot_see` |
| P09-2 | medium | One global token bucket and a deployment-wide device cap. | One anonymous client could stop every refresh and every device login. | Per-client GCRA buckets in a bounded 4096-entry map, and a per-client device bucket. The CLI retries `temporarily_unavailable` once (`b3fc93d`, `daf65b1`). | `oauth_core.rs::a_flooding_client_cannot_stop_another_clients_refresh`; `limit.rs` unit tests including the map bound; `profile.rs::a_busy_token_endpoint_is_retried_once` |
| P09-3 | medium | A store fault while checking a credential answered `401`. | Overload made every CLI spend its refresh token and report "not signed in". | `Refusal::Busy` answers 429 `rate_limited` with `retry_after_ms`; `Refusal::Fault` answers 500; only `NotFound` answers 401 (`b3fc93d`). | `oauth_core.rs::a_busy_store_is_rate_limited_not_unauthenticated` |
| P09-4 | medium | A path-prefixed `public_url` broke the embedded sign-in, the `/device` page and RFC 8414/9728 discovery. | A documented configuration did not work. | Every URL is built from the issuer; the RFC well-known locations include the issuer path (`b3fc93d`). | `oauth_core.rs::a_path_issuer_keeps_every_url_inside_its_mount`; `oauth::tests::a_path_issuer_builds_every_url_from_the_issuer` |
| P09-5 | low | Lost-response recovery could repeat within the 60 s window. | The documented single-successor guarantee was false. | Recovery requires exactly one child ever (`b3fc93d`). | store `oauth_tokens.rs::a_lost_response_is_not_recovered_a_second_time` |
| P09-6 | low | The token bucket dropped sub-millisecond refill. | The limiter admitted nothing under a fast flood. | Replaced by GCRA (`b3fc93d`). | `limit::tests::sub_millisecond_arrivals_still_refill_at_the_rate` |
| P09-7 | low | The wrong-user-code map was not bounded by `MAX_TRACKED`. | Memory grew with the number of accounts; O(n) scans. | Hard bound of 4096, a sweep at most once a second, fail closed when full (`b3fc93d`). | `page::tests::the_wrong_code_map_is_bounded_and_fails_closed` |
| P09-8 | low | A profile named `profiles` deadlocked on its own lock. | Exit 6 with a live, unrecorded grant. | The lock for `profiles.json` is `locks/.profiles.lock` (`daf65b1`). | `profile.rs::a_profile_named_profiles_signs_in_without_waiting_on_itself` |
| P09-9 | low | The OS-store key was per user, but the refresh lock was per configuration directory. | Concurrent refreshes from two directories replayed a token and revoked the grant. | Scoped key with a BLAKE3 hash of the directory, stored in the profile (`daf65b1`). | `profile.rs::windows_credential_manager_stores_reads_and_deletes` (extended to two directories) |
| P09-10 | low | The Windows file store was not owner-only outside `%APPDATA%`. | Other users could read refresh tokens. | Protected DACL for the current user and SYSTEM (`daf65b1`). | `profile.rs::windows_file_store_is_owner_only_wherever_it_lives` |
| P09-11 | high | `log show` failed on pages over ureq's 10 MiB body limit. | The CLI could not read large logs. | Server pages stop at 1 MiB of payload with `next_after`; the CLI follows it (`966062d`, `14f4cd0`, `c08fac3`). | `sentinel/tests/commands.rs::log_show_reads_a_log_of_full_frames_past_the_client_body_limit` |
| P09-12 | medium | Parked long polls plus transfers could take all 8 handler permits, and one credential could hold every subscriber slot. | Login, token and health requests queued behind them. | `TRANSFERS = 3`, `SUBSCRIBERS = 3`, a compile-time reserve of at least 2 handlers (`14f4cd0`). A per-user cap of 2 (`SUBSCRIBERS_PER_USER`) (`26cc5c1`). | `api.rs::downloads_hold_their_slot_and_control_requests_keep_handlers`; `sentinel-api/tests/wait.rs::one_user_cannot_take_every_subscriber_slot` (fails without the rule) |
| P09-13 | medium | Every stdout write panicked on a closed pipe (exit 101). | `… \| head -1` crashed outside the exit table. | All stdout goes through helpers; a closed stdout exits 0 quietly (`9138fac`). | `sentinel/tests/cli.rs::a_closed_stdout_ends_the_command_quietly_with_exit_zero`; `client.rs::a_closed_stdout_ends_a_networked_command_quietly_with_exit_zero` |
| P09-14 | low | `--expires-in` panicked on a non-ASCII last character. | Exit 101 instead of 2. | Split at a character boundary. Also fixed by intake's sweep; the merge `678bad6` keeps every case (`daf65b1`, `2f44f78`). | `service_accounts::tests::durations_parse_with_a_unit_only` |
| P09-15 | low | Client retries ignored `details.retry_after_ms`, although the docs said they honoured it. | Lock-step retries. | A named back-off is left to the caller (`wait` and `--follow` add jitter) (`9138fac`). | `client.rs::a_named_server_backoff_is_left_to_the_caller` |
| P09-16 | low | `log search` could skip matches when the client cut inside a frame. | Missed matches, and possibly a false `complete`. | Client fixed: it resumes at `seq - 1` with `complete: false` (`c08fac3`). Server side is not a defect. | `commands.rs::log_search_cut_inside_a_frame_resumes_before_it` |
| P09-17 | low | `run_version` sorted on every re-check. | A temp B-tree per waiter per commit. | `ORDER BY j.id` (`f1961a1`). | `sentinel-store/tests/changes.rs::the_run_version_recheck_reads_an_index_range_without_a_sort` (fails before) |
| P09-18 | low | Some tests accepted the wrong result. | False confidence. | Exit 4 asserted with a well-formed ID; `rate_limited` observed at the server; monotonic test clocks (`00fc258`; the auth merge `e7ca30a` keeps the stricter version). | The tests themselves |

Doc corrections:

- **[OAuth](oauth.md):**
  - "Recovers once" is now true.
  - The limiter, device page and known limits are described.
  - Revoked grants are listed only until the purge.
- **[CLI](cli.md):** the Windows ACL, lock name, key and retry behavior are described.
- **Consent-choices plan test:** now checks the statement that actually runs.
- **[Compatibility](compatibility.md):** the half-free-permits claim was replaced by the `RESERVED_HANDLERS` reservation.

## Found during integration

These came from merging the seven branches and from the flakes seen in their verification runs.

| Item | What happened | Fix (commit) | Regression test |
|---|---|---|---|
| Revocation reached only fleet's paths | P08-7 fenced acknowledge, renew, report and `is_held`. Execution's new `spec_gate`, `job_context`, `spec_bytes` and `decline` (spec hand-back), and cache's `cache_scope`, still answered a revoked worker. | Merge `5442ca7` extends the revocation check to all five. `report()` keeps both the revocation check and execution's reclassification of an unrequested cancel in one statement. | `sentinel-store/tests/fleet.rs::a_revoked_worker_gets_no_spec_hand_back_or_cache_boundary` |
| Batched sweeps hid their failures | Execution batched expiry and lapse into one transaction per pass with a savepoint per row. Fleet counts sweep failures. A plain merge would have dropped non-benign row failures before `Stats::sweep_errors` saw them. | Merge `5442ca7` keeps the batched sweeps inside fleet's dispatch pass. `expire_batch` and `lapse_due` return a `Swept` count, so non-benign failures reach `sweep_errors` and the rate-limited log. `expire` answers `Conflict` when a renewal won. | Fleet and link suites; the Part 04 expiry test renews at the deadline (P08-13) |
| Two spool gap fixes | Storage (P06-10, a `spent` file) and execution (P04-22, a `declared` file) both persisted spool gaps in different layouts. | Merge `84afa74` keeps execution's layout. The `declared` file is replaced atomically and synced, never declares an acknowledged sequence as a gap, and `persist_end` runs before `LogEnd`. Both clusters' tests are kept. | `spool::tests::a_full_spool_declares_gaps_and_the_sequences_stay_spent`, `a_crash_after_a_refused_tail_still_declares_it`, `a_reopened_spool_never_reuses_an_acknowledged_sequence` |
| Source issuance fault mapping | Execution and intake both changed `source::issue`. | Merge `84afa74` keeps intake's finer mapping, which already answers transient faults as `Unavailable` (P05-2). | `isolation.rs::a_rotation_racing_issuance_is_transient` |
| Link burst test race | `a_burst_spreads_over_identical_workers` waited for the store to show jobs leased, not for the offers to arrive. | Merge `5442ca7`: the test waits for the offers. | The test itself |
| Stale Tailcat probe | Investigating the flake `a_dead_helper_is_replaced_and_a_stalled_tunnel_is_not_trusted` found a real race. A probe still in flight when its helper ended and a successor started would kill that successor, which nothing had judged. The flake itself was a 10 s condition deadline on real shell spawns while the host was out of memory. | `66991de`: children carry a generation and start instant; the prober judges a helper only after a full interval and replaces only the child it probed. The deadline was raised to 60 s as a bound on a hang, not a sleep. | `sentinel-link/tests/tailcat.rs::a_stale_probe_never_replaces_the_successor_it_did_not_probe` (fails on the old supervisor) |
| P09-12 per-user cap | Storage made the subscriber and transfer reservation real but left the optional per-principal cap out. One `runs:read` credential could still hold all three subscriber slots. | `26cc5c1`: `SUBSCRIBERS_PER_USER = 2` of 3, held in a fixed three-entry table under one short lock. | `sentinel-api/tests/wait.rs::one_user_cannot_take_every_subscriber_slot` (fails without the rule) |
| Writer back-pressure flake | `store.rs::writer_queue_is_bounded_and_reports_back_pressure` failed intermittently in several clusters' runs. It guessed timing with two sleeps. Not a product bug. | `94711ab`: the test waits for the blocking job and the eight overflow answers; its assertions are exact. | The test itself |
| Offer comment | The `Offer` comment said it carries `name@sha256:…`. It carries only the digest. | `eee35e9` (docs) | None |
| Q07 throughput counted only control | The audit's Q07 note: "throughput" was the control connection's lifetime byte totals, so logs, specs and artifacts on the protocol-7 bulk connection were missing. No cluster took it. | `529d4a7`: `bytes_in`/`bytes_out` add every bulk connection of the session, keeping a lost connection's bytes across a redial; throughput is their rate between two reports. No wire change. | `session::tests::transport_bytes_count_every_bulk_connection_of_the_session` |
| CLI and wait suites hung after P08-7 | The merged `test-cli` run stalled in `sentinel/tests/commands.rs` (as the fleet cluster's run had, which it attributed to memory pressure). The fixtures leased attempts to a worker id with no `workers` row; since P08-7 the store answers such a worker's acknowledgement and reports `NotFound`, the helper failed in its thread, and `sentinel wait` without a deadline waited forever. The product behavior is correct. | `d65e7b4`: the fixtures enroll the worker in the lease transaction; the wait carries a deadline, so a run that never passes fails instead of hanging. | `commands.rs::wait_exits_zero_when_the_run_passes_eight_when_it_does_not_and_seven_at_the_deadline`, `wait.rs::an_attempt_summary_needs_cache_read_and_reports_cache_records` |
| Worker helper-wait timing test | `process::tests::a_quick_helper_is_not_held_by_a_poll_interval` failed in the merged `test-linux` run: two back-to-back averages drifted with the host's load (79 ms for a 10 ms child), exceeding its 8 ms margin. Test assumption, not a product bug. | `93884b4`: interleaved pairs, median paired difference, a 2 ms child the old poll would hold ~18 ms longer. | The test itself (30/30 under 6-way load) |
| Drain test offer race | The Q10 stress (6 parallel lanes) failed `a_drained_worker_takes_no_new_offers_and_keeps_its_held_attempt` once: the same leased-before-delivered race as the burst test. | `eea1e34`: waits for the offer to arrive. | The test itself (Q10 stress 120/120 after) |
| macOS type-check | The workspace did not type-check for `aarch64-apple-darwin`: the mirror's reflink used Linux-only `FICLONE` under `cfg(unix)`, and a cache test used the crate's Linux-only `libc` dependency. The Part 09 check had covered only the CLI package. | `ac121ad`: one `ficlone` helper, real on Linux and `Unsupported` elsewhere (other Unix targets copy bytes); the FIFO test is Linux-gated. | `cargo check` and `cargo clippy -D warnings --workspace --all-targets --target aarch64-apple-darwin` (type-check only; no macOS hardware) |
| Mirror disk-bound test under load | `the_sweep_bounds_mirror_disk` failed once in a crate run, and 9 in 60 parallel runs even with in-process retries: a sweep skips a mirror whose lock is momentarily held (by design), and git children the suite's other tests fork hold an inherited lock descriptor until they exec, so which mirror went depended on timing. | `c8b574b`: the test runs alone in `mirror_sweep.rs`; helpers shared through `tests/support`. | `sentinel-git/tests/mirror_sweep.rs::the_sweep_bounds_mirror_disk` (60/60 under 6-way load) |

## Not a defect / kept by design

- **P09-16, server side.** The server's search carry makes its paging exact, and limits are checked between frames. Only the CLI's cut inside a frame was wrong, and it is fixed.
- **Q01 "reject unsatisfiable jobs".** Rejecting at enqueue would fail a job that a worker enrolled later could run. Unsatisfiable jobs are explained with the blocking constraint, reserve nothing (P08-2), and are bounded by the 6 h queue timeout. Documented in `6759536`. The Q01 task text still says "reject"; see Task verdict changes.
- **P08-2's proposed aging cap on the large-job reservation.** Not needed. The reservation holds only jobs younger than the large job, and only for a large job this worker can run.
- **Intake's `WriteAmbiguous` → `429`.** Safe there, because deliveries are deduplicated by delivery ID. `outcome_unknown` (P02-1) applies to the API routes whose retry could duplicate work.
- **P07-11, restore double walk.** Folding the listing check into the clone would conflict with P07-8's rule of checking every tree before cloning any. The second walk reads metadata only, and its per-file allocation is gone.
- **P07-15, symlinks in payloads.** Fixed by documentation ([recipes](recipes.md) "Symlinks are not cached", [cache](cache.md)). A format change that carries symlinks would reopen the P07-1 surface.
- **P07-24.** The fallback reason is kept in `detail` without bumping the summary format.
- **P07-10, sending the terminal report before publication.** An optional part of the proposal; left unchanged. The cache report says this ordering belongs to the attempt lifecycle, not the cache cluster. The per-file cost it would have hidden is gone.
- **P08-C3 nonce.** Not needed. The draining state keeps a stale tail out of a new transfer.
- **P08-T3 argv exposure.** Upstream Tailcat offers no alternative input, so the exposure is documented.
- **P08-12.** Host aggregation is kept as designed and its whole-host semantics are documented.
- **P05-2, caching App source tokens.** The optional proposal was not needed to fix the defect.
- **P05-3, `apply_concurrency`.** Unchanged. A group is arbitrary, so the ordering guard belongs in the resolver, where a stale push is now never dispatched.
- **Q09, "100 sessions and 10,000 jobs" as one test.** Kept as two tests: TLS sessions in `fleet_sessions.rs`, scheduler cost in `fleet_load.rs`. Combining them would need 100 TLS sessions draining 10k jobs through simulated executors. The fleet suite has no controller restart; `link.rs` covers restart for one worker.

## Deferred

| Item | To | Reason |
|---|---|---|
| P07-12: tenant-scoped private-registry authorization, and the `image exists` fast path serving any tenant | **S05** | Needs per-tenant registry credentials, which arrive with per-attempt secret delivery. Registry authority stays worker-wide, and [executor](executor.md) says so. The S05 text is being extended to name this. |
| K05 bounded image prefetch (P07-12) | **B04** | A K05 requirement that was never implemented. An offer carries only the image digest; the name arrives with the spec after the ack, and preparation already starts the pull then (`eee35e9`). A prefetch belongs to the measured image fast-path work. The B04 text is being extended. |
| P07-20: mirror materialization copies the whole object store on non-reflink filesystems | **B04** | A performance item that needs before/after measurement on ext4 or overlay. It is bounded by `MAX_OBJECT_FILES`. With manual runs out of mirrors (P07-17), the exposure it widened is closed. |
| P08-C8 remainder: hydration writes each byte three times, the offer reads the payload twice, and the bundle digest is not stored with the generation | **B04** | Throughput work on a transfer already bounded to at most 5 s per job. |
| Worker-side spool free-space admission (noted against D06) | **R01** | D06 covers the controller's disk admission. The worker's spool is capped per attempt and a failed write is a declared gap, so the bound holds; admission by free space is retention/operations work. |
| Tailcat node-key rotation (noted against Q06) | **R04** | Not in Q06's text; plan §5 asks for rotatable identities. Key rotation sits with the key-material operations in R04. |

Items fixed without an automated regression test, with the fix report's reason:

- **P02-8:** docs only.
- **P04-5:** no dedicated clock-skew test. The watchdog needs Podman-backed `Executor::start` and is exercised by `end_to_end.rs` and `slice.rs`.
- **P04-8:** no contention test. Storage's `tput.rs` harness measures the per-attempt lock.
- **P04-15:** needs a real exec race or a nested-cgroup runtime.
- **P04-23:** eviction is a map removal. Storage's writer-eviction test covers the bound.
- **P04-27:** thread placement only.
- **P04-28:** power-loss durability needs a fault-injecting filesystem. **Blocked by: fault-injecting filesystem or VFS.**
- **P04-30:** a panic can only be injected with a test-only hook.
- **P06-14:** docs only; the function has no caller.
- **P07-15:** docs only.
- **P07-25:** latent path; the worker passes `None`.
- **P08-12:** docs only.
- **P08-14:** no before/after behavior to assert.
- **W09 duplicate offers on the real executor:** needs Podman-backed `Executor::start`. Link-level dedup is covered by `duplicate.rs`.

## Task verdict changes

The audits marked these tasks Partial or Missing. Each one is met now, with the exceptions stated after the table.

| Task | Audit verdict | Closed by |
|---|---|---|
| F05 | Partial | The runner always records commit and compiler (`cbde766`). The committed baseline records still lack them; a correction note says so and nothing was filled in after the fact. |
| C03 | Partial | `outcome_unknown` (P02-1). The log route is the first to emit and accept `c1` cursors (P02-3). |
| C07 | Partial | Bounded reads (P02-4) |
| A02 | Partial | P03-4, P03-5, P03-6 |
| A05 | Partial | P03-1, P03-3 |
| A06 | Partial | P03-2 |
| A07 | Partial | P03-1 |
| W01 | Partial | P04-1, P04-2, P04-9 |
| W02 | Partial | P04-4, P04-10 |
| W05 | Partial | P04-11, P04-12, P04-13 |
| W06 | Partial | P04-3, P04-5, P04-14, P04-15, P04-16 |
| W07 | Partial | P04-7 |
| G01 | Partial | P05-2 (= P04-4), P05-7 |
| G02 | Partial | P05-1, P05-3, P05-5 |
| G03 | Partial | P05-3 |
| G05 | Partial | P05-4 |
| G07 | Partial | P05-1, P05-6, P05-11 |
| D01 | Partial | P06-1, P06-7 |
| D02 | Partial | P06-2, P06-4, P06-13 |
| D04 | Partial | P06-3, P06-5. Time and line checkpoints are written but no reader seeks by them yet; this is now documented. |
| D06 | Partial | P06-1, P06-9. Worker-side spool free space moved to R01. |
| D07 | Partial | P06-5, P06-10 |
| K03 | Partial | P07-1, P07-2, P07-3, P07-4, P07-5 |
| K04 | Partial | P07-17, P07-18, P07-22 |
| K08 | Partial | P07-6, together with fleet's use of `avail_images` (P08-6) |
| Q01 | Partial | P08-2, P08-4. "Reject unsatisfiable jobs" was replaced by a documented design decision (see Not a defect). |
| Q02 | Partial | P08-1, P08-2, P08-3, P08-5 |
| Q03 | Partial | P08-6 |
| Q04 | Partial | P08-7, P08-8 |
| Q05 | Partial | P08-11. Mid-flight revocation is reconciled in the pass (P08-7). The cache docs about the control fallback were corrected. |
| Q06 | Partial | P08-T1, P08-T5. DERP and self-hosted relay docs (`fbf72cb`). Key rotation (a plan item, not in Q06's text) moved to R04. |
| Q07 | Partial | P08-T2, P08-T3, P08-T6; throughput counts the bulk connection (`529d4a7`) |
| Q08 | Partial | P08-C1 to P08-C9; part of C8 is deferred to B04 as a performance item. |
| Q09 | Partial | Load run rewritten to hold capacity and recorded in `bench/`; noisy-tenant fairness observable; P08-9 |
| O05 | Partial | P09-11, P09-12, P09-13 |

Not met, stated plainly:

- **K05 was Partial and is closed only by moving scope.** Bounded prefetch was never implemented; an offer carries only the digest and the reference arrives with the spec after the acknowledgement, when preparation already starts the pull. The requirement moved to B04 and tenant-scoped private-image authorization to S05; the K05 item text says so. The single-flight pulls and the pull/checkout overlap are met.
- **O07 remains Blocked by: no macOS hardware or Apple toolchain.** The macOS Keychain in O04 is also unverified. Nothing in this audit changes that.
- **P04-28's power-loss boundary is implemented but unverified.** Blocked by: a fault-injecting filesystem.

The audit notes raised three more gaps without finding IDs, and no cluster took them:

- **D06, worker-side spool free space.** D06 is the controller's disk admission (its reserve protects the metadata database and log evidence), and that is met. The worker's log spool is capped per attempt (256 MiB) and a failed write becomes a declared gap, but the worker has no free-space probe. Moved to **R01**, whose text now names it.
- **Q06, Tailcat key rotation.** Q06's text does not ask for it; plan §5 asks for rotatable identities. Moved to **R04** (key material operations), whose text now names it.
- **Q07, throughput.** Fixed in `529d4a7` (see [Found during integration](#found-during-integration)).

K08's costly-hit rule remains a fixed heuristic (hit + reflink root + everything copied, or more than 5 s of lock wait plus clone); it does not compare against a measured rebuild. K08's text asks to flag costly hits, which it does; comparing against a rebuild belongs with B05's cache-usefulness measurements.

## Measurements recorded by the fixes

These are quoted from the cluster reports. No number here was re-measured for this record.

- **Storage (P06-8).** `cargo test --release -p sentinel-store --test tput -- --ignored`. The workload was 8 threads × 250 frames of 512 B; every frame is a write plus fdatasync. It ran on Windows 11 NTFS on the shared development host, three alternating runs per tree:

  | Concurrent attempts | Base (frames/s) | Fix (frames/s) |
  |---|---|---|
  | 1 | 360, 347, 411 | 371, 370, 429 |
  | 8 | 383, 438, 418 | 784, 768, 945 |

- **Storage (P06-4).** In `a_large_seal_does_not_hold_the_writer`, writer round trips kept completing while a 64 MiB seal hashed outside the writer.
- **Cache (P07-10).** Publishing 20,000 files × 4 KiB in 200 directories, WSL2 ext4 `/tmp`, release build, 5 runs per series, two series per tree. WSL2 figures are reference only.
  - Cold publish median: base 108,143 ms and 111,048 ms; fix 351.3 ms and 320.6 ms.
  - Incremental publish median: base 857.2 ms and 836.9 ms; fix 282.8 ms and 252.6 ms.
- **Intake (P05-8).** At a 10 ms test tick, the idle lane caused 40 generation bumps in 500 ms before the fix and none after. The due query is now an index search with no temp B-tree. No wall-clock benchmark was run.
- **Fleet (P08-6 and P08-8), `bench/q09-fleet-load.jsonl`.** WSL2 Ubuntu 24.04, i7-13700KF, release.
  - Original harness (100 workers, 1 tenant, placements released in the same transaction):
    - elapsed: 22,380 ms before, 11,252 ms after;
    - `place()` p50/p95/p99: 1,887/3,093/3,821 µs before, 575/886/1,103 µs after.
  - New harness (capacity held; 4 tenants, 12 repositories, 20 PR runs, 25 labeled runs, 50 hosts × 2 identities):
    - elapsed: 9,464 ms before, 5,812 ms after;
    - waves: 13 before, 7 after;
    - `place()` p50/p95/p99/max: 252/860/3,303/17,523 µs before, 272/545/728/1,499 µs after;
    - queue wait p50/p95/p99/max: 5,800/9,105/9,408/9,423 ms before, 3,015/5,342/5,717/5,768 ms after;
    - throughput: 1,057 jobs/s before, 1,720 jobs/s after;
    - process CPU: 9,200 ms before, 5,320 ms after;
    - peak RSS: 12.6 MiB before, 12.7 MiB after.
  - `list_queue` over 5,000 queued jobs with 20 connected workers:
    - limit 100: 5,915,231 µs before, 3,981 µs after;
    - limit 500: 4,768,443 µs before, 1,683 µs after.
  - Tailcat helper verification: 8.7 ms → 0.9 µs per execution for an unchanged 18 MB helper.
  - P08-11: control teardown took 3.68 s before the fix; the test requires under 1.5 s after.
- **Execution (P04-19).** `process::tests::a_quick_helper_is_not_held_by_a_poll_interval` asserts that a helper costs less than a blocking `status()` plus 8 ms. The cluster could not measure log throughput (its release build was stopped for low memory); the integrator measured it, below.
- **Execution (P04-19), measured at integration.** `log_throughput` (`ea60329`) built in release from `cfcba5d` (the harness copied in; it uses only APIs present there) and from the merged tree `eee35e9`, run inside WSL2's own ext4 (`/root/bench`), i7-13700KF, 24 threads, alternating base and merged, five runs of `log_path_throughput` each under `timeout 300`, then three of `helper_wait_latency` each. 64 MiB in 8 KiB chunks through `LogPipe` over loopback TLS to an acknowledging stand-in:

  | | base `cfcba5d` | merged |
  |---|---|---|
  | linked and acknowledged | runs 2 and 5: 1,075.6 ms (60 MiB/s), 1,007.4 ms (64 MiB/s); runs 1, 3, 4: **never finished** (killed at 300 s) | 1,038.3, 924.4, 1,003.3, 988.5, 993.1 ms (62–69 MiB/s) |
  | spool only | 294.8, 291.2 ms (217, 220 MiB/s) | 314.3, 297.5, 327.9, 279.7, 285.7 ms (195–229 MiB/s) |
  | one helper run (`exit 0` shim) | 20.41, 20.36, 20.37 ms | 369, 298, 372 µs |
  | the same process with a blocking wait | 318, 289, 316 µs | 295, 274, 265 µs |

  Throughput on this loopback harness is unchanged within noise; the fix's gain is elsewhere: the helper wait drops from about 20 ms (the old 20 ms poll) to within about 0.1 ms of a blocking wait, and the base log path **stalled in three of five runs**. In a stalled base run only the main thread and the test's wait loop remained (the TLS session threads had ended) and no further frame was acknowledged. This is consistent with the rustls "message buffer full" session drop on bursts of full frames that the cache cluster fixed in `27d1135`; it was not traced further. Raw output: the integrator's scratch `log-throughput-results.txt`.
- **Foundation (P09-17).** No timing. The query plan lost its `USE TEMP B-TREE FOR ORDER BY` step, and the test asserts that.

## Verification evidence

Run sequentially, one build at a time, on the development host (i7-13700KF, 24 threads, Windows 11 and WSL2 Ubuntu 24.04, kernel 6.18.33.2). WSL2 verifies Linux process, signal and container behavior; it is not a production benchmark host. The final tree is `c8b574b` unless a row says otherwise.

| Where | Command | Exit | Result |
|---|---|---|---|
| Windows | `cargo fmt-check` | 0 | clean |
| Windows | `cargo lint` | 0 | no warnings |
| Windows | `cargo test-cli --no-fail-fast` | 0 | 127 binaries: 862 passed, 0 failed, 3 ignored (the two `fleet_load` measurements and `tput`) |
| Windows | `cargo release-cli` | 0 | built |
| WSL2 | `cargo lint-linux` | 0 | no warnings |
| WSL2 | `cargo test-server --no-fail-fast` | 0 | 127 binaries: 1,022 passed, 0 failed, 11 ignored |
| WSL2 | `cargo test-linux --no-fail-fast` | 0 | 127 binaries: 1,023 passed, 0 failed, 11 ignored |
| WSL2 | `cargo release-linux` | 0 | built |
| WSL2, rootless Podman 4.9.3 (cgroup v2) | each Podman-gated worker binary as the non-root `sentinelbench` account: `sudo -iu sentinelbench env SENTINEL_PODMAN_TESTS=1 <target>/debug/deps/<suite>-<hash>` | 0 | `podman` 2, `end_to_end` 1, `compiler_cache` 1, `k09` 3, `slice` 1: 8 passed, 0 failed, none skipped |
| WSL2, rootful Podman (tree `93884b4`; no link or Tailcat source changed after it) | the live Tailcat suite as its header documents: `SENTINEL_TAILCAT_LIVE=/root/tailcat/tailcat SENTINEL_TAILCAT_DERPER=… SENTINEL_TAILCAT_DERP_CA=… SSL_CERT_FILE=… cargo test -p sentinel-link --all-features --test tailcat_live -- --ignored --nocapture --test-threads=1`, `/usr/sbin` on `PATH` | 0 | 6 passed in 123 s; live probe `path Relay, rtt 67.6ms`; self-hosted relay `pong in 310µs via DERP(local)` |
| WSL2, release (tree `93884b4`; store code unchanged since) | `SENTINEL_BENCH_OUT=… cargo test --release -p sentinel-store --test fleet_load -- --ignored --nocapture --test-threads=1`, three runs | 0 ×3 | 2 passed each; recorded in `bench/q09-fleet-load.jsonl` (below) |
| WSL2 | Q10 stress: the prebuilt `sentinel-link` `fleet` binary (all 6 tests, the Q10 mixed-fleet test among them) in 6 parallel lanes × 10 runs | — | first batch (tree `93884b4`): 59 of 60 runs passed; the one failure was the drain test's offer race (fixed in `eea1e34`), and the Q10 test passed all 60. After the fix: two batches, 60 of 60 and 60 of 60 |
| WSL2 (zig 0.16 as C compiler, sysroot linked to the Windows toolchain's `aarch64-apple-darwin` std) | `cargo check` and `cargo clippy --locked --workspace --all-targets --target aarch64-apple-darwin -- -D warnings` | 0 | clean after `ac121ad`; before it, 3 errors (`libc::FICLONE` twice, a Linux-only `libc` use). A type-check, not a macOS run (Blocked by: no macOS hardware) |

Flaky-test fixes, re-run under load (6 parallel lanes):

- `sentinel-store` `writer_queue_is_bounded_and_reports_back_pressure`: 60 of 60. The old test also passed this stress; it had failed only under full-suite load with memory pressure. The fix removes its two timing guesses.
- `sentinel-link` Tailcat suite (17 tests): 30 of 30 full-suite runs.
- `sentinel-worker` `a_quick_helper_is_not_held_by_a_poll_interval`: 30 of 30, with full lib-suite runs alongside.
- `sentinel-git` `mirror` and `mirror_sweep`: 60 of 60 each. Before the split (with the test retrying skipped sweeps in-process), 51 of 60; the unchanged test failed once in a `sentinel-git`/`sentinel-cache` run.

**Load run (`fleet_load`, release, three runs on `93884b4`), against the fleet cluster's recorded run on `fix-fleet`:**

| | fleet report | run 1 | run 2 | run 3 |
|---|---|---|---|---|
| elapsed | 5,812 ms | 4,592 ms | 4,638 ms | 4,444 ms |
| `place()` p50 / p95 / p99 / max | 272 / 545 / 728 / 1,499 µs | 249 / 475 / 543 / 814 µs | 253 / 484 / 551 / 832 µs | 250 / 482 / 559 / 803 µs |
| queue wait p50 / p95 / p99 / max | 3,015 / 5,342 / 5,717 / 5,768 ms | 2,354 / 4,233 / 4,517 / 4,550 ms | 2,389 / 4,260 / 4,565 / 4,587 ms | 2,375 / 4,130 / 4,383 / 4,408 ms |
| throughput | 1,720 jobs/s | 2,178 | 2,156 | 2,250 |
| waves / rounds | 7 / 108 | 7 / 107 | 7 / 107 | 7 / 107 |
| first wave per tenant | [700, 300, 300, 300] | same | same | same |
| process CPU / peak RSS | 5,320 ms / 12.7 MiB | 4,780 ms / 12.8 MiB | 4,820 ms / 12.8 MiB | 4,850 ms / 12.8 MiB |
| `list_queue` 5,000 jobs, limit 100 / 500 | 3,981 / 1,683 µs | 3,728 / 1,426 µs | 3,491 / 1,483 µs | 3,420 / 1,460 µs |

All 10,000 jobs were placed with 0 placement failures in every run. The merged tree is at least as fast as the fleet branch; this is one host, three runs, and not a production benchmark.
