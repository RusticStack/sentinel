# Parts 09–11 re-audit

A second audit re-read Parts 09 (OAuth server and CLI), 10 (secret management and delivery) and 11 (structured diagnostics and MCP) after they were implemented. Its findings were fixed in five clusters on separate branches, each based on `f7e7b5d`. The branches were then merged into `part-09`, the leftovers the clusters could not close were closed, and the merged tree was verified once. This document records every finding with its outcome, commit and regression test, the leftovers, the test flakes found under load, and the verification that was actually run.

Worker protocol stays at **10**; no branch changed it. Migrations are now contiguous through **44** (see [compatibility](compatibility.md)).

## Integration

| Merge commit | Branch | Notes |
|---|---|---|
| `d5dc986` | `fix2-diagnostics` | The failure route moved to `crates/sentinel-api/src/routes/failure.rs`. |
| `06fdbbf` | `fix2-cli` | Clean merge; `run_wait` in `routes.rs` reads the version and view from one snapshot. |
| `8ba0057` | `fix2-delivery` | Conflict in `sentinel-worker/src/redact.rs` (see below). |
| `1931cb2` | `fix2-secrets` | Conflict in `sentinel/src/keystore/file.rs`, plus two semantic overlaps in `secrets.rs` and `controller.rs` (see below). |
| `236727c` | `fix2-oauth-mcp` | Conflicts in `schema.rs`, `routes.rs` and `compatibility.md`; migrations renumbered. |

**Migrations.** Both new migrations had been registered as version 43 on their branches. After the merge:

| Version | File | Content |
|---|---|---|
| 43 | `043_oauth_client_lifecycle.sql` | `deployment_policy.oauth_client_registration`, `oauth_clients.registrant`, `client_id` indexes, the enabled-only capacity trigger, the append-only `operation_audit` table |
| 44 | `044_secret_hardening.sql` | purges unkeyed `secret_idempotency` rows, rebuilds `secret_audit` (nullable `secret_id`, `name`, append-only), forward-only reseal triggers |

No file was renamed: the file numbers already matched the final order. `schema.rs` registers them as 43 and 44, the compile-time contiguity check passes, and every store test opens a fresh database through all 44 migrations in order.

**Conflicts and how they were resolved.**

- **`redact.rs` (delivery × diagnostics).** Delivery replaced the scan with two Aho–Corasick automata (P10D-10). Diagnostics registered JSON-escaped forms and the lines of multi-line values (P11D-4). The merge keeps the automata and folds the extra registrations into `register`. Duplicates are removed (and wiped) when the automata are rebuilt, so a value with many lines costs no quadratic search at registration. The merge also closed the short-line residual (see leftovers).
- **`keystore/file.rs` (cli × secrets).** The CLI cluster replaced the Windows ACL check with a shared walker (P09C-3). The secrets cluster added an owner check to the secret-input check (P10C-8). The merge keeps the walker, and its secret-input policy now also requires the owner to be the user or SYSTEM.
- **`secrets.rs` / `controller.rs` (delivery × secrets).** Both clusters audited a refused secret delivery: P10S-6 in `secrets::deliver`, and P10D-7 in `refuse_delivery`. Both also defined a type named `Refusal`. The store's private type is now `AuditedRefusal`, and `deliver` is the only audit writer. `refuse_delivery` only explains the refusal for the attempt's failure detail. The test drives the controller's order and asserts exactly one audit row per refusal.
- **`schema.rs`, `routes.rs`, `compatibility.md` (secrets × oauth-mcp).** Migrations renumbered as above. `routes.rs` keeps the `failure` module and gains `operations`; secret routes stay in `secret_routes`. Both compatibility paragraphs are kept, with their final numbers.
- **Tests building the API config.** `crates/sentinel/tests/secrets_cli.rs` (new in the secrets cluster) gained `trusted_proxies`. The X08 test's run-control audit check was rewritten for the diagnostics cluster's MCP session helper.

## Findings by cluster

Commits are the fix-branch commits, which the merges carry unchanged.

### OAuth and MCP (`fix2-oauth-mcp`; audits p09-server and p11-mcp)

| ID | Outcome | Commit | Regression test |
|---|---|---|---|
| P09S-1 / P11-2 | Fixed: CIMD documents are fetched only for a signed-in account, through one deployment-wide outbound slot shared with GitHub sign-in; 2 s timeout; 503 past the slot | d647455 | `oauth_code::anonymous_metadata_document_requests_neither_fetch_nor_hold_the_api`; api `outbound_calls_are_capped_without_queueing` |
| P09S-2 / P11-1 | Fixed: registration policy (`off`/`metadata`/`open`, default `metadata`), enabled-only cap, 16 per address, reclamation, `admin oauth-client` and `admin policy set --oauth-client-registration` | 6b7a256 | store `oauth_client_registration::*`; `oauth_code::dynamic_registration_is_off_by_default_and_not_advertised` |
| P09S-3 | Fixed: registered clients are redirected only after sign-in | d647455 | `oauth_code::a_registered_clients_errors_redirect_only_after_sign_in` |
| P09S-4 | Fixed: optional metadata members parse | 6b7a256 | protocol `metadata_from_a_controller_before_client_registration_still_parses` |
| P09S-5 | Fixed: RFC 7591 default `grant_types` | d647455 | api `registered_clients_must_declare_only_supported_grants_and_responses` |
| P09S-6 | Fixed: loopback redirects match any port | 6b7a256 | auth `registered_loopback_redirects_match_any_port_on_the_same_host_and_path` |
| P09S-7 | Fixed: a CIMD row is not addressable by its internal key | d647455 | `oauth_code::a_metadata_document_client_is_not_addressable_by_its_internal_key` |
| P09S-8 | Fixed: unverified-client notice, redirect origin in bold, no impersonating names | 6b7a256, d647455 | store `…names_are_not_impersonated`; consent `the_redirect_host_is_the_origin_of_the_redirect` |
| P09S-9 | Fixed: `trusted_proxies` (loopback-only default) | d647455 | api `oauth::limit::tests::*` |
| P09S-10 | Partly fixed on the branch (docs only); **closed at integration** (see leftovers) | d647455, ae2f50b, 7ce4b58 | `github_sign_in::the_same_origin_hop_revokes_the_session_the_callback_could_not_see` |
| P09S-11 | Fixed: one HTTP agent per process | d647455 | existing CIMD tests (no behavioral test possible) |
| P09S-12 | Fixed: bad-scope case, MCP token at `/api/v1` | 7e6e39d | `mcp_http_uses_its_resource_audience_and_protected_sessions` |
| P11-3 | Fixed: default grants accepted, device grant intersected away | d647455 | `standard_native_registrations_are_accepted_and_match_any_loopback_port` |
| P11-4 | Fixed: version negotiation, 400/404 session errors | 7e6e39d | `mcp_http_uses_…` |
| P11-5 | Fixed: 16 sessions per user, per-user LRU | 7e6e39d, 7c53fe1 | api `mcp_sessions_are_capped_per_user_with_lru_eviction` |
| P11-6 | Fixed: append-only `operation_audit` (migration 43) | 6b7a256, 7e6e39d | `wait::mcp_agent_finds_failure_in_a_hundred_mib_log_and_explicitly_reruns` |
| P11-7 | Fixed: route scope refusal lifted to the 403 challenge | 7e6e39d | `mcp_http_uses_…` |
| P11-8 | Fixed: stdio uses the shared `execute_tool` | 7e6e39d | `stdio_tools_call_without_arguments_uses_defaults`; protocol `only_a_preflighting_backend_compiles_dispatched_pipelines_itself` |
| P11-9 | Fixed: precise tool annotations | 7e6e39d | protocol `tool_annotations_describe_each_tool_precisely` |
| P11-10 | Partly fixed on the branch; **closed at integration** (see leftovers) | 7e6e39d, fa339f7 | `an_expired_mcp_token_gets_the_invalid_token_challenge`; `oauth_e2e::mcp_stdio_reports_scope_denial_without_starting_an_oauth_redirect_flow` |
| P11-11 | Fixed: no argument clones, catalogues serialized once; not measured | 7e6e39d | protocol `cached_catalogues_equal_the_definitions` |
| X07 | **Not met**: no real MCP client has been run; the task is `[ ]` with `Blocked by:` in [TODO](../TODO.md) | — | — |

### CLI (`fix2-cli`; audit p09-cli)

| ID | Outcome | Commit | Regression test |
|---|---|---|---|
| P09C-1 | Fixed: downloads resume from a partial file after a 30 s idle stall | 4803a1b | `client.rs::a_slow_download_longer_than_the_call_bound_completes`, `a_stalled_download_resumes_from_its_partial_file`, `an_interrupted_download_keeps_its_bytes_and_the_next_run_resumes` |
| P09C-2 | Fixed: named back-offs retried for repeatable requests | 4803a1b | `client.rs::a_named_server_backoff_is_honored_then_retried`, `an_mcp_tool_call_retries_a_named_backoff` |
| P09C-3 | Fixed: Windows ACL/owner checks on handles, tamper refusal | 398def8 | `profile.rs::windows_a_preexisting_configuration_directory_others_can_modify_is_refused`, `a_tampered_profile_is_refused_before_any_request` |
| P09C-4 | Fixed: loopback listener checks `state`, bounded threads | 398def8 | `profile.rs::the_loopback_listener_checks_state_and_issuer_and_ignores_other_paths`; `oauth_e2e.rs::the_cli_refuses_a_callback_with_the_wrong_state_or_issuer` |
| P09C-5 | Fixed: System32 launcher, no `SENTINEL_*` variables | 8bb0c65 | `browser.rs` launcher tests |
| P09C-6 | Fixed: `log show --output json` byte/frame budget | 4803a1b | `commands.rs::log_show_json_stops_at_its_byte_budget_with_a_continuation` |
| P09C-7 | Fixed: one-snapshot `run_wait`; client end check | 4803a1b | `client.rs::wait_does_not_judge_a_finished_answer_whose_run_is_live_again` |
| P09C-8 | Fixed on the branch; the two-directory race **closed at integration** | 398def8, 4325666 | `profile.rs::windows_a_legacy_shared_entry_moves_to_its_directory_or_is_left_to_its_owner`, `windows_two_directories_never_refresh_one_legacy_entry_at_once` |
| P09C-9 | Fixed in the secrets cluster (SAFETY comments) | bb0679d | — |
| P09C-10 | Fixed: capped, jittered named back-off | 4803a1b | `client::tests::a_named_backoff_is_capped_and_jittered_without_overflow` |

### Secrets (`fix2-secrets`; audits p10-store and p10-cli)

| ID | Outcome | Commit | Regression test |
|---|---|---|---|
| P10S-1 / P10C-1 | Fixed: keyed retry fingerprints (migration 44 purges old rows) | 8c7eaed, 00090a4 | `sealed::tests::fingerprints_are_keyed_by_the_master_key`; `api.rs::the_stored_retry_fingerprint_is_not_an_unkeyed_digest_of_the_value` |
| P10S-2 | Fixed: binding, allowlist and revocation routes and CLI commands; the MCP part **closed at integration** | 8c7eaed, 00090a4, bb0679d, 0fc1955 | `secret_scopes.rs::bindings_allowlists_and_revocations_are_idempotent_by_name`; `api.rs::secret_bindings_allowlists_and_revocation_are_served_over_http`; `api.rs::mcp_lists_a_slash_named_repositorys_secret_bindings_as_metadata_only` |
| P10S-3 | Fixed: no tenant oracle on secret routes | 00090a4 | `api.rs::a_foreign_tenant_or_repo_is_not_found_on_every_secret_route` |
| P10S-4 | Fixed: fixed key path, start-up refusal without the matching key | 4e2cc7c | `key_admin.rs::the_server_refuses_to_start_without_the_key_its_sealed_values_need` |
| P10S-5 | Fixed: `admin key reseal [--retire]` | 8c7eaed, 4e2cc7c | `sealed::tests::reseal_then_retire_…`; `secret_scopes.rs::every_sealed_row_is_resealed_…`; `key_admin.rs::admin_reseal_then_retire_…` |
| P10S-6 | Fixed: refused deliveries audited once (see the merge) | 8c7eaed, 1931cb2 | `secret_delivery.rs::preparation_is_acknowledgement_fenced_…`, `a_refused_delivery_is_explained_and_audited` |
| P10S-7 | Fixed: no second resolve, cached statements | 8c7eaed | existing delivery tests (performance, not measured) |
| P10S-8 | Fixed: zeroize features, exact-size bundle buffer | 8c7eaed | none possible (freed memory) |
| P10S-9 | Fixed: key file opened once with `O_NOFOLLOW`, checked on the handle | 8c7eaed | `sealed::tests::loose_key_permissions_and_links_are_refused` |
| P10S-10 | Fixed: stale pending key file removed | 8c7eaed | `sealed::tests::a_stale_pending_key_file_does_not_block_rotation` |
| P10S-11 | Fixed: one statement per listing scope | 8c7eaed | `secret_scopes.rs::each_listing_scope_walks_only_its_own_index` (query plan) |
| P10S-12 | Fixed: delegated writers stay in their repository | 8c7eaed | `secret_scopes.rs::a_delegated_writer_stays_inside_its_repository_and_narrowing` |
| P10C-2 | Fixed: retry-safe CLI writes naming key and version | bb0679d | `secrets_cli.rs::a_rerun_with_the_same_key_replays_…`, `an_import_bound_to_its_preview_refuses_a_moved_version` |
| P10C-3 | Fixed: raw prompt refusing pastes and oversize input | bb0679d | `commands::secrets::tests::the_prompt_line_never_truncates_and_refuses_pastes` |
| P10C-4 | Fixed: BOM, UTF-16 and bare CR handling | bb0679d | protocol `a_utf8_bom_is_skipped_and_utf16_is_named`, `a_bare_carriage_return_is_refused_with_its_line` |
| P10C-5 | Fixed: clap errors never echo a value | bb0679d | `secrets_cli.rs::a_value_typed_as_an_argument_is_never_echoed` |
| P10C-6 | Fixed on HTTP and CLI; the MCP side **closed at integration** | 00090a4, bb0679d, 0fc1955 | `api.rs::a_repository_name_with_a_slash_is_addressed_by_its_decoded_name`; protocol `secret_tools_address_owner_slash_name_repositories_in_the_query` |
| P10C-7 | Fixed: mintty message, Ctrl+C restores the terminal | bb0679d | the prompt-line test (a TTY is not automated) |
| P10C-8 | Fixed: Windows owner check (kept through the merge) | bb0679d, 1931cb2 | `commands::secrets::tests::a_permissive_windows_file_is_refused_with_the_icacls_fix` |
| P10C-9 | Fixed: `idempotency_mismatch` (422) | 8c7eaed, 00090a4 | `secret_scopes.rs::a_reused_idempotency_key_is_a_mismatch_not_a_conflict` |
| P10C-10 | Fixed: CLI tests added | bb0679d | `secrets_cli.rs::*`, `commands::secrets::tests::*` |
| P10C-11 | Fixed: one authorization per import | 8c7eaed, 00090a4, bb0679d | existing import tests (performance, not measured) |

### Delivery (`fix2-delivery`; audit p10-delivery)

| ID | Outcome | Commit | Regression test |
|---|---|---|---|
| P10D-1 | Fixed: stray processes cleared around secret steps | 2fa5fa2 | `secret_isolation::secret_delivery_holds_its_boundaries_in_rootless_podman` |
| P10D-2 | Fixed: excerpt redacted before it is transformed | 2fa5fa2 | `redact::tests::a_failure_excerpt_carries_no_fragment_of_a_value`; `logpipe::tests::a_failure_excerpt_is_redacted_before_it_is_cut` |
| P10D-3 | Fixed: transfer survives a reconnect between ack and spec | ea3126d | `session::tests::a_secret_transfer_survives_a_new_session_between_ack_and_spec` |
| P10D-4 | Fixed: non-root file targets readable | 2fa5fa2 | `attempt::tests::delivered_env_and_files_live_outside_workspace_…`; `secret_isolation` |
| P10D-5 | Fixed: per-tenant Podman stores for authorized pulls | 2fa5fa2, fe855c1 | `podman::tests::a_private_store_is_per_tenant_and_named_on_every_command`; `secret_isolation` |
| P10D-6 | Fixed: placement requires protocol 10 and bit 9 | 6207c21 | `secret_delivery::a_secret_job_is_never_placed_on_a_worker_below_protocol_10` |
| P10D-7 | Fixed: refused delivery explained; audit single-sourced at merge | 6207c21, 1931cb2 | `secret_delivery::a_refused_delivery_is_explained_and_audited` |
| P10D-8 | Fixed: env through a read-only file and wrapper, tmpfs staging | 2fa5fa2 | `attempt::tests::env_targets_reach_the_step_exactly_through_the_wrapper`; `recovery::tests::restart_reaps_secret_scratch_before_work_resumes` |
| P10D-9 | Fixed: core dumps off in containers and services | 2fa5fa2, 6207c21, 95870d3 | `service::hardening_tests::a_service_process_keeps_its_memory_out_of_dumps` |
| P10D-10 | Fixed: O(output) redaction | 2fa5fa2, 5f98491 | `redact::tests::the_automaton_matches_the_reference_scan`, `a_near_miss_value_costs_linear_time` |

### Diagnostics (`fix2-diagnostics`; audit p11-diag)

| ID | Outcome | Commit | Regression test |
|---|---|---|---|
| P11D-1 | Fixed: an unusable location drops only its source | 676ce1f, 5f7eed8 | `go_locations_with_colour_control_bytes_or_oversized_paths_never_void_the_report`; `wait::failure_view_keeps_coloured_reports_…` |
| P11D-2 | Fixed for reruns on the branch; the lapse residual **closed at integration** | 86facf2, 57d4ad0 | `wait::failure_view_parses_attempt_logs_…`; `dispatch.rs::a_lapsed_attempt_never_inherits_the_queued_jobs_later_verdict` |
| P11D-3 | Fixed: cargo `--message-format=json` | 676ce1f, 5f7eed8 | `cargo_message_format_json_yields_compiler_diagnostics_…` (real cargo 1.98.1 output) |
| P11D-4 | Fixed on the worker; the short-line residual **closed at integration** | 904ceff, 676ce1f, 8ba0057 | `redact::tests::json_escaped_values_are_redacted_…`, `multi_line_values_are_redacted_line_by_line`, `short_lines_of_a_multi_line_value_are_redacted` |
| P11D-5 | Fixed: newest window parsed; binary frames compacted | 86facf2, 5f7eed8 | X08 test; `failure::tests::binary_frames_are_told_from_coloured_text` |
| P11D-6 | Fixed: the step's own tail, to the real end | 86facf2, 5f7eed8 | `logs::the_newest_page_of_a_step_ignores_later_steps_…` |
| P11D-7 | Fixed: oversized lines skipped before parsing | 5f7eed8 | `failure::tests::detection_skips_oversized_lines_without_parsing_them` |
| P11D-8 | Fixed: truncated/deep JUnit is incomplete | 676ce1f | `junit_truncated_or_deeply_nested_documents_are_incomplete` |
| P11D-9 | Fixed: lenient output types, strict input | 676ce1f | `server_reports_ignore_additive_fields_…`, `input_rejects_unknown_fields_at_every_depth` |
| P11D-10 | Fixed: control characters sanitised, capping linear | 676ce1f, 5f7eed8 | `display_text_replaces_controls_…`, `capping_removes_items_by_measured_size_in_one_pass` |
| X02 / X03 / X08 gaps | Fixed: report-file collection, ownership, late failures | 86facf2, 5f7eed8 | `wait::artifact_reports_are_advisory_evidence_…`, `wait::mcp_agent_finds_failure_in_a_hundred_mib_log_and_explicitly_reruns` |

## Leftovers closed at integration

| Leftover | Root cause and fix | Commit | Test |
|---|---|---|---|
| Bindings over MCP (P10S-2) and `owner/name` repositories (P10C-6) | New read-only `list_secret_bindings` tool (`secrets:metadata`) in the shared contract; secret tools validate repository names with the store's rule and send them form-encoded in the query. Path-addressed tools keep the strict segment rule. | 0fc1955 | protocol `secret_tools_address_owner_slash_name_repositories_in_the_query`; `api.rs::mcp_lists_a_slash_named_repositorys_secret_bindings_as_metadata_only` |
| P11D-2 residual (lapse, then cancel or queue timeout) | A lapsed or declined offer kept the job's lease stamp (`leased_ms` is set with `COALESCE`), so the lapsed attempt still looked current. `give_back`, the only path back to `Queued`, now clears the stamp in the same transaction, which is the marker a rerun already sets. No migration is needed. | 57d4ad0 | `dispatch.rs::a_lapsed_attempt_never_inherits_the_queued_jobs_later_verdict` (fails without the fix) |
| P09S-10 (previous session not revoked) | Browsers withhold the Strict session cookie on GitHub's cross-site redirect back. The callback now issues nothing: it parks a 60-second in-memory hand-off, keyed by the browser's sign-in cookie digest, and moves the browser on to `GET /auth/github/finish`. That same-origin hop carries the Strict cookie, and finish revokes the old session and issues the new one in one transaction. A request labelled other than `Sec-Fetch-Site: same-origin` is refused without spending the hand-off. | 7ce4b58, f523501 | `github_sign_in::the_same_origin_hop_revokes_the_session_the_callback_could_not_see`. The sign-in suite now models SameSite and `Sec-Fetch-Site`; under that model the old callback fails `a_github_sign_in_replaces_the_browsers_previous_session`. |
| P11-10 (stdio test on a real profile) | The stdio MCP test imports a service grant with `auth login --grant-file` into a temporary `SENTINEL_CONFIG_DIR`. It asserts the scope refusal names `runs:read`, and that after revocation the refused refresh surfaces as `client_unauthenticated` with the local sign-in fix. Neither path creates a grant or starts a redirect. | fa339f7 | `oauth_e2e::mcp_stdio_reports_scope_denial_without_starting_an_oauth_redirect_flow` |
| Diagnostics residual (short lines of a multi-line secret) | Every line of a multi-line value is now registered, raw and JSON-escaped, whatever its length, unless it is only ASCII punctuation and whitespace (`{`, `}`, `-----`, blank), which would erase that character from all later output. [logs](logs.md) and [secrets](secrets.md) now say so; the stale "under 8 bytes" text is gone. | 8ba0057 | `redact::tests::short_lines_of_a_multi_line_value_are_redacted` |
| P09C-8 residual (two directories, one legacy entry) | Profile locks live in each configuration directory, but a legacy Credential Manager entry is shared by all of them. A legacy refresh now also takes a session-local named mutex derived from the entry's key. | 4325666 | `profile.rs::windows_two_directories_never_refresh_one_legacy_entry_at_once` (without the lock the same refresh token is presented twice) |

## Credential Manager under concurrent processes (found by the final run)

The first final `test-cli` run failed both Windows legacy-entry tests. They failed together about 1 run in 15. Logging every delete showed no deletion before the failed read. A probe that writes and immediately reads distinct keys showed the cause:

| Probe (4 threads × 100 write/read/delete) | Result |
|---|---|
| one process, 8 threads | 0 lost reads |
| four processes at once, 5 rounds, no lock | 15 of 20 processes lost at least one read |
| four processes at once, 2 rounds, with the store lock | 8 of 8 clean |

With several processes writing at once, `CredReadW` sometimes answers not-found for an entry that was just written and never deleted. Two parallel `sentinel` commands on one Windows account could therefore see "not signed in". Every Credential Manager call of this session's Sentinel processes now takes one named mutex first (`260f74f`). After the fix, the two legacy tests passed 15 of 15 runs together and the whole profile suite 10 of 10. The probe was a diagnostic and is not kept; its 950 leftover entries (keys on ports 40000–43099 from interrupted probe runs) were deleted, and no other entry was touched.

## Flaky tests

| Test | Root cause | Fix | Stress evidence |
|---|---|---|---|
| `sentinel-cache` `a_busy_answer_keeps_a_valid_partial` | The real 5 s hydration budget's rate projection includes resume hashing and staging fsyncs, so a stall under load aborted the resume (`Miss(Unavailable)`) | Behavior tests use a deadline no run reaches. A new deterministic test proves the budget: the fake holds the second chunk until the deadline passes, the partial is kept, and the next attempt resumes. | Before: 156 of 480 runs failed (48 parallel workers, 8 CPU hogs, 6 fsync writers). After: 480/480 for both tests under the same load. (These runs predate the owner's request to keep stress short and avoid disk-heavy load.) |
| `sentinel-pipeline` `hostile_documents_fail_fast_with_structured_errors` | Bounded work was asserted as `< 500 ms` wall-clock | Asserts work instead: `TooManyNodes` at `MAX_NODES` on the jobs line, before mid-line. The mutation sweeps judge the fastest of up to three runs on an overrun. | Before: 3 of 480 failed (96 workers, 24 CPU hogs, 8 fsync writers). After: 480/480, and 144/144 for each sweep |
| `sentinel` `client.rs` retry count | The fake server counted a request after writing its response, so the test could read the counter first | Count before answering | The old binary did not fail in 480 loaded runs; the fix follows from the ordering (happens-before) |
| `sentinel-api` `an_active_session_outlives_its_first_idle_deadline` | The probes ran on the client's clock, while the server stamps its own; the last probe sat 700 ms after a deadline that a late-handled request moves | Probes wait until the wall clock passes the deadlines recorded in `sessions`, and assert each use slid the deadline | Old and new each 24/24 on Windows under 16 CPU hogs (the flake had been seen in WSL2 under the full suite); the fix follows from the analysis |
| `sentinel-worker` `a_quick_helper_is_not_held_by_a_poll_interval` | Paired timings of a 2 ms child measured process-spawn noise (±2.9 s under load) | Event-based: a FIFO-held helper is waited for while it lives and released far from its deadline. sentinel-git proves a pidfd park returns only at the child's exit, and the helper's watch is asserted pidfd-backed. | 30/30 each (`process` test and `a_childs_exit_wakes_a_parked_wait`) in WSL2 with 8 CPU hogs |

## Final verification

One pass on the merged tree at `260f74f` (incremental build, per the owner's instruction), plus only the gated suites whose code changed. An earlier `test-cli` run of the merged tree found three failures: the GitHub CLI end-to-end test (fixed in `f523501`) and the two Credential Manager tests (fixed in `260f74f`).

| Where | Command | Exit | Passed / failed / ignored |
|---|---|---|---|
| Windows | `cargo fmt-check` | 0 | — |
| Windows | `cargo lint` | 0 | no warnings |
| Windows | `cargo test-cli --no-fail-fast` | 0 | 146 binaries: 1039 / 0 / 4 (the two `fleet_load` tests, `prefetch_placement_latency`, `concurrent_append_throughput`: opt-in measurements) |
| WSL2 | `cargo lint-linux` | 0 | no warnings (on `260f74f`) |
| WSL2 | `cargo test-linux --no-fail-fast` | 0 | 146 binaries: 1243 / 0 / 18 (live Tailcat helpers and opt-in measurements) |
| WSL2, `sentinelbench`, `SENTINEL_PODMAN_TESTS=1` | `secret_isolation` | 0 | 1 / 0 / 0 (26.5 s) |
| WSL2, `sentinelbench`, `SENTINEL_PODMAN_TESTS=1` | `oauth_e2e a_delegated_cli_writer_can_provision_a_secret_for_a_job_without_disclosure` (S07, container half ran) | 0 | 1 / 0 / 0 |

Per-merge checks: after each merge, `cargo check --workspace --all-targets --locked` and `cargo lint` on Windows and `cargo lint-linux` in WSL2 all exited 0.

**Not run, by the owner's instruction for this integration:** `cargo release-cli`, `cargo release-linux`, a separate `test-server` (`test-linux` is a superset), the other Podman-gated suites, `posix_crash_states`, `power_cut_on_dm_flakey`, the live Tailcat suite and `fleet_load`. None of their code changed here, apart from the delivery cluster's Podman call-site changes, which that cluster verified under Podman. No `cargo clean` preceded the pass. No performance measurement is claimed.

## Still open

- **X07**: no real MCP client (SDK, Claude Code, VS Code) has been run against a controller. The task is `[ ]` with `Blocked by:` in [TODO](../TODO.md); this was deferred by the owner's decision.
- **GitHub sign-in hand-offs** live in the controller's memory for 60 seconds; a restart between callback and finish asks the person to start again.
- **Test runtime directories**: `test-linux` workers leave empty `$XDG_RUNTIME_DIR/sentinel-*` directories (tmpfs, cleared at boot), as the delivery report notes. They were removed after this run.
