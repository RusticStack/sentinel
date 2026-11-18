# Worker enrollment

The operator's view of adding a machine to the fleet and taking it out again (Q11). This page is the short path and the checklist; the mechanisms are in [worker bootstrap](worker-bootstrap.md) (the script, `sentinel worker enroll`, the install layout), [worker link](worker-link.md) (what the controller stores and enforces) and [API](api.md) (the routes). The web page that drives the routes is `/platform/workers` ([web interface](web-ui.md#worker-enrollment)); the same steps are available through the API and the host-local `sentinel admin worker` commands.

## Who decides what

| The controller decides | The worker host decides |
|---|---|
| the pool, the transport (`tailcat` or `direct`), the CPU, memory and storage ceilings, the priority | its TLS identity, worker identifier and (Tailcat) node key, all generated locally; private keys never leave it |
| whether the secret is valid, unspent and unexpired | whether it can run a worker at all (refused before the secret is spent) |
| whether the identity is already taken | its own labels, `job_network` and isolation settings |

A worker can state what it has; it can never raise what the controller approved. Priority only orders hosts that already pass hard admission (ownership, architecture, OS, isolation, capacity); it cannot widen the set ([worker link](worker-link.md#host-policy-is-the-controllers)).

## Add a machine

1. Issue the enrollment: on the web page (Platform, Workers: pick the pool, the transport, the ceilings and priority; confirm with a second factor; save the file the one-time dialog offers as `enrollment`), with `POST /api/v1/admin/worker-enrollments` (platform administrator, fresh step-up), or on the controller host `sentinel admin worker enroll --pool NAME --transport tailcat|direct [--cpu-millis N] [--memory-bytes N] [--disk-bytes N] [--priority N]`. The secret is shown once; the HTTP response also carries the Tailcat address once. Audited as `worker-enrollment-issued`.
2. Download the script (the page's "Download script", or `GET /api/v1/admin/worker-enrollments/{id}/bootstrap.sh`, audited as `worker-bootstrap-downloaded`) and run it as root on the worker host, passing the secret by file or standard input, never as an argument. The page recomputes the script's SHA-256 and compares it with the controller's `bootstrap_sha256` before offering the file; without the page, `sha256sum` the file and compare it with `bootstrap_sha256` of the issue answer or of `GET /api/v1/admin/worker-bootstrap`. If the secret file is lost, withdraw the enrollment (the page's Withdraw, or `DELETE /api/v1/admin/worker-enrollments/{id}`) and issue another: the controller keeps only the secret's digest.
3. With `api_url` set on the controller the script runs `sentinel worker enroll` as the service account: it checks the host, generates the identities, redeems the secret over HTTPS in one transaction and writes `worker.toml`. Without `api_url` the older first-hello flow applies and a Tailcat key is authorized by an administrator, on the page (paste the line `sh sentinel-worker-bootstrap.sh identity` prints) or on the host ([worker bootstrap](worker-bootstrap.md#authorizing-a-node-key-without-api_url)).
4. Confirm: `GET /api/v1/admin/workers?pool=` lists the machine with its `approved`, `reported` and `effective` ceilings and whether it is `connected`.

A refusal is visible and leaves nothing behind: an unsupported host or configuration is refused before the secret is spent; a controller that refuses the secret (one uniform `403` for unknown, spent, expired, withdrawn or wrong-pool secrets) or answers about another worker leaves no identity, key or configuration on the host. A `409` (identity, fingerprint or node key already belongs to another worker) leaves the enrollment unspent. A failure after the controller accepted names the worker identifier so an administrator can uninstall it there.

## Change a machine

Three surfaces change a machine's approved ceilings and priority, and all of them end in the same store call (`workers::set_policy`, platform authority only):

- **The web page.** In the Workers table, "Edit policy" opens a panel for that machine with what it reported, what the controller offers now and what its accepted work holds, then the CPU, memory and disk ceilings and the priority. Saving asks for a second factor and sends the whole policy; an empty ceiling removes it, and a field left as shown keeps the approved value exactly. A controller refusal (a ceiling that is not positive, a priority outside −100…100, a worker that is gone) is shown in the panel in words. A machine over its cap carries an "over cap" badge in the table.
- **The API.** `PUT /api/v1/admin/workers/{wrk}/policy` replaces the whole policy (an absent or `null` ceiling removes it, an absent priority is 0) and answers with the worker's host view; `GET` on the same path reads it ([API](api.md#routes)).
- **The controller host.** `sentinel admin worker policy --data-dir DIR --id wrk_... [--cpu-millis N|none] [--memory-bytes N|none] [--disk-bytes N|none] [--priority N]` ([CLI](cli.md#host-local-worker-policy)). Unlike the API it changes only the flags given, and `none` is how a ceiling is cleared; with no flag it prints the view.

A reduction stops new oversubscription at once and shows an over-cap state (`over_cap` in the view, the badge and panel on the web, an `over-cap` line on the CLI) until accepted work fits; a raise or a removal is used by the next placement pass and never exceeds what the worker reports. Running attempts are untouched. The policy survives a controller restart. Audited as `worker-policy-changed`. Only the API and the web page wake the placement loop at once; the CLI writes the store and the loop reads it on its next pass.

`GET /api/v1/admin/placement` shows the order the next placement round uses and the factor that decides each position: the answer comes from the same sort key the round itself sorts by, for the free connected workers, at most 500 of them (`total` and `truncated` say when it is cut). It orders hosts only; whether a host may take a given job is hard admission, explained per job by the queue.

## Remove a machine

Both sides are needed, in this order:

1. On the controller, request the uninstall (the page's Request uninstall in the Workers table, `POST /api/v1/admin/workers/{wrk}/uninstall`, or `sentinel admin worker uninstall --id wrk_...`). The worker drains at once and is revoked when its accepted attempts have settled; its session ends, its fingerprint and node key stop being admitted, and a later dial is refused as `Revoked`. Audited as `worker-uninstall-requested` and `worker-uninstalled`.
2. On the host, run `sh sentinel-worker-bootstrap.sh uninstall [--keep-data]` (which calls `sentinel worker uninstall`). Its final line names the worker and the controller-side step if the controller was not told first.

To undo an upgrade on the host, `sh sentinel-worker-bootstrap.sh rollback` swaps back to the previous release; the page lists both commands under "Roll back or remove a machine". A host that was uninstalled can enroll again with a new enrollment. What the controller does when a copied data directory dials while the original is connected is a Q13 scenario (`duplicate-identity`) that no real-fleet run has confirmed yet; this page makes no claim about it.

## Verification

| Claim | Evidence |
|---|---|
| `sentinel worker enroll` keeps the secret out of arguments, output and files, refuses before any request on bad input and rolls back on refusal | `crates/sentinel/tests/worker_enroll.rs` (stand-in controller, real binary) |
| `sentinel worker uninstall` removes exactly what the install created and names the controller step | unit tests in `crates/sentinel/src/worker_install.rs`; container tests in `crates/sentinel-api/tests/worker_bootstrap_script.rs` (`#[ignore]`d, run on a verification host) |
| Routes, single use, expiry, replay, audit, ceilings and priority | `crates/sentinel-api/tests/worker_enrollment.rs`, `crates/sentinel-store/tests/redeem_presented.rs`, `crates/sentinel/tests/host_admin.rs` |
| Policy changes: members and tenant administrators refused, a platform administrator allowed, a reduction under running work answers with the over-cap state, a raise stays under the worker's report, an unknown or revoked worker is `not_found` | `crates/sentinel-api/tests/worker_enrollment.rs` (`a_member_and_a_tenant_administrator_are_refused_the_policy_routes_and_a_platform_administrator_is_not`, `a_reduction_under_running_work_shows_the_over_cap_state_and_a_raise_never_passes_the_report`, `an_unknown_or_revoked_worker_is_not_found_and_a_malformed_identifier_is_invalid`); on the host, `crates/sentinel/tests/host_admin.rs` (`a_reduction_under_running_work_prints_the_over_cap_state_and_a_raise_stays_under_the_report`) |
| The placement answer's order, deciding factors and bound; the order itself against live sessions | unit tests in `crates/sentinel-api/src/routes/worker_enrollment.rs`; `crates/sentinel-link/src/controller.rs` (ranking) and `crates/sentinel-link/tests/fleet.rs` (priority against speed, an over-cap host placed nothing) |
| The web editor sends exactly the numbers entered and refuses bad ones before any request | `web/test/enrollment.test.mjs` (the browser scenario of `web/test/ui.mjs` does not cover the editor yet; it runs against a real controller on a verification host) |
| The fleet path end to end (enroll, uninstall, Tailcat reconnect and revocation, duplicate identity, ceilings, ARM placement, OS and isolation explanations, priority) | `bench/q13-fleet.py run` against a real fleet. `bench/q13-fleet.py selftest` only proves the harness distinguishes a correct model from ten injected defects; its records are marked `simulated` and are not Q13 evidence. No real-fleet record is committed yet (needs the three verification hosts and a Tailcat-enabled controller; TODO.md Q13) |
