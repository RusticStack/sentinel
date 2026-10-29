# Worker enrollment

The operator's view of adding a machine to the fleet and taking it out again (Q11). This page is the short path and the checklist; the mechanisms are in [worker bootstrap](worker-bootstrap.md) (the script, `sentinel worker enroll`, the install layout), [worker link](worker-link.md) (what the controller stores and enforces) and [API](api.md) (the routes). The web page that drives the routes is not built yet (Part 20), so today the administrator uses the API or the host-local `sentinel admin worker` commands.

## Who decides what

| The controller decides | The worker host decides |
|---|---|
| the pool, the transport (`tailcat` or `direct`), the CPU, memory and storage ceilings, the priority | its TLS identity, worker identifier and (Tailcat) node key, all generated locally; private keys never leave it |
| whether the secret is valid, unspent and unexpired | whether it can run a worker at all (refused before the secret is spent) |
| whether the identity is already taken | its own labels, `job_network` and isolation settings |

A worker can state what it has; it can never raise what the controller approved. Priority only orders hosts that already pass hard admission (ownership, architecture, OS, isolation, capacity); it cannot widen the set ([worker link](worker-link.md#host-policy-is-the-controllers-q12)).

## Add a machine

1. Issue the enrollment: `POST /api/v1/admin/worker-enrollments` (platform administrator, fresh step-up), or on the controller host `sentinel admin worker enroll --pool NAME --transport tailcat|direct [--cpu-millis N] [--memory-bytes N] [--disk-bytes N] [--priority N]`. The secret is shown once; the HTTP response also carries the Tailcat address once. Audited as `worker-enrollment-issued`.
2. Download the script (`GET /api/v1/admin/worker-enrollments/{id}/bootstrap.sh`, audited as `worker-bootstrap-downloaded`) and run it as root on the worker host, passing the secret by file or standard input, never as an argument.
3. With `api_url` set on the controller the script runs `sentinel worker enroll` as the service account: it checks the host, generates the identities, redeems the secret over HTTPS in one transaction and writes `worker.toml`. Without `api_url` the older first-hello flow applies and a Tailcat key is authorized by an administrator ([worker bootstrap](worker-bootstrap.md#not-built-yet)).
4. Confirm: `GET /api/v1/admin/workers?pool=` lists the machine with its `approved`, `reported` and `effective` ceilings and whether it is `connected`.

A refusal is visible and leaves nothing behind: an unsupported host or configuration is refused before the secret is spent; a controller that refuses the secret (one uniform `403` for unknown, spent, expired, withdrawn or wrong-pool secrets) or answers about another worker leaves no identity, key or configuration on the host. A `409` (identity, fingerprint or node key already belongs to another worker) leaves the enrollment unspent. A failure after the controller accepted names the worker identifier so an administrator can uninstall it there.

## Change a machine

`PUT /api/v1/admin/workers/{wrk}/policy` (or `sentinel admin worker policy --id wrk_...`) replaces the approved ceilings and priority. A reduction stops new oversubscription at once and shows an over-cap state until accepted work fits; a raise is used by the next placement pass and never exceeds what the worker reports. Running attempts are untouched. The policy survives a controller restart. Audited as `worker-policy-changed`. `GET /api/v1/admin/placement` shows the order the next placement round uses and the factor that decides each position.

## Remove a machine

Both sides are needed, in this order:

1. On the controller, request the uninstall (`POST /api/v1/admin/workers/{wrk}/uninstall`, or `sentinel admin worker uninstall --id wrk_...`). The worker drains at once and is revoked when its accepted attempts have settled; its session ends, its fingerprint and node key stop being admitted, and a later dial is refused as `Revoked`. Audited as `worker-uninstall-requested` and `worker-uninstalled`.
2. On the host, run `sh sentinel-worker-bootstrap.sh uninstall [--keep-data]` (which calls `sentinel worker uninstall`). Its final line names the worker and the controller-side step if the controller was not told first.

A host that was uninstalled can enroll again with a new enrollment. What the controller does when a copied data directory dials while the original is connected is a Q13 scenario (`duplicate-identity`) that no real-fleet run has confirmed yet; this page makes no claim about it.

## Verification

| Claim | Evidence |
|---|---|
| `sentinel worker enroll` keeps the secret out of arguments, output and files, refuses before any request on bad input and rolls back on refusal | `crates/sentinel/tests/worker_enroll.rs` (stand-in controller, real binary) |
| `sentinel worker uninstall` removes exactly what the install created and names the controller step | unit tests in `crates/sentinel/src/worker_install.rs`; container tests in `crates/sentinel-api/tests/worker_bootstrap_script.rs` (`#[ignore]`d, run on a verification host) |
| Routes, single use, expiry, replay, audit, ceilings and priority | `crates/sentinel-api/tests/worker_enrollment.rs`, `crates/sentinel-store/tests/redeem_presented.rs`, `crates/sentinel/tests/host_admin.rs` |
| The fleet path end to end (enroll, uninstall, Tailcat reconnect and revocation, duplicate identity, ceilings, ARM placement, OS and isolation explanations, priority) | `bench/q13-fleet.py run` against a real fleet. `bench/q13-fleet.py selftest` only proves the harness distinguishes a correct model from ten injected defects; its records are marked `simulated` and are not Q13 evidence. No real-fleet record is committed yet (needs the three verification hosts and a Tailcat-enabled controller; TODO.md Q13) |
