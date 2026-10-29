# Worker bootstrap

How a platform administrator adds a machine to the fleet without writing a configuration file by hand (Q11). The controller issues a short-lived, single-use, pool-bound enrollment and serves a **worker-only shell script**; the script installs the pinned worker (and, by default, the pinned Tailcat helper), creates the local service account and identity, enrolls through the secret it is handed, installs the service, and can roll back or uninstall. Only the main deployment runs the controller, the API and the web interface; every other machine is a worker.

The routes are in the [API](api.md), the store rules behind them in [worker link](worker-link.md#approved-policy-the-bound-node-key-and-uninstall-q11-store-layer). The web page that drives them belongs to the web interface ([web interface](web-ui.md)).

## The flow

1. The administrator (a browser session that has stepped up) calls `POST /api/v1/admin/worker-enrollments` with the pool, the host ceilings and the priority the controller approves for that machine, and the transport (`tailcat`, the default, or `direct`).
2. The response carries the enrollment `id`, its expiry, **the secret and, for Tailcat, the controller's Tailcat address, once**, and `bootstrap_path`.
3. The administrator downloads `GET /api/v1/admin/worker-enrollments/{id}/bootstrap.sh` (an attachment; each download is audited) and runs it on the worker host as root, handing it the secret on a path that never touches a command line:

   ```sh
   # the secret file: root-owned, mode 0600; line 1 the secret, line 2 (Tailcat only) the controller's address
   sudo sh sentinel-worker-bootstrap.sh install --name build-1 --secret-file /root/enrollment
   # or, without a file
   printf '%s\n%s\n' "$SECRET" "$ADDRESS" | sudo sh sentinel-worker-bootstrap.sh install --secret-stdin
   ```

   Run from a terminal with `--secret-stdin` and no pipe, the script prompts for each line with the input hidden.
4. **With `api_url` configured (the default flow)**, the script installs the verified binary and then runs `sentinel worker enroll` as the service account ([below](#enrolling-over-https-sentinel-worker-enroll)). That command generates the machine's TLS identity, worker id and (Tailcat) node key, redeems the enrollment at the controller over HTTPS in one step, and writes `worker.toml` from the controller's answer, so a Tailcat machine enrolls before it can reach the link. The service then starts with everything it needs; no enrollment file exists and the administrator authorizes nothing by hand.

   **Without `api_url`**, the older flow applies: the worker starts, presents the secret once with its first hello, and the controller binds the machine to the enrollment's pool and policy; the worker deletes its enrollment file when it has enrolled, and a Tailcat key is authorized by an administrator (see [not built yet](#not-built-yet)).

Outstanding and spent enrollments are read back, without any secret, with `GET /api/v1/admin/worker-enrollments?pool=` (and one by `{id}`); the machines they produced, with their approved, reported and effective ceilings, are `GET /api/v1/admin/workers?pool=`. An unspent enrollment is withdrawn with `DELETE /api/v1/admin/worker-enrollments/{id}` and an enrolled machine is removed with `POST /api/v1/admin/workers/{id}/uninstall`.

An enrollment that is spent, withdrawn (`DELETE`) or expired gets no further script (`409`).

## Enrolling over HTTPS (`sentinel worker enroll`)

Enabled by `api_url` in the controller's `[worker_bootstrap]` section (see [controller configuration](#controller-configuration)). Without it the endpoint answers `404` and the script keeps the older link flow.

**The endpoint.** `POST /api/v1/worker-enrollments/redeem` (JSON, no session: the secret is the credential) takes `{secret, worker, name, fingerprint, arch, node_key?}` and answers `200 {worker, pool, transport, host, controller, controller_fingerprint, tailcat_address}`, `cache-control: no-store`. One store transaction (`workers::redeem_presented`) spends the secret and binds the worker's TLS fingerprint and, for a Tailcat enrollment, its node key to the enrollment's pool; the answer is the trust data a worker needs to dial: the link address, the controller's pinned fingerprint, the approved ceilings and priority, and the controller's Tailcat address. The secret travels only in the body of an HTTPS request, never in a URL, a header or a log. The route is bounded: a 2 KiB body, `application/json` only, browser-origin requests refused, a budget per client address (5 in a burst, one per 12 s) and an overall one (20 in a burst, one per 3 s), and a Tailcat enrollment is answered `429` (not spent) until the controller's Tailcat address exists. Every way a secret can fail (unknown, spent, expired, withdrawn, wrong pool or transport, a deactivated pool, another worker for an authorized key) is the same `403`, and the refusals that reach the store write at most 20 audit rows an hour (`WorkerEnrollmentRefused`), so guessing cannot grow the append-only audit. An identity or node key that already belongs to another worker is `409` and leaves the enrollment unspent for the real machine. After a redemption the controller wakes its Tailcat allow-list pass at once, so the key is admitted without waiting for the 10 s tick; the operator's `tailcat-allow` file stays an atomically written list, and bound and authorized keys come from the store.

**Lost answers.** If the response is lost, the same worker id, fingerprint and node key may present the same secret again for 10 minutes and gets the same answer without changing anything; any other presentation of a spent secret is refused. `sentinel worker enroll` retries a failed or `5xx`/`429` call up to three times for this reason.

**The command.** The script runs, as the service account (never as root):

```sh
printf '%s\n' "$SECRET" | sentinel worker enroll --api-url URL --data-dir DIR --config FILE --name NAME --secret-stdin \
    [--tailcat-binary FILE --tailcat-sha256 HEX [--tailcat-port N] [--derpmap-url URL] [--region NAME]]
```

- **Secret in, nowhere else.** `--secret-stdin` (a pipe, never a terminal) or `--secret-file` (a regular, owner-only file); the first line must be an `sntl_` secret. There is no flag that takes the secret as a value, and a misspelled attempt is refused without echoing its arguments. The secret exists in memory only until the request is built and is wiped; it is not written to the configuration, logs, standard output or any file. The URL must be `https://` (or `http://` for a loopback host) with no user information, query or fragment.
- **Refuse first.** Before anything is created or spent it refuses a host that already holds an identity or configuration for this data directory, and it runs the worker's own `--check` (`service::check_worker`) against a provisional configuration, so a host the worker cannot run on (for example an isolation setting the host cannot provide) is refused with the reason while the enrollment is still unspent. Podman, cgroup and user-namespace requirements stay in the script's host checks and the executor.
- **Identities.** It generates the TLS identity (`worker.crt`, `worker.key`, mode 0600), a worker id (`worker.id`) and, for Tailcat, the node key through the pinned helper; the private keys never leave the host.
- **Configuration.** `worker.toml` is written atomically from the controller's answer: the link address (`127.0.0.1:<port>` over Tailcat), the pinned fingerprint, the worker name, the Tailcat address and `[tailcat]` section. The approved ceilings and priority are recorded as comments for the operator, not as settings, because the controller enforces them and a raise there must need no edit here. The script installs the staged file `root:sentinel-worker` mode 0640 and removes the staged copy.
- **Rollback.** A journal removes everything the run created (identity files, the Tailcat directory, the configuration, a data directory it made) if any step fails. If the failure comes after the controller accepted the redemption (a malformed answer, a configuration that does not check out), the message names the worker id: the controller already holds that binding, so a platform administrator removes it with `POST /api/v1/admin/workers/{id}/uninstall` and issues a new enrollment. The script's own failure handling removes whatever the install had created.

## What the script holds, and what it never does

The script is the same for every enrollment of one transport. It carries the controller's dial address and public link fingerprint, the release version, and the SHA-256 and URL of each artifact per architecture. It holds **no credential**: not the enrollment secret, not the Tailcat address (both are listed in the [Tailcat credentials rule](configuration.md#optional-tailcat-transport)), not a token.

- **Nothing remote reaches a shell.** Every download goes to a root-owned, mode 0700 staging directory under `/var/tmp`, is checked against the pinned digest, and is installed only then; a mismatch removes the file and stops (`does not match the digest pinned by the controller`), leaving the host untouched. Archives are unpacked by extracting one named member, `bin/sentinel`; the script never executes anything it has not verified.
- **No credential in a URL, a process argument or a log.** URLs are plain release locations (`https://`, or `http://` for a loopback host only; the controller refuses a configured URL with user information, a query or a fragment). The secret is read from a file or standard input into a shell variable and never passed to an external command's arguments; with `api_url` it reaches `sentinel worker enroll` on a pipe into that command's standard input and is written nowhere, otherwise it is written once to the worker's own mode 0600 file. The script's messages never print it.
- **No persistent script text.** With `api_url` the secret exists on disk nowhere and the Tailcat address only inside `worker.toml` (0640, `root:sentinel-worker`), which the worker needs to reach the controller. Without it the secret is also `<data_dir>/enrollment` (0600, owned by the service account, deleted by the worker once it has enrolled).
- **Visible refusals.** A host the script cannot support is refused with exit status 2 and a reason, before anything changes (see below).

## Host checks

`install` and `check` verify, in this order, and refuse with exit status 2 and the reason:

| Check | Refused when |
|---|---|
| Operating system | not Linux |
| Architecture | not `x86_64` or `aarch64`, or the controller pins no worker release (or, for Tailcat, no helper) for it |
| Privilege | not root (`install`) |
| Init system | `/run/systemd/system` is missing: the worker is a systemd service |
| Tools | any of `systemctl`, `loginctl`, `tar`, `gzip`, `sha256sum`, `awk`, `sed`, `grep`, `head`, `install`, `mktemp`, `useradd`, `usermod`, `userdel`, `getent`, `runuser`, `stat`, `df`, `wc`, `tr` is missing, or neither `curl` nor `wget` |
| Containers | no `podman` 4 or newer, no `newuidmap`/`newgidmap`, user namespaces disabled, or cgroup v2 absent (rootless Podman on cgroup v2 is what the worker's executor requires) |
| Account and files | on a fresh install, an account `sentinel-worker` that this script did not create, or any of `/opt/sentinel-worker`, `/etc/sentinel-worker`, `/var/lib/sentinel-worker`, the unit file already existing without an install record (a data directory kept by `uninstall --keep-data` holds the identity of a worker that was revoked; remove it first) |

Other failures exit 1; a bad command line exits 64. Windows hosts have a separate task (N08); a host with only Firecracker and no Podman is not covered by this script.

## What it installs

| Path | Content |
|---|---|
| `/opt/sentinel-worker/releases/<version>-<sha12>/sentinel` | the verified worker binary, root-owned |
| `/opt/sentinel-worker/current`, `previous` | symlinks to the running release and the one before it |
| `/opt/sentinel-worker/tailcat/tailcat` | the verified helper (Tailcat only), root-owned, not writable by others: the worker's own helper check requires it |
| `/opt/sentinel-worker/install.state` | what this script created (`created_account`, `enabled_linger`, the release, the transport), so `uninstall` removes exactly that |
| `/etc/sentinel-worker/worker.toml` | the worker configuration: link address, pinned controller fingerprint, name, `[tailcat]` (and, without `api_url`, the enrollment file); with `api_url` it is written by `sentinel worker enroll` and the approved ceilings appear as comments |
| `/var/lib/sentinel-worker` | the worker's data directory, mode 0700, owned by the service account: its TLS identity, `worker.id`, caches |
| `/etc/systemd/system/sentinel-worker.service` | runs `<current>/sentinel worker` as `sentinel-worker` with `XDG_RUNTIME_DIR` of its lingering user manager |

The account `sentinel-worker` is a system account with its home at the data directory and `nologin`; the script gives it subordinate UID/GID ranges (the next free 65,536 above 100,000) and enables lingering, which rootless Podman needs. The TLS identity, worker identifier and Tailcat node key are generated on the host (by `sentinel worker enroll`, or by the worker on its first start without `api_url`); the script never sees a private key. The CPU, memory and storage ceilings and the priority chosen at enrollment are applied by the controller; they are not in `worker.toml`.

## Upgrade, rollback, uninstall

- **Upgrade**: run `install` again with a newer script (no secret needed). `worker.toml` is kept, so local settings you added (labels, `job_network = "egress"`, a microVM section) survive; the unit is rewritten. The new release is verified, its configuration is checked with `sentinel worker --check` as the service account, then `current` moves and the service restarts. If the service does not stay up for 30 s the script moves `current` back, restarts the old release and exits 1. The previous release is kept for `rollback`; older ones are removed.
- **`rollback`** swaps `current` and `previous` and restarts, undoing itself if the other release does not stay up either. It runs `sentinel worker rollback` from the installed release when that command exists (exit 1 is final) and otherwise does the same in shell.
- **`uninstall`** runs `sentinel worker uninstall [--keep-data]` from the installed release when it can (the same removal in Rust, with a `Host` seam that the tests drive, and idempotent), and falls back to shell for releases that predate it. It stops and removes the service, `/opt/sentinel-worker`, `/etc/sentinel-worker`, lingering, the account if the script created it, and the data directory (`--keep-data` keeps it). It does not tell the controller. To avoid cutting accepted work, request the worker's uninstall on the controller first: it drains the worker and revokes it, with its fingerprint and node key, once its attempts have settled ([worker link](worker-link.md#approved-policy-the-bound-node-key-and-uninstall-q11-store-layer)).
- A failed fresh `install` removes whatever it had created; a failed upgrade restores the previous release.
- `identity` prints the worker id and, for Tailcat, the line `nodekey:<64 hex> wrk_<id>` that `sentinel admin tailcat authorize` (or, for a hand-listed worker, `allow`) takes on the controller.

## Controller configuration

The controller serves enrollments only when its configuration has a `[worker_bootstrap]` section (server role only):

```toml
[worker_bootstrap]
controller = "203.0.113.5:7443"                       # IP:port workers dial for a direct TLS enrollment
release_url = "https://releases.example.com/sentinel/0.1.0"   # directory holding the release archives
release_sums = "/etc/sentinel/SHA256SUMS"             # the release's SHA256SUMS
api_url = "https://sentinel.example.com"             # optional: where workers redeem enrollments over HTTPS

# Only for Tailcat enrollments; needs the controller's own [tailcat] enabled = true.
[worker_bootstrap.tailcat]
x86_64_url = "https://releases.example.com/tailcat/tailcat-0.6.0-linux-amd64"   # sha256 defaults to the pinned build
aarch64_url = "https://releases.example.com/tailcat/tailcat-0.6.0-linux-arm64"
aarch64_sha256 = "…64 hex…"                           # this build pins no arm64 helper digest
```

`api_url` is the HTTPS base URL workers reach the controller's API at (`https://`, or `http://` for a loopback host; no user information, query or fragment). Setting it turns on the redeem endpoint and the script's `sentinel worker enroll` flow; it is a versioned setting of the generated script (see [compatibility](compatibility.md)). `release_sums` is the `SHA256SUMS` that `scripts/release/package.sh` writes beside the release archives (V01): the controller reads the `sentinel-<version>-<arch>-linux-worker.tar.gz` lines, requires one version, and pins each archive by its listed digest; the archives themselves are served from `release_url`, not by the controller. The helper is the bare executable whose digest `[tailcat] sha256` pins (the controller's own pin is the x86_64 default). The `controller` address is an IP address and port because the worker's `controller` setting is one; the controller's own link fingerprint is added automatically. The Tailcat address comes from `<data_dir>/tailcat/address` and the DERP map and region from the controller's `[tailcat]` section, so a Tailcat enrollment waits (`409`) until the controller is serving.

## Not built yet

- **Delivering the node key without the administrator, for controllers without `api_url`.** With `api_url` this is solved: the worker presents its node key together with the secret over HTTPS and the same transaction binds it. Without it, the controller side is built: the key is authorized through the enrollment with `sh sentinel-worker-bootstrap.sh identity | sentinel admin tailcat authorize --enrollment tok_… --data-dir <controller data dir>`, admitted to the Tailcat helper while the enrollment can still be redeemed, bound at redemption, and withdrawn with the enrollment or the worker ([worker link](worker-link.md#the-node-key-authorized-through-the-enrollment-q11)). What is missing is the automatic hand-over: before its tunnel exists the worker has no channel to the controller but the API, so a one-click flow needs the script (or the web page) to post the `identity` line to an authenticated route that calls the same `workers::authorize_node_key`. Without `api_url` the administrator runs the command above (`identity` waits for the worker's first start). Direct TLS enrollments need no such step.
- **The web page** that calls the routes and shows the secret once (Part 20).
- **The worker unit** of the V02 deployment examples; the unit this script writes is the minimal one and should converge with it.
- **A published V01 manifest beyond `SHA256SUMS`**, such as signatures or a Tailcat entry in the release set; the controller pins what its operator configures.

## Verification

`crates/sentinel-api/tests/worker_enrollment.rs` covers the routes (step-up, single-use secret, rate limits, audit, the script's content) and the redeem endpoint (single use, expiry, wrong pool and transport, replay, a taken identity, the Tailcat address gate, the closed endpoint without `api_url`, the size and origin limits). `crates/sentinel-store/tests/redeem_presented.rs` covers the transaction (single use, expiry, deactivated pool, replay window, authorized pairs, a rolled-back transaction that survives a restart, the bounded refusal audit). `crates/sentinel/tests/worker_enroll.rs` runs the real `sentinel worker enroll` against a stand-in controller and checks that the secret appears only in the request body (never in the request line, output or any file), that a refused or untrusted answer leaves no identity, key or configuration, and that bad input is refused before any request. `crates/sentinel-api/tests/worker_bootstrap_script.rs` lints the template and both rendered scripts with shellcheck and runs the script in containers against a fake download server: install, upgrade, automatic rollback, tampered download, uninstall, stdin input, the HTTPS enrollment flow (the secret only on the worker's standard input, the staged configuration installed `root:sentinel-worker` 0640, a refused enrollment leaving no account, directory or unit) and every refusal. The container tests are `#[ignore]`d and run on a verification host with `cargo test -p sentinel-api --test worker_bootstrap_script -- --ignored` (Podman, `tar` and the base images `almalinux:9`, `debian:12-slim` and `koalaman/shellcheck:v0.10.0` already pulled; override with `SENTINEL_BOOTSTRAP_IMAGE`, `SENTINEL_NO_DOWNLOADER_IMAGE`, `SENTINEL_SHELLCHECK_IMAGE`). They stub `systemctl`, `loginctl`, `podman` and `sentinel` itself, so they prove the script's own behavior, not a real systemd, Podman or worker.
