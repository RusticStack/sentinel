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
4. The worker starts, presents the secret once with its first hello, and the controller binds the machine to the enrollment's pool and policy. The worker deletes its enrollment file when it has enrolled.

An enrollment that is spent, withdrawn (`DELETE`) or expired gets no further script (`409`).

## What the script holds, and what it never does

The script is the same for every enrollment of one transport. It carries the controller's dial address and public link fingerprint, the release version, and the SHA-256 and URL of each artifact per architecture. It holds **no credential**: not the enrollment secret, not the Tailcat address (both are listed in the [Tailcat credentials rule](configuration.md#optional-tailcat-transport)), not a token.

- **Nothing remote reaches a shell.** Every download goes to a root-owned, mode 0700 staging directory under `/var/tmp`, is checked against the pinned digest, and is installed only then; a mismatch removes the file and stops (`does not match the digest pinned by the controller`), leaving the host untouched. Archives are unpacked by extracting one named member, `bin/sentinel`; the script never executes anything it has not verified.
- **No credential in a URL, a process argument or a log.** URLs are plain release locations (`https://`, or `http://` for a loopback host only; the controller refuses a configured URL with user information, a query or a fragment). The secret is read from a file or standard input into a shell variable, written once to the worker's own mode 0600 file, and never passed to an external command's arguments. The script's messages never print it.
- **No persistent script text.** The secret and the address exist on disk only as `<data_dir>/enrollment` (0600, owned by the service account, deleted by the worker once it has enrolled) and the address inside `worker.toml` (0640, `root:sentinel-worker`), which the worker needs to reach the controller.
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
| `/etc/sentinel-worker/worker.toml` | the worker configuration: link address, pinned controller fingerprint, name, enrollment file, `[tailcat]` |
| `/var/lib/sentinel-worker` | the worker's data directory, mode 0700, owned by the service account: its TLS identity, `worker.id`, caches |
| `/etc/systemd/system/sentinel-worker.service` | runs `<current>/sentinel worker` as `sentinel-worker` with `XDG_RUNTIME_DIR` of its lingering user manager |

The account `sentinel-worker` is a system account with its home at the data directory and `nologin`; the script gives it subordinate UID/GID ranges (the next free 65,536 above 100,000) and enables lingering, which rootless Podman needs. The worker generates its own TLS identity, worker identifier and Tailcat node key on first start; the script never sees a private key. The CPU, memory and storage ceilings and the priority chosen at enrollment are applied by the controller; they are not in `worker.toml`.

## Upgrade, rollback, uninstall

- **Upgrade**: run `install` again with a newer script (no secret needed). `worker.toml` is kept, so local settings you added (labels, `job_network = "egress"`, a microVM section) survive; the unit is rewritten. The new release is verified, its configuration is checked with `sentinel worker --check` as the service account, then `current` moves and the service restarts. If the service does not stay up for 30 s the script moves `current` back, restarts the old release and exits 1. The previous release is kept for `rollback`; older ones are removed.
- **`rollback`** swaps `current` and `previous` and restarts, undoing itself if the other release does not stay up either.
- **`uninstall`** stops and removes the service, `/opt/sentinel-worker`, `/etc/sentinel-worker`, lingering, the account if the script created it, and the data directory (`--keep-data` keeps it). It does not tell the controller. To avoid cutting accepted work, request the worker's uninstall on the controller first: it drains the worker and revokes it, with its fingerprint and node key, once its attempts have settled ([worker link](worker-link.md#approved-policy-the-bound-node-key-and-uninstall-q11-store-layer)).
- A failed fresh `install` removes whatever it had created; a failed upgrade restores the previous release.
- `identity` prints the worker id and, for Tailcat, the line `nodekey:<64 hex> wrk_<id>` that the controller's `tailcat-allow` list takes.

## Controller configuration

The controller serves enrollments only when its configuration has a `[worker_bootstrap]` section (server role only):

```toml
[worker_bootstrap]
controller = "203.0.113.5:7443"                       # IP:port workers dial for a direct TLS enrollment
release_url = "https://releases.example.com/sentinel/0.1.0"   # directory holding the release archives
release_sums = "/etc/sentinel/SHA256SUMS"             # the release's SHA256SUMS

# Only for Tailcat enrollments; needs the controller's own [tailcat] enabled = true.
[worker_bootstrap.tailcat]
x86_64_url = "https://releases.example.com/tailcat/tailcat-0.6.0-linux-amd64"   # sha256 defaults to the pinned build
aarch64_url = "https://releases.example.com/tailcat/tailcat-0.6.0-linux-arm64"
aarch64_sha256 = "…64 hex…"                           # this build pins no arm64 helper digest
```

`release_sums` is the `SHA256SUMS` that `scripts/release/package.sh` writes beside the release archives (V01): the controller reads the `sentinel-<version>-<arch>-linux-worker.tar.gz` lines, requires one version, and pins each archive by its listed digest; the archives themselves are served from `release_url`, not by the controller. The helper is the bare executable whose digest `[tailcat] sha256` pins (the controller's own pin is the x86_64 default). The `controller` address is an IP address and port because the worker's `controller` setting is one; the controller's own link fingerprint is added automatically. The Tailcat address comes from `<data_dir>/tailcat/address` and the DERP map and region from the controller's `[tailcat]` section, so a Tailcat enrollment waits (`409`) until the controller is serving.

## Not built yet

- **Controller-side Tailcat admission.** The worker's node key must reach the controller's allow list before its first connection, and the enrollment must bind it at redemption ([worker link](worker-link.md#approved-policy-the-bound-node-key-and-uninstall-q11-store-layer)). Until the controller feeds `workers::admitted_node_keys` to the allow list and presents the node key at redemption, the administrator lists the key by hand with `sh sentinel-worker-bootstrap.sh identity | sentinel admin tailcat allow --data-dir <controller data dir>`. Direct TLS enrollments need no such step.
- **The web page** that calls the routes and shows the secret once (Part 20).
- **The worker unit** of the V02 deployment examples; the unit this script writes is the minimal one and should converge with it.
- **A published V01 manifest beyond `SHA256SUMS`**, such as signatures or a Tailcat entry in the release set; the controller pins what its operator configures.

## Verification

`crates/sentinel-api/tests/worker_enrollment.rs` covers the routes (step-up, single-use secret, rate limits, audit, the script's content). `crates/sentinel-api/tests/worker_bootstrap_script.rs` lints the template and both rendered scripts with shellcheck and runs the script in containers against a fake download server: install, upgrade, automatic rollback, tampered download, uninstall, stdin input and every refusal. The container tests are `#[ignore]`d and run on a verification host with `cargo test -p sentinel-api --test worker_bootstrap_script -- --ignored` (Podman, `tar` and the base images `almalinux:9`, `debian:12-slim` and `koalaman/shellcheck:v0.10.0` already pulled; override with `SENTINEL_BOOTSTRAP_IMAGE`, `SENTINEL_NO_DOWNLOADER_IMAGE`, `SENTINEL_SHELLCHECK_IMAGE`). They stub `systemctl`, `loginctl`, `podman` and `sentinel` itself, so they prove the script's own behavior, not a real systemd, Podman or worker.
