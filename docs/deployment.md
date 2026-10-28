# Deployment

How a Sentinel release is built, packaged and verified, and how the controller and a worker run under systemd. The tasks are V01 (release packages) and V02 (the server and worker units); container examples and the TLS/ingress guide stay open under V02 in [TODO](../TODO.md). Configuration is in [configuration](configuration.md), upgrades in [upgrades](upgrades.md), the web process in [web interface](web-ui.md).

## Release packages

`scripts/release/package.sh build` builds and packages the architecture of the host it runs on, from the checkout it is in, with `cargo build --locked --release` (a dependency change must already be in the committed `Cargo.lock`). Run it once on an x86_64 and once on an arm64 Linux host. It refuses a working tree with uncommitted changes to tracked files; `--allow-dirty` marks the package `dirty: true` in its `BUILD-INFO` for development use.

| Package | Contents | Built as |
|---|---|---|
| `sentinel-<version>-<arch>-linux-server.tar.gz` | `bin/sentinel`, the server unit, the web unit, `server.toml` | `-p sentinel --features server` |
| `sentinel-<version>-<arch>-linux-worker.tar.gz` | `bin/sentinel`, the worker unit, `worker.toml` | `-p sentinel --features worker` |
| `sentinel-<version>-<arch>-linux-cli.tar.gz` | `bin/sentinel` (`pipeline`, `api`, `auth`, `mcp`; no role) | `-p sentinel`, default features |
| `sentinel-agent-<version>-<arch>-linux-musl.tar.gz` | `bin/sentinel-agent`, the static guest `/init` of microVM jobs | `-p sentinel-agent --target <arch>-unknown-linux-musl` |

`<arch>` is `x86_64` or `aarch64`; every archive has one top directory named like the archive, the `LICENSE` and a `BUILD-INFO` naming the package, version, commit, dirty flag, architecture and `rustc`. The role packages are separate binaries on purpose: a worker host carries no controller code and the reverse. `SHA256SUMS` lists every archive. The agent needs the musl standard library of the target (`rustup target add x86_64-unknown-linux-musl`, or the aarch64 one on arm64); `--skip-agent` leaves it out.

Archives are deterministic for a given binary (sorted entries, the commit's timestamp, numeric root ownership, `gzip -n`). The binaries are not claimed to be bit-for-bit reproducible across hosts or toolchain installs.

Not in the set yet (V01 stays open): the Windows CLI, a dependency and license inventory, and an `aarch64` Linux CLI built by cross-compilation (each architecture is built natively).

### Verifying a release

```sh
scripts/release/package.sh verify --out <dir>
```

or, without the repository, `sha256sum --check --strict SHA256SUMS` in the directory holding the archives. `verify` checks the sums, that every archive is listed and holds the files above, that each `bin/sentinel` runs (`--version`), and that the agent has no program interpreter (static). `build` runs it as its last step and fails when it does.

### Release profile

`[profile.release]` in the workspace `Cargo.toml` was chosen by measurement ([`scripts/release/measure-profile.sh`](../scripts/release/measure-profile.sh), records in [`bench/v01-release-profile.jsonl`](../bench/v01-release-profile.jsonl)), not guessed. The script builds the server-role binary under each candidate and times, interleaved across the candidates, the commands an operator waits on: `pipeline validate` and `pipeline explain --json` on a full pipeline, and the controller's start to a listening API on a fresh data directory.

Record of 2026-10-28 on the reference host (AMD EPYC 9645, 12 vCPUs, kernel 7.0), commit `3c8b8e5`, `CARGO_BUILD_JOBS=6` at `nice -n 19`; 60 interleaved rounds per command (reversed every round) and 15 start-ups per variant. CPU pressure was 8.4 % at the start and 4.0 % at the end of the timing window, so the timings are a comparison between variants in one window, not absolute figures; build times were taken while other verification jobs shared the host.

| Variant | Build | Binary | Stripped | `pipeline validate` median / p95 | Controller start to API, median / p95 |
|---|---|---|---|---|---|
| `lto = false`, 16 units (Cargo's default) | 148 s | 22.5 MB | 18.0 MB | 3.34 / 4.46 ms | 198 / 251 ms |
| `lto = "thin"`, 16 units | 144 s | 22.5 MB | 18.1 MB | 3.31 / 4.44 ms | 200 / 265 ms |
| `lto = "thin"`, 1 unit | 181 s | 18.9 MB | 16.5 MB | 3.30 / 4.78 ms | 191 / 240 ms |
| **`lto = "fat"`, 1 unit** | 292 s | 17.5 MB | 15.6 MB | 3.37 / 4.58 ms | 190 / 247 ms |

`pipeline explain --json` behaves like `validate` (3.27 to 3.37 ms medians). Process start dominates the two pipeline commands, so they cannot tell the variants apart; the controller start is the only command where the single-unit builds are ahead (about 4 % at the median, with overlapping p95s). The chosen profile is **`lto = "fat"`, `codegen-units = 1`**: it is the smallest binary (22 % under the default), no slower than the others beyond the noise of the pipeline columns, and its cost is a doubled release build time, paid once per release rather than per run. `strip = "debuginfo"` is kept: stripping symbols as well saves another 1.9 MB but leaves panics and crash reports without function names. What this does not show is a hot-path effect (dispatch, store, log ingestion): none of those has a standalone workload yet, so the profile is to be re-measured under the B-series benchmark contracts when they run on release builds.

`panic` stays `unwind` regardless of the numbers: the API acceptor, the worker's executor and the CPU/IO work lanes contain a panic with `catch_unwind` and keep serving, which `abort` would turn into a dead process. The agent is built with the same profile.

## The controller as a systemd service

[`examples/sentinel-server.service`](../examples/sentinel-server.service) runs `sentinel server` under a dedicated `sentinel` account. Install:

```sh
useradd --system --home-dir /var/lib/sentinel --shell /usr/sbin/nologin sentinel
tar -xzf sentinel-<version>-<arch>-linux-server.tar.gz
install -D -m 0755 sentinel-*/bin/sentinel /opt/sentinel/bin/sentinel
install -d -o root -g sentinel -m 0750 /etc/sentinel
install -o root -g sentinel -m 0640 sentinel-*/examples/server.toml /etc/sentinel/server.toml
install -m 0644 sentinel-*/examples/sentinel-server.service /etc/systemd/system/
install -d -o sentinel -g sentinel -m 0700 /var/lib/sentinel
systemctl daemon-reload
```

Edit `/etc/sentinel/server.toml` ([configuration](configuration.md)); then create the master key once, as the service account, before the first start, and start the unit:

```sh
runuser -u sentinel -- /opt/sentinel/bin/sentinel admin key create --data-dir /var/lib/sentinel
systemctl enable --now sentinel-server
```

`/var/lib/sentinel` is the unit's `StateDirectory=sentinel`: systemd keeps it owner-only, and it survives removing the unit. It is the controller's directory only: the worker runs under its own account and its own `/var/lib/sentinel-worker`, so a compromised worker host account never reaches the database or the master key. The unit:

- **Secrets.** The master key is `<data_dir>/master.key` because the controller reads it from that path only. The files the configuration names (GitHub App key, sign-in client secret, S3 and Resend credentials) must be owned by `sentinel` with mode `0600`; the controller refuses others. Under `ProtectSystem=strict` the service can read them but not rewrite them from `/etc`. The configuration file itself holds no credentials ([configuration](configuration.md)) and is root-owned, group-readable.
- **Restart.** `Restart=on-failure` after two seconds; exit status 2 (configuration error) is not retried, and more than five starts in five minutes stop the unit. `TimeoutStopSec=30s` covers the controller's own bounds (links 2 s, store drain 5 s).
- **Limits.** `MemoryMax=4G`, `TasksMax=4096`, `LimitNOFILE=65536`, `LimitCORE=0`. These are starting points for one host, not measured ceilings (an idle controller measures about 21 MiB, [`bench/r06-idle.jsonl`](../bench/r06-idle.jsonl)); change them with `systemctl edit`.
- **Sandbox.** No capabilities, `NoNewPrivileges`, `ProtectSystem=strict` with only the state directory writable, `ProtectHome`, private `/tmp` and `/dev`, kernel tunables, modules, logs, control groups, clock and hostname protected, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, namespaces and realtime restricted, `MemoryDenyWriteExecute`, and `@system-service` minus `@privileged @resources` system calls. `AF_NETLINK` is for the optional Tailcat helper; the helper under this sandbox has not been exercised. A `[backup] dir` or any other location outside the data directory needs `ReadWritePaths=` (the unit carries the line commented out).

The web unit, [`examples/sentinel-web.service`](../examples/sentinel-web.service), orders itself after this one.

### Checking the unit

```sh
scripts/release/check-server-unit.sh <path to a --features server binary>
```

as an unprivileged user with a user systemd instance (SQLite calls `fchown` when it runs as root, which the unit's system call filter forbids; the `sentinel` account never makes that call), it runs `systemd-analyze verify` on the unit, requires `systemd-analyze security --offline=true` to score the unit no worse than 1.5 overall, starts a copy in the calling user's systemd instance with every sandbox directive kept (only the account, the unit name, the paths, `ProtectHome=read-only` because a user instance keeps its state under the home directory, and the directives that work by dropping capabilities — the capability sets, `PrivateDevices`, `ProtectClock`, `ProtectKernelModules`, `ProtectKernelLogs` — which an unprivileged user instance cannot apply, differ; `systemd-analyze security` covers those on the shipped unit), and requires `GET /api/v1/health` to answer from a temporary data directory and a `SIGTERM` stop to be a clean exit. It writes only below `~/.local/state/sentinel-unit-check` and removes it.

## A worker as a systemd service

[`examples/sentinel-worker.service`](../examples/sentinel-worker.service) runs `sentinel worker` (the rootless-Podman executor, optionally the Firecracker executor and the Tailcat helper) under its own `sentinel-worker` account and `/var/lib/sentinel-worker`. It shares nothing with the controller unit: a worker host has no database and no master key, and a job that escapes its container reaches an account with neither.

The account is unprivileged and the unit **refuses to run as root**: a first `ExecStartPre` exits with status 2 (a configuration error, never retried) when the effective user id is 0, whatever `User=` was edited to. Rootless Podman needs three things from the account, none of which the unit can create by itself:

- **Subordinate ids** that overlap no other account (`/etc/subuid`, `/etc/subgid`), and the setuid `newuidmap`/`newgidmap` helpers (package `uidmap`).
- **A user manager** (`user@<uid>.service`), started by `loginctl enable-linger`. Job limits are enforced by a systemd user scope per job that the executor creates over the account's user bus (`systemd-run --user --scope`, also the microVM executor's cgroup); without the manager there is no `XDG_RUNTIME_DIR` and no limits, so the unit's second `ExecStartPre` refuses to start (status 1, retried: at boot the manager may still be coming up).
- **`/dev/kvm`** for microVMs, on a host that has it: add the account to the `kvm` group. Omit `[microvm]` elsewhere.

```sh
useradd --system --create-home --home-dir /var/lib/sentinel-worker \
        --shell /usr/sbin/nologin sentinel-worker
usermod --add-subuids 300000-365535 --add-subgids 300000-365535 sentinel-worker
loginctl enable-linger sentinel-worker
tar -xzf sentinel-<version>-<arch>-linux-worker.tar.gz
install -D -m 0755 sentinel-*/bin/sentinel /opt/sentinel/bin/sentinel
install -d -o root -g sentinel-worker -m 0750 /etc/sentinel
install -o root -g sentinel-worker -m 0640 sentinel-*/examples/worker.toml /etc/sentinel/worker.toml
install -m 0644 sentinel-*/examples/sentinel-worker.service /etc/systemd/system/
```

The home directory is the data directory on purpose: Podman keeps its images and containers under `~/.local/share/containers`, so one writable tree (`StateDirectory=sentinel-worker`) holds everything and `ProtectHome=read-only` needs no exception. Pick subordinate id ranges that do not collide with existing ones (`/etc/subuid`, `/etc/subgid`).

A system unit cannot name the account's numeric id, so the wiring to its user manager is a drop-in written once at install time:

```sh
uid=$(id -u sentinel-worker)
install -d /etc/systemd/system/sentinel-worker.service.d
cat >/etc/systemd/system/sentinel-worker.service.d/session.conf <<EOF
[Unit]
Requires=user@$uid.service
After=user@$uid.service
[Service]
Environment=XDG_RUNTIME_DIR=/run/user/$uid
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus
ReadWritePaths=/run/user/$uid
EOF
systemctl daemon-reload
```

Edit `/etc/sentinel/worker.toml` (controller address and fingerprint, enrollment, [configuration](configuration.md)), check it as the account (`runuser -u sentinel-worker -- /opt/sentinel/bin/sentinel worker --check --config /etc/sentinel/worker.toml --data-dir /var/lib/sentinel-worker`), then `systemctl enable --now sentinel-worker`. `ReadWritePaths` is there because `ProtectSystem=strict` would otherwise make the runtime directory read-only, and Podman keeps its run state in it.

What the unit sets:

- **Ordering.** After `network-online.target` only. The Tailcat helper is a child process of the worker (`[tailcat]` in `worker.toml`), not a unit, so there is no helper unit to order against; a worker redials with back-off until the controller answers. On the controller's own host add `After=sentinel-server.service` in a drop-in so a boot does not spend its first back-off on a controller that is still starting.
- **Restart.** As the controller: `Restart=on-failure` after two seconds, status 2 not retried, five starts in five minutes stop the unit. `TimeoutStopSec=60s` covers a drain (attempts handed back, sessions closed in 2 s, store drained in 5 s).
- **Limits.** `MemoryMax=2G`, `TasksMax=4096`, `LimitNOFILE=65536`, `LimitCORE=0`: starting points for the worker process, its `git` and `podman` clients and the helper. **Jobs are not in this cgroup**: each runs in a user scope under `user@<uid>.service`, limited by its own job resources and by the worker's `cpu_millis` and `memory_bytes`. To cap the account as a whole, set `CPUQuota=`, `MemoryMax=` and `TasksMax=` on `user-<uid>.slice` with `systemctl set-property`.
- **Sandbox.** Weaker than the controller's, on purpose. Left on: `ProtectSystem=strict` (state directory and `/run/user/<uid>` writable), `ProtectHome=read-only` (`yes` would hide `/run/user`), private `/tmp`, private mounts, `RemoveIPC`, `DevicePolicy=closed` allowing only `/dev/fuse` (fuse-overlayfs), `/dev/net/tun` (pasta, `job_network = "egress"`) and `/dev/kvm`, and a capability bounding set of `CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_SYS_ADMIN`. Left out: `NoNewPrivileges` (it disables the setuid helpers), `PrivateDevices`, the `Protect*` kernel switches and `RestrictNamespaces` (rootless Podman is built on user and mount namespaces), and every seccomp-based directive (`SystemCallFilter`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`): the filter would be inherited by every job process through conmon. `TMPDIR` is `/var/lib/sentinel-worker/tmp`, so image layers are staged on the data disk. `scripts/release/check-worker-unit.sh` fails if `systemd-analyze security` scores the unit worse than 7.0.

The system-scope unit with its drop-in (account switch, capability bounding set, device policy) has been checked by `systemd-analyze` only; starting it needs root on a host reserved for it, and it has not been started on one.

### A user unit instead

Where a system unit and a drop-in are unwelcome, the same file runs in the account's own manager, which lingering keeps up without a login. Copy the unit to `~sentinel-worker/.config/systemd/user/sentinel-worker.service` and delete what a user instance cannot apply: `User=`, `Group=`, `CapabilityBoundingSet=`, `AmbientCapabilities=`, `DevicePolicy=` and `DeviceAllow=`. The two `ExecStartPre` lines still work (a user instance never runs as root and always has its bus). Set `WantedBy=default.target`. The `StateDirectory=` of a user instance is below `~/.local/state`, so pass that `--data-dir` and `TMPDIR`, or keep `/var/lib/sentinel-worker` if the account owns it. **Also delete `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=` and `PrivateMounts=`:** a user instance builds a mount namespace inside an unprivileged user namespace of its own, and the setuid `newuidmap` helper refuses to write id maps from there, so any one of them makes Podman fail with `cannot clone: Operation not permitted` (measured with Podman 5.7.0 on systemd 259). A user unit is therefore less sandboxed than the system unit. Then, as the account with `XDG_RUNTIME_DIR=/run/user/<uid>` set:

```sh
systemctl --user daemon-reload
systemctl --user enable --now sentinel-worker
```

`loginctl enable-linger` is what makes it start at boot and survive logouts. `check-worker-unit.sh` builds exactly this copy and starts it.

### Checking the unit

```sh
scripts/release/check-worker-unit.sh <path to a --features worker binary>
```

as the unprivileged worker account (or any unprivileged user) with a user systemd instance. The script refuses root. It runs `systemd-analyze verify` on the unit (nothing may be reported about it), requires `systemd-analyze security --offline=true` to score it no worse than 7.0 overall, starts a user-instance copy that keeps every sandbox directive a user instance can apply (only the account, the unit name, the paths, the capability and device directives, and `ReadWritePaths=%t` differ) and requires `sentinel worker --check` to report `worker configuration valid`. When rootless Podman answers for the account it also starts the worker proper, from a copy without `ProtectSystem`, `ProtectHome`, `PrivateTmp` and `PrivateMounts` (see the user unit above), against an address nothing listens on, with Podman's storage, runtime and temporary directories pointed into the test's state directory, and requires the `executor_ready` event and a `SIGTERM` stop that is a clean exit. It writes only below `~/.local/state/sentinel-worker-unit-check` and removes it.
