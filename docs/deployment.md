# Deployment

How the controller and a worker run: under systemd, as containers, behind TLS, with GitHub ingress, or fully local. The tasks are V01 ([release packages](releasing.md)) and V02 (the units, the container examples and this guide). Configuration is in [configuration](configuration.md), upgrades in [upgrades](upgrades.md), the web process in [web interface](web-ui.md).

## Release packages

What a release contains, how to build it on each architecture, how to verify a download, the digest manifest, reproducibility and the dependency and license inventory are in [releasing](releasing.md). This page covers running the packages: the units and the release profile.

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

The system-scope unit and its drop-in as files have been checked by `systemd-analyze verify` and `security` only; they have not been installed and started on a host. The sandbox itself was exercised as a transient system service with the unit's account switch, capability bounding set, `ProtectSystem=strict`, `ProtectHome=read-only`, private `/tmp` and mounts, `RemoveIPC`, device policy and caps and the user manager's `XDG_RUNTIME_DIR` and bus: rootless Podman 5.7.0 on systemd 259 started a container with `--memory` and `--cpus` limits through the account's user scope and exited 0. One thing the probe taught: `PrivateTmp=yes` hides `/var/tmp`, so a `ReadWritePaths=` or data directory under `/tmp` or `/var/tmp` fails with status 226/NAMESPACE; keep the data directory elsewhere (the default `/var/lib/sentinel-worker` is).

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

## Container examples

Both examples start from the unpacked release package (so the image holds the verified binary, [releasing](releasing.md)) and ship inside it: `Containerfile.server`, `server-container.toml` and `compose.server.yaml` in the server package, `Containerfile.worker` and `compose.worker.yaml` in the worker package. They are Podman-first; the Compose files use only keys that `podman compose` and `docker compose` share. There is no published image: building one from the verified package is the supported path.

**Base image.** The binary links glibc dynamically and, as built on the reference builder, needs glibc 2.39 or newer (`objdump -T` on your binary shows the symbol versions; read it again for your build). The default `BASE` is `docker.io/library/ubuntu:26.04`; pass `--build-arg BASE=…` for another image whose glibc is at least that of the machine that built the package. Build the controller image with `--format docker` so it keeps its `HEALTHCHECK` (the OCI format drops it).

### The controller

```sh
tar -xzf sentinel-<version>-<arch>-linux-server.tar.gz && cd sentinel-*/
podman build --format docker -f examples/Containerfile.server -t localhost/sentinel-server:<version> .
cp examples/server-container.toml examples/compose.server.yaml .
export SENTINEL_VERSION=<version>
podman compose -f compose.server.yaml run --rm --no-deps server admin key create --data-dir /var/lib/sentinel
podman compose -f compose.server.yaml up -d
```

The image runs as `sentinel` (uid 10001) with `/var/lib/sentinel` as its only writable path: a volume holding the database and `master.key`, which must be backed up separately from the database ([backup](backup.md)). The Compose file adds a read-only root, a 64 MiB `/tmp`, no capabilities, `no-new-privileges`, `pids_limit` 4096 and `mem_limit` 4 GiB, publishes the API (7080) and the worker link (7443) on the **host's loopback only**, and mounts `server-container.toml` read-only. That configuration binds both listeners on `0.0.0.0` because a published port arrives on the container's interface; what protects them is the published address. Change `127.0.0.1:` in `ports` to a private address only when workers on other machines must reach 7443, and never publish 7080 beyond the reverse proxy ([TLS](#tls-and-a-reverse-proxy)).

- **Secrets.** Files the controller reads as secrets (GitHub App key, sign-in client secret, S3 and mail credentials, `github-webhook.json`) must be owned by uid 10001 with mode `0600`, which a bind mount from a rootless host cannot give. Keep them on the data volume, write them through a throwaway container of the same image (`podman run --rm --entrypoint /bin/sh -v <volume>:/var/lib/sentinel:U …`, `umask 077`; `:U` hands the volume to the image's user) and name them in the configuration by their in-container path.
- **Health.** The image's `HEALTHCHECK` asks `GET /api/v1/health` over loopback with bash's `/dev/tcp` (the image has no `curl`); `podman healthcheck run <container>` runs it by hand.
- **Stopping.** `SIGTERM` is the stop signal and `stop_grace_period` is 30 s, the controller's drain bounds ([the unit](#the-controller-as-a-systemd-service)).
- **`trusted_proxies`.** The controller sees the peer address of the container network, not the proxy's host address. With a proxy on the host list the network's gateway (`podman network inspect`); with a proxy container list its network. At the default (loopback only) every client behind the container network shares one rate-limit allowance.
- **Not here:** the web interface ([web interface](web-ui.md)) has no image; run it from `sentinel-web.service`.

### A worker

A worker container carries its own rootless Podman, because jobs run in containers the worker's executor starts. That nesting needs more than the controller image does, and the example says so:

```sh
tar -xzf sentinel-<version>-<arch>-linux-worker.tar.gz && cd sentinel-*/
podman build -f examples/Containerfile.worker -t localhost/sentinel-worker:<version> .
cp examples/worker.toml examples/compose.worker.yaml .   # edit worker.toml: controller, fingerprint, enrollment
SENTINEL_VERSION=<version> podman compose -f compose.worker.yaml up -d
```

- **Run it from a rootless Podman account** with subordinate ids and `newuidmap`, as for [the unit](#a-worker-as-a-systemd-service). Inside the image the `sentinel-worker` user (uid 10002) has its own range, `20000:30000`, taken from the ids the outer user namespace has (a range above its 65,536 ids makes `newuidmap` fail).
- **`privileged: true` is required, and weaker than the unit.** Measured with Podman 5.7.0, crun and cgroup v2 (Ubuntu 26.04, kernel 7.0): with default options the executor reports `executor_unavailable` (`cannot set up namespace using "/usr/bin/newuidmap"`); `--cap-add=SYS_ADMIN` lets Podman start but every nested container fails (`crun: open /proc/sys/net/ipv4/ping_group_range: Read-only file system`) because the outer container masks `/proc/sys`; unmasking only `/proc/sys` fails on the `proc` mount; `--privileged` works. On rootless Podman that means all capabilities inside the account's user namespace, no seccomp filter and the host devices the account can open, never root on the host; but the outer container no longer confines what runs in it. Where a systemd unit can be used, it is the better-isolated choice.
- **Job networking is `none` only.** With the default network or `job_network = "egress"` the nested `pasta` fails (`Couldn't open network namespace … Permission denied`), so egress jobs do not run in this container.
- **Resource limits.** The nested Podman uses the `cgroupfs` manager with `cpu memory pids` delegated; it accepts `--memory` and `--cpus` (read back with `podman inspect`). Enforcement was inspected, not stress-tested.
- **No microVMs.** The Firecracker executor needs `/dev/kvm` and its files; mount them yourself on a KVM host, or use the unit.
- **Disk.** The data volume also holds Podman's images and containers (`.local/share/containers` below it), so it grows with pulled job images.

### What was verified

On the reference host (Podman 5.7.0 rootless, Ubuntu 26.04 base, images built from the **debug** binaries of this commit, not from release packages): both images build. The controller image creates `master.key` as uid 10001, starts with the Compose file's read-only, capability and memory settings, answers `GET /api/v1/health` with 200 through the published loopback port, passes `podman healthcheck run`, and stops on `SIGTERM` with exit 0. `docker compose config` renders both Compose files (an offline check; no compose provider was started, so the Compose start is exercised through the equivalent `podman run` flags). The worker image passes `worker --check`, reports `executor_ready` (`cgroup_manager: cgroupfs`) under `--privileged`, stops with exit 0, and a nested `podman run --network none --memory 64m --cpus 0.5 --pids-limit 100` runs. Not run: a worker enrolled to a real controller executing a job, an arm64 image build, and a build from a real release package (`scripts/release/package.sh` now lists these files in each package; its `build` was not re-run, only `bash -n`).

## TLS and a reverse proxy

Sentinel speaks plain HTTP on `api_listen` (loopback by default) and does not terminate TLS for browsers or CLIs: a reverse proxy does, for the **public origin**, and the controller's `public_url` is exactly that origin (`https://ci.example.com`, [configuration](configuration.md)). Two kinds of traffic exist and only one goes through the proxy:

| Traffic | Port | Through the proxy? |
|---|---|---|
| Browser, CLI, MCP, OAuth, GitHub webhooks | `api_listen` (7080), or `sentinel-web` (3000) in front of it | Yes: HTTPS to the proxy, HTTP to loopback |
| Worker link | `listen` (7443) | **No.** It is its own TLS (a self-signed certificate pinned by fingerprint, or [Tailcat](configuration.md#optional-tailcat-transport)). Expose it on the private address workers reach, or not at all; do not put an HTTP proxy in front of it |

[`examples/sentinel.nginx.conf`](../examples/sentinel.nginx.conf) and [`examples/Caddyfile`](../examples/Caddyfile) are complete, equivalent configurations for the layout the units use (proxy to `sentinel-web` on `127.0.0.1:3000`, which forwards to the controller). What they set, and why:

- **TLS** 1.2 and 1.3 and HSTS, plus a redirect from port 80 (nginx) or automatic certificates (Caddy). The session cookie is `__Host-sentinel_session`, which browsers accept only over HTTPS (or from `localhost`).
- **`X-Forwarded-For` is overwritten, never appended** (`proxy_set_header X-Forwarded-For $remote_addr`, `header_up X-Forwarded-For {remote_host}`). The controller rate-limits unauthenticated requests per client and, **only for a peer in `trusted_proxies`**, takes the *last* `X-Forwarded-For` entry as the client; with the header overwritten that entry is the proxy's real peer, so a client cannot choose its own bucket. `sentinel-web` needs `NUXT_CLIENT_IP_HEADER=x-forwarded-for` for the same reason ([web interface](web-ui.md#client-addresses)).
- **Body limit 4 MiB.** The controller's largest body is the GitHub webhook's 4 MiB (it enforces smaller limits on its other routes); the proxy limit only keeps oversized uploads off the controller.
- **Unbuffered, long reads** (`proxy_buffering off`, `proxy_read_timeout 1h`; Caddy `flush_interval -1`), so log following is not held back.
- **`X-Forwarded-Proto`** is set by the proxy, but the controller builds its URLs from `public_url`; a wrong `public_url` is the usual cause of an OAuth redirect to the wrong origin.

### `trusted_proxies`

Set it in `server.toml` to exactly the addresses the proxy connects from: at most 64 IPs or CIDR networks with zero host bits (`trusted_proxies = ["127.0.0.1", "10.89.0.0/24"]`). Absent means loopback only, which is right when the proxy or `sentinel-web` runs on the controller's host. A network wider than the proxy lets anything in it pick its own rate-limit bucket with `X-Forwarded-For`. A proxy on another host, or on a container network ([the controller container](#the-controller)), must be listed; if it is missing nothing breaks, all clients behind it merely share one allowance.

### Without the web interface

Point the proxy at `api_listen` (`127.0.0.1:7080`) and send only what the controller serves: `/api/`, `/oauth/`, `/.well-known/`, `/device`, `/auth/github/` and `/mcp` (and, for generic OAuth clients under a path prefix, the host-root RFC 8414 / RFC 9728 locations listed in [configuration](configuration.md)).

### Verification

On the reference host with nginx stable and Caddy 2 in rootless Podman containers (host network, self-signed certificates, test ports instead of 80/443, `ci.example.com` resolved to loopback):

- `nginx -t` and `caddy validate` accept the shipped files unchanged.
- Against a request-echoing upstream standing in for `sentinel-web`: a client's `X-Forwarded-For: 6.6.6.6` and `X-Forwarded-Proto: spoof` reach the upstream as `['127.0.0.1']` and `https` on both proxies; nginx redirects HTTP to HTTPS (301) and sends HSTS (Caddy sends HSTS); a 5 MB body to `/api/v1/hooks/github` is refused with 413 and a 3.5 MB body passes, on both.
- With nginx pointed at the controller container's `api_listen`: `GET /api/v1/health` through the proxy returns 200 and the webhook requests in the next section behave as described.

Not run: the `sentinel-web` hop (the web interface is being replaced), Caddy's certificate issuance from a public CA, HTTP/3, and a proxy on a different host than the controller.

## GitHub ingress

GitHub reaches Sentinel in two places, both on the public origin: the **App webhook**, `POST /api/v1/hooks/github`, and the **OAuth callback**, `{public_url}/auth/github/callback`, for sign-in ([GitHub sign-in](github-sign-in.md)). Both need the controller reachable from GitHub over HTTPS at `public_url`; neither works on a loopback-only deployment.

1. Put the controller behind the proxy above and set `public_url`.
2. Choose the webhook secret (16 to 256 printable ASCII bytes) and store it **owner-only** as `<data_dir>/github-webhook.json`, `{"secret": "…"}`. Without the file the route answers `not_found`. Restart the controller (it reads the file at start). Use the same secret as the GitHub App's webhook secret.
3. In the GitHub App's settings set the webhook URL to `https://ci.example.com/api/v1/hooks/github`, content type `application/json`, and subscribe to `push`, `pull_request` and the control events that [intake](intake.md) and [checks](checks.md) list. The App id and key for source access and Checks are `<data_dir>/github-app.json` ([configuration](configuration.md)).
4. Redeliver the `ping` from the App's *Advanced* tab: `200 {"pong":true}` means path, secret and signature are right.

The route enforces, independent of the proxy: HMAC-SHA256 over the **raw body** in `X-Hub-Signature-256` (so the proxy must not rewrite request bodies), `X-GitHub-Delivery` deduplication (a redelivery with the same body returns the recorded outcome; the same id with another body is a conflict), a 4 MiB limit, and a `202` only once the event is durably recorded. The proxy need not allowlist GitHub's addresses for correctness, because an unsigned request is a `401`; allowlisting only reduces noise.

Verified through the nginx configuration above in front of the controller container: a correctly signed `ping` returned `200 {"pong":true}` and a wrong signature `401 invalid credential`. A real GitHub delivery to a public host was not part of this check.

Repositories that are not on GitHub, or a controller GitHub cannot reach, use the other two paths in [intake](intake.md): the `post-receive` hook relay (`POST /api/v1/intake/{repo}` with a per-repository secret, spooled and retried by the sender) and bounded `git ls-remote` polling.

## Fully local operation

Everything except GitHub works with no public name, no certificate and no outbound call:

1. **Bind loopback** (the defaults: `api_listen = "127.0.0.1:7080"`, `listen = "127.0.0.1:7443"`) and leave `public_url` unset; the controller then builds its URLs from the bound address. The session cookie works from `http://localhost:7080` (a `localhost` origin is a secure context); any other hostname needs HTTPS, which is what the proxy is for. Leave the GitHub App, GitHub sign-in and mail files out: absent means disabled.
2. **Create the first administrator on the host**, with no browser or email: `sentinel admin bootstrap` (or the setup token the controller writes to `<data_dir>/setup-token`, [configuration](configuration.md#first-run-setup-without-a-shell)), then `sentinel admin token issue …` for CLI credentials. Password recovery is `sentinel admin recover`, also on the host.
3. **Workers** on the same machine connect to `127.0.0.1:7443` with the logged controller fingerprint and an enrollment from `sentinel admin worker enroll` ([worker link](worker-link.md)). Tailcat and any DERP server are optional and off by default. A worker on another machine of the same network uses the controller's private address in `listen` and `controller`, still direct TLS with the pinned fingerprint.
4. **Sources.** A repository on local disk or a `file://` URL is a valid source ([sources](sources.md)); events arrive through the `post-receive` hook relay to `http://127.0.0.1:7080/api/v1/intake/{repo}` (plain HTTP is acceptable on loopback; the hook secret is a bearer credential, so use HTTPS anywhere else) or by polling. There is no webhook and no public address.
5. **Images.** Jobs run pinned `name@sha256:…` images and the worker checks `podman image exists` before pulling ([executor](executor.md#the-image-pull)); on a host with no outbound network, load the images into the worker account's Podman store beforehand.

Unavailable locally by design: GitHub sign-in, the GitHub webhook and GitHub Checks (GitHub must reach you and you must reach GitHub), email delivery (`sentinel admin invite` and `account` mint links instead), and the remote cache's S3 backend unless the endpoint is local. The pieces were exercised separately above (controller start, key creation, health, shutdown, the proxy); a full run from a local push to a finished job on a host with no outbound network was not part of this item.
