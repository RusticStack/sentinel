# CLI and process configuration

F02 implements the server and worker **process lifecycle**: command parsing, configuration validation, data-directory initialization, and clean signal-driven exit. F04 adds structured diagnostics, monotonic timing and bounded execution lanes; see [runtime foundations](runtime-foundation.md). Scheduling, API listeners, worker enrollment/connections, job execution, and durable writers arrive in later tasks. Startup explicitly reports this lifecycle-only status.

## Build and inspect

For shared Cargo shortcuts and contributor prerequisites, see [Development](development.md).

```sh
cargo build --locked --release --features server,worker
./target/release/sentinel --version
./target/release/sentinel --help
./target/release/sentinel server --help
./target/release/sentinel worker --help
```

The role build command requires Linux. Portable CLI builds use `cargo build --locked --release` and support help/version on Linux and Windows. Requesting a role omitted from the build produces an explicit unavailable-role error. Help describes both roles even in CLI-only builds; it does not indicate role availability. No command defaults to starting a service.

`--version` (also accepted after the subcommand) reports the package version from Cargo metadata. The current version is a development version, not a released executor.

## Configuration contract

Each role accepts:

| Option | Behavior |
|---|---|
| `--config FILE` | Read this UTF-8 TOML file; relative file paths resolve from the working directory |
| `--data-dir PATH` | Override the data directory; must be absolute |
| `--check` | Validate and print the effective data directory, then exit without creating directories, installing signal handlers or starting the lifecycle |
| `--log-format text\|json` | Internal diagnostic format; defaults to `text` |
| `--log-level error\|warn\|info\|debug\|trace` | Diagnostic verbosity; defaults to `info` |

Precedence is **built-in role defaults < explicit config file < command-line flags**. There is no implicit config discovery, environment-variable override, shell expansion, or dotenv loading. A supplied configuration file must be valid even when a flag overrides a setting.

The complete current file schema is:

```toml
data_dir = "/srv/sentinel/controller"
log_format = "text"
log_level = "info"
# server only: where workers connect (default 127.0.0.1:7443) and where the API answers (default 127.0.0.1:7080)
listen = "0.0.0.0:7443"
api_listen = "127.0.0.1:7080"
# server only: the deployment-facing base URL; it is the OAuth issuer ([OAuth](oauth.md)). Absent = http://{api_listen}
public_url = "https://ci.example.com"
# server only: the reverse proxy's networks, whose X-Forwarded-For is believed. Absent = loopback only
trusted_proxies = ["127.0.0.1"]
# worker only: the controller to reach and the fingerprint it logged at `link_listening`
controller = "10.0.0.5:7443"
controller_fingerprint = "<64 lower-case hex characters>"
worker_name = "builder-1"          # 1-128 bytes, default "worker"
enrollment_file = "/etc/sentinel/enrollment"  # absolute; read on start, removed once spent
cpu_millis = 8000                  # override measured capacity (default: every core); the WHOLE host's, see below
memory_bytes = 34359738368         # override measured capacity (default: total less a host reserve); the whole host's
git_mirrors = true                 # keep per-repository object mirrors under <data_dir>/mirrors (default on; [mirrors](mirrors.md))
labels = ["linux", "gpu"]          # scheduling labels this worker selects work by; at most 16, each 1-128 bytes (default none)
disk_bytes = 1073741824            # scratch disk offered to jobs; default: the data directory's free space less an eighth (clamped to 512 MiB-2 GiB)
spool_reserve_bytes = 1073741824   # free space the log spools never write the data directory below (default 1 GiB; 0 = none)
spool_quota_bytes = 4294967296     # bytes every attempt's log spool may hold together (> 0, default 4 GiB); output past either is declared as log gaps ([logs](logs.md))
cache_budget_bytes = 53687091200   # what the local cache may hold (≥ 64 MiB); default a fifth of the data file system, 1-50 GiB ([retention](retention.md))
mirror_budget_bytes = 53687091200  # what the Git mirrors may hold (≥ 64 MiB); default a tenth, 1-50 GiB
image_budget_bytes = 53687091200   # what each image store may hold (≥ 64 MiB); default a fifth, 2-50 GiB; least recently used images no container holds go first
tailcat_address = "tc…"            # required with `[tailcat] enabled = true`: the controller's address, copied from its `<data_dir>/tailcat/address`

# either role: the optional pinned Tailcat transport (Q06); absent or `enabled = false` = direct TLS
[tailcat]
enabled = false                    # default
binary = "/usr/local/bin/tailcat"  # absolute path to the helper executable
sha256 = "d46582…"                 # default: the pinned v0.6.0 build; a mismatch refuses to run the helper
derpmap_url = "https://derp.example/map"  # optional operator-owned DERP map
region = "eu-1"                    # optional region name inside that map
listen_port = 7443                 # server: must match `listen`; worker: the loopback port it dials

# either role: remote cache hydration (Q08); absent or `enabled = false` keeps every lookup local
[remote_cache]
enabled = true                     # default; the controller holds offered objects, the worker fetches/offers them
budget_bytes = 53687091200         # server only: what the controller's store may hold (≥ 64 MiB); default a tenth of the data file system, 1-50 GiB

# server only: the optional external S3 copy of objects and finished logs ([s3](s3.md)); absent keeps everything on the local disk only
[s3]
endpoint = "https://s3.eu-central-1.amazonaws.com"  # http(s)://host[:port], no path
region = "eu-central-1"
bucket = "sentinel-ci"
prefix = "prod/"                   # optional; ends in '/'
path_style = false                 # true for most self-hosted services
ca_file = "/etc/sentinel/s3-ca.pem"  # optional, absolute: trust these CAs instead of the Mozilla roots
credentials_file = "/etc/sentinel/s3.credentials"  # absolute, owner-only: access_key_id, secret_access_key[, session_token]
part_bytes = 16777216              # 5-512 MiB (default 16 MiB)
local_bytes = 0                    # replicated objects kept locally up to this; 0 (default) keeps all
backlog_bytes = 67549713920        # unreplicated bytes past which new artifacts and uploads wait (default a sixteenth of the data file system, 1-64 GiB)

# server only: scheduled online backups ([backup](backup.md)); absent takes none (use `admin backup create` beside a stopped controller)
[backup]
dir = "/mnt/backup/sentinel"       # absolute, outside data_dir: another disk or a mounted volume
interval_secs = 3600               # 300..604800 (default hourly: the metadata recovery point)
keep = 24                          # newest backups kept (1..1000, default 24)

# server only: disk admission, quotas and retention ([retention](retention.md), [storage](storage.md#disk-admission-quotas-and-reclamation-d06))
[storage]
reserve_bytes = 16777216000        # held back for metadata and log evidence (≥ 64 MiB); default a 64th of the data file system, 1-16 GiB; never less than twice the metadata database
low_watermark_bytes = 33554432000  # discretionary writes refuse when free space above the reserve falls under this; default a 32nd, 2-32 GiB
high_watermark_bytes = 67108864000 # …and admit again above this (≥ low); default twice low
quota_bytes = 0                    # cap on what every tenant stores together (objects, uploads, logs); 0 = unlimited (default)
tenant_quota_bytes = 0             # default cap per tenant, the same kinds of bytes; 0 = unlimited (default; one upload still declares at most 4 GiB)
log_retention_secs = 1209600       # finished attempt logs kept this long unless a tenant or repository says otherwise (1 h .. 366 d, default 14 d)
artifact_retention_secs = 7776000  # longest a pipeline's `retain` may keep an artifact; longer is shortened to it (1 h .. 366 d, default 90 d)
run_artifact_bytes = 17179869184   # artifact bytes one run may store (1 MiB .. 1 TiB, default 16 GiB)
attempt_log_bytes = 268435456      # stored log bytes one attempt may produce (1 MiB .. 4 GiB, default 256 MiB); past it frames are refused and declared as gaps
sweep_interval_secs = 300          # the maintenance pass runs on its own thread at most this often (5..86400)
```

The three common fields are optional in the file; `listen`, `api_listen`, `public_url` and `[storage]` are refused for the worker and the worker keys (`labels`, `disk_bytes`, `spool_reserve_bytes`, `spool_quota_bytes`, `cache_budget_bytes`, `mirror_budget_bytes`, `image_budget_bytes`, `tailcat_address`) for the server, as are `[remote_cache] budget_bytes`, `[s3]` and `[backup]` for the worker; `[tailcat]` is accepted by both roles; `controller` and `controller_fingerprint` are set together or not at all, and the other worker keys need them. A worker without a controller configured idles as a lifecycle-only process. Empty files use the logging defaults above and the role data path:

- Server: `/var/lib/sentinel`
- Worker: `/var/lib/sentinel-worker`

**Several worker identities on one machine.** The controller counts the reservations of every identity that reports the same host (`/etc/machine-id`) against each one's report, because each identity measures the same machine ([storage](storage.md#fleet-placement-q01q04)). A `cpu_millis`/`memory_bytes` override on such identities must therefore state the **whole host's** capacity, not a share of it: two identities overridden to `cpu_millis = 8000` on one 16-core host share 8,000 millicpu between them, not 16,000. An identity that reports no host id (a container without `/etc/machine-id`) is accounted alone, so several of those on one machine can oversubscribe it — give them the host's machine id, or size their overrides so their sum fits. The host id is the worker's own claim: a worker credential can make another host look busier, never its own look larger.

`public_url` is the URL clients reach the API at, exactly: an absolute `https://` URL (plain `http://` only for a loopback host), lower-case scheme and host, no default port, no trailing slash, query or fragment; a path prefix is kept (`https://ci.example.com/sentinel`). It names the OAuth issuer, every endpoint in the authorization-server metadata and the API's `resource`, so it must be what the CLI is given as `--server`. Behind a reverse proxy set it. With the web interface ([web interface](web-ui.md)) the proxy sends the whole origin to `sentinel-web`, which forwards `/api/*`, `/.well-known/*`, `/oauth/*`, `/device`, `/auth/github/*` and `/mcp` to `api_listen`, so `public_url` is the web interface's origin; without it, forward those routes to `api_listen` directly. With a path prefix (controller only; the web interface is served at the root of its origin), every URL Sentinel hands out (metadata, the consent and device pages' forms and sign-in) stays under the prefix, and the proxy may strip the prefix or forward it unchanged — both route. For generic OAuth clients also forward the host-root RFC 8414 / RFC 9728 locations, `/.well-known/oauth-authorization-server/<prefix>`, `/.well-known/oauth-protected-resource/<prefix>/api/v1` and `/.well-known/oauth-protected-resource/<prefix>/mcp`, unchanged ([OAuth](oauth.md#issuer-and-metadata)). Have the proxy set `X-Forwarded-For`: unauthenticated OAuth requests are rate-limited per client, and only requests arriving from a `trusted_proxies` network are counted under that header's last address. `trusted_proxies` (server only) lists at most 64 IP addresses or CIDR networks with zero host bits (`trusted_proxies = ["127.0.0.1", "10.0.0.0/24"]`); absent means loopback only (`127.0.0.0/8`, `::1`). List only the proxy's own addresses: any other peer, including a private-network neighbour that reaches `api_listen` directly, is keyed by its own address whatever header it sends. A proxy on another host must be listed, or every client behind it shares one allowance. Without it the issuer is `http://{api_listen}`, correct only for direct loopback use. The server also runs a maintenance tick every ten minutes that purges expired sessions, API credentials, sign-in state, OAuth rows (including DCR/CIMD client registrations that hold no grant after 24 hours) and idempotency records (older than 24 hours) in bounded batches of 1,000 rows per kind, ticking every second instead while a kind still fills its batch; validation never depends on it.

Use separate directories for the two roles. Paths must be absolute, non-root, and contain no `..` components. An existing non-directory is rejected. Existing directory contents are preserved. Data directories are trusted operator-managed paths; F02 does not provide an artifact extraction sandbox or a single-process directory lease. Ownership and access permissions follow the service account and its umask; Sentinel does not elevate privileges or change ownership.

Configuration input must be a regular file, valid UTF-8, and at most **64 KiB**. Unknown/duplicate keys, wrong field types and malformed TOML fail validation. Parser failures report the expected schema without echoing input values. There are no credential fields in this schema; enrollment credentials have a separate interface, and source credentials are sealed in the database.

Optional on-disk controller state configures sources ([sources](sources.md)), event intake ([intake](intake.md)) and the remote cache; each is used at startup when present:

- `<data_dir>/source-destinations.json` — a JSON array of at most 128 approved authorities (`https://host[:port]`, `ssh://user@host[:port]`). A source binding whose remote is not exactly one of them is refused. Absent means no binding can be created.
- `<data_dir>/github-app.json` — `{"app_id": 1234, "private_key_file": "/absolute/owner-only.pem"}` for the GitHub App association, plus two optional fields: `public_url`, the deployment-facing base URL used for a check's `details_url` ([checks](checks.md)), and `api_url`, another GitHub API endpoint (Enterprise, or a loopback stub). The PEM must be a regular file, not group- or world-readable, at most 16 KiB, PKCS#1 or unencrypted PKCS#8. The App key is never stored in the database.
- `<data_dir>/remote-cache/` — the controller's remote cache store (Q08): objects workers offered so another worker can hydrate them without the WAN. Created at server start; without a configured store every cache need and offer is refused `denied`; the store is reclaimed every 10 minutes to one bundle per entry and `[remote_cache] budget_bytes` (default sized from the disk, 50 GiB on the 1 TB reference host) ([cache](cache.md), [retention](retention.md)). The API also sets it through `Controller::set_remote_cache`.
- `<data_dir>/github-sign-in.json` — GitHub web sign-in on the browser pages (U07): `{"client_id": "Iv1.…", "client_secret_file": "/absolute/owner-only-file"}`, plus `web_url` and `api_url` together for GitHub Enterprise Server (both `https://`; absent means github.com). The client secret lives only in that file — a regular, owner-only file of at most 4 KiB, one trailing newline dropped — never in this JSON, the TOML configuration, the database or a log line; startup logs `github_sign_in_enabled` with the (public) client ID. Register the GitHub OAuth app's callback as exactly `{public_url}/auth/github/callback`. Without the file, the `/auth/github/*` routes do not exist and no page offers the button. There is no organization allow-list: who may sign in is decided by linked identities and [admission](admission.md) ([GitHub sign-in](github-sign-in.md#browser-routes-u07)).
- `<data_dir>/github-webhook.json` — `{"secret": "…"}` for GitHub webhook signature verification; the secret is 16–256 printable ASCII bytes and the file must be owner-only. Without it the GitHub intake route does not exist.

Source credentials themselves are sealed with `<data_dir>/master.key` (`admin key create`), the same key-outside-database file second factors use. Repository hook secrets are digests and need no key. Resolution also uses `<data_dir>/intake-work/` as per-delivery scratch space for the repository fetches it makes; it is emptied at startup and never reused.

`--check` validates syntax, effective path shape and currently inspectable filesystem metadata. It does not prove future write access, reserve the directory or validate networking/runtime prerequisites. Actual startup creates missing directories and reports initialization failures.

### Optional Tailcat transport

An optional `[tailcat]` section in the server or worker file runs the **pinned** Tailcat helper as an alternative transport for exactly this deployment's link port. Everything else — enrollment, identity, authorization, leases — is unchanged, and with `enabled = false` (or no section) the link uses direct TLS exactly as before.

|Key|Behavior|
|---|---|
|`enabled`|`false` (default) leaves direct TLS in place.|
|`binary`|Absolute path to the helper executable. It must be a regular file (not a symlink) owned by root or by the Sentinel user and not writable by group or others; anything else is refused before it runs.|
|`sha256`|The executable's SHA-256; defaults to the pinned v0.6.0 build `d46582137d21f03d15345e2be425d6317d49e5b8c8bb4f6fc56037f4c08cce73`. The pin is checked before *every* execution, and a mismatch refuses to run it. On Linux the file is opened once, hashed from that descriptor and executed through the same descriptor (`/proc/self/fd/<n>`), so a file swapped between the check and the exec never runs; an unchanged file (same device, inode, size, mtime and ctime) is not re-hashed — about 0.9 µs per execution instead of about 8.7 ms for the 18 MB helper (release build, WSL2). Elsewhere the file is hashed on every execution and executed by path.|
|`derpmap_url`|Optional `https://` URL of an operator-owned DERP map, passed to the helper. Public relays are best-effort; self-hosted relay infrastructure is supported without any Tailscale-hosted account (see below).|
|`region`|Optional region name in that map (`--region=…`); the controller otherwise asks the helper for a fixed region so its address survives restarts.|
|`listen_port`|The link port the helper carries (default 7443): the server serves it (it must match `listen`), the worker binds it on loopback and dials `127.0.0.1:<listen_port>`.|

Keys live under `<data_dir>/tailcat` (owner-only) and persist across restarts, so a node's address is stable until the operator rotates the key (see **Key rotation** below).

**Admission.** The controller admits workers from `<data_dir>/tailcat-allow` (owner-only, at most 64 KiB), one line per worker: its Tailcat node key and its Sentinel worker id, `nodekey:<64 hex> wrk_<id>` (`#` comments and blank lines allowed). The worker's node key is in its `<data_dir>/tailcat/client-default.nodekey` (the worker logs that path at `tailcat_forwarding`; nothing prints the key itself) and its id in `<data_dir>/worker.id`. A bare key without a worker id, a malformed line, or one key listed for two workers makes the file invalid. The controller re-reads the file and the store every 10 s and admits every listed key whose worker is not revoked — a worker the store does not know yet stays admitted, because it has to reach the controller over the tunnel to enroll — so `sentinel admin worker revoke` closes that worker's tunnel within one tick. An absent or empty file (or every listed worker revoked) admits no peer: the helper runs with `--allow=none`, never without `--allow` (which upstream treats as "every peer"), and the controller still has its address. An unreadable or invalid file is logged once (`tailcat_allow_unreadable`) and the last good list stays in force, still filtered by revocation; an invalid file at startup is a startup error.

**What an allow-list change costs.** A change that alters the set of admitted keys restarts the controller's helper; a rewrite that leaves the set the same (reordered lines, comments, a duplicate) restarts nothing and closes nothing. The pinned helper cannot reload `--allow`, and a killed helper closes nothing through its tunnels: `SIGKILL`, `SIGTERM` and `SIGINT` all left a tunnelled connection open for more than 30 s. Starting the replacement before stopping the old helper would not help either, because a tunnelled TCP stream lives inside the helper process that carried it. Nor can an addition leave the old helper running beside the new one: with two helpers holding the controller's key, relayed tunnels through both failed within about 30 s, and new connections kept failing on and off (details in the [Parts 00–09 audit](parts-00-09-audit.md#follow-up-tailcat-key-rotation-and-browser-launch)).

The controller therefore **hands the connections off** before the restart (`tailcat_allow_changed` in the log, with how many sessions and not-yet-sessions were closed, how many workers answered, and how long it waited). While the old helper still runs, every connection that came through it is closed cleanly: a TLS `close_notify`, then a FIN on the controller's side of the local socket. The old helper carries that close to the worker, which sees it within a round trip of the tunnel. A connection counts as tunnelled when the helper process owns the other end of its socket, read from `/proc`, so direct-TLS sessions are never touched, even on loopback. This covers sessions and also connections still in their TLS handshake or hello: the controller keeps a small record for each connection from loopback until it is a session (a remote peer costs nothing), and a hand-off claims those the helper carries. Each claimed connection closes itself from its own thread, with the same `close_notify` and FIN, so its worker redials at once instead of waiting out its 15 s deadline for the welcome.

The helper is replaced as soon as every closed connection's worker has closed its end too, which shows the close was delivered, plus 100 ms for the helper to send its last packets, and after 600 ms at most. That is less than the worker's shortest reconnect back-off (1 s less its 25 % jitter), so a worker that saw the close cannot redial into the old helper. The worker reads the close as a deliberate end, not a failure, whether or not it had been welcomed: it redials on its shortest back-off, and it replaces its own helper (`tailcat_replaced`; a forward that had carried a session through the old helper took 23.7–70.3 s to carry the next one) 200 ms after the close, whatever that helper's age, so its own end gets out through the tunnel first. The next session then waits only for the restarted controller helper to answer, which took 3.2–4.3 s in 46 restarts of the bare helper. Batching changes still saves each connected worker those seconds per change.

**A close the tunnel loses.** The old helper resends a dropped close on its own retransmission clock, but only while it runs. A worker from this release says so in its hello (capability `HANDOFF_ANSWER`): it answers every delivered close before its forward goes. When every closed session's worker carries that bit, a close still unanswered at 600 ms was not delivered, and the controller keeps the old helper for up to 3 s for it. A worker that redials into the old helper in that time is closed the same way, because a new loopback connection makes the controller read the helper's connections again. With a worker older than this release in the change, or a connection still in its handshake, the helper goes at 600 ms as before: such a worker keeps a forward younger than 10 s, and one that redialled through it into a helper kept for 3 s was stuck for 21 s.

In the live suite (`an_allow_list_change_hands_tunnelled_sessions_to_the_new_helper`, about an hour), each path runs 64 handed-off changes of a settled session. They cost 3.30–4.29 s direct and 3.61–4.60 s through a relay only, from the change to the next welcomed session; the worker saw the close after 1.6–9.2 ms and 34–40 ms, and every close came back answered, so the old helper went after 106–114 ms and 167–179 ms. The same changes cut without a hand-off cost 18.0–20.6 s and 20.5–21.1 s (four each), because the worker noticed only at its heartbeat deadline. A change that meets the worker's connection held in its TLS handshake by a slow link cost 3.34–4.27 s and 4.14–4.62 s (ten each), where it cost 16.7–18.1 s before the hand-off covered it. A change during 800 ms of loss at the worker, whose close only the old helper's resend delivers, cost 4.7–5.6 s and 4.6–6.0 s (six each); before the old helper was kept for it, the direct ones cost 17.7–20.5 s. Those loss windows were ended by a timer thread and could run long; since the [closing verification](parts-00-09-audit.md#closing-verification-parts-0009) the kernel ends them at 800 ms, and such changes cost 5.53–5.70 s and 5.31–5.46 s, the close seen after 1.41 s and 0.95–0.99 s. A worker that behaves as one from before `HANDOFF_ANSWER` still cost 3.87–4.63 s, and the controller never kept the helper past 600 ms for it. The test asserts that every handed-off change is noticed within 500 ms (3 s through the loss) and costs less than 5.5 s (9 s through the loss), and that every close of a worker with the bit came back answered. A removal is handed off the same way: the removed worker's session closes at once, and the restarted helper no longer admits it, so it cannot get back in. Details and the before/after runs are in the [Parts 00–09 audit](parts-00-09-audit.md#follow-up-tailcat-hand-off-edges). The wire protocol is unchanged: an older worker reads the close as the end of its connection and reconnects under its own rules, and an older controller masks bit 8.

**Credentials.** Node keys and `tc…` addresses are treated as credentials: `Debug`/`Display` redact them and no log line carries them. The controller writes its address to `<data_dir>/tailcat/address` (`0600`, replaced atomically) and logs only `tailcat_listening` with that file's path; the file's content is the worker's `tailcat_address`. Two values do appear in helper argv, which other local users can read in `/proc/<pid>/cmdline`: the controller's address on the worker (`forward`, `ping`) and the admitted node keys (public keys) on the controller (`serve --allow=…`). The pinned helper has no file or environment input for either (it only reads `TAILCAT_DERPMAP_URL` and writes `TAILCAT_ADDR_FILE`), so hosts that share users should mount `/proc` with `hidepid`. The helper runs with an otherwise empty environment: `HOME` (its key directory) plus `SSL_CERT_FILE`/`SSL_CERT_DIR` when set, since a private relay's CA needs them; nothing else from Sentinel's environment reaches it. On Linux it is killed with its supervising thread (`PR_SET_PDEATHSIG`), so a SIGKILLed Sentinel does not leave a helper holding the tunnel.

**Key rotation.** Both identities rotate on the operator's command. `sentinel admin tailcat` runs on the role's own host, in a server or worker build, and reads that role's configuration file. Every rotation has an overlap window: the new key is admitted, or served, before the old one is dropped. Node keys move only through standard input and output, never argv. Standard error names files and worker ids, never a key or an address.

To rotate a worker's key:

1. On the worker, run `sentinel admin tailcat rotate --role worker --config worker.toml`. It generates a second client key beside the active one, then prints that key's allow-list line, `nodekey:<64 hex> wrk_<id>`, and nothing else to stdout. The running worker is not affected.
2. On the controller, pipe that line into `sentinel admin tailcat allow --data-dir <controller data dir>`. The command adds the line to `tailcat-allow` beside the worker's current line. The file is replaced atomically and stays owner-only. A key already listed for another worker is refused. The controller admits both keys at its next 10 s tick.
3. On the worker, run `sentinel admin tailcat commit --role worker --config worker.toml`. It first runs `tailcat ping` with the new key against `tailcat_address`, and refuses to switch unless the controller admits the key. It then switches keys by atomically replacing one owner-only file, deletes the old private key through the helper, and prints the new key's line again. The running worker restarts its helper on the new key within one probe interval (30 s); the old key stays listed until the next step.
4. On the controller, pipe the printed line into `sentinel admin tailcat retire --data-dir <controller data dir>`. That key becomes the worker's only listed key, and the old line is removed. Run this after the worker has switched, or that worker is cut off until it does.

To rotate the controller's key:

1. On the controller, run `sentinel admin tailcat rotate --role server --config server.toml`. It generates a second server key with the same region rule as the first. Within 10 s the running controller starts a second helper that serves the new key beside the active one, with the same port and the same allow list. That helper writes its address to `<data_dir>/tailcat/address.next` (owner-only).
2. Give that address to every worker as `tailcat_address`, and restart each worker (drain it first). Both addresses carry the link during this window.
3. On the controller, run `sentinel admin tailcat commit --role server --config server.toml`. It refuses to switch until `address.next` exists, because until then no worker can have the new address. On commit it switches keys, moves `address.next` over `address` and deletes the old private key. Within 10 s the helper that already serves the new key becomes the main helper, without a restart, so workers on the new address keep their tunnel. The old key's helper stops, and workers still dialing the old address lose their tunnel then.

`sentinel admin tailcat abandon --role server|worker --config …` deletes a staged key that has not been committed. Nothing in use changes, and the controller stops serving the staged key at its next tick.

Rotation leaves revocation unchanged. Every allow-list line names its worker, so `sentinel admin worker revoke` withdraws every key of that worker, including both keys of a worker in its overlap window, within one tick. All rotation state is under `<data_dir>/tailcat`, owner-only, and is written by atomic replacement. `active-key` names the helper key in use when it is not the default. `staged.nodekey` records a staged key, and `address.next` holds the staged key's address. `<data_dir>/tailcat/client-default.nodekey` (worker) and `default.nodekey` (controller) always hold the key in use. A commit interrupted after the switch finishes on a retry. The new helper key names appear in helper argv as `--key=rotated` or `--key=client-rotated`. They are names, not key material.

**Health.** A worker runs `tailcat ping` every 30 s: it proves mesh reachability and measures the path, and a helper that stops reaching the controller is replaced. A helper is judged only once it has run a full interval, and a failed probe replaces only the helper it probed — never a successor that started while the probe was in flight. The probe sends nothing through the forward, and a `ping` cannot show that the forward itself is stuck, because it runs as a fresh process each time. The data path's health is the Sentinel session itself. A control session (or connection) the controller closed cleanly, a hand-off, replaces the worker's helper 200 ms later whatever its age. A lost or refused one replaces it at once (`tailcat_replaced`), unless that helper started less than 10 s ago; a younger helper is left for the probe to judge, so that while the controller is down the worker does not kill each new helper before it could connect. Helper restarts back off from 1 s to 30 s across consecutive failures; a helper that reported readiness (or ran past its 60 s readiness deadline) resets the back-off, and a deliberate replacement — a new allow list, a failed probe, a lost session — starts the next helper at once. The helper carries only the link port (never `serve all`, an exit node, a shell or its file mode; those words are refused as modes, flag names or flag values, except inside an `https://` URL), and the worker binds loopback only.

**Self-hosted relay.** Run Tailscale's `derper` where both sides reach its TLS port (TCP; STUN on UDP 3478 is optional and only helps direct paths form), with a certificate the helpers trust — a public CA, or a private CA named by `SSL_CERT_FILE`/`SSL_CERT_DIR` in Sentinel's environment on both roles. Serve a DERP map naming it over `https` with a trusted certificate as well, and set `derpmap_url` (plus `region` when the map has several) on both sides; the map is trust material. The live suite (`crates/sentinel-link/tests/tailcat_live.rs`) runs this with `derper` v1.86.2 in manual certificate mode on the Podman bridge gateway, a private CA through `SSL_CERT_FILE` and direct UDP dropped: the link runs via `DERP(local)` only.

### Remote cache

`[remote_cache] enabled = true` (the default) is what makes the two Q08 halves line up: the controller keeps objects workers offer under `<data_dir>/remote-cache`, and a worker fetches, offers and resumes objects over its bulk connection. Set it to `false` on either side to make every remote lookup a local miss — a worker then never asks and never offers, and a controller without the section serves nothing (`denied`). A local cache hit never touches the link in any configuration.

With the helper enabled, the worker's `Transport` telemetry carries the helper's version, the path its first `tailcat ping` reported (`Relay` for a pong via DERP, `Direct` for one from an `ip:port`, `Unknown` when the probe failed or said neither — never guessed) with that pong's own latency as the seed RTT, then the control session's measured round-trip time. Later probes keep the helper's own telemetry current; the link reports the path measured at start (see [worker link](worker-link.md)).

## Run the processes

On Linux, use independent terminals and writable absolute paths:

```sh
./target/release/sentinel server --data-dir "$PWD/data/controller" --check
./target/release/sentinel worker --data-dir "$PWD/data/worker" --check
```

Start the controller in one terminal:

```sh
./target/release/sentinel server --data-dir "$PWD/data/controller"
```

Start the worker in another:

```sh
./target/release/sentinel worker --data-dir "$PWD/data/worker"
```

Alternatively use `--config examples/server.toml` or `--config examples/worker.toml`, overriding `--data-dir` for a development account. The server process never starts the worker process. The server listens for workers on `listen` and logs `link_listening` with the address and the fingerprint workers pin, and answers the [API](api.md) on `api_listen` (`api_listening`); a worker with `controller`/`controller_fingerprint` configured connects, enrolls on its first hello with the secret in `enrollment_file`, and reconnects with back-off thereafter. See [worker link](worker-link.md#processes). The worker runs jobs only with rootless Podman on cgroup v2 available to its account ([development](development.md#linux-executor-work-f05f07-and-w03-onward)); it logs `executor_ready` with the runtime, or `executor_unavailable` and declines offers.

## Host-local administration

`sentinel admin` acts on the controller's own host, against `<data_dir>/metadata.sqlite`. Its authority is filesystem access to that database, not a session, and it is built into the Linux `server` binary only.

```sh
printf '%s' "$OPERATOR_PASSWORD" | ./target/release/sentinel admin bootstrap     --data-dir "$PWD/data/controller" --username root --display-name "Root Operator"
./target/release/sentinel admin status --data-dir "$PWD/data/controller"
printf '%s' "$NEW_PASSWORD" | ./target/release/sentinel admin recover     --data-dir "$PWD/data/controller" --username root
```

Scoped, expiring API credentials are provisioned the same way, and the secret is the only thing written to stdout:

```sh
./target/release/sentinel admin token issue --data-dir "$PWD/data/controller" \
    --user root --name "laptop cli" --scope read,run --expires-in 7d > credential
./target/release/sentinel admin token list --data-dir "$PWD/data/controller" --user root
./target/release/sentinel admin token revoke --data-dir "$PWD/data/controller" --id tok_...
```

Passwords are read from standard input only; no subcommand accepts one in argv, and a terminal stdin is refused. `bootstrap` creates the database if needed and is refused once any active super admin exists; `status` and `recover` refuse a path with no database rather than creating an empty one. Exit code 2 covers every refusal. Linked external sign-in identities are inspected with `admin identity list` and removed with `admin identity unlink`; linking itself only follows a verified provider sign-in. `admin policy`, `admin invite` and `admin account` show and change the deployment's admission policy, issue and revoke one-time invitations, and decide pending applications. `admin key create` writes the owner-only `<data_dir>/master.key` that seals second-factor seeds, secrets and source credentials, and `admin key rotate|reseal` rotate it and re-encrypt under the active key so old keys can be retired ([sealed storage](sealed-storage.md)); the server refuses to start when sealed values exist and that key is missing or does not match; `admin mfa` and `admin session` inspect and remove an account's second factor and sessions. `admin backup create|list|verify|prune` and `admin restore` take, check and restore backups ([backup](backup.md)); `admin upgrade check` reports what starting a new release on the data directory would do, without migrating it ([upgrades](upgrades.md)); a new release's `admin` command migrates the database like its server would, after the same pre-migration copy; `admin tenant` creates, suspends and reactivates a namespace and `admin tenant quota|storage` shows and sets its storage quota and retention, or a repository's ([retention](retention.md)); `admin pool` registers pools and grants shared ones to tenants; `admin worker` issues one-time enrollments, lists and revokes workers; `admin source create|bind|show|revoke|hook-token|refresh-installation|bind-installation|remove-installation` binds repositories to approved remotes with sealed credentials, issues the repository's intake hook secret and manages GitHub App installations ([sources](sources.md), [intake](intake.md)); `admin intake list|purge` shows and retires durable event deliveries; `admin logs --attempt att_… [--follow]` prints an attempt's log from `<data_dir>/logs` ([logs](logs.md)); `admin cancel --job job_…|--run run_…` records cancellation ([cancellation](cancellation.md)). Admin commands open the database directly, so they run beside a **stopped** server — one controller owns the database; while it runs, use the [API](api.md) and `sentinel api …` instead. See [local authentication](local-authentication.md), [API credentials](api-credentials.md) [GitHub sign-in](github-sign-in.md) and [admission](admission.md), [step-up](step-up.md), [tenancy](tenancy.md) and [worker link](worker-link.md).

## Shutdown and output

- Ctrl+C / `SIGINT`, service-manager `SIGTERM`, and `SIGHUP` request a clean exit. SIGHUP is **shutdown**, not configuration reload.
- A handler is registered before directory initialization. A capacity-one notification channel retains a shutdown request during startup and coalesces repeated requests; the main thread blocks without polling while idle.
- Structured startup and lifecycle diagnostics go to stderr. Help, version and successful `--check` output go to stdout. Bootstrap CLI/configuration errors remain plaintext.
- The main thread closes the bounded I/O/CPU lanes (one second per lane) and drains internal diagnostics (500 ms). Incomplete lane shutdown or diagnostic sink failure returns exit code 1. The server then closes worker sessions and stops the dispatcher (2 s) and drains the metadata store (5 s; a stall is reported and exits 1, and the store keeps database ownership until the process exits). The worker closes its session from the shutdown thread, so no heartbeat has to elapse. Nothing executes yet (W03), so there are no jobs to cancel; leases and offers are rows the next start reconciles.
- Data directories and existing contents survive shutdown. Uncatchable termination such as SIGKILL cannot run cleanup.

| Exit code | Meaning |
|---|---|
| `0` | Help/version/check succeeded, or requested lifecycle shutdown completed |
| `1` | Runtime initialization, bootstrap task deadline, lifecycle failure or incomplete diagnostic drain |
| `2` | CLI usage error, unavailable role, or invalid/unreadable configuration |

## Verification

The integration tests invoke the actual executable. On Linux with role features, they check configuration precedence, no-write checks, malformed/oversized input, path validation, and each enabled role's initialization/clean exit under all three supported signals. They use temporary directories and bounded waits for lifecycle assertions. Linux tests require the standard `kill` command; they do not need Podman, GitHub, root, or network services.

```sh
cargo test --locked --workspace
cargo test --locked --workspace --features server
cargo test --locked --workspace --features worker
cargo test --locked --workspace --features server,worker
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Only the first test command applies to non-Linux builds. See [Rust foundation](rust-foundation.md) for the cross-target build contract and dependency boundaries.
