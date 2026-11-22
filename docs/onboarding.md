# Onboarding

The path from an empty host to a first run, a first failure read and a first restore, in the order an operator meets them. Each step names the command or page, links the document that holds its contract, and says what has been verified. This is V03's text; the end-to-end walk on a fresh host is **not run yet** ([Verification](#verification)).

Two ways through the first steps exist and are equivalent: the host-local `sentinel admin` commands (authority is filesystem access to the controller's data directory, Linux `server` binary only) and the web interface. `D` below is the controller's data directory (`/var/lib/sentinel` under the shipped unit).

| Step | What | Contract |
|---|---|---|
| [1](#1-install-and-start-the-controller) | Install and start the controller | [deployment](deployment.md) |
| [2](#2-first-administrator) | First administrator | [admission](admission.md#first-run-setup) |
| [3](#3-tenant-pool-and-members) | Tenant, pool and members | [tenancy](tenancy.md) |
| [4](#4-github-app-and-repositories) | GitHub App and repositories, or a generic Git source | [GitHub App](github-app.md), [sources](sources.md) |
| [5](#5-enroll-a-worker) | Enroll a worker | [worker enrollment](worker-enrollment.md) |
| [6](#6-sign-in-from-the-cli-and-mcp) | Sign in from the CLI and MCP | [CLI](cli.md#authentication-and-profiles), [MCP](mcp.md) |
| [7](#7-a-secret) | A secret | [secrets](secrets.md) |
| [8](#8-a-run) | A run | [pipeline schema](pipeline-schema.md), [intake](intake.md) |
| [9](#9-inspect-a-failure) | Inspect a failure | [CLI](cli.md#commands) |
| [10](#10-back-up-and-restore) | Back up and restore | [backup](backup.md) |

## 1. Install and start the controller

Verify the release archive ([releasing](releasing.md)), then install it as [a systemd service](deployment.md#the-controller-as-a-systemd-service) or [a container](deployment.md#the-controller). Before the first start, create the master key as the service account: it seals source credentials, secrets and the GitHub App's keys, and it is backed up separately from the database ([backup](backup.md#the-master-key)).

```sh
runuser -u sentinel -- /opt/sentinel/bin/sentinel admin key create --data-dir /var/lib/sentinel
sentinel server --config /etc/sentinel/server.toml --check    # validates, starts nothing
systemctl enable --now sentinel-server
```

For anything beyond a loopback trial, put the controller behind [a TLS reverse proxy](deployment.md#tls-and-a-reverse-proxy) and set `public_url` to that origin: the session cookie, OAuth sign-in and the GitHub App all depend on it. A deployment with no public name follows [fully local operation](deployment.md#fully-local-operation) instead and skips the GitHub parts of step 4.

## 2. First administrator

A controller with no super administrator is in setup mode. Pick one:

- **Web wizard.** The controller writes a one-time token to `D/setup-token` (mode `0600`) and logs one `setup_required` line. Open the web interface, paste the token and choose the administrator, the registration policy and the instance name ([first-run setup without a shell](configuration.md#first-run-setup-without-a-shell)).
- **Host.** `printf '%s' "$PASSWORD" | sentinel admin bootstrap --data-dir D --username root`. The password is read from standard input; no subcommand takes one as an argument. It closes the same latch and voids an open wizard token.

`sentinel admin status --data-dir D` reports the super administrators and their `usr_` identifiers, which later `--actor` flags need. `sentinel admin recover --data-dir D --username root` resets a lost password on the host.

## 3. Tenant, pool and members

```sh
sentinel admin tenant create --data-dir D --slug acme                 # prints the tnt_ identifier
sentinel admin pool create   --data-dir D --name default --tenant acme
sentinel admin invite create --data-dir D --tenant acme --role admin  # reader, operator or admin; prints the secret once
```

A super administrator is **not** a member of a tenant: API reads under `/tenants/acme/…` answer `not_found` for it until the account joins, so issue yourself an invitation (or use the tenant's own administrator) before step 6. With mail delivery configured, `--email ADDRESS` queues the message instead of printing the secret ([admission](admission.md)). Who may register and who may create organizations is `sentinel admin policy show|set` (`invite-only` is the default registration policy).

## 4. GitHub App and repositories

**GitHub.** With `public_url` set, the master key present and none of `github-app.json`, `github-webhook.json` or `github-sign-in.json` in `D`, a platform administrator with a recent [step-up](step-up.md) creates the App from the web interface: GitHub registers it from a manifest, the controller seals its key, client secret and webhook secret, and the installation is bound to the tenant ([one-click GitHub App setup](github-app.md#the-flow)). The file-based alternative, and the only one for GitHub Enterprise Server, is [GitHub ingress](deployment.md#github-ingress). Repositories of a bound installation are then bound to sources ([sources](sources.md)).

**Any other Git remote.** A source is created and bound on the host, and its events arrive through the `post-receive` hook or bounded polling:

```sh
sentinel admin source create --data-dir D --actor usr_… --tenant tnt_… --name app
sentinel admin source bind --data-dir D --actor usr_… --repo rep_… --expected 0 < binding.json
sentinel admin source hook-token --data-dir D --actor usr_… --repo rep_…
```

The binding JSON (remote, allowed refs, pipeline path, trust and credential) is described in [sources](sources.md#commands); a remote is `https://` or `ssh://` only. [`examples/hooks/post-receive`](../examples/hooks/post-receive) is the hook.

A pull request from a fork is ignored by native intake (`fork_pr`); that is a [support limit](support-limits.md#product-limits), not a setting to change during onboarding.

## 5. Enroll a worker

Install the worker package as [a systemd service](deployment.md#a-worker-as-a-systemd-service) (preferred) or [a container](deployment.md#a-worker). Issue an enrollment for a pool:

- on the web page (Platform, Workers), which shows the secret once and offers the bootstrap script after checking its SHA-256;
- or on the controller host: `sentinel admin worker enroll --data-dir D --pool default [--transport direct|tailcat] [--cpu-millis N] [--memory-bytes N] [--disk-bytes N] [--priority N]`. The host command defaults to `direct`, a lifetime of one hour and priority 0.

Then, on the worker host, run the downloaded script as root with the secret in a root-owned `0600` file or on standard input, never as an argument:

```sh
sudo sh sentinel-worker-bootstrap.sh install --name build-1 --secret-file /root/enrollment
```

With `api_url` set in the controller's `[worker_bootstrap]` section the script runs `sentinel worker enroll`, which redeems the secret over HTTPS and writes `worker.toml`; without it the worker presents the secret on its first link hello ([worker bootstrap](worker-bootstrap.md#the-flow)). Confirm with `sentinel admin worker list --data-dir D --pool default` or, once signed in, `sentinel workers list`. The worker logs `executor_ready` when rootless Podman on cgroup v2 is usable by its account and `executor_unavailable` otherwise; `sentinel worker --config FILE --check` reports what is missing without starting.

Jobs have no network unless the worker sets `job_network = "egress"`.

## 6. Sign in from the CLI and MCP

```sh
sentinel auth login --server https://ci.example.com          # browser, authorization code with PKCE
sentinel auth login --server https://ci.example.com --device # approve a short code on another device
sentinel context use acme
sentinel auth status
sentinel doctor
```

The default scopes are `runs:read runs:write logs:read artifacts:read cache:read`; ask for others with `--scope` (step 7 needs `secrets:write`). Automation uses a [service account](cli.md#service-accounts) grant, or a host-issued credential: `sentinel admin token issue --data-dir D --user root --name ci --scope read,run --tenant acme` prints the secret once.

MCP over stdio reuses the profile: sign in, then have the MCP client start `sentinel mcp`. Stdio never opens a browser itself. Remote clients use the deployment's `{issuer}/mcp` endpoint with OAuth ([MCP](mcp.md#streamable-http)); which client registrations are accepted is `sentinel admin policy set --data-dir D --oauth-client-registration off|metadata|open` (`metadata` is the default).

## 7. A secret

```sh
sentinel auth login --server https://ci.example.com --scope "runs:read runs:write logs:read secrets:write"
sentinel secret set DEPLOY_TOKEN --repo app --file ./token     # or --stdin, or the hidden prompt
sentinel secret bind DEPLOY_TOKEN --repo app --job deploy
```

A value is never an argument and cannot be read back. A job receives a secret only through a binding; `--from-tenant` binds a tenant-wide secret (one set without `--repo`), which must first be allowed in the repository with `sentinel secret allow NAME --repo REPO`. Which runs receive bound secrets is in [secrets](secrets.md#who-may-cause-a-delivery): a manual dispatch whose pipeline declares secrets is refused.

## 8. A run

Commit a `.sentinel.yml` and check it offline on any platform:

```sh
sentinel pipeline validate .sentinel.yml
sentinel pipeline explain .sentinel.yml
```

A push or pull request on a bound repository starts a run through intake. A manual run is:

```sh
sentinel run dispatch --repo app --pipeline .sentinel.yml --source https://git.example.com/acme/app.git --sha <commit>
sentinel wait RUN          # exit 0 passed, 8 finished otherwise, 7 deadline
```

Images are pinned `name@sha256:…`; a host without outbound network needs them in the worker account's Podman store beforehand ([fully local operation](deployment.md#fully-local-operation)).

## 9. Inspect a failure

```sh
sentinel status RUN                         # the run and its jobs
sentinel log show ATTEMPT [--step N]        # the log as the job wrote it
sentinel log search ATTEMPT --text "error"
sentinel cache show ATTEMPT                 # hit or miss reason per cache record
sentinel queue                              # waiting jobs and why each is waiting
sentinel job rerun JOB
```

The same views are on the run page of the web interface, and through MCP's bounded diagnosis tools ([MCP](mcp.md#bounded-diagnosis-and-rerun)). On the controller host, without a session, `sentinel admin logs --data-dir D --attempt ATTEMPT` prints an attempt's log, and `sentinel admin diagnostics --data-dir D` prints a sanitized bundle of a stopped controller's data directory.

## 10. Back up and restore

A running controller backs itself up on its `[backup]` schedule (`dir` outside the data directory); a stopped one is backed up from the host. Keep `master.key` somewhere else:

```sh
sentinel admin backup create --data-dir D --to /mnt/backup/sentinel   # controller stopped
sentinel admin backup verify --dir /mnt/backup/sentinel
sentinel admin backup rpo    --dir /mnt/backup/sentinel               # exit 2 when the newest is older than --limit-secs (3600)
```

Rehearse a restore on a replacement directory before relying on it. The target must be empty and the controller must not run:

```sh
sentinel admin restore --from /mnt/backup/sentinel --key /secure/master.key --data-dir /var/lib/sentinel
sentinel server --config /etc/sentinel/server.toml
```

What a restore keeps and loses is in [restoring](backup.md#restoring). Upgrades follow [upgrades](upgrades.md): `sentinel admin upgrade check --data-dir D` first, on a stopped controller.

## Verification

**The whole path has not been walked end to end on a fresh host.** That walk closes V03 in Wave 6; until then this page is a guide assembled from the per-area documents, and each step's evidence is the evidence of the document it links.

| Step | Recorded evidence | Not run |
|---|---|---|
| 1, 3, 5, 8 (host commands, generic Git source over SSH, one worker, one run) | The local-mode check on the reference host ([fully local operation](deployment.md#checking-it)) | A second machine, Tailcat, an `https://` source |
| 2 (web wizard) | [web interface](web-ui.md#verification) | On a deployed controller behind the shipped proxy configuration |
| 4 (GitHub App) | Tests against a loopback GitHub double ([GitHub App](github-app.md#verification)) | The real github.com pages (owner prerequisite X3) |
| 5 (script enrollment, web page) | [worker bootstrap](worker-bootstrap.md#verification), [worker enrollment](worker-enrollment.md#verification) | The real three-host fleet (Q11 to Q13, Wave 4) |
| 6 (CLI and MCP sign-in) | [CLI](cli.md#verification) | A desktop browser launch and real MCP clients (X7) |
| 10 (restore) | [backup](backup.md#tests) | The drill at the 100 GiB objective (R04, Wave 2) |
| 1 to 10 as one sequence | **None. Blocked by: Wave 6's needs (every earlier wave)** | Everything |

Limits an operator meets on this path are collected in [support limits](support-limits.md).
