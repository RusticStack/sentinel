# Generic Git intake, verified against live forges

Generic Git intake was exercised end to end against real self-hosted forges and a bare repository, with no provider APIs: only `git`, `ssh`, `https`, the shipped `examples/hooks/post-receive` hook and the poll lane.

## Fixture matrix

All forges ran as containers on an unprivileged Linux verification account; the
controller, worker and fixtures shared one loopback. TLS for Gitea/Forgejo is a
local CA; every binding carries the CA PEM or a pinned `known_hosts` line.

| Fixture | Access | Sentinel repo | Credential |
|---|---|---|---|
| Gitea `ci/app` | `https://127.0.0.1:3443` | `gitea-app` | `read:repository` token |
| Gitea `ci/app` | `ssh://git@127.0.0.1:3022` (built-in Go SSH) | `gitea-app-ssh` | deploy key + host pin |
| Forgejo `ci/app` | `https://127.0.0.1:3444` | `forgejo-app` | `read:repository` token |
| GitLab CE `root/gitlab-app` | `ssh://git@127.0.0.1:3023` | `gitlab-app` | SSH key + host pin |
| Bare repo | `ssh://git@127.0.0.1:2222` (fixture `sshd`) | `bare-app` | SSH key + host pin |
| Gitea `ci/app2` | `https://127.0.0.1:3443` | `poll-app` | token + poll config (30 s) |
| Gitea `other/foreign` | `https://127.0.0.1:3443` | `foreign-app` | second user's token |

Hooks: `post-receive.d/sentinel` under each forge's managed hooks directory
(Gitea/Forgejo), `custom_hooks/post-receive` under Gitaly (GitLab), plain
`hooks/post-receive` on the bare repo. GitLab's container is bridged, so its
hook reaches the loopback API through a TCP forwarder on the bridge gateway —
the hook itself is unmodified.

## Fixtures

The five container rows above are raised by `scripts/git-fixtures/`, one script per row, from an
unprivileged account and with no root anywhere. Each script creates the forge's user, the private
repository with a first pipeline commit, and the row's hook carrying the shipped
[`examples/hooks/post-receive`](../examples/hooks/post-receive) — the shipped file, copied in, never
a fixture-local variant — then writes the binding a verification run applies.

| Script | Container | Ports | Hook | Binding credential |
|---|---|---|---|---|
| `gitea-https.sh` | Gitea 1.27.3 | `3443` HTTPS | `hooks/post-receive.d/sentinel` | `read:repository` token |
| `gitea-ssh.sh` | Gitea 1.27.3 | `3022` SSH, `3445` admin HTTP | `hooks/post-receive.d/sentinel` | deploy key + pinned known_hosts |
| `forgejo-https.sh` | Forgejo 17.0.2 | `3444` HTTPS | `hooks/post-receive.d/sentinel` | `read:repository` token |
| `gitlab-ssh.sh` | GitLab CE 18.3.2 | `3023` SSH, `8080` admin HTTP | `custom_hooks/post-receive` | SSH key + pinned known_hosts |
| `bare-sshd.sh` | Alpine 3.22 + sshd | `2222` SSH | `hooks/post-receive` | SSH key + pinned known_hosts |

Requirements: a rootless Podman (what `bench/` uses) or a Docker the account may drive — the
scripts prefer `podman` and fall back to `docker`, and `SENTINEL_FIXTURE_RUNTIME` names one;
`git`, `curl`, `openssl`, OpenSSH (`ssh`, `ssh-keygen`, `ssh-keyscan`) and `python3`. Every image
is pinned by digest, so only the first run pulls: 253 MiB for Gitea, 277 MiB for Forgejo and
5.8 GiB for GitLab CE unpacked (the pull itself is smaller), and the bare `sshd` image at 34 MiB is
built once from `sshd.Containerfile`. An absent runtime, a root account or an unusable runtime
exits `3` with the reason, before anything is pulled, and a taken port is refused before a container
is created.

```sh
scripts/git-fixtures/run.sh up                   # every fixture
scripts/git-fixtures/run.sh up gitea-https       # one of them
scripts/git-fixtures/run.sh status
scripts/git-fixtures/run.sh exercise             # push through each hook, verify the delivery
scripts/git-fixtures/run.sh down
```

`up` removes the fixture it is about to raise and starts again from an empty volume, so a second
run in a row gives the same working fixture and rotates its keys and tokens. State lives under
`${SENTINEL_FIXTURE_ROOT:-$XDG_STATE_HOME/sentinel-git-fixtures}/<fixture>/` (mode `0700`):

| File | Contents |
|---|---|
| `binding.json` | the JSON `sentinel admin source bind` reads: `remote`, `allowed_refs`, `pipeline_path`, `trust` (the CA PEM, or the pinned `known_hosts` line) and the credential. Mode `0600` |
| `bindings.sh` | the same addresses and paths as shell variables (`FIXTURE_REMOTE`, `FIXTURE_CA_PEM`, `FIXTURE_KNOWN_HOSTS`, `FIXTURE_SSH_KEY`, `FIXTURE_HOOK_ENV`, `FIXTURE_HOOK_INTAKE`), never the credential |
| `hook.env` | the `SENTINEL_INTAKE_URL` and `SENTINEL_HOOK_SECRET` the installed hook reads. Mode `0600` |
| `seed/` | a checkout whose first commit carries `.sentinel.yml` |
| `pat`, `push-token`, `read-token`, `client-key` | the fixture's own credentials, `0600`, so `run.sh push` can push without a password |

The token a binding carries is `read:repository`; the fixture's own pushes use a separate
`write:repository,write:user` token. The fixtures are not bound themselves: a verification run
applies `binding.json` with `admin source bind` and issues its own hook token, as
[deployment](deployment.md#fully-local-operation) describes. The secret a fixture writes
into `hook.env` is a fixed placeholder because nothing in the fixture validates it; point the hook
at a controller and it must be that repository's real `admin source hook-token`.

`run.sh exercise` needs no controller. It starts `listener.py` on `7099`, raises each requested
fixture, pushes twice through the fixture's own credential, and reads the listener's JSONL to
check that the hook delivered both pushes to its own intake route with the bearer secret, a JSON
content type, the pushed `old_sha`/`new_sha`, and a delivery id per push. `SENTINEL_FIXTURE_REUSE=1`
reuses a fixture that is already up. The hook posts to `host.containers.internal:<port>`: a
bridged container cannot reach another process's loopback, so a controller or listener on the host
must listen on the bridge gateway as well (`listener.py` binds both addresses under Docker).

`scripts/git-fixtures/selftest.sh` runs no container: it checks that every script parses, that
`up`, `down` and `status` each exit `3` naming the runtime when none is on `PATH`, that a named
but absent runtime is refused, that no script asks for `sudo` and that every image is
digest-pinned. `crates/sentinel/tests/git_fixtures.rs` runs it, and holds this page and the
scripts to the same fixture names and hook locations.

## What was exercised live

- Hook delivery to a passing run on Gitea (HTTPS), Forgejo, a bare repository over SSH and GitLab over SSH, with `trigger=push`.
- A failing step failing its run (`command_failed`) and skipping its dependent job; a pipeline error settling the delivery `failed:pipeline_invalid`.
- Manual dispatch through an SSH binding (`trigger=manual`); poll detection of a push (`poll_observed moved:1`) leading to a passing run.
- Cancel mid-run through the API with the controller staying up; rerun of a job into a new attempt.
- A tag push to a push-only pipeline settling `ignored:no_trigger`; a ref deletion settling `ignored:ref_deleted`; an identical re-POST answering `202 {"duplicate": true}` with the same delivery id.
- Credential revocation: `retried:source_unreachable` with doubling backoff, then `failed:resolution_attempts` after about 255 s, while the poll lane independently backed off `poll_failed` 1, 2, 4, 8 min.
- Credential rotation: rebinding to a fresh token (`--expected` compare-and-swap) resumed both push runs and the poll lane.
- Controller restart: a hook delivery spooled in the repository while the controller was down was delivered by `--flush` afterwards; the poll cursor persisted, with no baseline replay.
- Worker restart: graceful `shutdown_requested`/`link_stopped`, reconnect, and the queued job leased and passed.
- Refusals: another repository's hook secret and an invalid secret answer `401 unauthenticated`; an API token scoped to another tenant answers `401`; a manual dispatch naming a repository id instead of the bound remote answers `403` through `validate_source`.
- A binding that carries another user's token ran its own repository.

## Timings (pilot host, wall-clock deltas from the store and API)

No record: observed once on 2026-09-15 on a pilot host; no raw timings or fixture scripts are committed. These figures are not a baseline for G08 re-verification.

- **Trigger detection** — hook deliveries reach intake inside the push's own
  `post-receive` window (the push returns after the `202`). Poll detection is
  bounded by the configured interval plus jitter: 18.4 s and 27 s observed
  against a 30 s interval.
- **Source resolution + admission** — `received_ms → settled_ms`: 4–5 ms for
  hook deliveries (binding check, `file_at` pipeline read, dispatch); 173–233 ms
  for poll deliveries (the `ls_remote` sits inside the same pass); 1 ms for a
  deletion; 4 ms for a pipeline rejection. A dead credential costs
  `254,662 ms` end to end — bounded retries, then a terminal explicit failure.
- **Dispatch** — `queued_ms → leased_ms`: 1–311 ms; one outlier of 24.9 s is a
  run dispatched while its only worker was restarting — it leased the moment
  the link returned.
- **Execution** — `leased → terminal`: ~0.75–0.98 s per job (busybox image,
  warm cache).
- **Polling overhead** — `git ls-remote --heads --tags` against the poll
  remote: 72/91/120 ms per pass; steady cadence ~32 s on a 30 s interval
  (interval + ≤¼ jitter).

## What is not covered

- GitLab was exercised over SSH only; the fixture serves plain HTTP on its admin port and `sentinel_protocol::source::remote` accepts `https://` and `ssh://` only, so no GitLab HTTPS endpoint was stood up.
- Forgejo SSH was not bound; its HTTPS path is covered, and SSH is covered by Gitea (built-in server), GitLab and the bare `sshd` fixture.
- A forge-native PR/MR flow is out of scope by design for generic bindings; results were verified through the Sentinel API/UI surface only.

## Verification

Executed 2026-09-15 on a Linux verification host (Ubuntu 24.04, Docker, Podman 4.9.3, fixture `sshd`, Gitea 1.27.3, Forgejo, GitLab CE 18.3.2). The fixtures that produced those runs were local to that host. `scripts/git-fixtures/` now commits the containers, users, repositories and hooks they raised, so the transport side of the matrix can be raised again; the controller-side work above still cannot.

Re-verified 2026-11-19 on an unprivileged x86_64 Linux account (Ubuntu 24.04, Docker 29.9.3, Gitea 1.27.3, Forgejo 17.0.2, GitLab CE 18.3.2, Alpine 3.22 with OpenSSH): `scripts/git-fixtures/run.sh exercise` raised all five fixtures and verified two hook deliveries from each — the shipped hook's bearer secret, JSON content type, its own intake route and the pushed `old_sha`/`new_sha`, with a distinct delivery id per push — for Gitea over HTTPS and over its built-in SSH, Forgejo over HTTPS, GitLab CE over SSH and the bare `sshd` repository. That run used Docker because the machine also running it denied unprivileged access to `/dev/net/tun`, which a rootless Podman needs to give a container a network; the scripts still prefer rootless Podman, which is what the bench harnesses use.

Not reproduced by the committed fixtures: every row of "What was exercised live" that needs a controller and a worker — admission, dispatch, execution, failure settlement, cancellation, rerun, the poll lane, credential revocation and rotation, controller and worker restarts, and the refusals — and the timings above, which remain the 2026-09-15 observation and were not measured again. The matrix's `ci/app2` (poll) and `other/foreign` (a second user's repository) rows are two further repositories on the Gitea HTTPS fixture, not separate fixtures: the scripts raise the transport rows, so those two are created on a running `gitea-https` fixture with `gitea admin user create` and the API.
