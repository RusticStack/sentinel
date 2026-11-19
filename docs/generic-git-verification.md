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

## Standing the fixtures up

`bench/g08-forges.py` creates the matrix above from containers on one loopback, so a binding written here can be reproduced rather than remembered. It needs Podman (rootless preferred) or Docker, `openssl`, `ssh-keygen` and `git`; it refuses a fixture before pulling anything when the host cannot carry it.

```
python3 bench/g08-forges.py up bare        # or gitea, forgejo, gitlab, all
python3 bench/g08-forges.py bind gitea https://sentinel.example/api/v1/intake/rep_... secret-file
python3 bench/g08-forges.py converge gitea # the bindings a controller needs, as JSON
python3 bench/g08-forges.py status
python3 bench/g08-forges.py down
```

What each fixture is, and what it hands back:

| Fixture | What it runs | Ports | Hands back |
|---|---|---|---|
| `gitea` | Gitea 1.27.3 over HTTPS with the fixture CA, its built-in SSH server, users and repositories `ci/app`, `ci/app2` | 3443, 3022 | CA path, a `read:repository` token file for the binding, a `write:repository` token file for the person pushing |
| `forgejo` | Forgejo over HTTPS, same layout | 3444, 3024 | CA path, the two token files |
| `gitlab` | GitLab CE; refused below 6 GiB of memory | 3445, 3023 | the SSH URL |
| `bare` | A minimal sshd-with-git image built from `bench/g08/ssh-git.Containerfile`, serving `/git/app.git` | 2222 | the deploy key path |

Two things the harness gets right that a hand-built fixture usually does not: every container runs with host networking, so a push's `post-receive` reaches a controller on the same loopback (a bridged container would need the forwarder the GitLab row used to); and `bind` writes the hook's environment beside every hook the fixture runs, owned by the forge's own user, with a spool directory that user may write — a hook that cannot spool fails a push instead of losing an event.

The secret is read from a file, never from the command line, matching the hook's own rule that it reaches `curl` on stdin and never appears in `ps`.

### What has been exercised from this harness

- **bare repository over SSH**: fixture raised, a repository pushed to it twice, and both pushes delivered a signed `202`-answering POST to a loopback listener carrying `delivery_id`, `ref`, `old_sha` and `new_sha`.
- **Gitea over HTTPS**: fixture raised with the local CA, the user, both repositories and both tokens created, the hook installed globally and into each repository, and the hook's delivery received by the same listener with the same body.
- Not exercised from this harness: Forgejo, and GitLab (which needs more memory than the host this was written on). The rows in [What was exercised live](#what-was-exercised-live) above remain the record for those combinations, from the 2026-09-15 run.

## What is not covered

- GitLab was exercised over SSH only; the fixture serves plain HTTP on its admin port and `sentinel_protocol::source::remote` accepts `https://` and `ssh://` only, so no GitLab HTTPS endpoint was stood up.
- Forgejo SSH was not bound; its HTTPS path is covered, and SSH is covered by Gitea (built-in server), GitLab and the bare `sshd` fixture.
- A forge-native PR/MR flow is out of scope by design for generic bindings; results were verified through the Sentinel API/UI surface only.

## Verification

Executed 2026-09-15 on a Linux verification host (Ubuntu 24.04, Docker, Podman 4.9.3, fixture `sshd`, Gitea 1.27.3, Forgejo, GitLab CE 18.3.2). The fixture scripts of that run were local and are not in the repository; from 2026-11-19 the fixtures are [bench/g08-forges.py](../bench/g08-forges.py), and the two rows it has been exercised on since are listed above.

`bench/test_g08_forges.py` covers the harness without a container: the bindings, the refusals, and its own self-test.
