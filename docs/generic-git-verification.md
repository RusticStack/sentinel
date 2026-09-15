# Generic Git intake, verified against live forges (G08)

G08 adds no subsystem; it proves the G01–G03 and G07 machinery end to end
against real self-hosted forges and a bare repository — no provider APIs, only
`git`, `ssh`, `https`, the shipped `examples/hooks/post-receive` hook and the
poll lane.

## Fixture matrix

All forges run as containers on the pilot host (WSL2, `sentinelbench`); the
controller, worker and fixtures share one loopback. TLS for Gitea/Forgejo is a
local CA; every binding carries the CA PEM or a pinned `known_hosts` line.

| Fixture | Access | Sentinel repo | Credential |
|---|---|---|---|
| Gitea `ci/app` | `https://127.0.0.1:3443` | `gitea-app` | `read:repository` token |
| Gitea `ci/app` | `ssh://git@127.0.0.1:3022` (built-in Go SSH) | `gitea-app-ssh` | deploy key + host pin |
| Forgejo `ci/app` | `https://127.0.0.1:3444` | `forgejo-app` | `read:repository` token |
| GitLab CE `root/gitlab-app` | `ssh://git@127.0.0.1:3023` | `gitlab-app` | SSH key + host pin |
| Bare repo | `ssh://sentinelbench@127.0.0.1:2222` (fixture `sshd`) | `bare-app` | SSH key + host pin |
| Gitea `ci/app2` | `https://127.0.0.1:3443` | `poll-app` | token + poll config (30 s) |
| Gitea `other/foreign` | `https://127.0.0.1:3443` | `foreign-app` | second user's token |

Hooks: `post-receive.d/sentinel` under each forge's managed hooks directory
(Gitea/Forgejo), `custom_hooks/post-receive` under Gitaly (GitLab), plain
`hooks/post-receive` on the bare repo. GitLab's container is bridged, so its
hook reaches the loopback API through a TCP forwarder on the bridge gateway —
the hook itself is unmodified.

## What was exercised live

| Scenario | Evidence |
|---|---|
| hook → pass (Gitea HTTPS) | `dlv_68aa5ff2` → `run_a778a94c` `passed`, both jobs, `trigger=push` |
| hook → fail | `run_8141ddb8` `failed/command_failed`; dependent job `skipped` |
| hook → config error | `dlv_ad95c259` settled `failed:pipeline_invalid` |
| hook → pass (Forgejo) | `run_a560def8` `passed` |
| hook → pass (bare SSH) | `run_13faf819` `passed` |
| hook → pass (GitLab SSH) | `run_0257d18a` `passed` |
| manual dispatch (Gitea SSH binding) | `run_65e80651` `passed`, `trigger=manual` |
| poll → pass | push → `poll_observed moved:1` → `dlv_5b53c613` → `run_d23ecc66` `passed` |
| cancel mid-run | `run_5647f252` `canceled`, both jobs `canceled`, via API while the controller stayed up |
| rerun | `job_a379e7b9` rerun → new attempt → `passed` |
| tag ref, push-only pipeline | `dlv_a5e71002` → `ignored:no_trigger` (policy filtering honored) |
| duplicate delivery | identical body re-POST → `202 {"duplicate": true}`, same delivery id |
| ref deletion | synthetic transition → `ignored:ref_deleted`, settle 1 ms |
| credential revocation | token deleted → `retried:source_unreachable` with doubling backoff → `failed:resolution_attempts` after ~255 s; poll lane independently backed off `poll_failed` 1→2→4→8 min |
| credential rotation | binding rebound to a fresh token (`--expected` CAS v1→v2/v3) → next push `run_edb654ea` `passed`; poll lane resumed `unchanged` then detected a move → `run_4a684764` `passed` |
| controller restart | push while down spooled `1789471812962.json` in-repo; after restart `--flush` delivered it → `run_5d7af8ee` `passed`; poll cursor persisted (resumed `unchanged`, no baseline replay) |
| worker restart | graceful `shutdown_requested`/`link_stopped`, reconnect, queued job leased and passed |
| cross-repo hook secret | `gitea-app` secret on `bare-app` intake URL → `401 unauthenticated` |
| invalid secret | `401 unauthenticated` |
| cross-tenant API credential | token scoped to a second tenant → `401` on both `acme` and its own tenant's resources |
| remote substitution | manual dispatch naming a repo id rather than the bound remote → `403` via `validate_source` |
| foreign-credential binding | `foreign-app` (`other` user's token) intake → `run_2acf4087` `passed` |

## Timings (pilot host, wall-clock deltas from the store and API)

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

## What is still not covered

- GitLab was exercised over SSH only; the fixture serves plain HTTP on its
  admin port and `Binding::remote()` accepts `https://`/`ssh://` only — no
  GitLab HTTPS endpoint was stood up.
- Forgejo SSH was not bound; its HTTPS path is covered, and SSH is covered by
  Gitea (built-in server), GitLab and the bare `sshd` fixture.
- A forge-native PR/MR flow is out of scope by design for generic bindings;
  results are verified through the Sentinel API/UI surface only.
- The UI itself is a session SPA over the same API routes whose responses are
  recorded above.

## Verification

Executed 2026-09-15 on the pilot host (WSL2 Ubuntu 24.04, Docker, Podman 4.9.3,
fixture `sshd`, Gitea 1.27.3, Forgejo, GitLab CE 18.3.2) against the G07 build
`88dff98`. Fixture scripts live under `.local/g08/` (gitignored): PKI, forge
bring-up, provisioning, binding, hook installation, scenario drivers and the
evidence extraction (`evidence.py`, `timings.sh`).
