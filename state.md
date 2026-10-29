# Sentinel handoff state

Last updated: 2026-10-29
Branch: `main` at the merge of PR #3 (`30896d7`), in sync with `origin/main`.

Read this first in a new session, then [AGENTS.md](AGENTS.md) (the single source of
contributor rules) and the "Next task" and "Open items" sections of [TODO.md](TODO.md),
which stay authoritative. This file only records where the work stopped.

---

## 1. What is merged

- PR #1 and PR #2 (Part 24 correctness batches 1 and 2) are in `main`.
- PR #3 (`integration/part-24-20`) merged Part 20 (`part-20-web`: the TanStack Start web
  interface and one-click GitHub App setup) and the eleven Part 24 lane branches
  (`ws/api-auth`, `bench`, `cache`, `checks-s3-backup`, `cli`, `deploy`, `dispatch-link`,
  `host-mgmt`, `microvm`, `store`, `worker`). Every remote branch is contained in `main`.
- Migrations are one sequence, 56 to 63: `github_app`, `minted_grants_unattributed`,
  `delivery_authentication`, `link_admission`, `removal_tombstones`,
  `auto_join_generation`, `worker_enrollment_policy`, `host_policy`. Audit events 76/77
  (GitHub App) and 90-95 (worker and host) are in use.
- Merge-time decisions worth knowing:
  - The job `/tmp` is a directory beside the workspace on the same disk, and the storage
    guard (`quota::Guard`, several roots) charges it together with the workspace against
    `resources.disk`.
  - Secrets are released only to a run whose webhook delivery was authenticated at intake
    (migration 58, `provenance::may_receive_secrets`).
  - `workers::hosts` leaves out a worker revoked between the listing and its view.
  - Committed test PEMs were replaced by keys generated at run time (a guard test scans
    tracked files).
- The `TODO.md` row "Part 24 lane integration" holds the full list and the gate results.

## 2. Verification of the merged tree

Run on the reference verification host in a disposable checkout (never the production
tree): `fmt-check`, `lint-linux`, `lint` clean; `test-linux` 2,132 passed, 0 failed,
34 skipped; doc links clean; web typecheck, build, unit 24/24 and the browser test
(240/240 checks); the Podman suites as the rootless account 11 passed and the worker
`end_to_end` test passed.

Not run on this tree: the browser flow through GitHub's real pages (U17, needs a
registered App), `cargo licenses` (`cargo-deny` is missing on the host), the KVM and arm64
suites.

## 3. What to do next (from TODO.md)

1. Code-only gaps: the Part 20 worker-enrollment page that Q11 lacks; the web service in
   the V02 container and compose examples; U17's fake-GitHub-web-origin browser flow and
   the activation-time log line in the canary.
2. Q13: real fleet verification on the three hosts (needs Q11 and Q12).
3. The required Part 23 (microVM) gate runs on the KVM host.
4. B09 reliability and performance runs (needs Q13 and a quiet host).
5. Remaining Part 14 measurements (B04a, B05, B06, B07 support work).
6. B11, the Blacksmith comparison. **Blocked by: Blacksmith benchmark access.**
7. Close Part 24, then Part 15 release qualification (V01 also needs a Windows
   verification host for the CLI smoke test).

After v0.1: Part 25 (runner mode) first, then Part 21; Part 23's Windows guests before
Part 17; Parts 18, 19 and 22 are open; Part 16 is a backlog.

Needs the owner: a Windows verification host, Blacksmith access, and the RW02-RW10/RW12
items marked "Blocked by" (mostly measurements waiting for a quiet host window).

## 4. State outside the repository

- Part 14 data on the reference host is kept on purpose (`/srv/sentinel-p14-*`, the `p14*`
  files in `/srv/sentinel-runs`, and the bench account's home directory): Part 14 is still open. Do not
  delete it until the owner says Part 14 is closed.
- The lane build output and checkouts under `/var/tmp` on the reference host were deleted;
  a new gate rebuilds from scratch (budget the time).
- The shared verification lock is `/var/tmp/sentinel-verify.lock` (`flock`).
- The Windows workstation's lane worktrees and scratch were removed. A stash named
  "local TODO.md edit superseded by main" exists only in the workstation clone; it holds
  nothing that `main` lacks.

## 5. Rules that matter (also in AGENTS.md and the owner's habits)

- Tests and benchmarks run only on the designated Linux verification hosts, never on a
  workstation or in WSL. Local work stops at formatting, `cargo check`/lint and
  `pnpm typecheck`. If you are the one running on the verification host, use a disposable
  checkout under `/var/tmp`, `flock` the shared lock, `nice -n 19 ionice -c3`, bounded
  `CARGO_BUILD_JOBS`, and detached runs (`setsid nohup`) for anything long.
- Never touch production data, services or checkouts on a shared host. Never use
  `pkill -f`; stop processes by PID. Do not start a second heavy build while one runs.
- Commits are authored and committed as `KelpHect <kellhect@gmail.com>`. No co-author
  trailers and no AI attribution in commits; disclose AI-written work in the PR
  description (model and harness). Prefer a local merge over `gh pr merge`. Stage only the
  files you changed.
- Never print or commit host addresses, account names, credentials, keys or installation
  IDs; use the class labels (`reference-host`, `kvm-host`, `arm64-host`) in docs.
- Versioned contracts (pipeline schema, run spec, migrations, error/explain schemas,
  cursors, worker protocol) change only with an entry in `docs/compatibility.md`.
- For UI changes, run the unit and browser suites; typecheck alone is not evidence.
- Do not claim a result that was not run; record what was not verified.
