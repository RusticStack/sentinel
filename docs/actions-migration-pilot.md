# Guided migration on real workflows

The first run of the guided GitHub Actions migration ([workflow analysis](workflow-analysis.md),
[migration switch](migration-switch.md)) against workflows nobody wrote for it: the three
[pilot workloads](pilot-repositories.md) and one private Rust repository of the operator's
(`private-rust`). It drove the analyzer and the planner only — `analyze`, then `plan` for the
label, shadow, switch and disable phases — on each workflow file alone, with
`DockerHosts::MicrovmGuests`, the native path on and one digest-pinned image per OS. Nothing was
written to any repository and no job ran; the shadow run itself is AR11's (below).

Read on 2026-11-21 from each project's default branch (`private-rust` at `7311088`; the upstream
revisions were not recorded by that run, so this page is a reading, not a pinned contract).

## What the planner did

| Source | Workflows analyzed | Jobs | Moved and shadowed | Kept on GitHub |
|---|---|---|---|---|
| `private-rust` | 4 of 4 | 20 | 0 | 20 `expression` |
| cli | 10 of 15 | 26 | 7 | 2 `macos`, 17 `no_class` (job-level `uses:`) |
| ripgrep | 3 of 3 | 10 | 8 | 2 `macos` |
| gson | 6 of 6 | 9 | 9 | 0 |

- Every moved job went from `ubuntu-latest` to `sentinel-4vcpu-ubuntu-2404` with the stated change
  "`latest` is pinned to Ubuntu 24.04"; the shadow phase added one `sentinel / <job>` copy per move
  and the switch phase moved the same jobs. ripgrep's two macOS jobs are matrix jobs with a macOS
  cell; cli's 17 `no_class` jobs call reusable workflows and have no `runs-on:` of their own.
- The native plan was refused for **all** analyzed workflows, so the disable phase was unavailable
  everywhere and runner mode is the only path these repositories can take today. The reasons, most
  common first, over the 23 analyzed workflows: trigger filters a native trigger cannot express (12),
  an event with no native trigger (3), a job `if` (2), and one each for `pull_request_target`, a
  deployment environment, an action step, a local action, `continue-on-error` and an unresolved
  `${{ }}` label.

## Defects it found, and their fixes

| Defect | Fix |
|---|---|
| `cancel-in-progress: ${{ … }}` refused the whole file (`private-rust`) | [#125](https://github.com/RusticStack/sentinel/pull/125) |
| a shadow copy kept its original's job `concurrency.group`, so the pair could cancel each other | [#138](https://github.com/RusticStack/sentinel/pull/138) |
| the `runs-on:` cells of an include-only matrix were not resolved | [#127](https://github.com/RusticStack/sentinel/pull/127) |
| a job naming a class beside an unresolved expression label was moved instead of kept | [#134](https://github.com/RusticStack/sentinel/pull/134) |
| a matrix job whose cells all agree on one class was not shadowed | [#135](https://github.com/RusticStack/sentinel/pull/135) |

## Still open

Each is a finding with no fix yet; none is a defect in the sense of a wrong plan, because every one
keeps the job on GitHub or refuses the file with its path.

- **`ubuntu-slim`** (cli's two generated `*.lock.yml` files, below): GitHub's 1-vCPU container
  runner is not in label table version 1, so once those files load their jobs would be kept as
  `no_class`. Adding it moves the table to version 2, a compatibility entry.
- **`runs-on: ${{ vars.NAME || 'ubuntu-24.04' }}`** (`private-rust`, all 20 jobs): a variable with a
  literal fallback is an `expression`. The analyzer holds variable names, never values, so resolving
  it needs the repository's variables or a stated assumption that the variable is unset.
- **Refused files** (cli, 5 of 15): top-level `run-name` and `on.workflow_call.outputs` are outside
  the closed vocabulary; a matrix axis given as `${{ fromJSON(…) }}` is `expected sequence`; and two
  generated `*.lock.yml` files hold a scalar over the loader's 4,096-byte bound. The bound is the
  loader's own and stays; the other three are vocabulary to add.

## AR11: the shadow run, prepared

AR11 runs the shadow phase above on operator-controlled forks for a week of pushes and records the
runner-mode switch and its rollback. What is settled, and what it still needs:

- **Forks.** `KelpHect/sentinel-pilot` has no workflows, so it cannot carry a shadow. The run needs
  operator-controlled forks of ripgrep and gson (every Linux job moves) and of cli (7 jobs), with the
  App installed on each and nothing pushed upstream ([pilot workloads](pilot-repositories.md)).
- **What is shadowed.** ripgrep `wasm`, `rustfmt`, `docs`, `benches`, `fuzz_testing`, `publish`,
  `create-release`, `build-release-deb`; all nine gson jobs; cli `bump-go`, `CodeQL-Build`,
  `copilot-setup-steps`, `dispatch`, `govulncheck` (two workflows), `lint`. Jobs that run only on tags,
  schedules or dispatch produce pairs only when those events happen in the window, and the record
  says which did not.
- **The record.** One `sentinel.migration-parity/1` report per fork over the window's commits
  ([shadow parity](shadow-parity.md)), committed with source labels anonymized and no installation
  ID, plus the switch (labels swapped, required checks read back unchanged) and its rollback
  ([migration switch](migration-switch.md)).
- **Needs.** A worker registering runners that GitHub can reach, on a verification host
  (AR03's egress gate, AR04 for the jobs that need Docker), and the forks above. Until both exist
  AR11 stays open.
