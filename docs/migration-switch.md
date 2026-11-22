# The migration switch

A guided migration proves itself in shadow mode and then takes the work over: the copies go, the
originals move, and the merge gate stays exactly where it was
([plan 16.5](../plan.md#165-guided-github-actions-migration)). This page is what each path's switch
changes, how the required checks are read and — only with a tenant's opt-in — written, and what this
release can and cannot show.

## What the switch is, per path

| Path | The switch | What it moves |
|---|---|---|
| Runner mode | one pull request that drops the shadow copies and moves the originals' `runs-on:` labels | no job name and no check name: the copies were `sentinel / <original>` and non-required, and the originals keep their ids and `name:` values |
| Native path | the required status checks that gate a merge, then one pull request that disables the replaced workflow jobs | the required contexts a replaced job answered become the checks Sentinel publishes for it; the workflow job is disabled with `if: ${{ false }}` and keeps its name |

Runner mode needs no settings change at all, which is why it is the default. A job whose `runs-on:`
becomes a Sentinel label reports the same check name it always did, so branch protection naming that
check is satisfied by the run that replaces it. The copies the shadow phase added are non-required by
construction — every one is named `sentinel / <original>`, and the prefix is the one every per-job
check carries ([shadow parity](shadow-parity.md#what-a-pair-is)) — so dropping them removes checks
nothing required.

The native path is the one that moves a gate. A disabled job reports `skipped`, which a required check
counts as satisfied, so leaving the original required would let a merge through on a check Sentinel
never computed. The switch therefore replaces each replaced job's required context with the check
Sentinel publishes, and only then disables the job.

## Reading the required checks

The reads are `sentinel-github`'s `protection` module:

- `GET /repos/{owner}/{repo}/branches/{branch}/protection` states branch protection's own
  `required_status_checks` (`strict` and the contexts). A branch GitHub answers `404` for is
  unprotected, which is an empty set rather than an error; protection that requires no check states
  `required_status_checks: null`, which is the same empty set. Both of GitHub's context shapes are
  read — the older `contexts` array and the newer `checks` array — and unioned.
- `GET /repos/{owner}/{repo}/rules/branches/{branch}` states every rule that applies to the branch,
  the ones a repository or organization ruleset contributes included, and
  `GET /repos/{owner}/{repo}/rulesets` names the rulesets those rules came from. A context a rule
  states is reported in `from_rulesets`, apart from the ones branch protection states.

The answer is the union, sorted and deduplicated, with the rulesets that require a check named in the
order they were read. Both reads take a token minted with repository `administration`
([GitHub App](github-app.md#migration-permissions)), which GitHub answers these endpoints only to and
which is the same token the native path's write uses: one client reads and writes a branch's
protection for the switch and for its rollback alike (`sentinel-github::rollback`), and this step adds
the ruleset read and the change on top. A token that comes back without the grant is the grant's
answer, not a failure — the runner-mode switch refuses its step rather than proving a gate it could
not read, and the native path states `permitted.administration: false`.

### The change, exactly

Each required context belongs to a replaced job when it is the job's `name:` (its check name), or —
for a job that states no name — its id, or when it starts with `<name> (`, which is how GitHub writes
a matrix cell: cell `1.24` of job `build` reports `build (1.24)`. A matched context is replaced by
`sentinel / <the context>`, so the matrix pair stays a pair
([shadow parity](shadow-parity.md#what-a-pair-is)); a context no replaced job answers — an external
service's, another workflow's — is left exactly as it was. The change states the contexts added, the
contexts removed, and the set the two produce, and the set is sorted, so the same settings and the
same plan produce the same preview byte for byte.

A context the change removes that only a ruleset states is refused, and the refusal names it: this
deployment does not edit a ruleset, and a preview that claimed it would is worse than none. Additions
always land in branch protection, whose set unions with every ruleset's.

## Applying it: the opt-in

Sentinel changes a branch's required checks only when the tenant asks it to, twice over:

- **The tenant's opt-in.** `tenants.migration_settings` is a switch of its own, off until an
  administrator turns it on, set in the same request as the migration switch
  (`PUT /tenants/{slug}/migration` with `settings`) because the two are one decision. Off is the
  default and the safe path: the switch answers the preview, a person applies it, and the next
  request with `verify` compares the result with the preview.
- **The App's grant.** The write needs repository `administration` write, which the write's token is
  minted with and GitHub answers only when the installation holds it. With the opt-in on and the grant
  absent the switch says so, and the preview's `permitted` states it before anyone tries.

A branch with no protection rule at all is `"unprotected"`: creating protection is a person's
decision, not a migration's.

With both, the switch applies the change, reads the settings back, and answers whether the set read
back is the preview (`verdict: "equal"`) or not (`"moved"`, with both sets). It then opens the pull
request that disables the replaced jobs, because the jobs must not be disabled before the checks that
replace them are required.

## The plans the switch is made of

The change generator ([workflow analysis](workflow-analysis.md#the-change-generator)) has four phases,
and every one of them re-analyses the text it produced and refuses a plan whose result is not what it
stated:

| Phase | What it writes | What it proves |
|---|---|---|
| `label` | the `runs-on:` lines of the jobs that move, and nothing else | the jobs that move landed on their class with every other recorded fact unchanged (H03, H04) |
| `shadow` | one non-required copy per migrating job beside the unchanged original: id `sentinel-<id>`, `name: sentinel / <original>`, the original's own labels, steps, matrix and needs (a copy waits for the copy of a migrated dependency, and for the original of one that stays); a job-level `concurrency:` group becomes `sentinel-<group>`, so a copy never queues behind its original or cancels it | every original is byte-identical and every copy analyses back as the job it stands for (H05) |
| `switch` | drops every copy and moves the originals' labels | the result is exactly the label plan of the unshadowed workflow, so the drop and the move cannot disagree |
| `disable` | `if: ${{ false }}` as the first key of every job a native pipeline replaced | every job keeps its id and name, every job that stays on GitHub is untouched, and the only recorded difference on a disabled job is the condition |

The switch phase refuses a workflow in which a surviving job still needs a copy: dropping it would
leave the workflow needing a job that no longer exists, and a migration does not rewrite someone's
dependencies to make its own edit land.

## The route, and what it costs

`POST /tenants/{slug}/repos/{name}/migration/switch` ([API](api.md#routes)) takes
`{action, commit, native?}`:

| Action | Path | What it does |
|---|---|---|
| `shadow` | runner mode | opens or updates the pull request that adds the copies |
| `switch` | runner mode | refuses when a required check names a copy, then opens or updates the pull request that drops the copies and moves the labels, then re-reads the protection and compares |
| `preview` | `native: true` | the exact required-check change and whether this deployment may make it; writes nothing |
| `apply` | `native: true` | makes the change, reads it back and compares, then opens or updates the pull request that disables the replaced jobs |
| `verify` | `native: true` | reads the protection and compares it with the preview, for the change a person applied |

The commit is required and is the one the plan is computed at. The workflow files are the commit's
own, read through the App's migration token, so the plan applied is the plan a preview at the same
commit and the same deployment showed; nothing the caller sends is trusted as content.

One request makes at most six GitHub calls — the workflow listing and one read per file, the branch
protection, one required-check write on `apply`, the commit and pull-request write, and the
protection read back — each bounded by the module that makes it, and every figure in the answer is
either what GitHub stated or what Sentinel recorded. The answer is `sentinel.migration-switch/1`
([compatibility](compatibility.md)): the mode, the revision, `settings` (what was read, the change,
what the change expects, what was read back and the verdict), `permitted` (the opt-in and the App's
grant), the pull request when there is one, and the jobs the plan shadowed, dropped or disabled.

What became of each attempt is one row in the repository's own source audit trail: `migration_switch`
when the copies went and the protection read the same after as before, `migration_switch_settings_moved`
when it did not, `migration_settings_applied` and `migration_settings_moved` for the native path's
write, `migration_settings_verified` when a person applied it and the comparison held, and
`migration_settings_refused` when the switch refused before any write. The tenant's opt-in changing is
the tenant audit trail's event 103.

## What this release verifies, and what it cannot

The tests are [`crates/sentinel-pipeline/tests/switch.rs`](../crates/sentinel-pipeline/tests/switch.rs)
for the three new phases, [`crates/sentinel-github/tests/protection.rs`](../crates/sentinel-github/tests/protection.rs)
for the reads and the change, [`crates/sentinel-store/tests/migration.rs`](../crates/sentinel-store/tests/migration.rs)
for the gate and its audit rows, and [`crates/sentinel-api/tests/migration_switch.rs`](../crates/sentinel-api/tests/migration_switch.rs)
for the route against the recorded GitHub fake.

They cover the row's gate: the settings read after the switch equal the preview on every fixture, and
the required-check set is proven unchanged by comparing the protection read before the switch with the
protection read after it, rather than by asserting that the switch does not touch it. They also cover
the refusals — a required check naming a dropped copy, a removal a ruleset states, an apply without
the opt-in or without the grant, a switch with nothing to do — and that each one leaves its audit row
and no write.

What they cannot cover, because it needs things this host does not have: a real App installation
reading a real branch's protection and rulesets, a real ruleset's shape across the organizations and
repositories GitHub serves it in, GitHub accepting a required-check write on a protected default
branch, and the row's own gate on the three pilot forks — the switch of each, with its settings
compared before and after. That is H06's pilot record, and this release states the residual rather
than claiming it.
