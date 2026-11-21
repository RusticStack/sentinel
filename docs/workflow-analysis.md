# GitHub Actions workflow analysis

[`crates/sentinel-pipeline/src/workflow`](../crates/sentinel-pipeline/src/workflow) reads a repository's `.github/workflows/*.yml` at a pinned commit and builds the inventory guided migration works from ([plan 16.5](../plan.md#165-guided-github-actions-migration)). It is deterministic and bounded, involves no model, and decides every job and every construct: a job either runs on a Sentinel runner class or stays on GitHub's runners with a stated reason, and every construct is translatable, translatable with a stated change, or unsupported with its reason. The compiler remains the authority for anything the native path generates; this stage only classifies.

Two tables are versioned contracts ([compatibility](compatibility.md)): the label table (version 1) and the native rule table (version 1). A table version is a promise that the same input classifies the same way with the same wording until the version moves.

## Input and loading limits

`analyze(revision, files, docker)` takes the commit's workflow files as `(path, text)` pairs and the deployment's own fact about Docker hosts. The revision must be a full lower-case hex commit id (40 or 64 characters), and every path must be a `.yml`/`.yaml` file directly under `.github/workflows/`; anything else is refused, as is the same path given twice.

Each file passes through the pipeline loader's limits ([pipeline schema](pipeline-schema.md#loading-limits)), so a hostile workflow is rejected as events arrive, before it is materialised. Anchors, aliases, tags, non-string keys and duplicate keys are errors with line and column, and the duplicate-key message never echoes the key.

| Limit | Value |
|---|---|
| File size | 256 KiB (`MAX_PIPELINE_FILE_BYTES`, the pipeline loader's own bound) |
| Nesting depth | 16 |
| Nodes | 10,000 |
| Key length | 128 bytes, scalar length 4,096 bytes |
| Workflow files per analysis | 64 (`MAX_WORKFLOW_FILES`) |
| Jobs per workflow | 256 (`MAX_JOBS`) |
| Steps per job | 128 (`MAX_STEPS`) |
| Triggers per workflow | 32 (`MAX_TRIGGERS`) |
| Matrix axes, values per axis | 16 (`MAX_MATRIX_AXES`), 256 (`MAX_MATRIX_VALUES`) |
| `runs-on:` cells per job | 256 (`MAX_MATRIX_CELLS`) |
| Permission scopes, service containers | 16 each |
| Secret and variable names per job, paths per cache or artifact | 64, 32 |
| Recorded name, label, path, key, event | 1,024 bytes (`MAX_TEXT_BYTES`) |

The workflow vocabulary is closed: a job or step key outside the documented set is `unknown key` with its path, never skipped, so a key the analyzer does not model can never be silently dropped from a migration. `run-name`, for instance, is refused rather than ignored.

## Inventory

One `Inventory` carries the revision, both table versions and one `Workflow` per file, sorted by path so the same files produce the same inventory in any order.

- **Workflow**: `path`, `name`, `triggers`, workflow `permissions`, `concurrency`, `env` names, `defaults`, the secret and variable names the workflow references, workflow-level constructs with their classification, and the jobs.
- **Trigger**: `event`, `branches`/`branches-ignore`, `tags`/`tags-ignore`, `paths`/`paths-ignore`, `types`, `crons` (a `schedule`'s expressions) and `inputs` (a `workflow_dispatch`'s input names).
- **Job**: `id`, `name`, `needs`, whether it states an `if`, `timeout-minutes`, `environment`, output names, a reusable-workflow `uses`, `permissions`, `concurrency`, `env` names, `defaults`, `continue-on-error`, the declared `runs-on` (`demand`), the `matrix`, `container`, `services`, `steps`, `caches`, `artifacts`, the secret and variable names it references, one `Cell` per `runs-on:` variant, and the job's constructs with their classification.
- **Step**: `id`, `name`, the `uses` reference or a run step, `shell`, `working-directory`, `continue-on-error`, whether it states an `if`, `timeout-minutes` and `env` names.
- **Action**: a `Repository` reference with its `version` and whether that version is a full commit id, a `Docker` image, or a `Local` path.

Values never enter the inventory. An `env:` value, a `with:` value, a `run:` script and a job `if` are scanned for `${{ secrets.NAME }}`, `${{ secrets['NAME'] }}`, `${{ vars.NAME }}` and `${{ vars['NAME'] }}` and only the names are kept; names are deduplicated in the order met, per scope. That is why a diagnostic or a stored inventory can be shown without redaction: it holds names, paths and keys, never a value, a token or a script.

### Matrices and `runs-on:` cells

A `runs-on:` label may reference `${{ matrix.<axis> }}`. The analyzer expands only the axes the labels actually name (a matrix used elsewhere does not widen the placement), substituting those axis values into every label. One job therefore yields one cell per `runs-on:` variant; a job with no matrix, or a matrix its labels do not name, yields exactly one cell with no axes. The cross product is bounded by `MAX_MATRIX_CELLS`; a larger one is refused, not truncated. A matrix with no axis, only `include` entries, is one combination per entry as on GitHub: the distinct values the entries give the keys the labels name are the cells, and an entry that does not state a named key leaves its label unresolved. `include` entries beside declared axes are recorded and do not widen the cells. An expression that is not a matrix reference the cell holds leaves that label unresolved and the cell stays on GitHub's runners as `expression`.

Axis values must be scalars, `include` and `exclude` entries must be mappings of scalars, and `fail-fast` defaults to `true` as in GitHub. A non-scalar axis value is refused with the axis path.

## The label table (version 1)

`LabelTable::V1::classify` resolves one job's declared `runs-on:` to a `RunnerClass` (`sentinel-<n>vcpu-<os>`, the same vocabulary runner mode accepts, [configuration](configuration.md#runner-classes)) or keeps the job. `change` is the stated difference when the class is not exactly what the label asked for; it is never silent.

| Label | Class | Stated change |
|---|---|---|
| `ubuntu-24.04`, `ubuntu-latest` | `sentinel-4vcpu-ubuntu-2404` | `ubuntu-latest` is pinned to Ubuntu 24.04 |
| `ubuntu-22.04`, `ubuntu-20.04` | `sentinel-4vcpu-ubuntu-2404` | the class runs Ubuntu 24.04 |
| `ubuntu-24.04-arm`, `ubuntu-24.04-arm64`, `ubuntu-22.04-arm` | `sentinel-4vcpu-ubuntu-2404-arm` | the class runs 24.04 |
| `ubuntu-24.04-<n>core` (also `-arm`) | `sentinel-<n>vcpu-ubuntu-2404` (`-arm`) | — |
| `windows-2025`, `windows-latest` | `sentinel-4vcpu-windows-2025` | `windows-latest` is pinned to Windows Server 2025 |
| `windows-2022`, `windows-2019` | `sentinel-4vcpu-windows-2025` | the class runs Windows Server 2025 |
| `windows-2025-<n>core` | `sentinel-<n>vcpu-windows-2025` | — |
| `blacksmith-<n>vcpu-ubuntu-2404` | `sentinel-<n>vcpu-ubuntu-2404` | — |
| `blacksmith-<n>vcpu-ubuntu-2204`, `-2004` | `sentinel-<n>vcpu-ubuntu-2404` | the class runs Ubuntu 24.04 |
| `blacksmith-<n>vcpu-windows-2025` | `sentinel-<n>vcpu-windows-2025` | — |
| `blacksmith-<n>vcpu-windows-2022`, `-2019` | `sentinel-<n>vcpu-windows-2025` | the class runs Windows Server 2025 |
| `sentinel-<n>vcpu-<os>` | itself | — |
| any label containing `gpu`, or starting `nvidia` | kept, `gpu` | Sentinel has no GPU class |
| `macos-*` | kept, `macos` | Sentinel has no macOS class |
| anything else (`self-hosted`, custom labels, unknown images) | kept, `no_class` | no Sentinel class matches |
| a `${{ }}` label nothing resolves | kept, `expression` | not a label set the analyzer can resolve |

Rules that settle the edge cases:

- A label set is decided by the labels that name a class. Two labels naming different classes satisfy no one runner and the job is kept as `no_class`.
- `runs-on:` written as a mapping with a `group:` is a named runner group — GitHub's own scaling concept, not a Sentinel class — so the job is kept as `no_class`.
- A job that needs a Docker daemon (a `container:`, a `services:` entry or a `docker://` step) needs a class a Linux microVM guest serves ([executor](executor.md), [plan 16.8](../plan.md#168-microvm-execution-on-kvm-hosts)). With `DockerHosts::MicrovmGuests` its class carries `requires_microvm`; with `DockerHosts::ContainerOnly`, or for any Windows class (no nested virtualization in a Windows guest), the job is kept as `docker`.

The class is always a label the worker vocabulary accepts: `RunnerClass::parse` of what the table produced returns that class, and its vCPU count is between 1 and 128.

## The native rule table (version 1)

`RuleTable::V1::classify` answers for each construct the inventory records. `Translatable` means the construct maps as it is; `WithChange` carries the change a generated pipeline makes; `Unsupported` carries the reason the job stays on GitHub's runners on this path.

| Construct | Rule | Change or reason |
|---|---|---|
| `on: push`, `pull_request`, `merge_group`, `workflow_dispatch` | translatable | — |
| `on: schedule` | unsupported | durable schedules do not exist yet (I02) |
| `on: workflow_call`, `workflow_run` | unsupported | reusable pipelines and workflow chaining are not in the schema ([pipeline schema](pipeline-schema.md)) |
| `on: pull_request_target` | unsupported | the privileged context has no native equivalent |
| any other event | unsupported | no native trigger exists for it |
| `permissions` | with change | the source credential's scopes replace `GITHUB_TOKEN`; no ambient token |
| `concurrency`, `env`, `needs`, `timeout-minutes`, `run`, `working-directory` | translatable | — |
| `defaults` | with change | steps run under sh or bash; `defaults.run` becomes the step's `shell` and `workdir` |
| `if` (job or step) | with change | a pipeline condition in the expression language, type-checked at compile time |
| `strategy.matrix` | with change | one declared job per matrix cell; a pipeline may declare the `matrix` itself, which version 2 of this table would generate ([pipeline schema](pipeline-schema.md#matrices)) |
| `container` | unsupported | needs a Docker daemon, which only a microVM sandbox offers (I08) |
| `services` | unsupported | needs a Docker daemon (I08); service containers are not in the schema ([pipeline schema](pipeline-schema.md)) |
| `environment` | unsupported | deployment environments and OIDC are not modelled ([pipeline schema](pipeline-schema.md)) |
| `outputs` | with change | a job's outputs become each step's declared `outputs` and the job's re-exported `outputs`, plain text in the run's record |
| `jobs.<id>.uses` | unsupported | reusable pipelines are not in the schema ([pipeline schema](pipeline-schema.md)) |
| `continue-on-error` | unsupported | a failing step fails its job |
| `shell: sh`, `shell: bash` | translatable | — |
| another `shell` | unsupported | only sh and bash are available |
| `actions/checkout` | translatable | the compiled checkout at the pinned revision |
| `actions/cache`, `actions/cache/restore`, `actions/cache/save`, `Swatinem/rust-cache` | with change | the action becomes a declared cache: a class, a key template and paths |
| `actions/upload-artifact` | with change | an artifact declared on the job, published at its end |
| `actions/download-artifact` | unsupported | artifact handoff between jobs (I04) |
| `actions/setup-*`, `dtolnay/rust-toolchain`, `actions-rs/toolchain` | with change | a digest-pinned toolchain image replaces the setup step |
| `docker/*` actions, `docker://` steps | unsupported | needs a Docker daemon (I08) |
| a local `./` action | unsupported | its definition is not part of the workflow |
| any other action | unsupported | an action runs only in runner mode |

Action classification reads the repository, case-insensitively, so `Swatinem/rust-cache@v2` and `swatinem/rust-cache@v2` agree. An action reference without a `@version` is refused by the decoder, because an unpinnable action cannot be recorded with its version.

## The pull request

`POST /tenants/{slug}/repos/{name}/migration/pull-request` applies the plan: the branch
`sentinel/migrate` from the analysed commit, the `runs-on:` diff as one commit, and the pull request
against the repository's default branch ([API](api.md#routes), which is where the request and
response shapes are). The body names the action (`open` or `close`) and, for `open`, the commit;
`{"action":"open","commit":"<40 or 64 hex digits>"}` and `{"action":"close"}` are the whole of it.
The tenant's administrator is who may run it, the same authority the migration switch takes, and the
write itself is what [`sentinel_store::migration::authorize`](github-app.md#migration-permissions)
gates: the switch, and what the installation the repository is bound through was last reported to
grant. A refusal is answered before any request reaches GitHub and leaves its audit row.

**What it reads.** The workflow files come from GitHub, not from the caller: the route lists
`.github/workflows` at the commit and reads each `*.yml`/`*.yaml` through the Contents API, using the
App's migration token (contents, pull requests and workflows write, minted narrowed to the one
repository and verified against its remote, [GitHub App](github-app.md#migration-permissions)). The
file bytes a commit holds never change, the pinned commit is the id the analyzer takes, and the
tables are versioned, so the plan this route applies is the plan a preview at the same commit and the
same deployment showed. A file the analyzer would refuse — a closed workflow vocabulary, an oversized
document — is `invalid_request` with the analyzer's own message, and a commit with no workflow at all
is `409` with `details.reason: "no_workflows"`.

**What the interface reads.** The same files are what the wizard in the web interface analyses:
`GET /api/v1/tenants/{slug}/repos/{name}/migration/workflows?commit=` answers them, at the commit
named or at the default branch's head, through the same token — a browser holds no repository
credential and the preview takes its files from the caller, so the read is what lets one analyse a
repository. It answers `sentinel.migration-workflows/1` and writes nothing
([API](api.md#routes)).

**What it writes.** One commit, whose parent is the analysed commit and whose tree is that commit's
tree with exactly the files the diff rewrote replaced, so the change is the label lines and nothing
else. The branch name is a constant and the client refuses any other ref before it makes a request:
a migration never pushes to a repository's default branch. The commit message and the pull request's
title and body are built from the plan — the workflows and jobs it moved with the label each had and
the class it gets, and the jobs that stay on GitHub's runners with their reasons — so re-running the
same analysis at the same commit rewrites nothing a person did not re-analyse.

**Re-running, closing, protection.** The branch a repository already has is fast-forwarded to the new
commit, and the pull request it already has is updated instead of a second one being opened: the
migration runs as often as a person likes and leaves one branch and one pull request behind. A re-run
whose analysis is unchanged writes no commit at all — the branch already holds that tree — so the
history holds one commit per change, not one per click. `close`
closes that pull request and leaves the branch, so the next run finds it again; a close with nothing
open answers `pull_request: null` and records nothing that did not happen. A protection rule that
declines the update is **reported, never forced** — GitHub's refusal is the answer
(`409` with `details.reason: "branch_protected"`), the ref stays where it was, and the attempt is
recorded as refused.

What became of each attempt is one row in the repository's own source audit trail —
`migration_pull_request_open`, `_update`, `_close` or `_refused` — written after GitHub answered. The
pull request's number and page are not stored: GitHub holds them, the branch is always
`sentinel/migrate`, and a second copy could only go stale the first time someone closed the pull
request by hand. The answer states the branch, the revision, the pull request (`number`, `url`,
`head`, `base`, `state`), the workflows whose labels changed with their job ids, and the jobs kept,
and it is `sentinel.migration-pull-request/1` ([compatibility](compatibility.md)).

## Verification

Unit and fixture tests are in [`crates/sentinel-pipeline/tests/workflow.rs`](../crates/sentinel-pipeline/tests/workflow.rs); the fixtures are in [`fixtures/workflows`](../fixtures/workflows) — the documented pilot shapes (cli's Go matrix and a job needing `GH_TOKEN`, ripgrep's OS and toolchain matrices, gson's JDK matrix with a container and a service), a workflow already naming Blacksmith labels, one already migrated to Sentinel classes, and one using every key the analyzer records. Invalid fixtures carry the message they must fail with in a `# expect:` header.

The gate is that no job and no construct is left undecided on the fixtures: every job has at least one cell whose destination is a class or one of the five reasons, and every recorded item — a trigger, a container, a service, a matrix, an `if`, a timeout, an output, a reusable call, a shell, a working directory, a `continue-on-error`, and each `uses:` action with its version — has its construct classified, so a classification cannot be satisfied by omission. The limits are proved by refusal: an oversized file, a document nested deeper than 16 levels, more than 256 jobs, an axis wider than 256 values, a `runs-on:` expansion past 256 cells and more than 64 workflow files each fail with the limit named. Determinism is proved by analyzing the same files in both orders and comparing, and the inventory's own rendering is asserted to hold no value: a token-shaped `env:` value and a `run:` script never appear in it.

## The change generator

[`crates/sentinel-pipeline/src/workflow/change.rs`](../crates/sentinel-pipeline/src/workflow/change.rs) turns an inventory into the change a migration would make, and [`native.rs`](../crates/sentinel-pipeline/src/workflow/native.rs) into the native pipeline plan. `plan(inventory, files, options)` produces one `WorkflowPlan` per workflow, for the phase `Options::phase` names — `label`, `shadow`, `switch` or `disable` — and the output is versioned: `sentinel.migration-preview/1` (`workflow::PLAN_SCHEMA`), exposed by `POST /tenants/{slug}/repos/{name}/migration/preview` and, at the switch's steps, by `POST /tenants/{slug}/repos/{name}/migration/switch` ([API](api.md#routes), which is also where the request and response shapes are).

### The label diff

The default output is a unified diff per workflow, and it changes label lines and nothing else: a `runs-on:` value, as written, replaced by the class the label table resolves the job to. Three lines of context either side make it reviewable; there are no other hunks.

- A job moves when every one of its cells resolves to **one** class — a job with no matrix, or a matrix whose axes the labels do not name, or several cells that agree. When they agree, the whole `runs-on:` value becomes that one label, and a matrix the labels named keeps running for the values other steps read.
- A job whose labels name different classes stays: one `runs-on:` value cannot name them all. It is listed with `varies`, and its lines are untouched.
- A job with any cell the label table keeps stays, listed with that cell's reason (`macos`, `gpu`, `docker`, `expression`, `no_class`) and the sentence behind it.
- A job already naming its class is not touched, so a workflow that is already migrated produces an empty diff.

The gate is on the bytes: the plan records every change as the whole lines it replaces (`before`) and produces (`after`), the diff is rendered from those records, and the generator applies them and **analyses the result again** before it answers. The re-analysis must show the same workflow with the intended class on the changed jobs and every other recorded fact of every job identical — steps, matrix, needs, secrets, constructs — or the plan is refused (`PlanError::Unverified`) rather than shown with a diff that landed somewhere it did not mean. A text whose label is not where the inventory read it is refused as `PlanError::Rewrite`. Tokens come from the YAML parser's own positions ([`yaml::spans`](../crates/sentinel-pipeline/src/yaml.rs)), so a `runs-on:` written inside a `run:` block is never mistaken for a label.

The PR that carries the diff is H04's; what proves the migration before it is switched is the
shadow beside each migrated job and the parity of the pairs over a window of commits
([shadow parity](shadow-parity.md)), and the step that drops the copies and moves the labels is the
[migration switch](migration-switch.md#the-plans-the-switch-is-made-of). Those are the generator's
other three phases: `shadow` adds a non-required copy of every migrating job
(`sentinel-<id>`, `name: sentinel / <original>`) and touches no original, `switch` drops those copies
and moves the originals' labels so that its result is exactly this label diff of the unshadowed
workflow, and `disable` writes `if: ${{ false }}` on every job a native pipeline replaced. Each one is
proved the same way the diff is: the generated text is analysed again and a plan whose result is not
what it stated is refused rather than shown.

### The native pipeline

On request the plan also carries a `.sentinel.yml` per workflow, built from the inventory and the rule table ([`rules.rs`](../crates/sentinel-pipeline/src/workflow/rules.rs)) — the tables are read, never copied:

- The workflow has a pipeline only when every workflow-level construct is translatable or translatable with a change; an unsupported trigger keeps the whole workflow on GitHub's runners, since a pipeline cannot carry half a workflow's triggers. A trigger filter the native vocabulary cannot express (`paths`, `paths-ignore`, `branches-ignore`, `tags-ignore`, `types`) is refused the same way for the same reason: dropping it would run the pipeline on changes GitHub never ran it on. `workflow_dispatch` inputs are not carried (I01) and each workflow's notes say so.
- Each job becomes one pipeline job, **one per matrix cell** over every axis the job declares (a pipeline has no matrix), on the class its cell resolves to. `runs_on` carries the class label, `os: windows` or `arch: arm64` where the class names them, and `isolation: microvm` for a job that needs a Docker daemon. `needs` lists every cell of the jobs it needs; a job that needs a kept job is kept too.
- A job is kept, with the rule table's own wording, when a construct is unsupported, when it states an `if` (the inventory records *that* a job or step has one, never the expression), when its matrix carries `include`/`exclude` (which expand differently per cell), when no digest-pinned image is available for its platform, when a declared path or secret name is one the native schema refuses, or when nothing is left to run.
- Caches and artifacts are declared from the recorded `key` and `paths`, an up-to-date artifact name being kept when the schema accepts it. A cache key with a GitHub expression the native language cannot evaluate is generated as `fill-me` and the notes say so; the native equivalents that do exist are `hashFiles` → `hash_files` and `github.ref|sha|event_name|base_ref|repository|run_id` → `event.ref|sha|name|base_ref`/`repo.name`/`run.id`.
- Every job declares the secret **names** it referenced, and the plan lists them for the repository to provision. Values are never in the inventory and so never in the plan: a pipeline declares env in values, so `env` names (job and step) are listed in the mapping rather than written into the pipeline.

The inventory holds no `run:` script, so each `run:` step becomes a stub at `scripts/ci/<workflow>/<job>/<step>.sh` and the pipeline runs it with `sh`; the mapping says which GitHub step each stub stands for (`script`, `image`, `checkout`, `cache`, `artifact`) so the person knows where the commands and the toolchain image go. The generated text is **always validated by the pipeline compiler** before it is returned: `compile_str` must accept it and produce exactly the jobs the mapping names, or the workflow has no native plan. The plan writes nothing: the pull request that applies it is [the next section](#the-pull-request).

One construct at a time is answered by [`suggest.rs`](../crates/sentinel-pipeline/src/workflow/suggest.rs), behind the MCP tool `suggest_workflow_change` ([MCP](mcp.md)): for a construct the rule table marks unsupported it proposes a rewrite of the workflow's own text and offers it only after the analyzer reads the rewritten workflow as exactly that change, so a rewrite that does not verify is refused rather than shown. A suggestion is never applied by Sentinel.

## Verification

Unit and fixture tests are in [`crates/sentinel-pipeline/tests/workflow.rs`](../crates/sentinel-pipeline/tests/workflow.rs) for the inventory and [`tests/plan.rs`](../crates/sentinel-pipeline/tests/plan.rs) for the change generator; the fixtures are in [`fixtures/workflows`](../fixtures/workflows) — the documented pilot shapes (cli's Go matrix and a job needing `GH_TOKEN`, ripgrep's OS and toolchain matrices, gson's JDK matrix with a container and a service), a workflow already naming Blacksmith labels, one already migrated to Sentinel classes, and one using every key the analyzer records. Invalid fixtures carry the message they must fail with in a `# expect:` header. `fixtures/workflows/native/` holds the native path's own: `ci.yml`, which the native plan serves whole down to a recorded `.sentinel.yml`, `mixed.yml`, where each job keeps its place for its own reason, and `block-labels.yml`, whose `runs-on:` is a block sequence the diff replaces whole.

The inventory's gate is that no job and no construct is left undecided on the fixtures: every job has at least one cell whose destination is a class or one of the five reasons, and every recorded item — a trigger, a container, a service, a matrix, an `if`, a timeout, an output, a reusable call, a shell, a working directory, a `continue-on-error`, and each `uses:` action with its version — has its construct classified, so a classification cannot be satisfied by omission. The limits are proved by refusal: an oversized file, a document nested deeper than 16 levels, more than 256 jobs, an axis wider than 256 values, a `runs-on:` expansion past 256 cells and more than 64 workflow files each fail with the limit named. Determinism is proved by analyzing the same files in both orders and comparing, and the inventory's own rendering is asserted to hold no value: a token-shaped `env:` value and a `run:` script never appear in it.

The pull request is proved against `sentinel_github::fake`, which holds a repository's workflow at a
commit, its refs and its pull requests. [`crates/sentinel-github/tests/migration.rs`](../crates/sentinel-github/tests/migration.rs)
is the client: the workflows read at a commit and nothing at a commit the fake does not hold, one
commit carrying exactly the rewritten text, the branch it created and its pull request, a second run
that updates that same pull request and moves that same branch, a close that leaves the branch and a
second close that finds nothing, protection declining the update with the ref left where it was, and
what is bounded before a request is made. [`crates/sentinel-api/tests/migration_pull_request.rs`](../crates/sentinel-api/tests/migration_pull_request.rs)
is the route: the commit, the branch, the pull request and the audit row `open`; a second run that
answers `updated` with one pull request and one branch; a close and the close that finds nothing; a
withdrawn `workflows` permission refused `409` naming it with nothing written and no request made; a
switch turned off refused the same way; protection reported as `branch_protected`; a commit that is
not a commit id and a commit whose workflows already name their classes refused; and a credential
without the tenant's administration refused `403`.

The change generator has three gates. **The label diff touches no other line**: every diff on every fixture is parsed back and applied to the input, the result must equal the input line for line except at the `runs-on:` lines, every added line must be a `runs-on:` naming a Sentinel class, and analyzing the result must leave every job either moved or listed as kept and produce an empty diff the second time. **Every native pipeline validates**: each generated text compiles, its jobs are exactly the mapping's, its triggers are the workflow's, and every stub it names is one the pipeline runs. **Identical input gives byte-identical output**: the same files planned twice, and in another order, produce the same diff, mapping and bytes; the native fixture's text is compared to a recorded file.

## Rollback

`POST /tenants/{slug}/repos/{name}/migration/rollback` takes a migration back in one action
([plan 16.5](../plan.md#165-guided-github-actions-migration)). It restores a state rather than
composing a change: the workflow bytes are GitHub's own at the revision the caller names, and the
required checks are the document the switch's preview promised, compared against the branch's
protection as GitHub states it now. Nothing is stored — GitHub holds the bytes and the branch holds
the pull request — so a rollback cannot apply anything it did not read.

**Two actions, one write.** `{"action": "revert", "commit": "<pre-switch revision>"}` puts the labels
back in runner mode and re-enables the replaced jobs on the native path; `{"action": "shadow",
"commit": "<shadow revision>"}` puts a shadow revision's workflows back and re-enters shadow mode, as
often as a person likes. Both are committed to `sentinel/migrate` — the same branch and single pull
request a migration leaves — so a rollback never pushes to a default branch, a re-run updates the
pull request it found, and re-entering the same state twice writes no second commit.

**What the revision must be.** The revision is checked against itself before anything is written: a
revert names a state the migration would still move, so a revision whose jobs already name Sentinel
classes is `409` with `details.reason: "not_pre_switch"`; a shadow re-entry names a state holding a
copy named `sentinel / <job>`, and one that holds none is `409` with `"no_shadow"`. A revision with
no workflow at all is `"no_workflows"`.

**What it restores.** The commit's parent is the default branch's head, read from GitHub, so the pull
request proposes today's state with the pre-switch workflows in it instead of undoing whatever merged
since the switch. Its tree is that parent's with the named revision's workflow files written whole
and every workflow file the parent holds that the revision does not deleted, so the branch ends up
holding that revision's file set byte for byte. The bounds are the migration write's own — at most 64
workflow files of 256 KiB each — and a protection rule that declines the update is reported as
`branch_protected` with the ref untouched.

**The native path's settings.** With a `settings` object the same call also handles the branch's
required status checks. The body states the pre-switch document the switch's preview promised —
`{"required_checks": {"strict": bool, "checks": [{"context", "app_id"}]}, "apply": bool}` — and the
answer states what the branch holds now, the document to put back, the checks to remove and restore,
and what became of it. Reading it needs repository administration, so the step mints its own token
asking for `administration: write` on top of the migration's three; an installation that does not
grant it answers `reason: "not_permitted"` with the change still stated, which is the path where a
person applies it. `apply: false` shows the change and writes nothing (`"not_requested"`), a
protection that waits for nothing is `"not_protected"`, and a branch already holding the document is
`"unchanged"`. Applying writes the whole document in one statement and then reads the branch again:
`verified: true` is what GitHub states afterwards, and a write that did not land is `"mismatch"` with
`verified: false`. A required check held by a ruleset is not visible through branch protection, so a
repository that keeps its checks in a ruleset keeps that half by hand.

**What is recorded.** Every step that reached GitHub is one row in the repository's source audit
trail — `migration_rollback_revert` for the revert pull request, `migration_shadow_enter` for a shadow
re-entry, `migration_rollback_settings` for a change shown, `_settings_applied` for one applied and
verified, `_settings_failed` for one refused or not matching, and `migration_rollback_refused` when
GitHub declined the pull request. The gate's own refusal is written before any step, as on every
migration write.

The gate is on the bytes and on the settings, never on the intention.
[`crates/sentinel-github/tests/rollback.rs`](../crates/sentinel-github/tests/rollback.rs) is the
client against `sentinel_github::fake`: the restore built on the default branch's own head, the
committed text equal to the revision's text, one branch and one pull request across a re-run, a
workflow the revision does not hold stated as a deletion in the tree, a path outside the workflows
directory or one both written and removed refused before a request, the required checks read and put
back as one document, `administration` refused for an installation that never listed it, a branch
with no protection answered apart from a permission refusal, and the checks bound.
[`crates/sentinel-api/tests/migration_rollback.rs`](../crates/sentinel-api/tests/migration_rollback.rs)
is the route: the revert answering `opened` with the branch holding the pre-switch bytes and one
`migration_rollback_revert` row, a second call answering `updated` with one pull request and one
branch, an already-migrated revision refused `not_pre_switch` with nothing written, shadow re-entry
committing the shadow revision's bytes and recording `migration_shadow_enter`, a revision without a
copy refused `no_shadow`, the settings step shown and then applied so the branch's protection equals
the pre-switch document exactly (`verified: true`) and `unchanged` on a third call, the same step
without `administration` stating `not_permitted` with the protection untouched and the revert pull
request still opened, and the gate's own refusals — switch off, a withdrawn `workflows` permission,
and a credential without the tenant's administration — each before any request reaches GitHub.
