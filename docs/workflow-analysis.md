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

A `runs-on:` label may reference `${{ matrix.<axis> }}`. The analyzer expands only the axes the labels actually name (a matrix used elsewhere does not widen the placement), substituting those axis values into every label. One job therefore yields one cell per `runs-on:` variant; a job with no matrix, or a matrix its labels do not name, yields exactly one cell with no axes. The cross product is bounded by `MAX_MATRIX_CELLS`; a larger one is refused, not truncated. An expression that is not a matrix reference the cell holds leaves that label unresolved and the cell stays on GitHub's runners as `expression`.

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
| `on: workflow_call`, `workflow_run` | unsupported | reusable pipelines and workflow chaining (I10) |
| `on: pull_request_target` | unsupported | the privileged context has no native equivalent |
| any other event | unsupported | no native trigger exists for it |
| `permissions` | with change | the source credential's scopes replace `GITHUB_TOKEN`; no ambient token |
| `concurrency`, `env`, `needs`, `timeout-minutes`, `run`, `working-directory` | translatable | — |
| `defaults` | with change | steps run under sh or bash; `defaults.run` becomes the step's `shell` and `workdir` |
| `if` (job or step) | with change | a pipeline condition in the expression language, type-checked at compile time |
| `strategy.matrix` | with change | one declared job per cell; bounded matrices (I10) |
| `container` | unsupported | needs a Docker daemon, which only a microVM sandbox offers (I08) |
| `services` | unsupported | needs a Docker daemon (I08); service containers (I10) |
| `environment` | unsupported | deployment environments are not modelled |
| `outputs` | unsupported | declared outputs and artifact handoff (I04) |
| `jobs.<id>.uses` | unsupported | reusable pipelines (I10) |
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

## Verification

Unit and fixture tests are in [`crates/sentinel-pipeline/tests/workflow.rs`](../crates/sentinel-pipeline/tests/workflow.rs); the fixtures are in [`fixtures/workflows`](../fixtures/workflows) — the documented pilot shapes (cli's Go matrix and a job needing `GH_TOKEN`, ripgrep's OS and toolchain matrices, gson's JDK matrix with a container and a service), a workflow already naming Blacksmith labels, one already migrated to Sentinel classes, and one using every key the analyzer records. Invalid fixtures carry the message they must fail with in a `# expect:` header.

The gate is that no job and no construct is left undecided on the fixtures: every job has at least one cell whose destination is a class or one of the five reasons, and every recorded item — a trigger, a container, a service, a matrix, an `if`, a timeout, an output, a reusable call, a shell, a working directory, a `continue-on-error`, and each `uses:` action with its version — has its construct classified, so a classification cannot be satisfied by omission. The limits are proved by refusal: an oversized file, a document nested deeper than 16 levels, more than 256 jobs, an axis wider than 256 values, a `runs-on:` expansion past 256 cells and more than 64 workflow files each fail with the limit named. Determinism is proved by analyzing the same files in both orders and comparing, and the inventory's own rendering is asserted to hold no value: a token-shaped `env:` value and a `run:` script never appear in it.

## Not in this stage

The analyzer only reads and classifies. The `runs-on:` diff, the generated `.sentinel.yml` and the secret names to provision are H03's, validated by `pipeline validate`; opening the pull request is H04's. The inventory's Rust shape is internal until that preview exists and versions its own output.
