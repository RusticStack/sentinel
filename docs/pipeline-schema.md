# Pipeline schema 1

`crates/sentinel-pipeline` turns a `.sentinel.yml` into a compiled, immutable pipeline in three stages, each strict: bounded YAML loading, typed decoding, deterministic compilation. Anything the schema does not define is an error, never a silent no-op, so a repository can only rely on behaviour Sentinel implements. Fixtures live under [`fixtures/pipelines`](../fixtures/pipelines); every valid one must compile and every invalid one must fail with the message in its `# expect:` header.

## Loading limits

The YAML event stream feeds a receiver that enforces limits as events arrive, so hostile input is rejected before it is materialised.

| Limit | Value |
|---|---|
| File size | 256 KiB (`MAX_PIPELINE_FILE_BYTES`) |
| Nesting depth | 16 |
| Nodes | 10,000 |
| Key length | 128 bytes |
| Scalar length | 4,096 bytes |
| Documents | exactly one |

Anchors, aliases, tags, non-string keys and duplicate keys are errors with line and column; the duplicate-key message names the position, never the key (diagnostics do not echo parser payloads). Plain scalars resolve only `null`, `true`/`false` and decimal integers; `yes`, `on`, octal, hex and floats stay strings, so nothing is coerced behind the author's back.

## Document shape

The document is one mapping with three keys — `schema`, `on` and `jobs` — plus the optional `concurrency`.

```yaml
schema: 1                       # required, exactly 1
on: [push, pull_request, merge_group, tag, manual, schedule]   # 1–6 distinct kinds
# or the filtered form:
# on:
#   push: {branches: [main, "release/*"]}
#   tag: {tags: ["v*"]}
#   pull_request: {branches: [main]}
#   merge_group: {branches: [main]}
#   manual: true
concurrency:                    # optional
  group: "${{ repo.id }}:${{ event.key }}"
  cancel_in_progress: true
jobs:                           # 1–64, names [a-z0-9][a-z0-9_-]{0,63}
  test:
    image: rust:1-bookworm      # required OCI reference
    needs: [other]              # ≤ 32 job names
    runs_on: {arch: amd64|arm64, labels: [linux], os: linux|windows, isolation: container|microvm|native}   # ≤ 8 labels; os and isolation optional, see below
    resources: {cpu: 4, memory: 8GiB, disk: 20GiB}  # see policy
    timeout: 20m                # default 1h, max 24h
    env: {NAME: value}          # ≤ 64, names [A-Za-z_][A-Za-z0-9_]*
    workdir: crates/app         # relative, normalised
    checkout:                   # optional: history for the run's own checkout, and more repositories
      history: shallow|full|{depth: N}          # default shallow (the pinned commit alone)
      repositories:                             # ≤ 8 additional checkouts
        - {repo: shared, path: vendor/shared, ref: refs/heads/main, history: {depth: 50}}
    steps:                      # required, 1–64
      - id: test                # unique within the job
        run: cargo test         # ≤ 4 KiB
        shell: sh|bash          # default sh
        env: {…}
        workdir: …
        timeout: 5m             # ≤ job timeout
        outputs: [version]      # ≤ 8 names per step, ≤ 16 per job
    cache:                      # ≤ 8, unique names
      - {name: cargo, key: "cargo-${{ hash_files('Cargo.lock') }}", paths: [/usr/local/cargo/registry, target]}
      - {name: registry, class: downloads, key: "dl-${{ hash_files('Cargo.lock') }}", paths: [/usr/local/cargo/registry]}
    artifacts:                  # ≤ 8, unique names
      - {name: release, paths: [target/release/app], when: success|failure|always|step:<step id>, retain: 7d, required: false, class: standard}
    outputs: [version]          # ≤ 8 step outputs re-exported to the jobs that need this one
    handoff:                    # ≤ 8 artifacts of jobs in `needs`, taken before the steps run
      - {from: build, artifact: release, into: dist}
    finalize:                   # optional, runs when the job ends, never changes its verdict
      run: ./notify.sh
      shell: sh|bash            # default sh
      env: {…}
      workdir: …
      timeout: 30s              # default 1m, at most 5m
    locks: [db/staging]         # ≤ 4 named external resources; see below
    secrets: [DEPLOY_TOKEN]     # ≤ 16 names [A-Z_][A-Z0-9_]*; values never appear in YAML
```

A document may also declare *named* pipelines and typed *inputs* beside the pipeline above — see
[named pipelines](#named-pipelines) and [inputs](#inputs). The shape above is the document's unnamed
pipeline, and a document that declares no named pipeline compiles, digests and publishes exactly as it
did before those keys existed.

### Job keys

Unknown keys anywhere are rejected with their path, for example `jobs.test: unknown key `imgae``. Durations are `<int>s|m|h` sums such as `1h30m`. Sizes use binary units only, `MiB` or `GiB`. CPU is whole cores or a quoted decimal such as `"0.5"`, stored as millicores: plain digits only (no sign), at most three decimals, so `"+4"`, `"0.+5"` and `"0.5555"` are errors rather than being read or truncated. Paths are normalised relative paths with no `..`, `//`, leading `./` or trailing `/`; cache paths may also be absolute inside the container but never `/`. `concurrency.group` and cache `key` are templates; job and step `if` are expressions (see below).

**`on.merge_group`.** A merge-queue group: `checks_requested` when GitHub builds a
group out of queued pull requests and asks for its checks, and `destroyed` when it
discards one. Its filter matches the **base branch** exactly as `on.pull_request`
does, and the run is the commit GitHub merged into its queue branch, which the
pipeline reads at that object id ([sources](sources.md#merge-groups)). A
repository that requires `sentinel / ci` on its merge queue needs a pipeline with
this trigger as well as `on.pull_request`, because GitHub asks for the checks
under the `merge_group` event, not under the pull request's. `destroyed` never
runs anything: it cancels the run the group produced ([intake](intake.md#merge-groups)).

**`checkout`.** A job's workspace is its run's own repository at the run's pinned commit; `checkout.history` says how much of that commit's past the job needs — `shallow` fetches only the pinned tree, `{depth: N}` fetches `N` commits of it (`N` ≤ 10,000) and `full` fetches everything reachable from it. A pipeline that states anything other than `shallow` is stored as run-spec format 13 ([compatibility](compatibility.md)).

`checkout.repositories` adds up to eight further repositories beside it. Each names a repository of the run's tenant (`repo`, the name the repository has there, never a remote or URL), where it lands (`path`, a normalised relative path inside the workspace, so nothing can leave it), the branch or tag it resolves (`ref`, an exact `refs/heads/…` or `refs/tags/…` name its binding must allow) and optionally its own `history`. Paths must be distinct and must not nest inside one another, and no checkout may be placed in the workspace's own `.git`; the workspace root is the run's own checkout, so `path` is always inside it. An additional checkout is authorized exactly as the run's own is: the repository must belong to the run's tenant, hold a binding, and that binding's remote must be on the deployment's destination allowlist ([sources](sources.md#additional-checkouts)). A pipeline cannot authorize a repository; naming one it may not read fails closed, and nothing is fetched.

The `ref` is resolved to a commit once, when the run's first attempt for that job starts, and the commit — never the ref — is what every attempt checks out. The run's [source manifest](sources.md#additional-checkouts) records that commit beside the run's own, so a rerun of a past run builds the same revisions even after the branch has moved.

**`runs_on.os` and `runs_on.isolation`.** Unstated, a job is a Linux job run on whatever executor its worker uses by default (rootless Podman, or a microVM on a KVM host once that executor is set up; [plan 16.8](../plan.md#168-microvm-execution-on-kvm-hosts)), and any Linux worker may take it, including one that predates these fields. Stated, the job goes only to a worker that states it runs that OS and isolation; otherwise it waits with the reason `runtime_missing` ([API](api.md)). Linux jobs take `container` or `microvm`; Windows jobs take `microvm` (a Windows guest) or `native`, so `os: linux` with `native` and `os: windows` with `container` are errors. A spec with either field is stored as run spec format 7 ([compatibility](compatibility.md)).

## External resources (`locks:`)

A job may need a thing outside Sentinel to itself while it runs: a staging database, a host, a device.
`locks:` declares those names, at most four, each either a plain name or a mapping with a `wait` bound:

```yaml
jobs:
  migrate:
    image: postgres:16
    locks:
      - db/staging                 # waits the default ten minutes
      - {name: "device:rig-1", wait: 30m}
    steps: [{id: migrate, run: ./migrate.sh}]
```

A name is literal — `[A-Za-z0-9._:/-]`, at most 128 bytes, with no leading, trailing or doubled `/`, and
no template expansion — because it identifies something outside Sentinel rather than a value Sentinel
computes. `wait` is a positive duration up to 24 hours and defaults to `10m`. Duplicate names, a name
outside that set and a bound that is not a positive duration are each a schema error naming the path.

The lock is held from the moment a job is leased to a worker, released when its attempt ends — passed,
failed, cancelled, or with its lease lapsed, at which point another job may take it — and it is scoped to
the tenant: every repository of a tenant shares the names, and no other tenant can hold one of them. It is
**not** a concurrency group. A group (`concurrency:`, above) is a key inside Sentinel that orders one
repository's runs and can supersede them; a resource is a thing outside Sentinel that one job of any
repository holds, and a job the group cancelled gives it back when its attempt is released rather than when
the next run arrives ([storage](storage.md#external-resources)).

A job that cannot take a resource waits at most its `wait` bound, measured from the moment it became
ready, and is then failed with the failure class `resource_lock` naming the resource in the job's
`lock_wait`; while it waits, the queue lists it with the reason `resource_lock` and the name
([API](api.md), [core contracts](core-contracts.md#failure-classes)). A spec whose jobs declare locks is
stored as run spec format 13 ([compatibility](compatibility.md)).

## Source policies (`on:`)

`on:` is either the list form above (every ref of those kinds) or a mapping
that names kinds with optional ref filters:

```yaml
on:                                  # every branch, every tag, manual only
  push:                              # `branches` patterns; empty = every branch
    branches: [main, "release/*"]
  tag:
    tags: ["v*"]                     # `tags` patterns; empty = every tag
  pull_request:
    branches: [main]                 # matched against the base branch
  manual: true                       # `true` or the key is omitted
  schedule: true                     # a stored schedule may run this pipeline
```

Filter rules, enforced strictly:

- the list form takes 1–6 distinct kinds and no filters; the mapping form names
  at most those six kinds, and at least one must be present;
- a kind takes only its own key (`branches` for `push` and `pull_request`,
  `tags` for `tag`); the other is an unknown key;
- at most 32 patterns of at most 256 bytes each. `*` matches any run of
  characters inside one path segment and `**` matches zero or more whole
  segments, anchored to the whole branch or tag name (`release/*` does not
  match `release/1.0/x`; `release/**` does). An empty list is an error — omit
  the key to admit every ref;
- `manual: true` declares the trigger the API's explicit dispatch uses; an
  event-driven delivery never matches it, and a `manual` pipeline never runs
  from a push.
- `schedule: true` declares that a stored schedule may run this pipeline. The
  crons are not part of the pipeline: they are a per-repository row an operator
  configures, and its occurrences are UTC instants ([schedules](schedules.md)).
  A pipeline that does not state it is not run by a schedule, and the occurrence
  is recorded `failed` with reason `no_trigger`.

Which ref a policy is judged against is fixed by the event: a push is judged
against its branch, a tag against its tag, and a pull request against its
**base** branch. An event whose kind and ref disagree (a tag ref arriving as a
push) never matches, and neither does an event the pipeline does not declare.
The decision is made by the controller when it resolves the delivery
([intake](intake.md)); a mismatch is `ignored:no_trigger`, not a failure.

## Resource policy

Absent resource fields take the policy defaults so every compiled job has a finite, enforceable budget; explicit values must fall inside the policy bounds.

| Field | Default | Minimum | Maximum |
|---|---|---|---|
| cpu | 2 cores | 0.25 | 64 |
| memory | 4 GiB | 128 MiB | 256 GiB |
| disk | 10 GiB | 1 GiB | 1000 GiB |

The policy is a value passed to `compile_with`, so tenants or pools can carry their own without changing the parser.

## Compilation

The compiler validates cross-job references and produces a canonical form:

- `needs` must name existing, distinct, other jobs; cycles are reported with the jobs involved.
- Step IDs, cache names and artifact names are unique per job; a step timeout cannot exceed its job's timeout; at most 1,024 steps in total.
- Jobs are sorted by name, then ordered by Kahn's algorithm with a name-ordered ready set, so the execution order is a pure function of the DAG and does not change when unrelated jobs are edited. `needs` become ascending indices into that order, every one smaller than the job's own index.
- A 128-bit digest over the canonical form identifies the compiled pipeline. Reordering job declarations or `needs` lists yields the same digest; any semantic change yields a different one. The digest is FNV-1a, for equality only, never for trust.

## Run specification

> Execution admission: a job's image digest **and** platform must be durably recorded on the job (`runs::resolve_image`, migration 12) before `jobs::lease` will hand it to a worker; a tag-only or digest-only reference is not executable.

`RunSpec` binds one compiled pipeline to one exact source and is written once per run, never edited. It holds a `PinnedSource` (repository, full lowercase hex SHA-1 or SHA-256, optional ref name kept as provenance only), the `CompiledPipeline`, and one `ImageRef` per job. An image reference is parsed into name, tag and digest; it is *pinned* when it carries a `sha256` digest. Tag-only references are resolved by the first worker to pull them and the digest is recorded on the run, so every later attempt uses the same bytes; a pin can be set once and never changed.

The spec is persisted as one format byte plus a postcard-encoded blob in the store's `run_specs` table alongside the run, in the same transaction that creates the job rows. Jobs with no dependencies and no `if` are created `Queued`, the rest `Blocked` (a job with an `if` waits even with nothing to depend on, because its condition reads the run's event, which is recorded after the run row); dependency indices are read from the spec, not duplicated in rows. `get_run_spec` returns exactly what was written and rejects blobs with an unknown format byte instead of misreading them.

**Rerun versus new dispatch.** A rerun is a new attempt of an existing job under the same spec: the job goes from any terminal state back to `Queued`, its attempt history and failure class are cleared, and the fence is kept so the next lease advances it and any late report from the old attempt is stale. A job with cancellation desired cannot be rerun. A rerun also resumes the run it belongs to: the run's own cancel flag is cleared, and every job downstream of the rerun job that ended `skipped` (following a chain of skipped jobs only) goes back to `Blocked` and is decided again when the new attempt finishes, so a dependent skipped for a failure that a passing rerun replaces runs, and one skipped by its own `if` is evaluated again. A dependent that already ran keeps its result. Without this, a passed rerun would leave a required downstream job skipped and the run `passed`. This revival is a controller-only store operation (it is not a state-machine edge; see [core contracts](core-contracts.md#job-states-and-events)). A different source revision or pipeline is a new run with its own spec and its own IDs.

`RunSpec::step_command(job, step)` derives the exact process a worker runs: argv, merged environment and working directory, plus the effective timeout (step timeout, else job timeout).

## Expressions

`${{ … }}` in templates and the `if:` keys use one bounded grammar, parsed once at compile time into an AST stored with the run spec:

- Literals: `'single quoted'` (`''` escapes a quote), integers, `true`, `false`, `null`.
- Context paths: `event.name|ref|base_ref|sha|key|pr_number`, `repo.id|name`, `run.id`, `job.id|name`, `needs.<job>.result`, `inputs.<name>`. Any other root or field is a compile error, so a typo cannot evaluate to null, and `inputs.<name>` must name an input the pipeline declares.
- Operators: `==`, `!=` (same-type only, `null` compares with anything), `!`, `&&`, `||` (short-circuit, boolean operands only), parentheses. Comparisons do not chain.
- Functions: `success()`, `failure()`, `always()`, `cancelled()`, `contains(a, b)`, `starts_with(a, b)`, `ends_with(a, b)`, `hash_files('pattern', …)`. Nothing else: no arithmetic, no string building, no user functions, no network.
- Limits: 1,024 bytes, 256 tokens, depth 16, 8 arguments, 4 path segments.

The event paths are real values recorded as the run's immutable provenance
([intake](intake.md)), not defaults:

| Path | Value |
|---|---|
| `event.name` | `push`, `tag`, `pull_request`, `merge_group`, `manual` or `schedule` |
| `event.sha` | the checked-out revision (the pushed commit, the peeled tag commit, the tested merge, or the merge group's head commit) |
| `event.ref` | the pushed ref, the tag ref, `refs/pull/<n>/merge` for a pull request, or the queue branch for a merge group |
| `event.base_ref` | the pull request's or merge group's base branch (`main`); `null` for anything else |
| `event.pr_number` | the pull request number; `null` for anything else, including a merge group, which may hold several |
| `event.key` | a short, stable key: the branch or tag name, `pr-<n>`, the queue branch's path for a merge group, `manual`, or the ref a scheduled occurrence read |
| `inputs.<name>` | the value this run was given for a declared input: a string, a choice's string, a boolean or an integer |

Evaluation is phased. Each path and function has a minimum phase, and an expression evaluated earlier yields an `Unresolved` error rather than a default: `event`, `repo`, `run`, `job`, `inputs.*` and `cancelled()` at **dispatch**; `needs.*`, `success()`, `failure()`, `always()` at **schedule** (once every dependency is terminal); `hash_files` at **worker** (after the pinned checkout). The compiler enforces placement: `concurrency.group` may only use dispatch context; a job `if` may not use `hash_files` and may only name jobs in its own `needs`; step `if` and cache keys may use everything but also only name jobs in `needs`. A condition must be a boolean: the compiler types every `if` — with `inputs.<name>` typed by its declaration — and rejects, with the path of the key, a comparison between types that can never match (`event.ref == 7`, `event.pr_number == 'x'`, `inputs.count == 'x'`), a boolean operator or function over a value that is not always a boolean (`!event.ref`, `event.base_ref || true`), and a result that is not a boolean (`if: event.ref`). `null` compares with anything. A condition that compiled therefore cannot fail with a type error when it is evaluated. `success()` and `failure()` summarise dependency outcomes (`failure()` is true when any dependency did not succeed, `success()` when all passed or were skipped by their own condition); `always()` is true unless the run is cancelled.

**Job conditions.** A job's `if` is evaluated by the controller at the schedule phase, once every job in `needs` is terminal, with the run's event, repository, run and job facts, `needs.<job>.result` and the dependency summary (the same values the worker later gives a step's `if`; `hash_files` is a compile error there). A job with an `if` always starts `Blocked`, even with no `needs`, and is decided as soon as its event is recorded. The decision:

| Job | Starts when | Otherwise |
|---|---|---|
| no `if` (policy `on_success`) | every dependency passed or was skipped by its own condition | skipped as soon as one dependency did not succeed |
| `if` without a status function | the dependencies all succeeded **and** the condition is true | skipped |
| `if` that calls `success()`, `failure()` or `always()` | the condition is true, whatever the dependencies did | skipped |

So `cleanup: {needs: [test], if: always()}` runs after a failed `test` and `notify: {needs: [test], if: failure()}` runs only after one, while `deploy: {needs: [test], if: event.ref == 'refs/heads/main'}` runs only on `main` and only when `test` succeeded. `always()` and `failure()` are false once the run's cancel flag is set, and a cancelled run's unstarted jobs end `canceled` anyway. The core policies map as `on_success` = no `if`, `always` = `if: always()`, `on_failure` = `if: failure()`. A skip caused by a failure upstream is a failure for what follows: a job skipped because its dependency failed does not satisfy `on_success` for its own dependents, whereas a job skipped by its own false condition does (an optional branch not taken does not drag the DAG); the worker's step conditions see each dependency's recorded outcome (`skipped`), not this propagation. A condition that nevertheless cannot be evaluated when the dependencies finish ends the job `infra_failed` with failure class `preparation` and never runs or skips it on a guess.

Templates render each interpolation as string, integer or boolean; `null` is an error, and output is bounded (256 bytes for concurrency keys and cache keys).

`hash_files(root, patterns)` resolves on Linux workers against a pinned checkout root: segments may contain `*` or be `**` (zero or more directories); a terminal `**` includes regular files recursively. Unique matches are sorted by UTF-8 path bytes; the result remains the BLAKE3 hex of `path \0 little-endian-u64-length content` records. No match is an error, not an empty key. Overlapping patterns do not consume the unique-file budget twice.

The [resolver contract](hash-files.md) provides streaming directory enumeration, shared traversal and depth budgets, actual read accounting, and descriptor-rooted no-symlink/no-mount access. Matching symlinks and special files fail closed; filesystem failures are not silently treated as absent input. Secure resolution requires Linux `openat2` and host procfs; other platforms return `UnsupportedPlatform`. Portable offline validation/explanation still reports runtime hashes as unresolved.

## Declared outputs

A step declares the names it writes values under, and writes them into the file `SENTINEL_OUTPUT` names, one
`name=value` line each. A later step of the same job sees them as `SENTINEL_OUTPUT_<NAME>`; a job's own `outputs`
re-export the ones the jobs that need it read, as `SENTINEL_OUTPUT_<JOB>_<NAME>`, with `-` written as `_` and
everything upper case. The bounds are the schema's: at most 8 names per step and 16 across a job's steps, one value
of at most 1 KiB each, a written file of at most `1 KiB × 16 + 4 KiB`, and a declared output the step never wrote is
absent rather than empty. A step that writes a name it did not declare, writes one twice, writes a value past the
bound, writes something that is not text, or repeats a value the attempt was given as a secret fails with
`command_failed` and a message naming the name and the limit, never the value.

An output is **plain text in the run's record and public within the tenant**: the controller stores what the worker
accepted in the job's row, the jobs that need it read it from their context, `GET /runs/{id}` serves it as each job's
`outputs` map ([API](api.md#routes)), the run page lists it under Outputs, and nothing redacts it. That is why the
worker refuses one that repeats a delivered secret, and why a value is never a place for one. An output name is an
id (`[a-z0-9][a-z0-9_-]*`), so two steps of one job cannot write the same name and a later step's read is never
ambiguous.

## Artifact handoff

`handoff` names artifacts of jobs the job `needs` — `from` must be in `needs` and `artifact` must be one that job
declares — and the directory each is placed under, before the job's first step runs. The bytes are the producer's own
publication: the controller streams the artifact's manifest entries and the worker verifies each against the digest
the publication recorded, so a handoff makes no second copy, keeps the artifact's class, retention and record as the
publication set them, and honours the same per-artifact and per-run budgets. A declared handoff that is absent,
expired, refused or damaged fails preparation, because it is an input the job declared rather than an optional
result; nothing about it is optional and no step of the consuming job starts. Up to 8 artifacts may be taken, up to
1 GiB each.

## Bounded finalizers

`finalize` is a step that runs once the job's steps have ended, in the same container and workspace, whatever the
verdict was. It is bounded twice: by its own `timeout` (default 1m, at most 5m) and by what is left of the job's own
budget, so it can never run the job past its `timeout`. It takes no `outputs`, no `secrets` and no `if`, and it
cannot change the job's conclusion: what it did is an annotation on the attempt's record — its outcome, how long it
took and one bounded line naming an exit status or a bound — and a job that passes with a failing finalizer still
passes. A cancelled attempt does not run it at all, so a finalizer can never extend a cancelled job's life, and the
worker's own cancel and lease-expiry paths still end the job exactly as they did ([executor](executor.md#finalizers)).

## Bindings and offline validation

Three kinds of binding connect a job to state outside its container, and each is declared by name so grants can be checked before anything runs:

- **cache**: a name, an optional `class`, a key template and container paths. The worker materialises the named cache scope for the rendered key; the key is unknown offline whenever it interpolates runtime context. `class` is `downloads`, `dependencies` or `compiler` (default `dependencies`); the class chooses the validity rule the entry follows — see [cache classes](cache.md).
- **artifacts**: named path sets published under a `when` policy, with a `retain` period of `1d`–`365d` (default `7d`). `when: success`, `failure` or `always` matches the job's verdict and the artifact is captured once every step has finished; `when: step:<id>` names one of the job's own steps and publishes when that step completes successfully, while the steps after it keep running, so a large output uploads during the rest of the job instead of after it. A step trigger neither waits for nor depends on the job's verdict, publishes nothing when its step is skipped by its own `if` or ends with a failure (use `failure` for an artifact that records why), and publishes once: a redelivery or a second publication of the same name for the same attempt is a conflict, never a second record. Required coverage at finalization treats a step trigger as `success` does — a passing attempt that never published a `required: true` artifact behind a step fails with class `publication` — and a run spec whose artifacts state a step trigger is stored as run spec format 9 ([compatibility](compatibility.md)). `class` names one of the deployment's retention classes (1–32 lowercase letters, digits, `_` or `-`); unstated, the artifact takes the deployment's default class. A class the deployment does not define is refused before a run exists (`failed:artifact_class_unknown` from a delivery, `invalid_request` from a manual dispatch), so the loader accepts any well-formed name and the deployment decides which ones exist ([retention](retention.md#artifact-classes-and-pins)). The class's maximum age shortens `retain`; a spec whose artifacts state a class is stored as run spec format 8 ([compatibility](compatibility.md)). `paths` use the `hash_files` pattern language resolved against the job workspace: a declaration that resolves to no files is recorded `absent`; one that cannot resolve or publish is recorded `failed`. `required: true` (default `false`) turns an absent or failed outcome into a publication-class job failure; an optional artifact never changes the verdict. Each artifact publishes as an immutable manifest of content-addressed objects (D03); per-artifact and per-run byte and entry budgets are enforced during capture.
- **secrets**: names only. A job declares the names it may use; each step selects environment or file targets, while optional `registry_auth` selects a host-only OCI auth value for that job's image pull. The file never carries a value. A missing or revoked binding fails preparation instead of starting with an empty variable.

### Task results

`reuse:` opts a job into serving its own result from the worker's store instead of running ([cache](cache.md#task-results)). It is the only way to enable it: a job that states none always executes, and nothing in this schema makes an arbitrary command's success reusable.

```yaml
jobs:
  test:
    image: rust:1-bookworm
    env: {RUSTFLAGS: -Dwarnings}
    steps:
      - {id: run, run: cargo test --release}
    reuse:
      inputs: [Cargo.toml, Cargo.lock, "crates/**/src/**.rs", "crates/**/Cargo.toml"]
      paths: [target/release]
```

- **`inputs`** — 1–16 `hash_files` patterns, resolved against the pinned checkout. Each pattern's digest is part of the key, so adding, removing or rewriting a matched file, and renaming a pattern, are different tasks. A pattern that matches nothing does not fail the run: the key cannot be built, so that run is not reusable and seals nothing.
- **`paths`** — 1–8 normalised relative workspace directories, captured recursively exactly as a `cache:` path is, and never inside `.sentinel-cache`, which the worker owns. They are what a served result restores into the checkout and what the key records, so changing them is a different task; a result that captured nothing publishes nothing. They are not the [`outputs`](#declared-outputs) values a step writes and a dependent job reads.
- **Refused on the same job**, because a key could not then be complete or a served result could not behave as the declaration says: **`secrets`** and `registry_auth` (a secret value is never read into a key), a job **`if`** and any step **`if`** (nothing of a served job runs, so no condition is re-decided), step or job **`outputs`** (no step of a served job writes one), **`handoff`** (the bytes another job's artifact brings are not in the key) and **`finalize`** (a served job runs no finalizer), and a step-triggered artifact (**`when: step:<id>`** — it publishes at a completion a served result never reaches). Artifacts on a verdict trigger still publish from the restored trees.
- Every step runs in a fresh container with the declared environment; there is no shared state between jobs to account for, so the key is exactly what the job declares. The key's components are enumerated in the [cache contract](cache.md#task-results); changing any of them forces a fresh run.
- A run may ask for fresh execution of all its tasks (`fresh: true` on a manual dispatch, and every rerun — [API](api.md#routes)), which bypasses the store and seals nothing.
- A spec whose jobs state `reuse` is stored as run spec format 14 ([compatibility](compatibility.md)), so a worker that predates it refuses the spec instead of running a job it cannot tell is reusable.

`sentinel pipeline validate <file>` runs the same loader, decoder and compiler as the server on any platform, prints nothing on success, and on failure prints `<file>: <stage>: <path>: <message>` and exits 1. `sentinel pipeline explain <file> [--json]` prints the compiled view: digest, triggers (with their ref filters), concurrency, every job in execution order with its dependencies, image and pin status, condition, budgets, steps, caches, artifacts, secrets and any `reuse` declaration; a **requires** section (repository read, secret names to grant, cache scopes, artifact storage, registry access for unpinned images); and an **unresolved until runtime** list naming each expression with the phase that resolves it. Nothing unresolved is given a value: `hash_files` keys are shown as their template, secrets as names, and unpinned images as needing resolution at first pull. `--json` emits the `sentinel.explain/1` shape for tools and agents; `trigger_filters` lists each declared kind's patterns (empty for an unfiltered kind).

## Named pipelines

A document may declare several named pipelines beside its unnamed one. Each is a whole pipeline —
its own `on:`, `concurrency:`, `inputs:` and `jobs:` — and each compiles into its own immutable
spec, its own runs and its own checks:

```yaml
schema: 1                    # still 1: `pipelines`, `inputs` and `inputs.<name>` are additive keys
on: [push]                   # the unnamed pipeline, unchanged
jobs: {…}
pipelines:                   # 1–16 names, [a-z0-9][a-z0-9_-]{0,63}
  acceptance:
    on:
      pull_request: {branches: [main]}
    concurrency: {group: "${{ repo.id }}:acceptance", cancel_in_progress: true}
    jobs: {…}
  release:
    on:
      tag: {tags: ["v*"]}
    jobs: {…}
```

- **One event, one run per matching pipeline.** A delivery runs every pipeline whose `on:` admits it,
  in the document's order (the unnamed pipeline first, then the named ones by name), and each run is
  created with its own spec, its own jobs and its own provenance naming the delivery. A pipeline no
  trigger of which matches is not run; a delivery none of them matches settles `ignored:no_trigger`
  as before. The whole set is created in one transaction, so a delivery produces either all of its
  runs or none, and every run's provenance names the delivery it came from
  ([intake](intake.md#resolution)).
- **One schedule, one run per schedule-enabled pipeline.** An occurrence runs every pipeline that
  states `on.schedule: true` the same way ([schedules](schedules.md)).
- **Check identity is namespaced by the pipeline.** The unnamed pipeline publishes `sentinel / ci`
  and `sentinel / <job>`, exactly the names it always has. A named pipeline publishes
  `sentinel / <name>` and `sentinel / <name> / <job>` ([checks](checks.md#what-is-published)). The
  identity is the name and the job name and nothing else, so it is the same on every run: a
  repository protects `sentinel / acceptance` and gets that check from the `acceptance` pipeline.
- **No name is reserved.** Sentinel ships no list of pipeline names and no rule that reads a name's
  spelling: `ci`, `release` and `deploy` are a repository's to use, and the only names Sentinel
  derives are the namespaced check names above. Nothing a repository calls a pipeline is a Sentinel
  concept; a GitHub workflow's names never decide anything here.
- **One name, one check.** A document that gives one check name two meanings is refused, naming
  both: a named pipeline `acceptance` beside an unnamed job `acceptance` (both publish
  `sentinel / acceptance`) is `pipelines.acceptance: check `sentinel / acceptance` is also the
  unnamed pipeline's job `acceptance`; name one of them differently`. Because a job or pipeline name
  cannot contain `/` or a space, namespaces can only collide where the document itself makes them.
  The unnamed pipeline keeps the names it always published, a job called `ci` included: nothing an
  older document declared changes meaning.
- **Concurrency groups are scoped by the pipeline.** A named pipeline's rendered group is
  `<name>: <group>`, so two pipelines never share a group even when their templates render to the
  same text, and one pipeline's `cancel_in_progress` replaces its own previous run and never
  another pipeline's ([dispatch](core-contracts.md)). The unnamed pipeline's group is the rendered
  template, byte for byte as before.
- **Reports stay per pipeline.** A refused *delivery* publishes the single `sentinel / ci` it always
  has, because it produced no run to carry a pipeline name; a named pipeline's own aggregate is
  published by its runs.

## Inputs

A pipeline may declare inputs: typed values a **manual dispatch** passes, each with a bound that a
request must respect.

```yaml
pipelines:
  focus:
    on: [manual]
    inputs:                          # 1–16, names [a-z][a-z0-9_]{0,31}
      target:                        # required: no default
        type: string
        min_length: 1                # optional, 0..max_length
        max_length: 40               # required, 1–1024
      worker_count:
        type: integer
        min: 1                       # required
        max: 8                       # required, greater than min
        default: 2                   # optional; within the bound
      full: {type: boolean, default: false}      # bounded by construction
      profile:
        type: choice
        values: [debug, release]     # required, 1–32 distinct values of at most 128 bytes
        default: debug               # must be one of `values`
```

- **Every type carries a bound**, and a declaration that states none is refused:
  `inputs.target.max_length: required`, `inputs.a.max: must be greater than the minimum`,
  `inputs.a.default: must be one of x`.
- **A value outside its bound is refused before a run exists**, naming the input and the bound:
  `inputs.target: 1 to 4 bytes`, `inputs.count: 1 to 8, found 9`,
  `inputs.profile: one of debug, release`, `inputs.full: expected a boolean, found a string`,
  `inputs.target: required`, `inputs.extra: no input of this pipeline has that name`. A refusal
  echoes no value, only the figure its bound compares. The manual dispatch route answers
  `400 invalid_request` with that message ([API](api.md#routes)).
- **A required input needs a default unless the pipeline runs only from a manual dispatch**, because
  no event or schedule can supply one: `inputs.target: a required input needs a default unless the
  pipeline runs only from a manual dispatch`. A pipeline with a default for every input runs from any
  trigger with those defaults.
- **Where a value appears.** An input reads as `inputs.<name>` — at the dispatch phase, and with the
  type its declaration states — in `concurrency.group`, job and step `if`, and cache keys. Nothing
  reads an input the pipeline does not declare.
- **A value is in no identity.** It is not in the compiled digest, not in a check name, and not in a
  cache key or concurrency group unless the pipeline names it there: two runs of one pipeline with
  different values publish the same checks and have the same digest, and a cache key that reads
  `${{ inputs.target }}` differs between them while a key that does not is the same
  ([cache](cache.md#the-manifest)).

## Shell semantics

`sh` runs `/bin/sh -e -c <script>` so the first failing command fails the step. `bash` runs `bash -e -o pipefail -c <script>` and requires an image that provides bash. Failure classes are identical for both: exit 0 passes; any other exit status is `command_failed`; death by signal is `command_signaled`; exceeding the step or job timeout is `execution_timeout`; a cgroup memory kill is `out_of_memory`. Output is captured for diagnostics and never interpreted for the verdict. Environment precedence is job `env`, then step `env` overriding by name, then the worker's own `SENTINEL_*` context variables appended last so a pipeline cannot spoof them. A step `workdir` is joined under the job `workdir`; both are validated relative paths so the join cannot escape the workspace. Steps of one job run sequentially in one container and workspace; jobs share nothing implicitly.

## GitHub Actions workflows

A repository's GitHub Actions workflows are read by a separate, bounded analyzer in the same crate: [`sentinel-pipeline::workflow`](workflow-analysis.md) inventories `.github/workflows/*.yml` at a pinned commit through the loading limits above, and its two versioned tables decide which jobs move to a Sentinel runner class and which constructs translate to this schema. Nothing in this schema version changes for it.

## Verification

`crates/sentinel-pipeline/tests/locks.rs` covers the declaration: a name's default bound and a declared one, the resource in the digest while the spec's bytes stay what a pipeline without one writes and a decoded spec carries none, and the explanation naming each resource with its bound.

Unit tests cover secret-name validation, registry-auth delivery requirements, and the explanation model (requirements, unresolved inputs, no invented values), the expression grammar (precedence, rejected constructs, phase gating, typing, templates), the `hash_files` resolver (globbing, ordering, sensitivity, cross-root stability), scalar resolution, source SHA validation, image reference parsing and single pinning, spec encode/decode round trip with format-byte rejection, step command derivation and environment override, every rejected YAML construct, each loading limit, error positions, duration and size parsing, and identifier, path and image validation. Fixture tests compile every valid fixture, check the invalid fixtures against their expected messages, evaluate the conditions example across dispatch, schedule and worker phases, decode every field of the full example, and prove determinism on a diamond DAG under reordering. `crates/sentinel-pipeline/tests/named.rs` covers two named pipelines of one repository keeping their own triggers, concurrency policies, digests and check namespaces; the refusal of a document that gives one check name two meanings while any name a repository chooses is otherwise accepted; every input type's bound and refusal message; the loading bounds of a declaration; the required-input rule; the typing of `inputs.<name>`; the digest covering declarations and not values; a cache key changing with an input only when it names one; and an unnamed pipeline keeping its check names, digest and run spec format.

Not in this schema version: matrices and service containers (Part 16 and later parts). Files using them fail at `unknown key`. A run spec whose pipeline states `on.schedule` and no named pipeline and no input is stored as run spec format 10; one that names a pipeline or states an input is stored as format 11; one whose steps or jobs declare outputs or a handoff is stored as format 12; one whose job states a checkout history or an additional checkout is stored as format 13; and one whose jobs state `reuse` is stored as format 14 ([compatibility](compatibility.md)).
