# Pipeline schema 1 (C04)

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

Anchors, aliases, tags, non-string keys and duplicate keys are errors with line and column. Plain scalars resolve only `null`, `true`/`false` and decimal integers; `yes`, `on`, octal, hex and floats stay strings, so nothing is coerced behind the author's back.

## Document shape

```yaml
schema: 1                       # required, exactly 1
on: [push, pull_request, tag, manual]   # 1–4 distinct triggers
concurrency:                    # optional
  group: "${{ repo.id }}:${{ event.key }}"
  cancel_in_progress: true
jobs:                           # 1–64, names [a-z0-9][a-z0-9_-]{0,63}
  test:
    image: rust:1-bookworm      # required OCI reference
    needs: [other]              # ≤ 32 job names
    runs_on: {arch: amd64|arm64, labels: [linux]}   # ≤ 8 labels
    resources: {cpu: 4, memory: 8GiB, disk: 20GiB}  # see policy
    timeout: 20m                # default 1h, max 24h
    env: {NAME: value}          # ≤ 64, names [A-Za-z_][A-Za-z0-9_]*
    workdir: crates/app         # relative, normalised
    steps:                      # required, 1–64
      - id: test                # unique within the job
        run: cargo test         # ≤ 4 KiB
        shell: sh|bash          # default sh
        env: {…}
        workdir: …
        timeout: 5m             # ≤ job timeout
    cache:                      # ≤ 8, unique names
      - {name: cargo, key: "cargo-${{ hash_files('Cargo.lock') }}", paths: [/usr/local/cargo/registry, target]}
    artifacts:                  # ≤ 8, unique names
      - {name: release, paths: [target/release/app], when: success|failure|always, retain: 7d}
    secrets: [DEPLOY_TOKEN]     # ≤ 16 names [A-Z_][A-Z0-9_]*; values never appear in YAML
```

Unknown keys anywhere are rejected with their path, for example `jobs.test: unknown key `imgae``. Durations are `<int>s|m|h` sums such as `1h30m`. Sizes use binary units only, `MiB` or `GiB`. CPU is whole cores or a quoted decimal such as `"0.5"`, stored as millicores. Paths are normalised relative paths with no `..`, `//`, leading `./` or trailing `/`; cache paths may also be absolute inside the container but never `/`. `concurrency.group` and cache `key` are templates; job and step `if` are expressions (see below).

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

## Run specification (C05)

> Execution admission: a job's image digest **and** platform must be durably recorded on the job (`runs::resolve_image`, migration 12) before `jobs::lease` will hand it to a worker; a tag-only or digest-only reference is not yet executable. See the [Parts 01–02 audit](parts-01-02-audit.md).

`RunSpec` binds one compiled pipeline to one exact source and is written once per run, never edited. It holds a `PinnedSource` (repository, full lowercase hex SHA-1 or SHA-256, optional ref name kept as provenance only), the `CompiledPipeline`, and one `ImageRef` per job. An image reference is parsed into name, tag and digest; it is *pinned* when it carries a `sha256` digest. Tag-only references are resolved by the first worker to pull them and the digest is recorded on the run, so every later attempt uses the same bytes; a pin can be set once and never changed.

The spec is persisted as one format byte plus a postcard-encoded blob in the store's `run_specs` table alongside the run, in the same transaction that creates the job rows. Jobs with no dependencies are created `Queued`, the rest `Blocked`; dependency indices are read from the spec, not duplicated in rows. `get_run_spec` returns exactly what was written and rejects blobs with an unknown format byte instead of misreading them.

**Rerun versus new dispatch.** A rerun is a new attempt of an existing job under the same spec: the job goes from any terminal state back to `Queued`, its attempt history and failure class are cleared, and the fence is kept so the next lease advances it and any late report from the old attempt is stale. A job with cancellation desired cannot be rerun. A different source revision or pipeline is a new run with its own spec and its own IDs.

`RunSpec::step_command(job, step)` derives the exact process a worker runs: argv, merged environment and working directory, plus the effective timeout (step timeout, else job timeout).

## Expressions (C06)

`${{ … }}` in templates and the `if:` keys use one bounded grammar, parsed once at compile time into an AST stored with the run spec:

- Literals: `'single quoted'` (`''` escapes a quote), integers, `true`, `false`, `null`.
- Context paths: `event.name|ref|base_ref|sha|key|pr_number`, `repo.id|name`, `run.id`, `job.id|name`, `needs.<job>.result`. Any other root or field is a compile error, so a typo cannot evaluate to null.
- Operators: `==`, `!=` (same-type only, `null` compares with anything), `!`, `&&`, `||` (short-circuit, boolean operands only), parentheses. Comparisons do not chain.
- Functions: `success()`, `failure()`, `always()`, `cancelled()`, `contains(a, b)`, `starts_with(a, b)`, `ends_with(a, b)`, `hash_files('pattern', …)`. Nothing else: no arithmetic, no string building, no user functions, no network.
- Limits: 1,024 bytes, 256 tokens, depth 16, 8 arguments, 4 path segments.

Evaluation is phased. Each path and function has a minimum phase, and an expression evaluated earlier yields an `Unresolved` error rather than a default: `event`, `repo`, `run`, `job` and `cancelled()` at **dispatch**; `needs.*`, `success()`, `failure()`, `always()` at **schedule** (once every dependency is terminal); `hash_files` at **worker** (after the pinned checkout). The compiler enforces placement: `concurrency.group` may only use dispatch context; a job `if` may not use `hash_files` and may only name jobs in its own `needs`; step `if` and cache keys may use everything but also only name jobs in `needs`. A condition must evaluate to a boolean; a literal non-boolean `if` is rejected at compile time, and a string at evaluation time is an error, never truthy. `success()` and `failure()` summarise dependency outcomes; `always()` is true unless the run is cancelled.

Templates render each interpolation as string, integer or boolean; `null` is an error, and output is bounded (256 bytes for concurrency keys and cache keys).

`hash_files(root, patterns)` resolves on Linux workers against a pinned checkout root: segments may contain `*` or be `**` (zero or more directories); a terminal `**` includes regular files recursively. Unique matches are sorted by UTF-8 path bytes; the result remains the BLAKE3 hex of `path \0 little-endian-u64-length content` records. No match is an error, not an empty key. Overlapping patterns do not consume the unique-file budget twice.

The [C06 resolver contract](hash-files.md) closes the filesystem gaps from the [2026-09-14 audit](parts-01-02-audit.md): streaming directory enumeration, shared traversal and depth budgets, actual read accounting, and descriptor-rooted no-symlink/no-mount access. Matching symlinks and special files fail closed; filesystem failures are not silently treated as absent input. Secure resolution requires Linux `openat2` and host procfs; other platforms return `UnsupportedPlatform`. Portable offline validation/explanation still reports runtime hashes as unresolved.

## Bindings and offline validation (C07)

Three kinds of binding connect a job to state outside its container, and each is declared by name so grants can be checked before anything runs:

- **cache**: a name, a key template and container paths. The worker materialises the named cache scope for the rendered key; the key is unknown offline whenever it interpolates runtime context.
- **artifacts**: named path sets published after the job under a `when` policy and a retention period; publication needs artifact storage.
- **secrets**: names only. The worker injects each granted secret as an environment variable of that name; the file never carries a value, and a job that names a secret the repository has not been granted fails at dispatch, not silently with an empty variable.

`sentinel pipeline validate <file>` runs the same loader, decoder and compiler as the server on any platform, prints nothing on success, and on failure prints `<file>: <stage>: <path>: <message>` and exits 1. `sentinel pipeline explain <file> [--json]` prints the compiled view: digest, triggers, concurrency, every job in execution order with its dependencies, image and pin status, condition, budgets, steps, caches, artifacts and secrets; a **requires** section (repository read, secret names to grant, cache scopes, artifact storage, registry access for unpinned images); and an **unresolved until runtime** list naming each expression with the phase that resolves it. Nothing unresolved is given a value: `hash_files` keys are shown as their template, secrets as names, and unpinned images as needing resolution at first pull. `--json` emits the `sentinel.explain/1` shape for tools and agents.

## Shell semantics

`sh` runs `/bin/sh -e -c <script>` so the first failing command fails the step. `bash` runs `bash -e -o pipefail -c <script>` and requires an image that provides bash. Failure classes are identical for both: exit 0 passes; any other exit status is `command_failed`; death by signal is `command_signaled`; exceeding the step or job timeout is `execution_timeout`; a cgroup memory kill is `out_of_memory`. Output is captured for diagnostics and never interpreted for the verdict. Environment precedence is job `env`, then step `env` overriding by name, then the worker's own `SENTINEL_*` context variables appended last so a pipeline cannot spoof them. A step `workdir` is joined under the job `workdir`; both are validated relative paths so the join cannot escape the workspace. Steps of one job run sequentially in one container and workspace; jobs share nothing implicitly.

## Verification

Twenty unit tests cover secret-name validation and the explanation model (requirements, unresolved inputs, no invented values), the expression grammar (precedence, rejected constructs, phase gating, typing, templates), the `hash_files` resolver (globbing, ordering, sensitivity, cross-root stability), scalar resolution, source SHA validation, image reference parsing and single pinning, spec encode/decode round trip with format-byte rejection, step command derivation and environment override, every rejected YAML construct, each loading limit, error positions, duration and size parsing, and identifier, path and image validation. Five fixture tests compile the four valid fixtures, check each of the 29 invalid fixtures against its expected message, evaluate the conditions example across dispatch, schedule and worker phases, decode every field of the full example, and prove determinism on a diamond DAG under reordering. All pass on Windows and Linux.

Not in this schema version: named pipelines, schedules, manual inputs, matrices, service containers, extra checkouts (Part 16 and later parts). Files using them fail at `unknown key`.
