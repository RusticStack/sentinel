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
```

Unknown keys anywhere are rejected with their path, for example `jobs.test: unknown key `imgae``. Durations are `<int>s|m|h` sums such as `1h30m`. Sizes use binary units only, `MiB` or `GiB`. CPU is whole cores or a quoted decimal such as `"0.5"`, stored as millicores. Paths are normalised relative paths with no `..`, `//`, leading `./` or trailing `/`; cache paths may also be absolute inside the container but never `/`. Expressions in `concurrency.group` and cache keys are carried as opaque strings until C06 defines their grammar.

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

`RunSpec` binds one compiled pipeline to one exact source and is written once per run, never edited. It holds a `PinnedSource` (repository, full lowercase hex SHA-1 or SHA-256, optional ref name kept as provenance only), the `CompiledPipeline`, and one `ImageRef` per job. An image reference is parsed into name, tag and digest; it is *pinned* when it carries a `sha256` digest. Tag-only references are resolved by the first worker to pull them and the digest is recorded on the run, so every later attempt uses the same bytes; a pin can be set once and never changed.

The spec is persisted as one format byte plus a postcard-encoded blob in the store's `run_specs` table alongside the run, in the same transaction that creates the job rows. Jobs with no dependencies are created `Queued`, the rest `Blocked`; dependency indices are read from the spec, not duplicated in rows. `get_run_spec` returns exactly what was written and rejects blobs with an unknown format byte instead of misreading them.

**Rerun versus new dispatch.** A rerun is a new attempt of an existing job under the same spec: the job goes from any terminal state back to `Queued`, its attempt history and failure class are cleared, and the fence is kept so the next lease advances it and any late report from the old attempt is stale. A job with cancellation desired cannot be rerun. A different source revision or pipeline is a new run with its own spec and its own IDs.

`RunSpec::step_command(job, step)` derives the exact process a worker runs: argv, merged environment and working directory, plus the effective timeout (step timeout, else job timeout).

## Shell semantics

`sh` runs `/bin/sh -e -c <script>` so the first failing command fails the step. `bash` runs `bash -e -o pipefail -c <script>` and requires an image that provides bash. Failure classes are identical for both: exit 0 passes; any other exit status is `command_failed`; death by signal is `command_signaled`; exceeding the step or job timeout is `execution_timeout`; a cgroup memory kill is `out_of_memory`. Output is captured for diagnostics and never interpreted for the verdict. Environment precedence is job `env`, then step `env` overriding by name, then the worker's own `SENTINEL_*` context variables appended last so a pipeline cannot spoof them. A step `workdir` is joined under the job `workdir`; both are validated relative paths so the join cannot escape the workspace. Steps of one job run sequentially in one container and workspace; jobs share nothing implicitly.

## Verification

Ten unit tests cover scalar resolution, source SHA validation, image reference parsing and single pinning, spec encode/decode round trip with format-byte rejection, step command derivation and environment override, every rejected YAML construct, each loading limit, error positions, duration and size parsing, and identifier, path and image validation. Four fixture tests compile the three valid fixtures, check each of the 23 invalid fixtures against its expected message, decode every field of the full example, and prove determinism on a diamond DAG under reordering. All pass on Windows and Linux.

Not in this schema version: expressions and conditions (C06), named pipelines, schedules, manual inputs, matrices, service containers, extra checkouts (Part 16 and later parts). Files using them fail at `unknown key`.
