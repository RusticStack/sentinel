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

## Shell semantics

`sh` runs `/bin/sh -e -c` so the first failing command fails the step. `bash` runs `bash -eo pipefail -c` and requires an image that provides bash. Steps of one job run sequentially in one container and workspace; jobs share nothing implicitly.

## Verification

Six unit tests cover scalar resolution, every rejected YAML construct, each loading limit, error positions, duration and size parsing, and identifier, path and image validation. Four fixture tests compile the three valid fixtures, check each of the 23 invalid fixtures against its expected message, decode every field of the full example, and prove determinism on a diamond DAG under reordering. All pass on Windows and Linux.

Not in this schema version: expressions and conditions (C06), named pipelines, schedules, manual inputs, matrices, service containers, extra checkouts (Part 16 and later parts). Files using them fail at `unknown key`.
