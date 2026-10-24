# Cache and environment recipes (K07)

Nine tested recipes under [fixtures/recipes](../fixtures/recipes) show how
to wire a toolchain's caches into Sentinel's three cache classes. Each
recipe is a schema-1 pipeline with a digest-pinned image, a seed source
tree, and two edit overlays; `bench/k07-recipes.sh` provisions the
checked-in dependency stores, builds a three-commit repository per recipe
(base, source edit, dependency edit) and drives five real attempts per
recipe — **cold**, **warm**, **small-edit**, **changed-dependency**,
**changed-toolchain** — through `attempt::run` (checkout, pinned pull,
restore, rootless Podman steps, publish). Every attempt emits one JSONL
record to `bench/k07-recipes.jsonl` with per-phase timings and per-entry
cache outcomes; a recipe whose prerequisites cannot run records
`blocked`, never an invented number.

Measured steps run under the worker's `--network none` + read-only
rootfs, so every dependency must arrive through a checked-in store — the
same shapes a private mirror serves in production:

| Recipe | Store baked into the tree | Lockfile hashed |
|---|---|---|
| `custom-tool` | `pkgs/*.pkg` blobs + `tools/fakecc.sh` | `deps.txt` |
| `go` | `goproxy/` file:// module proxy | `go.sum` |
| `rust` | `local-registry/` (cargo local-registry index + `.crate`) | `Cargo.lock` |
| `npm` | `pkgs/*.tgz` (`file:` deps) | `package-lock.json` |
| `pnpm` | `pkgs/*.tgz` + vendored `tool/pnpm` | `pnpm-lock.yaml` |
| `bun` | `pkgs/*.tgz` (`file:` deps) | `bun.lock` |
| `python` | `pkgs/sdist` + vendored build-backend wheels | `requirements.txt` |
| `maven` | `m2-mirror/` file:// repo (deps + lifecycle plugins) | `pom.xml` |
| `gradle` | `m2-mirror/` file:// repo + `gradle.lockfile` | `gradle.lockfile` |

## Picking a class

The three classes exist because their validity rules differ; see
[cache](cache.md) for the contract. The recipes pick by *who owns
invalidation*:

- **downloads** — the tool's own blob store. It validates content by its
  own digest/protocol, so the entry is keyed by stem and survives
  lockfile edits: a changed `go.sum` still serves every module zip the
  new build needs. Used for `GOMODCACHE`, `CARGO_HOME`,
  `npm_config_cache`, pnpm's `store-dir`, `BUN_INSTALL_CACHE_DIR`,
  `PIP_CACHE_DIR`, Maven's `-Dmaven.repo.local`, `GRADLE_USER_HOME`, and
  the custom tool's `pkgs` store.
- **dependencies** — the exact materialization of a dependency set:
  `vendor/`, `node_modules/`, `.venv`. Served only under the identical
  rendered key — a lockfile edit is a guaranteed miss and
  rematerialization, which is the correct outcome.
- **compiler** — the tool's input-level invalidation namespace:
  `GOCACHE`, `CARGO_TARGET_DIR`, the fake compiler's object dir, javac /
  bundler-style output. Keyed `cc-normal-<lockfile hash>`: the stem is
  the namespace, the hash tail the volatile component, so a source edit
  hits while the tool decides per input what to rebuild.

## Environment wiring

A mounted cache path is useless unless the tool actually writes there —
each recipe declares the environment the tool reads:

| Recipe | Env wiring |
|---|---|
| go | `GOMODCACHE`, `GOCACHE`, `GOPROXY=file:///workspace/goproxy`, `GOSUMDB=off` |
| rust | `CARGO_HOME`, `CARGO_TARGET_DIR`, `CARGO_NET_OFFLINE` |
| npm | `npm_config_cache` |
| pnpm | `npm_config_store_dir` (mirrored by checked-in `.npmrc`), `PATH` prepends `tool/pnpm/bin` |
| bun | `BUN_INSTALL_CACHE_DIR` |
| python | `PIP_CACHE_DIR`, `VIRTUAL_ENV` + `PATH` prepend `.venv/bin` |
| maven | `MAVEN_OPTS=-Dmaven.repo.local=/dl/m2` |
| gradle | `GRADLE_USER_HOME=/dl/guhome` |
| custom-tool | none — the store paths are step arguments |

Two rules this enforces: the whole *tool-managed home* must be writable
(mounting only `CARGO_HOME/registry` breaks cargo's bookkeeping on the
read-only rootfs — mount the home), and scratch state the cache is not
meant to carry (`PNPM_HOME`) goes to the `/tmp` tmpfs, not a mount.

## What each case measures

- **cold** — fresh worker dir: every entry misses (`absent` or
  `no_current`), the image pull downloads, all stores populate and seal.
- **warm** — same commit and image: downloads and compiler entries hit by
  stem/exact key; `dependencies` hits the identical key; steps still run
  (a hit restores bytes, never a verdict).
- **small-edit** — a source file changes, lockfile does not: every entry
  hits; the compiler class shows its value as the tool reuses unchanged
  inputs (fakecc prints `reused`, go/cargo reuse their namespaces).
- **changed-dependency** — the lockfile moves: `downloads` still hits by
  stem and serves the old blobs the new resolve needs; `dependencies`
  and `compiler` miss on the new tail and republish under it.
- **changed-toolchain** — same commit, different image digest: the
  toolchain digest is a scope dimension, so every entry is a fresh-scope
  miss and republishes into the new scope — the two toolchains never
  share state.

## Adapting to a real repository

1. Replace the checked-in store with your private mirror:
   `GOPROXY=https://goproxy.internal`, a `cargo vendor` or
   `cargo-local-registry` tree, a Verdaccio/Artifactory npm registry, a
   Maven/Gradle repository manager URL in `settings.xml`/`build.gradle`.
   The cache classes do not change — only where bytes originate.
2. Keep the volatile component of each key last and let it hash the
   lockfile set (`hash_files('go.sum', 'go.mod', …)` for workspaces).
3. Split compiler modes into distinct stems (`cc-race-`, `cc-coverage-`)
   the moment outputs must not interleave — one stem means one `current`
   pointer.
4. Pin the image by digest at dispatch time (the controller resolves
   tags to digests); a toolchain upgrade then gets a clean scope
   automatically instead of inheriting a foreign toolchain's state.
5. Point every store the tool owns at the mount through its env var, and
   keep anything it scribbles besides the store on `/tmp` or in the
   workspace.

## Measurement status

`bench/k07-recipes.jsonl` is regenerated by `bench/k07-recipes.sh`.
Records carry `"status": "measured"` with the attempt's own timings, or
`"status": "blocked"` with the provisioning/runtime reason — see the
header of the script for the environment contract (rootless Podman on
Linux/WSL2; provisioning may use the network, measured steps cannot).

## Symlinks are not cached

A cache payload carries regular files and directories only: publication skips every symlink (it is counted in the commit's `skipped`, never followed), because a link's target is a path the next job's view could not trust. Tools that build their installed state out of links therefore restore *incomplete*, not broken silently — the recipes above rebuild what the links provided:

- **Python** — a venv's `bin/python` is a link to the interpreter; the recipe recreates the venv when it is missing (`test -x .venv/bin/python || python -m venv .venv`) before installing.
- **npm / Bun** — `node_modules/.bin` shims are links; the install step (`npm ci --prefer-offline`, `bun install`) recreates them from the restored packages.
- **pnpm** — the default isolated linker is built from links into the store; the recipe forces `node-linker=hoisted` so the restored tree is plain files. With the isolated linker the cache still serves the content-addressed store (`downloads`), just not the linked `node_modules`.

A cache whose value is mostly links belongs in a `downloads` store the tool re-links itself.
