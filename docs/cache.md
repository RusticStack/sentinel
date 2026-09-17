# Worker-local cache: classes, scopes, manifests and restore (K01+K02)

Sentinel keeps its caches on the worker that runs the job: no network fetch on a warm hit, no shared mutable volume between tenants. This document is the metadata contract — which cache classes exist, what boundary a generation is sealed under, how a job receives its private writable view, and the vocabulary a lookup answers with. Publication, garbage collection, compiler persistence and remote hydration each have their own section below; everything here is what they share: paths, formats and reasons.

## Why three classes

A `cache:` entry declares a `class` (`sentinel_protocol::cache::Class`) because the classes have different validity rules, and a permissive rule must never loosen an exact one:

- **`downloads`** — tool-addressed blobs: package registry responses, fetched archives. The installing tool validates content by its own digest or protocol, so an entry may serve a *different* key under the same stem (`cargo-<h1>` serving `cargo-<h2>`): lockfile edits that leave the stem intact can still hit. `Compat::Downloads { tool }` pins the installing tool's identity (`cargo`, `npm`, …).
- **`dependencies`** — an exact materialization of a dependency set. It may serve only a request whose recorded inputs match completely: the rendered key, the lockfile digest, the installer identity, its flag string and the ABI tag (`Compat::Dependencies`). This is the default for a `class`-less document — the only rule that is never wrong to assume.
- **`compiler`** — compiler intermediates in a stable toolchain namespace. The compiler performs input-level invalidation inside the namespace, so entries persist across source and lockfile edits; the store pins the key stem and the flags namespace (`Compat::Compiler`).

## The boundary

Every generation is sealed under a scope — and the manifest records every dimension of it, so a directory moved anywhere else can never serve:

```text
cache/<repo>/<class>/<trust>/<os>-<arch>/<toolchain16>/<name>/<entry>/gen-<unix_ms>-<rand>/
cache/<repo>/<class>/<trust>/<os>-<arch>/<toolchain16>/<name>/<entry>/current
cache/<repo>/<class>/<trust>/<os>-<arch>/<toolchain16>/<name>/<entry>/writing/
cache/<repo>/<class>/<trust>/<os>-<arch>/<toolchain16>/<name>/<entry>/lease/
```

- `<repo>` leads: repository IDs are globally unique, so two tenants can never produce the same scope directory. The tenant is still recorded in every manifest — a moved directory fails `WrongTenant`, not the path check.
- `<class>` and `<trust>` are the enum names: `downloads`/`dependencies`/`compiler` and `protected`/`pull_request`.
- `<os>-<arch>` is one component (`linux-x86_64`); a second OS can never silently reuse a scope directory.
- `<toolchain16>` is the first 8 bytes of the BLAKE3 digest of the toolchain descriptor — image digest, tool versions, whatever pins "the toolchain" — as 16 lowercase hex characters.
- `<name>` is the pipeline's cache name, already `valid_id`-shaped; `Scope::new` re-checks rather than trusts.
- `<entry>` is a readable slug of the rendered key plus 8 bytes of its digest: different keys can never share a directory, and a slug collision only produces a `WrongKey` miss — never wrong content.
- `gen-<unix_ms>-<rand>` names a generation: creation order in the name, an 8-hex random suffix so two generations sealed in the same millisecond never collide. `current` names the live generation; `writing/` holds generations being staged plus the writer lock; `lease/` holds the active-use pins that keep a generation away from reclamation.

## Trust derivation

`Trust` has two values with one rule (`Trust::of_event`, applied once in `dispatch::job_context` from the run's recorded provenance):

- `pull_request` runs → `PullRequest`: content a fork can influence never writes to — or reads — protected state.
- every other trigger, and a run with no recorded provenance (`manual`) → `Protected`.

Workers that negotiated protocol 6 receive the tenant and trust class in `Context2`; older workers get `Context` and scope to `PullRequest` — the reading that can never touch protected state. A trust byte that does not decode is a protocol error, never a guess.

## The manifest

Each generation directory carries `manifest`: `sentinel.cache` magic, a format byte (`1`), a reserved zero byte, then a postcard body — 16 bytes of head, at most `MAX_MANIFEST_BYTES` (64 KiB) ever read. The manifest records the full boundary (tenant, repo, class, trust, platform, the complete toolchain digest, the cache name), the rendered key, the class's `Compat` inputs, the seal timestamp, and the `files` blob's entry count, total bytes and BLAKE3 digest. `sealed_ms == 0` marks an interrupted write; an unsealed generation is always a miss.

The sibling `files` blob (`sentinel.files` magic, format byte `1`, at most `MAX_FILES_BLOB_BYTES`, `MAX_FILE_ENTRIES` entries) lists each payload file: path, size, digest, mode. It is separate because lookups read manifests and materialization reads listings — a 200k-file listing must never inflate the lookup path. Every entry is re-validated as a normalised relative path, so a listing can never name a file outside its generation.

## Explainable outcomes

A lookup answers an `Outcome`, never an error: `Hit` (the verified manifest plus its recorded payload bytes) or a `Miss` naming the reason. The check order is the explanation order — the outermost broken boundary wins:

| Miss | Meaning |
|---|---|
| `absent` | no directory, `current` or manifest where expected |
| `corrupt` | short head, bad magic, undecodable body, unreadable or oversize file |
| `unsupported_version` | a manifest format this build does not know |
| `unsealed` | the write never completed |
| `wrong_class` | sealed under a different cache class |
| `wrong_tenant` | sealed under another tenant |
| `wrong_repo` | sealed under another repository |
| `wrong_trust` | sealed under the other trust class |
| `wrong_platform` | sealed on another `os-arch` |
| `wrong_toolchain` | sealed under another toolchain digest |
| `wrong_name` | names a different cache entry |
| `wrong_key` | the rendered key differs (or, for `downloads`/`compiler`, the stem does) |
| `incompatible` | the class's own inputs differ: lockfile digest, installer, flags, ABI tag or tool |
| `invalid` | decoded but semantically wrong: bad IDs, invalid name, a `compat` payload from another class |
| `unavailable` | a transient filesystem or lease failure on the restore path — the bytes may be fine and the miss is worth retrying |

A cache must degrade a build to a rebuild, never break it: every failure mode above is a reasoned miss on the lookup path, and nothing in the read path panics or guesses.

## Restore: private views of immutable generations (K02)

A sealed generation is immutable forever — a job never writes into the store. Preparation (`attempt.rs`, after checkout and image pull, before container start) gives every declared `cache:` entry a private writable view:

1. The key renders against the fresh checkout — `hash_files` reads real bytes — with a 1024-byte cap (`attach::MAX_KEY_BYTES`). A key that will not render is an explainable miss, not a failure.
2. `entry/current` names the live generation; it is read bounded (128 bytes) and must name a `gen-<unix_ms>-<rand>`-shaped directory.
3. `manifest::lookup` reads the manifest and applies the request's boundary — the `Miss` vocabulary above is the whole answer set.
4. On a hit the entry is pinned with a `lease` (`Lease::acquire`, the attempt id as owner, `DEFAULT_TTL`) so GC can never take the generation mid-clone, and the `files` blob's BLAKE3 digest is verified against the manifest — that one digest is the trust anchor for the whole payload, so materialization skips per-file hashing (re-reading every byte would defeat reflinking).
5. Each `payload/<i>` tree is materialized into the declared path's target and the `Attached` carrier — scope, key, compat, generation, outcome, targets, lease, stats — lands on `job.caches` in declaration order for publish (K03).

The clone (`clone::tree`) is capability-detected once per cache root: **`FICLONE` reflink per file** where the filesystem answers (cost per file, not per byte), and a **bounded 256 KiB byte copy** everywhere else. A capable filesystem can still refuse an individual file — that file falls back to copying while the rest reflink. Hardlinks are never used: a shared inode would let one job's write corrupt the generation for every other. Symlinks are recreated verbatim and never followed — a link inside a generation is data, not a path — and entries that are neither file, directory nor symlink are skipped and counted. Whatever the backend, a job's writes can never reach the sealed generation.

The target mapping is the contract a job sees:

- A **relative** declared path materializes inside the workspace and reaches the container through the existing `/workspace` mount.
- An **absolute** declared path gets a private host directory under `.sentinel-cache/<name>/<index>` inside the workspace plus a bind mount to the declared container path — the job's writes stay private without the workspace mount ever serving outside its tree.
- On **any miss** the declared paths still exist as empty writable directories: a job always sees writable cache paths.
- Path components are re-validated against the schema's rule (`..`, absolute-inside-workspace and the `.sentinel-cache` name as a relative declaration are refused `invalid`), existing components are never resolved through symlinks, and a symlink sitting exactly at a target is replaced with the real directory it hid.

Restore is total from the attempt's perspective: nothing on the cache path is fatal. The stats the carrier records — `lookup_ns`, `lock_wait_ns`, `clone_ns`, files, bytes, copied bytes, the backend flag — feed the availability summaries (K08); a phase that never ran stays absent, never zero.

**First touch.** After a hit's clone materializes, restore measures one bounded first-read sample per target (`attach::Stats::first_touch_ns`): open the largest listed file and read its first 4 KiB. The clone's wall time is per-file work — `FICLONE` returns without touching extents — while the first real read is what faults a cold extent, so that cost is measured separately rather than folded into `clone_ns`. At most one small read per target; a file that will not open is simply not measured, and a miss or an empty listing records `None`.

The worker advertises `Capabilities::REFLINK` in its Hello exactly when `clone::detect(<data_dir>/cache)` reports `Backend::Reflink` — the same probe restore uses, so the advertised bit and the backend in use can never disagree.

## Publication (K03)

Publication is finalization work, off the verdict's path: after a job's steps finish and before its workspace is destroyed, the worker commits each attached cache whose verdict left real state — a passed job, or one that failed its commands (`command_failed`, `command_signaled`, `out_of_memory`). A canceled, timed-out, un-started or infrastructure-failed attempt publishes nothing, and a cache failure never changes the verdict: each entry's outcome is a diagnostic note (`cache_published`), never a build failure.

**Authorization.** `publish::commit` refuses an attachment whose scope trust is not the job's (`TrustMismatch`), before a single directory is made. There is no cross-trust promotion in v1: a pull-request publication can only ever produce `pull_request` entries. The entry directory is derived exactly as restore derives it (`attach::entry_key` — the key stem for `downloads`/`compiler`, the full key for `dependencies`), so the two paths always meet.

**One writer per entry.** Staging ownership is `writing/.lock`, taken with `create_new` — never waited on. A live marker is a `busy` skip; a marker older than `lease::MAX_TTL` (by declared expiry and by mtime, whichever reads live shorter) is a dead writer's and is reaped in place. Releasing removes the marker and the `writing/` directory while empty, so a release can never pull staging from under the next writer.

**Staging.** The generation is built at `writing/gen-<unix_ms>-<rand>` — never inside a live generation. The walk of the declared target directories follows no symlinks, skips non-regular and unencodable entries, and is bounded in depth (64, the `hash_files` bound), entry count (`MAX_FILE_ENTRIES`), blob size (`MAX_FILES_BLOB_BYTES`) and time: the whole publish batch runs under `CACHE_PUBLISH_TIMEOUT` (3 minutes) with cancel polled every 256 files.

**Reuse.** A file whose path, size and mode match the source generation's listing is hashed once; a digest match is staged by hardlinking out of that generation — one inode, no copy — and the staged name is re-hashed before seal, so a drifted generation can never poison its successor: a failed check falls back to copying the job's own bytes. Files that do not match are copied with hashing folded into the copy, so the recorded digest is always of the bytes actually staged.

**Sealing and promotion.** The `files` blob is sorted by path, then `manifest` records `bytes`, `files` and `files_digest` and is sealed. Promotion is two renames: the sealed generation lands inside the entry (durable via directory sync on unix), then `current.tmp` is written and synced and renamed over `current`. A reader resolving `current` sees the old generation or the new one — never a torn name, never a directory still being written. A canceled or failed publish removes its staging and leaves `current` untouched.

**Skip vocabulary.** A commit that published nothing answers a stable reason: `busy` (a live writer holds the entry), `canceled` (cancel or deadline), `empty` (zero files across every target), `unchanged` (the staged listing is identical to the source generation's — the bytes are already published).

## Measured availability and the costly hit (K08)

Every declared entry's carrier (`attach::Attached`) accumulates what the attempt measured, and finalization stamps the commit's half back onto it: `commit_ns` plus a `Committed` answer — `Sealed { staged_bytes, reused_bytes }` (the dirty side is `staged − reused`: what the job's view rewrote versus the source generation), `Skipped(reason)`, or `Failed`. The terminal `AttemptSummary` (format 3) carries one bounded `CacheRecord` per entry in declaration order — at most `MAX_CACHE_RECORDS` (16; the schema caps declarations at 8) — with the class's wire code, the outcome as `"hit"` or the `Miss` reason, every restore/commit duration as `Option` (a phase that never ran is absent, never zero), file/byte/copied counts, the backend flag, the commit's staged/reused/dirty bytes and publish answer (`"sealed"`, a skip reason or `"failed"`, absent when the verdict left nothing to publish), and the `costly_hit` flag below. `image_present` records whether the pinned image was already in the worker's store — the `podman image exists` fast path — versus an actual download.

**The costly-hit rule** (`attach::Attached::costly_hit`) flags a *nominal* hit whose restore plausibly cost more than rebuilding the dependency would have — because that is exactly when a cache is hurting rather than helping. A hit is flagged when either clause holds:

- `copied_all` — the clone backend is `Backend::Reflink` yet `copied_bytes == bytes` with a non-empty payload: the filesystem refused every file, so the "hit" paid a full copy anyway.
- `slow` — `lock_wait_ns + clone_ns` exceeds `COSTLY_HIT_NS` (5 s). A healthy restore — a per-file `FICLONE` pass, or a warm copy of a typical dependency payload at even 100 MiB/s — is nowhere near that; five seconds is deliberately generous so only implausible restores are flagged.

The flag is a diagnostic, never a verdict: it lands as `costly_hit` on the summary record and as a `cache_costly_hit` notice (`executor::Notice::CostlyCacheHit`) carrying the measured stats as evidence. It never fails an attempt.

The same sweep that reclaims (`gc::sweep`, at worker start and after every attempt's finalization) also produces the worker's **availability snapshot** — the pass already counts entries, generations and payload bytes, so the snapshot costs no second walk: `Notice::Availability` carries the sorted held-image digests (bounded by `images::MAX_HELD`), the in-flight pull count, and cache-root occupancy (entries, generations, payload bytes held — partial when the pass truncated). Part 08's placement consumes this feed; see [executor](executor.md).

## Leases and reclamation (K03)

A lease is a pin on an entry (`lease/<id>`, body `<expires> <owner>`): while any marker is live, nothing inside the entry is collected — a reader mid-clone or a writer mid-publish is never undercut. A lease reads live while `min(declared expiry, mtime + MAX_TTL)` is in the future, so a torn or corrupt marker still pins until it is provably old. A restore holds one for the attempt's run; release is delete-on-drop, and a crashed holder's marker simply expires.

`gc::sweep` runs one bounded pass — at worker start (off the start path, after recovery) and after every attempt's finalization, one at a time (`WouldBlock` skips; the running pass covers the work). The pass is bounded by a work counter (`DEFAULT_PASS_WORK`, 100k directory entries and removals): hitting the bound stops the pass cleanly, marked `truncated`, and the next pass continues.

Per entry, in order: sweep expired lease markers; remove stale `writing/` trees (no live lock and the directory older than the lease bound); then retention — `current`'s generation stays, the newest other generation stays as the spare, older non-current generations are removed oldest-first. `current` is the pointer GC trusts: a generation it names is never deleted, and a pointer naming nothing — or carrying bytes that are not a name — is counted `stale_current` and left for the next publication to overwrite.

**Budget.** When total payload bytes (per the sealed manifests) exceed `DEFAULT_BUDGET_BYTES` (50 GiB — a fixed ceiling, not a config key), the pass evicts non-current generations oldest-first across entries until under budget or out of candidates; each entry's leases are re-checked at eviction time so a reader that pinned mid-pass keeps its generation. Currents are never candidates, so a store can stay over budget rather than lose what `current` names.

Every stat is counted — entries seen, active and expired leases, removed staging, generations, freed bytes, stale pointers, failures, truncation — and reported once as `cache_swept` when the pass did work. A quiet pass stays quiet.

## Remote hydration (Q08)

A worker's warm path stays local: **a local hit never traverses the controller or the WAN**. Remote hydration is a miss path only — `restore::restore_remote` consults the transport exclusively in the branch where the local lookup answered a `Miss`, and never for `invalid` (a declared path that cannot serve wants no bytes at all). What a hydration installs becomes a normal local generation, so the next compatible attempt hits it locally.

**The bundle.** One sealed generation travels as a canonical byte stream: a 40-byte head (12-byte magic `snc.cache.b1`, format `1`, three reserved zero bytes, then `manifest_len`, `files_len` and `payload_len` as big-endian `u64`), the exact `manifest` bytes, the exact `files` bytes, then every payload file concatenated in listing order (`payload/…` sorted by path). The stream's BLAKE3 digest is the bundle id: content addressing, store dedup and resume validation in one value. Every chunk carries the running BLAKE3 of the prefix it extends, so corruption is caught at the chunk that caused it; the whole-stream digest is checked again before anything is installed.

**Messages.** Protocol 7, over the bulk transport — the control stream never carries cache bytes. A fetch is `CacheNeed { attempt, tenant, repo, class, trust, os, arch, toolchain, name, key, offset, have }` (`key` is the entry key; `offset`/`have` are the resume request, the empty digest at offset 0) answered by `CacheGrant { total, offset, prefix, digest }`, then ordered `CacheChunk { offset, bytes, prefix }` frames, then the terminal `CacheEnd { digest }`. An offer is `CacheOffer { …, total, digest }` answered by a grant (or `CacheEnd` when the store already holds that digest), then `CachePush { offset, bytes }` frames, then `CachePushEnd { digest }`. Refusals are `CacheRefused { attempt, code }` with a stable code: `no_bundle` (1), `denied` (2, not held or tenant/repo/trust mismatch), `wrong_scope` (3), `busy` (4), `too_large` (5), `store` (6). `aborted` (7) is worker-internal and never sent. A serve hands the link one chunk per frame — 48 KiB, because a chunk's running digest cannot be re-derived from split pieces — and a receiver accepts up to 1 MiB, so a wider framing needs no store change. Bundles are capped at 64 GiB.

**Authorization.** A request or offer is fenced by the attempt it names: the controller resolves it through `dispatch::attempt_scope` and requires the worker to hold it and the message's tenant, repo and trust to equal the job context's — the same trust boundary the manifest enforces again on arrival. A refusal is `denied`; nothing about the store's contents crosses it.

**Resume.** A hydration transfers into `<entry>/writing/remote.part` under the entry's single-writer marker (`writing/.lock`) and a lease — a live publisher is a skip, and GC can never take the entry mid-transfer. The worker hashes the partial prefix it already holds and asks to continue from it; the controller serves from that offset only when its bundle really extends the prefix, otherwise it answers offset 0 and the worker truncates. Bytes already on disk are never re-sent and never spliced: a prefix that does not match is dropped (`corrupt` — the partial can never verify) while a transfer cut short by the network or the budget keeps its partial for the next attempt. A completed partial is deleted; a stale one is reaped with the rest of `writing/`.

**The restore-cost bound.** A hydration may spend at most `min(5 s, job timeout / 4)` (`remote::BUDGET_MAX`, the job's own allowance read from its spec). The deadline bounds the whole transfer, and once at least 250 ms of it has been measured the worker extrapolates the measured rate: when the estimated remaining transfer no longer fits the budget that is left, it stops. An aborted transfer is `Miss::Unavailable` on the entry — a rebuild, never a wait — and keeps its partial for a later attempt. A stalling link cannot outlive the deadline.

**Install and promotion.** The received stream is decoded into a staging generation under `writing/`: the manifest must decode, be sealed and pass the *same* `Manifest::compatible` boundary check the local lookup runs (wrong tenant, repo, class, trust, platform, toolchain, name, key or compat is the same typed miss a local generation would answer); the `files` blob's digest must match the manifest's pin; every payload file is written and re-hashed against the listing entry that names it, with modes applied. Then the targets are materialized through the same `restore::materialize` a local hit uses — reflink or bounded copy — and the generation is promoted with the same two renames a publication uses: the directory lands inside the entry, then `current` is swapped atomically. Until that swap, nothing of the transfer is visible to a reader; a bundle that fails any check never serves, and no partial of it survives.

**Offers.** After a verdict's terminal report has left — never before, and never on its critical path — the worker may offer each generation it sealed to the controller: hash the generation, offer the metadata, stream the canonical bytes. The whole offer is bounded by `OFFER_BUDGET` (30 s) and the attempt's cancel flag; a refusal, a lost session or a passed deadline simply drops it. The controller's store mirrors the worker layout under `<data_dir>/remote-cache`: `<repo>/<class>/<trust>/<platform>/<toolchain16>/<name>/<entry>/<bundle-id>.bundle`, with `current` naming the bundle id a fetch is served. An incoming offer stages under the same `writing/` marker, verifies the whole stream by hashing what landed, and promotes by rename plus the `current` swap — an offer of a digest already stored is answered as stored and changes nothing.

**What is never served.** Corrupt content (a chunk that fails its running digest, a stream that fails its digest, a listing that disagrees with the manifest) and wrong-scope content (any boundary or compat mismatch) are typed misses, and a hydration neither materializes nor promotes them.

**Measured.** A hydrated restore records three facts on its `Stats`: `remote_ns`, the transfer's wall time (a duration, absent when no transfer ran — a local hit leaves it `None`); `remote_bytes`, the bytes actually delivered (a count, `0` when none, never counting a resumed prefix); and `remote_from`, the offset a resume began at (absent for a cold transfer and for no transfer at all).

## Compiler state (K06)

A `class: compiler` entry is a stable toolchain namespace whose tool owns per-input invalidation: Sentinel pins *where* compiler state lives and guarantees a writable view on every attempt, while the compiler (ccache, sccache, rustc's incremental store, go's build cache) decides per input what is still fresh. That split is what lets compiler state persist across small source and lockfile edits — a complete source hash in the outer key would destroy reuse that the tool's own content keys already express inside the namespace.

**Stem serving.** `attach::entry_key` maps a compiler request to its key *stem* — everything before the last `-` of the rendered key — so the entry directory and its `current` pointer span every volatile tail under one stem, and `Manifest::compatible` re-verifies the stem against the recorded key. A generation sealed under `cc-normal-<h1>` therefore serves a request for `cc-normal-<h2>`: a one-line source or lockfile edit moves the hash tail, not the stem, and the restored view carries whatever the last publisher left — stale inputs and all, for the tool to reconcile.

**Mode namespacing.** The convention is `cc-<mode>-<hash>`: `cc-normal-…`, `cc-race-…`, `cc-coverage-…`, `cc-experiment-…` are four stems, hence four entry directories with four `current` pointers. Instrumented and uninstrumented outputs can never serve each other, because the store-level boundary is the stem itself rather than a flag a step might mis-set. Keep exactly one volatile component last: everything before the final `-` is the namespace, so a second `hash_files` inside it (say, of the lockfile) makes that input part of the namespace — a deliberate choice, not an accident.

**Architecture and toolchain isolation.** `linux-x86_64` versus `linux-aarch64` are different scope-path components *and* different manifest platforms: a cross-arch lookup answers `absent`, a manifest moved across answers `wrong_platform` — never a cross-arch serve. The `<toolchain16>` component pins the image digest or tool versions the same way, so a toolchain upgrade is a new namespace too.

**`flags` is the recipe channel.** `Compat::Compiler { flags }` is a pin *inside* a stem for recipes that want a check tighter than the stem provides. A bare declaration leaves it `""`: the stem is the whole namespace — it already picks the entry directory and is re-verified in the manifest — so recording `key_stem(key)` there would only ever duplicate the check just run, and a stem longer than the 256-byte field bound would make the manifest unreadable for no benefit. A recipe (K07) that needs a flag-regime split under one stem pins a rendered token instead. Note that `current` is one pointer per entry directory: regimes that must not interleave belong in the stem, since two flag namespaces sharing a stem would contend on the pointer.

**A hit is never a cached verdict.** A compiler-cache hit restores *bytes* — the writable view the job's steps read — and nothing else. `execute` runs every declared step unconditionally; `job.caches` is consulted only by restore during preparation and publish during finalization, and the `Outcome::Hit` type itself carries only a manifest and a byte count. Go's documented build-cache/test-result distinction applies: forcing fresh test execution (`-count=1`) does not require discarding compiler reuse. A cache hit can never suppress a test, skip a step, or inherit a previous run's verdict. The Linux fixture `fixtures/compiler/fakecc.sh` — a content-keyed compiler stand-in — exercises this through real container mounts and restore/publish round-trips in `sentinel-worker/tests/compiler_cache.rs` and `sentinel-cache/tests/compiler.rs`.

## Recipe library (K07)

[recipes](recipes.md) publishes nine tested pipelines — a custom compiler tool, Go, Rust, npm, pnpm, Bun, Python, Maven and Gradle — showing how each toolchain's stores map onto these classes, which environment variables wire the mounts, how lockfile and toolchain changes move through the key and scope, and the measured cold/warm/small-edit/changed-dependency/changed-toolchain behavior.

## Verification (K09)

The adversarial pass over the guarantees above lives in
`crates/sentinel-cache/tests/k09.rs` (store level, threaded, both OSes)
and `crates/sentinel-worker/tests/k09.rs` (executor level, gated on
`SENTINEL_PODMAN_TESTS` like the rest of the suite). What each case
proves:

- **Concurrent clone/write isolation** —
  `concurrent_clones_during_republishing_are_never_torn`: eight readers
  loop `restore` on one entry while a writer republishes it and
  `gc::sweep` runs under a deliberately tiny budget. Every cloned view
  must read as exactly one generation's bytes (each generation's payload
  carries its own marker), the only answers are `hit` or a typed miss
  (`absent`, `corrupt`, `unavailable`), and afterward every surviving
  generation is re-verified — manifest, listing digest and every listed
  file's own digest. A sealed generation is never mutated; a reader is
  never torn.
- **Canceled writers** —
  `a_writer_canceled_mid_stage_promotes_nothing_and_the_store_recovers`:
  the cancel trips on the first poll after `writing/gen-*` exists — inside
  materialization, not the walk. Nothing promotes, `current` does not
  move, no staged tree survives; a dead writer's remains are reaped once
  provably old (and a still-warm one is never reaped), and the next
  publish seals cleanly.
- **Eviction during active use** —
  `eviction_during_active_use_never_undercuts_a_lease`: under a forcing
  budget the leased entry keeps both generations while the unleashed
  sibling loses its spare; once the pin drops, the next sweep takes it.
  The mid-clone pin itself is `tests/gc.rs::a_reader_mid_clone_keeps_its_generation_through_budget_eviction`.
- **Tampered state** —
  `tampered_state_is_a_typed_miss_and_republish_heals`: a rewritten
  `files` blob, a flipped manifest byte, a garbage `current`, a payload
  file the listing never recorded, a listed file deleted, and a listed
  file swapped for a symlink are each a typed miss — never a panic,
  never a wrong serve — and a republish heals the entry. This case found
  a real defect: restore trusted the tree to be the listing, so planted
  or missing payload files served silently. `restore::materialize` now
  verifies each `payload/<i>` tree is exactly the sealed listing
  (`check_payload_tree`, bounded by the publish walk's depth bound)
  before cloning — the listing is the payload's whole authority.
- **Trust change** —
  `protected_state_never_serves_or_writes_pull_request` plus the
  executor-level `a_pull_request_attempt_never_touches_protected_state`:
  protected bytes answer `absent` through the scope path and
  `wrong_trust` through a directory moved across; a pull-request attempt
  seals only `pull_request` state and leaves the protected entry
  byte-identical; a wrong-trust commit is refused before a directory
  exists (also `tests/publish.rs`).
- **Disk pressure** —
  `a_full_filesystem_fails_the_publish_cleanly` (linux-only, gated on
  `SENTINEL_MOUNT_TESTS=1` as a mount-capable account): a real `ENOSPC`
  mid-publish on an 8 MiB tmpfs — no promotion, `current` untouched,
  staging removed, and a clean seal once space returns. Its executor
  half is `sentinel-worker/tests/k09.rs::a_failing_publish_is_a_note_never_the_verdict`:
  a publication that cannot take the write lock still passes the job —
  the failure lands as a cache note and `publish: "failed"` on the
  summary record, never the verdict.
- **Concurrent writers on one entry** —
  `parallel_writers_are_serialized_and_never_double_promote`: a held
  `writing/.lock` makes every commit `busy`; raced for real behind a
  barrier with a deliberately slow stage, exactly one writer stages at a
  time — the loser skips, staging never interleaves, `current` never
  double-promotes.
- **Remote hydration** —
  `tests/remote.rs` drives the real miss path against an in-memory
  controller implementing the link's `Remote` seam: a cold transfer
  serves the job, installs a generation the store then serves locally,
  and a later attempt's transport is never called; an interrupted
  transfer resumes exactly at the offset it stopped — no prefix is
  re-sent and the partial is gone once it completes; a corrupted chunk
  and a bundle sealed for another trust are typed misses (`corrupt`,
  `wrong_trust`) that materialize nothing, leave no `current` and drop
  the partial; and a controller without the bundle leaves the local miss,
  partial and pointer untouched.

Cases not re-covered here because an earlier task's test already proves
them: lease staleness and `writing/` reap boundaries (`tests/gc.rs`),
walk-phase cancellation and trust-mismatch refusal (`tests/publish.rs`),
malformed compiler manifests (`tests/compiler.rs`). The mount-gated case
reports its skip rather than passing silently; on hosts without
`mount(2)` it is the one case left to a staging host's run.

## Versioned surface

The manifest and `files` blob formats are versioned contracts under [compatibility](compatibility.md); the miss-reason strings are the report vocabulary and change only there too. The remote bundle stream (`remote::STREAM_MAGIC`, format `1`) is a versioned transfer contract in the same sense. The pipeline-facing half — `cache.class`, its default, and the compiled digest — is schema 1 behavior documented in [pipeline schema](pipeline-schema.md).
