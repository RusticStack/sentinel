# Worker-local cache: classes, scopes and manifests (K01)

Sentinel keeps its caches on the worker that runs the job: no network fetch on a warm hit, no shared mutable volume between tenants. This document is the metadata contract — which cache classes exist, what boundary a generation is sealed under, and the vocabulary a lookup answers with. Immutable generations, writable clones, publication leases, garbage collection and remote hydration are later tasks (K02+); everything here is what they share: paths, formats and reasons.

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

A cache must degrade a build to a rebuild, never break it: every failure mode above is a reasoned miss on the lookup path, and nothing in the read path panics or guesses.

## Publication (K03)

Publication is finalization work, off the verdict's path: after a job's steps finish and before its workspace is destroyed, the worker commits each attached cache whose verdict left real state — a passed job, or one that failed its commands (`command_failed`, `command_signaled`, `out_of_memory`). A canceled, timed-out, un-started or infrastructure-failed attempt publishes nothing, and a cache failure never changes the verdict: each entry's outcome is a diagnostic note (`cache_published`), never a build failure.

**Authorization.** `publish::commit` refuses an attachment whose scope trust is not the job's (`TrustMismatch`), before a single directory is made. There is no cross-trust promotion in v1: a pull-request publication can only ever produce `pull_request` entries. The entry directory is derived exactly as restore derives it (`attach::entry_key` — the key stem for `downloads`/`compiler`, the full key for `dependencies`), so the two paths always meet.

**One writer per entry.** Staging ownership is `writing/.lock`, taken with `create_new` — never waited on. A live marker is a `busy` skip; a marker older than `lease::MAX_TTL` (by declared expiry and by mtime, whichever reads live shorter) is a dead writer's and is reaped in place. Releasing removes the marker and the `writing/` directory while empty, so a release can never pull staging from under the next writer.

**Staging.** The generation is built at `writing/gen-<unix_ms>-<rand>` — never inside a live generation. The walk of the declared target directories follows no symlinks, skips non-regular and unencodable entries, and is bounded in depth (64, the `hash_files` bound), entry count (`MAX_FILE_ENTRIES`), blob size (`MAX_FILES_BLOB_BYTES`) and time: the whole publish batch runs under `CACHE_PUBLISH_TIMEOUT` (3 minutes) with cancel polled every 256 files.

**Reuse.** A file whose path, size and mode match the source generation's listing is hashed once; a digest match is staged by hardlinking out of that generation — one inode, no copy — and the staged name is re-hashed before seal, so a drifted generation can never poison its successor: a failed check falls back to copying the job's own bytes. Files that do not match are copied with hashing folded into the copy, so the recorded digest is always of the bytes actually staged.

**Sealing and promotion.** The `files` blob is sorted by path, then `manifest` records `bytes`, `files` and `files_digest` and is sealed. Promotion is two renames: the sealed generation lands inside the entry (durable via directory sync on unix), then `current.tmp` is written and synced and renamed over `current`. A reader resolving `current` sees the old generation or the new one — never a torn name, never a directory still being written. A canceled or failed publish removes its staging and leaves `current` untouched.

**Skip vocabulary.** A commit that published nothing answers a stable reason: `busy` (a live writer holds the entry), `canceled` (cancel or deadline), `empty` (zero files across every target), `unchanged` (the staged listing is identical to the source generation's — the bytes are already published).

## Leases and reclamation (K03)

A lease is a pin on an entry (`lease/<id>`, body `<expires> <owner>`): while any marker is live, nothing inside the entry is collected — a reader mid-clone or a writer mid-publish is never undercut. A lease reads live while `min(declared expiry, mtime + MAX_TTL)` is in the future, so a torn or corrupt marker still pins until it is provably old. A restore holds one for the attempt's run; release is delete-on-drop, and a crashed holder's marker simply expires.

`gc::sweep` runs one bounded pass — at worker start (off the start path, after recovery) and after every attempt's finalization, one at a time (`WouldBlock` skips; the running pass covers the work). The pass is bounded by a work counter (`DEFAULT_PASS_WORK`, 100k directory entries and removals): hitting the bound stops the pass cleanly, marked `truncated`, and the next pass continues.

Per entry, in order: sweep expired lease markers; remove stale `writing/` trees (no live lock and the directory older than the lease bound); then retention — `current`'s generation stays, the newest other generation stays as the spare, older non-current generations are removed oldest-first. `current` is the pointer GC trusts: a generation it names is never deleted, and a pointer naming nothing — or carrying bytes that are not a name — is counted `stale_current` and left for the next publication to overwrite.

**Budget.** When total payload bytes (per the sealed manifests) exceed `DEFAULT_BUDGET_BYTES` (50 GiB — a fixed ceiling, not a config key), the pass evicts non-current generations oldest-first across entries until under budget or out of candidates; each entry's leases are re-checked at eviction time so a reader that pinned mid-pass keeps its generation. Currents are never candidates, so a store can stay over budget rather than lose what `current` names.

Every stat is counted — entries seen, active and expired leases, removed staging, generations, freed bytes, stale pointers, failures, truncation — and reported once as `cache_swept` when the pass did work. A quiet pass stays quiet.

## Versioned surface

The manifest and `files` blob formats are versioned contracts under [compatibility](compatibility.md); the miss-reason strings are the report vocabulary and change only there too. The pipeline-facing half — `cache.class`, its default, and the compiled digest — is schema 1 behavior documented in [pipeline schema](pipeline-schema.md).
