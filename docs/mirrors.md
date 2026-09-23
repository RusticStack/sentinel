# Worker-local Git mirrors (K04)

A worker keeps one **bare mirror per repository binding** — mirrors serve bound repositories only; a manual run names its own remote (possibly a local path) and always checks out direct, so it can never read another repository's store or feed its own objects into one — under
`<data_dir>/mirrors/<rep_id>/`, keyed by the dispatched `RepoId` — never by
remote URL, so a renamed remote cannot collide two tenants' stores. Attempts
share it under a writer lock plus reader leases, and each worktree is
materialized from it with a **private** object store.

The win is fetch traffic: a repository's history accumulates in the mirror
once, and each attempt negotiates only what is new instead of re-cloning or
re-fetching a depth-1 snapshot with no common base. The costs that remain —
init, the object copy, the worktree write — are measured and reported
separately as `checkout_materialize_ns`; the mirror update is
`checkout_fetch_ns`; `checkout_ns` stays the total.

## Layout

```
<data_dir>/mirrors/
    <rep_id>/            bare repository (HEAD, objects/, refs/)
    <rep_id>.lock        flock'd writer lock (content is operator provenance)
    <rep_id>.leases/     reader leases, one file per materializing attempt
    <rep_id>.suspect     mark left by store damage → rebuild
    <rep_id>/sentinel-remote  the remote that filled the store; another remote → rebuild
    <rep_id>.askpass/    credential helper, only for the fetch in flight
```

## Serialized incremental fetch

One writer at a time per mirror holds `flock(LOCK_EX)` on the sibling
`.lock` file. The lock is kernel-held on an open file: a process that dies
releases it, so there is **no stale state to take over**; the bounded
non-blocking `flock` poll (120 s, or the attempt's deadline when smaller)
is the whole wait, and overrunning it falls back to a direct fetch. The
file's contents — owner pid and deadline — are for an operator's eyes only.

The fetch itself is a normal incremental `git fetch` of two wants: the
**pinned commit itself** and, when the dispatch names a ref the binding
allows, `+ref:refs/sentinel/event`. Nothing is cloned again, nothing is
shallow, and `gc.auto`/`maintenance.auto` are forced off so pruning only
ever happens through the lease-checked path described below. A `file://`
remote accepts a raw commit id as a want; a real server that refuses an
unadvertised SHA gets the event-ref want instead — the commit usually rides
its history — with the SHA alone as the last resort. Those narrower wants
are tried only when the server refused a want; an authentication, network
or store failure is not asked twice more. Credentials reuse the
direct checkout's discipline exactly: the same askpass/`GIT_SSH` files,
owner-only, removed when the fetch returns (a crashed fetch's helper is
dropped by recovery on restart, and by the next writer's `ensure`).

A partial fetch is safe: objects that reached the store are complete (Git
publishes packs and loose objects by rename), the rest is re-negotiated by
the next fetch. `tmp_*` files an interrupted fetch leaves are never copied
into a workspace and never counted.

## Exact-commit verification

After every fetch the mirror verifies the pinned SHA itself —
`git rev-parse --verify --quiet <sha>^{commit}` — and writes
`refs/sentinel/pin` to it so GC can never prune what a materialization is
about to copy. A SHA that does not verify as a commit is a **preparation
failure naming the SHA**, never a fallback to a branch or another revision.
`PinnedSource.ref_name` stays provenance: it is fetched to enrich history,
never to select the checked-out revision.

## Reader-safe GC

Materialization creates a lease: `<rep_id>.leases/<attempt>` holding an
expiry timestamp — the reader's own deadline plus a minute, never a fixed
guess — published by rename (from a temp file a crashed publisher's leftover
cannot block) while the writer lock is still held, removed when the copy
finishes. `git gc --prune=now` runs only under the
writer lock, only when the store crossed a trigger (more than 16 packs or
4096 loose objects — a cache, not an archive), and only with **no live
lease**: expired leases are swept by that check, so a crashed attempt holds
GC off until its declared expiry (an unreadable record: at most the
20-minute TTL). Fetches never delete objects, so a
reader's copy only ever sees a superset of the verified store.

## Private materialization

A workspace's `.git/objects` is populated file-by-file — never
`clone --local` hardlinks, never an `alternates` pointer into shared
storage — so a job that `chmod`s or rewrites its own `.git` cannot touch
the mirror's bytes. Where the data directory's filesystem supports it, the
copy is a **reflink** (`FICLONE`: shared extents, separate inode), probed
once at worker start; elsewhere it is a plain byte copy. `tmp_*` files and
`info/alternates` are never copied. After `checkout --detach <sha>`, `HEAD`
is verified against the pin. A materialization failure marks the mirror
`suspect` only when the store itself is damaged (the health probe below
fails): a deadline, a full workspace or a checkout error on a healthy store
never forces a full refetch.

## Failure policy

Mirror failures split in two:

- **`Error::Mirror` / `Error::Io`** — the lock wait ran out, the store was
  damaged beyond a rebuild, a lease or copy failed. The worker empties the
  half-materialized workspace, runs the direct fetch, and records the route
  `MirrorFallback` plus the reason in the attempt summary.
- **`Error::Preparation`** — the remote's own answer: access refused, the
  pinned commit absent or not a commit. It propagates; a direct fetch would
  only re-ask the same question.
- **`Error::Timeout`** — the deadline is spent either way.

A mirror that does not look like a bare store, or that fails the health
probe after a fetch or verify error — Git must accept it as a bare
repository *and* every ref tip must still read as an object (`rev-list
--no-walk --all`), which catches a corrupt or truncated pack under a tip —
is rebuilt once under the lock (after any live readers drain) and retried
once; still broken reports `Mirror` and falls back. The fallback runs within
what is left of the checkout's one deadline: the mirror gets half of it,
and a mirror that ran out of its half (a cold full-history fetch of a large
repository) falls back too.

**Disk bound.** After every attempt (with the cache sweep) `Mirrors::sweep`
removes `tmp_*` leftovers of killed fetches older than an hour, removes
mirrors no writer touched for 14 days, and while the rest exceed 50 GiB
removes the least recently written — each under that mirror's writer lock
(taken without waiting) and with no live reader lease; the lock file stays.
`tmp_*` leftovers also count toward the GC trigger. The fallback reason of
a failed attempt is kept in `detail` after the failure reason.
A mirror root that cannot be opened at worker start logs
`mirrors_unavailable` once and every checkout runs direct for the life of
the process.

## Configuration

`git_mirrors = false` in the worker's configuration file disables mirrors
entirely: every checkout is the direct path and no mirror root is created.
It is a worker key — refused for the server role — and needs
`controller`/`controller_fingerprint` like the other worker keys.

## Reporting

The attempt summary carries, beside the unchanged total `checkout_ns`:

- `checkout_fetch_ns` — the mirror update, or the direct fetch;
- `checkout_materialize_ns` — init, object copy, detach and verify;
- `checkout_route` — `Direct`, `Mirror`, or `MirrorFallback` (whose reason
  sits in `detail`).

All three are `None` when not measured — never zero (summary format 2; see
[compatibility](compatibility.md)).
