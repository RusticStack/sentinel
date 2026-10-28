# Upgrades, version skew and rollback

Sentinel has four versioned surfaces, each with its own rules ([compatibility](compatibility.md)): the **metadata database** (`schema_migrations`), the **worker protocol** (negotiated per session), the **HTTP API** (`/api/v1`, additive) and the **pipeline and backup formats**. This page is how to move a deployment from one release to the next, and back.

## What each release promises

| Surface | Forward | Skew supported | Backward |
|---|---|---|---|
| Metadata database | Forward-only migrations, one transaction each, applied at the controller's (or an `admin` command's) first open | — (one controller owns it) | A newer database runs on an older release **only** when every migration that release does not know declares it readable (`readable_by`, below); otherwise roll back from the pre-migration copy or a backup |
| Worker protocol | The controller speaks protocols 1–10 (`SUPPORTED_MIN..=SUPPORTED_MAX`) and picks the highest both sides share at every hello | **Upgrade the controller first.** A worker one release behind keeps working; a feature needing a newer protocol (secret delivery, profiles) is simply not offered to it. A structural change raises `SUPPORTED_MAX` first and `SUPPORTED_MIN` only a release later, so a worker never falls out of range in one step | A rolled-back worker renegotiates down at its next hello |
| HTTP API | Additive within `v1`: new routes and fields, never a removed or retyped one | CLIs, MCP clients and `sentinel-web` of any `v1` release; clients ignore unknown fields | Clients must not depend on fields a rollback removes |
| Backups | `sentinel.backup/1` | A newer release restores an older backup and migrates it | An older release cannot restore a newer backup's snapshot unless it is readable (as above) |

`GET /api/v1/version` (any signed-in caller) answers the server's version, the database schema against the binary's, and the worker protocol range; `GET /workers` shows each worker's negotiated `protocol` and the `software` it announced ([API](api.md)), and the workers page shows both.

## Before upgrading

1. **Back up** ([backup](backup.md)) — and keep the master key where the backup is not.
2. **Check** the stopped controller's data directory with the **new** binary: `sentinel admin upgrade check --data-dir /var/lib/sentinel`. It opens the database read-only (it never migrates) and reports the schema against the binary's, the migrations that would run, SQLite's `quick_check`, the free space the upgrade needs (twice the database: the pre-migration copy plus growth), whether sealed values exist and `master.key` is present, and every enrolled worker's protocol and software, marking any this build would refuse. It exits 2 when something blocks: a database newer than the binary can read, a failed integrity check, too little room, sealed values without the key.
3. Plan the worker order: controller first, then workers at their own pace.

## Upgrading

Stop the controller, replace the binary (and `sentinel-web` with it; [web interface](web-ui.md)), start it. When the database has pending migrations the controller first copies it aside — `metadata.sqlite.v047` for a database at schema 47, `VACUUM INTO` on its own connection, written as `metadata.sqlite.v047.partial` and renamed once durable, so a copy cut short is never taken for one — logs `schema_upgraded` with the copy's path, then migrates. The newest two copies are kept. A host-local `admin` command of the new release does exactly the same, so running one first is also an upgrade.

A migration that fails rolls back its own transaction: the database stays at the last version that committed, never half-way through one, and the controller refuses to start with the reason, the schema it reached and the copy to roll back to:

```text
upgrading the database from schema 47 failed at migration 48: …; it is at schema 47;
to roll back, stop, replace metadata.sqlite with /var/lib/sentinel/metadata.sqlite.v047
and start the previous release
```

## Rolling back

- **Within readable limits** — every migration since the older release is readable by it (each is listed in [compatibility](compatibility.md)): stop, put the older binary back, start. It runs on the newer database as it is, logging `schema_newer`; nothing is migrated backwards.
- **Otherwise**: stop; replace `metadata.sqlite` with the pre-migration copy (`metadata.sqlite.vNNN`, the old schema) and remove `metadata.sqlite-wal` and `-shm`; start the older release. What was written after the upgrade is lost from the database; objects and logs it wrote stay on disk as orphans the storage pass collects, and workers reconcile against the restored controller on reconnect.
- **Without a copy** (it was pruned): restore the last backup taken before the upgrade with the older release's `admin restore`.

### Declaring rollback compatibility

Each migration from schema 48 on records `readable_by` in `schema_migrations`: the oldest schema whose binary may keep running on the result. A binary that opens a newer database runs on it only when the largest `readable_by` among the migrations it does not know is at most its own schema. The default is the migration's own version — no rollback past it without a copy. `schema::READABLE_BY` lists the exceptions, and a migration belongs there only when it adds nothing an older binary could break or be broken by: an index; a column no older statement reads, and whose default every older insert satisfies; a table no older code touches. Triggers an older binary would trip, dropped or renamed columns, changed constraints and data rewrites are never readable by an older schema. The current exceptions are 45 readable by 44, 48 by 47, 49 by 48, 52 by 51 and 53 by 51; [compatibility](compatibility.md) says why for each. Migrations 54 (`jobs.runtime`: an older binary would place a microVM or Windows job on any worker) and 55 (`oauth_grants.created_session`: older issuance statements would not record the provenance the new revocation rules need) are deliberately **not** listed. Releases before 48 predate the mechanism and refuse every newer database.

### Rollback matrix

A database at schema N runs on release R only when no migration in (R, N] declares a `readable_by` above R. The releases that matter are the `READABLE_BY` targets (44, 47, 48, 51) plus the last two before the first non-readable migration of the 54/55 line (53, 54):

| Older release R | database at 53 | database at 54 | database at 55 (current) |
|---|---|---|---|
| 44 | copy or backup | copy or backup | copy or backup |
| 47 | copy or backup | copy or backup | copy or backup |
| 48 | copy or backup | copy or backup | copy or backup |
| 51 | runs as is | copy or backup | copy or backup |
| 53 | runs as is | copy or backup | copy or backup |
| 54 | n/a | runs as is | copy or backup |

Because migrations 54 and 55 are not readable by anything older, **a deployment that has started on the current schema can only go back to an older release from the pre-migration copy or a backup**; rolling back to 54 or 53 means restoring `metadata.sqlite.v054` or `.v053`. What the restore loses is what was written after the upgrade: job runtime requirements and session-minted service grants created since then. The copy is taken only when the upgrade had a migration to run, so a deployment already at 55 has none for 55 itself.

## Behavior that changes with an upgrade

Everything below is additive on the wire. A client of any `v1` release keeps working, but these change what an upgraded deployment does; each has its full entry in [compatibility](compatibility.md).

| Change | Schema | What an operator sees |
|---|---|---|
| OAuth client registration | 43 | Upgraded deployments stop accepting anonymous `POST /oauth/register` (`403 access_denied`) until an operator runs `sentinel admin policy set --oauth-client-registration open`; client ID metadata documents are the default |
| Secret hardening | 44 | A retry of a secret write made before the upgrade runs again |
| Verified email identity, first-run setup, auto-join | 50, 52, 53 | New routes and settings; existing accounts keep working without an address |
| Job runtime | 54 | `runs_on.os` and `runs_on.isolation`; a job that states neither is placed as before, one that states them goes only to a worker that announces every bit it needs ([worker link](worker-link.md)) |
| Session grant provenance | 55 | New session-minted service grants revoke by session, including at logout-all; legacy rows keep the timestamp-window fallback ([authorization](authorization.md)) |
| Pushed cancellation | protocol 11 | Controller first; a protocol-10 worker still cancels at its next heartbeat |

New routes are listed in the [API](api.md). Check `GET /api/v1/version` before relying on a route a rollback may remove.

## Verification

`crates/sentinel-store/tests/upgrade.rs`: a database built at schema LATEST−3 migrates with a copy at its old schema taken first, records `readable_by` (45 → 44, 46 → 46, 48 → 47, 49 → 48, 50 → 50, 52 → 51, 53 → 51), takes no copy when nothing is pending, and keeps only the newest two copies; a migration that fails (migration 4 against inconsistent ownership) leaves the database at 3 and names the copy — still at 3 — in a message that says how to roll back; a newer database whose unknown migration is readable opens as it is, and one that needs a newer schema is refused and reported blocking by the preflight; the preflight reports pending migrations, room and key without writing a byte; a worker's software label is printable and bounded. `every_readable_by_release_upgrades_and_the_rollback_matrix_matches_the_docs` upgrades a database built at each `READABLE_BY` target (44, 47, 48, 51) and at 53 and 54 to the latest schema, checks the pre-migration copy is that release's database, and checks the rollback matrix above against the `readable_by` column; the migration 55 test keeps legacy grant rows with no provenance. `crates/sentinel-store/tests/authorization.rs` still refuses a future version with no declaration.
