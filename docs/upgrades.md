# Upgrades, version skew and rollback (R05)

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

Stop the controller, replace the binary (and `sentinel-web` with it; [web interface](web-ui.md)), start it. When the database has pending migrations the controller first copies it aside — `metadata.sqlite.v047` for a database at schema 47, `VACUUM INTO` on its own connection — logs `schema_upgraded` with the copy's path, then migrates. The newest two copies are kept. A host-local `admin` command of the new release does exactly the same, so running one first is also an upgrade.

A migration that fails rolls back its own transaction: the database stays at the last version that committed, never half-way through one, and the controller refuses to start with the reason, the schema it reached and the copy to roll back to:

```text
upgrading the database from schema 47 failed at migration 48: …; it is at schema 47;
to roll back, stop, replace metadata.sqlite with /var/lib/sentinel/metadata.sqlite.v047
and start the previous release
```

## Rolling back

- **Within readable limits** — every migration since the older release is readable by it (listed in [compatibility](compatibility.md) with its `readable_by`): stop, put the older binary back, start. It runs on the newer database as it is, logging `schema_newer`; nothing is migrated backwards.
- **Otherwise**: stop; replace `metadata.sqlite` with the pre-migration copy (`metadata.sqlite.vNNN`, the old schema) and remove `metadata.sqlite-wal` and `-shm`; start the older release. What was written after the upgrade is lost from the database; objects and logs it wrote stay on disk as orphans the storage pass collects, and workers reconcile against the restored controller on reconnect.
- **Without a copy** (it was pruned): restore the last backup taken before the upgrade with the older release's `admin restore`.

### Declaring rollback compatibility

Each migration from schema 48 on records `readable_by` in `schema_migrations`: the oldest schema whose binary may keep running on the result. A binary that opens a newer database runs on it only when the largest `readable_by` among the migrations it does not know is at most its own schema. The default is the migration's own version — no rollback past it without a copy. `schema::READABLE_BY` lists the exceptions, and a migration belongs there only when it adds nothing an older binary could break or be broken by: an index; a column no older statement reads, and whose default every older insert satisfies; a table no older code touches. Triggers an older binary would trip, dropped or renamed columns, changed constraints and data rewrites are never readable by an older schema. Today: 45 (indexes only) is readable by 44 and 48 (a column on `schema_migrations` and on `workers`) by 47. Releases before 48 predate the mechanism and refuse every newer database.

## Verification

`crates/sentinel-store/tests/upgrade.rs`: a database built at schema LATEST−3 migrates with a copy at its old schema taken first, records `readable_by` (45 → 44, 46 → 46, 48 → 47), takes no copy when nothing is pending, and keeps only the newest two copies; a migration that fails (migration 4 against inconsistent ownership) leaves the database at 3 and names the copy — still at 3 — in a message that says how to roll back; a newer database whose unknown migration is readable opens as it is, and one that needs a newer schema is refused and reported blocking by the preflight; the preflight reports pending migrations, room and key without writing a byte; a worker's software label is printable and bounded. `crates/sentinel-store/tests/authorization.rs` still refuses a future version with no declaration.
