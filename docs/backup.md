# Backup and restore

A controller's state is its data directory: the metadata database, the object and manifest trees, attempt logs, and a handful of files of its own. A **backup** is a consistent copy of all of it — except the master key — taken while the controller runs; a **restore** rebuilds a data directory from one, on the same host or a replacement.

## What a backup holds

```text
<dir>/objects/…              committed objects, content-addressed, shared by every backup
<dir>/manifests/…            manifest versions, immutable, shared
<dir>/logs/…                 attempt logs, mirrored incrementally, shared
<dir>/<id>/metadata.sqlite   the database at one instant
<dir>/<id>/config/…          controller.crt/.key, github-app.json, github-webhook.json,
                             github-sign-in.json, source-destinations.json, tailcat-allow, tailcat/
<dir>/<id>/backup.json       format sentinel.backup/1: schema, counts, checksums, key ids
```

`<id>` is the UTC time the backup started (`20260928T170000Z`), so ids sort by age. Objects and manifests are stored once however many backups name them, so a backup after the first copies only what is new — and every object is **rehashed while it is copied**: a file that no longer matches its digest is reported and not stored, so a backup never preserves rot. A copy an earlier backup left is **reused only after it is rehashed** against the digest the snapshot names (a matching length alone proves nothing): one that rotted in place is replaced from the data directory and counted (`objects.recopied`, `manifests.recopied` in `backup.json`, `objects_recopied` in the report). The cost is one read of the shared store per backup, in exchange for no backup naming a rotted file. A manifest version that does not match its digest at the source fails the backup with `corrupt`, since a backup cannot stand in for it.

**Consistency.** The database is copied with `VACUUM INTO` on a connection of its own — one read transaction in WAL mode, so the copy is the database at one instant while the writer keeps committing. The only ways a file the snapshot names could disappear before it is copied are reclamation, log expiry and S3 eviction; all three take the object store's maintenance lock, and a backup holds it from before the snapshot to the last copy (the storage pass and the replicator's eviction simply wait for their next turn). Objects a backup's snapshot knows are therefore always in the backup — or, for objects evicted to the external copy ([s3](s3.md)), recorded as `remote_only`.

Logs are mirrored as they are when copied: a live attempt's log is copied as far as it has come and refreshed by the next backup; a restore brings back the logs of every attempt its snapshot keeps.

## The master key

Sealed values — secret values, second-factor seeds, source credentials — are useless without `<data_dir>/master.key` ([sealed storage](sealed-storage.md)). **A backup never contains the key**: a backup that carried both would be one theft away from every secret. Instead `backup.json` records the key ids the sealed values were sealed under (`key.key_ids`), and a restore refuses to finish without a key file that opens them.

Keep the key separately, the moment it is created or rotated:

1. Copy `master.key` to offline or separately-controlled storage (a password manager's file store, a hardware-backed secret store, an encrypted USB key in a safe) — never next to the backups, never in the same cloud account.
2. After `admin key rotate --backup FILE`, keep the new file as well; the old key ids stay needed until `admin key reseal --retire` has moved every sealed value to the new key and a backup has been taken since.
3. A key file lists its ids; a backup's `key_ids` must be a subset. `sentinel admin backup list` shows them.

Losing the key loses the sealed values — the rest of the deployment restores without it, but secrets must be written again, second factors re-enrolled and source credentials re-bound.

## Taking backups

Online, on a schedule ([configuration](configuration.md)):

```toml
[backup]
dir = "/mnt/backup/sentinel"   # absolute, outside the data directory — another disk or a mounted volume
interval_secs = 3600           # 300 .. 604800, default hourly
keep = 24                      # newest kept, 1 .. 1000, default 24
```

The first backup runs one interval after start (a restarting controller does not take one per restart); a failed one is recorded and retried at the next interval, never stopping the controller. `POST /admin/backups` takes one now (`409 conflict` while one runs), `GET /admin/backups` lists them with the scheduler's state, and **Platform → Storage → Backups** shows both and has a *Back up now* button ([API](api.md)).

A backup is staged in `DIR/.<id>.partial` and renamed to `DIR/<id>` only after its `backup.json` is durable, so an interrupted one is never listed. The next backup removes every staging directory an interruption left (`partials_removed` in its report). An object the database names but the data directory lost is recorded in `backup.json`'s `objects.missing` and skipped, like one that fails its digest (`objects.corrupt`). The backup still completes, and `admin backup create` exits 2 so it is noticed ([failure drills](resilience.md)).

Offline, beside a stopped controller: `sentinel admin backup create --data-dir DATA --to DIR`. Pruning keeps the newest `keep` and removes every shared object, manifest and log file no kept backup names: `sentinel admin backup prune --dir DIR --keep N`.

**Writers are serialized.** `create` copies new shared files before its backup directory exists, so a `prune` from another process (the host-local tool beside the running scheduler) would find them named by no kept backup. Both take an exclusive advisory lock on `DIR/.lock` — `create` from before its first copy until its directory is in place, `prune` for its whole run — and wait for each other. A file system that answers `Unsupported` for advisory locks runs unlocked on purpose, leaving the host's own coordination as the only protection between `create` and `prune`; turning that answer into an error would make backups impossible there.

**Durability of the copies.** Every shared file is copied through a temporary file that is fsynced and renamed, and the directories those renames touched are fsynced (once per directory, not per file) before the backup names them and before `backup.json` is written; a restore does the same before the database lands, so a power loss after either reports success cannot lose a directory entry.

## Verifying

`sentinel admin backup verify --dir DIR [--id ID]` rehashes the snapshot against its recorded BLAKE3, runs SQLite's `PRAGMA integrity_check` on it, and rehashes every object and manifest it names; it exits 2 with the missing and corrupt paths when anything is wrong. It is a drill, not a request-path cost: schedule it (weekly, and after any storage incident) and alert on a non-zero exit. The rehash cost at chosen object counts is measured by `crates/sentinel-store/examples/backup-rehash-bench.rs` ([benchmarking](benchmarking.md#backup-rehash-cost)); no record is committed yet, and the 1.4 s drill figure below is a single run of one dataset.

## Restoring

On the same host after data loss, or on a replacement host:

```sh
sentinel admin restore --from /mnt/backup/sentinel [--id 20260928T170000Z] \
    --key /secure/master.key --data-dir /var/lib/sentinel
sentinel server --config /etc/sentinel/server.toml
```

The target data directory must hold no database. Every object and manifest is rehashed as it is copied (a mismatch stops the restore, `Corrupt`); the snapshot's checksum is checked first; with sealed values the key is checked against them before anything is written; the database lands last, so a half-restored directory is never mistaken for a controller's. The command then opens the store as the controller would — migrations for an older backup, object recovery — and reports what it restored and found. Objects evicted to S3 come back through the external copy's read-through once the same `[s3]` section is configured.

Because `controller.key` and `controller.crt` are restored, **workers keep their pinned fingerprint** and reconnect without re-enrollment; API credentials, OAuth clients and sessions issued before the backup keep working. What happened after the backup is lost: runs and their logs since then, and anything else written since. Workers reconnect and reconcile against the restored controller ([reconciliation](reconciliation.md)).

## Recovery objectives

| Objective | Default | What sets it |
|---|---|---|
| **Recovery point** (RPO), metadata | ≤ 1 hour | `[backup] interval_secs`; the database changes every commit, so it is exactly the interval |
| RPO, artifacts and uploads | ≤ 1 hour, or seconds with `[s3]` | the backup interval, or the external copy's backlog (seconds to minutes when healthy; [s3](s3.md)) |
| RPO, logs | ≤ 1 hour | the backup interval (finished logs also reach S3 once settled, when configured) |
| **Recovery time** (RTO) | measured below | copying the backup back plus opening the store — it scales with bytes, not with rows |

Measured on the verification VPS (12 vCPU AMD EPYC 9645, ext4 on a virtio disk), `crates/sentinel-store/tests/backup_drill.rs`, release build — see the record in [`bench/r04-backup-drill.jsonl`](../bench/r04-backup-drill.jsonl):

| Step | Time | For |
|---|---|---|
| Full backup, online | 17.8 s | 20,000 runs of metadata (41.6 MiB database, 20.5 MiB snapshot), 3,048 objects (2,052 MiB), 200 finished logs (760 MiB) |
| Incremental backup, nothing new | 0.3 s | the same deployment: no object or manifest copied again |
| Verify (rehash everything) | 1.4 s | the full backup |
| Restore: copy back, rehashing | 16.8 s | 2.8 GiB |
| Restore: open, migrate, recover | 28 ms | the restored directory |

So recovery time is about **6 seconds per GiB** of backed-up data on the reference disk, and the database's share is negligible: at that rate 100 GiB restores in about 10 minutes, and a controller start after it takes seconds. The objective adopted from this measurement is **RTO ≤ 15 minutes for up to 100 GiB** (an extrapolation of a linear, I/O-bound copy; re-measure on the deployment's own disks with the drill). The drill ran with CPU pressure under 1 %; the data had just been written, so part of it was likely still in the page cache — a cold restore from a slower backup volume takes longer, which is what the margin is for.

## Tests

- `crates/sentinel-store/tests/backup.rs`: an online backup taken while 200 writes land verifies and restores byte for byte — objects rehashed, the manifest, a finished log, the controller's files — with the key refused when absent or wrong and checked when right; a second backup copies nothing it holds; the restored directory opens, recovers with nothing missing and reads the object and the log. Verification catches a flipped byte in an object (and a restore refuses it), a deleted object and a tampered snapshot. A backup waits for the maintenance lock and releases it. Pruning keeps the newest and removes exactly the objects only pruned backups named. A shared copy that rotted in place with its length intact is replaced by the next backup, and a prune waits for a running create's writer lock instead of deleting its files.
- `crates/sentinel/tests/cli.rs::a_backup_taken_online_restores_onto_a_new_data_directory_that_serves`: a running controller with `[backup]` takes a backup when `POST /admin/backups` asks, `admin backup verify` passes it, `admin restore` rebuilds an empty directory, and a controller started there serves the same tenant with the same link certificate and the credential issued before the backup.
- The drill above (`crates/sentinel-store/tests/backup_drill.rs`). It is ignored by default and runs on the verification VPS with `SENTINEL_DRILL_DIR` pointing at the disk under test: `cargo nextest run --release -p sentinel-store --test backup_drill --run-ignored only --no-capture`. The JSON record it prints is appended to `bench/r04-backup-drill.jsonl`.
