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
<dir>/<id>/backup.json       format sentinel.backup/1: schema, counts, checksums, key ids,
                             started_ms and took_ms
```

`<id>` is the UTC time the backup started (`20260928T170000Z`), so ids sort by age. Objects and manifests are stored once however many backups name them, so a backup after the first copies only what is new — and every object is **rehashed while it is copied**: a file that no longer matches its digest is reported and not stored, so a backup never preserves rot. A copy an earlier backup left is **reused only after it is rehashed** against the digest the snapshot names (a matching length alone proves nothing): one that rotted in place is replaced from the data directory and counted (`objects.recopied`, `manifests.recopied` in `backup.json`, `objects_recopied` in the report). The cost is one read of the shared store per backup, in exchange for no backup naming a rotted file. A manifest version that does not match its digest at the source fails the backup with `corrupt`, since a backup cannot stand in for it. The controller's own files (`controller.key` and `controller.crt` decide whether workers reconnect) are checksummed too: `backup.json`'s `config_blake3` maps each to its BLAKE3, so rot in a backup's copy is caught by `verify` and refused by `restore` instead of surfacing as workers that will not reconnect.

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
interval_secs = 3000           # 300 .. 604800, default 3000 (50 min): interval + a backup's duration is the recovery point
keep = 24                      # newest kept, 1 .. 1000, default 24
```

The first backup runs one interval after start (a restarting controller does not take one per restart); a failed one is recorded and retried at the next interval, never stopping the controller. Intervals are counted from the **start** of a backup, so a backup's own duration does not lengthen the gap between two snapshots; one that outlasts the interval is followed at once by the next. `POST /admin/backups` takes one now (`409 conflict` while one runs), `GET /admin/backups` lists them with the scheduler's state, and **Platform → Storage → Backups** shows both and has a *Back up now* button ([API](api.md)).

A backup is staged in `DIR/.<id>.partial` and renamed to `DIR/<id>` only after its `backup.json` is durable, so an interrupted one is never listed. The next backup removes every staging directory an interruption left (`partials_removed` in its report). An object the database names but the data directory lost is recorded in `backup.json`'s `objects.missing` and skipped, like one that fails its digest (`objects.corrupt`). The backup still completes, and `admin backup create` exits 2 so it is noticed ([failure drills](resilience.md)). Such a backup is not rejected at restore time either: the objects it recorded as lost are skipped, everything else comes back, and recovery names the loss (see [Restoring](#restoring)).

Offline, beside a stopped controller: `sentinel admin backup create --data-dir DATA --to DIR`. Pruning keeps the newest `keep` and removes every shared object, manifest and log file no kept backup names: `sentinel admin backup prune --dir DIR --keep N`.

**Writers are serialized.** `create` copies new shared files before its backup directory exists, so a `prune` from another process (the host-local tool beside the running scheduler) would find them named by no kept backup. Both take an exclusive advisory lock on `DIR/.lock` — `create` from before its first copy until its directory is in place, `prune` for its whole run — and wait for each other. A file system that answers `Unsupported` for advisory locks runs unlocked on purpose, leaving the host's own coordination as the only protection between `create` and `prune`; turning that answer into an error would make backups impossible there.

**Durability of the copies.** Every shared file is copied through a temporary file that is fsynced and renamed, and the directories those renames touched are fsynced (once per directory, not per file) before the backup names them and before `backup.json` is written; a restore does the same before the database lands, so a power loss after either reports success cannot lose a directory entry.

## Verifying

`sentinel admin backup verify --dir DIR [--id ID]` rehashes the snapshot against its recorded BLAKE3, runs SQLite's `PRAGMA integrity_check` on it, rehashes every object and manifest it names and every checksummed controller file (`config/...`); it exits 2 with the missing and corrupt paths when anything is wrong. A snapshot that cannot be read at all is a failed verification (`integrity` says `unreadable`), not a crash, and its rows are not trusted to name further files; a `backup.json` that is not valid, or names another format, is an error. Logs are mirrors and are not checksummed. It is a drill, not a request-path cost: schedule it (weekly, and after any storage incident) and alert on a non-zero exit. The rehash cost at chosen object counts is measured by `crates/sentinel-store/examples/backup-rehash-bench.rs` ([benchmarking](benchmarking.md#backup-rehash-cost)); no record is committed yet, and the 1.4 s drill figure below is a single run of one dataset.

`sentinel admin backup rpo --dir DIR [--limit-secs 3600]` prints the age of the newest backup and the longest window between kept backups ([Recovery objectives](#recovery-objectives)) and exits 2 when the newest is older than the limit, or there is none: the check to alert on.

## Restoring

On the same host after data loss, or on a replacement host:

```sh
sentinel admin restore --from /mnt/backup/sentinel [--id 20260928T170000Z] \
    --key /secure/master.key --data-dir /var/lib/sentinel
sentinel server --config /etc/sentinel/server.toml
```

The target data directory must hold no database, and no leftover journal of one (`metadata.sqlite-wal` or `-shm`, which SQLite would replay into the restored file). Every object, manifest and checksummed controller file is rehashed as it is copied (a mismatch stops the restore, `Corrupt`); the snapshot's checksum is checked first; with sealed values the key file is parsed and checked against them before anything is written (a missing, unparsable or incomplete key file is refused with the directory untouched); the database lands last, so a half-restored directory is never mistaken for a controller's, and a restore that failed can be run again on the same directory once the cause is fixed (or another backup chosen with `--id`; the newest is the default).

The one thing a restore does not stop for is an object the backup itself recorded in `objects.missing` or `objects.corrupt` and does not hold: it is skipped, listed in the report (`objects_unavailable`) with a warning, and the opened store's recovery names it, exactly as on the controller the backup came from. An object absent from the backup that the backup did not record stops the restore. The command then opens the store as the controller would — migrations for an older backup, object recovery — and reports what it restored and found. Objects evicted to S3 come back through the external copy's read-through once the same `[s3]` section is configured.

Because `controller.key` and `controller.crt` are restored, **workers keep their pinned fingerprint** and reconnect without re-enrollment; API credentials, OAuth clients and sessions issued before the backup keep working. What happened after the backup is lost: runs and their logs since then, and anything else written since. Workers reconnect and reconcile against the restored controller ([reconciliation](reconciliation.md)).

## Recovery objectives

The objectives are **RPO at most 1 hour** and **RTO at most 15 minutes for 100 GiB**.

**Recovery point, and how it is stated.** A backup holds the database as it was when the backup *started*, but becomes the newest one only when it is listed, `took_ms` later. A loss just before that moment rolls back to the previous backup, so the worst loss between two backups is `started(next) + took(next) - started(previous)`: the interval plus the duration of the later backup. A failed backup adds a whole interval. `[backup] interval_secs` therefore has to leave room for the duration inside the objective, and its default of 3000 s leaves 10 minutes. Set it to `3600 - (the slowest took_ms you see) - a margin`, never to 3600. `admin backup list` prints each backup's `started_ms` and `took_ms`, and `admin backup rpo` computes both numbers from them: `age_secs` (what a loss now would cost) and `worst_window_secs` (the worst over the kept backups); alert when `age_secs` passes the objective.

| Objective | Value | What sets it |
|---|---|---|
| **Recovery point** (RPO), metadata | interval + `took_ms`; under 1 h at the default | `[backup] interval_secs`; the database changes every commit |
| RPO, artifacts and uploads | the same, or seconds with `[s3]` | the backup interval, or the external copy's backlog (seconds to minutes when healthy; [s3](s3.md)) |
| RPO, logs | the same | the backup interval (finished logs also reach S3 once settled, when configured) |
| **Recovery time** (RTO) | at most 15 min for 100 GiB | copying the backup back plus opening the store; it scales with bytes, not with rows |

**Recovery time, and how it is measured.** A restore is an I/O-bound sequential copy that rehashes as it goes, so the time is bytes over the backup volume's read rate and the data volume's write rate, **plus the recovery scan**: opening the restored store as a controller does rehashes every committed object (`objects.recover`), a second full read of the data. Both scale with bytes. The drill (`backup_drill.rs`, below) builds a deployment, takes a full and an incremental backup, verifies, restores into a second directory and opens it, printing `restore_s_per_gib` and the 100 GiB extrapolation (`rto_100gib_extrapolated_s`). The objective holds on a deployment when that extrapolation, measured **on that deployment's own disks with a cold cache and without competing load**, is below 900 s. The drill sizes itself with `SENTINEL_DRILL_BIG` (the number of 1 MiB objects, 2048 by default; 102400 is the objective's size and needs about three times that in free disk: the data, the backup and the restore).

Measured on the verification VPS (12 vCPU AMD EPYC 9645, ext4 on a virtio disk), `crates/sentinel-store/tests/backup_drill.rs`, release build; see the record in [`bench/r04-backup-drill.jsonl`](../bench/r04-backup-drill.jsonl):

| Step | Time | For |
|---|---|---|
| Full backup, online | 17.8 s | 20,000 runs of metadata (41.6 MiB database, 20.5 MiB snapshot), 3,048 objects (2,052 MiB), 200 finished logs (760 MiB) |
| Incremental backup, nothing new | 0.3 s | the same deployment: no object or manifest copied again |
| Verify (rehash everything) | 1.4 s | the full backup |
| Restore: copy back, rehashing | 16.8 s | 2.8 GiB |
| Restore: open, migrate, recover | 28 ms | the restored directory |

That run restored 2.8 GiB at about **6 seconds per GiB**, with the page cache still holding most of the data; its 28 ms for the open step reflects that, since the scan rehashes every object. The objective adopted from it is **RTO ≤ 15 minutes for up to 100 GiB**, an extrapolation of a linear, I/O-bound copy.

The larger drill on the same host (16.75 GiB, `SENTINEL_DRILL_BIG=16384`, run under `nice -n 19 ionice -c3` on a host shared with other work, so I/O ran at idle priority; the cache was not dropped) does not confirm it:

| Step | Time | For |
|---|---|---|
| Full backup, online | 138 s | 17,384 objects (16,388 MiB), 200 finished logs (760 MiB), 20,000 runs of metadata |
| Incremental backup, nothing new | 37.7 s | rehashing every reused copy, a full read of the shared store |
| Verify (rehash everything) | 36.7 s | the full backup |
| Restore: copy back, rehashing | 134 s | 16.75 GiB |
| Restore: open, migrate, recover | 46 s | the recovery scan |

That is **10.8 s per GiB** end to end, which extrapolates to about **1,077 s (18 min) for 100 GiB, over the 900 s objective**. The run was not on a quiet host, so it neither proves the objective unreachable nor meets it: the objective stays unconfirmed (below). Two consequences hold either way. A backup reads the whole shared store again to rehash reused copies, so an incremental backup costs a read of the data, not the 0.3 s of the small drill (about 225 s at 100 GiB at the rate above); and a first full backup of 100 GiB extrapolates to about 14 min, more than the 10 minutes the default interval leaves, so seed a large deployment with an offline `admin backup create` before relying on the schedule.

**Not yet measured at the objective's size.** The 16.75 GiB record above is the largest drill on record. No drill has restored 100 GiB, and the extrapolation from the one that came closest exceeds the objective under load. Settling it needs the reference host on a quiet window with about 300 GiB of free disk (the data, the backup and the restore), and either result goes into `bench/r04-backup-drill.jsonl`. If a quiet run still extrapolates past 900 s, the objective or the design (skipping the recovery scan after a verified restore, or an incremental backup that does not rehash unchanged copies) has to change; neither is done. This is tracked in the R04 item of the tracker.

## Tests

- `crates/sentinel-store/tests/backup.rs`: an online backup taken while 200 writes land verifies and restores byte for byte — objects rehashed, the manifest, a finished log, the controller's files — with the key refused when absent or wrong and checked when right; a second backup copies nothing it holds; the restored directory opens, recovers with nothing missing and reads the object and the log. Verification catches a flipped byte in an object (and a restore refuses it), a deleted object and a tampered snapshot. A backup waits for the maintenance lock and releases it. Failure paths: a backup taken while a writer commits two-row transactions never holds half of one (snapshot and restored copy); a restore goes on without the objects the backup recorded as lost, still stops for one it did not, and the opened store's recovery names the loss; a restore stopped by a rotten shared object leaves no database and succeeds when run again; rot in or loss of a backed-up `controller.key` is caught by `verify` and refused by `restore`; a snapshot that is truncated or gone, or a `backup.json` that is truncated or of another format, fails verification instead of crashing it; a missing, garbage or incomplete key file and a leftover `-wal` are refused before anything is written; the exposure (`admin backup rpo`) is the interval plus the later backup's duration. Six staggered kills of a process taking backups in a loop leave only backups that verify, and the next backup, a prune and a restore of the result succeed. Pruning keeps the newest and removes exactly the objects only pruned backups named. A shared copy that rotted in place with its length intact is replaced by the next backup, and a prune waits for a running create's writer lock instead of deleting its files.
- `crates/sentinel/tests/cli.rs::a_backup_taken_online_restores_onto_a_new_data_directory_that_serves`: a running controller with `[backup]` takes a backup when `POST /admin/backups` asks, `admin backup verify` passes it, `admin restore` rebuilds an empty directory, and a controller started there serves the same tenant with the same link certificate and the credential issued before the backup; `admin backup rpo` passes it within an hour and fails it at a limit of zero.
- The drill above (`crates/sentinel-store/tests/backup_drill.rs`). It is ignored by default and runs on the verification VPS with `SENTINEL_DRILL_DIR` pointing at the disk under test (and `SENTINEL_DRILL_BIG` for the size, see above): `cargo nextest run --release -p sentinel-store --test backup_drill --run-ignored only --no-capture`. The JSON record it prints is appended to `bench/r04-backup-drill.jsonl`.
