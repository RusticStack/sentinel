//! R04's recovery drill, measured: a deployment with 20,000 runs of
//! metadata, 2 GiB of artifacts in 2,048 objects plus 1,000 small ones and
//! 200 finished logs of about 4 MiB is backed up online, backed up again (nothing
//! changed), verified, and restored onto an empty data directory that is
//! then opened and recovered as a controller would. Prints one JSON record.
//!
//! Ignored by default: `cargo nextest run --release -p sentinel-store --test
//! backup_drill --run-ignored only --no-capture` on the verification VPS,
//! with `SENTINEL_DRILL_DIR` on the disk under test. The record goes in
//! `bench/r04-backup-drill.jsonl` ([backup](../../../docs/backup.md)).

use std::{sync::Arc, time::Instant};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    backup,
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{Expect, Objects},
    runs, tenancy,
    workers::{self, Presentation},
};

const RUNS: u32 = 20_000;
const BIG: u32 = 2_048;
const SMALL: u32 = 1_000;
const LOGS: u32 = 200;
/// 128 frames of 31 KiB, near the 32 KiB frame cap: about 4 MiB a log.
const LOG_FRAMES: u64 = 128;

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn mib(bytes: u64) -> f64 {
    (bytes as f64 / (1u64 << 20) as f64 * 10.0).round() / 10.0
}

#[test]
#[ignore = "the R04 drill: minutes and gigabytes; run on the verification VPS"]
fn drill() {
    let root_dir = std::env::var_os("SENTINEL_DRILL_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let temp = tempfile::tempdir_in(&root_dir).unwrap();
    let data = temp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let store = Arc::new(Store::open(data.join("metadata.sqlite"), Durability::Full).unwrap());
    let objects = Arc::new(Objects::open(&data).unwrap());
    let logs = LogStore::open(data.join("logs")).unwrap();
    let (root, tenant, repo, pool, worker) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        WorkerId::new(),
    );
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, now)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", now)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "b",
                tenancy::PoolKind::Dedicated(tenant),
                now,
            )?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &Secret::parse(&text).unwrap(),
                Presentation {
                    worker,
                    fingerprint: Secret::generate().digest(),
                    name: "w",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                now,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 1 << 30,
                    memory_bytes: 1 << 50,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();

    // Metadata: 20,000 runs of one job each, a thousand per transaction.
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", "0123456789abcdef0123456789abcdef01234567", Some("main")).unwrap(),
        compile_str("schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n").unwrap(),
    )
    .unwrap();
    for _ in 0..RUNS / 1_000 {
        let spec = spec.clone();
        store
            .writer()
            .write(move |tx| {
                for _ in 0..1_000 {
                    let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, now)?;
                    runs::resolve_image(
                        tx,
                        tenant,
                        ids[0],
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "linux/amd64",
                    )?;
                }
                Ok(())
            })
            .unwrap();
    }
    // 200 placed, finished attempts with 4 MiB logs each.
    let line = bytes(7, 31 * 1024 - 1);
    for _ in 0..LOGS {
        let offer = store
            .writer()
            .write(move |tx| {
                let offer =
                    dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now)?.unwrap();
                tx.execute(
                    "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                    (offer.attempt.as_bytes().as_slice(), now.0),
                )?;
                Ok(offer)
            })
            .unwrap();
        let run = store
            .read(|c| sentinel_store::lookup::job_run(c, offer.job))
            .unwrap();
        for seq in 1..=LOG_FRAMES {
            let mut text = line.clone();
            text.push(b'\n');
            logs.append(
                run,
                offer.job,
                offer.attempt,
                &sentinel_protocol::logs::Frame {
                    seq,
                    step: 0,
                    stream: sentinel_protocol::logs::Stream::Stdout,
                    bytes: text,
                },
            )
            .unwrap();
        }
        logs.finish(run, offer.job, offer.attempt, LOG_FRAMES, &[])
            .unwrap();
    }
    // Objects: 2 GiB in 1 MiB artifacts, and 1,000 small ones.
    for i in 0..BIG + SMALL {
        let body = bytes(u64::from(i) + 1, if i < BIG { 1 << 20 } else { 4 << 10 });
        let staged = objects
            .stage(tenant, body.as_slice(), u64::MAX, Expect::default())
            .unwrap();
        let o = Arc::clone(&objects);
        store
            .writer()
            .write(move |tx| o.commit(tx, &staged))
            .unwrap();
    }
    // Let the log compressor finish before measuring.
    std::thread::sleep(std::time::Duration::from_secs(5));
    let metadata_bytes = store.metadata_bytes();

    let target = temp.path().join("backups");
    let t = Instant::now();
    let full = backup::create(&store, &objects, &data, &target, "drill").unwrap();
    let full_ms = t.elapsed().as_millis();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let t = Instant::now();
    let incremental = backup::create(&store, &objects, &data, &target, "drill").unwrap();
    let incremental_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let check = backup::verify(&target, &full.id).unwrap();
    let verify_ms = t.elapsed().as_millis();
    assert!(check.ok(), "{check:?}");

    let restored = temp.path().join("restored");
    let t = Instant::now();
    let report = backup::restore(&target, &full.id, &restored, None).unwrap();
    let restore_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let reopened = Store::open(restored.join("metadata.sqlite"), Durability::Full).unwrap();
    let reobjects = Objects::open(&restored).unwrap();
    let recovery = reopened.read(|c| reobjects.recover(c)).unwrap();
    let open_ms = t.elapsed().as_millis();
    assert!(
        recovery.missing.is_empty() && recovery.corrupt.is_empty(),
        "{recovery:?}"
    );
    assert_eq!(report.objects, u64::from(BIG + SMALL));
    assert!(report.log_files >= u64::from(LOGS) * 2);

    let load = std::fs::read_to_string("/proc/pressure/cpu")
        .ok()
        .and_then(|p| p.lines().next().map(str::to_owned));
    println!(
        "{}",
        serde_json::json!({
            "record": "r04-backup-drill",
            "date_ms": UnixMillis::now().0,
            "dataset": {
                "runs": RUNS,
                "objects": BIG + SMALL,
                "object_mib": mib(u64::from(BIG) * (1 << 20) + u64::from(SMALL) * (4 << 10)),
                "logs": LOGS,
                "log_mib_copied": mib(full.log_bytes_copied),
                "metadata_mib": mib(metadata_bytes),
                "snapshot_mib": mib(full.metadata_bytes),
            },
            "full_backup_ms": full_ms,
            "incremental_backup_ms": incremental_ms,
            "incremental_objects_copied": incremental.objects_copied,
            "verify_ms": verify_ms,
            "restore_copy_ms": restore_ms,
            "restore_open_and_recover_ms": open_ms,
            "restore_total_ms": restore_ms + open_ms,
            "cpu_pressure": load,
        })
    );
}
