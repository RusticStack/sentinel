//! D07 fault boundaries: a crash can land between any file write and the
//! transaction that accounts for it, a disk can fill mid-stream, a log can
//! be torn at any byte, and a tenant can ask for another tenant's bytes.
//! Every boundary must settle into one of two states — committed and
//! accounted, or absent and declared — never a row without bytes, a file
//! without a fate, or a gap nobody reports.
use std::{
    fs,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use rusqlite::Connection;
use sentinel_core::{
    AttemptId, JobId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    logs::LogStore,
    objects::{self, Digest, Entry, Expect, Kind, Objects},
    space::{Admission, Watermarks},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);

struct Fixture {
    objects: Objects,
    conn: Connection,
    dir: tempfile::TempDir,
    tenant: TenantId,
    other: TenantId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let objects = Objects::open(dir.path()).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), P::ALL, None, None);
    let (tenant, other) = (TenantId::new(), TenantId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    for (id, slug) in [(tenant, "alice"), (other, "other")] {
        auth::create_namespace(
            &tx,
            alice,
            id,
            Namespace::parse(slug).unwrap(),
            if id == tenant {
                NamespaceKind::Personal(alice.user)
            } else {
                NamespaceKind::Organization
            },
            NOW,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    Fixture {
        objects,
        conn,
        dir,
        tenant,
        other,
    }
}

impl Fixture {
    fn put(&mut self, tenant: TenantId, body: &[u8]) -> Digest {
        let staged = self
            .objects
            .stage(tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        let tx = self.conn.transaction().unwrap();
        assert!(self.objects.commit(&tx, &staged).unwrap());
        tx.commit().unwrap();
        digest
    }

    fn object_path(&self, tenant: TenantId, digest: Digest) -> std::path::PathBuf {
        let hex = digest.to_string();
        self.dir
            .path()
            .join("objects")
            .join(tenant.to_string())
            .join(&hex[..2])
            .join(hex)
    }
}

fn entry(path: &str, digest: Digest, len: u64) -> Entry {
    Entry {
        path: path.into(),
        digest,
        len,
        mode: 0,
    }
}

/// An admission gate whose free-space figure the test drives.
fn probed(free: &Arc<AtomicU64>, marks: Watermarks) -> Admission {
    let probe = Arc::clone(free);
    Admission::with_probe(marks, move || Ok(probe.load(Ordering::Relaxed))).unwrap()
}

/// `Admission` caches probe results for a second; changing the figure must
/// let the cache lapse before the next gate consults it.
fn refresh() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn age(path: &std::path::Path, by: Duration) {
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - by).unwrap();
}

fn frame(seq: u64, bytes: &[u8]) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: bytes.to_vec(),
    }
}

#[test]
fn a_commit_rolled_back_leaves_an_orphan_the_sweep_collects() {
    let mut fx = fixture();
    let staged = fx
        .objects
        .stage(
            fx.tenant,
            &b"paid for but never referenced"[..],
            u64::MAX,
            Expect::default(),
        )
        .unwrap();
    let path = fx.object_path(fx.tenant, staged.digest());
    let tx = fx.conn.transaction().unwrap();
    assert!(fx.objects.commit(&tx, &staged).unwrap());
    // The crash lands here: file durable, transaction rolled back.
    tx.rollback().unwrap();
    assert!(path.is_file());

    // Recovery reports it; it is not corrupt and no row is missing.
    let report = fx.objects.recover(&fx.conn).unwrap();
    assert_eq!(report.orphans, vec![path.clone()]);
    assert!(report.corrupt.is_empty() && report.missing.is_empty());
    // Fresh files are never swept — the grace protects an in-flight commit.
    assert_eq!(fx.objects.sweep_orphans(&fx.conn, 64).unwrap(), 0);
    age(
        &path,
        Duration::from_millis(objects::FILE_ORPHAN_GRACE_MS as u64 + 1_000),
    );
    assert_eq!(fx.objects.sweep_orphans(&fx.conn, 64).unwrap(), 1);
    assert!(!path.exists());
    // Nothing was ever owed for it.
    assert_eq!(fx.objects.usage(&fx.conn, fx.tenant).unwrap(), 0);
}

#[test]
fn a_manifest_commit_rolled_back_leaves_an_orphan_file() {
    let mut fx = fixture();
    let object = fx.put(fx.tenant, b"payload");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "dist",
            &[entry("a", object, 7)],
        )
        .unwrap();
    // The file was renamed durable; the row insert rolls back with the tx.
    tx.rollback().unwrap();
    let mut stack = vec![fx.dir.path().join("manifests")];
    let mut found = None;
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                found = Some(e.path());
            }
        }
    }
    let path = found.expect("the manifest file outlived its transaction");

    let report = fx.objects.recover(&fx.conn).unwrap();
    assert_eq!(report.orphans, vec![path.clone()]);
    age(
        &path,
        Duration::from_millis(objects::FILE_ORPHAN_GRACE_MS as u64 + 1_000),
    );
    assert_eq!(fx.objects.sweep_orphans(&fx.conn, 64).unwrap(), 1);
    assert!(!path.exists());
    // The object the manifest named is still committed — unreferenced, but
    // inside the reclamation grace, so nothing collects it yet.
    assert_eq!(fx.objects.meta(&fx.conn, fx.tenant, object).unwrap().len, 7);
}

#[test]
fn a_chunk_that_landed_without_its_bookkeeping_still_resumes() {
    let mut fx = fixture();
    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 8, None, 60_000, now)
        .unwrap();
    tx.commit().unwrap();

    // First chunk commits; the second's bytes land but its transaction
    // rolls back — the crash between write and bookkeeping.
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .put_chunk(&tx, fx.tenant, id, 0, b"abcd", now)
        .unwrap();
    tx.commit().unwrap();
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .put_chunk(&tx, fx.tenant, id, 4, b"efgh", now)
        .unwrap();
    tx.rollback().unwrap();

    // The store claims four bytes while the file holds eight: sealing now
    // is incomplete, never corrupt — the resume is the client's to drive.
    let status = fx.objects.upload(&fx.conn, fx.tenant, id).unwrap();
    assert_eq!(status.received, 4);
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.seal_upload(&tx, fx.tenant, id, now),
        Err(Error::InvalidInput("upload incomplete"))
    ));
    tx.rollback().unwrap();
    // Re-sending the lost range converges: the delta rewrites the same
    // offsets, the range record catches up, and the seal verifies all of
    // it against the declared length.
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(
        fx.objects
            .put_chunk(&tx, fx.tenant, id, 4, b"efgh", now)
            .unwrap(),
        8
    );
    let digest = fx.objects.seal_upload(&tx, fx.tenant, id, now).unwrap();
    tx.commit().unwrap();
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, digest, &mut out)
        .unwrap();
    assert_eq!(out, b"abcdefgh");
}

#[test]
fn closed_admission_refuses_object_bytes_but_logs_keep_their_floor() {
    let mut fx = fixture();
    // free - reserve = 500: under `low` (gate closed to discretionary
    // bytes) but above `floor` (log evidence still flows).
    let free = Arc::new(AtomicU64::new(2_500));
    let admission = Arc::new(probed(
        &free,
        Watermarks {
            reserve: 2_000,
            low: 3_000,
            high: 5_000,
            floor: 400,
        },
    ));
    fx.objects.set_admission(Arc::clone(&admission));
    let logs = LogStore::open(fx.dir.path().join("logs")).unwrap();
    logs.set_admission(Arc::clone(&admission));

    assert!(matches!(
        fx.objects.stage(
            fx.tenant,
            &b"discretionary"[..],
            u64::MAX,
            Expect::default()
        ),
        Err(Error::StorageFull)
    ));
    let mut staging = fx.objects.stage_begin(fx.tenant, 1_000).unwrap();
    assert!(matches!(
        fx.objects.stage_write(&mut staging, b"x"),
        Err(Error::StorageFull)
    ));
    assert_eq!(admission.total_inflight(), 0);
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects
            .begin_upload(&tx, fx.tenant, 100, None, 60_000, NOW),
        Err(Error::StorageFull)
    ));
    tx.rollback().unwrap();

    // The log floor is a lower bar: frames still land while headroom holds.
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    logs.append(run, job, attempt, &frame(1, b"kept\n"))
        .unwrap();
    free.store(300, Ordering::Relaxed); // raw free < floor: even logs refuse
    refresh();
    assert!(matches!(
        logs.append(run, job, attempt, &frame(2, b"lost\n")),
        Err(Error::StorageFull)
    ));
    // A refused frame records no hole it could later fill wrongly: the tail
    // is exactly what was stored.
    logs.finish(run, job, attempt, 2, &[]).unwrap();
    let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.frames.len(), 1);
    assert_eq!(tail.gaps, vec![(2, 2)]);
}

#[test]
fn log_frames_carry_binary_and_the_oversized_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let logs = LogStore::open(dir.path()).unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    // Every byte value, NULs and invalid UTF-8 included, round-trips intact.
    let binary: Vec<u8> = (0..=255u8).cycle().take(1_024).collect();
    logs.append(run, job, attempt, &frame(1, &binary)).unwrap();
    let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
    assert_eq!(tail.frames.len(), 1);
    assert_eq!(tail.frames[0].bytes, binary);
    assert!(!tail.complete);

    // A frame past the wire maximum cannot be encoded; the refusal leaves
    // the sequence untouched so the next valid frame declares the hole.
    let oversized = frame(
        2,
        &vec![0u8; sentinel_protocol::limits::MAX_LOG_FRAME_BYTES + 1],
    );
    assert!(matches!(
        logs.append(run, job, attempt, &oversized),
        Err(Error::InvalidInput("log frame"))
    ));
    logs.append(run, job, attempt, &frame(3, b"after\n"))
        .unwrap();
    logs.finish(run, job, attempt, 3, &[]).unwrap();
    let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(2, 2)]);
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 3]
    );
}

#[test]
fn the_log_cap_refuses_and_the_refusal_is_a_declared_gap() {
    let dir = tempfile::tempdir().unwrap();
    // Two 30-byte payloads fit under a 100-byte cap (each record is
    // 18 header bytes + payload); the third cannot.
    let logs = LogStore::open_with_limit(dir.path(), 100).unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    logs.append(run, job, attempt, &frame(1, &[b'a'; 30]))
        .unwrap();
    logs.append(run, job, attempt, &frame(2, &[b'b'; 30]))
        .unwrap();
    assert!(matches!(
        logs.append(run, job, attempt, &frame(3, &[b'c'; 30])),
        Err(Error::InvalidInput("log size"))
    ));
    // What the cap refused is missing for good: the end marker declares it.
    logs.finish(run, job, attempt, 3, &[]).unwrap();
    assert!(logs.has_end(run, job, attempt));
    let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(3, 3)]);
    assert_eq!(tail.frames.len(), 2);
}

#[test]
fn a_torn_tail_never_reaches_a_reader_and_is_cut_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let attempt_dir = dir
        .path()
        .join(run.to_string())
        .join(job.to_string())
        .join(attempt.to_string());
    {
        let logs = LogStore::open(dir.path()).unwrap();
        for i in 1..=3u64 {
            logs.append(run, job, attempt, &frame(i, b"line\n"))
                .unwrap();
        }
        // A reader mid-stream pages within its window; it sees complete
        // records only, in order.
        let tail = logs.tail(run, job, attempt, 0, 2, None).unwrap();
        assert_eq!(tail.frames.len(), 2);
        assert!(!tail.complete);
        // The crash lands mid-record: half a header past the third frame.
        let seg = attempt_dir.join("seg-000000");
        let torn_at = fs::metadata(&seg).unwrap().len();
        fs::OpenOptions::new()
            .append(true)
            .open(&seg)
            .unwrap()
            .write_all(&[1, 9, 0])
            .unwrap();
        // A live reader sees the torn bytes as the end of the stream, not
        // as a record.
        let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
        assert_eq!(tail.frames.len(), 3);
        // Reopening folds the segment back: the torn tail is cut and the
        // writer continues exactly where the complete prefix ended.
        drop(logs);
        let seg_len = torn_at;
        let logs = LogStore::open(dir.path()).unwrap();
        logs.append(run, job, attempt, &frame(4, b"more\n"))
            .unwrap();
        assert_eq!(fs::metadata(&seg).unwrap().len(), seg_len + 18 + 5);
        let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
        assert_eq!(
            tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        logs.finish(run, job, attempt, 4, &[]).unwrap();
        assert!(logs.has_end(run, job, attempt));
    }
}

#[test]
fn a_lost_end_marker_is_rewritten_from_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let attempt_dir = dir
        .path()
        .join(run.to_string())
        .join(job.to_string())
        .join(attempt.to_string());
    {
        let logs = LogStore::open(dir.path()).unwrap();
        logs.append(run, job, attempt, &frame(1, b"x\n")).unwrap();
        logs.finish(run, job, attempt, 1, &[]).unwrap();
    }
    // The end record is in the sealed segment but the marker file is lost —
    // the crash between the rename and the directory sync, or disk loss.
    fs::remove_file(attempt_dir.join("end")).unwrap();
    {
        let logs = LogStore::open(dir.path()).unwrap();
        assert!(!logs.has_end(run, job, attempt));
        // Touching the writer folds the segment back, sees the end record,
        // and rewrites the marker; appends still refuse a finished log.
        assert!(matches!(
            logs.append(run, job, attempt, &frame(2, b"late\n")),
            Err(Error::Conflict)
        ));
        assert!(logs.has_end(run, job, attempt));
        let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
        assert!(tail.complete);
        assert_eq!(tail.frames.len(), 1);
    }
}

#[test]
fn foreign_tenant_bytes_are_indistinguishable_from_absent() {
    let mut fx = fixture();
    let digest = fx.put(fx.tenant, b"alice's bytes");
    // Every read surface answers NotFound under a foreign tenant.
    for result in [
        fx.objects.meta(&fx.conn, fx.other, digest).map(|_| ()),
        fx.objects.open_read(&fx.conn, fx.other, digest).map(|_| ()),
        fx.objects
            .read(&fx.conn, fx.other, digest, &mut Vec::new())
            .map(|_| ()),
    ] {
        assert!(matches!(result, Err(Error::NotFound)));
    }
    // A manifest that names another tenant's committed digest cannot
    // launder a reference to it — the ref commits only for owned rows.
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.commit_manifest(
            &tx,
            fx.other,
            Kind::Artifact,
            "stolen",
            &[entry("x", digest, 13)],
        ),
        Err(Error::InvalidInput("uncommitted object"))
    ));
    tx.rollback().unwrap();
    // And the same digest under its own tenant stays reachable.
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, digest, &mut out)
        .unwrap();
    assert_eq!(out, b"alice's bytes");
}
