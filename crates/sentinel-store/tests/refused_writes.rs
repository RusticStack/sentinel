#![cfg(unix)]

//! R07: writes that are refused — a database with no room, an object store that cannot write, and a wall clock
//! stepped backwards — leave no acknowledged state behind, serve nothing unverifiable, and settle exactly once when
//! the cause is gone.

use std::{
    fs, io::Cursor, os::unix::fs::PermissionsExt, path::Path, sync::Arc, thread, time::Duration,
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    objects::{self, Expect, Objects},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    let objects = Arc::new(Objects::open(dir.path().join("data")).unwrap());
    Fixture {
        dir,
        store,
        objects,
        tenant,
        repo,
        pool,
    }
}

impl Fixture {
    fn rows(&self) -> (i64, i64, i64) {
        self.store
            .read(|c| {
                let count = |table: &str| -> std::result::Result<i64, rusqlite::Error> {
                    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                };
                Ok((count("runs")?, count("jobs")?, count("objects")?))
            })
            .unwrap()
    }

    fn state(&self, tenant: TenantId, job: JobId) -> JobState {
        self.store
            .read(|c| jobs::get_job(c, tenant, job))
            .unwrap()
            .state
    }

    /// One run of one job, a worker holding it under an acknowledged lease, and that lease.
    fn placed(&self) -> (RunId, JobId, AttemptId, Fence, WorkerId, UnixMillis) {
        let (tenant, repo, pool) = (self.tenant, self.repo, self.pool);
        let run = RunId::new();
        let worker = WorkerId::new();
        let spec = spec_of(ONE_JOB);
        self.store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, NOW)?;
                runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
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
                    NOW,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    Capacity {
                        cpu_millis: 4_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 0,
                    },
                )?;
                let offer = dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                    .expect("a queued job was placed");
                let until = dispatch::acknowledge(tx, worker, offer.attempt, offer.fence, NOW)?;
                Ok((ids[0], offer, until))
            })
            .map(|(job, offer, until)| (run, job, offer.attempt, offer.fence, worker, until))
            .unwrap()
    }
}

const ONE_JOB: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

fn spec_of(yaml: &str) -> RunSpec {
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(yaml).unwrap(),
    )
    .unwrap()
}

/// A pipeline too large to fit in one database page, even compressed: every job carries a step of its own
/// pseudo-random text, which the spec's deflate cannot shrink to nothing.
fn crowded(jobs: usize) -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    let mut x = 0x2545_F491u32;
    for i in 0..jobs {
        let mut script = String::from("echo ");
        for _ in 0..3_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            script.push(char::from(b'a' + (x % 26) as u8));
        }
        yaml.push_str(&format!(
            "  job-{i}:\n    image: alpine:3\n    steps: [{{ id: s, run: '{script}' }}]\n"
        ));
    }
    yaml
}

fn freed(store: &Store) -> (i64, i64) {
    store
        .writer()
        .raw(|c| {
            Ok((
                c.query_row("PRAGMA page_count", [], |r| r.get(0))?,
                c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?,
            ))
        })
        .unwrap()
}

fn set_page_cap(store: &Store, pages: i64) {
    store
        .writer()
        .raw(move |c| {
            c.pragma_update(None, "max_page_count", pages)?;
            Ok(())
        })
        .unwrap();
}

fn files_under(root: &Path) -> usize {
    let mut found = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(entry.path());
            } else {
                found += 1;
            }
        }
    }
    found
}

#[test]
fn a_database_with_no_room_refuses_the_write_and_the_retry_commits_it_once() {
    let fx = fixture();
    let (tenant, repo) = (fx.tenant, fx.repo);
    let before = fx.rows();
    let (pages, free) = freed(&fx.store);
    // Every used page plus what the file can reuse, and one spare: the next run has nowhere to go.
    set_page_cap(&fx.store, pages + free + 1);

    let run = RunId::new();
    let refused = fx
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &spec_of(&crowded(64)), NOW))
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            Error::Sqlite(rusqlite::Error::SqliteFailure(failure, _))
                if failure.code == rusqlite::ErrorCode::DiskFull
        ),
        "a full database refuses the write as such: {refused}"
    );
    assert_eq!(fx.rows(), before, "a refused write acknowledged nothing");

    // Room again: the very same run commits, once.
    set_page_cap(&fx.store, 1_000_000);
    let ids = fx
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &spec_of(&crowded(64)), NOW))
        .unwrap();
    assert_eq!(ids.len(), 64);
    assert_eq!(fx.rows(), (before.0 + 1, before.1 + 64, before.2));
    let stored = fx
        .store
        .read(move |c| runs::get_run_spec(c, tenant, run))
        .unwrap();
    assert_eq!(stored.pipeline.jobs.len(), 64);
}

#[test]
fn an_object_store_that_refuses_a_write_publishes_nothing_and_stores_one_copy() {
    let fx = fixture();
    let tenant = fx.tenant;
    let data = fx.dir.path().join("data");
    let body = b"an artifact the store is asked to keep".to_vec();
    let stage = |body: &[u8]| fx.objects.stage(tenant, body, u64::MAX, Expect::default());

    // The staging area refuses the bytes: the write fails and nothing is recorded or served.
    let tmp = data.join(objects::TMP_DIR);
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o500)).unwrap();
    match stage(&body) {
        Err(Error::Io(_)) => {}
        Err(e) => panic!("the store refused the bytes and nothing else: {e}"),
        Ok(_) => panic!("a staging area that cannot be written accepted bytes"),
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(fx.rows().2, 0, "a refused object wrote no row");
    assert_eq!(
        fx.store.read(|c| fx.objects.usage(c, tenant)).unwrap(),
        0,
        "a refused object is charged to nobody"
    );
    assert_eq!(files_under(&data.join(objects::OBJECTS_DIR)), 0);

    let staged = stage(&body).unwrap();
    let digest = staged.digest();
    let objects = Arc::clone(&fx.objects);
    // Staged but not committed is not served: a download finds no row rather than half an object.
    let served = fx.store.read(|c| {
        let mut out = Vec::new();
        objects.read(c, tenant, digest, &mut out).map(|_| out)
    });
    assert!(matches!(served, Err(Error::NotFound)), "{served:?}");

    let committing = Arc::clone(&fx.objects);
    assert!(
        fx.store
            .writer()
            .write(move |tx| committing.commit(tx, &staged))
            .unwrap()
    );
    let mut out = Vec::new();
    let len = fx
        .store
        .read(|c| fx.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!((len, out), (body.len() as u64, body.clone()));

    // The same bytes again: held once, written once, no second publication.
    let again = stage(&body).unwrap();
    let digest_again = again.digest();
    assert_eq!(digest_again, digest);
    let committing = Arc::clone(&fx.objects);
    assert!(
        !fx.store
            .writer()
            .write(move |tx| committing.commit(tx, &again))
            .unwrap()
    );
    assert_eq!(fx.rows().2, 1);
    assert_eq!(files_under(&data.join(objects::OBJECTS_DIR)), 1);
    let report = fx.store.read(|c| fx.objects.recover(c)).unwrap();
    assert!(report.missing.is_empty() && report.corrupt.is_empty());
    let mut whole = Cursor::new(Vec::new());
    fx.store
        .read(|c| fx.objects.read(c, tenant, digest, &mut whole))
        .unwrap();
    assert_eq!(whole.into_inner(), body);
}

#[test]
fn a_clock_stepped_backwards_expires_no_lease_and_never_shortens_one() {
    let fx = fixture();
    let steady = UnixMillis::steady();
    thread::sleep(Duration::from_millis(20));
    assert!(
        UnixMillis::steady() > steady,
        "the deadline clock is monotonic"
    );

    let (_, job, attempt, fence, worker, lease) = fx.placed();
    let behind = UnixMillis(lease.0 - 3_600_000);

    let (until, stopped) = fx
        .store
        .writer()
        .write(move |tx| {
            dispatch::renew(tx, worker, &[attempt], dispatch::DEFAULT_LEASE_MS, behind)
        })
        .unwrap();
    assert!(stopped.is_empty());
    assert!(until < lease);
    assert_eq!(
        fx.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT lease_until_ms FROM attempts WHERE id = ?1 AND fence = ?2",
                    rusqlite::params![attempt.as_bytes().as_slice(), fence.0 as i64],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .unwrap(),
        lease.0,
        "a renewal on a clock that stepped back cannot shorten the lease"
    );

    let due = fx.store.read(|c| dispatch::expired(c, behind)).unwrap();
    assert!(due.is_empty(), "a backwards step expires nothing: {due:?}");
    let settled = fx
        .store
        .writer()
        .write(move |tx| dispatch::reconcile_startup(tx, behind, None))
        .unwrap();
    assert_eq!((settled.expired, settled.lapsed), (0, 0));
    assert_eq!(fx.state(fx.tenant, job), JobState::Leased);

    // The same lease still ends when the clock that decides deadlines passes it.
    let after = UnixMillis(lease.0 + 1);
    assert_eq!(
        fx.store.read(|c| dispatch::expired(c, after)).unwrap(),
        vec![attempt]
    );
    let state = fx
        .store
        .writer()
        .write(move |tx| dispatch::expire(tx, attempt, after, None))
        .unwrap();
    assert_eq!(state, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(
        fx.state(fx.tenant, job),
        JobState::Terminal(Outcome::InfraFailed)
    );
}
