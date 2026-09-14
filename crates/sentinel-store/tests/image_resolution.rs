//! Parts 01–02 audit gate C05/W03: a job is admitted to execution only once
//! its image digest and platform are durably resolved, written once.

use sentinel_core::{Actor, Event, RepoId, RunId, TenantId, UnixMillis, WorkerId};
use sentinel_pipeline::{
    compile_str,
    run::{PinnedSource, RunSpec},
};
use sentinel_store::{Durability, Error, Store, jobs, runs};

const SHA: &str = "0c87e0180c87e0180c87e0180c87e0180c87e018";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NOW: UnixMillis = UnixMillis(1_000);

fn spec(image: &str) -> RunSpec {
    let yaml = format!(
        "schema: 1
on: [push]
jobs:
  build:
    image: {image}
    steps:
      - id: make
        run: make
"
    );
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    job: sentinel_core::JobId,
}

fn fixture(image: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (tenant, repo, run) = (TenantId::new(), RepoId::new(), RunId::new());
    let spec = spec(image);
    let job = store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", NOW)?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            Ok(runs::create_run(tx, tenant, repo, run, &spec, NOW)?[0])
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        job,
    }
}

fn try_lease(f: &Fixture) -> Result<(), Error> {
    let (tenant, job) = (f.tenant, f.job);
    f.store.writer().write(move |tx| {
        jobs::lease(tx, tenant, job, WorkerId::new(), UnixMillis(9_999), NOW).map(|_| ())
    })
}

#[test]
fn a_tag_only_image_is_not_executable_until_resolved_and_resolution_is_written_once() {
    let f = fixture("ghcr.io/o/i:v1");
    assert!(matches!(
        f.store.read(|c| runs::resolved_image(c, f.tenant, f.job)),
        Err(Error::Unresolved)
    ));
    // Ready, yet not admissible: the spec's existence is not readiness.
    assert!(matches!(try_lease(&f), Err(Error::Unresolved)));
    assert_eq!(
        f.store
            .read(|c| jobs::get_job(c, f.tenant, f.job))
            .unwrap()
            .state,
        sentinel_core::JobState::Queued
    );

    let (tenant, job) = (f.tenant, f.job);
    for (digest, platform) in [
        ("sha256:short", "linux/amd64"),
        (DIGEST, "amd64"),
        (DIGEST, "Linux/AMD64"),
        (DIGEST, ""),
    ] {
        let refused = f
            .store
            .writer()
            .write(move |tx| runs::resolve_image(tx, tenant, job, digest, platform));
        assert!(
            matches!(refused, Err(Error::InvalidInput(_))),
            "{digest} {platform}"
        );
    }
    f.store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64"))
        .unwrap();
    assert_eq!(
        f.store
            .read(|c| runs::resolved_image(c, f.tenant, f.job))
            .unwrap(),
        runs::ResolvedImage {
            digest: DIGEST.into(),
            platform: "linux/amd64".into(),
        }
    );
    try_lease(&f).unwrap();

    // Once written, neither the API nor raw SQL can move it.
    let refused = f
        .store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, OTHER, "linux/amd64"));
    assert!(matches!(refused, Err(Error::Conflict)));
    let raw = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE jobs SET image_digest = ?1 WHERE id = ?2",
            rusqlite::params![OTHER, job.as_bytes()],
        )?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
    // A rerun keeps the same bytes: the resolution is on the job, not the attempt.
    let (tenant, job) = (f.tenant, f.job);
    f.store
        .writer()
        .write(move |tx| {
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Worker(sentinel_core::Fence(1)),
                Event::PreparationStarted,
                NOW,
            )?;
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Worker(sentinel_core::Fence(1)),
                Event::StepsStarted,
                NOW,
            )?;
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Worker(sentinel_core::Fence(1)),
                Event::FinalizationStarted,
                NOW,
            )?;
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Worker(sentinel_core::Fence(1)),
                Event::Passed,
                NOW,
            )?;
            runs::rerun_job(tx, tenant, job, NOW)
        })
        .unwrap();
    assert_eq!(
        f.store
            .read(|c| runs::resolved_image(c, f.tenant, f.job))
            .unwrap()
            .digest,
        DIGEST
    );
    try_lease(&f).unwrap();
}

#[test]
fn a_digest_pinned_spec_prefills_the_digest_but_still_needs_a_platform() {
    let f = fixture(&format!("ghcr.io/o/i:v1@{DIGEST}"));
    assert!(matches!(try_lease(&f), Err(Error::Unresolved)));
    let (tenant, job) = (f.tenant, f.job);
    // Resolution must agree with the pin.
    let refused = f
        .store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, OTHER, "linux/arm64"));
    assert!(matches!(refused, Err(Error::Conflict)));
    f.store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, DIGEST, "linux/arm64"))
        .unwrap();
    try_lease(&f).unwrap();
    let refused = f
        .store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64"));
    assert!(
        matches!(refused, Err(Error::Conflict)),
        "platform is written once too"
    );
}
