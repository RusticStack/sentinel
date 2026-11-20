//! Durable UTC schedules: dedup by occurrence instant, overlap policy, the missed bound, pinned
//! revisions and suspension.

use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    provenance::Provenance,
    registration::Authority,
    runs, schedule,
    schedule::{Claim, Overlap, Spec, State},
    sources::{self, Update},
    tenancy,
};

const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const REMOTE: &str = "https://git.example:8443/team/repo.git";
const MAIN: &str = "refs/heads/main";
/// The first occurrence of `0 * * * *` after this instant, and a multiple of both an hour and a minute.
const HOUR: i64 = 3_600_000;
const MINUTE: i64 = 60_000;
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

struct Fixture {
    conn: Connection,
    key: Key,
    _dir: tempfile::TempDir,
    admin: Principal,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let admin = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, admin.user, "admin", true, UnixMillis(1)).unwrap();
    auth::create_namespace(
        &tx,
        admin,
        tenant,
        Namespace::parse("team").unwrap(),
        NamespaceKind::Personal(admin.user),
        UnixMillis(1),
    )
    .unwrap();
    auth::create_repo(&tx, admin, tenant, repo, "project", UnixMillis(1)).unwrap();
    tx.commit().unwrap();
    let mut f = Fixture {
        conn,
        key,
        _dir: dir,
        admin,
        tenant,
        repo,
    };
    bind(&mut f);
    f
}

fn bind(f: &mut Fixture) {
    let binding = Binding {
        remote: REMOTE.into(),
        allowed_refs: vec!["refs/heads/*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let tx = f.conn.transaction().unwrap();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.admin.user),
        Update {
            repo: f.repo,
            expected: 0,
            binding: &binding,
            credential: &Credential::Public,
            forge: None,
        },
        &["https://git.example:8443".into()],
        &f.key,
        UnixMillis(1),
    )
    .unwrap();
    tx.commit().unwrap();
}

fn configure(f: &mut Fixture, cron: &str, overlap: Overlap, now: i64) -> Result<i64, Error> {
    let spec = Spec {
        cron: cron.into(),
        ref_name: MAIN.into(),
        overlap,
    };
    let tx = f.conn.transaction().unwrap();
    let next = schedule::configure(
        &tx,
        Authority::credential(f.admin),
        None,
        f.repo,
        &spec,
        UnixMillis(now),
    );
    match next {
        Ok(next) => {
            tx.commit().unwrap();
            Ok(next)
        }
        Err(e) => {
            tx.rollback().unwrap();
            Err(e)
        }
    }
}

fn claim(f: &mut Fixture, now: i64) -> Vec<Claim> {
    let tx = f.conn.transaction().unwrap();
    let claims = schedule::claim(&tx, UnixMillis(now), schedule::MAX_PER_PASS).unwrap();
    tx.commit().unwrap();
    claims
}

fn spec(sha: &str) -> RunSpec {
    let yaml = format!(
        "schema: 1\non: [schedule]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new(REMOTE, sha, Some(MAIN)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

fn provenance(f: &Fixture, sha: &str, digest: [u8; 16]) -> Provenance {
    Provenance {
        tenant: f.tenant,
        repo: f.repo,
        trigger: "schedule".into(),
        delivery: None,
        provider: None,
        ref_name: Some(MAIN.into()),
        old_sha: None,
        new_sha: Some(sha.into()),
        head_sha: None,
        base_sha: None,
        merge_sha: None,
        pipeline_sha: sha.into(),
        pipeline_path: Some(".sentinel.yml".into()),
        pipeline_digest: digest,
        pr_number: None,
        group_ref: None,
    }
}

/// Dispatch one claim the way the lane does: the run, its provenance and the occurrence commit together.
fn dispatch(f: &mut Fixture, claim: &Claim, sha: &str, now: i64) -> RunId {
    let spec = spec(sha);
    let images = runs::pinned_images(&spec).unwrap();
    let provenance = provenance(f, sha, spec.pipeline.digest.to_le_bytes());
    let tx = f.conn.transaction().unwrap();
    let run = schedule::dispatch(&tx, claim, &spec, &images, &provenance, UnixMillis(now)).unwrap();
    tx.commit().unwrap();
    run
}

fn occurrences(f: &Fixture) -> Vec<(i64, i64, i64, Option<String>)> {
    let mut query = f
        .conn
        .prepare("SELECT at_ms, state, skipped, reason FROM schedule_occurrences ORDER BY at_ms")
        .unwrap();
    query
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn runs_of(f: &Fixture) -> Vec<String> {
    let mut query = f
        .conn
        .prepare("SELECT source_sha FROM runs ORDER BY created_ms, source_sha")
        .unwrap();
    query
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn stepped_up(admin: Principal) -> Authority {
    Authority::Credential {
        principal: admin,
        stepped_up: true,
    }
}

fn next_at(f: &Fixture) -> i64 {
    schedule::of_repo(&f.conn, f.repo)
        .unwrap()
        .unwrap()
        .next_at_ms
}

fn jobs_of(f: &Fixture, run: RunId) -> Vec<JobId> {
    let mut query = f
        .conn
        .prepare("SELECT id FROM jobs WHERE run_id = ?1 ORDER BY spec_index")
        .unwrap();
    query
        .query_map([run.as_bytes()], |r| r.get::<_, [u8; 16]>(0))
        .unwrap()
        .map(|r| JobId::from_bytes(r.unwrap()).unwrap())
        .collect()
}

#[test]
fn schedules_are_owned_by_the_tenant_and_validated_before_they_are_stored() {
    let mut f = fixture();
    let now = HOUR - 1;
    assert_eq!(
        configure(&mut f, "0 * * * *", Overlap::Skip, now).unwrap(),
        HOUR
    );
    let stored = schedule::of_repo(&f.conn, f.repo).unwrap().unwrap();
    assert_eq!(stored.tenant, f.tenant);
    assert_eq!(stored.ref_name, MAIN);
    assert_eq!(stored.overlap, Overlap::Skip, "skip is the default policy");
    for (cron, ref_name) in [
        ("", MAIN),
        ("* * *", MAIN),
        ("60 * * * *", MAIN),
        ("0 * * * *", "main"),
        ("0 * * * *", "refs/pull/1/head"),
    ] {
        let spec = Spec {
            cron: cron.into(),
            ref_name: ref_name.into(),
            overlap: Overlap::Skip,
        };
        let tx = f.conn.transaction().unwrap();
        assert!(
            matches!(
                schedule::configure(
                    &tx,
                    Authority::HostLocal,
                    None,
                    f.repo,
                    &spec,
                    UnixMillis(now)
                ),
                Err(Error::InvalidInput(_))
            ),
            "{cron:?} {ref_name:?} is refused"
        );
        tx.rollback().unwrap();
    }
    // A ref the binding does not allow is refused even when the cron is fine.
    let outsider = RepoId::new();
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        schedule::disable(&tx, Authority::HostLocal, None, outsider, UnixMillis(now)),
        Err(Error::NotFound)
    ));
    tx.rollback().unwrap();
}

#[test]
fn a_restart_neither_repeats_an_occurrence_nor_loses_the_next_one() {
    let mut f = fixture();
    let start = HOUR - 1;
    assert_eq!(
        configure(&mut f, "0 * * * *", Overlap::Skip, start).unwrap(),
        HOUR
    );
    let claims = claim(&mut f, HOUR);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].at_ms, HOUR);
    let first = dispatch(&mut f, &claims[0], SHA, HOUR);
    assert_eq!(next_at(&f), 2 * HOUR);

    // A controller that recomputes the same instant — a restart, a second instance, a clock step —
    // finds the occurrence recorded and fires nothing.
    assert!(claim(&mut f, HOUR).is_empty());
    assert_eq!(runs_of(&f).len(), 1);

    // A controller that died before advancing the cursor is the same case: the row is the record.
    f.conn
        .execute("UPDATE schedules SET next_at_ms = ?1", [HOUR])
        .unwrap();
    assert!(claim(&mut f, HOUR).is_empty());
    assert_eq!(
        next_at(&f),
        2 * HOUR,
        "the cursor moves past the recorded instant"
    );
    assert_eq!(runs_of(&f).len(), 1);
    finish(&mut f, first, HOUR + 1);

    let next = claim(&mut f, 2 * HOUR);
    assert_eq!(next.len(), 1);
    let second = dispatch(&mut f, &next[0], SHA, 2 * HOUR);
    assert_ne!(first, second);
    assert_eq!(runs_of(&f).len(), 2);
    assert_eq!(
        occurrences(&f)
            .into_iter()
            .map(|o| (o.0, o.1))
            .collect::<Vec<_>>(),
        vec![
            (HOUR, State::Dispatched as i64),
            (2 * HOUR, State::Dispatched as i64)
        ]
    );
}

#[test]
fn two_schedulers_racing_produce_one_run_for_one_occurrence() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    // Both controllers claimed the same instant: only one occurrence row exists, and once the first
    // dispatch commits the second pass has nothing left to claim.
    let claims = claim(&mut f, HOUR);
    assert_eq!(claims.len(), 1);
    dispatch(&mut f, &claims[0], SHA, HOUR);
    assert!(claim(&mut f, HOUR).is_empty());
    // The other order: the occurrence is recorded, so a pass that has not seen it claims nothing.
    f.conn
        .execute(
            "INSERT INTO schedule_occurrences(schedule_id, at_ms, tenant_id, state, settled_ms)
             VALUES(?1, ?2, ?3, 2, ?2)",
            rusqlite::params![f.repo.as_bytes(), 2 * HOUR, f.tenant.as_bytes()],
        )
        .unwrap();
    assert!(claim(&mut f, 2 * HOUR).is_empty());
    assert_eq!(runs_of(&f).len(), 1);
}

#[test]
fn an_occurrence_skips_while_the_previous_run_is_going() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let claims = claim(&mut f, HOUR);
    let first = dispatch(&mut f, &claims[0], SHA, HOUR);
    // The run is live: nothing else touches its jobs.
    assert!(!jobs_of(&f, first).is_empty());
    assert!(claim(&mut f, 2 * HOUR).is_empty());
    let recorded = occurrences(&f);
    assert_eq!(recorded.last().unwrap().1, State::Overlap as i64);
    assert_eq!(runs_of(&f).len(), 1);
    // Once the first run is over, the next occurrence fires.
    finish(&mut f, first, 2 * HOUR);
    assert_eq!(claim(&mut f, 3 * HOUR).len(), 1);
}

#[test]
fn cancel_overlap_stops_the_previous_run_and_starts_the_newer_occurrence() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Cancel, HOUR - 1).unwrap();
    let claims = claim(&mut f, HOUR);
    let first = dispatch(&mut f, &claims[0], SHA, HOUR);
    let claims = claim(&mut f, 2 * HOUR);
    assert_eq!(claims.len(), 1, "the newer occurrence is claimed");
    let canceled: i64 = f
        .conn
        .query_row(
            "SELECT cancel_requested FROM runs WHERE id = ?1",
            [first.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(canceled, 1);
    let second = dispatch(&mut f, &claims[0], SHA, 2 * HOUR);
    assert_ne!(first, second);
    assert_eq!(runs_of(&f).len(), 2);
}

#[test]
fn an_hour_of_downtime_fires_one_occurrence_and_records_the_rest() {
    let mut f = fixture();
    // Every minute, configured just before the first minute of the hour.
    let start = HOUR - 1;
    configure(&mut f, "* * * * *", Overlap::Skip, start).unwrap();
    assert_eq!(next_at(&f), HOUR);
    // The controller was down for an hour: 60 occurrences came due.
    let claims = claim(&mut f, HOUR + 59 * MINUTE);
    assert_eq!(
        claims.len(),
        1,
        "one occurrence is fired, not one per missed minute"
    );
    assert_eq!(claims[0].at_ms, HOUR + 59 * MINUTE, "the newest one");
    assert_eq!(claims[0].skipped, 59);
    let recorded = occurrences(&f);
    assert_eq!(
        recorded.len(),
        2,
        "one missed row for the gap, one claimed row"
    );
    assert_eq!(
        recorded[0],
        (HOUR, State::Missed as i64, 59, None),
        "the gap is one row, keyed at its first instant, with how many it covers"
    );
    dispatch(&mut f, &claims[0], SHA, HOUR + 59 * MINUTE);
    assert_eq!(next_at(&f), HOUR + 60 * MINUTE);
    assert_eq!(runs_of(&f).len(), 1);
}

#[test]
fn a_very_long_gap_stops_recording_instants_and_says_it_did() {
    let mut f = fixture();
    configure(&mut f, "* * * * *", Overlap::Skip, HOUR - 1).unwrap();
    // A year down, on the minute: the scan is bounded, and the row says the count is a floor.
    let now = HOUR + 525_600 * MINUTE;
    let claims = claim(&mut f, now);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].skipped, schedule::MAX_MISSED_RECORDED as i64);
    let recorded = occurrences(&f);
    assert_eq!(recorded[0].1, State::Missed as i64);
    assert_eq!(recorded[0].2, schedule::MAX_MISSED_RECORDED as i64);
    assert_eq!(recorded[0].3.as_deref(), Some("gap_over_scan"));
}

#[test]
fn a_suspended_tenant_fires_nothing_and_the_gap_is_not_replayed() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let tx = f.conn.transaction().unwrap();
    tenancy::suspend(&tx, stepped_up(f.admin), f.tenant, UnixMillis(HOUR)).unwrap();
    tx.commit().unwrap();
    assert!(
        claim(&mut f, HOUR).is_empty(),
        "a suspended tenant's schedule does not fire"
    );
    assert_eq!(next_at(&f), 2 * HOUR);
    assert_eq!(occurrences(&f).last().unwrap().1, State::Suspended as i64);
    assert!(claim(&mut f, 2 * HOUR).is_empty());
    // Reactivated: the schedule resumes at the next occurrence, and the suspended ones are not run.
    let tx = f.conn.transaction().unwrap();
    tenancy::reactivate(&tx, stepped_up(f.admin), f.tenant, UnixMillis(2 * HOUR)).unwrap();
    tx.commit().unwrap();
    let claims = claim(&mut f, 3 * HOUR);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].at_ms, 3 * HOUR);
    assert_eq!(
        claims[0].skipped, 0,
        "the suspended gap is not a missed burst"
    );
    assert!(runs_of(&f).is_empty());
}

#[test]
fn each_occurrence_pins_the_revision_it_resolved() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let first = "a".repeat(40);
    let second = "b".repeat(40);
    let claims = claim(&mut f, HOUR);
    let run = dispatch(&mut f, &claims[0], &first, HOUR);
    finish(&mut f, run, HOUR + 1);
    let claims = claim(&mut f, 2 * HOUR);
    dispatch(&mut f, &claims[0], &second, 2 * HOUR);
    assert_eq!(runs_of(&f), vec![first.clone(), second.clone()]);
    let pinned: (String, String) = f
        .conn
        .query_row(
            "SELECT r.source_sha, p.pipeline_sha FROM runs r JOIN run_provenance p ON p.run_id = r.id
             WHERE r.id = ?1",
            [run.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(pinned, (first.clone(), first.clone()));
    let trigger: String = f
        .conn
        .query_row(
            "SELECT trigger FROM run_provenance WHERE run_id = ?1",
            [run.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(trigger, "schedule");
}

#[test]
fn a_claim_its_controller_died_holding_is_claimed_again_after_the_ttl() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let claims = claim(&mut f, HOUR);
    assert_eq!(claims.len(), 1);
    // Nothing was dispatched and nothing settled it: the row stays claimed.
    assert!(claim(&mut f, HOUR + 1).is_empty());
    let again = claim(&mut f, HOUR + schedule::CLAIM_TTL_MS + 1);
    assert_eq!(again.len(), 1, "the occurrence is claimed again, not lost");
    assert_eq!(again[0].at_ms, HOUR);
    let run = dispatch(&mut f, &again[0], SHA, HOUR + schedule::CLAIM_TTL_MS + 2);
    assert_eq!(runs_of(&f), vec![SHA.to_owned()]);
    assert!(!jobs_of(&f, run).is_empty());
}

#[test]
fn an_occurrence_that_cannot_be_dispatched_is_recorded_with_its_reason() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let claims = claim(&mut f, HOUR);
    let tx = f.conn.transaction().unwrap();
    schedule::settle(
        &tx,
        f.repo,
        claims[0].at_ms,
        State::Failed,
        Some("no_pipeline"),
        UnixMillis(HOUR),
    )
    .unwrap();
    tx.commit().unwrap();
    let recorded = occurrences(&f);
    assert_eq!(recorded.last().unwrap().1, State::Failed as i64);
    assert_eq!(recorded.last().unwrap().3.as_deref(), Some("no_pipeline"));
    assert_eq!(next_at(&f), 2 * HOUR);
    assert!(runs_of(&f).is_empty());
}

#[test]
fn settled_occurrences_are_purged_and_the_cursor_is_not_affected() {
    let mut f = fixture();
    configure(&mut f, "0 * * * *", Overlap::Skip, HOUR - 1).unwrap();
    let claims = claim(&mut f, HOUR);
    dispatch(&mut f, &claims[0], SHA, HOUR);
    let tx = f.conn.transaction().unwrap();
    let purged = schedule::purge_settled(&tx, UnixMillis(HOUR + 1), 10).unwrap();
    tx.commit().unwrap();
    assert_eq!(purged, 1);
    assert!(occurrences(&f).is_empty());
    assert_eq!(next_at(&f), 2 * HOUR);
}

fn finish(f: &mut Fixture, run: RunId, now: i64) {
    let jobs = jobs_of(f, run);
    let tx = f.conn.transaction().unwrap();
    for job in jobs {
        sentinel_store::jobs::transition(
            &tx,
            f.tenant,
            job,
            sentinel_core::Actor::Controller,
            sentinel_core::Event::CancelBeforeStart,
            UnixMillis(now),
        )
        .unwrap_or_else(|e| panic!("job {job} is not fail-settable: {e:?}"));
    }
    tx.commit().unwrap();
}
