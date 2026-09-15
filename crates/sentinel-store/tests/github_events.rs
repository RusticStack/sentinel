//! G05 store behavior: control-event receipts deduplicate and conflict on a
//! changed body, check rerequests resolve through durable publication
//! identity and only requeue terminal, non-superseded runs, lifecycle events
//! disable and revoke without waiting on the network, and the durable refresh
//! queue fences stale settlements.
use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
    state::{Actor, Event as JobEvent, JobState},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    checks, github_events,
    github_events::Event,
    provenance::{self, Provenance},
    registration::{self, Authority},
    runs, sources,
    sources_forge::{self, Snapshot},
};

const NOW: UnixMillis = UnixMillis(1_000_000);
const REF: &str = "refs/heads/main";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GITHUB_REPO_ID: u64 = 91;
const INSTALLATION: u64 = 42;
const ACCOUNT: u64 = 73;
const REMOTE: &str = "https://github.com/account/app.git";
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

struct Fixture {
    conn: Connection,
    _key: Key,
    _dir: tempfile::TempDir,
    alice: Principal,
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
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        alice,
        tenant,
        Namespace::parse("acme").unwrap(),
        NamespaceKind::Personal(alice.user),
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, alice, tenant, repo, "app", NOW).unwrap();
    let installation = sources_forge::refresh(
        &tx,
        Snapshot {
            external_id: INSTALLATION,
            account_id: ACCOUNT,
            login: "account",
            personal: false,
            suspended: false,
            permissions_valid: true,
            expected: 0,
        },
        NOW,
    )
    .unwrap();
    registration::bind_installation_trusted(&tx, installation, tenant, NOW).unwrap();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(alice.user),
        sources::Update {
            repo,
            expected: 0,
            binding: &Binding {
                remote: REMOTE.into(),
                allowed_refs: vec![REF.into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            },
            credential: &Credential::Public,
            forge: Some((installation, GITHUB_REPO_ID)),
        },
        &["https://github.com".into()],
        &key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    Fixture {
        conn,
        _key: key,
        _dir: dir,
        alice,
        tenant,
        repo,
    }
}

fn spec() -> RunSpec {
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n  test:\n    image: {IMAGE}\n    needs: [build]\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new(REMOTE, SHA_B, Some(REF)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

/// An event-driven run, recorded at `at` so provenance can supersede it.
fn create_run(f: &mut Fixture, at: UnixMillis) -> (RunId, Vec<JobId>) {
    let (tenant, repo) = (f.tenant, f.repo);
    let run = RunId::new();
    let spec = spec();
    let tx = f.conn.transaction().unwrap();
    let jobs = runs::create_run(&tx, tenant, repo, run, &spec, at).unwrap();
    provenance::insert(
        &tx,
        &Provenance {
            tenant,
            repo,
            trigger: "push".into(),
            delivery: None,
            provider: None,
            ref_name: Some(REF.into()),
            old_sha: None,
            new_sha: Some(SHA_B.into()),
            head_sha: None,
            base_sha: None,
            merge_sha: None,
            pipeline_sha: SHA_B.into(),
            pipeline_path: Some(".sentinel.yml".into()),
            pipeline_digest: spec.pipeline.digest.to_le_bytes(),
            pr_number: None,
        },
        run,
        at,
    )
    .unwrap();
    checks::record_run(&tx, tenant, run, at).unwrap();
    tx.commit().unwrap();
    (run, jobs)
}

/// Drive every job to a terminal state the cheap way.
fn finish(f: &mut Fixture, jobs: &[JobId]) {
    for job in jobs {
        let tx = f.conn.transaction().unwrap();
        sentinel_store::jobs::transition(
            &tx,
            f.tenant,
            *job,
            Actor::Controller,
            JobEvent::CancelBeforeStart,
            NOW,
        )
        .unwrap();
        tx.commit().unwrap();
    }
}

/// The jobs' states in the caller's order.
fn states(f: &Fixture, run: RunId, jobs: &[JobId]) -> Vec<JobState> {
    let all = runs::run_jobs(&f.conn, f.tenant, run).unwrap();
    jobs.iter()
        .map(|job| {
            all.iter()
                .find(|(id, _)| id == job)
                .map(|(_, state)| *state)
                .unwrap()
        })
        .collect()
}

fn accept(f: &mut Fixture, delivery: &str, digest: u8, event: &Event) -> (String, bool) {
    let tx = f.conn.transaction().unwrap();
    let out = github_events::accept(&tx, delivery, &[digest; 32], event, NOW);
    match out {
        Ok(done) => {
            tx.commit().unwrap();
            done
        }
        Err(error) => {
            tx.rollback().unwrap();
            panic!("accept failed: {error:?}");
        }
    }
}

fn binding_state(f: &Fixture, repo: RepoId) -> (bool, Vec<u8>, i64) {
    f.conn
        .query_row(
            "SELECT revoked,credential,version FROM source_bindings WHERE repo_id=?1",
            [repo.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

fn installation_state(f: &Fixture) -> (bool, bool) {
    f.conn
        .query_row(
            "SELECT suspended,permissions_valid FROM installations WHERE external_id='42'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

#[test]
fn a_receipt_replays_identically_and_a_changed_body_conflicts() {
    let mut f = fixture();
    let event = Event::Installation {
        installation: INSTALLATION,
        disable: true,
    };
    let (outcome, duplicate) = accept(&mut f, "d-1", 7, &event);
    assert_eq!(outcome, "installation_disabled");
    assert!(!duplicate);
    // The same delivery and digest replays the recorded outcome.
    let replay = accept(&mut f, "d-1", 7, &event);
    assert_eq!(replay, (outcome, true));
    // The same delivery under a different body is a conflict, not a second
    // effect.
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        github_events::accept(&tx, "d-1", &[9; 32], &event, NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
}

#[test]
fn a_check_run_rerequest_requeues_the_terminal_run() {
    let mut f = fixture();
    let (run, jobs) = create_run(&mut f, NOW);
    finish(&mut f, &jobs);
    // The publication must name the check run the rerequest points at: both
    // the numeric handle and the external id, so a foreign id cannot aim the
    // rerun at an unrelated run.
    let publication = checks::of_run(&f.conn, f.tenant, run)
        .unwrap()
        .into_iter()
        .find(|row| row.scope == jobs[0].to_string())
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    checks::published(&tx, publication.id, publication.seq, 4242, Some(9001), NOW).unwrap();
    tx.commit().unwrap();
    let (outcome, duplicate) = accept(
        &mut f,
        "d-rerequest",
        1,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: Some((4242, publication.external_id.clone())),
            suite: 9001,
        },
    );
    assert_eq!(outcome, "rerequested");
    assert!(!duplicate);
    // The DAG reset is exact: the root job queues, its dependent blocks, and
    // fresh check desired state is recorded for the lane.
    let states = states(&f, run, &jobs);
    assert_eq!(states, vec![JobState::Queued, JobState::Blocked]);
    let after = checks::of_run(&f.conn, f.tenant, run).unwrap();
    assert!(
        after
            .iter()
            .all(|row| row.seq > 1 && row.published_seq < row.seq),
        "{after:?}"
    );
    // The completed check runs are immutable on the forge: the rerun's new
    // generations carry no handle, so the publisher creates fresh runs.
    assert!(
        after.iter().all(|row| row.check_run_id.is_none()),
        "{after:?}"
    );
    // A replayed delivery does not requeue a second time inside the same
    // generation; the receipt answers what the first attempt did.
    let replay = accept(
        &mut f,
        "d-rerequest",
        1,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: Some((4242, publication.external_id.clone())),
            suite: 9001,
        },
    );
    assert_eq!(replay, ("rerequested".to_owned(), true));
    // A *new* rerequest of the old check run cannot aim the rerun again: the
    // handle was cleared when the generation moved past `completed`, so the
    // pair no longer resolves — and the run is active besides.
    let again = accept(
        &mut f,
        "d-rerequest-2",
        2,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: Some((4242, publication.external_id.clone())),
            suite: 9001,
        },
    );
    assert_eq!(again.0, "unknown_check");
}

#[test]
fn a_check_suite_rerequest_resolves_by_suite_including_legacy_rows() {
    let mut f = fixture();
    // One publication knows its suite; a legacy row does not. Both resolve.
    let (run, jobs) = create_run(&mut f, NOW);
    finish(&mut f, &jobs);
    let rows = checks::of_run(&f.conn, f.tenant, run).unwrap();
    let tx = f.conn.transaction().unwrap();
    for (i, row) in rows.iter().enumerate() {
        let suite = if i == 0 { Some(7001) } else { None };
        checks::published(&tx, row.id, row.seq, 5000 + i as i64, suite, NOW).unwrap();
    }
    tx.commit().unwrap();
    let (outcome, _) = accept(
        &mut f,
        "d-suite",
        3,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 7001,
        },
    );
    assert_eq!(outcome, "rerequested");
    let states = states(&f, run, &jobs);
    assert_eq!(states, vec![JobState::Queued, JobState::Blocked]);
}

#[test]
fn a_rerequest_never_touches_a_superseded_run() {
    let mut f = fixture();
    let (old, old_jobs) = create_run(&mut f, NOW);
    let (_new, _new_jobs) = create_run(&mut f, UnixMillis(NOW.0 + 1));
    finish(&mut f, &old_jobs);
    // The suite id matches every publication of both runs through legacy
    // NULL rows; only the newest provenance may run again.
    let (outcome, _) = accept(
        &mut f,
        "d-stale",
        4,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 1,
        },
    );
    assert_eq!(outcome, "active_or_superseded");
    assert!(
        states(&f, old, &old_jobs)
            .iter()
            .all(|state| matches!(state, JobState::Terminal(_))),
        "the superseded run stayed terminal"
    );
    let _ = old;
}

#[test]
fn a_rerequest_refuses_unbound_and_revoked_targets() {
    let mut f = fixture();
    // An installation this deployment does not know.
    let (outcome, _) = accept(
        &mut f,
        "d-unknown-installation",
        5,
        &Event::Rerequest {
            installation: 999,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 1,
        },
    );
    assert_eq!(outcome, "unbound_installation");
    // A repository the installation does not grant here.
    let (outcome, _) = accept(
        &mut f,
        "d-unknown-repo",
        6,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: 555,
            head: SHA_B.into(),
            check: None,
            suite: 1,
        },
    );
    assert_eq!(outcome, "unbound_repository");
    // A bound but revoked source: no rerun, no check writes.
    let (run, jobs) = create_run(&mut f, NOW);
    finish(&mut f, &jobs);
    let tx = f.conn.transaction().unwrap();
    sources::revoke(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        f.repo,
        1,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    let (outcome, _) = accept(
        &mut f,
        "d-revoked",
        7,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 1,
        },
    );
    // A revoked binding resolves like an unbound one: `github_target` only
    // ever sees active grants, and the second fence (`grant`) covers the race.
    assert_eq!(outcome, "unbound_repository");
    assert!(
        states(&f, run, &jobs)
            .iter()
            .all(|state| matches!(state, JobState::Terminal(_)))
    );
}

#[test]
fn installation_events_disable_issuance_and_schedule_a_refresh() {
    let mut f = fixture();
    let (outcome, _) = accept(
        &mut f,
        "d-install",
        8,
        &Event::Installation {
            installation: INSTALLATION,
            disable: true,
        },
    );
    assert_eq!(outcome, "installation_disabled");
    assert_eq!(installation_state(&f), (true, false));
    // A durable refresh row exists for the reconcile lane.
    let work = github_events::due(&f.conn, NOW)
        .unwrap()
        .expect("a refresh");
    assert_eq!(work.kind, 0);
    // A suspension lifted by a later event is not trusted on the webhook's
    // word: issuance stays off until the authenticated refresh lands.
    let (outcome, _) = accept(
        &mut f,
        "d-unsuspend",
        9,
        &Event::Installation {
            installation: INSTALLATION,
            disable: false,
        },
    );
    assert_eq!(outcome, "refresh_pending");
    assert_eq!(installation_state(&f), (true, false));
    // The refresh row was rescheduled: its sequence moved.
    let work = github_events::due(&f.conn, NOW)
        .unwrap()
        .expect("a refresh");
    assert_eq!(work.seq, 2);
}

#[test]
fn removed_repositories_revoke_bindings_and_clear_credentials() {
    let mut f = fixture();
    let before = binding_state(&f, f.repo);
    assert!(!before.0, "the binding starts active");
    let (outcome, _) = accept(
        &mut f,
        "d-repos",
        10,
        &Event::Repositories {
            installation: INSTALLATION,
            removed: vec![GITHUB_REPO_ID],
        },
    );
    assert_eq!(outcome, "repository_access_changed");
    let (revoked, credential, version) = binding_state(&f, f.repo);
    assert!(revoked, "the binding is revoked");
    assert!(credential.is_empty(), "the sealed credential is destroyed");
    assert!(version > before.2, "the version moved");
    // The reconcile lane owes both the installation pass and a re-verify of
    // the surviving bindings.
    assert!(github_events::due(&f.conn, NOW).unwrap().is_some());
}

#[test]
fn a_repository_event_revokes_without_silently_following() {
    let mut f = fixture();
    for (delivery, outcome) in [
        ("d-renamed", "repository_rebind_required"),
        // A second event for the same repository is still an acknowledgement.
        ("d-renamed-again", "repository_rebind_required"),
    ] {
        let (done, _) = accept(
            &mut f,
            delivery,
            delivery.len() as u8,
            &Event::Repository {
                installation: INSTALLATION,
                repository: GITHUB_REPO_ID,
            },
        );
        assert_eq!(done, outcome);
    }
    let (revoked, _, _) = binding_state(&f, f.repo);
    assert!(revoked);
}

#[test]
fn refresh_rows_fence_stale_settlements_and_finish_gone_targets() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
    // Two rows: the installation pass and the repository pass.
    let first = github_events::due(&f.conn, NOW).unwrap().unwrap();
    let second = {
        let tx = f.conn.transaction().unwrap();
        github_events::settled(&tx, &first, NOW, false).unwrap();
        tx.commit().unwrap();
        github_events::due(&f.conn, NOW).unwrap().unwrap()
    };
    assert_ne!(first.id, second.id);
    // A reschedule moves the sequence; the stale pass can no longer settle it.
    let tx = f.conn.transaction().unwrap();
    github_events::schedule(&tx, &second.id, second.kind, NOW).unwrap();
    tx.commit().unwrap();
    let fresh = github_events::due(&f.conn, NOW).unwrap().unwrap();
    assert_eq!(fresh.id, second.id);
    assert_eq!(fresh.seq, second.seq + 1);
    let tx = f.conn.transaction().unwrap();
    github_events::settled(&tx, &second, NOW, false).unwrap();
    tx.commit().unwrap();
    // The row is still due: the stale settlement touched nothing.
    let still = github_events::due(&f.conn, NOW).unwrap().unwrap();
    assert_eq!(still.seq, fresh.seq);
    // A finished row whose sequence moved is not deleted by the stale pass.
    let tx = f.conn.transaction().unwrap();
    github_events::finished(&tx, &second).unwrap();
    tx.commit().unwrap();
    assert!(github_events::due(&f.conn, NOW).unwrap().is_some());
    let tx = f.conn.transaction().unwrap();
    github_events::finished(&tx, &fresh).unwrap();
    tx.commit().unwrap();
    // The first row was parked minutes out; nothing is due any more.
    assert!(github_events::due(&f.conn, NOW).unwrap().is_none());
}

#[test]
fn a_confirmed_gone_installation_revokes_everything() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
    // The installation row, whichever order `due` returns the two rows in.
    let work = f
        .conn
        .query_row(
            "SELECT id,kind,seq,attempts FROM github_refresh WHERE kind=0",
            [],
            |r| {
                Ok(github_events::Refresh {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    seq: r.get(2)?,
                    attempts: r.get(3)?,
                })
            },
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    github_events::installation_gone(&tx, &work, &work.id).unwrap();
    tx.commit().unwrap();
    assert_eq!(installation_state(&f), (true, false));
    let (revoked, credential, _) = binding_state(&f, f.repo);
    assert!(revoked && credential.is_empty());
    // The installation row's refresh work is finished; the repository row
    // remains until the lane sees its target is gone.
    let remaining = github_events::due(&f.conn, NOW).unwrap().unwrap();
    assert_eq!(remaining.kind, 1);
    assert!(
        github_events::repo_target(&f.conn, &remaining.id)
            .unwrap()
            .is_none()
    );
    let tx = f.conn.transaction().unwrap();
    github_events::finished(&tx, &remaining).unwrap();
    tx.commit().unwrap();
    assert!(github_events::due(&f.conn, NOW).unwrap().is_none());
}

#[test]
fn a_repository_refresh_verifies_or_revokes_under_the_sequence_fence() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
    // The repository row is the kind-1 refresh.
    let work = {
        let mut found = None;
        for _ in 0..4 {
            let due = github_events::due(&f.conn, NOW).unwrap().unwrap();
            if due.kind == 1 {
                found = Some(due);
                break;
            }
            let tx = f.conn.transaction().unwrap();
            github_events::settled(&tx, &due, UnixMillis(NOW.0 + 999_999_999), false).unwrap();
            tx.commit().unwrap();
        }
        found.unwrap()
    };
    let target = github_events::repo_target(&f.conn, &work.id)
        .unwrap()
        .expect("a bound repository");
    assert_eq!(target.forge_repo, GITHUB_REPO_ID);
    assert_eq!(target.remote, REMOTE);
    assert_eq!(target.installation_external, INSTALLATION);
    // Verified: nothing revoked, the row is parked for the next period.
    let tx = f.conn.transaction().unwrap();
    github_events::apply_repository(&tx, &work, target.repo, false, NOW).unwrap();
    tx.commit().unwrap();
    assert!(!binding_state(&f, f.repo).0);
    let parked = f
        .conn
        .query_row(
            "SELECT next_ms FROM github_refresh WHERE id=?1",
            [work.id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert!(
        parked > NOW.0 + 100_000,
        "the periodic pass is minutes away"
    );
    // Changed or gone: the binding is revoked under the same fence.
    let tx = f.conn.transaction().unwrap();
    github_events::apply_repository(&tx, &work, target.repo, true, NOW).unwrap();
    tx.commit().unwrap();
    assert!(binding_state(&f, f.repo).0);
}

#[test]
fn the_candidate_limit_bounds_a_rerequest() {
    let mut f = fixture();
    // More terminal runs than the cap may resolve; the answer is an explicit
    // bound, not an unbounded fan-out.
    for i in 0..66u32 {
        let (_run, jobs) = create_run(&mut f, UnixMillis(NOW.0 + i64::from(i) + 1));
        finish(&mut f, &jobs);
    }
    let (outcome, _) = accept(
        &mut f,
        "d-fanout",
        11,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 77,
        },
    );
    assert_eq!(outcome, "rerequest_limit");
}
