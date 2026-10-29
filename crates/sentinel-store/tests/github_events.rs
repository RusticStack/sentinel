use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    FailureClass, Fence, JobId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
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
const RELEASE: &str = "refs/heads/release";
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
                allowed_refs: vec![REF.into(), RELEASE.into()],
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

fn spec_at(reference: &str) -> RunSpec {
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n  test:\n    image: {IMAGE}\n    needs: [build]\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new(REMOTE, SHA_B, Some(reference)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

fn create_run(f: &mut Fixture, at: UnixMillis) -> (RunId, Vec<JobId>) {
    create_run_on(f, at, REF)
}

fn create_run_on(f: &mut Fixture, at: UnixMillis, reference: &str) -> (RunId, Vec<JobId>) {
    let (tenant, repo) = (f.tenant, f.repo);
    let run = RunId::new();
    let spec = spec_at(reference);
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
            ref_name: Some(reference.into()),
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

/// The operator narrows the binding: only `main` is allowed from now on.
fn narrow_to_main(f: &Fixture) {
    let narrowed = Binding {
        remote: REMOTE.into(),
        allowed_refs: vec![REF.into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let changed = f
        .conn
        .execute(
            "UPDATE source_bindings SET binding = ?2 WHERE repo_id = ?1",
            rusqlite::params![f.repo.as_bytes(), serde_json::to_vec(&narrowed).unwrap()],
        )
        .unwrap();
    assert_eq!(changed, 1);
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
    let replay = accept(&mut f, "d-1", 7, &event);
    assert_eq!(replay, (outcome, true));
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
    let states = states(&f, run, &jobs);
    assert_eq!(states, vec![JobState::Queued, JobState::Blocked]);
    let after = checks::of_run(&f.conn, f.tenant, run).unwrap();
    assert!(
        after
            .iter()
            .all(|row| row.seq > 1 && row.published_seq < row.seq),
        "{after:?}"
    );
    // Completed check runs are immutable on GitHub: a rerun creates fresh runs without a handle.
    assert!(
        after.iter().all(|row| row.check_run_id.is_none()),
        "{after:?}"
    );
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
fn a_rerequest_resets_a_canceled_previously_leased_run_without_touching_attempts() {
    let mut f = fixture();
    let (run, jobs) = create_run(&mut f, NOW);
    let tenant = f.tenant;
    let first = jobs[0];
    let fence = {
        let tx = f.conn.transaction().unwrap();
        runs::resolve_image(
            &tx,
            tenant,
            first,
            "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
            "linux/amd64",
        )
        .unwrap();
        let (_, fence) = sentinel_store::jobs::lease(
            &tx,
            tenant,
            first,
            WorkerId::new(),
            UnixMillis(NOW.0 + 60_000),
            NOW,
        )
        .unwrap();
        tx.commit().unwrap();
        fence
    };
    assert_eq!(fence, Fence(1));
    let tx = f.conn.transaction().unwrap();
    sentinel_store::dispatch::cancel_run(&tx, tenant, run, NOW).unwrap();
    sentinel_store::jobs::transition(
        &tx,
        tenant,
        first,
        Actor::Worker(fence),
        JobEvent::Failed(FailureClass::Canceled),
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();

    let attempt_rows = |conn: &Connection| {
        let mut stmt = conn
            .prepare(
                "SELECT id, fence, worker_id, lease_until_ms, offered_ms, acked_ms, released_ms
                 FROM attempts ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    };
    let before = attempt_rows(&f.conn);
    assert_eq!(before.len(), 1);
    let rows = checks::of_run(&f.conn, tenant, run).unwrap();
    let tx = f.conn.transaction().unwrap();
    for row in rows {
        checks::published(&tx, row.id, row.seq, 4242, Some(9001), NOW).unwrap();
    }
    tx.commit().unwrap();

    let (outcome, _) = accept(
        &mut f,
        "d-canceled-rerequest",
        9,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: None,
            suite: 9001,
        },
    );
    assert_eq!(outcome, "rerequested");
    assert_eq!(
        states(&f, run, &jobs),
        vec![JobState::Queued, JobState::Blocked]
    );
    assert_eq!(attempt_rows(&f.conn), before);
    for job in jobs {
        let row = sentinel_store::jobs::get_job(&f.conn, tenant, job).unwrap();
        assert!(!row.cancel_requested);
        assert_eq!(row.fence.0, i64::from(job == first) as u64);
    }
    assert!(
        !f.conn
            .query_row(
                "SELECT cancel_requested FROM runs WHERE id=?1",
                [run.as_bytes()],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
    );
    let tx = f.conn.transaction().unwrap();
    let (_, next_fence) = sentinel_store::jobs::lease(
        &tx,
        tenant,
        first,
        WorkerId::new(),
        UnixMillis(NOW.0 + 120_000),
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(next_fence, Fence(2));
}

#[test]
fn a_rerequest_names_the_run_by_its_create_identity() {
    let mut f = fixture();
    let (run, jobs) = create_run(&mut f, NOW);
    finish(&mut f, &jobs);
    let publication = checks::of_run(&f.conn, f.tenant, run)
        .unwrap()
        .into_iter()
        .find(|row| row.scope == jobs[0].to_string())
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    checks::create_started(&tx, publication.id, publication.seq, NOW).unwrap();
    checks::published(&tx, publication.id, publication.seq, 4242, Some(9001), NOW).unwrap();
    tx.commit().unwrap();
    let identity = checks::create_identity(&publication.external_id, publication.seq);
    let (outcome, _) = accept(
        &mut f,
        "d-foreign",
        3,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: Some((4242, format!("{}:99", publication.external_id))),
            suite: 9001,
        },
    );
    assert_eq!(outcome, "unknown_check");
    let (outcome, _) = accept(
        &mut f,
        "d-identity",
        1,
        &Event::Rerequest {
            installation: INSTALLATION,
            repository: GITHUB_REPO_ID,
            head: SHA_B.into(),
            check: Some((4242, identity)),
            suite: 9001,
        },
    );
    assert_eq!(outcome, "rerequested");
}

#[test]
fn receipts_are_purged_by_age_but_never_inside_the_replay_window() {
    let mut f = fixture();
    let event = Event::Installation {
        installation: INSTALLATION,
        disable: false,
    };
    for n in 0..3 {
        accept(&mut f, &format!("d-{n}"), 7, &event);
    }
    let receipts = |f: &Fixture| -> i64 {
        f.conn
            .query_row("SELECT count(*) FROM github_events", [], |r| r.get(0))
            .unwrap()
    };
    let tx = f.conn.transaction().unwrap();
    let inside = UnixMillis(NOW.0 + 1_000);
    assert_eq!(
        github_events::purge_receipts(&tx, inside, inside, 100).unwrap(),
        0
    );
    tx.commit().unwrap();
    assert_eq!(receipts(&f), 3);
    let later = UnixMillis(NOW.0 + github_events::MIN_RECEIPT_RETENTION_MS + 1);
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        github_events::purge_receipts(&tx, later, later, 2).unwrap(),
        2
    );
    assert_eq!(
        github_events::purge_receipts(&tx, later, later, 2).unwrap(),
        1
    );
    tx.commit().unwrap();
    assert_eq!(receipts(&f), 0);
}

#[test]
fn a_check_suite_rerequest_resolves_by_suite_including_legacy_rows() {
    let mut f = fixture();
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
fn a_rerequest_skips_a_candidate_the_binding_no_longer_allows_and_reruns_the_rest() {
    let mut f = fixture();
    let (allowed, allowed_jobs) = create_run(&mut f, NOW);
    // The operator narrows the binding to `main`: the run of the other ref is no longer allowed.
    let (barred, barred_jobs) = create_run_on(&mut f, NOW, RELEASE);
    finish(&mut f, &allowed_jobs);
    finish(&mut f, &barred_jobs);
    narrow_to_main(&f);
    let event = Event::Rerequest {
        installation: INSTALLATION,
        repository: GITHUB_REPO_ID,
        head: SHA_B.into(),
        check: None,
        suite: 3,
    };
    let (outcome, duplicate) = accept(&mut f, "d-narrowed", 6, &event);
    assert_eq!(outcome, "rerequested");
    assert!(!duplicate);
    assert_eq!(
        states(&f, allowed, &allowed_jobs),
        vec![JobState::Queued, JobState::Blocked],
        "the allowed run reran"
    );
    assert!(
        states(&f, barred, &barred_jobs)
            .iter()
            .all(|state| matches!(state, JobState::Terminal(_))),
        "the disallowed run was left alone"
    );
    // The receipt was committed with the rerun, so a redelivery replays it.
    assert_eq!(
        accept(&mut f, "d-narrowed", 6, &event),
        ("rerequested".to_owned(), true)
    );
}

#[test]
fn a_rerequest_that_only_finds_forbidden_candidates_is_receipted_not_failed() {
    let mut f = fixture();
    let (barred, barred_jobs) = create_run_on(&mut f, NOW, RELEASE);
    finish(&mut f, &barred_jobs);
    narrow_to_main(&f);
    let event = Event::Rerequest {
        installation: INSTALLATION,
        repository: GITHUB_REPO_ID,
        head: SHA_B.into(),
        check: None,
        suite: 4,
    };
    let (outcome, duplicate) = accept(&mut f, "d-forbidden", 8, &event);
    assert_eq!(outcome, "source_not_allowed");
    assert!(!duplicate);
    assert!(
        states(&f, barred, &barred_jobs)
            .iter()
            .all(|state| matches!(state, JobState::Terminal(_)))
    );
    assert_eq!(
        accept(&mut f, "d-forbidden", 8, &event),
        ("source_not_allowed".to_owned(), true)
    );
}

#[test]
fn a_rerequest_refuses_unbound_and_revoked_targets() {
    let mut f = fixture();
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
    let work = github_events::due(&f.conn, NOW)
        .unwrap()
        .expect("a refresh");
    assert_eq!(work.kind, 0);
    // A lifted suspension is untrusted until the authenticated refresh lands; a webhook alone cannot re-enable issuance.
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
    assert!(github_events::due(&f.conn, NOW).unwrap().is_some());
}

#[test]
fn a_repository_event_revokes_without_silently_following() {
    let mut f = fixture();
    for (delivery, outcome) in [
        ("d-renamed", "repository_rebind_required"),
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
    let first = github_events::due(&f.conn, NOW).unwrap().unwrap();
    let second = {
        let tx = f.conn.transaction().unwrap();
        github_events::settled(&tx, &first, NOW, false).unwrap();
        tx.commit().unwrap();
        github_events::due(&f.conn, NOW).unwrap().unwrap()
    };
    assert_ne!(first.id, second.id);
    let tx = f.conn.transaction().unwrap();
    github_events::schedule(&tx, &second.id, second.kind, NOW).unwrap();
    tx.commit().unwrap();
    let fresh = github_events::due(&f.conn, NOW).unwrap().unwrap();
    assert_eq!(fresh.id, second.id);
    assert_eq!(fresh.seq, second.seq + 1);
    let tx = f.conn.transaction().unwrap();
    github_events::settled(&tx, &second, NOW, false).unwrap();
    tx.commit().unwrap();
    let still = github_events::due(&f.conn, NOW).unwrap().unwrap();
    assert_eq!(still.seq, fresh.seq);
    let tx = f.conn.transaction().unwrap();
    github_events::finished(&tx, &second).unwrap();
    tx.commit().unwrap();
    assert!(github_events::due(&f.conn, NOW).unwrap().is_some());
    let tx = f.conn.transaction().unwrap();
    github_events::finished(&tx, &fresh).unwrap();
    tx.commit().unwrap();
    assert!(github_events::due(&f.conn, NOW).unwrap().is_none());
}

#[test]
fn a_confirmed_gone_installation_revokes_everything() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
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
    let tx = f.conn.transaction().unwrap();
    github_events::apply_repository(&tx, &work, target.repo, target.version, false, NOW).unwrap();
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
    let tx = f.conn.transaction().unwrap();
    github_events::apply_repository(&tx, &work, target.repo, target.version, true, NOW).unwrap();
    tx.commit().unwrap();
    assert!(binding_state(&f, f.repo).0);
}

#[test]
fn a_revocation_never_lands_on_a_binding_that_changed_since_it_was_read() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
    let work = f
        .conn
        .query_row(
            "SELECT id,kind,seq,attempts FROM github_refresh WHERE kind=1",
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
    let target = github_events::repo_target(&f.conn, &work.id)
        .unwrap()
        .expect("a bound repository");
    f.conn
        .execute(
            "UPDATE source_bindings SET version = version + 1 WHERE repo_id = ?1",
            [f.repo.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    github_events::apply_repository(&tx, &work, target.repo, target.version, true, NOW).unwrap();
    tx.commit().unwrap();
    assert!(
        !binding_state(&f, f.repo).0,
        "the verdict was about the old binding, not the new one"
    );

    let bound = github_events::bound_repositories(&f.conn, &target.installation).unwrap();
    assert_eq!(bound.len(), 1);
    let (repo, _, _, version) = bound[0].clone();
    f.conn
        .execute(
            "UPDATE source_bindings SET version = version + 1 WHERE repo_id = ?1",
            [f.repo.as_bytes()],
        )
        .unwrap();
    let install = f
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
    github_events::apply_installation(
        &tx,
        &install,
        Snapshot {
            external_id: INSTALLATION,
            account_id: ACCOUNT,
            login: "account",
            personal: false,
            suspended: false,
            permissions_valid: true,
            expected: 0,
        },
        &[(repo, version)],
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(
        !binding_state(&f, f.repo).0,
        "a stale version revokes nothing"
    );
}

#[test]
fn a_row_that_keeps_failing_is_pushed_out_and_then_quarantined() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    github_events::seed(&tx, NOW).unwrap();
    tx.commit().unwrap();
    let mut work = github_events::due(&f.conn, NOW).unwrap().unwrap();
    let mut last = 0;
    for _ in 0..(github_events::QUARANTINE_AFTER + 2) {
        let tx = f.conn.transaction().unwrap();
        github_events::settled(&tx, &work, NOW, true).unwrap();
        tx.commit().unwrap();
        let (attempts, next): (u32, i64) = f
            .conn
            .query_row(
                "SELECT attempts,next_ms FROM github_refresh WHERE id=?1",
                [work.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(next > NOW.0, "a failed row is never left due");
        assert!(next >= last, "the back-off never shrinks");
        last = next;
        work.attempts = attempts;
    }
    assert!(
        last >= NOW.0 + 60 * 60 * 1000,
        "a row that failed {} times waits an hour: {}",
        work.attempts,
        last - NOW.0
    );
}

#[test]
fn an_unreadable_binding_is_reported_as_corrupt_not_as_absent() {
    let f = fixture();
    f.conn
        .execute(
            "UPDATE source_bindings SET binding = x'00ff' WHERE repo_id = ?1",
            [f.repo.as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        github_events::repo_target(&f.conn, f.repo.as_bytes()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn the_candidate_limit_bounds_a_rerequest() {
    let mut f = fixture();
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

#[test]
fn the_rerequest_lookups_are_index_ranges() {
    let f = fixture();
    let plan_of = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> String {
        let mut stmt = f
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map(params, |r| r.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.join(" | ")
    };
    let id = [0u8; 16];
    let candidates = plan_of(
        github_events::RERUN_CANDIDATES_SQL,
        &[&id.as_slice(), &SHA_B, &Some(1i64), &"x", &1i64],
    );
    assert!(
        candidates.contains("check_publications_head"),
        "a rerequest finds a head's runs on its index: {candidates}"
    );
    assert!(
        !candidates.contains("SCAN check_publications"),
        "{candidates}"
    );
    let stale = plan_of(github_events::RERUN_STALE_SQL, &[&id.as_slice()]);
    assert!(
        stale.contains("provenance_by_repo"),
        "the newer-run check is a range of the repository's runs: {stale}"
    );
    assert!(!stale.contains("SCAN newer"), "{stale}");
}

#[test]
fn a_runs_recorded_actor_cannot_be_rewritten() {
    let mut f = fixture();
    let (run, _) = create_run(&mut f, NOW);
    let alice = [7u8; 16];
    f.conn
        .execute(
            "UPDATE run_provenance SET actor_user_id = ?2 WHERE run_id = ?1",
            rusqlite::params![run.as_bytes().as_slice(), alice.as_slice()],
        )
        .expect_err("provenance is written once");
}
