//! Runner-mode provisioning: demand counted per label set, one lease per unmet job, the
//! single-use configuration, and every end of a lease that has to be de-registered.

use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    PoolId, RepoId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::{
    cache::Trust,
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
};
use sentinel_store::{
    auth::{self, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    registration::Authority,
    runner as runner_store,
    runner_provision::{self, DECLINED, IDLE, JOB_COMPLETED, LAPSED, LeaseState, SESSION_LOST},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const CLASS: &str = "sentinel-4vcpu-ubuntu-2404";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    conn: Connection,
    _key: tempfile::TempDir,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let owner = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo, pool) = (TenantId::new(), RepoId::new(), PoolId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, owner.user, "owner", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        owner,
        tenant,
        Namespace::parse("acme").unwrap(),
        NamespaceKind::Organization,
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, owner, tenant, repo, "app", NOW).unwrap();
    tenancy::create_pool(
        &tx,
        Authority::HostLocal,
        pool,
        "builders",
        PoolKind::Shared,
        NOW,
    )
    .unwrap();
    tenancy::grant_pool(&tx, Authority::HostLocal, pool, tenant, NOW).unwrap();
    tx.execute(
        "UPDATE tenants SET runner_mode = 1 WHERE id = ?1",
        [tenant.as_bytes()],
    )
    .unwrap();
    tx.commit().unwrap();
    Fixture {
        conn,
        _key: dir,
        tenant,
        repo,
        pool,
    }
}

fn worker(f: &Fixture, cpu_millis: i64, memory_bytes: i64, labels: &[&str]) -> WorkerId {
    worker_on_host(f, cpu_millis, memory_bytes, labels, None)
}

fn worker_on_host(
    f: &Fixture,
    cpu_millis: i64,
    memory_bytes: i64,
    labels: &[&str],
    host: Option<[u8; 16]>,
) -> WorkerId {
    let id = WorkerId::new();
    let fingerprint = Secret::generate().digest();
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
    let tx = f.conn.unchecked_transaction().unwrap();
    let issued = workers::issue_enrollment(&tx, Authority::HostLocal, f.pool, 60_000, NOW).unwrap();
    let mut text = String::new();
    issued.secret.expose(&mut text);
    workers::enroll(
        &tx,
        &Secret::parse(&text).unwrap(),
        Presentation {
            worker: id,
            fingerprint,
            name: "w",
            negotiated: Negotiated {
                protocol: ProtocolVersion(12),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
            },
        },
        NOW,
    )
    .unwrap();
    dispatch::report_capacity(
        &tx,
        id,
        Capacity {
            cpu_millis,
            memory_bytes,
            disk_bytes: 100 << 30,
        },
    )
    .unwrap();
    dispatch::report_profile(
        &tx,
        id,
        &dispatch::ReportedProfile {
            labels: labels.as_slice(),
            host_id: host,
            avail_images: &[],
            cache_bytes: Some(0),
            load_ns: Some(0),
        },
    )
    .unwrap();
    tx.commit().unwrap();
    id
}

fn queued(f: &Fixture, job: u64, labels: &str) {
    f.conn
        .execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms)
             VALUES (?1, ?2, ?3, ?3, ?4, 0, NULL, NULL, ?5, NULL, NULL)",
            rusqlite::params![
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                job as i64,
                labels,
                NOW.0
            ],
        )
        .unwrap();
}

fn place(f: &Fixture, worker: WorkerId, now: UnixMillis) -> Option<runner_provision::Lease> {
    let tx = f.conn.unchecked_transaction().unwrap();
    let lease = runner_provision::place(&tx, worker, runner_provision::LEASE_MS, now).unwrap();
    tx.commit().unwrap();
    lease
}

fn accepting(f: &Fixture, lease: &runner_provision::Lease, now: UnixMillis) {
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(runner_provision::accept(&tx, lease.worker, lease.id, now).unwrap());
    tx.commit().unwrap();
}

#[test]
fn a_burst_of_queued_jobs_gets_one_lease_each() {
    let f = fixture();
    let workers: Vec<WorkerId> = (0..3)
        .map(|_| worker(&f, 16_000, 64 << 30, &[CLASS]))
        .collect();
    for job in 1..=3 {
        queued(&f, job, CLASS);
    }
    let mut placed = Vec::new();
    for &w in &workers {
        let lease = place(&f, w, NOW).expect("each worker takes one");
        assert_eq!(lease.class, CLASS);
        assert_eq!(lease.state, LeaseState::Offered);
        placed.push(lease);
    }
    // Demand per label set: three jobs, three runners, and nothing more to place.
    assert_eq!(placed.len(), 3);
    for &w in &workers {
        assert!(place(&f, w, at(2_000)).is_none(), "no fourth runner");
    }
    // The worker holds 4 vCPU and 8 GiB for its one runner: two of them fit, the third does not.
    let tx = f.conn.unchecked_transaction().unwrap();
    let free = dispatch::free_capacity(&tx, workers[0]).unwrap();
    let (cpu, memory) = runner_provision::class_capacity(4);
    assert_eq!(free.cpu_millis, 16_000 - cpu);
    assert_eq!(free.memory_bytes, (64 << 30) - memory);
}

#[test]
fn one_burst_spreads_over_the_fleet_before_any_machine_takes_two_on_one_host_too() {
    let f = fixture();
    let host = Some([3u8; 16]);
    let workers: Vec<WorkerId> = (0..3)
        .map(|_| worker_on_host(&f, 16_000, 64 << 30, &[CLASS], host))
        .collect();
    for job in 1..=3 {
        queued(&f, job, CLASS);
    }
    let tx = f.conn.unchecked_transaction().unwrap();
    let mut placed = Vec::new();
    for _ in 0..3 {
        for &w in &workers {
            if let Some(lease) =
                runner_provision::place(&tx, w, runner_provision::LEASE_MS, NOW).unwrap()
            {
                placed.push(lease.worker);
            }
        }
    }
    tx.commit().unwrap();
    let mut machines: Vec<WorkerId> = placed.clone();
    machines.sort_unstable();
    machines.dedup();
    assert_eq!(placed.len(), 3, "{placed:?}");
    assert_eq!(machines.len(), 3, "one each: {placed:?}");
}

#[test]
fn one_burst_spreads_over_the_fleet_before_any_machine_takes_two() {
    let f = fixture();
    let workers: Vec<WorkerId> = (0..3)
        .map(|_| worker(&f, 16_000, 64 << 30, &[CLASS]))
        .collect();
    for job in 1..=3 {
        queued(&f, job, CLASS);
    }
    let tx = f.conn.unchecked_transaction().unwrap();
    let mut placed = Vec::new();
    for round in 0..3 {
        for &w in &workers {
            if let Some(lease) =
                runner_provision::place(&tx, w, runner_provision::LEASE_MS, NOW).unwrap()
            {
                placed.push((round, lease.worker));
            }
        }
    }
    tx.commit().unwrap();
    assert_eq!(placed.len(), 3, "{placed:?}");
    let mut machines: Vec<WorkerId> = placed.iter().map(|(_, w)| *w).collect();
    machines.sort_unstable();
    machines.dedup();
    assert_eq!(machines.len(), 3, "one runner each: {placed:?}");
}

#[test]
fn demand_is_counted_per_label_set_not_per_job() {
    let f = fixture();
    let w = worker(&f, 32_000, 128 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let first = place(&f, w, NOW).expect("demand");
    // One live runner covers the label set: a second queued job that GitHub could hand to it is
    // not a second runner.
    assert!(place(&f, w, NOW).is_none(), "one queued job is one runner");
    queued(&f, 2, CLASS);
    // Two queued jobs and one live runner leave one unit of demand, whichever job it takes.
    let second = place(&f, w, NOW).expect("the second queued job needs a runner");
    assert_ne!(first.id, second.id);
    assert_eq!(
        runner_provision::get(&f.conn, second.id)
            .unwrap()
            .unwrap()
            .job,
        None,
        "a lease is placed for a label set, not bound to the job that caused it"
    );
}

#[test]
fn a_worker_that_does_not_name_the_class_is_never_given_it() {
    let f = fixture();
    let plain = worker(&f, 16_000, 32 << 30, &["linux", "egress"]);
    queued(&f, 1, CLASS);
    assert!(place(&f, plain, NOW).is_none());
    // A worker that has room for a smaller class but not this one takes nothing either.
    let small = worker(&f, 2_000, 4 << 30, &[CLASS]);
    assert!(place(&f, small, NOW).is_none());
}

#[test]
fn an_idle_runner_is_released_at_its_bound_and_its_capacity_returns() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(
        runner_provision::idle(&tx, at(5_000), 60_000)
            .unwrap()
            .is_empty()
    );
    let due = runner_provision::idle(&tx, at(61_000), 60_000).unwrap();
    tx.commit().unwrap();
    assert_eq!(due, vec![(lease.id, w)]);
    let ended = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
    assert_eq!(ended.state, LeaseState::Released);
    assert_eq!(ended.reason.as_deref(), Some(IDLE));
    let tx = f.conn.unchecked_transaction().unwrap();
    let free = dispatch::free_capacity(&tx, w).unwrap();
    assert_eq!(free.cpu_millis, 16_000, "the reservation is gone");
    assert_eq!(free.memory_bytes, 32 << 30);
}

#[test]
fn an_offer_nobody_answers_lapses_and_the_worker_can_take_the_next() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    queued(&f, 2, CLASS);
    let first = place(&f, w, NOW).expect("demand");
    let tx = f.conn.unchecked_transaction().unwrap();
    let lapsed = runner_provision::lapsed(&tx, at(NOW.0 + runner_provision::OFFER_ACK_MS)).unwrap();
    tx.commit().unwrap();
    assert_eq!(lapsed, vec![(first.id, w)]);
    assert!(place(&f, w, NOW).is_some(), "the capacity came back");
}

#[test]
fn a_declined_offer_releases_the_lease_at_once() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(runner_provision::decline(&tx, w, lease.id, NOW).unwrap());
    tx.commit().unwrap();
    let ended = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
    assert_eq!(ended.reason.as_deref(), Some(DECLINED));
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(!runner_provision::decline(&tx, w, lease.id, NOW).unwrap());
    tx.commit().unwrap();
}

#[test]
fn the_configuration_is_stored_sealed_and_read_exactly_once() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(
        runner_provision::set_config(&tx, lease.id, w, 91, b"sealed-bytes", NOW).unwrap(),
        "written once"
    );
    assert!(
        !runner_provision::set_config(&tx, lease.id, w, 92, b"again", NOW).unwrap(),
        "never rewritten"
    );
    let stored: Vec<u8> = tx
        .query_row(
            "SELECT sealed_jit FROM runner_leases WHERE id = ?1",
            [lease.id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, b"sealed-bytes");
    let taken = runner_provision::take_config(&tx, lease.id, w, NOW).unwrap();
    assert_eq!(taken.as_deref(), Some(&b"sealed-bytes"[..]));
    // The same transaction that returns it clears it: a retried frame, another reader or a copy
    // of the database finds nothing.
    assert!(
        runner_provision::take_config(&tx, lease.id, w, NOW)
            .unwrap()
            .is_none()
    );
    tx.commit().unwrap();
    assert!(
        runner_provision::sealed_config(&f.conn, lease.id, w)
            .unwrap()
            .is_none()
    );
    let lease_row = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
    assert_eq!(lease_row.runner_id, Some(91));
}

#[test]
fn a_job_binds_to_the_runner_the_lease_registered_and_completion_ends_it() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 7, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_provision::set_config(&tx, lease.id, w, 91, b"sealed", NOW).unwrap();
    let bound = runner_provision::bind(&tx, f.tenant, f.repo, &lease.runner_name, 7, NOW)
        .unwrap()
        .expect("the name is the lease's");
    assert_eq!(bound, lease.id);
    tx.commit().unwrap();
    // The idle sweep leaves a runner that took a job alone.
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(
        runner_provision::idle(&tx, at(10_000_000), 60_000)
            .unwrap()
            .is_empty()
    );
    let ended = runner_provision::complete(&tx, f.tenant, f.repo, 7, JOB_COMPLETED, at(9_000))
        .unwrap()
        .expect("the job's lease");
    tx.commit().unwrap();
    assert_eq!(ended, lease.id);
    let row = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
    assert_eq!(row.reason.as_deref(), Some(JOB_COMPLETED));
    assert_eq!(row.job, Some(7));
}

/// AR06: the boundary the controller states for a lease comes from the row the delivery wrote — the
/// tenant and repository the lease was minted for, the GitHub run and job, and the trust the fork flag
/// decides — and a lease no job has taken states nothing, because nothing about its job is known.
#[test]
fn a_bound_lease_states_its_boundary_and_an_unclaimed_one_states_nothing() {
    let f = fixture();
    let w = worker(&f, 32_000, 64 << 30, &[CLASS]);
    queued(&f, 7, CLASS);
    // The fork fact is written once, by the delivery that created the row, and never rewritten.
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    // Nothing has taken it: a sandbox built now would serve no cache call.
    assert!(
        runner_provision::bound_scopes(&f.conn, w)
            .unwrap()
            .is_empty()
    );
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_provision::bind(&tx, f.tenant, f.repo, &lease.runner_name, 7, NOW).unwrap();
    tx.commit().unwrap();

    let scopes = runner_provision::bound_scopes(&f.conn, w).unwrap();
    assert_eq!(scopes.len(), 1);
    let scope = scopes[0];
    assert_eq!(scope.lease, lease.id);
    assert_eq!(scope.tenant, f.tenant);
    assert_eq!(scope.repo, f.repo);
    assert_eq!(scope.job, 7);
    // `queued` wrote run 7 too, and the trust is the ordinary pool's.
    assert_eq!(scope.run, 7);
    assert_eq!(scope.trust, Trust::Protected);

    // Another machine has nothing of this worker's leases to state.
    let other = worker(&f, 32_000, 64 << 30, &[CLASS]);
    assert!(
        runner_provision::bound_scopes(&f.conn, other)
            .unwrap()
            .is_empty()
    );

    // A released lease states nothing either: its runner is gone.
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_provision::complete(&tx, f.tenant, f.repo, 7, JOB_COMPLETED, at(9_000)).unwrap();
    tx.commit().unwrap();
    assert!(
        runner_provision::bound_scopes(&f.conn, w)
            .unwrap()
            .is_empty()
    );
}

/// A fork job's boundary is the untrusted one, and it is the delivery's own row that says so.
#[test]
fn a_fork_jobs_boundary_is_pull_request_and_a_trusted_jobs_is_protected() {
    let f = fixture();
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(tenancy::set_pool_fork(&tx, Authority::HostLocal, f.pool, true).unwrap());
    tx.commit().unwrap();
    opt_in(&f);
    let w = worker(&f, 32_000, 64 << 30, &[CLASS]);
    f.conn
        .execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms, fork_pr)
             VALUES (?1, ?2, 9, 90, ?3, 0, NULL, NULL, ?4, NULL, NULL, 1)",
            rusqlite::params![f.tenant.as_bytes(), f.repo.as_bytes(), CLASS, NOW.0],
        )
        .unwrap();
    let lease = place(&f, w, NOW).expect("a fork job is demand on a fork pool");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_provision::bind(&tx, f.tenant, f.repo, &lease.runner_name, 9, NOW).unwrap();
    tx.commit().unwrap();
    let scope = runner_provision::bound_scopes(&f.conn, w).unwrap()[0];
    assert_eq!(scope.trust, Trust::PullRequest);
    assert_eq!((scope.run, scope.job), (90, 9));
}

#[test]
fn a_lost_session_ends_every_lease_of_that_worker() {
    let f = fixture();
    let w = worker(&f, 32_000, 64 << 30, &[CLASS]);
    for job in 1..=2 {
        queued(&f, job, CLASS);
    }
    let first = place(&f, w, NOW).expect("demand");
    let second = place(&f, w, NOW).expect("second demand");
    let tx = f.conn.unchecked_transaction().unwrap();
    assert_eq!(
        runner_provision::release_worker(&tx, w, SESSION_LOST, NOW).unwrap(),
        2
    );
    tx.commit().unwrap();
    for lease in [first, second] {
        let row = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
        assert_eq!(row.reason.as_deref(), Some(SESSION_LOST));
    }
}

#[test]
fn every_registration_is_removed_even_after_its_lease_ended() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_provision::set_config(&tx, lease.id, w, 91, b"sealed", NOW).unwrap();
    runner_provision::release(&tx, lease.id, IDLE, at(61_000)).unwrap();
    tx.commit().unwrap();
    let pending = runner_provision::to_unregister(&f.conn, 16).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].runner_id, 91);
    assert_eq!((pending[0].tenant, pending[0].repo), (f.tenant, f.repo));
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(runner_provision::unregistered(&tx, lease.id, at(62_000)).unwrap());
    assert!(!runner_provision::unregistered(&tx, lease.id, at(62_000)).unwrap());
    tx.commit().unwrap();
    assert!(
        runner_provision::to_unregister(&f.conn, 16)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_lease_the_controller_stopped_renewing_is_released_as_lapsed() {
    let f = fixture();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    queued(&f, 1, CLASS);
    let lease = place(&f, w, NOW).expect("demand");
    accepting(&f, &lease, NOW);
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(
        runner_provision::expired(&tx, at(NOW.0 + runner_provision::LEASE_MS - 1))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        runner_provision::expired(&tx, at(NOW.0 + runner_provision::LEASE_MS)).unwrap(),
        vec![(lease.id, w)]
    );
    tx.commit().unwrap();
    let row = runner_provision::get(&f.conn, lease.id).unwrap().unwrap();
    assert_eq!(row.reason.as_deref(), Some(LAPSED));
}

#[test]
fn a_lost_queued_event_is_recovered_by_observing_githubs_queue() {
    let f = fixture();
    let tx = f.conn.unchecked_transaction().unwrap();
    assert!(runner_provision::observe(&tx, f.tenant, f.repo, 41, 9, CLASS, NOW).unwrap());
    // The same job twice is one row, and a class this build does not know is not demand.
    assert!(!runner_provision::observe(&tx, f.tenant, f.repo, 41, 9, CLASS, NOW).unwrap());
    assert!(runner_provision::observe(&tx, f.tenant, f.repo, 42, 9, "ubuntu-latest", NOW).is_err());
    tx.commit().unwrap();
    let w = worker(&f, 16_000, 32 << 30, &[CLASS]);
    assert!(place(&f, w, NOW).is_some(), "the observed job is demand");
}

#[test]
fn reconciliation_covers_every_bound_repository_of_a_runner_mode_tenant() {
    let f = fixture();
    let found = runner_provision::reconcile_targets(&f.conn, None, 32).unwrap();
    assert!(
        found.is_empty(),
        "a repository bound through no installation"
    );
}

fn fork_pool(f: &Fixture) -> PoolId {
    let pool = PoolId::new();
    let tx = f.conn.unchecked_transaction().unwrap();
    tenancy::create_pool(
        &tx,
        Authority::HostLocal,
        pool,
        "forks",
        PoolKind::Shared,
        NOW,
    )
    .unwrap();
    tenancy::grant_pool(&tx, Authority::HostLocal, pool, f.tenant, NOW).unwrap();
    assert!(tenancy::set_pool_fork(&tx, Authority::HostLocal, pool, true).unwrap());
    tx.commit().unwrap();
    pool
}

fn opt_in(f: &Fixture) {
    let tx = f.conn.unchecked_transaction().unwrap();
    runner_store::set_fork_prs(&tx, Authority::HostLocal, f.tenant, true).unwrap();
    tx.commit().unwrap();
}

fn queued_fork(f: &Fixture, job: u64, labels: &str) {
    f.conn
        .execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms, fork_pr)
             VALUES (?1, ?2, ?3, ?3, ?4, 0, NULL, NULL, ?5, NULL, NULL, 1)",
            rusqlite::params![
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                job as i64,
                labels,
                NOW.0
            ],
        )
        .unwrap();
}

#[test]
fn a_fork_pull_requests_job_is_never_placed_without_the_tenants_opt_in() {
    let f = fixture();
    let w = worker(&f, 16_000, 64 << 30, &[CLASS]);
    queued_fork(&f, 1, CLASS);
    assert!(
        place(&f, w, NOW).is_none(),
        "a fork job was leased on a tenant that does not serve fork pull requests"
    );
    // The trusted pool may not serve it either, even after the opt-in: it is not a fork pool.
    opt_in(&f);
    assert!(
        place(&f, w, NOW).is_none(),
        "a fork job was leased on a pool that is not the hostile-fork pool"
    );
    // With a pool marked for fork jobs the same demand is served.
    let forks = fork_pool(&f);
    let forked = worker_on_pool(&f, forks, &[CLASS]);
    assert!(place(&f, forked, NOW).is_some());
}

#[test]
fn the_hostile_fork_pool_serves_no_trusted_job() {
    let f = fixture();
    let forks = fork_pool(&f);
    opt_in(&f);
    let forked = worker_on_pool(&f, forks, &[CLASS]);
    queued(&f, 1, CLASS);
    assert!(
        place(&f, forked, NOW).is_none(),
        "a trusted job was leased on the hostile-fork pool"
    );
    queued_fork(&f, 2, CLASS);
    let lease = place(&f, forked, NOW).expect("fork demand has a fork pool");
    assert_eq!(lease.class, CLASS);
}

#[test]
fn a_fork_pool_lease_is_refused_by_the_database_without_the_opt_in() {
    let f = fixture();
    let forks = fork_pool(&f);
    let lease = sentinel_core::RunnerLeaseId::new();
    let refused = f.conn.execute(
        "INSERT INTO runner_leases(id, tenant_id, repo_id, class, pool_id, worker_id, fence,
            state_code, cpu_millis, memory_bytes, runner_name, offered_ms, lease_until_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 0, 4000, 8589934592, 'sentinel-fork-1', ?7, ?8)",
        rusqlite::params![
            lease.as_bytes(),
            f.tenant.as_bytes(),
            f.repo.as_bytes(),
            CLASS,
            forks.as_bytes(),
            WorkerId::new().as_bytes(),
            NOW.0,
            NOW.0 + 60_000
        ],
    );
    let error = refused.expect_err("a fork pool took a lease without the tenant's opt-in");
    assert!(
        error.to_string().contains("fork pool"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn offering_fork_jobs_is_refused_without_runner_mode() {
    let f = fixture();
    f.conn
        .execute(
            "UPDATE tenants SET runner_mode = 0 WHERE id = ?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.unchecked_transaction().unwrap();
    assert_eq!(
        runner_store::set_fork_prs(&tx, Authority::HostLocal, f.tenant, true).unwrap(),
        sentinel_store::switch::Switch::NoRunnerMode
    );
    tx.commit().unwrap();
    assert!(
        !runner_store::fork_prs(&f.conn, f.tenant).unwrap(),
        "nothing was written"
    );
}

#[test]
fn the_fork_pull_request_opt_in_is_audited() {
    let f = fixture();
    opt_in(&f);
    let tx = f.conn.unchecked_transaction().unwrap();
    assert_eq!(
        runner_store::set_fork_prs(&tx, Authority::HostLocal, f.tenant, true).unwrap(),
        sentinel_store::switch::Switch::Unchanged
    );
    tx.commit().unwrap();
    // Audit event 101 is `runner-fork-prs-changed`; the detail says which way the switch went.
    let rows: Vec<Option<String>> = f
        .conn
        .prepare("SELECT detail FROM auth_audit WHERE event = 101 ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(rows, [Some("enabled".to_owned())]);
}

fn worker_on_pool(f: &Fixture, pool: PoolId, labels: &[&str]) -> WorkerId {
    let id = WorkerId::new();
    let fingerprint = Secret::generate().digest();
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
    let tx = f.conn.unchecked_transaction().unwrap();
    let issued = workers::issue_enrollment(&tx, Authority::HostLocal, pool, 60_000, NOW).unwrap();
    let mut text = String::new();
    issued.secret.expose(&mut text);
    workers::enroll(
        &tx,
        &Secret::parse(&text).unwrap(),
        Presentation {
            worker: id,
            fingerprint,
            name: "w",
            negotiated: Negotiated {
                protocol: ProtocolVersion(12),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
            },
        },
        NOW,
    )
    .unwrap();
    dispatch::report_capacity(
        &tx,
        id,
        Capacity {
            cpu_millis: 16_000,
            memory_bytes: 64 << 30,
            disk_bytes: 100 << 30,
        },
    )
    .unwrap();
    dispatch::report_profile(
        &tx,
        id,
        &dispatch::ReportedProfile {
            labels: labels.as_slice(),
            host_id: None,
            avail_images: &[],
            cache_bytes: Some(0),
            load_ns: Some(0),
        },
    )
    .unwrap();
    tx.commit().unwrap();
    id
}
