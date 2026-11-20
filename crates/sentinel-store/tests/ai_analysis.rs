//! Automatic failure analysis and the expiry of a cached analysis (Part 22 Y05).
//!
//! The gate this file proves is the request's: a tenant that turns automatic analysis on gets one
//! request for a failed job and none for anything else, written by the sweep the AI process's poll
//! already runs — never by the attempt that failed, so no run, job, dispatch or check waits on it.
//! The second half is the analysis cache's: an answer is kept only as long as the log it cites, so
//! nothing outlives its own evidence.
//!
//! No provider is involved anywhere: the controller only decides.

use std::sync::Arc;

use sentinel_core::{
    AiRequestId, AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role, Scopes},
};
use sentinel_store::{
    Durability, Store,
    ai::{
        self, Admitted, Budgets, DataPolicy, Deployment, Origin, Outcome, Provider, Providers,
        Reservation, State, Tenant,
    },
    auth::{self as authz, Authority, provisioning},
    jobs,
};

const NOW: UnixMillis = UnixMillis(1_700_000_000_000);

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    tenant: TenantId,
    platform: UserId,
    admin: UserId,
    member: UserId,
    repo: RepoId,
    run: RunId,
    /// The job whose failure the sweep reads, with the attempt that ended it.
    failed_job: JobId,
    failed_attempt: AttemptId,
}

impl Fixture {
    /// A repository with one job, and the attempt that ended it.
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let (tenant, platform, admin, member) =
            (TenantId::new(), UserId::new(), UserId::new(), UserId::new());
        let (repo, run, failed_job, failed_attempt) =
            (RepoId::new(), RunId::new(), JobId::new(), AttemptId::new());
        store
            .writer()
            .write(move |tx| {
                jobs::insert_tenant(tx, tenant, "acme", NOW)?;
                provisioning::insert_human(tx, platform, "Root", true, NOW)?;
                provisioning::insert_human(tx, admin, "Ada", false, NOW)?;
                provisioning::insert_human(tx, member, "Mia", false, NOW)?;
                let root = Principal::new(platform, P::ALL, None, None);
                authz::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
                authz::set_membership(tx, root, tenant, member, Role::Reader)?;
                authz::create_repo(tx, root, tenant, repo, "app", NOW)?;
                authz::set_repo_grant(tx, root, repo, member, P::READ)?;
                jobs::insert_run(tx, tenant, repo, run, "abc123", NOW)?;
                jobs::insert_job(tx, tenant, run, failed_job, "alpha", 5, 0)?;
                tx.execute(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                        repo_id, released_ms)
                     VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6)",
                    (
                        failed_attempt.as_bytes(),
                        tenant.as_bytes(),
                        failed_job.as_bytes(),
                        [9u8; 16],
                        repo.as_bytes(),
                        NOW.0,
                    ),
                )?;
                let mut providers = Providers::NONE;
                providers.insert(Provider::Local);
                providers.insert(Provider::OpenRouter);
                ai::set_deployment(
                    tx,
                    Authority::Credential {
                        principal: Principal::new(platform, P::ALL, None, None),
                        stepped_up: true,
                    },
                    Deployment {
                        enabled: true,
                        providers,
                    },
                    NOW,
                )?;
                Ok(())
            })
            .unwrap();
        let f = Fixture {
            _dir: dir,
            store,
            tenant,
            platform,
            admin,
            member,
            repo,
            run,
            failed_job,
            failed_attempt,
        };
        f.opt_in(Budgets::default());
        f
    }

    /// The deployment's allow-list, as a platform administrator sets it.
    fn deployment(&self, providers: Providers) {
        let (store, platform) = (Arc::clone(&self.store), self.platform);
        store
            .writer()
            .write(move |tx| {
                ai::set_deployment(
                    tx,
                    Authority::Credential {
                        principal: Principal::new(platform, P::ALL, None, None),
                        stepped_up: true,
                    },
                    Deployment {
                        enabled: true,
                        providers,
                    },
                    NOW,
                )
            })
            .unwrap();
    }

    fn opt_in(&self, budgets: Budgets) {
        self.policy(false, DataPolicy::LocalOnly, budgets);
    }

    /// The tenant's opt-in, with automatic analysis stated.
    fn policy(&self, auto_analysis: bool, data_policy: DataPolicy, budgets: Budgets) {
        let authority = Authority::Credential {
            principal: Principal::new(self.admin, P::REPOSITORY.union(P::TENANT_ADMIN), None, None),
            stepped_up: true,
        };
        let (tenant, store) = (self.tenant, Arc::clone(&self.store));
        store
            .writer()
            .write(move |tx| {
                ai::set_tenant(
                    tx,
                    authority,
                    tenant,
                    Tenant {
                        enabled: true,
                        data_policy,
                        budgets,
                        auto_analysis,
                    },
                    NOW,
                )
            })
            .unwrap();
    }

    /// A job in the state the sweep reads, with the class and the time it ended.
    fn finish(&self, job: JobId, state: i64, at: UnixMillis) {
        let class = match state {
            20 => Some(0i64),
            19 => Some(3),
            18 => Some(5),
            _ => None,
        };
        Arc::clone(&self.store)
            .writer()
            .write(move |tx| {
                tx.execute(
                    "UPDATE jobs SET state_code = ?2, failure_class = ?3, terminal_ms = ?4
                      WHERE id = ?1",
                    (job.as_bytes(), state, class, at.0),
                )?;
                Ok(())
            })
            .unwrap();
    }

    /// One more job of the same run, with the attempt that ended it.
    fn job(&self, name: &str) -> (JobId, AttemptId) {
        let (job, attempt) = (JobId::new(), AttemptId::new());
        let (tenant, run, repo) = (self.tenant, self.run, self.repo);
        let name = name.to_owned();
        Arc::clone(&self.store)
            .writer()
            .write(move |tx| {
                jobs::insert_job(tx, tenant, run, job, &name, 5, 1)?;
                tx.execute(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                        repo_id, released_ms)
                     VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6)",
                    (
                        attempt.as_bytes(),
                        tenant.as_bytes(),
                        job.as_bytes(),
                        [8u8; 16],
                        repo.as_bytes(),
                        NOW.0,
                    ),
                )?;
                Ok(())
            })
            .unwrap();
        (job, attempt)
    }

    /// The sweep, as the AI process's poll runs it.
    fn sweep(&self, now: UnixMillis) -> usize {
        Arc::clone(&self.store)
            .writer()
            .write(move |tx| ai::enqueue_automatic(tx, now, 16))
            .unwrap()
    }

    fn requests(&self) -> Vec<ai::Request> {
        self.store
            .read(|c| {
                let mut statement = c.prepare(
                    "SELECT id FROM ai_requests WHERE tenant_id = ?1 ORDER BY created_ms, id",
                )?;
                let ids: Vec<[u8; 16]> = statement
                    .query_map([self.tenant.as_bytes()], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                ids.into_iter()
                    .map(|id| ai::by_id(c, AiRequestId::from_bytes(id).unwrap()))
                    .collect()
            })
            .unwrap()
    }
}

/// A request the sweep wrote, claimed and answered: what a cached analysis needs.
fn answered(f: &Fixture, id: AiRequestId) -> UnixMillis {
    let attempt = f.failed_attempt;
    // After the sweep wrote the row, so the claim follows its creation.
    let at = UnixMillis(NOW.0 + 3_000);
    let asked = Reservation {
        input_tokens: 1_000,
        output_tokens: 500,
        cost_micros: 9_000,
        digest: [1; 32],
        fingerprint: [42; 32],
        prompt_version: "analysis-1".into(),
        model: "fake/model".into(),
    };
    Arc::clone(&f.store)
        .writer()
        .write(move |tx| {
            ai::claim(tx, id, at)?;
            let admitted = ai::reserve(tx, id, &asked, at)?;
            assert!(matches!(admitted, Admitted::Reserved { .. }));
            ai::settle(
                tx,
                id,
                Outcome::Completed,
                Some(&format!(
                    "{{\"schema\":\"sentinel.ai-analysis/1\",\"summary\":\"s\",\"claims\":\
                     [{{\"text\":\"t\",\"citations\":[{{\"attempt\":\"{}\",\"evidence\":\"log-1\"}}]}}]}}",
                    attempt
                )),
                None,
                at,
                None,
            )?;
            Ok(())
        })
        .unwrap();
    at
}

fn cached(f: &Fixture) -> Option<i64> {
    f.store
        .read(|c| {
            Ok(c.prepare("SELECT expires_ms FROM ai_analyses")?
                .query_row([], |r| r.get::<_, i64>(0))
                .ok())
        })
        .unwrap()
}

#[test]
fn automatic_analysis_is_off_until_the_tenant_turns_it_on() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    assert_eq!(f.sweep(UnixMillis(NOW.0 + 2_000)), 0, "off by default");
    assert!(f.requests().is_empty());
    // Turning it on is the tenant administrator's decision, and it reads back on the policy.
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    assert_eq!(
        f.store.read(|c| ai::tenant(c, f.tenant)).unwrap().unwrap(),
        Tenant {
            enabled: true,
            data_policy: DataPolicy::LocalOnly,
            budgets: Budgets::default(),
            auto_analysis: true,
        }
    );
    assert_eq!(f.sweep(UnixMillis(NOW.0 + 2_000)), 1);
}

#[test]
fn only_a_failed_job_gets_a_request_and_it_is_the_failure_it_ended_with() {
    let f = Fixture::new();
    let (passed, _) = f.job("beta");
    let (cancelled, _) = f.job("gamma");
    let (timed_out, _) = f.job("delta");
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    f.finish(passed, 16, UnixMillis(NOW.0 + 1_000));
    f.finish(cancelled, 18, UnixMillis(NOW.0 + 1_000));
    f.finish(timed_out, 19, UnixMillis(NOW.0 + 1_000));
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    assert_eq!(f.sweep(UnixMillis(NOW.0 + 2_000)), 1);
    let requests = f.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.attempt, f.failed_attempt);
    assert_eq!(request.repo, f.repo);
    assert_eq!(request.origin, Origin::Automatic);
    assert_eq!(request.state, State::Queued);
    assert_eq!(
        request.requester, f.admin,
        "the administrator whose decision turned it on asks, so the delegation reads what they could"
    );
    assert_eq!(
        request.provider,
        Provider::Local,
        "the first allow-listed provider the data policy permits"
    );
    assert_eq!(request.data_policy, DataPolicy::LocalOnly);
    assert_eq!(request.deadline.0, NOW.0 + 2_000 + ai::REQUEST_LIFETIME_MS);
}

#[test]
fn the_sweep_writes_one_request_however_often_it_runs() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    let now = UnixMillis(NOW.0 + 2_000);
    assert_eq!(f.sweep(now), 1);
    assert_eq!(
        f.sweep(now),
        0,
        "the attempt already has its automatic request"
    );
    assert_eq!(f.sweep(UnixMillis(now.0 + 1)), 0);
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn a_failure_older_than_the_window_gets_nothing() {
    let f = Fixture::new();
    f.finish(
        f.failed_job,
        20,
        UnixMillis(NOW.0 - ai::AUTOMATIC_WINDOW_MS - 1),
    );
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    assert_eq!(
        f.sweep(NOW),
        0,
        "a switch turned on today pays for today's failures"
    );
}

#[test]
fn a_tenant_whose_policy_admits_no_provider_gets_no_automatic_request() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    // The local endpoint is the only provider that keeps every byte inside the operator's network,
    // so a tenant under `local_only` has nothing to send to a deployment that allows hosted ones alone.
    let mut providers = Providers::NONE;
    providers.insert(Provider::OpenRouter);
    f.deployment(providers);
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    assert_eq!(f.sweep(UnixMillis(NOW.0 + 2_000)), 0);
    assert!(f.requests().is_empty());
    // The same failure under a policy that names what the allow-list holds is written.
    f.policy(true, DataPolicy::ZeroRetention, Budgets::default());
    assert_eq!(f.sweep(UnixMillis(NOW.0 + 2_000)), 1);
    assert_eq!(f.requests()[0].provider, Provider::OpenRouter);
}

#[test]
fn an_analysis_expires_with_the_log_it_cites_not_with_the_cache_alone() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    // The attempt's log retention ends in an hour: the analysis it is computed from may not outlive it.
    let retention = NOW.0 + 60 * 60 * 1000;
    Arc::clone(&f.store)
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expires_ms = ?2 WHERE id = ?1",
                (f.failed_attempt.as_bytes(), retention),
            )?;
            Ok(())
        })
        .unwrap();
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    f.sweep(UnixMillis(NOW.0 + 2_000));
    let id = f.requests()[0].id;
    let settled = answered(&f, id);
    assert_eq!(
        cached(&f),
        Some(retention),
        "the cache's own 30 days give way to the log's retention"
    );
    let document = f
        .store
        .read(move |c| ai::by_id(c, id))
        .unwrap()
        .analysis
        .unwrap();
    assert_eq!(
        f.store
            .read(move |c| ai::answer(c, f.failed_attempt, UnixMillis(NOW.0 + 4_000)))
            .unwrap(),
        ai::Answer::Analysis {
            document,
            reused: false,
            settled,
            origin: Origin::Automatic,
        }
    );
}

#[test]
fn an_analysis_whose_log_is_already_gone_is_not_cached() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    Arc::clone(&f.store)
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expires_ms = ?2, log_expired_ms = ?2 WHERE id = ?1",
                (f.failed_attempt.as_bytes(), NOW.0 + 1_000),
            )?;
            Ok(())
        })
        .unwrap();
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    f.sweep(UnixMillis(NOW.0 + 2_000));
    let id = f.requests()[0].id;
    answered(&f, id);
    assert_eq!(
        cached(&f),
        None,
        "an answer with no evidence left is not kept"
    );
    assert!(
        f.store
            .read(|c| ai::by_id(c, id))
            .unwrap()
            .analysis
            .is_some(),
        "the request still carries what the member asked for"
    );
    assert_eq!(
        f.store
            .read(move |c| ai::retention(c, f.failed_attempt))
            .unwrap(),
        Some(ai::Retention {
            expires: Some(UnixMillis(NOW.0 + 1_000)),
            expired: true,
        })
    );
}

#[test]
fn a_members_request_keeps_its_own_origin_and_the_sweep_leaves_it_alone() {
    let f = Fixture::new();
    f.finish(f.failed_job, 20, UnixMillis(NOW.0 + 1_000));
    let authority = Authority::Credential {
        principal: Principal::new(f.member, P::READ, None, None),
        stepped_up: false,
    };
    let (tenant, repo, attempt, store) = (f.tenant, f.repo, f.failed_attempt, Arc::clone(&f.store));
    let asked = store
        .writer()
        .write(move |tx| {
            ai::enqueue(
                tx,
                authority,
                tenant,
                repo,
                attempt,
                Provider::Local,
                None,
                Scopes::READ_ONLY,
                NOW,
            )
        })
        .unwrap();
    assert_eq!(asked.origin, Origin::Member);
    f.policy(true, DataPolicy::LocalOnly, Budgets::default());
    assert_eq!(
        f.sweep(UnixMillis(NOW.0 + 2_000)),
        1,
        "the member's request does not stand in for the tenant's own"
    );
    let origins: Vec<Origin> = f.requests().iter().map(|row| row.origin).collect();
    assert_eq!(origins, [Origin::Member, Origin::Automatic]);
}
