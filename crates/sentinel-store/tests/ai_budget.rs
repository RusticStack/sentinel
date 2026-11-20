//! AI budgets, the ledger and the analysis cache (Part 22 Y04).
//!
//! The gate this file proves is the budget's: a request reserves its maximum in one writer
//! transaction before any provider is contacted, so concurrent requests can never be admitted past
//! the month's limit, and a refused one is settled `unavailable` in that same write rather than
//! queued. It also proves the two ways a request stops costing anything — a reservation that
//! expires with its request, and an analysis reused by evidence digest or by failure fingerprint.
//!
//! No provider is involved anywhere: the controller only decides.

use std::sync::{Arc, Barrier};

use sentinel_core::{
    AiRequestId, AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role, Scopes},
};
use sentinel_store::{
    Durability, Error, Store,
    ai::{
        self, Admitted, Budgets, DataPolicy, Deployment, Outcome, Provider, Providers, Reservation,
        Reuse, State, Tenant, Usage,
    },
    auth::{self as authz, Authority, provisioning},
    jobs,
};

const NOW: UnixMillis = UnixMillis(1_700_000_000_000);

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    tenant: TenantId,
    admin: UserId,
    member: UserId,
    repo: RepoId,
    attempt: AttemptId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (tenant, platform, admin, member) =
        (TenantId::new(), UserId::new(), UserId::new(), UserId::new());
    let (repo, run, job, attempt) = (RepoId::new(), RunId::new(), JobId::new(), AttemptId::new());
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
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                    repo_id, released_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5, ?6)",
                (
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [9u8; 16],
                    repo.as_bytes(),
                    NOW.0,
                ),
            )?;
            let mut providers = Providers::NONE;
            providers.insert(Provider::Local);
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
        admin,
        member,
        repo,
        attempt,
    };
    opt_in(&f, Budgets::default());
    f
}

/// The tenant's opt-in, with the budget it is given.
fn opt_in(f: &Fixture, budgets: Budgets) {
    let authority = Authority::Credential {
        principal: Principal::new(f.admin, P::REPOSITORY.union(P::TENANT_ADMIN), None, None),
        stepped_up: true,
    };
    let (tenant, store) = (f.tenant, Arc::clone(&f.store));
    store
        .writer()
        .write(move |tx| {
            ai::set_tenant(
                tx,
                authority,
                tenant,
                Tenant {
                    enabled: true,
                    data_policy: DataPolicy::LocalOnly,
                    budgets,
                    auto_analysis: false,
                },
                NOW,
            )
        })
        .unwrap();
}

/// One request, queued and then claimed: what a reservation is asked of.
fn claimed(f: &Fixture, now: UnixMillis) -> AiRequestId {
    let authority = Authority::Credential {
        principal: Principal::new(f.member, P::READ, None, None),
        stepped_up: false,
    };
    let (tenant, repo, attempt, store) = (f.tenant, f.repo, f.attempt, Arc::clone(&f.store));
    store
        .writer()
        .write(move |tx| {
            let row = ai::enqueue(
                tx,
                authority,
                tenant,
                repo,
                attempt,
                Provider::Local,
                Scopes::READ_ONLY,
                now,
            )?;
            ai::claim(tx, row.id, now)?;
            Ok(row.id)
        })
        .unwrap()
}

fn asked(input: u64, output: u64, cost: u64, digest: u8, fingerprint: u8) -> Reservation {
    Reservation {
        input_tokens: input,
        output_tokens: output,
        cost_micros: cost,
        digest: [digest; 32],
        fingerprint: [fingerprint; 32],
        prompt_version: "analysis-1".into(),
        model: "fake/model".into(),
    }
}

fn reserve(f: &Fixture, id: AiRequestId, asked: &Reservation, now: UnixMillis) -> Admitted {
    let asked = asked.clone();
    Arc::clone(&f.store)
        .writer()
        .write(move |tx| ai::reserve(tx, id, &asked, now))
        .unwrap()
}

/// The stored form of an answer: one `sentinel.ai-analysis/1` claim citing one frame of the fixture's
/// attempt. The store keeps the document whole and never reads inside it; the controller decodes it
/// before it gets here.
fn document(f: &Fixture, claim: &str) -> String {
    format!(
        "{{\"schema\":\"sentinel.ai-analysis/1\",\"summary\":\"the unit step failed\",\
         \"claims\":[{{\"text\":\"{claim}\",\"citations\":[{{\"attempt\":\"{}\",\
         \"evidence\":\"log-1\"}}]}}]}}",
        f.attempt
    )
}

fn settle(f: &Fixture, id: AiRequestId, claim: &str, usage: Usage, now: UnixMillis) {
    let text = document(f, claim);
    Arc::clone(&f.store)
        .writer()
        .write(move |tx| {
            ai::settle(
                tx,
                id,
                Outcome::Completed,
                Some(&text),
                None,
                now,
                Some(usage),
            )
        })
        .unwrap();
}

fn row(f: &Fixture, id: AiRequestId) -> ai::Request {
    f.store.read(move |c| ai::by_id(c, id)).unwrap()
}

fn month(f: &Fixture, now: UnixMillis) -> ai::Month {
    f.store.read(move |c| ai::month(c, f.tenant, now)).unwrap()
}

/// A settled request is charged what the provider reported, and its answer is kept under the key
/// it reserved: the same evidence then costing nothing.
#[test]
fn a_settled_request_is_charged_what_the_provider_reported_and_its_answer_is_reused() {
    let f = fixture();
    let id = claimed(&f, NOW);
    let key = asked(1_000, 500, 9_000, 7, 9);
    assert_eq!(
        reserve(&f, id, &key, NOW),
        Admitted::Reserved {
            expires: UnixMillis(NOW.0 + ai::REQUEST_LIFETIME_MS)
        }
    );
    assert_eq!(
        month(&f, NOW).reserved.tokens(),
        1_500,
        "the maximum is held"
    );
    settle(
        &f,
        id,
        "the unit step failed on an assertion",
        Usage {
            input_tokens: Some(800),
            output_tokens: Some(300),
            cost_micros: Some(4_000),
        },
        UnixMillis(NOW.0 + 1),
    );
    let after = month(&f, NOW);
    assert_eq!(
        (after.settled.input_tokens, after.settled.output_tokens),
        (800, 300),
        "the ledger holds what the provider reported, not the maximum"
    );
    assert_eq!(after.settled.cost_micros, 4_000);
    assert_eq!(after.reserved, ai::Spend::default(), "the hold is released");
    assert_eq!(after.in_flight, 0);
    let settled = row(&f, id);
    assert_eq!(settled.state, State::Settled);
    assert!(!settled.reused);
    assert_eq!(settled.outcome, Some(Outcome::Completed));

    // The same question over the same evidence, asked again: served from the analysis, marked
    // reused, and the month is not charged twice.
    let again = claimed(&f, UnixMillis(NOW.0 + 2));
    let reused = reserve(&f, again, &key, UnixMillis(NOW.0 + 2));
    assert_eq!(
        reused,
        Admitted::Reused {
            analysis: document(&f, "the unit step failed on an assertion"),
            by: Reuse::Evidence,
        }
    );
    let row = row(&f, again);
    assert!(row.reused, "a reused answer is marked as one");
    assert_eq!(row.reason, None);
    let still = month(&f, NOW);
    assert_eq!(
        (still.settled.input_tokens, still.settled.cost_micros),
        (800, 4_000),
        "a reused answer costs nothing"
    );
}

/// A component the provider did not report settles at what the reservation held: an unaccounted
/// call is charged its maximum, never zero, and never more than it reserved.
#[test]
fn an_unreported_component_settles_at_the_reserved_maximum() {
    let f = fixture();
    let id = claimed(&f, NOW);
    reserve(&f, id, &asked(1_000, 500, 9_000, 7, 9), NOW);
    settle(
        &f,
        id,
        "an answer",
        Usage {
            input_tokens: Some(700),
            output_tokens: None,
            cost_micros: Some(90_000),
        },
        UnixMillis(NOW.0 + 1),
    );
    let after = month(&f, NOW);
    assert_eq!(after.settled.input_tokens, 700);
    assert_eq!(
        after.settled.output_tokens, 500,
        "unreported settles at the hold"
    );
    assert_eq!(after.settled.cost_micros, 9_000, "and never above it");
}

/// A reservation nobody settled expires with its request: the sweep deletes the hold and ends the
/// row, so a killed AI process cannot keep a tenant's month spent.
#[test]
fn a_reservation_nobody_settled_expires_with_its_request_and_frees_the_budget() {
    let f = fixture();
    opt_in(
        &f,
        Budgets {
            monthly_tokens: 1_500,
            ..Budgets::default()
        },
    );
    let id = claimed(&f, NOW);
    assert!(matches!(
        reserve(&f, id, &asked(1_000, 500, 9_000, 7, 9), NOW),
        Admitted::Reserved { .. }
    ));
    // The month is spent, so a second request of the same size is refused rather than queued.
    let second = claimed(&f, NOW);
    let refused = reserve(&f, second, &asked(1_000, 500, 9_000, 8, 8), NOW);
    let Admitted::Refused { reason } = refused else {
        panic!("a full month admitted a second request: {refused:?}");
    };
    assert!(reason.starts_with("budget: "), "{reason}");
    let refused_row = row(&f, second);
    assert_eq!(refused_row.state, State::Settled);
    assert_eq!(refused_row.outcome, Some(Outcome::Unavailable));
    assert_eq!(refused_row.reason.as_deref(), Some(reason.as_str()));

    // Past the deadline the hold is gone, and the same request fits again.
    let later = UnixMillis(NOW.0 + ai::REQUEST_LIFETIME_MS + 1);
    f.store
        .writer()
        .write(move |tx| ai::sweep(tx, later, 32))
        .unwrap();
    let expired = row(&f, id);
    assert_eq!(expired.state, State::Settled, "the sweep ended the request");
    assert_eq!(expired.outcome, Some(Outcome::Unavailable));
    let freed = month(&f, later);
    assert_eq!(freed.reserved.tokens(), 0, "the hold outlived its request");
    assert_eq!(
        freed.settled.tokens(),
        0,
        "a request nobody answered costs nothing"
    );
    let third = claimed(&f, later);
    assert!(matches!(
        reserve(&f, third, &asked(1_000, 500, 9_000, 10, 10), later),
        Admitted::Reserved { .. }
    ));
}

/// The gate: concurrent requests never take the month past its limit, and every one that does not
/// fit is refused immediately — settled in the write that refused it, with no provider contacted.
#[test]
fn concurrent_requests_never_exceed_the_budget_and_refusals_are_immediate() {
    let f = fixture();
    let budgets = Budgets {
        monthly_tokens: 8_000,
        concurrency: 64,
        ..Budgets::default()
    };
    opt_in(&f, budgets);
    let threads = 24usize;
    let ids: Vec<AiRequestId> = (0..threads).map(|_| claimed(&f, NOW)).collect();
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = ids
        .into_iter()
        .enumerate()
        .map(|(at, id)| {
            let store = Arc::clone(&f.store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let asked = asked(
                    600,
                    400,
                    1_000,
                    u8::try_from(at).unwrap(),
                    u8::try_from(at).unwrap(),
                );
                barrier.wait();
                store
                    .writer()
                    .write(move |tx| Ok((id, ai::reserve(tx, id, &asked, NOW))))
                    .unwrap()
            })
        })
        .collect();
    let mut admitted = Vec::new();
    let mut refused = Vec::new();
    for handle in handles {
        let (id, outcome) = handle.join().unwrap();
        match outcome.expect("a concurrent reservation errored") {
            Admitted::Reserved { .. } => admitted.push(id),
            Admitted::Refused { reason } => refused.push((id, reason)),
            Admitted::Reused { .. } => panic!("nothing was cached"),
        }
    }
    assert_eq!(
        admitted.len(),
        8,
        "8000 tokens fit eight 1000-token requests"
    );
    assert_eq!(refused.len(), threads - 8);
    let held = month(&f, NOW);
    assert!(
        held.reserved.tokens() <= budgets.monthly_tokens,
        "held {} tokens against a limit of {}",
        held.reserved.tokens(),
        budgets.monthly_tokens
    );
    assert_eq!(held.in_flight, 8);
    // A refusal is immediate: the row ended in the same write, so nothing is waiting to expire.
    for (id, reason) in refused {
        let row = row(&f, id);
        assert_eq!(row.state, State::Settled, "{reason}");
        assert_eq!(row.outcome, Some(Outcome::Unavailable));
        assert!(
            row.reason
                .as_deref()
                .unwrap_or_default()
                .starts_with("budget: ")
        );
    }
}

/// Per-request caps are refused before anything is held, each naming the field it is over.
#[test]
fn a_request_past_a_per_request_cap_is_refused_and_holds_nothing() {
    let f = fixture();
    opt_in(
        &f,
        Budgets {
            max_input_tokens: 1_000,
            max_output_tokens: 400,
            max_cost_micros: 5_000,
            ..Budgets::default()
        },
    );
    for (key, over) in [
        (asked(1_001, 400, 5_000, 1, 1), "a prompt of 1001 tokens"),
        (asked(1_000, 401, 5_000, 2, 2), "an output of 401 tokens"),
        (asked(1_000, 400, 5_001, 3, 3), "a request of 5001 micros"),
    ] {
        let id = claimed(&f, NOW);
        let Admitted::Refused { reason } = reserve(&f, id, &key, NOW) else {
            panic!("{over} fitted a cap it is over");
        };
        assert!(reason.starts_with("per_request: "), "{reason}");
        assert!(reason.contains(over), "{reason} does not name {over}");
        assert_eq!(month(&f, NOW).reserved, ai::Spend::default());
        assert_eq!(row(&f, id).state, State::Settled);
    }
}

/// The concurrency limit refuses a request while the tenant's own requests hold its slots.
#[test]
fn the_concurrency_limit_refuses_a_request_while_requests_are_in_flight() {
    let f = fixture();
    opt_in(
        &f,
        Budgets {
            concurrency: 2,
            ..Budgets::default()
        },
    );
    for _ in 0..2 {
        let id = claimed(&f, NOW);
        assert!(matches!(
            reserve(&f, id, &asked(800, 200, 1_000, 1, 1), NOW),
            Admitted::Reserved { .. }
        ));
    }
    let third = claimed(&f, NOW);
    let Admitted::Refused { reason } = reserve(&f, third, &asked(800, 200, 1_000, 2, 2), NOW)
    else {
        panic!("a third request was admitted past a limit of two");
    };
    assert!(reason.starts_with("concurrency: 2 requests"), "{reason}");
    assert_eq!(month(&f, NOW).in_flight, 2);
}

/// A rerun of the same failure reuses the earlier analysis, and a different prompt version or model
/// does not: the key is all three, and the fingerprint is what survives a new attempt.
#[test]
fn a_failure_fingerprint_is_reused_across_reruns_but_a_new_prompt_or_model_is_not() {
    let f = fixture();
    let first = claimed(&f, NOW);
    reserve(&f, first, &asked(1_000, 500, 9_000, 1, 42), NOW);
    settle(
        &f,
        first,
        "the unit step failed: left != right",
        Usage::default(),
        UnixMillis(NOW.0 + 1),
    );

    // Another attempt, another evidence digest, the same failure: reused, and marked so.
    let rerun = claimed(&f, UnixMillis(NOW.0 + 2));
    let reused = reserve(
        &f,
        rerun,
        &asked(1_000, 500, 9_000, 2, 42),
        UnixMillis(NOW.0 + 2),
    );
    assert_eq!(
        reused,
        Admitted::Reused {
            analysis: document(&f, "the unit step failed: left != right"),
            by: Reuse::Fingerprint,
        }
    );
    assert!(row(&f, rerun).reused);

    // A new prompt version is a new question: nothing cached answers it.
    let versioned = claimed(&f, UnixMillis(NOW.0 + 3));
    let mut other = asked(1_000, 500, 9_000, 2, 42);
    other.prompt_version = "analysis-2".into();
    assert!(matches!(
        reserve(&f, versioned, &other, UnixMillis(NOW.0 + 3)),
        Admitted::Reserved { .. }
    ));

    // And so is another model.
    let modelled = claimed(&f, UnixMillis(NOW.0 + 4));
    let mut other = asked(1_000, 500, 9_000, 2, 42);
    other.model = "other/model".into();
    assert!(matches!(
        reserve(&f, modelled, &other, UnixMillis(NOW.0 + 4)),
        Admitted::Reserved { .. }
    ));
}

/// A different failure on the same repository is not reused: the fingerprint has to match too.
#[test]
fn a_different_failure_is_not_reused() {
    let f = fixture();
    let first = claimed(&f, NOW);
    reserve(&f, first, &asked(1_000, 500, 9_000, 1, 42), NOW);
    settle(
        &f,
        first,
        "the unit step failed",
        Usage::default(),
        UnixMillis(NOW.0 + 1),
    );
    let other = claimed(&f, UnixMillis(NOW.0 + 2));
    assert!(matches!(
        reserve(
            &f,
            other,
            &asked(1_000, 500, 9_000, 2, 43),
            UnixMillis(NOW.0 + 2)
        ),
        Admitted::Reserved { .. }
    ));
}

/// A disable takes the tenant's analyses and its holds with its queue, so a tenant that is turned
/// off keeps no answer it paid for and holds no budget it cannot use.
#[test]
fn a_disable_takes_the_analyses_and_the_reservations_with_the_queue() {
    let f = fixture();
    let id = claimed(&f, NOW);
    reserve(&f, id, &asked(1_000, 500, 9_000, 1, 42), NOW);
    settle(&f, id, "an answer", Usage::default(), UnixMillis(NOW.0 + 1));
    let live = claimed(&f, UnixMillis(NOW.0 + 2));
    reserve(
        &f,
        live,
        &asked(1_000, 500, 9_000, 2, 42),
        UnixMillis(NOW.0 + 2),
    );
    let authority = Authority::Credential {
        principal: Principal::new(f.admin, P::REPOSITORY.union(P::TENANT_ADMIN), None, None),
        stepped_up: true,
    };
    let tenant = f.tenant;
    let counts: (i64, i64, i64) = Arc::clone(&f.store)
        .writer()
        .write(move |tx| {
            ai::set_tenant(
                tx,
                authority,
                tenant,
                Tenant {
                    enabled: false,
                    data_policy: DataPolicy::LocalOnly,
                    budgets: Budgets::default(),
                    auto_analysis: false,
                },
                NOW,
            )?;
            let count = |table: &str| -> Result<i64, Error> {
                Ok(tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
            };
            Ok((
                count("ai_requests")?,
                count("ai_reservations")?,
                count("ai_analyses")?,
            ))
        })
        .unwrap();
    assert_eq!(counts, (0, 0, 0), "a disable left something behind");
    // The ledger is what was spent and stays: a re-enable does not refund the month.
    assert_eq!(month(&f, NOW).settled.tokens(), 1_500);
}

/// A reservation is only askable of a claimed request, and only once.
#[test]
fn a_reservation_needs_a_claimed_request_and_settles_once() {
    let f = fixture();
    let queued = {
        let authority = Authority::Credential {
            principal: Principal::new(f.member, P::READ, None, None),
            stepped_up: false,
        };
        let (tenant, repo, attempt) = (f.tenant, f.repo, f.attempt);
        Arc::clone(&f.store)
            .writer()
            .write(move |tx| {
                ai::enqueue(
                    tx,
                    authority,
                    tenant,
                    repo,
                    attempt,
                    Provider::Local,
                    Scopes::READ_ONLY,
                    NOW,
                )
            })
            .unwrap()
            .id
    };
    let refused = Arc::clone(&f.store)
        .writer()
        .write(move |tx| ai::reserve(tx, queued, &asked(100, 100, 100, 1, 1), NOW));
    assert!(matches!(refused, Err(Error::Conflict)), "{refused:?}");

    let id = claimed(&f, NOW);
    reserve(&f, id, &asked(100, 100, 100, 1, 1), NOW);
    settle(&f, id, "an answer", Usage::default(), UnixMillis(NOW.0 + 1));
    let twice = Arc::clone(&f.store)
        .writer()
        .write(move |tx| ai::reserve(tx, id, &asked(100, 100, 100, 1, 1), UnixMillis(NOW.0 + 2)));
    assert!(matches!(twice, Err(Error::Conflict)), "{twice:?}");
}

/// The month is the UTC calendar month of the reservation, so a ledger never mixes two months.
#[test]
fn the_ledger_is_keyed_by_the_utc_calendar_month() {
    assert_eq!(ai::month_of(0), 197001);
    assert_eq!(ai::month_of(1_700_000_000_000), 202311);
    assert_eq!(ai::month_of(1_735_689_599_000), 202412);
    assert_eq!(ai::month_of(1_735_689_600_000), 202501);

    let f = fixture();
    let id = claimed(&f, NOW);
    reserve(&f, id, &asked(1_000, 500, 9_000, 1, 1), NOW);
    settle(&f, id, "an answer", Usage::default(), UnixMillis(NOW.0 + 1));
    let next = UnixMillis(1_735_689_600_000);
    let later = month(&f, next);
    assert_eq!(later.month, 202501);
    assert_eq!(
        later.settled,
        ai::Spend::default(),
        "another month's ledger"
    );
    assert_eq!(month(&f, NOW).settled.tokens(), 1_500);
}
