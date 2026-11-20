//! AI assistance policy (Part 22 Y01): off on both sides until two administrators say
//! otherwise, the tenant's change needs a live step-up and is audited, and the gate every
//! request passes reads the policy at the moment of the request, so a disable applies at once.
//! No test here, and no code in the controller, reaches a provider: the provider client lives in
//! `ai/`, and these tests cover the queue a disable has to delete — Y03's own half of the promise.

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role, Scopes},
};
use sentinel_store::{
    Durability, Error, Store,
    ai::{self, DataPolicy, Deployment, Provider, Providers, Tenant},
    auth::{self, Authority, provisioning},
    jobs,
    local_auth::{self, Event},
};

const NOW: UnixMillis = UnixMillis(1_000_000);

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    platform: UserId,
    admin: UserId,
    member: UserId,
    /// The repository and attempt a request is about: what the queue tests need and the policy
    /// tests do not.
    attempt: AttemptId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
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
            auth::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, tenant, member, Role::Reader)?;
            auth::create_repo(tx, root, tenant, repo, "app", NOW)?;
            auth::set_repo_grant(tx, root, repo, member, P::READ)?;
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
            Ok(())
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        platform,
        admin,
        member,
        attempt,
    }
}

fn authority(user: UserId, permissions: P, stepped_up: bool) -> Authority {
    Authority::Credential {
        principal: Principal::new(user, permissions, None, None),
        stepped_up,
    }
}

fn tenant_administrator(f: &Fixture, stepped_up: bool) -> Authority {
    authority(f.admin, P::REPOSITORY.union(P::TENANT_ADMIN), stepped_up)
}

/// Why a policy change was refused, so a test names the refusal it expects.
fn refusal(result: Result<(), Error>) -> &'static str {
    match result {
        Ok(()) => "accepted",
        Err(Error::Forbidden) => "forbidden",
        Err(Error::StepUpRequired) => "step-up",
        Err(_) => "error",
    }
}

fn set_deployment(
    f: &Fixture,
    authority: Authority,
    providers: &[Provider],
    enabled: bool,
) -> Result<(), Error> {
    let mut allow = Providers::NONE;
    for &provider in providers {
        allow.insert(provider);
    }
    f.store.writer().write(move |tx| {
        ai::set_deployment(
            tx,
            authority,
            Deployment {
                enabled,
                providers: allow,
            },
            NOW,
        )
    })
}

fn set_tenant(
    f: &Fixture,
    authority: Authority,
    enabled: bool,
    policy: DataPolicy,
) -> Result<(), Error> {
    let tenant = f.tenant;
    f.store.writer().write(move |tx| {
        ai::set_tenant(
            tx,
            authority,
            tenant,
            Tenant {
                enabled,
                data_policy: policy,
            },
            NOW,
        )
    })
}

fn admit(f: &Fixture, provider: Provider) -> Option<DataPolicy> {
    f.store.read(|c| ai::admit(c, f.tenant, provider)).unwrap()
}

/// The bundle's gate: `admit` for whichever provider the tenant may use.
fn permits(f: &Fixture) -> bool {
    f.store.read(|c| ai::permits(c, f.tenant)).unwrap()
}

fn audit(f: &Fixture) -> Vec<Event> {
    f.store
        .read(|c| local_auth::audit_page(c, None, 100))
        .unwrap()
        .into_iter()
        .map(|record| record.event)
        .collect()
}

#[test]
fn a_fresh_deployment_is_off_and_admits_no_provider() {
    let f = fixture();
    assert_eq!(f.store.read(ai::deployment).unwrap(), Deployment::default());
    assert_eq!(f.store.read(|c| ai::tenant(c, f.tenant)).unwrap(), None);
    for provider in Provider::ALL {
        assert_eq!(admit(&f, provider), None, "{}", provider.as_str());
    }
    // The bundle gate is the same reading without a provider: a tenant that could send nothing
    // has no evidence bundle either (Y02).
    assert!(!permits(&f));
}

/// The tripwire Y01 left for Y03, now the thing it promised: the request queue exists, a disable
/// deletes every row of it and revokes the delegation it minted, in the same write that turns the
/// tenant off — and a tenant that is off cannot queue a row at all.
#[test]
fn a_disable_deletes_the_queue_and_revokes_its_delegation_in_one_transaction() {
    let f = fixture();
    let member = f.member;
    let attempt = f.attempt;
    let tenant = f.tenant;
    let store = &f.store;

    assert_eq!(queued_rows(store), 0, "a fresh deployment has no request");
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::Local],
        true,
    )
    .unwrap();
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        true,
        DataPolicy::LocalOnly,
    )
    .unwrap();

    let enqueue = |permissions: P| {
        store.writer().write(move |tx| {
            ai::enqueue(
                tx,
                Authority::Credential {
                    principal: Principal::new(member, permissions, None, None),
                    stepped_up: false,
                },
                tenant,
                repo_of(tx, tenant)?,
                attempt,
                Provider::Local,
                Scopes::READ_ONLY,
                NOW,
            )
        })
    };
    let row = enqueue(P::READ).expect("a member who can read may ask");
    assert_eq!(row.state, ai::State::Queued);
    assert_eq!(row.data_policy, DataPolicy::LocalOnly);
    assert_eq!(queued_rows(store), 1);

    // A provider outside what the tenant's policy allows is refused, whatever the deployment
    // allow-list says.
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::Local, Provider::OpenRouter],
        true,
    )
    .unwrap();
    assert!(matches!(
        store.writer().write({
            let tenant = f.tenant;
            let attempt = f.attempt;
            move |tx| {
                ai::enqueue(
                    tx,
                    Authority::Credential {
                        principal: Principal::new(member, P::READ, None, None),
                        stepped_up: false,
                    },
                    tenant,
                    repo_of(tx, tenant)?,
                    attempt,
                    Provider::OpenRouter,
                    Scopes::READ_ONLY,
                    NOW,
                )
            }
        }),
        Err(Error::Forbidden)
    ));
    assert_eq!(queued_rows(store), 1, "a refused request stores nothing");

    // The service claims it, which mints the delegation; the disable then has both to deal with.
    let claimed = store
        .writer()
        .write(move |tx| ai::claim(tx, row.id, UnixMillis(NOW.0 + 1)))
        .expect("a queued request is claimable");
    let delegation = claimed.token;
    assert_eq!(queued_rows(store), 1, "a claimed row is still a row");

    set_tenant(
        &f,
        tenant_administrator(&f, true),
        false,
        DataPolicy::LocalOnly,
    )
    .unwrap();
    assert_eq!(queued_rows(store), 0, "the disable deleted the queue");
    let revoked: bool = store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT revoked_ms IS NOT NULL FROM api_tokens WHERE id = ?1",
                [delegation.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(revoked, "the delegation it minted was revoked with it");

    // And with the tenant off, nothing can be queued at all.
    let refused = store.writer().write(move |tx| {
        ai::enqueue(
            tx,
            Authority::Credential {
                principal: Principal::new(member, P::READ, None, None),
                stepped_up: false,
            },
            f.tenant,
            repo_of(tx, f.tenant)?,
            attempt,
            Provider::Local,
            Scopes::READ_ONLY,
            NOW,
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

fn queued_rows(store: &Store) -> i64 {
    store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM ai_requests", [], |r| r.get(0))?))
        .unwrap()
}

/// The fixture repository, read through the tenant it belongs to.
fn repo_of(c: &rusqlite::Connection, tenant: TenantId) -> Result<RepoId, Error> {
    let mut statement = c.prepare("SELECT id FROM repos WHERE tenant_id = ?1")?;
    let bytes: [u8; 16] = statement.query_row([tenant.as_bytes()], |r| r.get(0))?;
    RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))
}

#[test]
fn the_allow_list_is_set_only_by_a_platform_administrator_with_a_step_up() {
    let f = fixture();
    assert_eq!(
        refusal(set_deployment(
            &f,
            authority(f.admin, P::TENANT_ADMIN, true),
            &[Provider::Local],
            true
        )),
        "forbidden",
        "a tenant administrator allowed a deployment provider"
    );
    assert_eq!(
        refusal(set_deployment(
            &f,
            authority(f.platform, P::ALL, false),
            &[Provider::Local],
            true
        )),
        "step-up",
        "a deployment policy changed without a step-up"
    );
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::Local],
        true,
    )
    .unwrap();
    let deployment = f.store.read(ai::deployment).unwrap();
    assert!(deployment.enabled);
    assert_eq!(
        deployment.providers.list().collect::<Vec<_>>(),
        [Provider::Local]
    );
    assert_eq!(audit(&f).first(), Some(&Event::AiPolicyChanged));
}

#[test]
fn a_tenant_opts_in_only_with_a_step_up_and_the_deployment_allowing_it() {
    let f = fixture();
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::OpenRouter],
        true,
    )
    .unwrap();
    assert_eq!(
        refusal(set_tenant(
            &f,
            tenant_administrator(&f, false),
            true,
            DataPolicy::ZeroRetention
        )),
        "step-up",
        "a tenant opted in without a step-up"
    );
    assert_eq!(
        refusal(set_tenant(
            &f,
            authority(f.member, P::READ, true),
            true,
            DataPolicy::ZeroRetention
        )),
        "forbidden",
        "a reader changed the tenant's policy"
    );
    assert_eq!(
        f.store.read(|c| ai::tenant(c, f.tenant)).unwrap(),
        None,
        "a refused change left a row"
    );
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        true,
        DataPolicy::ZeroRetention,
    )
    .unwrap();
    assert_eq!(
        f.store.read(|c| ai::tenant(c, f.tenant)).unwrap(),
        Some(Tenant {
            enabled: true,
            data_policy: DataPolicy::ZeroRetention,
        })
    );
    assert_eq!(
        admit(&f, Provider::OpenRouter),
        Some(DataPolicy::ZeroRetention)
    );
    assert_eq!(
        admit(&f, Provider::Local),
        None,
        "a provider outside the allow list"
    );
    assert_eq!(audit(&f).first(), Some(&Event::TenantAiPolicyChanged));
}

#[test]
fn enabling_a_tenant_needs_the_deployment_to_allow_ai() {
    let f = fixture();
    assert_eq!(
        refusal(set_tenant(
            &f,
            tenant_administrator(&f, true),
            true,
            DataPolicy::ProviderTerms
        )),
        "forbidden",
        "a tenant enabled AI while the deployment forbids it"
    );
    set_deployment(&f, authority(f.platform, P::ALL, true), &[], true).unwrap();
    assert_eq!(
        refusal(set_tenant(
            &f,
            tenant_administrator(&f, true),
            true,
            DataPolicy::ProviderTerms
        )),
        "forbidden",
        "a tenant enabled AI with an empty allow list"
    );
    assert_eq!(f.store.read(|c| ai::tenant(c, f.tenant)).unwrap(), None);
}

#[test]
fn local_only_never_admits_a_hosted_provider() {
    let f = fixture();
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::Local, Provider::Anthropic],
        true,
    )
    .unwrap();
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        true,
        DataPolicy::LocalOnly,
    )
    .unwrap();
    let (providers, policy) = f.store.read(|c| ai::effective(c, f.tenant)).unwrap();
    assert_eq!(policy, Some(DataPolicy::LocalOnly));
    assert_eq!(providers.list().collect::<Vec<_>>(), [Provider::Local]);
    assert_eq!(admit(&f, Provider::Local), Some(DataPolicy::LocalOnly));
    assert_eq!(admit(&f, Provider::Anthropic), None);
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        true,
        DataPolicy::ProviderTerms,
    )
    .unwrap();
    assert_eq!(
        admit(&f, Provider::Anthropic),
        Some(DataPolicy::ProviderTerms)
    );
}

#[test]
fn disabling_takes_effect_at_the_next_request_and_is_audited() {
    let f = fixture();
    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::OpenAi],
        true,
    )
    .unwrap();
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        true,
        DataPolicy::ZeroRetention,
    )
    .unwrap();
    assert_eq!(admit(&f, Provider::OpenAi), Some(DataPolicy::ZeroRetention));
    assert!(permits(&f));
    let before = audit(&f).len();
    set_tenant(
        &f,
        tenant_administrator(&f, true),
        false,
        DataPolicy::ZeroRetention,
    )
    .unwrap();
    assert_eq!(
        admit(&f, Provider::OpenAi),
        None,
        "the disable was not immediate"
    );
    assert!(!permits(&f), "a disabled tenant kept its bundle gate open");
    assert_eq!(
        f.store.read(|c| ai::tenant(c, f.tenant)).unwrap(),
        Some(Tenant {
            enabled: false,
            data_policy: DataPolicy::ZeroRetention,
        }),
        "the tenant's data policy is kept for the next opt-in"
    );
    let after = audit(&f);
    assert_eq!(after.len(), before + 1);
    assert_eq!(after.first(), Some(&Event::TenantAiPolicyChanged));

    set_deployment(
        &f,
        authority(f.platform, P::ALL, true),
        &[Provider::Local],
        false,
    )
    .unwrap();
    assert_eq!(admit(&f, Provider::Local), None);
}

#[test]
fn a_data_policy_outside_the_three_is_refused_by_the_row_itself() {
    let f = fixture();
    let tenant = f.tenant;
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            Ok(tx.execute(
                "INSERT INTO tenant_ai(tenant_id, enabled, data_policy, updated_ms)
                 VALUES (?1, 1, 3, ?2)",
                rusqlite::params![tenant.as_bytes(), NOW.0],
            )?)
        })
        .unwrap_err();
    assert!(matches!(refused, Error::Sqlite(_)), "{refused:?}");
}
