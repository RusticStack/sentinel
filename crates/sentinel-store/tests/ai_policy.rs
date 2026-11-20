//! AI assistance policy (Part 22 Y01): off on both sides until two administrators say
//! otherwise, the tenant's change needs a live step-up and is audited, and the gate every
//! request passes reads the policy at the moment of the request, so a disable applies at once.
//! No test here, and no code in the workspace yet, reaches a provider: there is no provider
//! client until Y03, which is why a disabled tenant provably has no request in flight or queued.

use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role},
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
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (tenant, platform, admin, member) =
        (TenantId::new(), UserId::new(), UserId::new(), UserId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", NOW)?;
            provisioning::insert_human(tx, platform, "Root", true, NOW)?;
            provisioning::insert_human(tx, admin, "Ada", false, NOW)?;
            provisioning::insert_human(tx, member, "Mia", false, NOW)?;
            let root = Principal::new(platform, P::ALL, None, None);
            auth::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, tenant, member, Role::Reader)
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        platform,
        admin,
        member,
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

/// Y03 adds the durable request queue and the consumer that fills it. Until then nothing can
/// store a request, so a disabled tenant provably has none queued; this test is the tripwire
/// that makes Y03 prove its disable deletes those rows in the same transaction.
#[test]
fn no_ai_request_can_be_queued_yet() {
    let f = fixture();
    let queues: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'ai%'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(
        queues, 0,
        "an AI request queue exists: Y03 must replace this test with one proving a disable \
         deletes its rows in the same transaction"
    );
    assert_eq!(
        f.store.read(|c| ai::effective(c, f.tenant)).unwrap(),
        (Providers::NONE, None)
    );
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
