//! A platform administrator has no ambient data access: granting it needs fresh step-up and an audited reason.

use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
};

const NOW: UnixMillis = UnixMillis(1_000_000);

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    admin: UserId,
    dev: UserId,
    stranger: UserId,
    tenant: TenantId,
    repo: RepoId,
}

fn principal(user: UserId, platform: bool) -> Principal {
    let base = P::REPOSITORY.union(P::TENANT_ADMIN);
    Principal::new(
        user,
        if platform {
            base.union(P::PLATFORM_ADMIN)
        } else {
            base
        },
        None,
        None,
    )
}

fn stepped(user: UserId, platform: bool) -> Authority {
    Authority::Credential {
        principal: principal(user, platform),
        stepped_up: true,
    }
}

fn unstepped(user: UserId, platform: bool) -> Authority {
    Authority::credential(principal(user, platform))
}

fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        admin: UserId::new(),
        dev: UserId::new(),
        stranger: UserId::new(),
        tenant: TenantId::new(),
        repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, i.root, "Root", true, NOW)?;
            for (user, name) in [(i.admin, "Admin"), (i.dev, "Dev"), (i.stranger, "Stranger")] {
                provisioning::insert_human(tx, user, name, false, NOW)?;
            }
            let root = principal(i.root, true);
            auth::create_namespace(
                tx,
                root,
                i.tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            auth::set_membership(tx, root, i.tenant, i.admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, i.tenant, i.dev, Role::Reader)?;
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            for (user, name) in [(i.dev, "dev"), (i.stranger, "stranger")] {
                tx.execute(
                    "INSERT INTO local_credentials(user_id, username, phc, updated_ms)
                     VALUES (?1, ?2, 'xxxxxxxxxxxxxxxxxxxx', 0)",
                    rusqlite::params![user.as_bytes(), name],
                )?;
            }
            Ok(())
        })
        .unwrap();
    (dir, store, i)
}

fn set_member(
    store: &Store,
    i: Ids,
    authority: Authority,
    user: UserId,
    role: Role,
    reason: Option<&str>,
) -> Result<(), Error> {
    let reason = reason.map(str::to_owned);
    store.writer().write(move |tx| {
        auth::set_membership_as(tx, authority, i.tenant, user, role, reason.as_deref())
    })
}

fn grant(
    store: &Store,
    i: Ids,
    authority: Authority,
    user: UserId,
    reason: Option<&str>,
) -> Result<(), Error> {
    let reason = reason.map(str::to_owned);
    store.writer().write(move |tx| {
        auth::set_repo_grant_as(
            tx,
            authority,
            i.repo,
            user,
            P::READ.union(P::RUN),
            reason.as_deref(),
        )
    })
}

#[test]
fn a_tenant_administrator_changes_membership_without_a_proof_or_a_reason() {
    let (_dir, store, i) = fixture();
    set_member(
        &store,
        i,
        unstepped(i.admin, false),
        i.dev,
        Role::Operator,
        None,
    )
    .unwrap();
    grant(&store, i, unstepped(i.admin, false), i.dev, None).unwrap();
    assert!(matches!(
        set_member(
            &store,
            i,
            stepped(i.dev, false),
            i.dev,
            Role::TenantAdmin,
            None
        ),
        Err(Error::Forbidden)
    ));
}

#[test]
fn a_platform_administrator_cannot_grant_themselves_access_without_proof_and_reason() {
    let (_dir, store, i) = fixture();
    for reason in [None, Some("incident 7")] {
        assert!(matches!(
            set_member(
                &store,
                i,
                unstepped(i.root, true),
                i.root,
                Role::TenantAdmin,
                reason
            ),
            Err(Error::StepUpRequired)
        ));
        assert!(matches!(
            grant(&store, i, unstepped(i.root, true), i.root, reason),
            Err(Error::StepUpRequired)
        ));
    }
    let long = "x".repeat(101);
    for reason in [None, Some(""), Some(long.as_str())] {
        assert!(matches!(
            set_member(
                &store,
                i,
                stepped(i.root, true),
                i.root,
                Role::TenantAdmin,
                reason
            ),
            Err(Error::InvalidInput("reason"))
        ));
    }
    let member: bool = store
        .read(|c| {
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND user_id = ?2)",
                rusqlite::params![i.tenant.as_bytes(), i.root.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(!member);
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_ne!(audit[0].event, Event::PlatformOverride);
}

#[test]
fn an_accepted_override_is_audited_with_its_reason_and_fails_closed_for_host_local() {
    let (_dir, store, i) = fixture();
    set_member(
        &store,
        i,
        stepped(i.root, true),
        i.root,
        Role::TenantAdmin,
        Some("incident 7"),
    )
    .unwrap();
    let audit = store.read(|c| local_auth::recent_audit(c, 3)).unwrap();
    assert_eq!(audit[0].event, Event::MembershipSet);
    assert_eq!(audit[1].event, Event::MemberAdded);
    assert_eq!(audit[2].event, Event::PlatformOverride);
    assert_eq!(audit[2].actor, Some(i.root));
    assert_eq!(audit[2].detail.as_deref(), Some("incident 7"));
    grant(&store, i, unstepped(i.root, true), i.root, None).unwrap();
    assert!(matches!(
        set_member(&store, i, Authority::HostLocal, i.dev, Role::Reader, None),
        Err(Error::Forbidden)
    ));
}

#[test]
fn sign_in_names_resolve_only_among_the_tenants_members() {
    let (_dir, store, i) = fixture();
    let resolve = |text: &str| store.read(|c| auth::resolve_member(c, i.tenant, text));
    assert_eq!(resolve("dev").unwrap(), i.dev);
    assert!(matches!(resolve("stranger"), Err(Error::NotFound)));
    assert!(matches!(resolve("nobody"), Err(Error::NotFound)));
    assert_eq!(resolve(&i.stranger.to_string()).unwrap(), i.stranger);
    set_member(
        &store,
        i,
        unstepped(i.admin, false),
        i.stranger,
        Role::Reader,
        None,
    )
    .unwrap();
    assert_eq!(resolve("stranger").unwrap(), i.stranger);
}

#[test]
fn adding_a_non_member_is_audited_apart_from_changing_a_member() {
    let (_dir, store, i) = fixture();
    let admin = unstepped(i.admin, false);
    set_member(&store, i, admin, i.stranger, Role::Reader, None).unwrap();
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[0].event, Event::MembershipSet);
    assert_eq!(audit[1].event, Event::MemberAdded);
    assert_eq!(audit[1].actor, Some(i.admin));
    assert_eq!(audit[1].subject, Some(i.stranger));
    set_member(&store, i, admin, i.stranger, Role::Operator, None).unwrap();
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[0].event, Event::MembershipSet);
    assert_ne!(audit[1].event, Event::MemberAdded);
}

/// Everything an administrator tries on an id that is not a member: the answer and the rows touched.
fn probe(store: &Store, i: Ids, target: UserId, adding: bool) -> Vec<Result<(), Error>> {
    let admin = stepped(i.admin, false);
    let mut results = Vec::new();
    if adding {
        results.push(set_member(store, i, admin, target, Role::Reader, None));
    }
    let remove = store.writer().write(move |tx| {
        auth::remove_membership(
            tx,
            principal(i.admin, false),
            i.tenant,
            target,
            UnixMillis(NOW.0 + 5),
        )
    });
    results.push(remove);
    results.push(grant(store, i, admin, target, None));
    results
}

fn counts(store: &Store) -> (i64, i64, i64) {
    store
        .read(|c| {
            let one = |sql: &str| c.query_row(sql, [], |r| r.get::<_, i64>(0));
            Ok((
                one("SELECT COUNT(*) FROM memberships")?,
                one("SELECT COUNT(*) FROM repo_grants")?,
                one("SELECT COALESCE(MAX(seq), 0) FROM auth_audit")?,
            ))
        })
        .unwrap()
}

fn same_refusal(results: &[Result<(), Error>], expected: fn(&Error) -> bool) {
    for result in results {
        let error = result.as_ref().expect_err("a non-member is never changed");
        assert!(expected(error), "{error:?}");
    }
}

#[test]
fn ids_that_name_nobody_a_member_or_an_inactive_account_are_refused_alike() {
    let (_dir, store, i) = fixture();
    let inactive = UserId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, inactive, "Gone", false, NOW)?;
            tx.execute(
                "UPDATE users SET active = 0 WHERE id = ?1",
                [inactive.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    // An existing active person who is not a member is added by the add itself, so the add is probed only
    // for ids that name nobody usable; removal and a repository grant treat every other id the same way.
    let before = counts(&store);
    for target in [UserId::new(), inactive] {
        let results = probe(&store, i, target, true);
        same_refusal(&results, |e| matches!(e, Error::NotFound));
    }
    let results = probe(&store, i, i.stranger, false);
    same_refusal(&results, |e| matches!(e, Error::NotFound));
    // Refusals write nothing: no membership, grant or audit row differs between the three kinds of id.
    assert_eq!(counts(&store), before);
}

#[test]
fn a_github_backed_tenant_refuses_every_id_but_its_own_service_accounts_alike() {
    let (_dir, store, i) = fixture();
    let bot = UserId::new();
    let foreign_bot = UserId::new();
    let elsewhere = TenantId::new();
    let inactive = UserId::new();
    store
        .writer()
        .write(move |tx| {
            let root = principal(i.root, true);
            auth::create_namespace(
                tx,
                root,
                elsewhere,
                Namespace::parse("elsewhere").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            for (account, tenant) in [(bot, i.tenant), (foreign_bot, elsewhere)] {
                auth::create_service_account(
                    tx,
                    stepped(i.root, true),
                    tenant,
                    account,
                    "bot",
                    Role::Reader,
                    Some("fixture"),
                    NOW,
                )?;
            }
            provisioning::insert_human(tx, inactive, "Gone", false, NOW)?;
            tx.execute(
                "UPDATE users SET active = 0 WHERE id = ?1",
                [inactive.as_bytes()],
            )?;
            tx.execute(
                "UPDATE tenants SET membership_source = 1 WHERE id = ?1",
                [i.tenant.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let before = counts(&store);
    // A member, a person who is not a member, an inactive person, another tenant's service account and an
    // id that names nothing: the same refusal for all of them, so it does not reveal which ones exist.
    for target in [i.dev, i.stranger, inactive, foreign_bot, UserId::new()] {
        let results = probe(&store, i, target, true);
        same_refusal(&results, |e| matches!(e, Error::Forbidden));
    }
    assert_eq!(counts(&store), before);
    // The tenant's own service accounts stay editable by hand.
    set_member(
        &store,
        i,
        stepped(i.admin, false),
        bot,
        Role::Operator,
        None,
    )
    .unwrap();
    grant(&store, i, stepped(i.admin, false), bot, None).unwrap();
}
