//! Changing who can reach a tenant's data from a client route: a platform
//! administrator carries no ambient data access, so granting it to themselves
//! (or anyone) without being an administrator of the tenant needs fresh
//! step-up and an audited reason; naming a person resolves a sign-in name only
//! among the tenant's members, so the route is no oracle for which accounts
//! exist.

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

/// `root` is a super admin who is not a member of `acme`; `admin` administers
/// it; `dev` is a member; `stranger` has an account but no membership. Local
/// sign-in names exist for `dev` and `stranger`.
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
    // A member who does not administer the tenant is refused as before.
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
    // Not stepped up: asked for a proof, whatever the reason.
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
    // Stepped up but no reason, or an empty or oversized one: refused.
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
    // Nothing changed.
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
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[0].event, Event::MembershipSet);
    assert_eq!(audit[1].event, Event::PlatformOverride);
    assert_eq!(audit[1].actor, Some(i.root));
    assert_eq!(audit[1].detail.as_deref(), Some("incident 7"));
    // Now an administrator-member, root needs neither proof nor reason here.
    grant(&store, i, unstepped(i.root, true), i.root, None).unwrap();
    // A host-local authority has no principal to attribute: refused.
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
    // A real account outside the tenant and a name nobody has are the same.
    assert!(matches!(resolve("stranger"), Err(Error::NotFound)));
    assert!(matches!(resolve("nobody"), Err(Error::NotFound)));
    // An id is taken as given: adding a new member needs the person's id.
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
