//! O06 service-account grants: only an administrator of the principal's
//! tenant (or a platform administrator) issues them, within lifetime bounds,
//! never with administrative scopes, confined to the tenant and its
//! repositories; the refresh token is returned once and stored only as a
//! digest; listing is metadata; revocation by owner, tenant administrator or
//! platform administrator, NotFound for anyone else.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
    oauth::{
        self, GrantKind, RefreshError, SERVICE_DEFAULT_MS, SERVICE_MAX_MS, SERVICE_MIN_MS, service,
    },
};

const NOW: UnixMillis = UnixMillis(1_000_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(NOW.0 + ms)
}

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    admin: UserId,
    dev: UserId,
    outsider: UserId,
    bot: UserId,
    foreign_bot: UserId,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    other_repo: RepoId,
}

/// A super admin; `admin` administers `acme`; `dev` operates it; `outsider`
/// administers only `other`; `bot` is a service principal of `acme` allowed
/// read and run on `app`; `foreign_bot` belongs to `other`.
fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        admin: UserId::new(),
        dev: UserId::new(),
        outsider: UserId::new(),
        bot: UserId::new(),
        foreign_bot: UserId::new(),
        tenant: TenantId::new(),
        other: TenantId::new(),
        repo: RepoId::new(),
        other_repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, i.root, "Root", true, NOW)?;
            for (user, name) in [(i.admin, "Admin"), (i.dev, "Dev"), (i.outsider, "Outsider")] {
                provisioning::insert_human(tx, user, name, false, NOW)?;
            }
            let root = Principal::new(i.root, P::ALL, None, None);
            for (tenant, slug) in [(i.tenant, "acme"), (i.other, "other")] {
                auth::create_namespace(
                    tx,
                    root,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            auth::set_membership(tx, root, i.tenant, i.admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, i.tenant, i.dev, Role::Operator)?;
            auth::set_membership(tx, root, i.other, i.outsider, Role::TenantAdmin)?;
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            auth::create_repo(tx, root, i.other, i.other_repo, "app", NOW)?;
            auth::create_service_account(tx, root, i.tenant, i.bot, "bot", Role::Operator, NOW)?;
            auth::create_service_account(
                tx,
                root,
                i.other,
                i.foreign_bot,
                "bot",
                Role::Operator,
                NOW,
            )?;
            auth::set_repo_grant(tx, root, i.repo, i.bot, P::READ.union(P::RUN))
        })
        .unwrap();
    (dir, store, i)
}

/// What a person holds through a session: every repository permission and
/// tenant administration, platform administration for a super admin.
fn person(user: UserId, super_admin: bool) -> Principal {
    let base = P::REPOSITORY.union(P::TENANT_ADMIN);
    let permissions = if super_admin {
        base.union(P::PLATFORM_ADMIN)
    } else {
        base
    };
    Principal::new(user, permissions, None, None)
}

struct Issue {
    principal: Principal,
    tenant: TenantId,
    account: UserId,
    scopes: Scopes,
    repo: Option<RepoId>,
    lifetime_ms: i64,
}

impl Issue {
    fn by(i: Ids, principal: Principal) -> Self {
        Self {
            principal,
            tenant: i.tenant,
            account: i.bot,
            scopes: Scopes::RUNS_READ.union(Scopes::LOGS_READ),
            repo: None,
            lifetime_ms: SERVICE_DEFAULT_MS,
        }
    }
}

fn issue(store: &Store, r: Issue) -> Result<(GrantId, Secret, UnixMillis), Error> {
    store.writer().write(move |tx| {
        service::issue_service_grant(
            tx,
            r.principal,
            r.tenant,
            r.account,
            "deploy",
            r.scopes,
            r.repo,
            r.lifetime_ms,
            NOW,
        )
    })
}

#[test]
fn only_an_administrator_of_the_tenant_issues() {
    let (_dir, store, i) = fixture();
    for refused in [person(i.dev, false), person(i.outsider, false)] {
        assert!(matches!(
            issue(&store, Issue::by(i, refused)),
            Err(Error::Forbidden)
        ));
    }
    // A tenant-admin principal narrowed to another tenant, or to a
    // repository, is not an administrator of this one.
    let narrowed = Principal::new(
        i.admin,
        P::REPOSITORY.union(P::TENANT_ADMIN),
        Some(i.other),
        None,
    );
    assert!(matches!(
        issue(&store, Issue::by(i, narrowed)),
        Err(Error::Forbidden)
    ));
    // The service principal cannot issue to itself.
    let own = Principal::new(i.bot, P::REPOSITORY, Some(i.tenant), None);
    assert!(matches!(
        issue(&store, Issue::by(i, own)),
        Err(Error::Forbidden)
    ));

    let (grant, _, expires) = issue(&store, Issue::by(i, person(i.admin, false))).unwrap();
    assert_eq!(expires, at(SERVICE_DEFAULT_MS));
    let platform = issue(&store, Issue::by(i, person(i.root, true))).unwrap();
    assert_ne!(grant, platform.0);
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[1].event, Event::ServiceGrantIssued);
    assert_eq!(audit[1].actor, Some(i.admin));
    assert_eq!(audit[1].subject, Some(i.bot));
}

#[test]
fn terms_are_bounded_confined_and_never_administrative() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    let with = |f: &dyn Fn(&mut Issue)| {
        let mut r = Issue::by(i, admin);
        f(&mut r);
        issue(&store, r)
    };
    for lifetime in [SERVICE_MIN_MS - 1, SERVICE_MAX_MS + 1, 0, -1] {
        assert!(matches!(
            with(&|r| r.lifetime_ms = lifetime),
            Err(Error::InvalidInput("grant lifetime"))
        ));
    }
    for scopes in [
        Scopes::NONE,
        Scopes::TENANT_ADMIN,
        Scopes::RUNS_READ.union(Scopes::PLATFORM_ADMIN),
    ] {
        assert!(matches!(
            with(&|r| r.scopes = scopes),
            Err(Error::InvalidInput("scope"))
        ));
    }
    // A repository of another tenant; a principal of another tenant; a person.
    assert!(matches!(
        with(&|r| r.repo = Some(i.other_repo)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        with(&|r| r.account = i.foreign_bot),
        Err(Error::NotFound)
    ));
    assert!(matches!(with(&|r| r.account = i.dev), Err(Error::NotFound)));
    // The bounds themselves are fine, and a repository of the tenant narrows.
    with(&|r| r.lifetime_ms = SERVICE_MIN_MS).unwrap();
    with(&|r| r.lifetime_ms = SERVICE_MAX_MS).unwrap();
    let (grant, refresh, _) = with(&|r| r.repo = Some(i.repo)).unwrap();
    let minted = oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, at(1)).unwrap();
    assert_eq!(minted.grant, grant);
    let who = store
        .read(|c| oauth::authenticate_access(c, &minted.access, Audience::Api, at(2)))
        .unwrap();
    assert_eq!(who.principal.user, i.bot);
    assert_eq!(who.principal.tenant, Some(i.tenant));
    assert_eq!(who.principal.repo, Some(i.repo));
    assert_eq!(who.scopes, Scopes::RUNS_READ.union(Scopes::LOGS_READ));
}

#[test]
fn the_refresh_token_is_returned_once_and_stored_only_as_a_digest() {
    let (dir, store, i) = fixture();
    let (grant, refresh, expires) = issue(&store, Issue::by(i, person(i.admin, false))).unwrap();
    // The holder's first refresh works and keeps the service life: the
    // refresh token lives exactly as long as the grant.
    let minted = oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, at(10)).unwrap();
    assert_eq!(minted.refresh_expires, expires);
    assert!(matches!(
        oauth::refresh(&store, "other", &minted.refresh, None, at(11)),
        Err(RefreshError::Invalid)
    ));
    let listed = store
        .read(|c| service::service_grants(c, person(i.admin, false), i.tenant, i.bot))
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, grant);
    drop(store);
    // Neither the token (as text or raw bytes) is anywhere in the database
    // files; its digest is what was stored.
    let mut hex = String::new();
    refresh.expose(&mut hex);
    let raw = refresh_bytes(&hex);
    let mut found_digest = false;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            continue;
        }
        let bytes = std::fs::read(path).unwrap();
        assert!(!contains(&bytes, hex.as_bytes()));
        assert!(!contains(&bytes, &raw));
        found_digest |= contains(&bytes, &refresh.digest().0);
    }
    assert!(found_digest);
}

fn refresh_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn listing_is_metadata_for_administrators_only() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    let (first, _, _) = issue(&store, Issue::by(i, admin)).unwrap();
    let mut second = Issue::by(i, admin);
    second.repo = Some(i.repo);
    second.scopes = Scopes::RUNS_READ;
    let (second, _, _) = issue(&store, second).unwrap();
    let listed = store
        .read(|c| service::service_grants(c, admin, i.tenant, i.bot))
        .unwrap();
    assert_eq!(listed.len(), 2);
    let record = listed.iter().find(|g| g.id == second).unwrap();
    assert_eq!(record.kind, GrantKind::Service);
    assert_eq!(record.client_id, CLI_CLIENT_ID);
    assert_eq!(record.name.as_deref(), Some("deploy"));
    assert_eq!(record.tenant, Some(i.tenant));
    assert_eq!(record.repo, Some(i.repo));
    assert_eq!(record.scopes, Scopes::RUNS_READ);
    assert!(!record.revoked);
    assert!(listed.iter().any(|g| g.id == first));
    // Platform administration also lists; members and other tenants do not.
    assert_eq!(
        store
            .read(|c| service::service_grants(c, person(i.root, true), i.tenant, i.bot))
            .unwrap()
            .len(),
        2
    );
    for refused in [person(i.dev, false), person(i.outsider, false)] {
        assert!(matches!(
            store.read(|c| service::service_grants(c, refused, i.tenant, i.bot)),
            Err(Error::Forbidden)
        ));
    }
    // A person or another tenant's principal is not a service principal here.
    for account in [i.dev, i.foreign_bot] {
        assert!(matches!(
            store.read(|c| service::service_grants(c, admin, i.tenant, account)),
            Err(Error::NotFound)
        ));
    }
}

#[test]
fn owner_tenant_admin_and_platform_admin_revoke_anyone_else_sees_nothing() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    let revoke = |authority: Authority, grant: GrantId| {
        store
            .writer()
            .write(move |tx| oauth::revoke_grant(tx, authority, grant, at(5)))
    };
    let (grant, refresh, _) = issue(&store, Issue::by(i, admin)).unwrap();
    for outsider in [person(i.dev, false), person(i.outsider, false)] {
        assert!(matches!(
            revoke(Authority::credential(outsider), grant),
            Err(Error::NotFound)
        ));
    }
    revoke(Authority::credential(admin), grant).unwrap();
    assert!(matches!(
        oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, at(6)),
        Err(RefreshError::Invalid)
    ));
    // The owner (the service principal's own credential) and a platform
    // administrator may too.
    let (owned, _, _) = issue(&store, Issue::by(i, admin)).unwrap();
    let own = Principal::new(i.bot, P::REPOSITORY, Some(i.tenant), None);
    revoke(Authority::credential(own), owned).unwrap();
    let (platform, _, _) = issue(&store, Issue::by(i, admin)).unwrap();
    revoke(Authority::credential(person(i.root, true)), platform).unwrap();
    let listed = store
        .read(|c| service::service_grants(c, admin, i.tenant, i.bot))
        .unwrap();
    assert!(listed.iter().all(|g| g.revoked));
    assert_eq!(listed.len(), 3);
}

#[test]
fn repository_access_is_allowed_only_within_the_tenant() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    let allow = |principal: Principal, account: UserId, repo: RepoId, p: P| {
        store
            .writer()
            .write(move |tx| service::allow_repo(tx, principal, i.tenant, account, repo, p))
    };
    assert!(matches!(
        allow(person(i.dev, false), i.bot, i.repo, P::READ),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        allow(admin, i.bot, i.other_repo, P::READ),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        allow(admin, i.dev, i.repo, P::READ),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        allow(admin, i.foreign_bot, i.repo, P::READ),
        Err(Error::NotFound)
    ));
    allow(admin, i.bot, i.repo, P::READ).unwrap();
    let bot = Principal::new(i.bot, P::REPOSITORY, None, None);
    assert!(
        store
            .read(|c| auth::require_repo(c, bot, i.repo, P::READ))
            .is_ok()
    );
    assert!(
        store
            .read(|c| auth::require_repo(c, bot, i.repo, P::RUN))
            .is_err()
    );
    allow(admin, i.bot, i.repo, P::NONE).unwrap();
    assert!(
        store
            .read(|c| auth::require_repo(c, bot, i.repo, P::READ))
            .is_err()
    );
}

#[test]
fn creating_a_service_account_is_audited_and_needs_an_administrator() {
    let (_dir, store, i) = fixture();
    let audit = store.read(|c| local_auth::recent_audit(c, 3)).unwrap();
    // Newest first: the repository grant, then the two creations.
    assert_eq!(audit[0].event, Event::GrantChanged);
    for (row, account) in audit[1..].iter().zip([i.foreign_bot, i.bot]) {
        assert_eq!(row.event, Event::ServiceAccountCreated);
        assert_eq!(row.actor, Some(i.root));
        assert_eq!(row.subject, Some(account));
    }
    let refused = store.writer().write(move |tx| {
        auth::create_service_account(
            tx,
            person(i.dev, false),
            i.tenant,
            UserId::new(),
            "rogue",
            Role::Reader,
            NOW,
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    let after = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(
        after[0].event,
        Event::GrantChanged,
        "a refusal writes nothing"
    );
}
