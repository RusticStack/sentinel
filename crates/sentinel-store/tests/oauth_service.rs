use sentinel_auth::secret::Secret;
use sentinel_core::{
    GrantId, RepoId, SessionId, TenantId, UnixMillis, UserId,
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
            auth::create_service_account(
                tx,
                stepped(person(i.admin, false)),
                i.tenant,
                i.bot,
                "bot",
                Role::Operator,
                None,
                NOW,
            )?;
            auth::create_service_account(
                tx,
                stepped(person(i.outsider, false)),
                i.other,
                i.foreign_bot,
                "bot",
                Role::Operator,
                None,
                NOW,
            )?;
            auth::set_repo_grant(tx, root, i.repo, i.bot, P::READ.union(P::RUN))
        })
        .unwrap();
    (dir, store, i)
}

fn person(user: UserId, super_admin: bool) -> Principal {
    let base = P::REPOSITORY.union(P::TENANT_ADMIN);
    let permissions = if super_admin {
        base.union(P::PLATFORM_ADMIN)
    } else {
        base
    };
    Principal::new(user, permissions, None, None)
}

fn stepped(principal: Principal) -> Authority {
    Authority::Credential {
        principal,
        stepped_up: true,
    }
}

struct Issue {
    authority: Authority,
    tenant: TenantId,
    account: UserId,
    scopes: Scopes,
    repo: Option<RepoId>,
    lifetime_ms: i64,
    reason: Option<String>,
    now: UnixMillis,
}

impl Issue {
    fn by(i: Ids, principal: Principal) -> Self {
        Self::with(i, stepped(principal))
    }

    fn with(i: Ids, authority: Authority) -> Self {
        Self {
            authority,
            tenant: i.tenant,
            account: i.bot,
            scopes: Scopes::RUNS_READ.union(Scopes::LOGS_READ),
            repo: None,
            lifetime_ms: SERVICE_DEFAULT_MS,
            reason: None,
            now: NOW,
        }
    }
}

fn issue(store: &Store, r: Issue) -> Result<(GrantId, Secret, UnixMillis), Error> {
    store.writer().write(move |tx| {
        service::issue_service_grant(
            tx,
            r.authority,
            r.tenant,
            r.account,
            "deploy",
            r.scopes,
            r.repo,
            r.lifetime_ms,
            r.reason.as_deref(),
            r.now,
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
    let own = Principal::new(i.bot, P::REPOSITORY, Some(i.tenant), None);
    assert!(matches!(
        issue(&store, Issue::by(i, own)),
        Err(Error::Forbidden)
    ));

    let (grant, _, expires) = issue(&store, Issue::by(i, person(i.admin, false))).unwrap();
    assert_eq!(expires, at(SERVICE_DEFAULT_MS));
    let mut platform = Issue::by(i, person(i.root, true));
    platform.reason = Some("incident 42".to_owned());
    let platform = issue(&store, platform).unwrap();
    assert_ne!(grant, platform.0);
    let audit = store.read(|c| local_auth::recent_audit(c, 3)).unwrap();
    assert_eq!(audit[0].event, Event::ServiceGrantIssued);
    assert_eq!(audit[1].event, Event::PlatformOverride);
    assert_eq!(audit[1].actor, Some(i.root));
    assert_eq!(audit[1].detail.as_deref(), Some("incident 42"));
    assert_eq!(audit[2].event, Event::ServiceGrantIssued);
    assert_eq!(audit[2].actor, Some(i.admin));
    assert_eq!(audit[2].subject, Some(i.bot));
}

#[test]
fn issuing_needs_fresh_step_up_and_platform_reach_needs_a_reason() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    // Bearer and OAuth credentials and unstamped sessions never step up; host-local has no principal to attribute.
    assert!(matches!(
        issue(&store, Issue::with(i, Authority::credential(admin))),
        Err(Error::StepUpRequired)
    ));
    assert!(matches!(
        issue(&store, Issue::with(i, Authority::HostLocal)),
        Err(Error::Forbidden)
    ));
    // Forbidden rather than a step-up prompt, so a non-administrator learns nothing about proof.
    assert!(matches!(
        issue(
            &store,
            Issue::with(i, Authority::credential(person(i.dev, false)))
        ),
        Err(Error::Forbidden)
    ));
    let root = person(i.root, true);
    assert!(matches!(
        issue(&store, Issue::with(i, Authority::credential(root))),
        Err(Error::StepUpRequired)
    ));
    assert!(matches!(
        issue(&store, Issue::by(i, root)),
        Err(Error::InvalidInput("reason"))
    ));
    for bad in [String::new(), "x".repeat(101)] {
        let mut r = Issue::by(i, root);
        r.reason = Some(bad);
        assert!(matches!(
            issue(&store, r),
            Err(Error::InvalidInput("reason"))
        ));
    }
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(audit[0].event, Event::GrantChanged);
}

fn session(store: &Store, user: UserId, stepped_ago_ms: Option<i64>) -> (Authority, Secret) {
    let secret = Secret::generate();
    let digest = secret.digest();
    let id = SessionId::new();
    let now = UnixMillis::now().0;
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO sessions(token_digest, user_id, csrf_digest, created_ms,
                    idle_deadline_ms, absolute_deadline_ms, stepped_up_ms, id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
                rusqlite::params![
                    digest.0,
                    user.as_bytes(),
                    [7u8; 32],
                    now - 60_000,
                    now + 3_600_000,
                    stepped_ago_ms.map(|ago| now - ago),
                    id.as_bytes()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    let session = store
        .read(|c| local_auth::authenticate(c, &secret, UnixMillis(now)))
        .unwrap();
    let authority = Authority::live_session(&session, digest, local_auth::Policy::default());
    (authority, secret)
}

#[test]
fn a_sessions_step_up_is_read_again_where_the_change_is_made() {
    let (_dir, store, i) = fixture();
    let policy = local_auth::Policy::default();
    for stamp in [None, Some(policy.step_up_ms + 1_000)] {
        let (authority, _) = session(&store, i.admin, stamp);
        assert!(matches!(
            issue(&store, Issue::with(i, authority)),
            Err(Error::StepUpRequired)
        ));
    }
    let (authority, _) = session(&store, i.admin, Some(1_000));
    let mut fresh = Issue::with(i, authority);
    fresh.now = UnixMillis::now();
    issue(&store, fresh).unwrap();
    let (authority, secret) = session(&store, i.admin, Some(1_000));
    let digest = secret.digest();
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE sessions SET revoked_ms = ?2 WHERE token_digest = ?1",
                rusqlite::params![digest.0, UnixMillis::now().0],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        issue(&store, Issue::with(i, authority)),
        Err(Error::StepUpRequired)
    ));
}

#[test]
fn revoking_an_accounts_sessions_revokes_service_grants_it_minted_in_the_window() {
    let (_dir, store, i) = fixture();
    let now = UnixMillis::now();
    let minted = |ago: i64, minter: UserId| {
        let mut r = Issue::by(i, person(minter, minter == i.root));
        if minter == i.root {
            r.reason = Some("incident 42".to_owned());
        }
        r.now = UnixMillis(now.0 - ago);
        issue(&store, r).unwrap().0
    };
    let before = minted(120_000, i.admin);
    let during = minted(10_000, i.admin);
    let theirs = minted(10_000, i.root);
    let _ = session(&store, i.admin, None);
    let revoked = store
        .writer()
        .write(move |tx| local_auth::revoke_all(tx, i.admin, now))
        .unwrap();
    assert_eq!(revoked, 1);
    let listed = store
        .read(|c| service::service_grants(c, person(i.admin, false), i.tenant, i.bot))
        .unwrap();
    let state = |grant: GrantId| listed.iter().find(|g| g.id == grant).unwrap().revoked;
    assert!(state(during), "minted while the session was live");
    assert!(!state(before), "minted before the session began");
    assert!(!state(theirs), "minted by somebody else");
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(audit[0].event, Event::OAuthGrantRevoked);
    assert_eq!(audit[0].subject, Some(i.admin));
}

fn named_session(store: &Store, user: UserId, created_ms: i64, expired: bool) -> SessionId {
    let id = SessionId::new();
    let now = UnixMillis::now().0;
    let deadline = if expired {
        now - 1_000
    } else {
        now + 3_600_000
    };
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO sessions(token_digest, user_id, csrf_digest, created_ms,
                    idle_deadline_ms, absolute_deadline_ms, id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                rusqlite::params![
                    Secret::generate().digest().0,
                    user.as_bytes(),
                    [7u8; 32],
                    created_ms,
                    deadline,
                    id.as_bytes()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    id
}

fn mint_at(store: &Store, i: Ids, minter: UserId, at_ms: i64) -> GrantId {
    let mut r = Issue::by(i, person(minter, false));
    r.now = UnixMillis(at_ms);
    issue(store, r).unwrap().0
}

fn grant_revoked(store: &Store, i: Ids, grant: GrantId) -> bool {
    store
        .read(|c| service::service_grants(c, person(i.admin, false), i.tenant, i.bot))
        .unwrap()
        .iter()
        .find(|g| g.id == grant)
        .unwrap()
        .revoked
}

#[test]
fn revoking_one_session_by_name_revokes_the_grants_minted_since_it_began() {
    let (_dir, store, i) = fixture();
    let now = UnixMillis::now();
    let began = now.0 - 60_000;
    let hijacked = named_session(&store, i.admin, began, false);
    let other = named_session(&store, i.admin, now.0 - 30_000, false);
    let before = mint_at(&store, i, i.admin, began - 5_000);
    let during = mint_at(&store, i, i.admin, now.0 - 10_000);
    store
        .writer()
        .write(move |tx| {
            local_auth::revoke_session(tx, Authority::HostLocal, i.admin, hijacked, now)
        })
        .unwrap();
    assert!(grant_revoked(&store, i, during));
    assert!(!grant_revoked(&store, i, before));
    let later = mint_at(&store, i, i.admin, now.0 - 1_000);
    let again = store.writer().write(move |tx| {
        local_auth::revoke_session(tx, Authority::HostLocal, i.admin, hijacked, now)
    });
    assert!(matches!(again, Err(Error::NotFound)));
    assert!(!grant_revoked(&store, i, later));
    let _ = other;
}

#[test]
fn logout_all_reaches_grants_minted_by_a_session_that_has_since_expired() {
    let (_dir, store, i) = fixture();
    let now = UnixMillis::now();
    let _ = named_session(&store, i.admin, now.0 - 120_000, true);
    let minted = mint_at(&store, i, i.admin, now.0 - 100_000);
    let _ = named_session(&store, i.admin, now.0 - 10_000, false);
    store
        .writer()
        .write(move |tx| local_auth::revoke_all(tx, i.admin, now))
        .unwrap();
    assert!(grant_revoked(&store, i, minted));
}

#[test]
fn session_provenance_isolates_concurrent_sessions_and_is_immutable() {
    let (_dir, store, i) = fixture();
    let now = UnixMillis::now();
    let (first, first_cookie) = session(&store, i.admin, Some(1_000));
    let (second, second_cookie) = session(&store, i.admin, Some(1_000));
    let first_id = store
        .read(|c| local_auth::authenticate(c, &first_cookie, now))
        .unwrap()
        .id
        .unwrap();
    let second_id = store
        .read(|c| local_auth::authenticate(c, &second_cookie, now))
        .unwrap()
        .id
        .unwrap();
    let mut first_issue = Issue::with(i, first);
    first_issue.now = now;
    let first_grant = issue(&store, first_issue).unwrap().0;
    let mut second_issue = Issue::with(i, second);
    second_issue.now = now;
    let second_grant = issue(&store, second_issue).unwrap().0;
    let provenance = |grant: GrantId| {
        store
            .read(|c| {
                c.query_row(
                    "SELECT created_session FROM oauth_grants WHERE id = ?1",
                    [grant.as_bytes()],
                    |row| row.get::<_, Option<[u8; 16]>>(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
            .map(|bytes| SessionId::from_bytes(bytes).unwrap())
    };
    assert_eq!(provenance(first_grant), Some(first_id));
    assert_eq!(provenance(second_grant), Some(second_id));

    store
        .writer()
        .write(move |tx| {
            local_auth::revoke_session(tx, Authority::HostLocal, i.admin, first_id, now)
        })
        .unwrap();
    assert!(grant_revoked(&store, i, first_grant));
    assert!(!grant_revoked(&store, i, second_grant));
    let immutable = store.writer().write(move |tx| {
        tx.execute(
            "UPDATE oauth_grants SET created_session = ?2 WHERE id = ?1",
            rusqlite::params![second_grant.as_bytes(), first_id.as_bytes()],
        )?;
        Ok(())
    });
    assert!(matches!(immutable, Err(Error::Sqlite(_))));
    let audit = store
        .read(|c| local_auth::recent_audit(c, 1))
        .unwrap()
        .remove(0);
    assert_eq!(audit.event, Event::OAuthGrantRevoked);
    assert_eq!(
        audit.detail.as_deref(),
        Some("1 service grants minted in session window")
    );
}

#[test]
fn logout_all_revokes_provenanced_grants_after_expiry_and_session_purge() {
    let (_dir, store, i) = fixture();
    let now = UnixMillis::now();
    let (authority, _) = session(&store, i.admin, Some(1_000));
    let mut request = Issue::with(i, authority);
    request.now = now;
    let grant = issue(&store, request).unwrap().0;
    let purged_at = UnixMillis(now.0 + SERVICE_DEFAULT_MS + 1);
    assert_eq!(local_auth::purge_expired(&store, purged_at, 10).unwrap(), 1);
    store
        .writer()
        .write(move |tx| local_auth::revoke_all(tx, i.admin, purged_at))
        .unwrap();
    assert!(grant_revoked(&store, i, grant));
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
    assert!(matches!(
        with(&|r| r.repo = Some(i.other_repo)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        with(&|r| r.account = i.foreign_bot),
        Err(Error::NotFound)
    ));
    assert!(matches!(with(&|r| r.account = i.dev), Err(Error::NotFound)));
    with(&|r| r.lifetime_ms = SERVICE_MIN_MS).unwrap();
    with(&|r| r.lifetime_ms = SERVICE_MAX_MS).unwrap();
    let (grant, refresh, _) = with(&|r| r.repo = Some(i.repo)).unwrap();
    let minted = oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, None, at(1)).unwrap();
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
    let minted = oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, None, at(10)).unwrap();
    assert_eq!(minted.refresh_expires, expires);
    assert!(matches!(
        oauth::refresh(&store, "other", &minted.refresh, None, None, at(11)),
        Err(RefreshError::Invalid)
    ));
    let listed = store
        .read(|c| service::service_grants(c, person(i.admin, false), i.tenant, i.bot))
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, grant);
    drop(store);
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
        oauth::refresh(&store, CLI_CLIENT_ID, &refresh, None, None, at(6)),
        Err(RefreshError::Invalid)
    ));
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
        store.writer().write(move |tx| {
            service::allow_repo(tx, stepped(principal), i.tenant, account, repo, p, None)
        })
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
fn withdrawing_repository_access_needs_the_same_step_up_and_reason_as_allowing_it() {
    let (_dir, store, i) = fixture();
    let admin = person(i.admin, false);
    let root = person(i.root, true);
    let bot = Principal::new(i.bot, P::REPOSITORY, None, None);
    let withdraw = |authority: Authority, reason: Option<&str>| {
        let reason = reason.map(str::to_owned);
        store.writer().write(move |tx| {
            service::allow_repo(
                tx,
                authority,
                i.tenant,
                i.bot,
                i.repo,
                P::NONE,
                reason.as_deref(),
            )
        })
    };
    let holds = || {
        store
            .read(|c| auth::require_repo(c, bot, i.repo, P::READ))
            .is_ok()
    };
    let last_audit = || {
        store
            .read(|c| local_auth::recent_audit(c, 1))
            .unwrap()
            .remove(0)
            .seq
    };
    assert!(holds());
    let before = last_audit();
    // Without a fresh proof every caller is refused, a tenant administrator and a bearer credential
    // included; a person who administers nothing learns nothing about proof.
    for (authority, reason) in [
        (Authority::credential(admin), None),
        (Authority::credential(admin), Some("not needed")),
        (Authority::credential(root), None),
        (Authority::credential(root), Some("incident 9")),
    ] {
        assert!(matches!(
            withdraw(authority, reason),
            Err(Error::StepUpRequired)
        ));
    }
    for authority in [
        Authority::credential(person(i.dev, false)),
        stepped(person(i.dev, false)),
        stepped(person(i.outsider, false)),
        Authority::HostLocal,
    ] {
        assert!(matches!(withdraw(authority, None), Err(Error::Forbidden)));
    }
    // A platform administrator who administers nothing in the tenant also needs a reason of 1-100 bytes.
    let long = "x".repeat(101);
    for reason in [None, Some(""), Some(long.as_str())] {
        assert!(matches!(
            withdraw(stepped(root), reason),
            Err(Error::InvalidInput("reason"))
        ));
    }
    assert!(holds());
    assert_eq!(last_audit(), before, "a refusal leaves no audit row");
    // A stepped-up tenant administrator needs no reason; the platform administrator's reason is recorded.
    withdraw(stepped(admin), None).unwrap();
    assert!(!holds());
    let allow = |p: Principal, reason: Option<&str>| {
        let reason = reason.map(str::to_owned);
        store.writer().write(move |tx| {
            service::allow_repo(
                tx,
                stepped(p),
                i.tenant,
                i.bot,
                i.repo,
                P::READ,
                reason.as_deref(),
            )
        })
    };
    allow(admin, None).unwrap();
    assert!(holds());
    withdraw(stepped(root), Some("incident 9")).unwrap();
    assert!(!holds());
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[0].event, Event::GrantChanged);
    assert_eq!(audit[1].event, Event::PlatformOverride);
    assert_eq!(audit[1].actor, Some(i.root));
    assert_eq!(audit[1].detail.as_deref(), Some("incident 9"));
}

#[test]
fn creating_a_service_account_is_audited_and_needs_an_administrator() {
    let (_dir, store, i) = fixture();
    let audit = store.read(|c| local_auth::recent_audit(c, 3)).unwrap();
    assert_eq!(audit[0].event, Event::GrantChanged);
    for (row, (account, actor)) in audit[1..]
        .iter()
        .zip([(i.foreign_bot, i.outsider), (i.bot, i.admin)])
    {
        assert_eq!(row.event, Event::ServiceAccountCreated);
        assert_eq!(row.actor, Some(actor));
        assert_eq!(row.subject, Some(account));
    }
    let refused = store.writer().write(move |tx| {
        auth::create_service_account(
            tx,
            stepped(person(i.dev, false)),
            i.tenant,
            UserId::new(),
            "rogue",
            Role::Reader,
            None,
            NOW,
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    let unstepped = store.writer().write(move |tx| {
        auth::create_service_account(
            tx,
            Authority::credential(person(i.admin, false)),
            i.tenant,
            UserId::new(),
            "rogue",
            Role::Reader,
            None,
            NOW,
        )
    });
    assert!(matches!(unstepped, Err(Error::StepUpRequired)));
    let after = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(
        after[0].event,
        Event::GrantChanged,
        "a refusal writes nothing"
    );
}

fn plan(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("SQLite refused {sql}: {e}"));
    let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn revoking_minted_grants_seeks_the_minter_by_key_and_never_walks_other_users_grants() {
    let (_dir, store, _) = fixture();
    // Each statement is one index search on `created_by`; none may fall back to the expiry
    // or user indexes, which would read every unexpired grant of every account.
    for (sql, search) in [
        (
            oauth::REVOKE_MINTED_BY_SESSION,
            "SEARCH oauth_grants USING INDEX oauth_grants_by_created_session \
             (created_by=? AND created_session=?)",
        ),
        (
            oauth::REVOKE_MINTED_BY_USER,
            "SEARCH oauth_grants USING INDEX oauth_grants_by_created_session \
             (created_by=? AND created_session>?)",
        ),
        (
            oauth::REVOKE_MINTED_LEGACY,
            "SEARCH oauth_grants USING INDEX oauth_grants_by_unattributed_minter \
             (created_by=? AND created_ms>? AND created_ms<?)",
        ),
    ] {
        let plan = store.read(|c| Ok(plan(c, sql))).unwrap();
        assert_eq!(plan, [search], "{sql}");
    }
}
