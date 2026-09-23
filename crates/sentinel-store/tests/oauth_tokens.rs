//! O02 token core: grants mint access/refresh pairs that authenticate into the
//! ordinary authorization layer; refresh rotation with lost-response recovery
//! and replay revocation; holder revocation; cascading revocation; the
//! database's own refusals; and bounded purging.

use sentinel_auth::{
    oauth::{self as forms, Kind},
    secret::Secret,
};
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
    oauth::{self, ClientSpec, GrantKind, Minted, NewGrant, ROTATION_GRACE_MS, RefreshError},
    registration, tenancy,
};

const NOW: UnixMillis = UnixMillis(1_000_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(NOW.0 + ms)
}

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    second: UserId,
    dev: UserId,
    bot: UserId,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    other_repo: RepoId,
}

/// A super admin (and a second one, so the first can be demoted), a
/// developer who administers `acme`, a service principal of `acme`, and an
/// unrelated tenant with its own repository.
fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        second: UserId::new(),
        dev: UserId::new(),
        bot: UserId::new(),
        tenant: TenantId::new(),
        other: TenantId::new(),
        repo: RepoId::new(),
        other_repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, i.root, "Root", true, NOW)?;
            provisioning::insert_human(tx, i.second, "Second", true, NOW)?;
            provisioning::insert_human(tx, i.dev, "Dev", false, NOW)?;
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
            auth::set_membership(tx, root, i.tenant, i.dev, Role::TenantAdmin)?;
            auth::set_membership(tx, root, i.other, i.dev, Role::Reader)?;
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            auth::create_repo(tx, root, i.other, i.other_repo, "app", NOW)?;
            auth::create_service_account(tx, root, i.tenant, i.bot, "bot", Role::Operator, NOW)?;
            auth::set_repo_grant(tx, root, i.repo, i.bot, P::READ.union(P::RUN))?;
            Ok(())
        })
        .unwrap();
    (dir, store, i)
}

fn privileged(i: Ids) -> Authority {
    Authority::Credential {
        principal: Principal::new(i.root, P::ALL, None, None),
        stepped_up: true,
    }
}

fn login_grant(user: UserId, scopes: Scopes) -> NewGrant<'static> {
    NewGrant {
        user,
        client_id: CLI_CLIENT_ID,
        kind: GrantKind::Code,
        scopes,
        tenant: None,
        repo: None,
        audience: Audience::Api,
        name: None,
        lifetime_ms: oauth::LOGIN_GRANT_MS,
        created_by: None,
    }
}

fn issue(store: &Store, grant: NewGrant<'_>) -> Minted {
    oauth::issue_grant_trusted(store, grant, NOW).unwrap()
}

fn authenticate(
    store: &Store,
    access: &Secret,
    now: UnixMillis,
) -> Result<oauth::Authenticated, Error> {
    store.read(|c| oauth::authenticate_access(c, access, Audience::Api, now))
}

fn refresh(
    store: &Store,
    token: &Secret,
    narrow: Option<Scopes>,
    now: UnixMillis,
) -> Result<Minted, RefreshError> {
    oauth::refresh(store, CLI_CLIENT_ID, token, narrow, now)
}

fn revoked(store: &Store, grant: GrantId, user: UserId) -> bool {
    store
        .read(|c| oauth::grants(c, Authority::HostLocal, user, 100))
        .unwrap()
        .iter()
        .find(|g| g.id == grant)
        .expect("grant listed")
        .revoked
}

fn text(kind: Kind, secret: &Secret) -> String {
    forms::format(kind, secret)
}

#[test]
fn an_access_token_authenticates_through_the_live_authorization_layer() {
    let (_dir, store, i) = fixture();
    let minted = issue(
        &store,
        NewGrant {
            tenant: Some(i.tenant),
            ..login_grant(i.dev, Scopes::CLI_DEFAULT)
        },
    );
    assert_eq!(minted.scopes, Scopes::CLI_DEFAULT);
    assert_eq!(minted.access_expires, at(oauth::ACCESS_LIFETIME_MS));
    assert_eq!(minted.refresh_expires, at(oauth::REFRESH_IDLE_MS));
    let who = authenticate(&store, &minted.access, at(1)).unwrap();
    assert_eq!(who.grant, minted.grant);
    assert_eq!(who.principal.user, i.dev);
    assert_eq!(who.principal.tenant, Some(i.tenant));
    assert_eq!(who.principal.permissions, P::READ.union(P::RUN));
    assert_eq!(who.scopes, Scopes::CLI_DEFAULT);
    store
        .read(|c| auth::require_repo(c, who.principal, i.repo, P::RUN))
        .unwrap();
    // Narrowed to acme: another tenant's repository is not visible even
    // though the account is a member there.
    assert!(matches!(
        store.read(|c| auth::require_repo(c, who.principal, i.other_repo, P::READ)),
        Err(Error::NotFound)
    ));
    // The grant carries no tenant administration; the account's role does not add it.
    assert!(
        store
            .read(|c| auth::require_tenant_admin(c, who.principal, i.tenant))
            .is_err()
    );
    // Refresh tokens, codes and garbage never authenticate as access tokens.
    assert!(matches!(
        authenticate(&store, &minted.refresh, at(1)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        authenticate(&store, &Secret::generate(), at(1)),
        Err(Error::NotFound)
    ));
}

#[test]
fn expiry_revocation_and_audience_are_predicates_of_validation() {
    let (_dir, store, i) = fixture();
    let minted = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    assert!(authenticate(&store, &minted.access, at(oauth::ACCESS_LIFETIME_MS - 1)).is_ok());
    assert!(matches!(
        authenticate(&store, &minted.access, at(oauth::ACCESS_LIFETIME_MS)),
        Err(Error::NotFound)
    ));

    // A grant for another audience (reserved code 2, only reachable with
    // the CHECK constraint lifted) is invisible to the API audience.
    let foreign = Secret::generate();
    let digest = foreign.digest().0;
    let (grant, dev) = (GrantId::new(), i.dev);
    store
        .writer()
        .raw(move |c| {
            c.execute_batch("PRAGMA ignore_check_constraints = ON")?;
            c.execute(
                "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, audience,
                    created_ms, expires_ms) VALUES (?1, ?2, 'sentinel-cli', 1, 1, 2, ?3, ?4)",
                rusqlite::params![grant.as_bytes(), dev.as_bytes(), NOW.0, at(60_000).0],
            )?;
            c.execute(
                "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
                    created_ms, expires_ms) VALUES (?1, ?2, 1, 1, ?3, ?4)",
                rusqlite::params![digest, grant.as_bytes(), NOW.0, at(60_000).0],
            )?;
            c.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        authenticate(&store, &foreign, at(1)),
        Err(Error::NotFound)
    ));

    // Revoking the grant ends its access token at once, before its expiry.
    let grant = minted.grant;
    store
        .writer()
        .write(move |tx| oauth::revoke_grant(tx, privileged(i), grant, at(2)))
        .unwrap();
    assert!(matches!(
        authenticate(&store, &minted.access, at(3)),
        Err(Error::NotFound)
    ));
    assert!(revoked(&store, grant, i.dev));
}

#[test]
fn platform_scope_is_dropped_once_the_account_is_demoted() {
    let (_dir, store, i) = fixture();
    let minted = issue(&store, login_grant(i.root, Scopes::ALL));
    let who = authenticate(&store, &minted.access, at(1)).unwrap();
    assert!(who.scopes.contains(Scopes::PLATFORM_ADMIN));
    assert!(who.principal.permissions.contains(P::PLATFORM_ADMIN));
    store
        .writer()
        .write(move |tx| {
            local_auth::set_super_admin(tx, Authority::HostLocal, i.root, false, at(2))
        })
        .unwrap();
    let who = authenticate(&store, &minted.access, at(3)).unwrap();
    assert!(!who.scopes.contains(Scopes::PLATFORM_ADMIN));
    assert!(!who.principal.permissions.contains(P::PLATFORM_ADMIN));
    assert!(who.scopes.contains(Scopes::TENANT_ADMIN));
}

#[test]
fn service_principals_are_confined_to_their_home_tenant() {
    let (_dir, store, i) = fixture();
    let minted = issue(
        &store,
        NewGrant {
            kind: GrantKind::Service,
            tenant: Some(i.tenant),
            name: Some("deploy bot"),
            lifetime_ms: oauth::SERVICE_DEFAULT_MS,
            created_by: Some(i.dev),
            ..login_grant(i.bot, Scopes::RUNS_READ.union(Scopes::RUNS_WRITE))
        },
    );
    // A service grant's refresh token lives as long as the grant.
    assert_eq!(minted.refresh_expires, at(oauth::SERVICE_DEFAULT_MS));
    let who = authenticate(&store, &minted.access, at(1)).unwrap();
    assert_eq!(who.principal.tenant, Some(i.tenant));
    store
        .read(|c| auth::require_repo(c, who.principal, i.repo, P::RUN))
        .unwrap();
    for escaping in [None, Some(i.other)] {
        let refused = oauth::issue_grant_trusted(
            &store,
            NewGrant {
                kind: GrantKind::Service,
                tenant: escaping,
                ..login_grant(i.bot, Scopes::RUNS_READ)
            },
            NOW,
        );
        assert!(matches!(refused, Err(Error::Forbidden)), "{escaping:?}");
    }
}

#[test]
fn the_database_refuses_ineligible_grants() {
    let (_dir, store, i) = fixture();
    oauth::register_client(
        &store,
        &ClientSpec {
            id: "reader-app",
            name: "Reader",
            first_party: false,
            loopback: false,
            redirect_path: None,
            device: false,
            max_scopes: Scopes::RUNS_READ,
        },
        &["https://reader.example/cb"],
    )
    .unwrap();
    let cases: [(&str, NewGrant<'_>); 6] = [
        (
            "platform scope for a non-super-admin",
            login_grant(i.dev, Scopes::PLATFORM_ADMIN),
        ),
        (
            "tenant administration for a service principal",
            NewGrant {
                tenant: Some(i.tenant),
                ..login_grant(i.bot, Scopes::TENANT_ADMIN)
            },
        ),
        (
            "a repository outside the narrowed tenant",
            NewGrant {
                tenant: Some(i.tenant),
                repo: Some(i.other_repo),
                ..login_grant(i.dev, Scopes::RUNS_READ)
            },
        ),
        (
            "scopes beyond the client's ceiling",
            NewGrant {
                client_id: "reader-app",
                ..login_grant(i.dev, Scopes::RUNS_READ.union(Scopes::LOGS_READ))
            },
        ),
        (
            "an unknown client",
            NewGrant {
                client_id: "nobody",
                ..login_grant(i.dev, Scopes::RUNS_READ)
            },
        ),
        (
            "a lifetime past 90 days",
            NewGrant {
                lifetime_ms: oauth::GRANT_MAX_MS + 1,
                ..login_grant(i.dev, Scopes::RUNS_READ)
            },
        ),
    ];
    for (what, grant) in cases {
        let refused = oauth::issue_grant_trusted(&store, grant, NOW);
        assert!(
            matches!(refused, Err(Error::Forbidden | Error::InvalidInput(_))),
            "{what}: {refused:?}"
        );
    }
    // Inside the ceiling the registered client is fine, and a suspended
    // account can hold nothing.
    issue(
        &store,
        NewGrant {
            client_id: "reader-app",
            ..login_grant(i.dev, Scopes::RUNS_READ)
        },
    );
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, privileged(i), i.dev, false, at(1)))
        .unwrap();
    assert!(matches!(
        oauth::issue_grant_trusted(&store, login_grant(i.dev, Scopes::RUNS_READ), at(2)),
        Err(Error::Forbidden)
    ));
    // The seeded CLI client redirects to loopback only, on its own path.
    let cli = store.read(|c| oauth::client(c, CLI_CLIENT_ID)).unwrap();
    assert!(cli.first_party && cli.loopback && cli.device);
    assert_eq!(cli.max_scopes, Scopes::ALL);
    let reader = store.read(|c| oauth::client(c, "reader-app")).unwrap();
    for (client, uri, allowed) in [
        (&cli, "http://127.0.0.1:4711/callback", true),
        (&cli, "http://[::1]:4711/callback", true),
        (&cli, "http://localhost:4711/callback", false),
        (&cli, "https://reader.example/cb", false),
        (&reader, "https://reader.example/cb", true),
        (&reader, "https://reader.example/cb/", false),
        (&reader, "http://127.0.0.1:4711/callback", false),
    ] {
        assert_eq!(
            store
                .read(|c| oauth::redirect_allowed(c, client, uri))
                .unwrap(),
            allowed,
            "{} {uri}",
            client.id
        );
    }
    assert!(matches!(
        store.read(|c| oauth::client(c, "nobody")),
        Err(Error::NotFound)
    ));
}

#[test]
fn rotation_issues_exactly_one_successor() {
    let (_dir, store, i) = fixture();
    let first = issue(&store, login_grant(i.dev, Scopes::CLI_DEFAULT));
    let second = refresh(&store, &first.refresh, None, at(1_000)).unwrap();
    assert_eq!(second.grant, first.grant);
    assert_eq!(second.scopes, Scopes::CLI_DEFAULT);
    assert_eq!(second.refresh_expires, at(1_000 + oauth::REFRESH_IDLE_MS));
    assert!(authenticate(&store, &second.access, at(1_001)).is_ok());
    let third = refresh(&store, &second.refresh, None, at(2_000)).unwrap();
    assert!(authenticate(&store, &third.access, at(2_001)).is_ok());
    let generations: i64 = store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM oauth_refresh_tokens WHERE grant_id = ?1",
                [first.grant.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(generations, 3);
    // Only the right client may present it.
    assert!(matches!(
        oauth::refresh(&store, "other-client", &third.refresh, None, at(3_000)),
        Err(RefreshError::Invalid)
    ));
    assert!(matches!(
        refresh(&store, &Secret::generate(), None, at(3_000)),
        Err(RefreshError::Invalid)
    ));
    assert!(!revoked(&store, first.grant, i.dev));
}

#[test]
fn a_lost_response_recovers_once_and_the_abandoned_successor_is_a_replay() {
    let (_dir, store, i) = fixture();
    let first = issue(&store, login_grant(i.dev, Scopes::CLI_DEFAULT));
    // The response carrying `lost` never reached the client.
    let lost = refresh(&store, &first.refresh, None, at(1_000)).unwrap();
    // Recovery at the last instant of the grace window; everything after it
    // happens later still, as a real client's clock would run (P09-18).
    let t = 1_000 + ROTATION_GRACE_MS;
    let recovered = refresh(&store, &first.refresh, None, at(t)).unwrap();
    assert_eq!(recovered.grant, first.grant);
    assert!(authenticate(&store, &recovered.access, at(t + 1)).is_ok());
    // The abandoned successor's access token is gone with it.
    assert!(authenticate(&store, &lost.access, at(t + 1)).is_err());
    // The recovered token keeps rotating normally.
    let next = refresh(&store, &recovered.refresh, None, at(t + 1_000)).unwrap();
    assert_eq!(next.refresh_expires, at(t + 1_000 + oauth::REFRESH_IDLE_MS));
    assert!(authenticate(&store, &next.access, at(t + 1_001)).is_ok());
    assert!(!revoked(&store, first.grant, i.dev));
    // Presenting the superseded successor is a replay: the grant goes.
    assert!(matches!(
        refresh(&store, &lost.refresh, None, at(t + 2_000)),
        Err(RefreshError::Replay)
    ));
    assert!(revoked(&store, first.grant, i.dev));
    assert!(authenticate(&store, &next.access, at(t + 2_001)).is_err());
    assert!(matches!(
        refresh(&store, &next.refresh, None, at(t + 2_002)),
        Err(RefreshError::Invalid)
    ));
}

#[test]
fn a_replay_after_grace_or_after_the_successor_was_used_revokes_and_audits() {
    let (_dir, store, i) = fixture();
    // Past the grace window.
    let first = issue(&store, login_grant(i.dev, Scopes::CLI_DEFAULT));
    let second = refresh(&store, &first.refresh, None, at(1_000)).unwrap();
    assert!(matches!(
        refresh(&store, &first.refresh, None, at(1_001 + ROTATION_GRACE_MS)),
        Err(RefreshError::Replay)
    ));
    assert!(revoked(&store, first.grant, i.dev));
    assert!(authenticate(&store, &second.access, at(2_000)).is_err());
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(audit[0].event, Event::OAuthRefreshReplay);
    assert_eq!(audit[0].subject, Some(i.dev));

    // Inside the window, but the successor was already used: no recovery.
    let first = issue(&store, login_grant(i.dev, Scopes::CLI_DEFAULT));
    let second = refresh(&store, &first.refresh, None, at(1_000)).unwrap();
    let third = refresh(&store, &second.refresh, None, at(2_000)).unwrap();
    assert!(matches!(
        refresh(&store, &first.refresh, None, at(3_000)),
        Err(RefreshError::Replay)
    ));
    assert!(authenticate(&store, &third.access, at(3_001)).is_err());
}

#[test]
fn refresh_narrows_scopes_and_never_widens_them() {
    let (_dir, store, i) = fixture();
    let first = issue(&store, login_grant(i.dev, Scopes::CLI_DEFAULT));
    let narrowed = refresh(&store, &first.refresh, Some(Scopes::RUNS_READ), at(1_000)).unwrap();
    assert_eq!(narrowed.scopes, Scopes::RUNS_READ);
    let who = authenticate(&store, &narrowed.access, at(1_001)).unwrap();
    assert_eq!(who.scopes, Scopes::RUNS_READ);
    assert_eq!(who.principal.permissions, P::READ);
    for widening in [Scopes::CACHE_WRITE, Scopes::NONE, Scopes::ALL] {
        assert!(matches!(
            refresh(&store, &narrowed.refresh, Some(widening), at(2_000)),
            Err(RefreshError::InvalidScope)
        ));
    }
    // A refused narrowing wrote nothing: the token is still live, and the
    // next refresh without narrowing returns the grant's full scopes.
    let full = refresh(&store, &narrowed.refresh, None, at(3_000)).unwrap();
    assert_eq!(full.scopes, Scopes::CLI_DEFAULT);
}

#[test]
fn a_holder_revokes_the_whole_grant_with_either_token() {
    let (_dir, store, i) = fixture();
    let by_refresh = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    oauth::revoke_presented(
        &store,
        CLI_CLIENT_ID,
        &text(Kind::Refresh, &by_refresh.refresh),
        at(1),
    )
    .unwrap();
    assert!(authenticate(&store, &by_refresh.access, at(2)).is_err());
    assert!(matches!(
        refresh(&store, &by_refresh.refresh, None, at(3)),
        Err(RefreshError::Invalid)
    ));

    let by_access = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    // Another client's revocation, codes and garbage are silently ignored.
    for ignored in [
        text(Kind::Code, &by_access.access),
        text(Kind::Device, &by_access.refresh),
        "sntl_rt_nothex".to_owned(),
        text(Kind::Refresh, &Secret::generate()),
        String::new(),
    ] {
        oauth::revoke_presented(&store, CLI_CLIENT_ID, &ignored, at(4)).unwrap();
    }
    oauth::revoke_presented(
        &store,
        "other",
        &text(Kind::Access, &by_access.access),
        at(4),
    )
    .unwrap();
    assert!(authenticate(&store, &by_access.access, at(5)).is_ok());
    oauth::revoke_presented(
        &store,
        CLI_CLIENT_ID,
        &text(Kind::Access, &by_access.access),
        at(6),
    )
    .unwrap();
    assert!(authenticate(&store, &by_access.access, at(7)).is_err());
    assert!(revoked(&store, by_access.grant, i.dev));
    // Revoking again is harmless.
    oauth::revoke_presented(
        &store,
        CLI_CLIENT_ID,
        &text(Kind::Access, &by_access.access),
        at(8),
    )
    .unwrap();
}

#[test]
fn grants_are_listed_and_revoked_only_by_their_owner_or_administrators() {
    let (_dir, store, i) = fixture();
    let own = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    let service = issue(
        &store,
        NewGrant {
            kind: GrantKind::Service,
            tenant: Some(i.tenant),
            name: Some("ci"),
            ..login_grant(i.bot, Scopes::RUNS_READ)
        },
    );
    let dev = Authority::credential(Principal::new(i.dev, P::READ, None, None));
    let listed = store.read(|c| oauth::grants(c, dev, i.dev, 10)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, own.grant);
    assert_eq!(listed[0].kind, GrantKind::Code);
    assert_eq!(listed[0].client_id, CLI_CLIENT_ID);
    assert!(!listed[0].revoked);
    // Nobody lists or revokes another account's grants by guessing.
    let second = Authority::credential(Principal::new(i.second, P::READ, None, None));
    assert!(matches!(
        store.read(|c| oauth::grants(c, second, i.dev, 10)),
        Err(Error::NotFound)
    ));
    let own_grant = own.grant;
    assert!(matches!(
        store
            .writer()
            .write(move |tx| oauth::revoke_grant(tx, second, own_grant, at(1))),
        Err(Error::NotFound)
    ));
    // The service tenant's administrator may revoke the service grant.
    let tenant_admin = Authority::credential(Principal::new(
        i.dev,
        P::REPOSITORY.union(P::TENANT_ADMIN),
        None,
        None,
    ));
    let service_grant = service.grant;
    store
        .writer()
        .write(move |tx| oauth::revoke_grant(tx, tenant_admin, service_grant, at(2)))
        .unwrap();
    assert!(revoked(&store, service.grant, i.bot));
    // And the owner their own.
    store
        .writer()
        .write(move |tx| oauth::revoke_grant(tx, dev, own_grant, at(3)))
        .unwrap();
    assert!(revoked(&store, own.grant, i.dev));
}

/// Revocations that cascade from other decisions, each in the same
/// transaction as the decision.
#[test]
fn account_tenant_and_membership_decisions_revoke_grants() {
    let (_dir, store, i) = fixture();
    let root = Principal::new(i.root, P::ALL, None, None);

    // Membership removal revokes the grants narrowed to that tenant only.
    let narrowed = issue(
        &store,
        NewGrant {
            tenant: Some(i.other),
            ..login_grant(i.dev, Scopes::RUNS_READ)
        },
    );
    let broad = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    store
        .writer()
        .write(move |tx| auth::remove_membership(tx, root, i.other, i.dev, at(1)))
        .unwrap();
    assert!(revoked(&store, narrowed.grant, i.dev));
    assert!(!revoked(&store, broad.grant, i.dev));

    // Tenant suspension revokes every grant narrowed to it, service grants too.
    let service = issue(
        &store,
        NewGrant {
            kind: GrantKind::Service,
            tenant: Some(i.tenant),
            ..login_grant(i.bot, Scopes::RUNS_READ)
        },
    );
    let suspension = store
        .writer()
        .write(move |tx| tenancy::suspend(tx, privileged(i), i.tenant, at(2)))
        .unwrap();
    assert_eq!(suspension.tokens_revoked, 1);
    assert!(revoked(&store, service.grant, i.bot));
    assert!(!revoked(&store, broad.grant, i.dev));

    // Account suspension revokes everything the account holds.
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, privileged(i), i.dev, false, at(3)))
        .unwrap();
    assert!(revoked(&store, broad.grant, i.dev));

    // Rejection revokes an approved account's grants.
    let other = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, other, "Other", false, NOW))
        .unwrap();
    let rejected = issue(&store, login_grant(other, Scopes::RUNS_READ));
    store
        .writer()
        .write(move |tx| registration::reject(tx, privileged(i), other, at(4)))
        .unwrap();
    assert!(revoked(&store, rejected.grant, other));
}

#[test]
fn password_change_and_recovery_revoke_grants() {
    let (_dir, store, i) = fixture();
    let phc = sentinel_auth::password::hash(b"first password").unwrap();
    store
        .writer()
        .write(move |tx| {
            local_auth::provision_credential(tx, privileged(i), i.dev, "dev", &phc, NOW)
        })
        .unwrap();
    let before = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    let policy = local_auth::Policy::default();
    let now = UnixMillis::now();
    let local_auth::Login::Accepted(issued) =
        local_auth::login(&store, "dev", b"first password", policy, now).unwrap()
    else {
        panic!("login refused");
    };
    let session = store
        .read(|c| local_auth::authenticate(c, &issued.session, now))
        .unwrap();
    assert!(
        local_auth::change_password(&store, &session, b"first password", b"second password", now)
            .unwrap()
    );
    assert!(revoked(&store, before.grant, i.dev));

    let again = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    local_auth::recover(&store, "dev", b"third password", now).unwrap();
    assert!(revoked(&store, again.grant, i.dev));
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(audit[0].event, Event::PasswordRecovered);
}

#[test]
fn raw_sql_cannot_widen_or_resurrect_a_grant() {
    let (_dir, store, i) = fixture();
    let minted = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    let grant = minted.grant;
    // One rotation, so a rotated row exists to try to un-rotate.
    refresh(&store, &minted.refresh, None, at(1)).unwrap();
    store
        .writer()
        .write(move |tx| oauth::revoke_grant(tx, Authority::HostLocal, grant, at(1)))
        .unwrap();
    for sql in [
        "UPDATE oauth_grants SET scopes = 1023 WHERE id = ?1",
        "UPDATE oauth_grants SET expires_ms = expires_ms + 1 WHERE id = ?1",
        "UPDATE oauth_grants SET revoked_ms = NULL, revoked_reason = NULL WHERE id = ?1",
        "UPDATE oauth_grants SET revoked_reason = 1 WHERE id = ?1",
        "UPDATE oauth_access_tokens SET expires_ms = expires_ms + 1 WHERE grant_id = ?1",
        "UPDATE oauth_refresh_tokens SET rotated_ms = NULL WHERE grant_id = ?1 AND rotated_ms IS NOT NULL",
        "UPDATE oauth_refresh_tokens SET idle_expires_ms = idle_expires_ms + 1 WHERE grant_id = ?1",
    ] {
        let outcome = store.writer().write(move |tx| {
            let changed = tx.execute(sql, [grant.as_bytes()])?;
            Ok(changed)
        });
        // Either refused, or it matched nothing it could change.
        assert!(
            matches!(outcome, Err(Error::Sqlite(_)) | Ok(0)),
            "{sql}: {outcome:?}"
        );
    }
    let widened = store.writer().write(move |tx| {
        tx.execute(
            "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
                created_ms, expires_ms) VALUES (?1, ?2, 9, 1023, 1, 2)",
            rusqlite::params![[7u8; 32], grant.as_bytes()],
        )?;
        Ok(())
    });
    assert!(matches!(widened, Err(Error::Sqlite(_))));
    assert!(revoked(&store, grant, i.dev));
}

#[test]
fn purging_is_bounded_and_spares_live_grants() {
    let (_dir, store, i) = fixture();
    let live = issue(&store, login_grant(i.dev, Scopes::RUNS_READ));
    let mut dead = Vec::new();
    for _ in 0..3 {
        let minted = issue(
            &store,
            NewGrant {
                lifetime_ms: 1_000,
                ..login_grant(i.dev, Scopes::RUNS_READ)
            },
        );
        dead.push(minted.grant);
    }
    let later = at(oauth::ACCESS_LIFETIME_MS + 1);
    let mut removed = 0;
    for _ in 0..10 {
        let pass = oauth::purge_expired(&store, later, 1).unwrap();
        if pass == 0 {
            break;
        }
        // One of each kind at most, plus one grant and what hangs off it.
        assert!(pass <= 1 + 1 + 1 + 1 + 1 + 5, "{pass}");
        removed += pass;
    }
    assert!(removed >= 3, "{removed}");
    let remaining = store
        .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 100))
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, live.grant);
    // The live grant's refresh token still rotates.
    refresh(&store, &live.refresh, None, later).unwrap();
}
