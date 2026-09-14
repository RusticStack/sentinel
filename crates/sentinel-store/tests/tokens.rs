//! A03 behavior: host-local provisioning, scoped and expiring credentials,
//! hashed secrets, delegation limits, revocation and reuse of the A01 layer.

use sentinel_auth::{secret::Secret, token};
use sentinel_core::{
    RepoId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    tokens::{self, Grant},
};

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}
const NOW: UnixMillis = UnixMillis(1_000);

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    dev: UserId,
    outsider: UserId,
    bot: UserId,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    other_repo: RepoId,
}

/// One organization with a developer tenant admin, a tenant-bound service
/// principal, an unrelated tenant and an account with no membership at all.
fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        dev: UserId::new(),
        outsider: UserId::new(),
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
            provisioning::insert_human(tx, i.dev, "Dev", false, NOW)?;
            provisioning::insert_human(tx, i.outsider, "Outsider", false, NOW)?;
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
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            auth::create_repo(tx, root, i.other, i.other_repo, "app", NOW)?;
            auth::create_service_account(tx, root, i.tenant, i.bot, "bot", Role::Operator, NOW)?;
            Ok(())
        })
        .unwrap();
    (dir, store, i)
}

fn stepped(i: Ids) -> local_auth::Authority {
    local_auth::Authority::Credential {
        principal: admin(i),
        stepped_up: true,
    }
}

fn admin(i: Ids) -> Principal {
    Principal::new(i.root, P::ALL, None, None)
}

fn authenticate(store: &Store, secret: &Secret, now: UnixMillis) -> Result<Principal, Error> {
    store.read(|conn| tokens::authenticate(conn, secret, now).map(|auth| auth.principal))
}

#[test]
fn a_host_local_credential_authenticates_through_the_ordinary_authorization_layer() {
    let (_dir, store, i) = fixture();
    let grant = Grant {
        tenant: Some(i.tenant),
        repo: Some(i.repo),
        ..Grant::new(i.dev, "laptop cli", P::READ.union(P::RUN))
    };
    let granted = tokens::provision(&store, grant, NOW).unwrap();

    let principal = authenticate(&store, &granted.secret, at(2_000)).unwrap();
    assert_eq!(principal.user, i.dev);
    assert_eq!(principal.tenant, Some(i.tenant));
    assert_eq!(principal.repo, Some(i.repo));
    assert!(principal.permissions.contains(P::RUN));
    assert!(!principal.permissions.contains(P::WRITE_SECRETS));

    // The credential is not authority by itself: A01 decides, live.
    store
        .read(|conn| auth::require_repo(conn, principal, i.repo, P::RUN))
        .unwrap();
    assert!(matches!(
        store.read(|conn| auth::require_repo(conn, principal, i.other_repo, P::READ)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.read(|conn| auth::require_repo(conn, principal, i.repo, P::WRITE_SECRETS)),
        Err(Error::NotFound)
    ));
    // Losing the membership behind the credential ends its access at once.
    store
        .writer()
        .write(move |tx| auth::remove_membership(tx, admin(i), i.tenant, i.dev))
        .unwrap();
    assert!(matches!(
        store.read(|conn| auth::require_repo(conn, principal, i.repo, P::READ)),
        Err(Error::NotFound)
    ));
}

#[test]
fn the_secret_is_shown_once_and_stored_only_as_a_digest() {
    let (_dir, store, i) = fixture();
    let granted = tokens::provision(&store, Grant::new(i.dev, "cli", P::READ), NOW).unwrap();
    let text = token::format(&granted.secret);
    assert!(text.starts_with(token::PREFIX));

    let found: i64 = store
        .read(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM api_tokens WHERE hex(token_digest) = upper(?1) OR name = ?1",
                [text.trim_start_matches(token::PREFIX)],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(found, 0);

    // Only the exact presented secret validates.
    assert!(authenticate(&store, &Secret::generate(), NOW).is_err());
    let presented = token::parse(&token::format(&granted.secret)).unwrap();
    assert!(authenticate(&store, &presented, NOW).is_ok());
}

#[test]
fn credentials_expire_and_expiry_is_bounded_at_issuance() {
    let (_dir, store, i) = fixture();
    let grant = Grant {
        lifetime_ms: 5_000,
        ..Grant::new(i.dev, "short lived", P::READ)
    };
    let granted = tokens::provision(&store, grant, NOW).unwrap();
    assert_eq!(granted.expires.0, 6_000);
    assert!(authenticate(&store, &granted.secret, at(5_999)).is_ok());
    assert!(matches!(
        authenticate(&store, &granted.secret, at(6_000)),
        Err(Error::NotFound)
    ));

    for lifetime in [0, -1, tokens::MAX_LIFETIME_MS + 1] {
        let refused = tokens::provision(
            &store,
            Grant {
                lifetime_ms: lifetime,
                ..Grant::new(i.dev, "unbounded", P::READ)
            },
            NOW,
        );
        assert!(matches!(
            refused,
            Err(Error::InvalidInput("credential lifetime"))
        ));
    }
    const { assert!(tokens::DEFAULT_LIFETIME_MS <= tokens::MAX_LIFETIME_MS) };
}

#[test]
fn an_empty_or_undefined_scope_is_refused_rather_than_defaulted() {
    let (_dir, store, i) = fixture();
    for permissions in [P::NONE, P::from_bits(0b0010_0000).unwrap_or(P::NONE)] {
        assert!(matches!(
            tokens::provision(&store, Grant::new(i.dev, "empty", permissions), NOW),
            Err(Error::InvalidInput("credential scope"))
        ));
    }
    assert!(
        P::from_bits(0b0010_0000).is_none(),
        "undefined bit accepted"
    );
    assert!(matches!(
        tokens::provision(&store, Grant::new(i.dev, "", P::READ), NOW),
        Err(Error::InvalidInput("credential name"))
    ));
    assert!(matches!(
        tokens::provision(
            &store,
            Grant {
                repo: Some(i.repo),
                ..Grant::new(i.dev, "repo without tenant", P::READ)
            },
            NOW
        ),
        Err(Error::InvalidInput("repository scope without its tenant"))
    ));
}

#[test]
fn a_repository_scope_cannot_point_across_an_ownership_boundary() {
    let (_dir, store, i) = fixture();
    let refused = tokens::provision(
        &store,
        Grant {
            tenant: Some(i.tenant),
            repo: Some(i.other_repo),
            ..Grant::new(i.dev, "crossed", P::READ)
        },
        NOW,
    );
    assert!(matches!(refused, Err(Error::Sqlite(_))));
}

#[test]
fn platform_scope_needs_a_super_admin_and_is_dropped_when_the_role_goes() {
    let (_dir, store, i) = fixture();
    assert!(matches!(
        tokens::provision(
            &store,
            Grant::new(i.dev, "escalation", P::PLATFORM_ADMIN),
            NOW
        ),
        Err(Error::Sqlite(_))
    ));

    let granted = tokens::provision(
        &store,
        Grant::new(i.root, "platform", P::READ.union(P::PLATFORM_ADMIN)),
        NOW,
    )
    .unwrap();
    let principal = authenticate(&store, &granted.secret, at(2_000)).unwrap();
    assert!(principal.permissions.contains(P::PLATFORM_ADMIN));
    store
        .read(|conn| auth::require_platform_admin(conn, principal))
        .unwrap();

    // Demote: the stored scope is a ceiling, not a grant.
    let deputy = UserId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, deputy, "Deputy", true, NOW)?;
            local_auth::set_super_admin(tx, stepped(i), i.root, false, at(2_100))
        })
        .unwrap();
    let principal = authenticate(&store, &granted.secret, at(2_200)).unwrap();
    assert!(!principal.permissions.contains(P::PLATFORM_ADMIN));
    assert!(principal.permissions.contains(P::READ));
    assert!(matches!(
        store.read(|conn| auth::require_platform_admin(conn, principal)),
        Err(Error::Forbidden)
    ));
}

#[test]
fn delegation_can_only_narrow_and_only_where_authority_already_exists() {
    let (_dir, store, i) = fixture();
    let dev = Principal::new(i.dev, P::READ.union(P::RUN), Some(i.tenant), None);

    // Self-issue inside the caller's own scope.
    let granted = store
        .writer()
        .write(move |tx| {
            tokens::issue(
                tx,
                dev,
                Grant {
                    tenant: Some(i.tenant),
                    ..Grant::new(i.dev, "self", P::READ)
                },
                NOW,
            )
        })
        .unwrap();
    assert!(authenticate(&store, &granted.secret, NOW).is_ok());

    // Wider than the caller holds, or for another human, or outside the
    // caller's tenant: refused.
    for grant in [
        Grant {
            tenant: Some(i.tenant),
            ..Grant::new(i.dev, "wider", P::WRITE_SECRETS)
        },
        Grant {
            tenant: Some(i.tenant),
            ..Grant::new(i.outsider, "someone else", P::READ)
        },
        Grant {
            tenant: Some(i.other),
            ..Grant::new(i.dev, "elsewhere", P::READ)
        },
        Grant::new(i.dev, "unscoped", P::READ),
    ] {
        let refused = store
            .writer()
            .write(move |tx| tokens::issue(tx, dev, grant, NOW).map(|_| ()));
        assert!(matches!(refused, Err(Error::Forbidden)), "{:?}", grant.name);
    }
}

#[test]
fn a_tenant_admin_may_issue_for_its_own_service_principal_only() {
    let (_dir, store, i) = fixture();
    let dev = Principal::new(i.dev, P::ALL, None, None);
    let granted = store
        .writer()
        .write(move |tx| {
            tokens::issue(
                tx,
                dev,
                Grant {
                    tenant: Some(i.tenant),
                    ..Grant::new(i.bot, "deploy agent", P::READ.union(P::RUN))
                },
                NOW,
            )
        })
        .unwrap();
    let principal = authenticate(&store, &granted.secret, NOW).unwrap();
    assert_eq!(principal.user, i.bot);
    assert_eq!(principal.tenant, Some(i.tenant));

    // A service credential cannot be scoped outside its home tenant, and the
    // admin of an unrelated tenant cannot issue for it.
    assert!(matches!(
        tokens::provision(
            &store,
            Grant {
                tenant: Some(i.other),
                ..Grant::new(i.bot, "roaming", P::READ)
            },
            NOW
        ),
        Err(Error::Sqlite(_))
    ));
    assert!(matches!(
        tokens::provision(&store, Grant::new(i.bot, "unscoped bot", P::READ), NOW),
        Err(Error::Sqlite(_))
    ));
    let outsider = Principal::new(i.outsider, P::ALL, None, None);
    let refused = store.writer().write(move |tx| {
        tokens::issue(
            tx,
            outsider,
            Grant {
                tenant: Some(i.tenant),
                ..Grant::new(i.bot, "hijack", P::READ)
            },
            NOW,
        )
        .map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn revocation_is_immediate_final_and_reaches_the_whole_account() {
    let (_dir, store, i) = fixture();
    let first = tokens::provision(&store, Grant::new(i.dev, "one", P::READ), NOW).unwrap();
    let second = tokens::provision(&store, Grant::new(i.dev, "two", P::READ), NOW).unwrap();

    let owner = Principal::new(i.dev, P::READ, None, None);
    let id = first.id;
    store
        .writer()
        .write(move |tx| tokens::revoke(tx, Authority::credential(owner), id, at(2_000)))
        .unwrap();
    assert!(matches!(
        authenticate(&store, &first.secret, at(2_100)),
        Err(Error::NotFound)
    ));
    assert!(authenticate(&store, &second.secret, at(2_100)).is_ok());

    // A revoked credential cannot be brought back by a raw update.
    let revive = store.writer().write(move |tx| {
        tx.execute("UPDATE api_tokens SET revoked_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(revive, Err(Error::Sqlite(_))));

    // Suspending the account takes its remaining credentials with it.
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, stepped(i), i.dev, false, at(2_200)))
        .unwrap();
    assert!(matches!(
        authenticate(&store, &second.secret, at(2_300)),
        Err(Error::NotFound)
    ));
}

#[test]
fn another_account_cannot_revoke_list_or_learn_of_a_credential() {
    let (_dir, store, i) = fixture();
    let granted = tokens::provision(&store, Grant::new(i.dev, "private", P::READ), NOW).unwrap();
    let outsider = Principal::new(i.outsider, P::ALL, None, None);

    let id = granted.id;
    let refused = store
        .writer()
        .write(move |tx| tokens::revoke(tx, Authority::credential(outsider), id, at(2_000)));
    assert!(matches!(refused, Err(Error::NotFound)));
    assert!(matches!(
        store.read(|conn| tokens::list(conn, Authority::credential(outsider), i.dev, 10)),
        Err(Error::NotFound)
    ));
    // A guessed identifier is not a discovery channel either.
    let refused = store.writer().write(move |tx| {
        tokens::revoke(
            tx,
            Authority::credential(admin(i)),
            TokenId::new(),
            at(2_000),
        )
    });
    assert!(matches!(refused, Err(Error::NotFound)));
    assert!(authenticate(&store, &granted.secret, at(2_100)).is_ok());
}

#[test]
fn listing_returns_metadata_and_records_use_without_the_secret() {
    let (_dir, store, i) = fixture();
    let granted = tokens::provision(
        &store,
        Grant {
            tenant: Some(i.tenant),
            repo: Some(i.repo),
            ..Grant::new(i.dev, "laptop cli", P::READ.union(P::RUN))
        },
        NOW,
    )
    .unwrap();
    let owner = Principal::new(i.dev, P::READ, None, None);

    let authenticated = store
        .read(|conn| tokens::authenticate(conn, &granted.secret, at(2_000)))
        .unwrap();
    assert!(authenticated.record_use_due(at(2_000)));
    tokens::record_use(&store, authenticated.token, at(2_000)).unwrap();
    let authenticated = store
        .read(|conn| tokens::authenticate(conn, &granted.secret, at(2_001)))
        .unwrap();
    assert!(!authenticated.record_use_due(at(2_001)));

    let records = store
        .read(|conn| tokens::list(conn, Authority::credential(owner), i.dev, 10))
        .unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.id, granted.id);
    assert_eq!(record.name, "laptop cli");
    assert_eq!(record.permissions, P::READ.union(P::RUN));
    assert_eq!(record.tenant, Some(i.tenant));
    assert_eq!(record.repo, Some(i.repo));
    assert_eq!(record.last_used, Some(at(2_000)));
    assert!(!record.revoked);
    let mut text = String::new();
    granted.secret.expose(&mut text);
    assert!(!format!("{record:?}").contains(&text));
    assert!(
        store
            .read(|conn| tokens::list(conn, Authority::credential(owner), i.dev, 0))
            .is_err()
    );
}

#[test]
fn issuance_and_revocation_are_audited_and_expired_records_are_purged() {
    let (_dir, store, i) = fixture();
    let granted = tokens::provision(&store, Grant::new(i.dev, "agent", P::READ), NOW).unwrap();
    tokens::revoke_host_local(&store, granted.id, at(2_000)).unwrap();
    assert!(matches!(
        authenticate(&store, &granted.secret, at(2_100)),
        Err(Error::NotFound)
    ));

    let records = store
        .read(|conn| local_auth::recent_audit(conn, 10))
        .unwrap();
    let issued = records
        .iter()
        .find(|r| r.event == local_auth::Event::TokenIssued)
        .expect("issuance is audited");
    assert!(issued.host_local);
    assert_eq!(issued.subject, Some(i.dev));
    assert_eq!(issued.detail.as_deref(), Some("agent"));
    assert!(
        records
            .iter()
            .any(|r| r.event == local_auth::Event::TokenRevoked && r.host_local)
    );

    let live = tokens::provision(&store, Grant::new(i.dev, "live", P::READ), at(2_200)).unwrap();
    let stale = tokens::provision(
        &store,
        Grant {
            lifetime_ms: 10,
            ..Grant::new(i.dev, "stale", P::READ)
        },
        at(2_200),
    )
    .unwrap();
    assert_eq!(tokens::purge_expired(&store, at(3_000), 1).unwrap(), 1);
    assert_eq!(tokens::purge_expired(&store, at(3_000), 10).unwrap(), 1);
    assert_eq!(tokens::purge_expired(&store, at(3_000), 10).unwrap(), 0);
    assert!(authenticate(&store, &stale.secret, at(3_000)).is_err());
    assert!(authenticate(&store, &live.secret, at(3_000)).is_ok());
}

#[test]
fn a_credential_cannot_be_widened_or_moved_after_issuance() {
    let (_dir, store, i) = fixture();
    let granted = tokens::provision(
        &store,
        Grant {
            tenant: Some(i.tenant),
            ..Grant::new(i.dev, "narrow", P::READ)
        },
        NOW,
    )
    .unwrap();
    for raw in [
        "UPDATE api_tokens SET permissions = 31",
        "UPDATE api_tokens SET tenant_id = NULL",
        "UPDATE api_tokens SET expires_ms = expires_ms + 1000",
        "UPDATE api_tokens SET user_id = (SELECT id FROM users WHERE display_name = 'Root')",
    ] {
        let refused = store.writer().write(move |tx| {
            tx.execute(raw, [])?;
            Ok(())
        });
        assert!(
            matches!(refused, Err(Error::Sqlite(_))),
            "{raw} was allowed"
        );
    }
    let principal = authenticate(&store, &granted.secret, at(2_000)).unwrap();
    assert_eq!(principal.permissions, P::READ);
    assert_eq!(principal.tenant, Some(i.tenant));
}
