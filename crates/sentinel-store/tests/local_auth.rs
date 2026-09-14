//! A02 behavior: host-local bootstrap, local login, opaque sessions, expiry and
//! revocation, CSRF/cookie policy, audited recovery and last-admin protection.

use sentinel_auth::{cookie, secret::Secret};
use sentinel_core::{
    UnixMillis, UserId,
    auth::{Permissions, Principal},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::provisioning,
    local_auth::{self, Event, Login, Policy},
};

const PASSWORD: &[u8] = b"an acceptable operator password";
const OTHER: &[u8] = b"a different operator password";

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    (dir, store)
}

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

/// An authority whose session proved a second factor just now.
fn stepped(principal: Principal) -> local_auth::Authority {
    local_auth::Authority::Credential {
        principal,
        stepped_up: true,
    }
}

fn accept(login: Login) -> local_auth::Issued {
    match login {
        Login::Accepted(issued) => issued,
        Login::Rejected => panic!("login rejected"),
        Login::Locked { until } => panic!("login locked until {}", until.0),
    }
}

fn bootstrapped(store: &Store) -> (UserId, local_auth::Issued) {
    let user = local_auth::bootstrap(store, "root", "Root Operator", PASSWORD, at(1_000)).unwrap();
    let issued =
        accept(local_auth::login(store, "root", PASSWORD, Policy::default(), at(2_000)).unwrap());
    (user, issued)
}

fn events(store: &Store) -> Vec<Event> {
    store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap()
        .into_iter()
        .map(|record| record.event)
        .collect()
}

#[test]
fn bootstrap_admits_exactly_one_first_admin_and_then_disables_itself() {
    let (_dir, store) = store();
    assert!(store.read(local_auth::bootstrap_available).unwrap());
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(1_000)).unwrap();

    assert!(!store.read(local_auth::bootstrap_available).unwrap());
    assert!(matches!(
        local_auth::bootstrap(&store, "second", "Second", OTHER, at(1_100)),
        Err(Error::Forbidden)
    ));
    let count: i64 = store
        .read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM local_credentials", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(count, 1);

    let super_admin: bool = store
        .read(move |conn| {
            conn.query_row(
                "SELECT super_admin FROM users WHERE id = ?1",
                [root.as_bytes()],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert!(super_admin);
    assert_eq!(events(&store), [Event::Bootstrap]);
}

#[test]
fn an_existing_active_super_admin_blocks_bootstrap_even_without_the_latch() {
    let (_dir, store) = store();
    let existing = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, existing, "prior", true, at(1)))
        .unwrap();
    assert!(!store.read(local_auth::bootstrap_available).unwrap());
    assert!(matches!(
        local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(2)),
        Err(Error::Forbidden)
    ));
}

#[test]
fn only_the_right_password_issues_a_session_and_it_carries_platform_authority() {
    let (_dir, store) = store();
    let (root, issued) = bootstrapped(&store);
    assert_eq!(issued.user, root);

    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(3_000)))
        .unwrap();
    assert_eq!(session.user, root);
    assert!(session.super_admin);
    let principal = session.principal();
    assert!(principal.permissions.contains(Permissions::PLATFORM_ADMIN));
    assert!(principal.tenant.is_none() && principal.repo.is_none());

    assert!(matches!(
        local_auth::login(&store, "root", OTHER, Policy::default(), at(3_100)).unwrap(),
        Login::Rejected
    ));
    assert!(matches!(
        local_auth::login(&store, "nobody", PASSWORD, Policy::default(), at(3_200)).unwrap(),
        Login::Rejected
    ));
    assert!(matches!(
        local_auth::login(&store, "Root", PASSWORD, Policy::default(), at(3_300)).unwrap(),
        Login::Rejected
    ));
    assert_eq!(
        events(&store),
        [
            Event::LoginRejected,
            Event::LoginRejected,
            Event::LoginRejected,
            Event::LoginAccepted,
            Event::Bootstrap
        ]
    );
}

#[test]
fn an_unrelated_or_forged_cookie_authenticates_nobody() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let forged = Secret::generate();
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &forged, at(3_000))),
        Err(Error::NotFound)
    ));

    // The stored row is a digest: the database never holds a usable cookie.
    let mut text = String::new();
    issued.session.expose(&mut text);
    let stored: i64 = store
        .read(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE hex(token_digest) = upper(?1)",
                [&text],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(stored, 0);
}

#[test]
fn sessions_expire_on_idle_and_absolute_deadlines_and_refresh_cannot_exceed_them() {
    let (_dir, store) = store();
    local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(0)).unwrap();
    let policy = Policy {
        idle_ms: 1_000,
        absolute_ms: 2_500,
        refresh_after_ms: 200,
        ..Policy::default()
    };
    let issued = accept(local_auth::login(&store, "root", PASSWORD, policy, at(0)).unwrap());

    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(900)))
        .unwrap();
    assert_eq!(session.idle_deadline.0, 1_000);
    assert!(local_auth::refresh_due(&session, policy, at(900)));
    local_auth::refresh(&store, &issued.session, policy, at(900)).unwrap();
    // Idle slid forward from the refreshing request, not from issuance.
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(1_400)))
        .unwrap();
    assert_eq!(session.idle_deadline.0, 1_900);
    // The absolute deadline is the ceiling: refreshing cannot pass it.
    local_auth::refresh(&store, &issued.session, policy, at(1_800)).unwrap();
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(1_800)))
        .unwrap();
    assert_eq!(session.idle_deadline.0, 2_500);
    assert!(!local_auth::refresh_due(&session, policy, at(1_800)));
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &issued.session, at(2_500))),
        Err(Error::NotFound)
    ));
    // Refreshing an expired session does not resurrect it.
    local_auth::refresh(&store, &issued.session, policy, at(2_600)).unwrap();
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &issued.session, at(2_600))),
        Err(Error::NotFound)
    ));

    let idle = accept(local_auth::login(&store, "root", PASSWORD, policy, at(3_000)).unwrap());
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &idle.session, at(4_001))),
        Err(Error::NotFound)
    ));
}

#[test]
fn logout_and_logout_all_revoke_immediately_and_irreversibly() {
    let (_dir, store) = store();
    let (_root, first) = bootstrapped(&store);
    let second =
        accept(local_auth::login(&store, "root", PASSWORD, Policy::default(), at(2_100)).unwrap());

    local_auth::logout(&store, &first.session, at(2_200)).unwrap();
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &first.session, at(2_300))),
        Err(Error::NotFound)
    ));
    let session = store
        .read(|conn| local_auth::authenticate(conn, &second.session, at(2_300)))
        .unwrap();

    assert_eq!(
        local_auth::logout_all(&store, &session, at(2_400)).unwrap(),
        1
    );
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &second.session, at(2_500))),
        Err(Error::NotFound)
    ));
    // A revoked session cannot be un-revoked by a raw update.
    let revive = store.writer().write(move |tx| {
        tx.execute("UPDATE sessions SET revoked_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(revive, Err(Error::Sqlite(_))));
    assert!(events(&store).contains(&Event::LogoutAll));
}

#[test]
fn repeated_failures_lock_the_account_and_a_correct_password_cannot_unlock_it() {
    let (_dir, store) = store();
    local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(0)).unwrap();
    let policy = Policy {
        max_failures: 3,
        lockout_ms: 60_000,
        ..Policy::default()
    };
    for attempt in 0..3 {
        assert!(matches!(
            local_auth::login(&store, "root", OTHER, policy, at(attempt)).unwrap(),
            Login::Rejected
        ));
    }
    let locked = local_auth::login(&store, "root", PASSWORD, policy, at(10)).unwrap();
    let Login::Locked { until } = locked else {
        panic!("expected a lockout");
    };
    assert_eq!(until.0, 60_002);
    // The lockout is a window, not a permanent state.
    assert!(matches!(
        local_auth::login(&store, "root", PASSWORD, policy, at(60_003)).unwrap(),
        Login::Accepted(_)
    ));
    assert!(events(&store).contains(&Event::LoginLocked));
}

#[test]
fn host_local_recovery_resets_the_password_revokes_sessions_and_is_audited() {
    let (_dir, store) = store();
    let (root, issued) = bootstrapped(&store);
    let policy = Policy {
        max_failures: 1,
        ..Policy::default()
    };
    assert!(matches!(
        local_auth::login(&store, "root", OTHER, policy, at(2_100)).unwrap(),
        Login::Rejected
    ));

    assert_eq!(
        local_auth::recover(&store, "root", OTHER, at(3_000)).unwrap(),
        root
    );
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &issued.session, at(3_100))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        local_auth::login(&store, "root", OTHER, policy, at(3_200)).unwrap(),
        Login::Accepted(_)
    ));
    assert!(matches!(
        local_auth::login(&store, "root", PASSWORD, policy, at(3_300)).unwrap(),
        Login::Rejected
    ));
    assert!(matches!(
        local_auth::recover(&store, "absent", OTHER, at(3_400)),
        Err(Error::NotFound)
    ));

    let recovery = store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap()
        .into_iter()
        .find(|record| record.event == Event::PasswordRecovered)
        .expect("recovery is audited");
    assert!(recovery.host_local);
    assert_eq!(recovery.subject, Some(root));
    assert_eq!(recovery.detail.as_deref(), Some("root"));
}

#[test]
fn changing_a_password_requires_the_current_one_and_rotates_every_session() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2_100)))
        .unwrap();

    assert!(!local_auth::change_password(&store, &session, OTHER, OTHER, at(2_200)).unwrap());
    assert!(matches!(
        local_auth::change_password(&store, &session, PASSWORD, b"short", at(2_300)),
        Err(Error::InvalidInput("password"))
    ));
    assert!(local_auth::change_password(&store, &session, PASSWORD, OTHER, at(2_400)).unwrap());

    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &issued.session, at(2_500))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        local_auth::login(&store, "root", PASSWORD, Policy::default(), at(2_600)).unwrap(),
        Login::Rejected
    ));
    assert!(matches!(
        local_auth::login(&store, "root", OTHER, Policy::default(), at(2_700)).unwrap(),
        Login::Accepted(_)
    ));
}

#[test]
fn the_last_active_super_admin_cannot_be_demoted_suspended_or_deleted() {
    let (_dir, store) = store();
    let (root, issued) = bootstrapped(&store);
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2_100)))
        .unwrap();
    let principal = session.principal();

    for raw in [
        "UPDATE users SET super_admin = 0",
        "UPDATE users SET active = 0",
        "DELETE FROM users",
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
    let refused = store.writer().write(move |tx| {
        local_auth::set_super_admin(tx, stepped(principal), root, false, at(2_200))
    });
    assert!(matches!(refused, Err(Error::Sqlite(_))));

    // With a second active super admin, demotion is allowed and revokes the
    // demoted account's sessions in the same transaction.
    let deputy = UserId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, deputy, "Deputy", true, at(2_300))?;
            local_auth::set_super_admin(tx, stepped(principal), root, false, at(2_400))
        })
        .unwrap();
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &issued.session, at(2_500))),
        Err(Error::NotFound)
    ));
    let refused = store.writer().write(move |tx| {
        local_auth::set_super_admin(tx, stepped(principal), deputy, false, at(2_600))
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn suspending_an_account_invalidates_its_live_cookies_at_once() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let admin = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2_100)))
        .unwrap()
        .principal();

    let member = UserId::new();
    let phc = sentinel_auth::password::hash(PASSWORD).unwrap();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, member, "Member", false, at(2_200))?;
            local_auth::provision_credential(tx, admin, member, "member", &phc, at(2_200))
        })
        .unwrap();
    let theirs = accept(
        local_auth::login(&store, "member", PASSWORD, Policy::default(), at(2_300)).unwrap(),
    );
    assert!(
        !store
            .read(|conn| local_auth::authenticate(conn, &theirs.session, at(2_400)))
            .unwrap()
            .super_admin
    );

    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, stepped(admin), member, false, at(2_500)))
        .unwrap();
    assert!(matches!(
        store.read(|conn| local_auth::authenticate(conn, &theirs.session, at(2_600))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        local_auth::login(&store, "member", PASSWORD, Policy::default(), at(2_700)).unwrap(),
        Login::Rejected
    ));
}

#[test]
fn credentials_and_sessions_are_refused_for_non_human_principals() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let admin = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2_100)))
        .unwrap()
        .principal();

    let tenant = sentinel_core::TenantId::new();
    let bot = UserId::new();
    let phc = sentinel_auth::password::hash(PASSWORD).unwrap();
    store
        .writer()
        .write(move |tx| {
            sentinel_store::auth::create_namespace(
                tx,
                admin,
                tenant,
                sentinel_core::auth::Namespace::parse("acme").unwrap(),
                sentinel_store::auth::NamespaceKind::Organization,
                at(2_200),
            )?;
            sentinel_store::auth::create_service_account(
                tx,
                admin,
                tenant,
                bot,
                "bot",
                sentinel_core::auth::Role::Operator,
                at(2_200),
            )
        })
        .unwrap();
    let refused = store
        .writer()
        .write(move |tx| local_auth::provision_credential(tx, admin, bot, "bot", &phc, at(2_300)));
    assert!(matches!(refused, Err(Error::Sqlite(_))));
}

#[test]
fn administration_requires_explicit_platform_scope_not_merely_a_session() {
    let (_dir, store) = store();
    let (root, issued) = bootstrapped(&store);
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2_100)))
        .unwrap();
    let target = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, target, "Target", false, at(2_200)))
        .unwrap();

    // Same human, credential scope narrowed below platform administration.
    let narrowed = Principal::new(root, Permissions::REPOSITORY, None, None);
    let refused = store
        .writer()
        .write(move |tx| local_auth::set_active(tx, stepped(narrowed), target, false, at(2_300)));
    assert!(matches!(refused, Err(Error::Forbidden)));
    store
        .writer()
        .write(move |tx| {
            local_auth::set_active(tx, stepped(session.principal()), target, false, at(2_400))
        })
        .unwrap();
}

#[test]
fn the_audit_trail_is_append_only_and_records_no_credential_material() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let mut cookie_value = String::new();
    issued.session.expose(&mut cookie_value);

    for raw in [
        "UPDATE auth_audit SET event = 1",
        "DELETE FROM auth_audit",
        "UPDATE bootstrap SET completed_ms = 0",
        "DELETE FROM bootstrap",
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

    let dumped: String = store
        .read(|conn| {
            conn.query_row(
                "SELECT group_concat(COALESCE(detail, '') || event) FROM auth_audit",
                [],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert!(!dumped.contains(&cookie_value));
    assert!(!dumped.contains("argon2"));
    assert!(
        store
            .read(|conn| local_auth::recent_audit(conn, 0))
            .is_err()
    );
}

#[test]
fn expired_and_revoked_sessions_are_purged_without_touching_live_ones() {
    let (_dir, store) = store();
    local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(0)).unwrap();
    let short = Policy {
        idle_ms: 100,
        absolute_ms: 100,
        ..Policy::default()
    };
    for start in 0..3 {
        accept(local_auth::login(&store, "root", PASSWORD, short, at(start)).unwrap());
    }
    let live =
        accept(local_auth::login(&store, "root", PASSWORD, Policy::default(), at(500)).unwrap());

    assert_eq!(local_auth::purge_expired(&store, at(1_000), 2).unwrap(), 2);
    assert_eq!(local_auth::purge_expired(&store, at(1_000), 10).unwrap(), 1);
    assert_eq!(local_auth::purge_expired(&store, at(1_000), 10).unwrap(), 0);
    assert!(
        store
            .read(|conn| local_auth::authenticate(conn, &live.session, at(1_000)))
            .is_ok()
    );
}

#[test]
fn the_cookie_and_csrf_policy_binds_a_state_change_to_its_own_session() {
    let (_dir, store) = store();
    let (_root, issued) = bootstrapped(&store);
    let header = cookie::issue(cookie::SESSION_COOKIE, &issued.session, issued.max_age_secs);
    assert!(header.contains("; Secure; HttpOnly; SameSite=Strict"));

    let presented =
        cookie::read(cookie::SESSION_COOKIE, header.split(';').next().unwrap()).unwrap();
    let session = store
        .read(|conn| local_auth::authenticate(conn, &presented, at(2_200)))
        .unwrap();

    let mut csrf = String::new();
    issued.csrf.expose(&mut csrf);
    assert!(cookie::csrf_accepted(&session.csrf, Some(&csrf)));
    assert!(!cookie::csrf_accepted(&session.csrf, None));

    // Another session's CSRF secret is not accepted for this one.
    let other =
        accept(local_auth::login(&store, "root", PASSWORD, Policy::default(), at(2_300)).unwrap());
    let mut other_csrf = String::new();
    other.csrf.expose(&mut other_csrf);
    assert!(!cookie::csrf_accepted(&session.csrf, Some(&other_csrf)));
    // The session cookie value is not usable as its own CSRF secret.
    let mut cookie_value = String::new();
    issued.session.expose(&mut cookie_value);
    assert!(!cookie::csrf_accepted(&session.csrf, Some(&cookie_value)));
}
