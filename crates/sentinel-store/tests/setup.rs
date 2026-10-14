//! First-run setup and self-service organizations: the behavior a person at
//! the wizard or an attacker against it can observe, and the failure paths.

use rusqlite::params;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    TenantId, UnixMillis,
    auth::{Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store, email,
    local_auth::{self, Login, Policy},
    organizations,
    registration::{
        self, Admission, Applicant, Authority, DeploymentPolicy, InstallationBinding, Registration,
        TenantCreation, Terms,
    },
    setup::{self, Setup},
};

const PASSWORD: &[u8] = b"a long enough administrator password";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn open() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    (dir, store)
}

fn request<'a>(token: &'a Secret, email: &'a str) -> Setup<'a> {
    Setup {
        token,
        email,
        display_name: "Ada",
        password: PASSWORD,
        registration: Registration::ApprovalRequired,
        tenant_creation: TenantCreation::ApprovedUsers,
        instance_name: "Acme CI",
        base_url: Some("https://ci.example.com"),
        personal_namespace: None,
        organization: None,
    }
}

fn count(store: &Store, sql: &'static str) -> i64 {
    store
        .read(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?))
        .unwrap()
}

fn nothing_was_created(store: &Store) {
    assert_eq!(count(store, "SELECT COUNT(*) FROM users"), 0);
    assert_eq!(count(store, "SELECT COUNT(*) FROM bootstrap"), 0);
    assert_eq!(count(store, "SELECT COUNT(*) FROM instance_settings"), 0);
    assert_eq!(count(store, "SELECT COUNT(*) FROM tenants"), 0);
}

#[test]
fn setup_creates_the_administrator_policy_and_session_in_one_commit() {
    let (_dir, store) = open();
    assert!(store.read(setup::is_open).unwrap());
    let token = setup::issue(&store, at(1_000)).unwrap().unwrap();
    let done = setup::complete(
        &store,
        &Setup {
            personal_namespace: Some("ada"),
            organization: Some("acme"),
            ..request(&token, "Ada@Example.COM")
        },
        Policy::default(),
        at(2_000),
    )
    .unwrap();

    // The latch the CLI bootstrap uses is the one that closed.
    assert!(!store.read(setup::is_open).unwrap());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM bootstrap"), 1);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM setup_token"), 0);
    assert!(matches!(
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(3_000)),
        Err(Error::Forbidden)
    ));

    // A verified, canonical address; the administrator signs in with it.
    let (address, verified) = store
        .read(|c| email::account_email(c, done.user))
        .unwrap()
        .unwrap();
    assert_eq!(address, "ada@example.com");
    assert!(verified);
    let login = local_auth::login(
        &store,
        "ada@example.com",
        PASSWORD,
        Policy::default(),
        at(4_000),
    )
    .unwrap();
    assert!(matches!(login, Login::Accepted(_)));

    // The session the wizard ended with is a live super-admin session.
    let session = store
        .read(|c| local_auth::authenticate(c, &done.issued.session, at(2_500)))
        .unwrap();
    assert_eq!(session.user, done.user);
    assert!(session.super_admin);

    // The choices were recorded, and the organization is the admin's.
    let policy = store.read(registration::policy).unwrap();
    assert_eq!(policy.registration, Registration::ApprovalRequired);
    assert_eq!(policy.tenant_creation, TenantCreation::ApprovedUsers);
    let (name, url) = store.read(setup::instance).unwrap().unwrap();
    assert_eq!(name, "Acme CI");
    assert_eq!(url.as_deref(), Some("https://ci.example.com"));
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM memberships m JOIN tenants t ON t.id = m.tenant_id
             WHERE t.slug = 'acme' AND m.role = 3"
        ),
        1
    );
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM tenants WHERE slug = 'ada' AND kind = 1"
        ),
        1
    );
    assert!(done.organization.is_some() && done.personal.is_some());
    // Audited as the host-local act it is.
    assert!(
        count(
            &store,
            "SELECT COUNT(*) FROM auth_audit WHERE event = 1 AND host_local = 1"
        ) >= 1
    );
}

#[test]
fn a_token_works_once_and_setup_after_it_is_closed() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        at(1),
    )
    .unwrap();

    // Reuse of the spent token, and a fresh attempt by anyone, find setup shut.
    let again = setup::complete(
        &store,
        &request(&token, "mallory@example.com"),
        Policy::default(),
        at(2),
    );
    assert!(matches!(again, Err(Error::NotFound)));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM users"), 1);
    assert!(setup::issue(&store, at(3)).unwrap().is_none());
    assert!(matches!(
        setup::verify(&store, &token, at(4)),
        Err(Error::NotFound)
    ));
}

#[test]
fn the_token_is_stored_only_as_its_digest() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    let stored: Vec<u8> = store
        .read(|c| Ok(c.query_row("SELECT digest FROM setup_token", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(stored, token.digest().0.to_vec());
    let mut text = String::new();
    token.expose(&mut text);
    assert_ne!(stored, text.into_bytes());
}

#[test]
fn an_expired_token_is_refused_and_nothing_is_written() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    let late = at(setup::TOKEN_TTL_MS);
    let outcome = setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        late,
    );
    assert!(matches!(outcome, Err(Error::Forbidden)));
    nothing_was_created(&store);
    // One second before the deadline it still worked.
    setup::verify(&store, &token, at(setup::TOKEN_TTL_MS - 1000)).unwrap();
    // Maintenance then deletes the dead row; a later attempt is still refused.
    setup::purge(&store, late, 64).unwrap();
    assert_eq!(count(&store, "SELECT COUNT(*) FROM setup_token"), 0);
    assert!(matches!(
        setup::verify(&store, &token, late),
        Err(Error::Forbidden)
    ));
}

#[test]
fn issuing_again_voids_the_earlier_token() {
    let (_dir, store) = open();
    let first = setup::issue(&store, at(0)).unwrap().unwrap();
    let second = setup::issue(&store, at(10)).unwrap().unwrap();
    assert!(matches!(
        setup::verify(&store, &first, at(20)),
        Err(Error::Forbidden)
    ));
    setup::verify(&store, &second, at(20)).unwrap();
}

#[test]
fn no_issued_token_means_no_setup() {
    let (_dir, store) = open();
    let stranger = Secret::generate();
    assert!(matches!(
        setup::complete(
            &store,
            &request(&stranger, "ada@example.com"),
            Policy::default(),
            at(0)
        ),
        Err(Error::Forbidden)
    ));
    nothing_was_created(&store);
}

#[test]
fn guessing_locks_setup_for_everyone_until_the_lock_ends() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    for n in 0..setup::FAILURES_BEFORE_LOCK {
        let guess = Secret::generate();
        let outcome = setup::complete(
            &store,
            &request(&guess, "mallory@example.com"),
            Policy::default(),
            at(100 + n),
        );
        assert!(matches!(outcome, Err(Error::Forbidden)));
    }
    // Locked: even the right token is refused, and nothing was created.
    let during = setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        at(1_000),
    );
    assert!(matches!(during, Err(Error::Forbidden)));
    nothing_was_created(&store);
    // After the lock the right token works: the lock delays, never admits.
    setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        at(1_000 + setup::LOCK_MS),
    )
    .unwrap();
}

#[test]
fn a_bad_field_is_refused_before_the_token_is_judged_or_spent() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    let weak = Setup {
        password: b"short",
        ..request(&token, "ada@example.com")
    };
    assert!(matches!(
        setup::complete(&store, &weak, Policy::default(), at(1)),
        Err(Error::InvalidInput(_))
    ));
    for bad in [
        Setup {
            organization: Some("api"),
            ..request(&token, "ada@example.com")
        },
        Setup {
            personal_namespace: Some("same"),
            organization: Some("same"),
            ..request(&token, "ada@example.com")
        },
        Setup {
            instance_name: "  ",
            ..request(&token, "ada@example.com")
        },
        Setup {
            base_url: Some("javascript:alert(1)"),
            ..request(&token, "ada@example.com")
        },
    ] {
        assert!(matches!(
            setup::complete(&store, &bad, Policy::default(), at(2)),
            Err(Error::InvalidInput(_))
        ));
    }
    assert!(matches!(
        setup::complete(
            &store,
            &request(&token, "not-an-address"),
            Policy::default(),
            at(3)
        ),
        Err(Error::InvalidInput(_))
    ));
    nothing_was_created(&store);
    // The token survived every refusal and still works.
    setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        at(4),
    )
    .unwrap();
}

#[test]
fn a_taken_organization_name_rolls_the_whole_setup_back() {
    let (_dir, store) = open();
    // A namespace of that name already exists (made host-locally).
    store
        .writer()
        .write(|tx| {
            sentinel_store::tenancy::create_organization(
                tx,
                Authority::HostLocal,
                TenantId::new(),
                sentinel_core::auth::Namespace::parse("acme").unwrap(),
                at(0),
            )
        })
        .unwrap();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    let clash = Setup {
        organization: Some("acme"),
        ..request(&token, "ada@example.com")
    };
    assert!(matches!(
        setup::complete(&store, &clash, Policy::default(), at(1)),
        Err(Error::Conflict)
    ));
    // The administrator, the latch and the settings rolled back with it.
    assert_eq!(count(&store, "SELECT COUNT(*) FROM users"), 0);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM bootstrap"), 0);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM instance_settings"), 0);
    assert!(store.read(setup::is_open).unwrap());
    // The token is still good: the person fixes the name and tries again.
    setup::complete(
        &store,
        &request(&token, "ada@example.com"),
        Policy::default(),
        at(2),
    )
    .unwrap();
}

#[test]
fn a_host_local_bootstrap_closes_setup_and_kills_the_token() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(1)).unwrap();
    assert_eq!(count(&store, "SELECT COUNT(*) FROM setup_token"), 0);
    assert!(matches!(
        setup::complete(
            &store,
            &request(&token, "ada@example.com"),
            Policy::default(),
            at(2)
        ),
        Err(Error::NotFound)
    ));
    assert_eq!(count(&store, "SELECT COUNT(*) FROM users"), 1);
}

#[test]
fn concurrent_setups_admit_exactly_one_administrator() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|n| {
                let store = &store;
                let token = &token;
                scope.spawn(move || {
                    let address = format!("admin{n}@example.com");
                    setup::complete(store, &request(token, &address), Policy::default(), at(1))
                        .map(|done| done.user)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let winners = outcomes.iter().filter(|o| o.is_ok()).count();
    assert_eq!(winners, 1, "{} succeeded", winners);
    for loser in outcomes.iter().filter_map(|o| o.as_ref().err()) {
        assert!(matches!(loser, Error::NotFound | Error::Forbidden));
    }
    assert_eq!(count(&store, "SELECT COUNT(*) FROM bootstrap"), 1);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM users WHERE super_admin = 1 AND kind = 0"
        ),
        1
    );
}

#[test]
fn a_race_with_the_cli_bootstrap_leaves_one_administrator() {
    let (_dir, store) = open();
    let token = setup::issue(&store, at(0)).unwrap().unwrap();
    std::thread::scope(|scope| {
        let wizard = scope.spawn(|| {
            setup::complete(
                &store,
                &request(&token, "ada@example.com"),
                Policy::default(),
                at(1),
            )
            .is_ok()
        });
        let cli = scope.spawn(|| {
            local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(1)).is_ok()
        });
        let (wizard, cli) = (wizard.join().unwrap(), cli.join().unwrap());
        assert!(wizard ^ cli, "wizard {wizard}, cli {cli}");
    });
    assert_eq!(count(&store, "SELECT COUNT(*) FROM bootstrap"), 1);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM users"), 1);
}

// ------------------------------------------------------ self-service orgs

struct World {
    _dir: tempfile::TempDir,
    store: Store,
    admin: Principal,
}

fn world(creation: TenantCreation) -> World {
    let (dir, store) = open();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration: Registration::InviteOnly,
                    tenant_creation: creation,
                    installation_binding: InstallationBinding::TenantAdmins,
                },
                at(1),
            )
        })
        .unwrap();
    World {
        _dir: dir,
        store,
        admin: Principal::new(root, P::ALL, None, None),
    }
}

impl World {
    fn member(&self, name: &str) -> Principal {
        let invitation = self
            .store
            .writer()
            .write(|tx| registration::invite(tx, Authority::HostLocal, Terms::default(), at(2)))
            .unwrap();
        let admitted = registration::register(
            &self.store,
            Applicant::Local {
                display_name: name,
                username: name,
                password: b"an acceptable member password",
            },
            Some(&invitation.secret),
            at(3),
        )
        .unwrap();
        let Admission::Admitted(user) = admitted else {
            panic!("expected an admitted account");
        };
        Principal::new(user, P::REPOSITORY.union(P::TENANT_ADMIN), None, None)
    }

    fn create(&self, who: Principal, slug: &str, now: i64) -> Result<TenantId, Error> {
        let tenant = TenantId::new();
        let slug = slug.to_owned();
        self.store
            .writer()
            .write(move |tx| organizations::create_self_service(tx, who, tenant, &slug, at(now)))
            .map(|()| tenant)
    }
}

#[test]
fn an_approved_user_creates_an_organization_and_administers_it() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    w.create(ada, "acme", 10).unwrap();
    let settings = w
        .store
        .read(|c| organizations::settings(c, ada, "acme"))
        .unwrap();
    assert_eq!(settings.role, Some(Role::TenantAdmin));
    assert!(!settings.personal && !settings.github_backed && !settings.installation_bound);
    assert_eq!(
        count(
            &w.store,
            "SELECT COUNT(*) FROM auth_audit WHERE event = 43 AND detail = 'acme'"
        ),
        1
    );
    // The same name again, by anyone, is a conflict and creates nothing.
    let bob = w.member("bob");
    assert!(matches!(w.create(bob, "acme", 11), Err(Error::Conflict)));
}

#[test]
fn the_default_policy_keeps_organization_creation_with_the_platform() {
    let w = world(TenantCreation::SuperAdminOnly);
    let ada = w.member("ada");
    assert!(matches!(w.create(ada, "acme", 10), Err(Error::Forbidden)));
    assert_eq!(
        count(&w.store, "SELECT COUNT(*) FROM tenants WHERE slug = 'acme'"),
        0
    );
    // A platform administrator still may.
    w.create(w.admin, "acme", 11).unwrap();
}

#[test]
fn reserved_and_malformed_names_are_refused() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    for bad in [
        "api", "settings", "a", "Acme", "-acme", "acme-", "ac me", "",
    ] {
        assert!(
            matches!(w.create(ada, bad, 10), Err(Error::InvalidInput(_))),
            "{bad:?}"
        );
    }
    assert_eq!(count(&w.store, "SELECT COUNT(*) FROM tenants"), 0);
}

#[test]
fn a_scoped_credential_cannot_create_an_organization() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    let tenant = w.create(ada, "acme", 10).unwrap();
    let scoped = Principal::new(ada.user, P::REPOSITORY, Some(tenant), None);
    assert!(matches!(
        w.create(scoped, "other", 11),
        Err(Error::Forbidden)
    ));
}

#[test]
fn a_pending_account_cannot_create_an_organization() {
    let w = world(TenantCreation::ApprovedUsers);
    w.store
        .writer()
        .write(|tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration: Registration::ApprovalRequired,
                    tenant_creation: TenantCreation::ApprovedUsers,
                    installation_binding: InstallationBinding::TenantAdmins,
                },
                at(5),
            )
        })
        .unwrap();
    let Admission::Pending(user) = registration::register(
        &w.store,
        Applicant::Local {
            display_name: "Pat",
            username: "pat",
            password: b"an acceptable member password",
        },
        None,
        at(6),
    )
    .unwrap() else {
        panic!("expected a pending account");
    };
    let pending = Principal::new(user, P::REPOSITORY.union(P::TENANT_ADMIN), None, None);
    assert!(matches!(
        w.create(pending, "acme", 7),
        Err(Error::Forbidden)
    ));
}

#[test]
fn quotas_bound_how_many_organizations_an_account_creates() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    let hour = 60 * 60 * 1000;
    for n in 0..organizations::SELF_SERVICE_PER_HOUR {
        w.create(ada, &format!("org-{n}"), 100 + n).unwrap();
    }
    // The hourly allowance is spent, not the lifetime one.
    assert!(matches!(
        w.create(ada, "one-too-many", 200),
        Err(Error::QuotaExceeded)
    ));
    // Someone else is unaffected by Ada's budget.
    let bob = w.member("bob");
    w.create(bob, "bobs-org", 201).unwrap();
    // Later hours refill the allowance until the lifetime cap.
    let mut made = organizations::SELF_SERVICE_PER_HOUR;
    let mut hours = 1;
    while made < organizations::MAX_SELF_SERVICE_ORGS {
        let base = hours * hour * 2;
        for n in 0..organizations::SELF_SERVICE_PER_HOUR {
            if made == organizations::MAX_SELF_SERVICE_ORGS {
                break;
            }
            w.create(ada, &format!("later-{made}"), base + n).unwrap();
            made += 1;
        }
        hours += 1;
    }
    assert!(matches!(
        w.create(ada, "past-the-cap", hours * hour * 2 + 5),
        Err(Error::QuotaExceeded)
    ));
    // The platform administrator is not held to it.
    w.create(w.admin, "platform-made", hours * hour * 2 + 6)
        .unwrap();
}

#[test]
fn settings_are_not_found_for_a_stranger_and_hide_nothing_by_guessing() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    let bob = w.member("bob");
    w.create(ada, "acme", 10).unwrap();
    for slug in ["acme", "no-such-org"] {
        let outcome = w.store.read(|c| organizations::settings(c, bob, slug));
        assert!(matches!(outcome, Err(Error::NotFound)), "{slug}");
    }
}

#[test]
fn settings_report_github_backing_apart_from_a_bound_installation() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    let tenant = w.create(ada, "acme", 10).unwrap();
    w.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE tenants SET membership_source = 1 WHERE id = ?1",
                params![tenant.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let settings = w
        .store
        .read(|c| organizations::settings(c, ada, "acme"))
        .unwrap();
    assert!(settings.github_backed);
    assert!(!settings.installation_bound);
    // Nothing confirmed and nothing queued yet.
    assert_eq!(settings.github_confirmed_ms, None);
    assert_eq!(settings.github_check_failures, None);
    assert_eq!(settings.github_check_next_ms, None);
}

#[test]
fn settings_report_only_the_callers_own_github_standing() {
    let w = world(TenantCreation::ApprovedUsers);
    let ada = w.member("ada");
    let bob = w.member("bob");
    let tenant = w.create(ada, "acme", 10).unwrap();
    let (ada_id, bob_id) = (ada.user, bob.user);
    w.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE tenants SET membership_source = 1 WHERE id = ?1",
                params![tenant.as_bytes()],
            )?;
            tx.execute(
                "UPDATE memberships SET synced_ms = 5000 WHERE tenant_id = ?1 AND user_id = ?2",
                params![tenant.as_bytes(), ada_id.as_bytes()],
            )?;
            // GitHub could not answer Ada's last three checks; Bob, who is
            // no member, has a queued check of his own that must not leak.
            tx.execute(
                "INSERT INTO github_member_checks(tenant_id, user_id, next_ms, attempts)
                 VALUES (?1, ?2, 0, 3), (?1, ?3, 0, 7)",
                params![tenant.as_bytes(), ada_id.as_bytes(), bob_id.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let settings = w
        .store
        .read(|c| organizations::settings(c, ada, "acme"))
        .unwrap();
    assert_eq!(settings.github_confirmed_ms, Some(5000));
    assert_eq!(settings.github_check_failures, Some(3));
    assert_eq!(settings.github_check_next_ms, Some(0));
    // A queued check is no membership: Bob still cannot see the tenant.
    assert!(matches!(
        w.store.read(|c| organizations::settings(c, bob, "acme")),
        Err(Error::NotFound)
    ));
}
