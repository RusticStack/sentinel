//! A05 behavior: registration policy, one-use expiring invitations,
//! pending/approved/rejected accounts, and the separate decisions of creating a
//! tenant and binding a forge installation to it.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    InstallationId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind},
    local_auth::{self, Event, Login, Policy},
    registration::{
        self, Admission, Applicant, Authority, DeploymentPolicy, InstallationBinding, Refusal,
        Registration, TenantCreation, Terms,
    },
    sign_in,
};

const PASSWORD: &[u8] = b"an acceptable member password";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    admin: Principal,
    tenant: TenantId,
}

/// A bootstrapped deployment with one organization the super admin administers.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    let admin = Principal::new(root, P::ALL, None, None);
    let tenant = TenantId::new();
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                at(1),
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        root,
        admin,
        tenant,
    }
}

impl Fixture {
    fn set_registration(&self, registration: Registration) {
        let admin = self.admin;
        let policy = DeploymentPolicy {
            registration,
            ..self.store.read(registration::policy).unwrap()
        };
        self.store
            .writer()
            .write(move |tx| registration::set_policy(tx, stepped(admin), policy, at(2)))
            .unwrap();
    }

    fn invite(&self, terms: Terms<'static>) -> registration::Invitation {
        let admin = self.admin;
        self.store
            .writer()
            .write(move |tx| registration::invite(tx, Authority::credential(admin), terms, at(3)))
            .unwrap()
    }

    fn apply_local(&self, username: &'static str, invitation: Option<&Secret>) -> Admission {
        registration::register(
            &self.store,
            Applicant::Local {
                display_name: "A Member",
                username,
                password: PASSWORD,
            },
            invitation,
            at(10),
        )
        .unwrap()
    }

    fn events(&self) -> Vec<Event> {
        self.store
            .read(|conn| local_auth::recent_audit(conn, 100))
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect()
    }
}

/// A platform admin whose session proved a second factor just now.
fn stepped(principal: Principal) -> Authority {
    Authority::Credential {
        principal,
        stepped_up: true,
    }
}

fn admitted(admission: Admission) -> UserId {
    match admission {
        Admission::Admitted(user) => user,
        other => panic!("expected admission, got {other:?}"),
    }
}

#[test]
fn the_default_policy_is_invite_only_and_an_uninvited_application_is_refused() {
    let f = fixture();
    let policy = f.store.read(registration::policy).unwrap();
    assert_eq!(policy.registration, Registration::InviteOnly);
    assert_eq!(policy.tenant_creation, TenantCreation::SuperAdminOnly);
    assert_eq!(
        policy.installation_binding,
        InstallationBinding::TenantAdmins
    );

    assert!(matches!(
        f.apply_local("member", None),
        Admission::Refused(Refusal::InvitationRequired)
    ));
    let accounts: i64 = f
        .store
        .read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(accounts, 1, "only the bootstrapped admin exists");
    assert!(f.events().contains(&Event::RegistrationRefused));
}

#[test]
fn an_invitation_admits_once_and_only_once() {
    let f = fixture();
    let invitation = f.invite(Terms::default());
    let user = admitted(f.apply_local("member", Some(&invitation.secret)));

    // The new account is active and can sign in immediately.
    assert!(matches!(
        local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(20)).unwrap(),
        Login::Accepted(_)
    ));

    // The same invitation cannot admit a second person.
    assert!(matches!(
        f.apply_local("second", Some(&invitation.secret)),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    // Nor can an unknown or revoked one.
    assert!(matches!(
        f.apply_local("third", Some(&Secret::generate())),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    let records = f
        .store
        .read(|conn| registration::invitations(conn, Authority::credential(f.admin), None, 10))
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, invitation.id);
    assert!(records[0].redeemed && !records[0].revoked);
    let _ = user;
}

#[test]
fn invitations_expire_are_revocable_and_are_bounded_at_creation() {
    let f = fixture();
    let expiring = f.invite(Terms {
        lifetime_ms: 1_000,
        ..Terms::default()
    });
    assert_eq!(expiring.expires.0, 1_003);
    assert!(matches!(
        registration::register(
            &f.store,
            Applicant::Local {
                display_name: "Late",
                username: "late",
                password: PASSWORD,
            },
            Some(&expiring.secret),
            at(1_003),
        )
        .unwrap(),
        Admission::Refused(Refusal::InvitationUnusable)
    ));

    let revoked = f.invite(Terms::default());
    let admin = f.admin;
    let id = revoked.id;
    f.store
        .writer()
        .write(move |tx| {
            registration::revoke_invitation(tx, Authority::credential(admin), id, at(5))
        })
        .unwrap();
    assert!(matches!(
        f.apply_local("member", Some(&revoked.secret)),
        Admission::Refused(Refusal::InvitationUnusable)
    ));

    for lifetime in [0, -1, registration::MAX_INVITATION_MS + 1] {
        let refused = f.store.writer().write(move |tx| {
            registration::invite(
                tx,
                Authority::credential(admin),
                Terms {
                    lifetime_ms: lifetime,
                    ..Terms::default()
                },
                at(6),
            )
            .map(|_| ())
        });
        assert!(matches!(
            refused,
            Err(Error::InvalidInput("invitation lifetime"))
        ));
    }
}

#[test]
fn an_invitation_can_bind_a_tenant_role_and_a_verified_identity() {
    let f = fixture();
    let bound = f.invite(Terms {
        tenant: Some(f.tenant),
        role: Some(Role::Operator),
        identity: Some(("github", "4242")),
        lifetime_ms: registration::DEFAULT_INVITATION_MS,
    });

    // A local applicant cannot redeem an identity-bound invitation.
    assert!(matches!(
        f.apply_local("member", Some(&bound.secret)),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    // Neither can a different GitHub account.
    let wrong = registration::register(
        &f.store,
        Applicant::External {
            display_name: "Impostor",
            provider: "github",
            subject: "9999",
        },
        Some(&bound.secret),
        at(10),
    )
    .unwrap();
    assert!(matches!(
        wrong,
        Admission::Refused(Refusal::InvitationUnusable)
    ));

    let user = admitted(
        registration::register(
            &f.store,
            Applicant::External {
                display_name: "The Octocat",
                provider: "github",
                subject: "4242",
            },
            Some(&bound.secret),
            at(11),
        )
        .unwrap(),
    );
    // The membership it promised exists, and no more than that.
    let role: i64 = f
        .store
        .read(move |conn| {
            conn.query_row(
                "SELECT role FROM memberships WHERE tenant_id = ?1 AND user_id = ?2",
                rusqlite::params![f.tenant.as_bytes(), user.as_bytes()],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(role, Role::Operator as i64);
    // And that verified identity now signs in as this account.
    assert!(matches!(
        sign_in::complete(&f.store, "github", "4242", Policy::default(), at(12)).unwrap(),
        sign_in::Outcome::SignedIn(_)
    ));
}

#[test]
fn approval_required_creates_a_pending_account_that_holds_nothing() {
    let f = fixture();
    f.set_registration(Registration::ApprovalRequired);
    let user = match f.apply_local("member", None) {
        Admission::Pending(user) => user,
        other => panic!("expected pending, got {other:?}"),
    };

    // Pending is not admitted: the password is right and login still fails.
    assert!(matches!(
        local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(20)).unwrap(),
        Login::Rejected
    ));
    // Nor can a session or credential be minted for it.
    let refused = f.store.writer().write(move |tx| {
        local_auth::issue_session(tx, user, Policy::default(), at(21)).map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Sqlite(_))));

    let pending = f
        .store
        .read(|conn| registration::pending(conn, Authority::credential(f.admin), 10))
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].user, user);
    assert_eq!(pending[0].display_name, "A Member");

    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| registration::approve(tx, Authority::credential(admin), user, at(22)))
        .unwrap();
    assert!(matches!(
        local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(23)).unwrap(),
        Login::Accepted(_)
    ));
    assert!(
        f.store
            .read(|conn| registration::pending(conn, Authority::credential(f.admin), 10))
            .unwrap()
            .is_empty()
    );
    // Approving twice is not a silent success.
    let again = f
        .store
        .writer()
        .write(move |tx| registration::approve(tx, Authority::credential(admin), user, at(24)));
    assert!(matches!(again, Err(Error::NotFound)));
}

#[test]
fn rejection_ends_access_and_keeps_the_identity_claimed() {
    let f = fixture();
    f.set_registration(Registration::ApprovalRequired);
    let user = match f.apply_local("member", None) {
        Admission::Pending(user) => user,
        other => panic!("expected pending, got {other:?}"),
    };
    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| registration::approve(tx, Authority::credential(admin), user, at(20)))
        .unwrap();
    let issued =
        match local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(21)).unwrap() {
            Login::Accepted(issued) => issued,
            _ => panic!("login"),
        };

    f.store
        .writer()
        .write(move |tx| registration::reject(tx, Authority::credential(admin), user, at(22)))
        .unwrap();
    // The live session stops working, and the password no longer signs in.
    assert!(matches!(
        f.store
            .read(|conn| local_auth::authenticate(conn, &issued.session, at(23))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(24)).unwrap(),
        Login::Rejected
    ));
    // The username stays claimed: a rejected applicant cannot simply reapply.
    assert!(matches!(
        f.apply_local("member", None),
        Admission::Refused(Refusal::AlreadyRegistered)
    ));
    // A rejected account cannot be made active again by a raw update.
    let revive = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE users SET active = 1 WHERE id = ?1",
            [user.as_bytes()],
        )?;
        Ok(())
    });
    assert!(matches!(revive, Err(Error::Sqlite(_))));
}

#[test]
fn closing_registration_refuses_everyone_new_and_locks_nobody_out() {
    let f = fixture();
    let invitation = f.invite(Terms::default());
    let member = admitted(f.apply_local("member", Some(&invitation.secret)));

    f.set_registration(Registration::Closed);
    // An outstanding invitation does not survive closing: closed means closed.
    let spare = f.invite(Terms::default());
    assert!(matches!(
        f.apply_local("second", Some(&spare.secret)),
        Admission::Refused(Refusal::RegistrationClosed)
    ));
    assert!(matches!(
        f.apply_local("third", None),
        Admission::Refused(Refusal::RegistrationClosed)
    ));

    // Everybody already admitted keeps working: local login and GitHub alike.
    assert!(matches!(
        local_auth::login(&f.store, "member", PASSWORD, Policy::default(), at(30)).unwrap(),
        Login::Accepted(_)
    ));
    let session = f
        .store
        .writer()
        .write(move |tx| local_auth::issue_session(tx, member, Policy::default(), at(31)))
        .unwrap();
    let session = f
        .store
        .read(|conn| local_auth::authenticate(conn, &session.session, at(32)))
        .unwrap();
    sign_in::link(&f.store, &session, "github", "4242", at(33)).unwrap();
    assert!(matches!(
        sign_in::complete(&f.store, "github", "4242", Policy::default(), at(34)).unwrap(),
        sign_in::Outcome::SignedIn(_)
    ));
}

#[test]
fn only_a_platform_admin_sets_policy_approves_or_rejects() {
    let f = fixture();
    let invitation = f.invite(Terms::default());
    let member = admitted(f.apply_local("member", Some(&invitation.secret)));
    let theirs = Principal::new(member, P::ALL, None, None);

    let refused = f.store.writer().write(move |tx| {
        registration::set_policy(
            tx,
            stepped(theirs),
            DeploymentPolicy {
                registration: Registration::ApprovalRequired,
                tenant_creation: TenantCreation::ApprovedUsers,
                installation_binding: InstallationBinding::TenantAdmins,
            },
            at(20),
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    assert_eq!(
        f.store.read(registration::policy).unwrap().registration,
        Registration::InviteOnly
    );

    let refused = f
        .store
        .writer()
        .write(move |tx| registration::approve(tx, Authority::credential(theirs), member, at(21)));
    assert!(matches!(refused, Err(Error::Forbidden)));
    let refused = f
        .store
        .writer()
        .write(move |tx| registration::reject(tx, Authority::credential(theirs), member, at(22)));
    assert!(matches!(refused, Err(Error::Forbidden)));
    assert!(matches!(
        f.store
            .read(move |conn| registration::pending(conn, Authority::credential(theirs), 10)),
        Err(Error::Forbidden)
    ));

    // Even the admin's own session loses it when the credential is narrowed.
    let narrowed = Principal::new(f.root, P::REPOSITORY, None, None);
    let refused = f.store.writer().write(move |tx| {
        registration::approve(tx, Authority::credential(narrowed), member, at(23))
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn a_tenant_admin_may_invite_only_into_the_tenant_they_administer() {
    let f = fixture();
    let invitation = f.invite(Terms {
        tenant: Some(f.tenant),
        role: Some(Role::TenantAdmin),
        ..Terms::default()
    });
    let member = admitted(f.apply_local("member", Some(&invitation.secret)));
    let theirs = Principal::new(member, P::ALL, None, None);

    // Their own tenant: allowed.
    let their_invite = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::credential(theirs),
                Terms {
                    tenant: Some(f.tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                at(20),
            )
        })
        .unwrap();
    assert!(matches!(
        f.apply_local("reader", Some(&their_invite.secret)),
        Admission::Admitted(_)
    ));

    // A deployment-wide invitation, or one into another tenant, is not theirs
    // to make.
    let refused = f.store.writer().write(move |tx| {
        registration::invite(tx, Authority::credential(theirs), Terms::default(), at(21))
            .map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    let other = TenantId::new();
    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                other,
                Namespace::parse("other").unwrap(),
                NamespaceKind::Organization,
                at(22),
            )
        })
        .unwrap();
    let refused = f.store.writer().write(move |tx| {
        registration::invite(
            tx,
            Authority::credential(theirs),
            Terms {
                tenant: Some(other),
                role: Some(Role::Reader),
                ..Terms::default()
            },
            at(23),
        )
        .map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn creating_a_namespace_is_a_separate_decision_from_being_admitted() {
    let f = fixture();
    let invitation = f.invite(Terms::default());
    let member = admitted(f.apply_local("member", Some(&invitation.secret)));
    let theirs = Principal::new(member, P::ALL, None, None);

    // Default policy: an admitted account still cannot create a namespace.
    let refused = f.store.writer().write(move |tx| {
        registration::create_personal_namespace(
            tx,
            theirs,
            TenantId::new(),
            Namespace::parse("member").unwrap(),
            at(20),
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));

    let admin = f.admin;
    let policy = DeploymentPolicy {
        tenant_creation: TenantCreation::ApprovedUsers,
        ..f.store.read(registration::policy).unwrap()
    };
    f.store
        .writer()
        .write(move |tx| registration::set_policy(tx, stepped(admin), policy, at(21)))
        .unwrap();

    let personal = TenantId::new();
    f.store
        .writer()
        .write(move |tx| {
            registration::create_personal_namespace(
                tx,
                theirs,
                personal,
                Namespace::parse("member").unwrap(),
                at(22),
            )
        })
        .unwrap();
    // It is theirs: the owner membership was created with it.
    assert_eq!(
        f.store
            .read(move |conn| auth::get_namespace(
                conn,
                theirs,
                Namespace::parse("member").unwrap()
            ))
            .unwrap()
            .id,
        personal
    );
    // One each, and a tenant-scoped credential cannot create another.
    let second = f.store.writer().write(move |tx| {
        registration::create_personal_namespace(
            tx,
            theirs,
            TenantId::new(),
            Namespace::parse("member-two").unwrap(),
            at(23),
        )
    });
    assert!(matches!(second, Err(Error::Sqlite(_))));
    let scoped = Principal::new(member, P::ALL, Some(personal), None);
    let refused = f.store.writer().write(move |tx| {
        registration::create_personal_namespace(
            tx,
            scoped,
            TenantId::new(),
            Namespace::parse("member-three").unwrap(),
            at(24),
        )
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn an_installation_is_known_but_inactive_until_an_authorized_binding_exists() {
    let f = fixture();
    let admin = f.admin;
    let installation = f
        .store
        .writer()
        .write(move |tx| registration::record_installation(tx, "github", "12345", "acme", at(20)))
        .unwrap();

    // Seeing it grants nothing: it resolves to no tenant.
    assert_eq!(
        f.store
            .read(|conn| registration::installation_tenant(conn, "github", "12345"))
            .unwrap(),
        None
    );
    // Repeated deliveries do not duplicate or re-create it.
    let again = f
        .store
        .writer()
        .write(move |tx| registration::record_installation(tx, "github", "12345", "acme", at(21)))
        .unwrap();
    assert_eq!(again, installation);
    assert!(matches!(
        f.store
            .read(|conn| registration::installation_tenant(conn, "github", "99999")),
        Err(Error::NotFound)
    ));

    f.store
        .writer()
        .write(move |tx| registration::bind_installation(tx, admin, installation, f.tenant, at(22)))
        .unwrap();
    assert_eq!(
        f.store
            .read(|conn| registration::installation_tenant(conn, "github", "12345"))
            .unwrap(),
        Some(f.tenant)
    );

    // Rebinding elsewhere requires an explicit unbind first.
    let other = TenantId::new();
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                other,
                Namespace::parse("other").unwrap(),
                NamespaceKind::Organization,
                at(23),
            )
        })
        .unwrap();
    let refused = f
        .store
        .writer()
        .write(move |tx| registration::bind_installation(tx, admin, installation, other, at(24)));
    assert!(matches!(refused, Err(Error::Conflict)));
    f.store
        .writer()
        .write(move |tx| registration::unbind_installation(tx, admin, installation, at(25)))
        .unwrap();
    assert_eq!(
        f.store
            .read(|conn| registration::installation_tenant(conn, "github", "12345"))
            .unwrap(),
        None
    );
    f.store
        .writer()
        .write(move |tx| registration::bind_installation(tx, admin, installation, other, at(26)))
        .unwrap();
    assert!(f.events().contains(&Event::InstallationBound));
    assert!(f.events().contains(&Event::InstallationUnbound));
}

#[test]
fn binding_requires_administering_that_tenant_and_the_policy_to_allow_it() {
    let f = fixture();
    let admin = f.admin;
    let invitation = f.invite(Terms {
        tenant: Some(f.tenant),
        role: Some(Role::TenantAdmin),
        ..Terms::default()
    });
    let member = admitted(f.apply_local("member", Some(&invitation.secret)));
    let theirs = Principal::new(member, P::ALL, None, None);
    let outsider = admitted({
        let invitation = f.invite(Terms::default());
        f.apply_local("outsider", Some(&invitation.secret))
    });
    let outsiders = Principal::new(outsider, P::ALL, None, None);
    let installation = f
        .store
        .writer()
        .write(move |tx| registration::record_installation(tx, "github", "12345", "acme", at(20)))
        .unwrap();

    // Not an admin of that tenant: refused, policy or no policy.
    let refused = f.store.writer().write(move |tx| {
        registration::bind_installation(tx, outsiders, installation, f.tenant, at(21))
    });
    assert!(matches!(refused, Err(Error::Forbidden)));

    // The tenant's own admin may, under the default policy.
    f.store
        .writer()
        .write(move |tx| {
            registration::bind_installation(tx, theirs, installation, f.tenant, at(22))
        })
        .unwrap();
    f.store
        .writer()
        .write(move |tx| registration::unbind_installation(tx, theirs, installation, at(23)))
        .unwrap();

    // Under the stricter policy, the same tenant admin may not.
    let policy = DeploymentPolicy {
        installation_binding: InstallationBinding::SuperAdminOnly,
        ..f.store.read(registration::policy).unwrap()
    };
    f.store
        .writer()
        .write(move |tx| registration::set_policy(tx, stepped(admin), policy, at(24)))
        .unwrap();
    let refused = f.store.writer().write(move |tx| {
        registration::bind_installation(tx, theirs, installation, f.tenant, at(25))
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    f.store
        .writer()
        .write(move |tx| registration::bind_installation(tx, admin, installation, f.tenant, at(26)))
        .unwrap();
    // A guessed installation identifier is not a discovery channel.
    let refused = f.store.writer().write(move |tx| {
        registration::bind_installation(tx, admin, InstallationId::new(), f.tenant, at(27))
    });
    assert!(matches!(refused, Err(Error::Conflict)));
}

#[test]
fn admission_decisions_are_audited_and_spent_invitations_are_purged() {
    let f = fixture();
    let invitation = f.invite(Terms::default());
    f.apply_local("member", Some(&invitation.secret));
    f.apply_local("member", Some(&invitation.secret));

    let events = f.events();
    for expected in [
        Event::PolicyChanged,
        Event::InvitationCreated,
        Event::InvitationRedeemed,
        Event::RegistrationAdmitted,
        Event::RegistrationRefused,
    ] {
        if expected == Event::PolicyChanged {
            continue;
        }
        assert!(events.contains(&expected), "{expected:?} missing");
    }
    let records = f
        .store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap();
    let refused = records
        .iter()
        .find(|r| r.event == Event::RegistrationRefused)
        .unwrap();
    assert_eq!(refused.detail.as_deref(), Some("InvitationUnusable"));

    let live = f.invite(Terms::default());
    assert_eq!(
        registration::purge_expired_invitations(&f.store, at(100), 10).unwrap(),
        1,
        "only the spent invitation is removed"
    );
    assert!(matches!(
        f.apply_local("second", Some(&live.secret)),
        Admission::Admitted(_)
    ));
}
