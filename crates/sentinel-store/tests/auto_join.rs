use rusqlite::params;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind},
    auto_join::{self, Reason},
    email::{self, Confirmation},
    local_auth::{self, Event, Login, Policy},
    registration::{self, Admission, Applicant, Authority, DeploymentPolicy, Registration, Terms},
};

const PASSWORD: &[u8] = b"an acceptable member password";
const SLUG: &str = "rusticstack-com";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    admin: Principal,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    let admin = Principal::new(root, P::ALL, None, None);
    Fixture { dir, store, admin }
}

impl Fixture {
    fn rules(&self, setting: &str) -> Vec<auto_join::Ignored> {
        let parsed = auto_join::parse(setting);
        let mut refused = parsed.ignored.clone();
        refused.extend(auto_join::set_rules(&self.store, &parsed.rules).unwrap());
        refused
    }

    fn admission(&self) -> Secret {
        let admin = self.admin;
        self.store
            .writer()
            .write(move |tx| {
                registration::invite(tx, Authority::credential(admin), Terms::default(), at(2))
            })
            .unwrap()
            .secret
    }

    fn claim(&self, address: &str) -> UserId {
        let invitation = self.admission();
        match registration::register_with(
            &self.store,
            Applicant::Email {
                display_name: "New Person",
                email: address,
                password: PASSWORD,
            },
            Some(&invitation),
            None,
            at(10),
        )
        .unwrap()
        {
            Admission::Admitted(user) => user,
            other => panic!("expected admission, got {other:?}"),
        }
    }

    fn link(&self, user: UserId) -> Secret {
        self.store
            .writer()
            .write(move |tx| email::issue_link(tx, Authority::HostLocal, user, None, at(11)))
            .unwrap()
            .secret
    }

    fn verified(&self, address: &str) -> UserId {
        let user = self.claim(address);
        let secret = self.link(user);
        match email::confirm(&self.store, &secret, at(20)).unwrap() {
            Confirmation::Verified { user: got, .. } => assert_eq!(got, user),
            Confirmation::Refused => panic!("verification refused"),
        }
        user
    }

    fn sign_in(&self, address: &str) {
        let outcome =
            local_auth::login(&self.store, address, PASSWORD, Policy::default(), at(50)).unwrap();
        assert!(matches!(outcome, Login::Accepted(_)), "sign-in refused");
    }

    fn tenants_named(&self, slug: &str) -> i64 {
        self.store
            .read(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM tenants WHERE slug = ?1",
                    [slug],
                    |r| r.get(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    }

    fn role_in(&self, slug: &str, user: UserId) -> i64 {
        self.store
            .read(|c| {
                c.query_row(
                    "SELECT COALESCE((SELECT m.role FROM memberships m JOIN tenants t
                      ON t.id = m.tenant_id WHERE t.slug = ?1 AND m.user_id = ?2), 0)",
                    params![slug, user.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    }

    fn memberships_of(&self, user: UserId) -> i64 {
        self.store
            .read(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM memberships WHERE user_id = ?1",
                    [user.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    }

    fn count(&self, event: Event) -> i64 {
        self.store
            .read(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM auth_audit WHERE event = ?1",
                    [event as u8],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    }

    fn organization(&self, slug: &'static str) -> TenantId {
        let (admin, tenant) = (self.admin, TenantId::new());
        self.store
            .writer()
            .write(move |tx| {
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    at(1),
                )
            })
            .unwrap();
        tenant
    }

    fn bind_github(&self, tenant: TenantId) {
        self.store
            .writer()
            .write(move |tx| {
                let installation =
                    registration::record_installation(tx, "github", "424242", "rustic", at(4))?;
                registration::bind_installation_trusted(tx, installation, tenant, at(5))
            })
            .unwrap();
    }
}

#[test]
fn the_first_matching_person_creates_the_organization_and_later_ones_join_as_readers() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    assert_eq!(
        f.tenants_named(SLUG),
        0,
        "nothing exists until someone matches"
    );

    let first = f.verified("ana@rusticstack.com");
    assert_eq!(f.tenants_named(SLUG), 1);
    assert_eq!(f.role_in(SLUG, first), 3, "the first match administers it");

    let second = f.verified("bruno@rusticstack.com");
    assert_eq!(f.tenants_named(SLUG), 1);
    assert_eq!(f.role_in(SLUG, second), 1, "later matches are readers");
    assert_eq!(f.role_in(SLUG, first), 3);

    assert_eq!(f.count(Event::NamespaceCreated), 1);
    assert_eq!(f.count(Event::DomainAutoJoined), 2);
}

#[test]
fn a_named_organization_is_used_and_an_existing_one_is_joined_not_replaced() {
    let f = fixture();
    f.organization("acme");
    assert!(f.rules("rusticstack.com=acme").is_empty());
    let user = f.verified("ana@rusticstack.com");
    assert_eq!(f.role_in("acme", user), 1);
    assert_eq!(f.tenants_named("acme"), 1);
    assert_eq!(f.count(Event::NamespaceCreated), 0);
}

#[test]
fn lookalike_domains_never_match() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    for lookalike in [
        "a@evilrusticstack.com",
        "a@rusticstack.com.evil.io",
        "a@mail.rusticstack.com",
        "a@rusticstack.co",
        "a@notrusticstack.com",
        "a@rusti\u{0441}stack.com",
    ] {
        let user = f.verified(lookalike);
        assert_eq!(f.memberships_of(user), 0, "{lookalike}");
    }
    assert_eq!(
        f.tenants_named(SLUG),
        0,
        "no lookalike created the organization"
    );
    assert_eq!(f.count(Event::DomainAutoJoined), 0);
}

#[test]
fn case_does_not_change_the_domain() {
    let f = fixture();
    assert!(f.rules("RusticStack.COM").is_empty());
    let user = f.verified("Ana@RUSTICSTACK.com");
    assert_eq!(f.role_in(SLUG, user), 3);
}

#[test]
fn an_internationalized_domain_matches_in_either_spelling() {
    let f = fixture();
    assert!(f.rules("bücher.example=books").is_empty());
    let user = f.verified("a@xn--bcher-kva.example");
    assert_eq!(f.role_in("books", user), 3);
    let other = f.verified("b@BÜCHER.example");
    assert_eq!(f.role_in("books", other), 1);
}

#[test]
fn an_unverified_address_grants_nothing_at_sign_in_or_when_claimed() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    let user = f.claim("ana@rusticstack.com");
    let _ = f.link(user);
    assert_eq!(f.memberships_of(user), 0);
    let invitation = f.admission();
    let local = match registration::register_with(
        &f.store,
        Applicant::Local {
            display_name: "Local",
            username: "carla",
            password: PASSWORD,
        },
        Some(&invitation),
        None,
        at(12),
    )
    .unwrap()
    {
        Admission::Admitted(user) => user,
        other => panic!("{other:?}"),
    };
    f.store
        .writer()
        .write(move |tx| email::request(tx, None, local, "carla@rusticstack.com", None, at(13)))
        .unwrap();
    f.sign_in("carla");
    assert_eq!(f.memberships_of(local), 0);
    assert_eq!(f.tenants_named(SLUG), 0);
}

#[test]
fn a_domain_listed_after_the_address_was_verified_joins_at_the_next_sign_in() {
    let f = fixture();
    let user = f.verified("ana@rusticstack.com");
    assert_eq!(f.memberships_of(user), 0);
    assert!(f.rules("rusticstack.com").is_empty());
    assert_eq!(f.memberships_of(user), 0, "recording the rule joins nobody");
    f.sign_in("ana@rusticstack.com");
    assert_eq!(f.role_in(SLUG, user), 3);
    f.sign_in("ana@rusticstack.com");
    assert_eq!(f.role_in(SLUG, user), 3);
    assert_eq!(f.count(Event::DomainAutoJoined), 1);
}

#[test]
fn an_account_waiting_for_approval_joins_only_once_admitted() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    f.store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration: Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                at(3),
            )
        })
        .unwrap();
    let pending = match registration::register_with(
        &f.store,
        Applicant::Email {
            display_name: "Pending",
            email: "ana@rusticstack.com",
            password: PASSWORD,
        },
        None,
        None,
        at(10),
    )
    .unwrap()
    {
        Admission::Pending(user) => user,
        other => panic!("{other:?}"),
    };
    // A proven mailbox plus a domain match is not an approval; the operator must still admit the account.
    let secret = f.link(pending);
    assert!(matches!(
        email::confirm(&f.store, &secret, at(20)).unwrap(),
        Confirmation::Verified { .. }
    ));
    assert_eq!(f.memberships_of(pending), 0);
    assert_eq!(f.tenants_named(SLUG), 0);

    f.store
        .writer()
        .write(move |tx| registration::approve(tx, Authority::HostLocal, pending, at(30)))
        .unwrap();
    f.sign_in("ana@rusticstack.com");
    assert_eq!(f.role_in(SLUG, pending), 3);
}

#[test]
fn a_github_backed_organization_is_never_joined_by_domain() {
    let f = fixture();
    let tenant = f.organization("rusticstack-com");
    f.bind_github(tenant);
    let refused = f.rules("other.example, rusticstack.com");
    assert_eq!(
        refused,
        vec![auto_join::Ignored {
            index: 2,
            reason: Reason::GithubBacked
        }]
    );
    let user = f.verified("ana@rusticstack.com");
    assert_eq!(f.memberships_of(user), 0);

    let g = fixture();
    g.organization("rusticstack-com");
    g.store
        .writer()
        .write(|tx| {
            tx.execute(
                "UPDATE tenants SET membership_source = 1 WHERE slug = 'rusticstack-com'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(g.rules("rusticstack.com").len(), 1);
    let user = g.verified("ana@rusticstack.com");
    assert_eq!(g.memberships_of(user), 0);
}

#[test]
fn an_organization_converted_after_start_stops_admitting_by_domain() {
    let f = fixture();
    let tenant = f.organization("rusticstack-com");
    assert!(f.rules("rusticstack.com").is_empty());
    let early = f.verified("ana@rusticstack.com");
    assert_eq!(f.role_in(SLUG, early), 1);

    // Converted after start: the stored rule still names the organization, so the joining transaction must refuse it.
    f.bind_github(tenant);
    let late = f.verified("bruno@rusticstack.com");
    assert_eq!(f.role_in(SLUG, late), 0);
    f.sign_in("bruno@rusticstack.com");
    assert_eq!(f.role_in(SLUG, late), 0);
}

#[test]
fn a_personal_namespace_or_a_suspended_organization_is_never_joined() {
    let f = fixture();
    let owner = f.verified("owner@elsewhere.example");
    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                TenantId::new(),
                Namespace::parse(SLUG).unwrap(),
                NamespaceKind::Personal(owner),
                at(1),
            )
        })
        .unwrap();
    f.organization("sleepy");
    f.store
        .writer()
        .write(|tx| {
            tx.execute("UPDATE tenants SET active = 0 WHERE slug = 'sleepy'", [])?;
            Ok(())
        })
        .unwrap();
    let refused = f.rules("rusticstack.com, sleepy.example=sleepy");
    assert_eq!(
        refused,
        vec![
            auto_join::Ignored {
                index: 1,
                reason: Reason::PersonalNamespace
            },
            auto_join::Ignored {
                index: 2,
                reason: Reason::Suspended
            },
        ]
    );
    let user = f.verified("ana@rusticstack.com");
    assert_eq!(f.memberships_of(user), 0);
    assert_eq!(f.role_in(SLUG, owner), 3);
}

#[test]
fn simultaneous_verifications_create_the_organization_once() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    let users: Vec<(UserId, Secret)> = (0..6)
        .map(|n| {
            let user = f.claim(&format!("person{n}@rusticstack.com"));
            let secret = f.link(user);
            (user, secret)
        })
        .collect();
    let store = &f.store;
    std::thread::scope(|scope| {
        for (_, secret) in &users {
            scope.spawn(move || {
                assert!(matches!(
                    email::confirm(store, secret, at(20)).unwrap(),
                    Confirmation::Verified { .. }
                ));
            });
        }
    });
    assert_eq!(f.tenants_named(SLUG), 1);
    let roles: Vec<i64> = users.iter().map(|(u, _)| f.role_in(SLUG, *u)).collect();
    assert_eq!(roles.iter().filter(|r| **r == 3).count(), 1, "{roles:?}");
    assert_eq!(roles.iter().filter(|r| **r == 1).count(), 5, "{roles:?}");
    assert_eq!(f.count(Event::NamespaceCreated), 1);
    assert_eq!(f.count(Event::DomainAutoJoined), 6);
}

#[test]
fn a_restart_changes_nobodys_access_and_joins_nobody_twice() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    let admin = f.verified("ana@rusticstack.com");
    let reader = f.verified("bruno@rusticstack.com");

    assert!(f.rules("rusticstack.com").is_empty());
    f.sign_in("ana@rusticstack.com");
    f.sign_in("bruno@rusticstack.com");
    assert_eq!(
        f.role_in(SLUG, admin),
        3,
        "the administrator is not demoted"
    );
    assert_eq!(f.role_in(SLUG, reader), 1);
    assert_eq!(f.count(Event::DomainAutoJoined), 2);

    let Fixture { dir, store, .. } = f;
    drop(store);
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let parsed = auto_join::parse("rusticstack.com");
    assert!(
        auto_join::set_rules(&store, &parsed.rules)
            .unwrap()
            .is_empty()
    );
    let outcome = local_auth::login(
        &store,
        "bruno@rusticstack.com",
        PASSWORD,
        Policy::default(),
        at(60),
    )
    .unwrap();
    assert!(matches!(outcome, Login::Accepted(_)));
    let tenants: i64 = store
        .read(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM tenants WHERE slug = ?1",
                [SLUG],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(tenants, 1);
}

#[test]
fn removing_a_domain_stops_new_joins_and_removes_nobody() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    let member = f.verified("ana@rusticstack.com");
    assert_eq!(f.role_in(SLUG, member), 3);

    assert!(f.rules("").is_empty());
    assert_eq!(f.role_in(SLUG, member), 3, "existing access stays");
    let newcomer = f.verified("bruno@rusticstack.com");
    f.sign_in("bruno@rusticstack.com");
    assert_eq!(f.role_in(SLUG, newcomer), 0, "no new joins once unlisted");
}

#[test]
fn every_account_keeps_its_own_namespace_independent_of_the_domain_rule() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    let user = f.verified("ana@rusticstack.com");
    f.store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    tenant_creation: registration::TenantCreation::ApprovedUsers,
                    ..registration::policy(tx)?
                },
                at(3),
            )?;
            registration::create_personal_namespace(
                tx,
                Principal::new(user, P::NONE, None, None),
                TenantId::new(),
                Namespace::parse("ana").unwrap(),
                at(30),
            )
        })
        .unwrap();
    assert_eq!(f.role_in("ana", user), 3);
    assert_eq!(f.role_in(SLUG, user), 3);
}

#[test]
fn the_audit_trail_names_the_organization_and_never_the_address() {
    let f = fixture();
    assert!(f.rules("rusticstack.com").is_empty());
    f.verified("ana.secret@rusticstack.com");
    let (joined, leaked): (Vec<String>, i64) = f
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT detail FROM auth_audit WHERE event = ?1")?;
            let joined = stmt
                .query_map([Event::DomainAutoJoined as u8], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let leaked = c.query_row(
                "SELECT COUNT(*) FROM auth_audit WHERE detail LIKE '%ana.secret%'",
                [],
                |r| r.get(0),
            )?;
            Ok((joined, leaked))
        })
        .unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].contains(SLUG), "{}", joined[0]);
    assert_eq!(leaked, 0);
}
