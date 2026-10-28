use std::sync::Mutex;

use rusqlite::{
    params,
    trace::{TraceEvent, TraceEventCodes},
};
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

static SQL: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(_, sql) = event {
        SQL.lock().unwrap().push(sql.to_owned());
    }
}

const PASSWORD: &[u8] = b"an acceptable member password";
const SLUG: &str = "example-com";

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

    fn generation(&self) -> i64 {
        self.store
            .read(|c| {
                c.query_row("SELECT generation FROM auto_join_state", [], |r| r.get(0))
                    .map_err(Error::from)
            })
            .unwrap()
    }

    /// Every statement one `issue_session` runs, in order.
    fn session_statements(&self, user: UserId, ms: i64) -> Vec<String> {
        SQL.lock().unwrap().clear();
        self.store
            .writer()
            .write(move |tx| {
                tx.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(record));
                let issued = local_auth::issue_session(tx, user, Policy::default(), at(ms));
                tx.trace_v2(TraceEventCodes::empty(), None);
                issued.map(|_| ())
            })
            .unwrap();
        std::mem::take(&mut *SQL.lock().unwrap())
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
                    registration::record_installation(tx, "github", "424242", "alpha", at(4))?;
                registration::bind_installation_trusted(tx, installation, tenant, at(5))
            })
            .unwrap();
    }
}

#[test]
fn the_first_matching_person_creates_the_organization_and_later_ones_join_as_readers() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    assert_eq!(
        f.tenants_named(SLUG),
        0,
        "nothing exists until someone matches"
    );

    let first = f.verified("ana@example.com");
    assert_eq!(f.tenants_named(SLUG), 1);
    assert_eq!(f.role_in(SLUG, first), 3, "the first match administers it");

    let second = f.verified("bruno@example.com");
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
    assert!(f.rules("example.com=acme").is_empty());
    let user = f.verified("ana@example.com");
    assert_eq!(f.role_in("acme", user), 1);
    assert_eq!(f.tenants_named("acme"), 1);
    assert_eq!(f.count(Event::NamespaceCreated), 0);
}

#[test]
fn lookalike_domains_never_match() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    for lookalike in [
        "a@evilexample.com",
        "a@example.com.evil.io",
        "a@mail.example.com",
        "a@example.org",
        "a@notexample.com",
        "a@exa\u{043c}ple.com",
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
    assert!(f.rules("EXAMPLE.COM").is_empty());
    let user = f.verified("Ana@EXAMPLE.com");
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
    assert!(f.rules("example.com").is_empty());
    let user = f.claim("ana@example.com");
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
        .write(move |tx| email::request(tx, None, local, "carla@example.com", None, at(13)))
        .unwrap();
    f.sign_in("carla");
    assert_eq!(f.memberships_of(local), 0);
    assert_eq!(f.tenants_named(SLUG), 0);
}

#[test]
fn a_domain_listed_after_the_address_was_verified_joins_at_the_next_sign_in() {
    let f = fixture();
    let user = f.verified("ana@example.com");
    assert_eq!(f.memberships_of(user), 0);
    assert!(f.rules("example.com").is_empty());
    assert_eq!(f.memberships_of(user), 0, "recording the rule joins nobody");
    f.sign_in("ana@example.com");
    assert_eq!(f.role_in(SLUG, user), 3);
    f.sign_in("ana@example.com");
    assert_eq!(f.role_in(SLUG, user), 3);
    assert_eq!(f.count(Event::DomainAutoJoined), 1);
}

#[test]
fn an_account_waiting_for_approval_joins_only_once_admitted() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
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
            email: "ana@example.com",
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
    f.sign_in("ana@example.com");
    assert_eq!(f.role_in(SLUG, pending), 3);
}

#[test]
fn a_suspended_account_cannot_confirm_an_address_or_auto_join() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let user = f.claim("ana@example.com");
    let secret = f.link(user);
    f.store
        .writer()
        .write(move |tx| local_auth::set_active(tx, Authority::HostLocal, user, false, at(12)))
        .unwrap();
    assert_eq!(
        email::confirm(&f.store, &secret, at(20)).unwrap(),
        Confirmation::Refused
    );
    assert_eq!(f.memberships_of(user), 0);
    assert_eq!(f.tenants_named(SLUG), 0);
    assert_eq!(f.count(Event::EmailVerified), 0);
    assert_eq!(f.count(Event::DomainAutoJoined), 0);
}

#[test]
fn a_github_backed_organization_is_never_joined_by_domain() {
    let f = fixture();
    let tenant = f.organization("example-com");
    f.bind_github(tenant);
    let refused = f.rules("other.example, example.com");
    assert_eq!(
        refused,
        vec![auto_join::Ignored {
            index: 2,
            reason: Reason::GithubBacked
        }]
    );
    let user = f.verified("ana@example.com");
    assert_eq!(f.memberships_of(user), 0);

    let g = fixture();
    g.organization("example-com");
    g.store
        .writer()
        .write(|tx| {
            tx.execute(
                "UPDATE tenants SET membership_source = 1 WHERE slug = 'example-com'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(g.rules("example.com").len(), 1);
    let user = g.verified("ana@example.com");
    assert_eq!(g.memberships_of(user), 0);
}

#[test]
fn an_organization_converted_after_start_stops_admitting_by_domain() {
    let f = fixture();
    let tenant = f.organization("example-com");
    assert!(f.rules("example.com").is_empty());
    let early = f.verified("ana@example.com");
    assert_eq!(f.role_in(SLUG, early), 1);

    // Converted after start: the stored rule still names the organization, so the joining transaction must refuse it.
    f.bind_github(tenant);
    let late = f.verified("bruno@example.com");
    assert_eq!(f.role_in(SLUG, late), 0);
    f.sign_in("bruno@example.com");
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
    let refused = f.rules("example.com, sleepy.example=sleepy");
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
    let user = f.verified("ana@example.com");
    assert_eq!(f.memberships_of(user), 0);
    assert_eq!(f.role_in(SLUG, owner), 3);
}

#[test]
fn simultaneous_verifications_create_the_organization_once() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let users: Vec<(UserId, Secret)> = (0..6)
        .map(|n| {
            let user = f.claim(&format!("person{n}@example.com"));
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
    assert!(f.rules("example.com").is_empty());
    let admin = f.verified("ana@example.com");
    let reader = f.verified("bruno@example.com");

    assert!(f.rules("example.com").is_empty());
    f.sign_in("ana@example.com");
    f.sign_in("bruno@example.com");
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
    let parsed = auto_join::parse("example.com");
    assert!(
        auto_join::set_rules(&store, &parsed.rules)
            .unwrap()
            .is_empty()
    );
    let outcome = local_auth::login(
        &store,
        "bruno@example.com",
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
    assert!(f.rules("example.com").is_empty());
    let member = f.verified("ana@example.com");
    assert_eq!(f.role_in(SLUG, member), 3);

    assert!(f.rules("").is_empty());
    assert_eq!(f.role_in(SLUG, member), 3, "existing access stays");
    let newcomer = f.verified("bruno@example.com");
    f.sign_in("bruno@example.com");
    assert_eq!(f.role_in(SLUG, newcomer), 0, "no new joins once unlisted");
}

#[test]
fn every_account_keeps_its_own_namespace_independent_of_the_domain_rule() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let user = f.verified("ana@example.com");
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
    assert!(f.rules("example.com").is_empty());
    f.verified("ana.secret@example.com");
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

impl Fixture {
    fn tenant_id(&self, slug: &'static str) -> TenantId {
        let bytes: [u8; 16] = self
            .store
            .read(|c| {
                c.query_row("SELECT id FROM tenants WHERE slug = ?1", [slug], |r| {
                    r.get(0)
                })
                .map_err(Error::from)
            })
            .unwrap();
        TenantId::from_bytes(bytes).unwrap()
    }

    fn remove(&self, slug: &'static str, user: UserId, now: i64) {
        let (admin, tenant) = (self.admin, self.tenant_id(slug));
        self.store
            .writer()
            .write(move |tx| auth::remove_membership(tx, admin, tenant, user, at(now)))
            .unwrap();
    }

    fn add(&self, slug: &'static str, user: UserId, role: sentinel_core::auth::Role) {
        let (admin, tenant) = (self.admin, self.tenant_id(slug));
        self.store
            .writer()
            .write(move |tx| auth::set_membership(tx, admin, tenant, user, role))
            .unwrap();
    }
}

#[test]
fn a_member_removed_by_an_administrator_is_not_re_added_by_the_domain() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let _ana = f.verified("ana@example.com");
    let bruno = f.verified("bruno@example.com");
    assert_eq!(f.role_in(SLUG, bruno), 1);
    let joins = f.count(Event::DomainAutoJoined);

    f.remove(SLUG, bruno, 100);
    assert_eq!(f.role_in(SLUG, bruno), 0);

    // The first sign-in runs `auto_join::apply`; a changed rule set runs it again at the next one. Neither
    // consumes the veto.
    f.sign_in("bruno@example.com");
    assert!(f.rules("example.com, other.example").is_empty());
    f.sign_in("bruno@example.com");
    assert_eq!(f.role_in(SLUG, bruno), 0, "the removal stands");
    assert_eq!(
        f.count(Event::DomainAutoJoined),
        joins,
        "no join was audited"
    );

    // The veto is per person and per organization.
    let carla = f.verified("carla@example.com");
    assert_eq!(f.role_in(SLUG, carla), 1, "others still join");
    assert_eq!(f.tenants_named(SLUG), 1);
}

#[test]
fn an_administrator_can_add_a_removed_member_back_and_a_second_removal_still_holds() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let _ana = f.verified("ana@example.com");
    let bruno = f.verified("bruno@example.com");
    f.remove(SLUG, bruno, 100);

    f.add(SLUG, bruno, sentinel_core::auth::Role::Operator);
    f.sign_in("bruno@example.com");
    assert_eq!(f.role_in(SLUG, bruno), 2, "an explicit add is not undone");

    f.remove(SLUG, bruno, 300);
    f.sign_in("bruno@example.com");
    assert_eq!(f.role_in(SLUG, bruno), 0);
    let rows: i64 = f
        .store
        .read(|c| {
            c.query_row("SELECT COUNT(*) FROM membership_removals", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(rows, 1, "one tombstone per person and organization");
}

// A sign-in is one writer transaction; once a person was checked under the rules in force, the join logic
// costs it one conditional UPDATE and reads neither the rules nor the organization.
#[test]
fn a_session_checks_auto_join_once_per_rule_set_with_one_statement() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let user = f.verified("ana@example.com");

    let first = f.session_statements(user, 60);
    assert!(
        first.iter().any(|sql| sql.contains("auto_join_domains")),
        "the first sign-in applies the rules: {first:?}"
    );
    let second = f.session_statements(user, 61);
    let joining = |sql: &&String| {
        [
            "auto_join_domains",
            "INTO memberships",
            "membership_removals",
            "t.slug = ?1",
        ]
        .iter()
        .any(|word| sql.contains(word))
    };
    assert_eq!(
        second.iter().filter(joining).count(),
        0,
        "a checked person pays no join read: {second:?}"
    );
    assert_eq!(
        second
            .iter()
            .filter(|sql| sql.contains("UPDATE users SET auto_join_gen"))
            .count(),
        1,
        "{second:?}"
    );
    assert!(
        second.len() < first.len(),
        "{} vs {}",
        second.len(),
        first.len()
    );

    // A changed rule set checks the person once more, then stops again.
    assert!(f.rules("example.com, other.example").is_empty());
    let third = f.session_statements(user, 62);
    assert!(third.iter().any(|sql| sql.contains("auto_join_domains")));
    let fourth = f.session_statements(user, 63);
    assert_eq!(fourth.len(), second.len(), "{fourth:?}");
    assert_eq!(f.role_in(SLUG, user), 3);
}

#[test]
fn a_domain_listed_after_the_person_signed_in_still_joins_at_the_next_sign_in() {
    let f = fixture();
    assert!(f.rules("").is_empty());
    let user = f.verified("ana@example.com");
    f.sign_in("ana@example.com");
    assert_eq!(f.memberships_of(user), 0);
    f.sign_in("ana@example.com");
    assert_eq!(f.memberships_of(user), 0);

    assert!(f.rules("example.com").is_empty());
    f.sign_in("ana@example.com");
    assert_eq!(f.role_in(SLUG, user), 3);
    assert_eq!(f.count(Event::DomainAutoJoined), 1);
}

// The controller rewrites the rules at every start; only a different effective set may send everyone back
// through the join logic.
#[test]
fn the_generation_moves_only_when_the_effective_rules_change() {
    let f = fixture();
    let start = f.generation();
    assert!(f.rules("").is_empty());
    assert_eq!(f.generation(), start, "empty over empty");

    assert!(f.rules("example.com").is_empty());
    let listed = f.generation();
    assert!(listed > start);
    assert!(f.rules("EXAMPLE.com").is_empty());
    assert!(f.rules("example.com").is_empty());
    assert_eq!(f.generation(), listed, "a restart with the same rules");

    assert!(f.rules("example.com=acme").is_empty());
    let renamed = f.generation();
    assert!(renamed > listed, "the same domain for another organization");
    assert!(f.rules("").is_empty());
    assert!(f.generation() > renamed, "removing the last domain");

    // A rule the joining transaction would refuse is not part of the effective set.
    let tenant = f.organization("example-com");
    f.bind_github(tenant);
    let before = f.generation();
    assert_eq!(f.rules("example.com").len(), 1);
    assert_eq!(f.generation(), before, "a refused rule changes nothing");
}

// An account that cannot join yet is not marked checked, so the sign-in after it can join looks again.
#[test]
fn an_unverified_account_is_looked_at_again_until_it_can_join() {
    let f = fixture();
    assert!(f.rules("example.com").is_empty());
    let user = f.claim("ana@example.com");
    let marked = |f: &Fixture| -> i64 {
        f.store
            .read(|c| {
                c.query_row(
                    "SELECT auto_join_gen FROM users WHERE id = ?1",
                    [user.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    };
    let statements = f.session_statements(user, 60);
    assert!(
        statements.iter().any(|sql| sql.contains("auto_join_gen")),
        "{statements:?}"
    );
    assert_eq!(marked(&f), 0, "not eligible, so not checked");
    let secret = f.link(user);
    assert!(matches!(
        email::confirm(&f.store, &secret, at(70)).unwrap(),
        Confirmation::Verified { .. }
    ));
    assert_eq!(f.role_in(SLUG, user), 3);
    f.session_statements(user, 80);
    assert_eq!(marked(&f), f.generation());
}
