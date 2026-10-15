//! `NotFound` over `Forbidden` is asserted by value, not timing: the store does one keyed probe either way.

use std::thread;

use rusqlite::{Connection, params};
use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{
    InstallationId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_protocol::{
    cursor::{Cursor, CursorError, Seq, StreamKind},
    source::{Binding, Credential},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    auto_join,
    email::{self, Confirmation},
    github_members::{self, Check, Membership, Observed, OrgRole, RepoAccess, Timing},
    jobs, local_auth, lookup,
    registration::{self, Accepted, Admission, Applicant, Terms},
    secrets::{self, Scope, Update},
    sources,
    sources_forge::{self, Snapshot},
    tenancy::{self, PoolKind},
    views,
};

const PASSWORD: &[u8] = b"an acceptable member password";
const HOUR: i64 = 3_600_000;
const TIMING: Timing = Timing {
    recheck_ms: HOUR,
    grace_ms: 24 * HOUR,
};

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn principal(user: UserId) -> Principal {
    Principal::new(user, P::ALL, None, None)
}

fn stepped(user: UserId) -> Authority {
    Authority::Credential {
        principal: principal(user),
        stepped_up: true,
    }
}

struct World {
    dir: tempfile::TempDir,
    store: Store,
    admin: Principal,
    owner: UserId,
    colleague: UserId,
    bruno: UserId,
    rustic: TenantId,
    mutual: TenantId,
    owner_home: TenantId,
    colleague_home: TenantId,
    rustic_app: RepoId,
    owner_notes: RepoId,
    mutual_site: RepoId,
    colleague_dots: RepoId,
}

impl World {
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
                display_name: "Person",
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

    fn tenant(&self, slug: &str) -> TenantId {
        self.store
            .read(|c| lookup::tenant_by_slug_any(c, slug))
            .unwrap()
    }

    fn role_in(&self, tenant: TenantId, user: UserId) -> i64 {
        self.store.read(|c| role_of(c, tenant, user)).unwrap()
    }

    fn memberships_of(&self, user: UserId) -> Vec<TenantId> {
        self.store
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT tenant_id FROM memberships WHERE user_id = ?1 ORDER BY 1")?;
                let rows = stmt.query_map([user.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?;
                rows.map(|r| Ok(TenantId::from_bytes(r?).unwrap()))
                    .collect::<Result<Vec<_>, Error>>()
            })
            .unwrap()
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

    fn can_resolve(&self, who: UserId, slug: &str) -> bool {
        match self
            .store
            .read(|c| auth::member_tenant_by_slug(c, principal(who), slug))
        {
            Ok(_) => true,
            Err(Error::NotFound) => false,
            Err(other) => panic!("{slug}: {other:?}"),
        }
    }
}

fn role_of(c: &Connection, tenant: TenantId, user: UserId) -> Result<i64, Error> {
    Ok(c.query_row(
        "SELECT COALESCE((SELECT role FROM memberships WHERE tenant_id = ?1 AND user_id = ?2), 0)",
        params![tenant.as_bytes(), user.as_bytes()],
        |r| r.get(0),
    )?)
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    let admin = principal(root);
    let parsed = auto_join::parse("rusticstack.com=rusticstack, mutualismo.pt=mutualismo");
    assert!(parsed.ignored.is_empty());
    assert!(
        auto_join::set_rules(&store, &parsed.rules)
            .unwrap()
            .is_empty()
    );
    let mut w = World {
        dir,
        store,
        admin,
        owner: root,
        colleague: root,
        bruno: root,
        rustic: TenantId::new(),
        mutual: TenantId::new(),
        owner_home: TenantId::new(),
        colleague_home: TenantId::new(),
        rustic_app: RepoId::new(),
        owner_notes: RepoId::new(),
        mutual_site: RepoId::new(),
        colleague_dots: RepoId::new(),
    };
    w.owner = w.verified("owner@rusticstack.com");
    w.colleague = w.verified("ana@mutualismo.pt");
    w.bruno = w.verified("bruno@mutualismo.pt");
    w.rustic = w.tenant("rusticstack");
    w.mutual = w.tenant("mutualismo");
    let (owner, colleague) = (w.owner, w.colleague);
    let (owner_home, colleague_home) = (w.owner_home, w.colleague_home);
    let (rustic, mutual) = (w.rustic, w.mutual);
    let (rustic_app, owner_notes, mutual_site, colleague_dots) =
        (w.rustic_app, w.owner_notes, w.mutual_site, w.colleague_dots);
    w.store
        .writer()
        .write(move |tx| {
            for (tenant, slug, user) in [
                (owner_home, "owner", owner),
                (colleague_home, "ana", colleague),
            ] {
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Personal(user),
                    at(30),
                )?;
            }
            for (tenant, repo, name) in [
                (rustic, rustic_app, "app"),
                (owner_home, owner_notes, "notes"),
                (mutual, mutual_site, "site"),
                (colleague_home, colleague_dots, "dotfiles"),
            ] {
                auth::create_repo(tx, admin, tenant, repo, name, at(31))?;
            }
            Ok(())
        })
        .unwrap();
    w
}

#[test]
fn the_cast_has_the_roles_the_product_model_promises() {
    let w = world();
    assert_eq!(w.role_in(w.rustic, w.owner), 3, "first match administers");
    assert_eq!(w.role_in(w.mutual, w.colleague), 3);
    assert_eq!(w.role_in(w.mutual, w.bruno), 1, "later matches read");
    assert_eq!(w.role_in(w.owner_home, w.owner), 3);
    assert_eq!(w.role_in(w.colleague_home, w.colleague), 3);
    assert_eq!(w.memberships_of(w.bruno), vec![w.mutual]);
    assert_eq!(
        {
            let mut mine = w.memberships_of(w.owner);
            mine.sort();
            mine
        },
        {
            let mut expected = vec![w.rustic, w.owner_home];
            expected.sort();
            expected
        }
    );
}

#[test]
fn every_resolution_of_a_foreign_namespace_is_the_same_answer_as_a_guess() {
    let w = world();
    let camps = [
        (w.owner, ["rusticstack", "owner"], ["mutualismo", "ana"]),
        (w.colleague, ["mutualismo", "ana"], ["rusticstack", "owner"]),
    ];
    for (who, mine, theirs) in camps {
        for slug in mine {
            assert!(w.can_resolve(who, slug), "{slug} is theirs");
            w.store
                .read(|c| auth::get_namespace(c, principal(who), Namespace::parse(slug).unwrap()))
                .unwrap();
            w.store
                .read(|c| auth::narrowing_by_name(c, who, slug, None))
                .unwrap();
        }
        for slug in theirs.into_iter().chain(["no-such-namespace", "root"]) {
            assert!(!w.can_resolve(who, slug), "{slug} must not resolve");
            assert!(matches!(
                w.store.read(|c| auth::get_namespace(
                    c,
                    principal(who),
                    Namespace::parse(slug).unwrap()
                )),
                Err(Error::NotFound)
            ));
            assert!(matches!(
                w.store
                    .read(|c| auth::narrowing_by_name(c, who, slug, Some("app"))),
                Err(Error::NotFound)
            ));
        }
        for slug in [
            "RusticStack",
            "mutualismo ",
            "mutualismo%00",
            "ana/../owner",
        ] {
            assert!(!w.can_resolve(who, slug) || mine.contains(&slug), "{slug}");
        }
    }
    assert!(w.can_resolve(w.bruno, "mutualismo"));
    for slug in ["rusticstack", "owner", "ana"] {
        assert!(!w.can_resolve(w.bruno, slug), "{slug}");
    }
}

#[test]
fn repositories_runs_and_listings_never_cross_the_camps() {
    let w = world();
    let (owner, colleague, bruno) = (
        principal(w.owner),
        principal(w.colleague),
        principal(w.bruno),
    );
    let run = RunId::new();
    let (rustic, rustic_app) = (w.rustic, w.rustic_app);
    w.store
        .writer()
        .write(move |tx| jobs::insert_run(tx, rustic, rustic_app, run, "abc", at(40)))
        .unwrap();

    for (who, repo) in [
        (owner, w.rustic_app),
        (owner, w.owner_notes),
        (colleague, w.mutual_site),
        (colleague, w.colleague_dots),
    ] {
        w.store
            .read(|c| auth::require_repo(c, who, repo, P::READ))
            .unwrap();
        w.store.read(|c| auth::get_repo(c, who, repo)).unwrap();
    }
    for (who, foreign) in [
        (colleague, [w.rustic_app, w.owner_notes]),
        (owner, [w.mutual_site, w.colleague_dots]),
    ] {
        for repo in foreign.into_iter().chain([RepoId::new()]) {
            for check in [P::READ, P::RUN, P::WRITE_SECRETS] {
                assert!(
                    matches!(
                        w.store.read(|c| auth::require_repo(c, who, repo, check)),
                        Err(Error::NotFound)
                    ),
                    "{check:?} on {repo:?}"
                );
            }
            assert!(matches!(
                w.store.read(|c| auth::get_repo(c, who, repo)),
                Err(Error::NotFound)
            ));
        }
    }
    for who in [colleague, bruno] {
        for guessed in [run, RunId::new()] {
            assert!(matches!(
                w.store.read(|c| auth::get_run_spec(c, who, guessed)),
                Err(Error::NotFound)
            ));
        }
    }
    for (who, tenant) in [
        (colleague, w.rustic),
        (colleague, w.owner_home),
        (owner, w.mutual),
        (owner, w.colleague_home),
        (bruno, w.rustic),
        (bruno, w.mutual),
    ] {
        assert!(
            w.store
                .read(|c| auth::list_repos(c, who, tenant, None, 100))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        w.store
            .read(|c| auth::list_repos(c, owner, w.rustic, None, 100))
            .unwrap()
            .len(),
        1
    );
    let narrowed = Principal::new(w.colleague, P::ALL, Some(w.mutual), None);
    w.store
        .read(|c| auth::require_repo(c, narrowed, w.mutual_site, P::READ))
        .unwrap();
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, narrowed, w.colleague_dots, P::READ)),
        Err(Error::NotFound)
    ));
}

#[test]
fn administration_is_never_reachable_from_the_other_camp_or_by_joining_a_domain() {
    let w = world();
    let (owner, colleague, bruno) = (
        principal(w.owner),
        principal(w.colleague),
        principal(w.bruno),
    );
    for (who, tenant) in [
        (colleague, w.rustic),
        (colleague, w.owner_home),
        (owner, w.mutual),
        (bruno, w.mutual),
        (bruno, w.rustic),
    ] {
        assert!(
            w.store
                .read(|c| views::members(c, who, tenant, None, 10))
                .is_err()
        );
        assert!(
            w.store
                .read(|c| views::operations(c, who, tenant, None, 10))
                .is_err()
        );
        assert!(
            w.store
                .read(|c| registration::invitations(
                    c,
                    Authority::credential(who),
                    Some(tenant),
                    10
                ))
                .is_err()
        );
    }
    let members = w
        .store
        .read(|c| views::members(c, colleague, w.mutual, None, 10))
        .unwrap();
    assert_eq!(
        members.len(),
        2,
        "ana and bruno, nobody from the other camp"
    );
    for foreign in [w.owner, w.admin.user] {
        assert!(members.iter().all(|m| m.user != foreign));
    }

    for (who, tenant, target) in [
        (colleague, w.rustic, w.colleague),
        (colleague, w.owner_home, w.colleague),
        (owner, w.mutual, w.owner),
        (bruno, w.mutual, w.bruno),
    ] {
        let refused = w
            .store
            .writer()
            .write(move |tx| auth::set_membership(tx, who, tenant, target, Role::TenantAdmin));
        assert!(
            matches!(refused, Err(Error::Forbidden) | Err(Error::NotFound)),
            "{refused:?}"
        );
        assert_eq!(
            w.role_in(tenant, target),
            if target == w.bruno { 1 } else { 0 }
        );
    }
    let refused = w
        .store
        .writer()
        .write(move |tx| auth::set_repo_grant(tx, colleague, w.rustic_app, w.colleague, P::READ));
    assert!(matches!(
        refused,
        Err(Error::NotFound) | Err(Error::Forbidden)
    ));
    let refused = w.store.writer().write(move |tx| {
        auth::create_repo(tx, colleague, w.rustic, RepoId::new(), "planted", at(50))
    });
    assert!(refused.is_err());
    assert_eq!(
        w.store
            .read(|c| auth::list_repos(c, owner, w.rustic, None, 100))
            .unwrap()
            .len(),
        1
    );
    let refused = w
        .store
        .writer()
        .write(move |tx| auth::set_membership(tx, bruno, w.mutual, w.bruno, Role::TenantAdmin));
    assert!(matches!(refused, Err(Error::Forbidden)));
    assert_eq!(w.role_in(w.mutual, w.bruno), 1);
}

#[test]
fn secrets_are_sealed_per_tenant_and_a_guess_is_not_a_probe() {
    let w = world();
    let (owner, colleague, bruno) = (
        principal(w.owner),
        principal(w.colleague),
        principal(w.bruno),
    );
    let key_path = w.dir.path().join("master.key");
    let put = |who: Principal, scope: Scope, name: &'static str| {
        let key_path = key_path.clone();
        w.store.writer().write(move |tx| {
            let key = Key::load(&key_path).unwrap();
            secrets::put(
                tx,
                who,
                Update {
                    scope,
                    name,
                    expected: 0,
                    value: b"the value",
                },
                &key,
                at(60),
            )
            .map(|meta| meta.version)
        })
    };
    assert_eq!(put(owner, Scope::Repo(w.rustic_app), "TOKEN").unwrap(), 1);
    assert_eq!(put(owner, Scope::Tenant(w.rustic), "SHARED").unwrap(), 1);
    assert_eq!(
        put(colleague, Scope::Repo(w.mutual_site), "TOKEN").unwrap(),
        1,
        "the same name in another tenant is another secret"
    );

    for scope in [
        Scope::Repo(w.rustic_app),
        Scope::Tenant(w.rustic),
        Scope::Repo(w.owner_notes),
        Scope::Tenant(w.owner_home),
    ] {
        let missing = match scope {
            Scope::Repo(_) => Scope::Repo(RepoId::new()),
            Scope::Tenant(_) => Scope::Tenant(TenantId::new()),
        };
        for name in ["TOKEN", "SHARED", "ABSENT"] {
            let real = w
                .store
                .read(|c| secrets::describe(c, colleague, scope, name))
                .unwrap_err();
            let guess = w
                .store
                .read(|c| secrets::describe(c, colleague, missing, name))
                .unwrap_err();
            assert!(matches!(
                (&real, &guess),
                (Error::NotFound, Error::NotFound)
            ));
        }
        assert!(matches!(
            w.store.read(|c| secrets::list(c, colleague, scope, "", 10)),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            put(colleague, scope, "PLANTED"),
            Err(Error::NotFound)
        ));
    }
    let kept = w
        .store
        .read(|c| secrets::list(c, owner, Scope::Repo(w.rustic_app), "", 10))
        .unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].name, "TOKEN");
    assert_eq!(kept[0].version, 1);
    assert!(matches!(
        w.store
            .read(|c| secrets::list(c, bruno, Scope::Repo(w.mutual_site), "", 10)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        put(bruno, Scope::Tenant(w.mutual), "FROM_READER"),
        Err(Error::NotFound)
    ));
}

#[test]
fn pools_and_workers_belong_to_the_tenant_that_owns_or_is_granted_them() {
    let w = world();
    let (owner, colleague) = (principal(w.owner), principal(w.colleague));
    let (mine, theirs, shared) = (PoolId::new(), PoolId::new(), PoolId::new());
    let (rustic, mutual) = (w.rustic, w.mutual);
    w.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                mine,
                "rustic-builders",
                PoolKind::Dedicated(rustic),
                at(70),
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                theirs,
                "mutual-builders",
                PoolKind::Dedicated(mutual),
                at(70),
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                shared,
                "shared",
                PoolKind::Shared,
                at(70),
            )?;
            tenancy::grant_pool(tx, Authority::HostLocal, shared, mutual, at(71))
        })
        .unwrap();
    let names = |who: Principal, tenant: TenantId| -> Result<Vec<String>, Error> {
        w.store
            .read(|c| tenancy::pools_for_tenant(c, Authority::credential(who), tenant))
            .map(|pools| pools.into_iter().map(|p| p.name).collect())
    };
    assert_eq!(names(owner, w.rustic).unwrap(), ["rustic-builders"]);
    assert_eq!(
        names(colleague, w.mutual).unwrap(),
        ["mutual-builders", "shared"]
    );
    for (who, tenant) in [
        (owner, w.mutual),
        (colleague, w.rustic),
        (colleague, w.owner_home),
        (owner, TenantId::new()),
    ] {
        assert!(matches!(names(who, tenant), Err(Error::NotFound)));
    }
    for (who, pool, ok) in [
        (owner, mine, true),
        (owner, theirs, false),
        (owner, shared, false),
        (colleague, theirs, true),
        (colleague, shared, true),
        (colleague, mine, false),
        (colleague, PoolId::new(), false),
    ] {
        let listed = w
            .store
            .read(|c| sentinel_store::workers::in_pool(c, Authority::credential(who), pool));
        assert_eq!(listed.is_ok(), ok, "{pool:?}");
        if !ok {
            assert!(matches!(listed, Err(Error::NotFound)));
        }
    }
    assert!(matches!(
        w.store
            .read(|c| tenancy::require_pool_access(c, w.rustic, shared)),
        Err(Error::Forbidden)
    ));
}

#[test]
fn a_cursor_names_its_tenant_and_a_foreign_one_is_refused_before_it_is_read() {
    let w = world();
    let attempt = [7u8; 16];
    let minted = Cursor {
        tenant: w.rustic,
        kind: StreamKind::RunEvents,
        stream: attempt,
        seq: Seq(12),
    }
    .to_string();
    assert!(Cursor::parse(&minted, w.rustic).is_ok());
    for other in [w.mutual, w.owner_home, w.colleague_home, TenantId::new()] {
        assert_eq!(
            Cursor::parse(&minted, other),
            Err(CursorError::WrongTenant),
            "{other:?}"
        );
    }
    for forged in [
        minted.replacen('1', "2", 1),
        minted.to_uppercase(),
        minted[..minted.len() - 1].to_owned(),
        format!("{minted}0"),
        String::new(),
    ] {
        match Cursor::parse(&forged, w.mutual) {
            Err(_) => {}
            Ok(parsed) => assert_eq!(parsed.tenant, w.mutual, "{forged}"),
        }
    }
}

#[test]
fn an_invitation_to_one_organization_joins_nothing_else_even_beside_a_domain_match() {
    let w = world();
    let owner = principal(w.owner);
    let rustic = w.rustic;
    let invited = w
        .store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(owner),
                Terms {
                    tenant: Some(rustic),
                    role: Some(Role::Operator),
                    ..Terms::default()
                },
                "carla@mutualismo.pt",
                None,
                at(80),
            )
        })
        .unwrap();
    let carla = w.claim("carla@mutualismo.pt");
    let link = w.link(carla);
    assert_eq!(
        email::confirm(&w.store, &link, at(81)).unwrap(),
        Confirmation::Verified {
            user: carla,
            joined: None
        },
        "a plain verification link redeems no invitation"
    );
    assert_eq!(w.role_in(w.mutual, carla), 1, "domain: reader");
    assert_eq!(
        w.role_in(w.rustic, carla),
        0,
        "an unredeemed invitation grants nothing"
    );
    match registration::accept_invitation(&w.store, carla, &invited.invitation.secret, None, at(82))
        .unwrap()
    {
        Accepted::Joined(tenant) => assert_eq!(tenant, w.rustic),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        w.role_in(w.rustic, carla),
        2,
        "the invitation's role, exactly"
    );
    let mut held = w.memberships_of(carla);
    held.sort();
    let mut expected = vec![w.mutual, w.rustic];
    expected.sort();
    assert_eq!(
        held, expected,
        "nothing of the personal namespaces or others"
    );
    let other = w.verified("dora@mutualismo.pt");
    assert!(matches!(
        registration::accept_invitation(&w.store, other, &invited.invitation.secret, None, at(83))
            .unwrap(),
        Accepted::Unusable
    ));
    assert_eq!(w.role_in(w.rustic, other), 0);
    let colleague = Authority::credential(principal(w.colleague));
    assert!(
        w.store
            .read(|c| registration::invitations(c, colleague, Some(w.rustic), 10))
            .is_err()
    );
}

#[test]
fn an_invitation_cannot_be_redeemed_into_another_tenant_by_tampering_with_who_asks() {
    let w = world();
    let colleague = principal(w.colleague);
    let mutual = w.mutual;
    let link_form = w
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::credential(colleague),
                Terms {
                    tenant: Some(mutual),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                at(90),
            )
        })
        .unwrap();
    match registration::accept_invitation(&w.store, w.owner, &link_form.secret, None, at(91))
        .unwrap()
    {
        Accepted::Joined(tenant) => assert_eq!(tenant, w.mutual),
        other => panic!("{other:?}"),
    }
    assert_eq!(w.role_in(w.mutual, w.owner), 1);
    assert_eq!(w.role_in(w.rustic, w.owner), 3);
    assert!(matches!(
        w.store
            .read(|c| views::members(c, principal(w.owner), w.mutual, None, 10)),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, principal(w.owner), w.mutual_site, P::READ)),
        Err(Error::NotFound)
    ));
}

#[test]
fn domain_joins_racing_a_rule_change_leave_one_administrator_or_no_organization() {
    let w = world();
    let users: Vec<(UserId, Secret)> = (0..6)
        .map(|n| {
            let user = w.claim(&format!("racer{n}@newco.example"));
            (user, w.link(user))
        })
        .collect();
    let parsed = auto_join::parse("newco.example=newco");
    assert!(
        auto_join::set_rules(&w.store, &parsed.rules)
            .unwrap()
            .is_empty()
    );
    let store = &w.store;
    thread::scope(|scope| {
        for (n, (_, secret)) in users.iter().enumerate() {
            scope.spawn(move || {
                email::confirm(store, secret, at(100 + n as i64)).unwrap();
            });
        }
        scope.spawn(|| {
            auto_join::set_rules(store, &auto_join::parse("").rules).unwrap();
        });
    });
    let tenant = w.tenants_named("newco");
    assert!(tenant <= 1, "the organization is created at most once");
    let roles: Vec<i64> = if tenant == 1 {
        let id = w.tenant("newco");
        users.iter().map(|(u, _)| w.role_in(id, *u)).collect()
    } else {
        Vec::new()
    };
    if tenant == 1 {
        assert_eq!(roles.iter().filter(|r| **r == 3).count(), 1, "{roles:?}");
        assert!(roles.iter().all(|r| matches!(r, 0 | 1 | 3)), "{roles:?}");
    }
    for (user, _) in &users {
        assert!(w.memberships_of(*user).len() <= 1);
        assert_eq!(w.role_in(w.rustic, *user), 0);
        assert_eq!(w.role_in(w.mutual, *user), 0);
    }
}

struct Hub {
    tenant: TenantId,
    app: RepoId,
}

fn github_org(w: &World) -> Hub {
    let (admin, tenant) = (w.admin, TenantId::new());
    let app = RepoId::new();
    let key = Key::load(&w.dir.path().join("master.key")).unwrap();
    w.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("ghorg").unwrap(),
                NamespaceKind::Organization,
                at(5),
            )?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: 4242,
                    account_id: 9001,
                    login: "ghorg",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    expected: 0,
                },
                at(5),
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, at(5))?;
            auth::create_repo(tx, admin, tenant, app, "app", at(5))?;
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(admin.user),
                sources::Update {
                    repo: app,
                    expected: 0,
                    binding: &Binding {
                        remote: "https://github.com/ghorg/app.git".into(),
                        allowed_refs: vec!["refs/heads/main".into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, 91)),
                },
                &["https://github.com".into()],
                &key,
                at(5),
            )?;
            github_members::set_backing_trusted(tx, tenant, true, at(6))
        })
        .unwrap();
    Hub { tenant, app }
}

fn person_with_github(w: &World, name: &'static str, subject: &'static str) -> UserId {
    let user = UserId::new();
    w.store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, user, name, false, at(7))?;
            provisioning::link_verified_identity(tx, user, "github", subject, at(7))
        })
        .unwrap();
    user
}

fn check_of(w: &World, tenant: TenantId, user: UserId) -> Option<Check> {
    w.store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT seq, attempts, cursor FROM github_member_checks
                 WHERE tenant_id = ?1 AND user_id = ?2",
                params![tenant.as_bytes(), user.as_bytes()],
                |r| {
                    Ok(Check {
                        tenant,
                        user,
                        seq: r.get(0)?,
                        attempts: r.get::<_, i64>(1)? as u32,
                        cursor: r
                            .get::<_, Option<[u8; 16]>>(2)?
                            .map(|b| RepoId::from_bytes(b).unwrap()),
                    })
                },
            )
            .ok())
        })
        .unwrap()
}

fn confirm_member(w: &World, hub: &Hub, user: UserId, github: u64, role: OrgRole, now: i64) {
    let tenant = hub.tenant;
    w.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(github), at(now)))
        .unwrap();
    let check = check_of(w, hub.tenant, user).expect("queued by the hint");
    let observed = Observed {
        github_id: Some(github),
        membership: Membership::Active(role),
        repos: vec![(hub.app, RepoAccess::Known(P::READ))],
        complete: true,
    };
    w.store
        .writer()
        .write(move |tx| github_members::apply(tx, &check, false, &observed, TIMING, at(now + 1)))
        .unwrap();
}

#[test]
fn a_github_backed_organization_admits_only_people_github_confirmed() {
    let w = world();
    let hub = github_org(&w);
    let confirmed = person_with_github(&w, "gh-member", "1001");
    let hinted = person_with_github(&w, "gh-hinted", "2002");
    let unlinked = UserId::new();
    w.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, unlinked, "no-github", false, at(7)))
        .unwrap();
    confirm_member(&w, &hub, confirmed, 1001, OrgRole::Member, 100);
    let tenant = hub.tenant;
    w.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(2002), at(110)))
        .unwrap();

    assert_eq!(w.role_in(hub.tenant, confirmed), 2);
    assert!(w.can_resolve(confirmed, "ghorg"));
    w.store
        .read(|c| auth::require_repo(c, principal(confirmed), hub.app, P::READ))
        .unwrap();
    for outsider in [hinted, unlinked, w.owner, w.colleague, w.bruno] {
        assert_eq!(w.role_in(hub.tenant, outsider), 0);
        assert!(!w.can_resolve(outsider, "ghorg"));
        assert!(matches!(
            w.store
                .read(|c| auth::require_repo(c, principal(outsider), hub.app, P::READ)),
            Err(Error::NotFound)
        ));
    }
    let admin = w.admin;
    let tenant = hub.tenant;
    for attempt in [
        w.store
            .writer()
            .write(move |tx| auth::set_membership(tx, admin, tenant, unlinked, Role::Reader)),
        w.store.writer().write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(admin),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                "someone@mutualismo.pt",
                None,
                at(120),
            )
            .map(|_| ())
        }),
    ] {
        assert!(attempt.is_err(), "{attempt:?}");
    }
    assert_eq!(w.role_in(hub.tenant, unlinked), 0);
    assert_eq!(w.memberships_of(confirmed), vec![hub.tenant]);
    for slug in ["rusticstack", "mutualismo", "owner", "ana"] {
        assert!(!w.can_resolve(confirmed, slug), "{slug}");
    }
    assert!(matches!(
        w.store
            .read(|c| views::members(c, principal(confirmed), hub.tenant, None, 10)),
        Err(Error::Forbidden)
    ));
    let owner_gh = person_with_github(&w, "gh-owner", "3003");
    confirm_member(&w, &hub, owner_gh, 3003, OrgRole::Owner, 200);
    assert_eq!(w.role_in(hub.tenant, owner_gh), 3);
    let listed = w
        .store
        .read(|c| views::members(c, principal(owner_gh), hub.tenant, None, 10))
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|m| m.synced.is_some()));
}

#[test]
fn leaving_github_removes_that_organizations_access_and_only_that() {
    let w = world();
    let hub = github_org(&w);
    let user = w.verified("eve@mutualismo.pt");
    let (tenant, mutual) = (hub.tenant, w.mutual);
    w.store
        .writer()
        .write(move |tx| provisioning::link_verified_identity(tx, user, "github", "4004", at(8)))
        .unwrap();
    confirm_member(&w, &hub, user, 4004, OrgRole::Member, 300);
    assert_eq!(w.role_in(hub.tenant, user), 2);
    assert_eq!(w.role_in(w.mutual, user), 1);
    assert!(w.can_resolve(user, "ghorg") && w.can_resolve(user, "mutualismo"));

    w.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(4004), at(400)))
        .unwrap();
    let check = check_of(&w, hub.tenant, user).expect("queued");
    w.store
        .writer()
        .write(move |tx| {
            github_members::apply(
                tx,
                &check,
                false,
                &Observed {
                    github_id: Some(4004),
                    membership: Membership::Absent,
                    repos: vec![],
                    complete: true,
                },
                TIMING,
                at(401),
            )
        })
        .unwrap();
    assert_eq!(w.role_in(hub.tenant, user), 0);
    assert!(!w.can_resolve(user, "ghorg"));
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, principal(user), hub.app, P::READ)),
        Err(Error::NotFound)
    ));
    assert_eq!(w.role_in(mutual, user), 1);
    assert!(w.can_resolve(user, "mutualismo"));
    assert!(matches!(
        local_auth::login(
            &w.store,
            "eve@mutualismo.pt",
            PASSWORD,
            local_auth::Policy::default(),
            at(402)
        )
        .unwrap(),
        local_auth::Login::Accepted(_)
    ));
    assert_eq!(w.role_in(w.mutual, w.colleague), 3);
    assert_eq!(w.role_in(w.rustic, w.owner), 3);
    let _ = InstallationId::new();
}

#[test]
fn the_last_administrator_of_an_organization_cannot_be_removed_and_recovery_is_by_the_platform() {
    let w = world();
    let colleague = principal(w.colleague);
    let (mutual, ana, bruno) = (w.mutual, w.colleague, w.bruno);
    for attempt in [
        w.store
            .writer()
            .write(move |tx| auth::set_membership(tx, colleague, mutual, ana, Role::Operator)),
        w.store
            .writer()
            .write(move |tx| auth::remove_membership(tx, colleague, mutual, ana, at(500))),
    ] {
        assert!(matches!(attempt, Err(Error::Conflict)), "{attempt:?}");
    }
    assert_eq!(w.role_in(w.mutual, w.colleague), 3);

    w.store
        .writer()
        .write(move |tx| auth::set_membership(tx, colleague, mutual, bruno, Role::TenantAdmin))
        .unwrap();
    w.store
        .writer()
        .write(move |tx| auth::remove_membership(tx, colleague, mutual, ana, at(501)))
        .unwrap();
    assert!(!w.can_resolve(w.colleague, "mutualismo"));
    assert!(w.can_resolve(w.colleague, "ana"));
    let bruno_p = principal(w.bruno);
    let refused = w
        .store
        .writer()
        .write(move |tx| auth::remove_membership(tx, bruno_p, mutual, bruno, at(502)));
    assert!(matches!(refused, Err(Error::Conflict)));

    let root = w.admin.user;
    let refused = w.store.writer().write(move |tx| {
        auth::set_membership_as(
            tx,
            Authority::credential(principal(root)),
            mutual,
            ana,
            Role::TenantAdmin,
            Some("recovery"),
        )
    });
    assert!(refused.is_err(), "no step-up, no override");
    w.store
        .writer()
        .write(move |tx| {
            auth::set_membership_as(
                tx,
                stepped(root),
                mutual,
                ana,
                Role::TenantAdmin,
                Some("recovery after departure"),
            )
        })
        .unwrap();
    assert_eq!(w.role_in(w.mutual, w.colleague), 3);
    assert_eq!(w.role_in(w.rustic, w.colleague), 0);
    assert_eq!(w.role_in(w.owner_home, w.colleague), 0);
}

#[test]
fn everything_holds_across_a_reopen() {
    let w = world();
    let World {
        dir,
        store,
        owner,
        colleague,
        rustic,
        mutual,
        mutual_site,
        ..
    } = w;
    drop(store);
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    assert!(
        store
            .read(|c| auth::member_tenant_by_slug(c, principal(owner), "rusticstack"))
            .is_ok()
    );
    for (who, slug) in [(owner, "mutualismo"), (colleague, "rusticstack")] {
        assert!(matches!(
            store.read(|c| auth::member_tenant_by_slug(c, principal(who), slug)),
            Err(Error::NotFound)
        ));
    }
    assert!(matches!(
        store.read(|c| auth::require_repo(c, principal(owner), mutual_site, P::READ)),
        Err(Error::NotFound)
    ));
    let _ = (rustic, mutual);
}
