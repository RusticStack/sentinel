use rusqlite::{Connection, params};
use sentinel_auth::sealed::Key;
use sentinel_core::{
    InstallationId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    github_events::{self, Event},
    github_members::{self, Check, Membership, Observed, OrgRole, RepoAccess, Timing},
    local_auth::{self, Policy},
    registration::{self, Admission, Applicant, Authority, Refusal, Terms},
    sign_in, sources,
    sources_forge::{self, Snapshot},
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

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    admin: Principal,
    tenant: TenantId,
    installation: InstallationId,
    app: RepoId,
    lib: RepoId,
}

fn stepped(principal: Principal) -> Authority {
    Authority::Credential {
        principal,
        stepped_up: true,
    }
}

fn organization(
    store: &Store,
    admin: Principal,
    slug: &'static str,
    external: u64,
    account: u64,
    personal: bool,
) -> (TenantId, InstallationId) {
    let tenant = TenantId::new();
    let installation = store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse(slug).unwrap(),
                NamespaceKind::Organization,
                at(1),
            )?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: external,
                    account_id: account,
                    login: slug,
                    personal,
                    suspended: false,
                    permissions_valid: true,
                    expected: 0,
                },
                at(1),
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, at(1))?;
            Ok(installation)
        })
        .unwrap();
    (tenant, installation)
}

fn bind_repo(
    store: &Store,
    key_path: &std::path::Path,
    admin: Principal,
    tenant: TenantId,
    installation: InstallationId,
    (name, forge_id, remote): (&'static str, u64, &'static str),
) -> RepoId {
    let repo = RepoId::new();
    let key = Key::load(key_path).unwrap();
    store
        .writer()
        .write(move |tx| {
            auth::create_repo(tx, admin, tenant, repo, name, at(1))?;
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(admin.user),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: remote.into(),
                        allowed_refs: vec!["refs/heads/main".into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, forge_id)),
                },
                &["https://github.com".into()],
                &key,
                at(1),
            )
        })
        .unwrap();
    repo
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key");
    Key::create(&key_path).unwrap();
    let _ = Key::load(&key_path).unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    let admin = Principal::new(root, P::ALL, None, None);
    let (tenant, installation) = organization(&store, admin, "acme", 42, 73, false);
    let app = bind_repo(
        &store,
        &key_path,
        admin,
        tenant,
        installation,
        ("app", 91, "https://github.com/acme/app.git"),
    );
    let lib = bind_repo(
        &store,
        &key_path,
        admin,
        tenant,
        installation,
        ("lib", 92, "https://github.com/acme/lib.git"),
    );
    Fixture {
        _dir: dir,
        store,
        admin,
        tenant,
        installation,
        app,
        lib,
    }
}

impl Fixture {
    fn person(&self, name: &'static str, github: Option<&'static str>) -> UserId {
        let user = UserId::new();
        self.store
            .writer()
            .write(move |tx| {
                provisioning::insert_human(tx, user, name, false, at(1))?;
                if let Some(subject) = github {
                    provisioning::link_verified_identity(tx, user, "github", subject, at(1))?;
                }
                Ok(())
            })
            .unwrap();
        user
    }

    fn back(&self) {
        let tenant = self.tenant;
        self.store
            .writer()
            .write(move |tx| github_members::set_backing_trusted(tx, tenant, true, at(10)))
            .unwrap();
    }

    fn membership(&self, user: UserId) -> Option<(i64, Option<i64>)> {
        let tenant = self.tenant;
        self.store
            .read(move |c| Ok(membership_of(c, tenant, user)))
            .unwrap()
    }

    fn grants(&self, user: UserId) -> Vec<([u8; 16], i64)> {
        let tenant = self.tenant;
        self.store
            .read(move |c| {
                let mut stmt = c.prepare(
                    "SELECT repo_id, permissions FROM repo_grants
                     WHERE tenant_id = ?1 AND user_id = ?2 ORDER BY repo_id",
                )?;
                let rows = stmt.query_map(params![tenant.as_bytes(), user.as_bytes()], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap()
    }

    fn epoch(&self) -> i64 {
        let tenant = self.tenant;
        self.store
            .read(move |c| sentinel_store::tenancy::epoch(c, tenant))
            .unwrap()
    }

    fn check(&self, user: UserId) -> Option<Check> {
        let tenant = self.tenant;
        self.store
            .read(move |c| Ok(check_row(c, tenant, user)))
            .unwrap()
    }

    fn apply(
        &self,
        user: UserId,
        observed: Observed,
        more: bool,
        now: i64,
    ) -> Result<&'static str, Error> {
        let check = self.check(user).expect("a check is queued");
        self.store
            .writer()
            .write(move |tx| github_members::apply(tx, &check, more, &observed, TIMING, at(now)))
    }

    fn audit(&self, event: &'static str) -> usize {
        self.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM auth_audit WHERE event = ?1",
                    [event_code(event)],
                    |r| r.get::<_, i64>(0),
                )? as usize)
            })
            .unwrap()
    }

    fn principal(&self, user: UserId) -> Principal {
        Principal::new(user, P::READ.union(P::RUN), None, None)
    }

    fn can_read(&self, user: UserId, repo: RepoId) -> bool {
        let principal = self.principal(user);
        self.store
            .read(move |c| Ok(auth::require_repo(c, principal, repo, P::READ).is_ok()))
            .unwrap()
    }

    fn can_see_tenant(&self, user: UserId) -> bool {
        let principal = self.principal(user);
        self.store
            .read(move |c| {
                Ok(auth::get_namespace(c, principal, Namespace::parse("acme").unwrap()).is_ok())
            })
            .unwrap()
    }
}

fn event_code(name: &str) -> i64 {
    match name {
        "joined" => 70,
        "role-changed" => 71,
        "removed" => 72,
        other => panic!("unknown audit name {other}"),
    }
}

fn membership_of(c: &Connection, tenant: TenantId, user: UserId) -> Option<(i64, Option<i64>)> {
    c.query_row(
        "SELECT role, synced_ms FROM memberships WHERE tenant_id = ?1 AND user_id = ?2",
        params![tenant.as_bytes(), user.as_bytes()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .ok()
}

fn check_row(c: &Connection, tenant: TenantId, user: UserId) -> Option<Check> {
    c.query_row(
        "SELECT seq, attempts, cursor FROM github_member_checks
         WHERE tenant_id = ?1 AND user_id = ?2 AND next_ms != ?3",
        params![
            tenant.as_bytes(),
            user.as_bytes(),
            github_members::PARKED_MS
        ],
        |r| {
            Ok(Check {
                tenant,
                user,
                seq: r.get(0)?,
                attempts: r.get::<_, i64>(1)? as u32,
                cursor: r
                    .get::<_, Option<[u8; 16]>>(2)?
                    .map(|bytes| RepoId::from_bytes(bytes).unwrap()),
            })
        },
    )
    .ok()
}

fn observed(id: u64, membership: Membership, repos: Vec<(RepoId, RepoAccess)>) -> Observed {
    Observed {
        github_id: Some(id),
        membership,
        repos,
        complete: true,
    }
}

fn role_of(membership: Option<(i64, Option<i64>)>) -> Option<i64> {
    membership.map(|(role, _)| role)
}

#[test]
fn only_a_verified_organization_installation_can_make_a_tenant_github_backed() {
    let f = fixture();
    let tenant = f.tenant;
    let (personal, _) = organization(&f.store, f.admin, "solo", 43, 74, true);
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| github_members::set_backing_trusted(tx, personal, true, at(2))),
        Err(Error::Conflict)
    ));
    let bare = TenantId::new();
    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                bare,
                Namespace::parse("bare").unwrap(),
                NamespaceKind::Organization,
                at(1),
            )
        })
        .unwrap();
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| github_members::set_backing_trusted(tx, bare, true, at(2))),
        Err(Error::Conflict)
    ));
    f.back();
    let epoch = f.epoch();
    f.back();
    assert_eq!(f.epoch(), epoch);
    assert!(
        f.store
            .read(move |c| github_members::is_github_backed(c, tenant))
            .unwrap()
    );
}

#[test]
fn conversion_starts_the_grace_clock_of_existing_members_and_queues_their_check() {
    let f = fixture();
    let alice = f.person("alice", Some("1001"));
    let (admin, tenant) = (f.admin, f.tenant);
    f.store
        .writer()
        .write(move |tx| auth::set_membership(tx, admin, tenant, alice, Role::Operator))
        .unwrap();
    assert_eq!(f.membership(alice), Some((2, None)), "managed here");
    f.back();
    assert_eq!(f.membership(alice), Some((2, Some(10))), "clock started");
    assert!(f.check(alice).is_some(), "queued for verification");
    f.store
        .writer()
        .write(move |tx| github_members::set_backing_trusted(tx, tenant, false, at(11)))
        .unwrap();
    assert_eq!(f.membership(alice), Some((2, None)));
    assert!(f.check(alice).is_none());
}

#[test]
fn an_owner_administers_and_a_demotion_follows_github() {
    let f = fixture();
    f.back();
    let alice = f.person("alice", Some("1001"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1001), at(20)))
        .unwrap();
    assert!(
        f.check(alice).is_some(),
        "the signed hint queued the person"
    );
    assert!(!f.can_see_tenant(alice), "a hint grants nothing");

    let outcome = f
        .apply(
            alice,
            observed(1001, Membership::Active(OrgRole::Owner), vec![]),
            false,
            30,
        )
        .unwrap();
    assert_eq!(outcome, "joined");
    assert_eq!(role_of(f.membership(alice)), Some(3));
    assert!(f.can_see_tenant(alice));
    assert_eq!(f.audit("joined"), 1);

    let epoch = f.epoch();
    let outcome = f
        .apply(
            alice,
            observed(1001, Membership::Active(OrgRole::Member), vec![]),
            false,
            40,
        )
        .unwrap();
    assert_eq!(outcome, "role changed");
    assert_eq!(role_of(f.membership(alice)), Some(2));
    assert!(f.epoch() > epoch);
    assert_eq!(f.audit("role-changed"), 1);
    let principal = Principal::new(alice, P::ALL, None, None);
    assert!(
        f.store
            .read(move |c| Ok(auth::require_tenant_admin(c, principal, tenant).is_err()))
            .unwrap()
    );
}

#[test]
fn repository_grants_follow_github_and_never_exceed_it() {
    assert_eq!(
        github_members::repo_permissions("admin"),
        P::READ.union(P::RUN).union(P::WRITE_SECRETS)
    );
    assert_eq!(
        github_members::repo_permissions("maintain"),
        P::READ.union(P::RUN)
    );
    assert_eq!(
        github_members::repo_permissions("write"),
        P::READ.union(P::RUN)
    );
    assert_eq!(github_members::repo_permissions("triage"), P::READ);
    assert_eq!(github_members::repo_permissions("read"), P::READ);
    for unknown in ["none", "", "owner", "Admin", "custom-role", "write "] {
        assert_eq!(
            github_members::repo_permissions(unknown),
            P::NONE,
            "{unknown:?}"
        );
    }

    let f = fixture();
    f.back();
    let bob = f.person("bob", Some("2002"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(2002), at(20)))
        .unwrap();
    let (app, lib) = (f.app, f.lib);
    let mut repos = vec![
        (
            app,
            RepoAccess::Known(github_members::repo_permissions("write")),
        ),
        (
            lib,
            RepoAccess::Known(github_members::repo_permissions("triage")),
        ),
    ];
    repos.sort_by_key(|(repo, _)| *repo.as_bytes());
    f.apply(
        bob,
        observed(2002, Membership::Active(OrgRole::Member), repos),
        false,
        30,
    )
    .unwrap();
    let grants = f.grants(bob);
    assert_eq!(grants.len(), 2);
    assert!(grants.contains(&(*app.as_bytes(), 3)));
    assert!(grants.contains(&(*lib.as_bytes(), 1)));
    assert!(f.can_read(bob, app) && f.can_read(bob, lib));
    let principal = f.principal(bob);
    let ran = f
        .store
        .read(move |c| {
            Ok((
                auth::require_repo(c, principal, app, P::RUN).is_ok(),
                auth::require_repo(c, principal, lib, P::RUN).is_ok(),
            ))
        })
        .unwrap();
    assert_eq!(ran, (true, false));

    let epoch = f.epoch();
    f.apply(
        bob,
        observed(
            2002,
            Membership::Active(OrgRole::Member),
            vec![
                (app, RepoAccess::Known(P::READ)),
                (lib, RepoAccess::Known(P::NONE)),
            ],
        ),
        false,
        40 + HOUR,
    )
    .unwrap();
    assert_eq!(f.grants(bob), vec![(*app.as_bytes(), 1)]);
    assert!(f.epoch() > epoch);
    assert!(!f.can_read(bob, lib));
    let epoch = f.epoch();
    f.apply(
        bob,
        observed(
            2002,
            Membership::Active(OrgRole::Member),
            vec![(app, RepoAccess::Known(P::READ))],
        ),
        false,
        40 + 2 * HOUR,
    )
    .unwrap();
    assert_eq!(f.epoch(), epoch, "a confirmation is not a change of access");
}

#[test]
fn a_member_who_left_the_organization_loses_every_trace_of_access() {
    let f = fixture();
    f.back();
    let carol = f.person("carol", Some("3003"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(3003), at(20)))
        .unwrap();
    f.apply(
        carol,
        observed(
            3003,
            Membership::Active(OrgRole::Member),
            vec![(f.app, RepoAccess::Known(P::READ))],
        ),
        false,
        30,
    )
    .unwrap();
    assert!(f.can_read(carol, f.app));
    let epoch = f.epoch();
    let outcome = f
        .apply(carol, observed(3003, Membership::Absent, vec![]), false, 40)
        .unwrap();
    assert_eq!(outcome, "removed: not a member");
    assert_eq!(f.membership(carol), None);
    assert!(
        f.grants(carol).is_empty(),
        "grants went with the membership"
    );
    assert!(!f.can_read(carol, f.app));
    assert!(!f.can_see_tenant(carol));
    assert!(f.epoch() > epoch, "streams must re-authorize");
    assert!(f.check(carol).is_none(), "nothing left queued");
    assert_eq!(f.audit("removed"), 1);
    assert!(
        f.store
            .read(move |c| Ok(c
                .query_row(
                    "SELECT active FROM users WHERE id = ?1",
                    [carol.as_bytes()],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()))
            .unwrap()
    );
}

#[test]
fn an_unknown_answer_keeps_access_within_grace_grants_nothing_and_expires() {
    let f = fixture();
    f.back();
    let dave = f.person("dave", Some("4004"));
    let erin = f.person("erin", Some("5005"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            github_members::hint(tx, tenant, Some(4004), at(20))?;
            github_members::hint(tx, tenant, Some(5005), at(20))
        })
        .unwrap();
    f.apply(
        dave,
        observed(4004, Membership::Active(OrgRole::Member), vec![]),
        false,
        100,
    )
    .unwrap();
    assert!(f.can_see_tenant(dave));

    let unreachable = |user: UserId, now: i64| {
        let check = f.check(user).unwrap();
        f.store
            .writer()
            .write(move |tx| {
                github_members::unreachable(tx, &check, TIMING, at(now), Some(120_000))
            })
            .unwrap()
    };
    assert_eq!(unreachable(dave, 100 + HOUR), "kept: unreachable");
    assert_eq!(unreachable(erin, 100 + HOUR), "kept: unreachable");
    assert!(
        f.can_see_tenant(dave),
        "stale cache keeps access inside grace"
    );
    assert!(!f.can_see_tenant(erin), "unknown grants nothing new");
    assert_eq!(
        f.apply(
            dave,
            observed(4004, Membership::Unknown, vec![]),
            false,
            100 + 2 * HOUR
        )
        .unwrap(),
        "kept: unknown"
    );
    let mut last = "";
    for attempt in 0..6 {
        last = unreachable(erin, 100 + 3 * HOUR + attempt);
        if f.check(erin).is_none() {
            break;
        }
    }
    assert_eq!(last, "dropped: unreachable");
    let outcome = unreachable(dave, 100 + 24 * HOUR);
    assert_eq!(outcome, "removed: grace expired");
    assert!(!f.can_see_tenant(dave));
}

#[test]
fn a_backed_tenant_without_a_target_still_expires_derived_access() {
    let f = fixture();
    f.back();
    let gina = f.person("gina", Some("7007"));
    let hugo = f.person("hugo", Some("8008"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            github_members::hint(tx, tenant, Some(7007), at(20))?;
            github_members::hint(tx, tenant, Some(8008), at(20))
        })
        .unwrap();
    f.apply(
        gina,
        observed(7007, Membership::Active(OrgRole::Member), vec![]),
        false,
        100,
    )
    .unwrap();
    assert!(f.can_see_tenant(gina));
    // The installation loses its organization account while the tenant stays GitHub-backed.
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE installations SET account_id = NULL WHERE tenant_id = ?1",
                [tenant.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let check = f.check(gina).unwrap();
    f.store
        .read(move |c| {
            assert!(github_members::target(c, &check)?.is_none());
            Ok(())
        })
        .unwrap();
    let no_target = |user: UserId, now: i64| {
        let check = f.check(user).unwrap();
        f.store
            .writer()
            .write(move |tx| github_members::no_target(tx, &check, TIMING, at(now)))
            .unwrap()
    };
    assert_eq!(no_target(gina, 100 + HOUR), "kept: unreachable");
    assert!(f.can_see_tenant(gina), "inside grace the access stays");
    assert!(
        f.check(gina).is_some(),
        "the row stays so the grace can end"
    );
    assert_eq!(
        f.membership(gina).unwrap().1,
        Some(100),
        "the clock is the last confirmation"
    );
    assert_eq!(no_target(gina, 100 + 24 * HOUR), "removed: grace expired");
    assert!(!f.can_see_tenant(gina));

    // A derived member whose clock never started gets one now and expires a grace period later.
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO memberships(tenant_id, user_id, role, synced_ms) VALUES (?1, ?2, 1, NULL)",
                params![tenant.as_bytes(), hugo.as_bytes()],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO github_member_checks(tenant_id, user_id, next_ms) VALUES (?1, ?2, 0)",
                params![tenant.as_bytes(), hugo.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(no_target(hugo, 1_000), "kept: unreachable");
    assert_eq!(f.membership(hugo).unwrap().1, Some(1_000));
    assert_eq!(no_target(hugo, 1_000 + 24 * HOUR), "removed: grace expired");
    assert!(f.membership(hugo).is_none());

    // A tenant that is no longer GitHub-backed owes nothing: the row goes.
    let ines = f.person("ines", Some("9009"));
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(9009), at(2_000)))
        .unwrap();
    f.store
        .writer()
        .write(move |tx| github_members::set_backing_trusted(tx, tenant, false, at(2_100)))
        .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO github_member_checks(tenant_id, user_id, next_ms) VALUES (?1, ?2, 0)",
                params![tenant.as_bytes(), ines.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(no_target(ines, 3_000), "target gone");
    assert!(f.check(ines).is_none());
}

#[test]
fn an_answer_about_a_different_github_account_is_discarded() {
    let f = fixture();
    f.back();
    let frank = f.person("frank", Some("6006"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(6006), at(20)))
        .unwrap();
    // Observations match the GitHub numeric id, never the login, so a reused login admits no one.
    let outcome = f
        .apply(
            frank,
            observed(7007, Membership::Active(OrgRole::Owner), vec![]),
            false,
            30,
        )
        .unwrap();
    assert_eq!(outcome, "identity changed");
    assert_eq!(f.membership(frank), None);
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM external_identities WHERE user_id = ?1",
                [frank.as_bytes()],
            )?;
            provisioning::link_verified_identity(tx, frank, "github", "8008", at(31))
        })
        .unwrap();
    let outcome = f
        .apply(
            frank,
            observed(6006, Membership::Active(OrgRole::Owner), vec![]),
            false,
            32,
        )
        .unwrap();
    assert_eq!(outcome, "identity changed");
    assert_eq!(f.membership(frank), None);
}

#[test]
fn an_observation_older_than_a_signed_event_is_superseded_and_writes_nothing() {
    let f = fixture();
    f.back();
    let nora = f.person("nora", Some("1616"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1616), at(20)))
        .unwrap();
    f.apply(
        nora,
        observed(1616, Membership::Active(OrgRole::Member), vec![]),
        false,
        30,
    )
    .unwrap();
    assert!(f.can_see_tenant(nora));

    let stale_check = f.check(nora).unwrap();
    let removal = Event::Members {
        installation: 42,
        user: Some(1616),
        removed: true,
    };
    f.store
        .writer()
        .write(move |tx| github_events::accept(tx, "delivery-s", &[9u8; 32], &removal, at(40)))
        .unwrap();
    assert_eq!(f.membership(nora), None);

    let observation = observed(1616, Membership::Active(OrgRole::Member), vec![]);
    let outcome = f
        .store
        .writer()
        .write(move |tx| {
            github_members::apply(tx, &stale_check, false, &observation, TIMING, at(41))
        })
        .unwrap();
    assert_eq!(outcome, "superseded");
    assert_eq!(
        f.membership(nora),
        None,
        "the removal stands until a fresh check"
    );
    let outcome = f
        .store
        .writer()
        .write(move |tx| github_members::unreachable(tx, &stale_check, TIMING, at(42), None))
        .unwrap();
    assert_eq!(outcome, "superseded");
    assert!(f.check(nora).is_some(), "the fresh check is still queued");
}

#[test]
fn opening_a_backed_tenant_with_a_stale_confirmation_asks_for_a_check() {
    let f = fixture();
    f.back();
    let owen = f.person("owen", Some("1717"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1717), at(20)))
        .unwrap();
    f.apply(
        owen,
        observed(1717, Membership::Active(OrgRole::Member), vec![]),
        false,
        1_000,
    )
    .unwrap();
    let ttl = github_members::OPEN_TTL_MS;
    let stale = |now: i64| {
        f.store
            .read(move |c| github_members::touch(c, tenant, owen, ttl, at(now)))
            .unwrap()
    };
    assert!(
        !stale(1_000 + ttl - 1),
        "a fresh confirmation asks for nothing"
    );
    assert!(stale(1_000 + ttl), "an old one does");
    let stranger = f.person("stranger", Some("1818"));
    assert!(
        !f.store
            .read(move |c| github_members::touch(c, tenant, stranger, ttl, at(10 * ttl)))
            .unwrap()
    );
}

#[test]
fn a_suspended_tenants_members_keep_honest_clocks() {
    let f = fixture();
    f.back();
    let pia = f.person("pia", Some("1919"));
    let (admin, tenant) = (f.admin, f.tenant);
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1919), at(20)))
        .unwrap();
    f.apply(
        pia,
        observed(1919, Membership::Active(OrgRole::Member), vec![]),
        false,
        30,
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            sentinel_store::tenancy::suspend(tx, stepped(admin), tenant, at(40)).map(|_| ())
        })
        .unwrap();
    let check = f.check(pia).unwrap();
    let target = f
        .store
        .read(move |c| github_members::target(c, &check))
        .unwrap();
    assert!(target.is_some());
}

#[test]
fn a_renamed_login_keeps_access_and_the_numeric_id_is_the_only_key() {
    let f = fixture();
    f.back();
    let gina = f.person("gina", Some("9009"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(9009), at(20)))
        .unwrap();
    f.apply(
        gina,
        observed(9009, Membership::Active(OrgRole::Member), vec![]),
        false,
        30,
    )
    .unwrap();
    let outcome = f
        .apply(
            gina,
            observed(9009, Membership::Active(OrgRole::Member), vec![]),
            false,
            40 + HOUR,
        )
        .unwrap();
    assert_eq!(outcome, "confirmed");
    assert_eq!(role_of(f.membership(gina)), Some(2));
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1_234_567), at(50)))
        .unwrap();
    let queued: i64 = f
        .store
        .read(|c| {
            Ok(
                c.query_row("SELECT COUNT(*) FROM github_member_checks", [], |r| {
                    r.get(0)
                })
                .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(queued, 1, "only the linked account has a check");
}

#[test]
fn unlinking_github_removes_the_derived_access_and_only_that() {
    let f = fixture();
    f.back();
    let (second, _) = organization(&f.store, f.admin, "beta", 44, 75, false);
    let (admin, tenant) = (f.admin, f.tenant);
    let henry = f.person("henry", Some("1010"));
    f.store
        .writer()
        .write(move |tx| {
            github_members::hint(tx, tenant, Some(1010), at(20))?;
            auth::set_membership(tx, admin, second, henry, Role::Reader)
        })
        .unwrap();
    f.apply(
        henry,
        observed(1010, Membership::Active(OrgRole::Member), vec![]),
        false,
        30,
    )
    .unwrap();
    assert!(f.can_see_tenant(henry));

    f.store
        .writer()
        .write(move |tx| {
            sign_in::unlink(
                tx,
                Authority::Credential {
                    principal: Principal::new(henry, P::ALL, None, None),
                    stepped_up: true,
                },
                henry,
                "github",
                at(40),
            )
        })
        .unwrap();
    assert_eq!(
        f.membership(henry),
        None,
        "derived access ended with the link"
    );
    assert!(f.check(henry).is_none());
    let beta_role = f
        .store
        .read(move |c| Ok(membership_of(c, second, henry)))
        .unwrap();
    assert_eq!(
        beta_role.map(|m| m.0),
        Some(1),
        "an app-managed membership stays"
    );
    assert!(
        f.store
            .read(move |c| Ok(sign_in::identities(
                c,
                Authority::Credential {
                    principal: Principal::new(henry, P::ALL, None, None),
                    stepped_up: false
                },
                henry
            )
            .unwrap()
            .is_empty()))
            .unwrap()
    );
}

#[test]
fn people_cannot_be_added_invited_granted_or_removed_by_hand_in_a_backed_tenant() {
    let f = fixture();
    let (admin, tenant) = (f.admin, f.tenant);
    let kept = f.person("kept", None);
    let outsider = f.person("outsider", None);
    let invitation = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                stepped(admin),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                at(2),
            )
        })
        .unwrap();
    f.back();

    let refused = registration::register(
        &f.store,
        Applicant::Local {
            display_name: "Eve",
            username: "eve",
            password: PASSWORD,
        },
        Some(&invitation.secret),
        at(20),
    )
    .unwrap();
    assert!(matches!(
        refused,
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    assert!(matches!(
        f.store.writer().write(move |tx| registration::invite(
            tx,
            stepped(admin),
            Terms {
                tenant: Some(tenant),
                role: Some(Role::Reader),
                ..Terms::default()
            },
            at(21),
        )),
        Err(Error::Forbidden)
    ));
    assert!(
        f.store
            .writer()
            .write(move |tx| registration::invite(tx, stepped(admin), Terms::default(), at(22)))
            .is_ok()
    );

    let attempts = f.store.writer().write(move |tx| {
        Ok((
            auth::set_membership(tx, admin, tenant, outsider, Role::Operator),
            auth::set_membership(tx, admin, tenant, kept, Role::TenantAdmin),
            auth::remove_membership(tx, admin, tenant, kept, at(23)),
        ))
    });
    let (add, promote, remove) = attempts.unwrap();
    assert!(matches!(add, Err(Error::Forbidden)));
    assert!(matches!(promote, Err(Error::Forbidden)));
    assert!(matches!(remove, Err(Error::Forbidden)));
    let (app, kept_id) = (f.app, kept);
    let grant = f
        .store
        .writer()
        .write(move |tx| Ok(auth::set_repo_grant(tx, admin, app, kept_id, P::READ)))
        .unwrap();
    assert!(matches!(grant, Err(Error::Forbidden)));
    assert_eq!(f.membership(outsider), None);
    assert_eq!(f.membership(kept), None);
    assert!(f.grants(kept).is_empty());
}

#[test]
fn a_signed_removal_revokes_at_once_and_a_replay_is_a_recorded_no_op() {
    let f = fixture();
    f.back();
    let ivy = f.person("ivy", Some("1111"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1111), at(20)))
        .unwrap();
    f.apply(
        ivy,
        observed(
            1111,
            Membership::Active(OrgRole::Member),
            vec![(f.app, RepoAccess::Known(P::READ))],
        ),
        false,
        30,
    )
    .unwrap();
    assert!(f.can_read(ivy, f.app));

    let removal = Event::Members {
        installation: 42,
        user: Some(1111),
        removed: true,
    };
    let digest = [7u8; 32];
    let first = f
        .store
        .writer()
        .write({
            let removal = removal.clone();
            move |tx| github_events::accept(tx, "delivery-1", &digest, &removal, at(50))
        })
        .unwrap();
    assert_eq!(first, ("member_removed".to_owned(), false));
    assert_eq!(f.membership(ivy), None, "no network round trip was needed");
    assert!(!f.can_read(ivy, f.app));
    assert!(
        f.check(ivy).is_some(),
        "a check follows, in case the removal was stale"
    );

    f.apply(
        ivy,
        observed(1111, Membership::Active(OrgRole::Member), vec![]),
        false,
        60,
    )
    .unwrap();
    assert!(f.can_see_tenant(ivy));

    let replay = f
        .store
        .writer()
        .write({
            let removal = removal.clone();
            move |tx| github_events::accept(tx, "delivery-1", &digest, &removal, at(70))
        })
        .unwrap();
    assert_eq!(replay, ("member_removed".to_owned(), true));
    assert!(f.can_see_tenant(ivy), "a replay must not revoke again");
    let tampered = f
        .store
        .writer()
        .write(move |tx| github_events::accept(tx, "delivery-1", &[8u8; 32], &removal, at(71)));
    assert!(matches!(tampered, Err(Error::Conflict)));
}

#[test]
fn membership_events_of_another_installation_or_an_unbacked_tenant_touch_nothing() {
    let f = fixture();
    let jack = f.person("jack", Some("1212"));
    let (admin, tenant) = (f.admin, f.tenant);
    f.store
        .writer()
        .write(move |tx| auth::set_membership(tx, admin, tenant, jack, Role::Operator))
        .unwrap();
    let event = Event::Members {
        installation: 42,
        user: Some(1212),
        removed: true,
    };
    let outcome = f
        .store
        .writer()
        .write({
            let event = event.clone();
            move |tx| github_events::accept(tx, "d-unbacked", &[1u8; 32], &event, at(50))
        })
        .unwrap();
    assert_eq!(outcome.0, "not_github_backed");
    assert!(f.membership(jack).is_some());

    // The signed delivery's installation id picks the tenant, never the body.
    f.back();
    let (_other, _) = organization(&f.store, f.admin, "gamma", 45, 76, false);
    let foreign = Event::Members {
        installation: 45,
        user: Some(1212),
        removed: true,
    };
    let outcome = f
        .store
        .writer()
        .write(move |tx| github_events::accept(tx, "d-foreign", &[2u8; 32], &foreign, at(60)))
        .unwrap();
    assert_eq!(outcome.0, "not_github_backed");
    assert!(f.membership(jack).is_some());
    let _ = f.installation;
}

#[test]
fn a_sign_in_queues_checks_without_waiting_and_cannot_be_used_to_flood() {
    let f = fixture();
    f.back();
    let kate = f.person("kate", Some("1313"));
    let plain = f.person("plain", None);
    let issue = |user: UserId, now: i64| {
        f.store
            .writer()
            .write(move |tx| local_auth::issue_session(tx, user, Policy::default(), at(now)))
            .unwrap();
    };
    issue(plain, 100);
    assert!(
        f.check(plain).is_none(),
        "no linked GitHub account, nothing to ask"
    );
    issue(kate, 100);
    let queued = f.check(kate).expect("the sign-in queued a check");
    issue(kate, 1_000);
    assert_eq!(f.check(kate).unwrap().seq, queued.seq);
}

#[test]
fn releasing_the_installation_returns_the_tenant_to_app_managed_membership() {
    let f = fixture();
    f.back();
    let lena = f.person("lena", Some("1414"));
    let (admin, tenant, installation) = (f.admin, f.tenant, f.installation);
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1414), at(20)))
        .unwrap();
    f.apply(
        lena,
        observed(1414, Membership::Active(OrgRole::Member), vec![]),
        false,
        30,
    )
    .unwrap();
    f.store
        .writer()
        .write(move |tx| registration::unbind_installation(tx, admin, installation, at(40)))
        .unwrap();
    assert_eq!(
        f.membership(lena),
        Some((2, None)),
        "kept, now managed here"
    );
    assert!(
        !f.store
            .read(move |c| github_members::is_github_backed(c, tenant))
            .unwrap()
    );
    f.store
        .writer()
        .write(move |tx| auth::set_membership(tx, admin, tenant, lena, Role::Reader))
        .unwrap();
}

#[test]
fn a_walk_over_many_repositories_resumes_where_it_stopped() {
    let f = fixture();
    f.back();
    let mia = f.person("mia", Some("1515"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1515), at(20)))
        .unwrap();
    let mut both = [f.app, f.lib];
    both.sort_by_key(|r| *r.as_bytes());
    let (first, second) = (both[0], both[1]);
    let partial = Observed {
        github_id: Some(1515),
        membership: Membership::Active(OrgRole::Member),
        repos: vec![(first, RepoAccess::Known(P::READ))],
        complete: false,
    };
    f.apply(mia, partial, true, 30).unwrap();
    assert_eq!(f.grants(mia), vec![(*first.as_bytes(), 1)]);
    let check = f.check(mia).unwrap();
    assert_eq!(check.cursor, Some(first));
    assert_eq!(check.attempts, 1, "a throttled step counts as a failure");
    let target = f
        .store
        .read(move |c| github_members::target(c, &check))
        .unwrap()
        .unwrap();
    assert_eq!(
        target.repos.iter().map(|r| r.repo).collect::<Vec<_>>(),
        vec![second]
    );
    assert!(!target.more);
    assert_eq!(target.org_id, 73);
    assert_eq!(target.github_id, Some(1515));
}

#[test]
fn a_finished_pass_keeps_the_on_demand_gap_instead_of_forgetting_the_check() {
    let f = fixture();
    f.back();
    let ned = f.person("ned", Some("1717"));
    let enqueue = |now: i64| {
        f.store
            .writer()
            .write(move |tx| github_members::enqueue_user(tx, ned, at(now)))
            .unwrap()
    };
    assert_eq!(enqueue(100), 1, "the first sign-in queues a check");
    let outcome = f
        .apply(ned, observed(1717, Membership::Absent, vec![]), false, 200)
        .unwrap();
    assert_eq!(outcome, "not a member");
    assert!(f.check(ned).is_none(), "nothing is owed after the pass");

    // Repeated sign-ins inside the gap must not queue GitHub traffic again, even though the pass finished.
    for now in [300, 10_000, 59_000] {
        assert_eq!(enqueue(now), 0, "inside the gap at {now}");
        assert!(f.check(ned).is_none(), "still nothing owed at {now}");
    }
    // The gap is measured from the pass that finished, and a later sign-in queues again.
    assert_eq!(enqueue(200 + github_members::MIN_ON_DEMAND_GAP_MS), 1);
    assert!(f.check(ned).is_some());

    // A signed event is not on-demand traffic: it wakes a parked row at once.
    f.apply(
        ned,
        observed(1717, Membership::Absent, vec![]),
        false,
        70_000,
    )
    .unwrap();
    assert!(f.check(ned).is_none());
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(1717), at(70_100)))
        .unwrap();
    assert!(f.check(ned).is_some(), "a signed hint is never held back");
}

#[test]
fn parked_rows_do_not_pile_up_and_a_tenant_wide_hint_leaves_them_asleep() {
    let f = fixture();
    f.back();
    let oda = f.person("oda", Some("1818"));
    let pam = f.person("pam", Some("1919"));
    for (user, id) in [(oda, 1818), (pam, 1919)] {
        f.store
            .writer()
            .write(move |tx| github_members::enqueue_user(tx, user, at(100)))
            .unwrap();
        f.apply(user, observed(id, Membership::Absent, vec![]), false, 200)
            .unwrap();
    }
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, None, at(300)))
        .unwrap();
    assert!(f.check(oda).is_none() && f.check(pam).is_none());

    let rows = || -> i64 {
        f.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM github_member_checks WHERE next_ms = ?1",
                    [github_members::PARKED_MS],
                    |r| r.get(0),
                )
                .unwrap())
            })
            .unwrap()
    };
    assert_eq!(rows(), 2);
    // Another person's sign-in, after the gap, sweeps the parked rows that no longer hold a gap.
    let quin = f.person("quin", Some("2020"));
    f.store
        .writer()
        .write(move |tx| {
            github_members::enqueue_user(tx, quin, at(200 + github_members::MIN_ON_DEMAND_GAP_MS))
        })
        .unwrap();
    assert_eq!(rows(), 0);
}

#[test]
fn a_repository_that_cannot_be_read_keeps_its_grant_and_does_not_stop_the_walk() {
    let f = fixture();
    f.back();
    let rae = f.person("rae", Some("2121"));
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(2121), at(20)))
        .unwrap();
    let mut both = [f.app, f.lib];
    both.sort_by_key(|r| *r.as_bytes());
    let (first, second) = (both[0], both[1]);
    f.apply(
        rae,
        observed(
            2121,
            Membership::Active(OrgRole::Member),
            vec![(first, RepoAccess::Known(P::READ))],
        ),
        false,
        30,
    )
    .unwrap();
    assert_eq!(f.grants(rae), vec![(*first.as_bytes(), 1)]);

    // The first repository now answers unknown; the second is still settled in the same pass.
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(2121), at(40)))
        .unwrap();
    f.apply(
        rae,
        observed(
            2121,
            Membership::Active(OrgRole::Member),
            vec![
                (first, RepoAccess::Unknown),
                (second, RepoAccess::Known(P::READ.union(P::RUN))),
            ],
        ),
        false,
        50,
    )
    .unwrap();
    let mut expected = vec![(*first.as_bytes(), 1), (*second.as_bytes(), 3)];
    expected.sort();
    assert_eq!(f.grants(rae), expected, "unknown changes nothing");
    let check = f.check(rae).unwrap();
    assert_eq!(
        check.attempts, 0,
        "an unreadable repository is not a failed pass"
    );
    assert_eq!(check.cursor, None, "the walk finished");

    // Never confirmed again, the unknown repository's grant lapses with the grace period.
    f.store
        .writer()
        .write(move |tx| github_members::hint(tx, tenant, Some(2121), at(60)))
        .unwrap();
    f.apply(
        rae,
        observed(
            2121,
            Membership::Active(OrgRole::Member),
            vec![
                (first, RepoAccess::Unknown),
                (second, RepoAccess::Known(P::READ.union(P::RUN))),
            ],
        ),
        false,
        50 + 25 * HOUR,
    )
    .unwrap();
    assert_eq!(f.grants(rae), vec![(*second.as_bytes(), 3)]);
}
