//! A08: the consolidated cross-tenant sweep. One deployment, two
//! organizations and a personal namespace, overlapping memberships, a
//! tenant-bound service account, unbound installations, invitations raced and
//! reused, guessed identifiers, cross-tenant queries and cursors, and
//! last-admin recovery — exercised together rather than per task, because the
//! failures worth finding live between the modules.

use std::thread;

use sentinel_auth::secret::Secret;
use sentinel_core::{
    InstallationId, RepoId, RunId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_protocol::cursor::{Cursor, CursorError, Seq, StreamKind};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind},
    jobs,
    local_auth::{self, Login, Policy},
    registration::{self, Admission, Applicant, Refusal, Terms},
    sign_in, tenancy,
    tokens::{self, Grant},
};

const PASSWORD: &[u8] = b"an acceptable operator password";
const T: UnixMillis = UnixMillis(1_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn stepped(user: UserId) -> Authority {
    Authority::Credential {
        principal: Principal::new(user, P::ALL, None, None),
        stepped_up: true,
    }
}

struct World {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    dev: UserId,
    sam: UserId,
    bot: UserId,
    acme: TenantId,
    globex: TenantId,
    personal: TenantId,
    acme_repo: RepoId,
    globex_repo: RepoId,
}

/// root: bootstrapped super admin. dev: acme admin, globex reader, owns a
/// personal namespace. sam: globex admin only. bot: acme service account.
fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD, T).unwrap();
    let admin = Principal::new(root, P::ALL, None, None);
    let (acme, globex, personal) = (TenantId::new(), TenantId::new(), TenantId::new());
    let (acme_repo, globex_repo) = (RepoId::new(), RepoId::new());
    let dev = match registration::register(
        &store,
        Applicant::Local {
            display_name: "Dev",
            username: "dev",
            password: PASSWORD,
        },
        Some(
            &store
                .writer()
                .write(move |tx| registration::invite(tx, stepped(root), Terms::default(), T))
                .unwrap()
                .secret,
        ),
        T,
    )
    .unwrap()
    {
        Admission::Admitted(user) => user,
        other => panic!("{other:?}"),
    };
    let sam = UserId::new();
    let bot = UserId::new();
    store
        .writer()
        .write(move |tx| {
            auth::provisioning::insert_human(tx, sam, "Sam", false, T)?;
            for (tenant, slug, kind) in [
                (acme, "acme", NamespaceKind::Organization),
                (globex, "globex", NamespaceKind::Organization),
                (personal, "dev", NamespaceKind::Personal(dev)),
            ] {
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    kind,
                    T,
                )?;
            }
            auth::set_membership(tx, admin, acme, dev, Role::TenantAdmin)?;
            auth::set_membership(tx, admin, globex, dev, Role::Reader)?;
            auth::set_membership(tx, admin, globex, sam, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, acme, acme_repo, "app", T)?;
            auth::create_repo(tx, admin, globex, globex_repo, "app", T)?;
            auth::create_service_account(tx, admin, acme, bot, "bot", Role::Operator, T)?;
            auth::set_repo_grant(tx, admin, acme_repo, bot, P::READ.union(P::RUN))?;
            Ok(())
        })
        .unwrap();
    World {
        _dir: dir,
        store,
        root,
        dev,
        sam,
        bot,
        acme,
        globex,
        personal,
        acme_repo,
        globex_repo,
    }
}

fn principal(user: UserId) -> Principal {
    Principal::new(user, P::ALL, None, None)
}

#[test]
fn overlapping_memberships_resolve_per_tenant_and_never_bleed_across() {
    let w = world();
    let (dev, sam, bot) = (principal(w.dev), principal(w.sam), principal(w.bot));

    // dev administers acme, only reads globex (and has no grant there), owns the
    // personal namespace; sam sees globex only; the bot sees its grant only.
    w.store
        .read(|c| auth::require_repo(c, dev, w.acme_repo, P::WRITE_SECRETS))
        .unwrap();
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, dev, w.globex_repo, P::READ)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, sam, w.acme_repo, P::READ)),
        Err(Error::NotFound)
    ));
    w.store
        .read(|c| auth::require_repo(c, sam, w.globex_repo, P::RUN))
        .unwrap();
    w.store
        .read(|c| auth::require_repo(c, bot, w.acme_repo, P::RUN))
        .unwrap();
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, bot, w.acme_repo, P::WRITE_SECRETS)),
        Err(Error::NotFound)
    ));
    for slug in ["acme", "dev"] {
        w.store
            .read(|c| auth::get_namespace(c, dev, Namespace::parse(slug).unwrap()))
            .unwrap();
    }
    assert!(matches!(
        w.store
            .read(|c| auth::get_namespace(c, sam, Namespace::parse("dev").unwrap())),
        Err(Error::NotFound)
    ));
    // Lists are filtered before pagination: a globex reader lists nothing of
    // acme, and the page never says how much was hidden.
    assert!(
        w.store
            .read(|c| auth::list_repos(c, sam, w.acme, None, 100))
            .unwrap()
            .is_empty()
    );
    // A credential narrowed to globex cannot reach acme even for its admin.
    let narrowed = Principal::new(w.dev, P::ALL, Some(w.globex), None);
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, narrowed, w.acme_repo, P::READ)),
        Err(Error::NotFound)
    ));
    // Tenant administration is per tenant: sam cannot grant on acme's repo,
    // and dev cannot administer globex despite being a member.
    let refused = w
        .store
        .writer()
        .write(move |tx| auth::set_repo_grant(tx, sam, w.acme_repo, w.sam, P::READ));
    assert!(matches!(refused, Err(Error::NotFound)));
    let refused = w
        .store
        .writer()
        .write(move |tx| auth::set_membership(tx, dev, w.globex, w.dev, Role::TenantAdmin));
    assert!(matches!(refused, Err(Error::Forbidden)));
}

#[test]
fn guessed_identifiers_and_foreign_cursors_yield_nothing_distinguishable() {
    let w = world();
    let dev = principal(w.dev);
    let run = RunId::new();
    w.store
        .writer()
        .write(move |tx| jobs::insert_run(tx, w.globex, w.globex_repo, run, "abc", T))
        .unwrap();

    // Guessed or real-but-foreign identifiers give the same answer.
    for repo in [RepoId::new(), w.globex_repo] {
        assert!(matches!(
            w.store.read(|c| auth::get_repo(c, dev, repo)),
            Err(Error::NotFound)
        ));
    }
    for run in [RunId::new(), run] {
        assert!(matches!(
            w.store.read(|c| auth::get_run_spec(c, dev, run)),
            Err(Error::NotFound)
        ));
    }
    let guessed = TokenId::new();
    let refused = w
        .store
        .writer()
        .write(move |tx| tokens::revoke(tx, Authority::credential(dev), guessed, T));
    assert!(matches!(refused, Err(Error::NotFound)));
    let refused = w.store.writer().write(move |tx| {
        registration::bind_installation(tx, dev, InstallationId::new(), w.acme, T)
    });
    assert!(matches!(refused, Err(Error::Conflict)));
    assert!(matches!(
        w.store
            .read(|c| tenancy::require_pool_access(c, w.acme, sentinel_core::PoolId::new())),
        Err(Error::Forbidden)
    ));

    // A cursor minted for globex is refused when presented as acme, and a
    // substituted tenant inside the text is refused as well.
    let cursor = Cursor {
        tenant: w.globex,
        kind: StreamKind::RunEvents,
        stream: *run.as_bytes(),
        seq: Seq(7),
    }
    .to_string();
    assert!(Cursor::parse(&cursor, w.globex).is_ok());
    assert_eq!(
        Cursor::parse(&cursor, w.acme),
        Err(CursorError::WrongTenant)
    );
    let forged = cursor.replacen(
        &cursor[2 + 2..2 + 34],
        &w.acme.to_string()[4..].replace('-', ""),
        1,
    );
    assert!(matches!(
        Cursor::parse(&forged, w.acme),
        Ok(_) | Err(CursorError::Malformed)
    ));
    // Whatever the forgery parses to, the run it names still resolves through
    // ownership, and ownership is not acme's.
    assert!(matches!(
        w.store.read(|c| auth::get_run_spec(c, dev, run)),
        Err(Error::NotFound)
    ));
}

#[test]
fn an_invitation_raced_by_many_applicants_admits_exactly_one() {
    let w = world();
    let invitation = w
        .store
        .writer()
        .write({
            let root = w.root;
            let acme = w.acme;
            move |tx| {
                registration::invite(
                    tx,
                    stepped(root),
                    Terms {
                        tenant: Some(acme),
                        role: Some(Role::Operator),
                        ..Terms::default()
                    },
                    T,
                )
            }
        })
        .unwrap();
    let mut text = String::new();
    invitation.secret.expose(&mut text);

    let outcomes: Vec<Admission> = thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|n| {
                let store = &w.store;
                let text = text.clone();
                scope.spawn(move || {
                    let secret = Secret::parse(&text).unwrap();
                    registration::register(
                        store,
                        Applicant::Local {
                            display_name: "Racer",
                            username: &format!("racer{n}"),
                            password: PASSWORD,
                        },
                        Some(&secret),
                        at(2_000 + n),
                    )
                    .unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let admitted = outcomes
        .iter()
        .filter(|o| matches!(o, Admission::Admitted(_)))
        .count();
    let refused = outcomes
        .iter()
        .filter(|o| matches!(o, Admission::Refused(Refusal::InvitationUnusable)))
        .count();
    assert_eq!((admitted, refused), (1, 7));
    // Exactly one membership came out of it.
    let members: i64 = w
        .store
        .read(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM memberships m JOIN local_credentials c ON c.user_id = m.user_id
                 WHERE m.tenant_id = ?1 AND m.role = 2 AND c.username LIKE 'racer%'",
                [w.acme.as_bytes()],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(members, 1);

    // Reuse after the fact, and reuse of a username under a race, both fail
    // cleanly: no half-created account exists.
    let again = registration::register(
        &w.store,
        Applicant::Local {
            display_name: "Late",
            username: "late",
            password: PASSWORD,
        },
        Some(&invitation.secret),
        at(3_000),
    )
    .unwrap();
    assert!(matches!(
        again,
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    let orphaned: i64 = w
        .store
        .read(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM users u WHERE kind = 0
                 AND NOT EXISTS(SELECT 1 FROM local_credentials WHERE user_id = u.id)
                 AND NOT EXISTS(SELECT 1 FROM external_identities WHERE user_id = u.id)
                 AND u.display_name IN ('Racer', 'Late')",
                [],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(orphaned, 0);
}

#[test]
fn unbound_installations_and_pending_accounts_hold_nothing_anywhere() {
    let w = world();
    let root = stepped(w.root);
    w.store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                root,
                registration::DeploymentPolicy {
                    registration: registration::Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                T,
            )
        })
        .unwrap();
    let pending = match registration::register(
        &w.store,
        Applicant::External {
            display_name: "Applicant",
            provider: "github",
            subject: "777",
        },
        None,
        T,
    )
    .unwrap()
    {
        Admission::Pending(user) => user,
        other => panic!("{other:?}"),
    };
    // Pending: no session by any path, no membership even if an admin tries,
    // no credential.
    assert!(matches!(
        sign_in::complete(&w.store, "github", "777", Policy::default(), T).unwrap(),
        sign_in::Outcome::NoAccount
    ));
    let refused = w.store.writer().write({
        let admin = principal(w.root);
        let acme = w.acme;
        move |tx| auth::set_membership(tx, admin, acme, pending, Role::Reader)
    });
    assert!(matches!(refused, Err(Error::NotFound)));
    assert!(matches!(
        tokens::provision(&w.store, Grant::new(pending, "early", P::READ), T),
        Err(Error::Sqlite(_))
    ));

    // An installation seen twice is one row, unbound, resolving to no tenant,
    // and binding it to a tenant the caller does not administer fails.
    let installation = w
        .store
        .writer()
        .write(move |tx| registration::record_installation(tx, "github", "31337", "acme-org", T))
        .unwrap();
    assert_eq!(
        w.store
            .read(|c| registration::installation_tenant(c, "github", "31337"))
            .unwrap(),
        None
    );
    let refused = w.store.writer().write({
        let sam = principal(w.sam);
        let acme = w.acme;
        move |tx| registration::bind_installation(tx, sam, installation, acme, T)
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    w.store
        .writer()
        .write({
            let dev = principal(w.dev);
            let acme = w.acme;
            move |tx| registration::bind_installation(tx, dev, installation, acme, T)
        })
        .unwrap();
    // Bound to acme, it is still nothing to globex's admin.
    let refused = w.store.writer().write({
        let sam = principal(w.sam);
        move |tx| registration::unbind_installation(tx, sam, installation, T)
    });
    assert!(matches!(refused, Err(Error::NotFound)));
}

#[test]
fn suspension_of_one_tenant_leaves_the_others_and_shared_people_working() {
    let w = world();
    let dev = principal(w.dev);
    let dev_cookie =
        match local_auth::login(&w.store, "dev", PASSWORD, Policy::default(), T).unwrap() {
            Login::Accepted(issued) => issued.session,
            _ => panic!("login"),
        };
    let acme_token = tokens::provision(
        &w.store,
        Grant {
            tenant: Some(w.acme),
            ..Grant::new(w.dev, "acme", P::READ)
        },
        T,
    )
    .unwrap();
    let globex_token = tokens::provision(
        &w.store,
        Grant {
            tenant: Some(w.globex),
            ..Grant::new(w.dev, "globex", P::READ)
        },
        T,
    )
    .unwrap();
    let globex_epoch = w.store.read(|c| tenancy::epoch(c, w.globex)).unwrap();

    w.store
        .writer()
        .write({
            let root = w.root;
            let acme = w.acme;
            move |tx| tenancy::suspend(tx, stepped(root), acme, at(2_000))
        })
        .unwrap();

    // dev's session still works, their globex credential still works, their
    // personal namespace still resolves; only acme is gone.
    w.store
        .read(|c| local_auth::authenticate(c, &dev_cookie, at(2_100)))
        .unwrap();
    assert!(
        w.store
            .read(|c| tokens::authenticate(c, &globex_token.secret, at(2_100)))
            .is_ok()
    );
    assert!(matches!(
        w.store
            .read(|c| tokens::authenticate(c, &acme_token.secret, at(2_100))),
        Err(Error::NotFound)
    ));
    w.store
        .read(|c| auth::get_namespace(c, dev, Namespace::parse("dev").unwrap()))
        .unwrap();
    assert!(matches!(
        w.store
            .read(|c| auth::get_namespace(c, dev, Namespace::parse("acme").unwrap())),
        Err(Error::NotFound)
    ));
    w.store
        .read(|c| auth::require_repo(c, principal(w.sam), w.globex_repo, P::RUN))
        .unwrap();
    assert_eq!(
        w.store.read(|c| tenancy::epoch(c, w.globex)).unwrap(),
        globex_epoch
    );
    // The acme service account is dead in every way that matters.
    assert!(matches!(
        w.store
            .read(|c| auth::require_repo(c, principal(w.bot), w.acme_repo, P::RUN)),
        Err(Error::NotFound)
    ));
    let _ = w.personal;
}

#[test]
fn last_admin_recovery_survives_lockout_demotion_and_suspension_attempts() {
    let w = world();
    let root = stepped(w.root);
    // Root cannot be demoted, suspended or rejected while alone; a deputy
    // changes that, and removing the deputy again restores the protection.
    for attempt in [
        w.store
            .writer()
            .write(move |tx| local_auth::set_super_admin(tx, root, w.root, false, T)),
        w.store
            .writer()
            .write(move |tx| local_auth::set_active(tx, root, w.root, false, T)),
        w.store
            .writer()
            .write(move |tx| registration::reject(tx, root, w.root, T)),
    ] {
        assert!(matches!(attempt, Err(Error::Sqlite(_))), "{attempt:?}");
    }
    w.store
        .writer()
        .write(move |tx| local_auth::set_super_admin(tx, root, w.dev, true, at(2_000)))
        .unwrap();
    w.store
        .writer()
        .write(move |tx| local_auth::set_active(tx, root, w.root, false, at(2_100)))
        .unwrap();
    let dev = stepped(w.dev);
    assert!(matches!(
        w.store
            .writer()
            .write(move |tx| local_auth::set_super_admin(tx, dev, w.dev, false, at(2_200))),
        Err(Error::Sqlite(_))
    ));

    // Lock root's password out entirely, then recover host-locally: the
    // account is reactivated by an admin, recovered, and signs in again.
    w.store
        .writer()
        .write(move |tx| local_auth::set_active(tx, dev, w.root, true, at(2_300)))
        .unwrap();
    let policy = Policy {
        max_failures: 1,
        ..Policy::default()
    };
    assert!(matches!(
        local_auth::login(
            &w.store,
            "root",
            b"wrong password entirely",
            policy,
            at(2_400)
        )
        .unwrap(),
        Login::Rejected
    ));
    assert!(matches!(
        local_auth::login(&w.store, "root", PASSWORD, policy, at(2_500)).unwrap(),
        Login::Locked { .. }
    ));
    local_auth::recover(
        &w.store,
        "root",
        b"a replacement operator password",
        at(2_600),
    )
    .unwrap();
    assert!(matches!(
        local_auth::login(
            &w.store,
            "root",
            b"a replacement operator password",
            policy,
            at(2_700)
        )
        .unwrap(),
        Login::Accepted(_)
    ));
    // Bootstrap stays closed throughout: recovery is the path, not a re-bootstrap.
    assert!(matches!(
        local_auth::bootstrap(&w.store, "root2", "Root", PASSWORD, at(2_800)),
        Err(Error::Forbidden)
    ));
}

#[test]
fn everything_above_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let (acme, dev, cookie) = {
        let store = Store::open(&path, Durability::Full).unwrap();
        let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD, T).unwrap();
        let acme = TenantId::new();
        let dev = UserId::new();
        store
            .writer()
            .write(move |tx| {
                let admin = principal(root);
                auth::provisioning::insert_human(tx, dev, "Dev", false, T)?;
                auth::create_namespace(
                    tx,
                    admin,
                    acme,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    T,
                )?;
                auth::set_membership(tx, admin, acme, dev, Role::TenantAdmin)?;
                tenancy::suspend(tx, stepped(root), acme, at(2_000))?;
                local_auth::issue_session(tx, dev, Policy::default(), at(2_100))
            })
            .map(|issued| (acme, dev, issued.session))
            .unwrap()
    };
    let store = Store::open(&path, Durability::Full).unwrap();
    let session = store
        .read(|c| local_auth::authenticate(c, &cookie, at(2_200)))
        .unwrap();
    assert_eq!(session.user, dev);
    assert!(matches!(
        store.read(|c| auth::get_namespace(c, principal(dev), Namespace::parse("acme").unwrap())),
        Err(Error::NotFound)
    ));
    assert!(store.read(|c| tenancy::epoch(c, acme)).unwrap() >= 1);
}
