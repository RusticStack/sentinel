//! A07 behavior: tenant suspension propagating to credentials, invitations,
//! live jobs and long-lived subscriptions; audited membership and grant
//! changes; pool grants that never cross a tenant boundary.

use sentinel_core::{
    Actor, Event as JobEvent, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId,
    UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    jobs,
    local_auth::{self, Event},
    registration::{self, Terms},
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
};

const NOW: UnixMillis = UnixMillis(1_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    dev: UserId,
    bot: UserId,
    acme: TenantId,
    other: TenantId,
    repo: RepoId,
}

/// A stepped-up platform admin, as a session that just proved presence.
fn privileged(user: UserId) -> Authority {
    Authority::Credential {
        principal: Principal::new(user, P::ALL, None, None),
        stepped_up: true,
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, dev, bot) = (UserId::new(), UserId::new(), UserId::new());
    let (acme, other, repo) = (TenantId::new(), TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            provisioning::insert_human(tx, dev, "Dev", false, NOW)?;
            let admin = Principal::new(root, P::ALL, None, None);
            for (tenant, slug) in [(acme, "acme"), (other, "other")] {
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            auth::set_membership(tx, admin, acme, dev, Role::TenantAdmin)?;
            auth::set_membership(tx, admin, other, dev, Role::Reader)?;
            auth::create_repo(tx, admin, acme, repo, "app", NOW)?;
            auth::create_service_account(tx, admin, acme, bot, "bot", Role::Operator, NOW)?;
            Ok(())
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        root,
        dev,
        bot,
        acme,
        other,
        repo,
    }
}

/// A run with three jobs: one queued, one leased to a worker, one blocked.
fn seed_jobs(f: &Fixture) -> (JobId, JobId, JobId) {
    let (queued, leased, blocked) = (JobId::new(), JobId::new(), JobId::new());
    let (tenant, repo, run) = (f.acme, f.repo, RunId::new());
    f.store
        .writer()
        .write(move |tx| {
            jobs::insert_run(tx, tenant, repo, run, "abc", NOW)?;
            for (job, seq) in [(queued, 1), (leased, 2), (blocked, 3)] {
                jobs::insert_job(tx, tenant, run, job, &format!("job{seq}"), 0, seq)?;
            }
            jobs::transition(
                tx,
                tenant,
                queued,
                Actor::Controller,
                JobEvent::DependenciesSatisfied,
                NOW,
            )?;
            jobs::transition(
                tx,
                tenant,
                leased,
                Actor::Controller,
                JobEvent::DependenciesSatisfied,
                NOW,
            )?;
            jobs::lease(tx, tenant, leased, WorkerId::new(), at(9_999), NOW)?;
            Ok(())
        })
        .unwrap();
    (queued, leased, blocked)
}

#[test]
fn suspension_stops_intake_revokes_scoped_credentials_and_cancels_live_work() {
    let f = fixture();
    let (queued, leased, blocked) = seed_jobs(&f);
    let dev = Principal::new(f.dev, P::ALL, None, None);
    let scoped = tokens::provision(
        &f.store,
        Grant {
            tenant: Some(f.acme),
            ..Grant::new(f.dev, "acme cli", P::READ)
        },
        NOW,
    )
    .unwrap();
    let unscoped =
        tokens::provision(&f.store, Grant::new(f.dev, "everywhere", P::READ), NOW).unwrap();
    let bot_token = tokens::provision(
        &f.store,
        Grant {
            tenant: Some(f.acme),
            ..Grant::new(f.bot, "bot", P::RUN)
        },
        NOW,
    )
    .unwrap();
    let invitation = f
        .store
        .writer()
        .write({
            let root = f.root;
            let acme = f.acme;
            move |tx| {
                registration::invite(
                    tx,
                    Authority::credential(Principal::new(root, P::ALL, None, None)),
                    Terms {
                        tenant: Some(acme),
                        role: Some(Role::Reader),
                        ..Terms::default()
                    },
                    NOW,
                )
            }
        })
        .unwrap();
    let epoch_before = f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap();

    // A plain session cannot suspend; a stepped-up platform admin can.
    let refused = f.store.writer().write({
        let root = f.root;
        let acme = f.acme;
        move |tx| {
            tenancy::suspend(
                tx,
                Authority::credential(Principal::new(root, P::ALL, None, None)),
                acme,
                at(2_000),
            )
        }
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));
    let done = f
        .store
        .writer()
        .write({
            let root = f.root;
            let acme = f.acme;
            move |tx| tenancy::suspend(tx, privileged(root), acme, at(2_000))
        })
        .unwrap();
    assert_eq!(
        done,
        tenancy::Suspension {
            tokens_revoked: 2,
            invitations_revoked: 1,
            jobs_canceled: 2,
            jobs_cancel_requested: 1,
        }
    );

    // Intake: the repository is unreachable through any live predicate.
    assert!(matches!(
        f.store
            .read(|c| auth::require_repo(c, dev, f.repo, P::READ)),
        Err(Error::NotFound)
    ));
    // Credentials: the tenant-scoped ones died, the deployment-wide one lives.
    assert!(matches!(
        f.store
            .read(|c| tokens::authenticate(c, &scoped.secret, at(2_100))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .read(|c| tokens::authenticate(c, &bot_token.secret, at(2_100))),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| tokens::authenticate(c, &unscoped.secret, at(2_100)))
            .is_ok()
    );
    // The invitation into the tenant is spent.
    assert!(matches!(
        registration::register(
            &f.store,
            registration::Applicant::Local {
                display_name: "Late",
                username: "late",
                password: b"an acceptable member password",
            },
            Some(&invitation.secret),
            at(2_100),
        )
        .unwrap(),
        registration::Admission::Refused(registration::Refusal::InvitationUnusable)
    ));
    // Jobs: unowned ones are canceled through the state machine; the leased
    // one carries the durable cancel flag for its worker.
    for (job, expected) in [
        (queued, JobState::Terminal(Outcome::Canceled)),
        (blocked, JobState::Terminal(Outcome::Canceled)),
        (leased, JobState::Leased),
    ] {
        let row = f.store.read(|c| jobs::get_job(c, f.acme, job)).unwrap();
        assert_eq!(row.state, expected);
        assert!(row.cancel_requested);
    }
    // Subscriptions: the epoch moved, so a held stream re-authorizes and fails.
    assert!(f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap() > epoch_before);
    // Retained evidence is untouched.
    let runs: i64 = f
        .store
        .read(|c| {
            c.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(runs, 1);
    // The other tenant is unaffected: the reader still resolves it.
    assert!(
        f.store
            .read(|c| auth::get_namespace(c, dev, Namespace::parse("other").unwrap()))
            .is_ok()
    );
    let record = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .find(|r| r.event == Event::TenantSuspended)
        .unwrap();
    assert_eq!(
        record.detail.as_deref(),
        Some("tokens=2 invitations=1 canceled=2 requested=1")
    );

    // Suspending twice is not a silent success; reactivation restores intake
    // and nothing revoked comes back.
    let again = f.store.writer().write({
        let root = f.root;
        let acme = f.acme;
        move |tx| tenancy::suspend(tx, privileged(root), acme, at(2_200))
    });
    assert!(matches!(again, Err(Error::NotFound)));
    f.store
        .writer()
        .write({
            let root = f.root;
            let acme = f.acme;
            move |tx| tenancy::reactivate(tx, privileged(root), acme, at(2_300))
        })
        .unwrap();
    assert!(
        f.store
            .read(|c| auth::require_repo(c, dev, f.repo, P::READ))
            .is_ok()
    );
    assert!(matches!(
        f.store
            .read(|c| tokens::authenticate(c, &scoped.secret, at(2_400))),
        Err(Error::NotFound)
    ));
    assert_eq!(
        f.store
            .read(|c| jobs::get_job(c, f.acme, queued))
            .unwrap()
            .state,
        JobState::Terminal(Outcome::Canceled)
    );
    let leased_row = f.store.read(|c| jobs::get_job(c, f.acme, leased)).unwrap();
    assert_eq!(leased_row.fence, Fence(1));
}

#[test]
fn membership_and_grant_changes_are_audited_and_move_the_epoch() {
    let f = fixture();
    let admin = Principal::new(f.root, P::ALL, None, None);
    let epoch0 = f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap();
    let scoped = tokens::provision(
        &f.store,
        Grant {
            tenant: Some(f.acme),
            ..Grant::new(f.dev, "acme cli", P::READ)
        },
        NOW,
    )
    .unwrap();
    let elsewhere = tokens::provision(
        &f.store,
        Grant {
            tenant: Some(f.other),
            ..Grant::new(f.dev, "other cli", P::READ)
        },
        NOW,
    )
    .unwrap();

    // Downgrade: takes effect on the next query, and the epoch moves.
    f.store
        .writer()
        .write({
            let (acme, dev) = (f.acme, f.dev);
            move |tx| auth::set_membership(tx, admin, acme, dev, Role::Reader)
        })
        .unwrap();
    let epoch1 = f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap();
    assert!(epoch1 > epoch0);
    let dev = Principal::new(f.dev, P::ALL, None, None);
    assert!(
        matches!(
            f.store
                .read(|c| auth::require_repo(c, dev, f.repo, P::READ)),
            Err(Error::NotFound)
        ),
        "a reader without a grant sees nothing"
    );
    f.store
        .writer()
        .write({
            let (repo, dev) = (f.repo, f.dev);
            move |tx| auth::set_repo_grant(tx, admin, repo, dev, P::READ)
        })
        .unwrap();
    assert!(f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap() > epoch1);
    assert!(
        f.store
            .read(|c| auth::require_repo(c, dev, f.repo, P::READ))
            .is_ok()
    );

    // Removal: grants cascade, the tenant-scoped credential dies, the other
    // tenant's credential survives.
    f.store
        .writer()
        .write({
            let (acme, dev) = (f.acme, f.dev);
            move |tx| auth::remove_membership(tx, admin, acme, dev, at(3_000))
        })
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| auth::require_repo(c, dev, f.repo, P::READ)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .read(|c| tokens::authenticate(c, &scoped.secret, at(3_100))),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| tokens::authenticate(c, &elsewhere.secret, at(3_100)))
            .is_ok()
    );
    let removed_again = f.store.writer().write({
        let (acme, dev) = (f.acme, f.dev);
        move |tx| auth::remove_membership(tx, admin, acme, dev, at(3_200))
    });
    assert!(matches!(removed_again, Err(Error::NotFound)));

    let events: Vec<Event> = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    for expected in [
        Event::MembershipSet,
        Event::GrantChanged,
        Event::MembershipRemoved,
    ] {
        assert!(events.contains(&expected), "{expected:?} missing");
    }
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE tenants SET authz_epoch = 0", [])?;
        Ok(())
    });
    assert!(
        matches!(raw, Err(Error::Sqlite(_))),
        "epoch cannot be rewound"
    );
}

#[test]
fn pool_access_is_ownership_or_an_explicit_grant_and_never_crosses_tenants() {
    let f = fixture();
    let root = privileged(f.root);
    let (dedicated, shared) = (PoolId::new(), PoolId::new());
    f.store
        .writer()
        .write({
            let acme = f.acme;
            move |tx| {
                tenancy::create_pool(
                    tx,
                    root,
                    dedicated,
                    "acme-builders",
                    PoolKind::Dedicated(acme),
                    NOW,
                )?;
                tenancy::create_pool(tx, root, shared, "shared-linux", PoolKind::Shared, NOW)
            }
        })
        .unwrap();
    for bad in ["", "Acme", "has space", &"x".repeat(65)] {
        let refused = f.store.writer().write({
            let bad = bad.to_owned();
            move |tx| tenancy::create_pool(tx, root, PoolId::new(), &bad, PoolKind::Shared, NOW)
        });
        assert!(
            matches!(refused, Err(Error::InvalidInput("pool name"))),
            "{bad:?}"
        );
    }

    // Ownership admits; nothing else does, and a dedicated pool takes no grant.
    f.store
        .read(|c| tenancy::require_pool_access(c, f.acme, dedicated))
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| tenancy::require_pool_access(c, f.other, dedicated)),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        f.store
            .read(|c| tenancy::require_pool_access(c, f.acme, shared)),
        Err(Error::Forbidden)
    ));
    let refused = f.store.writer().write({
        let other = f.other;
        move |tx| tenancy::grant_pool(tx, root, dedicated, other, NOW)
    });
    assert!(matches!(refused, Err(Error::Sqlite(_))));
    let raw = f.store.writer().write({
        let other = f.other;
        move |tx| {
            tx.execute(
                "INSERT INTO pool_grants(pool_id, tenant_id, granted_ms) VALUES (?1, ?2, 1)",
                rusqlite::params![dedicated.as_bytes(), other.as_bytes()],
            )?;
            Ok(())
        }
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));

    // A grant admits exactly that tenant, moves its epoch, and is withdrawable.
    let epoch0 = f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap();
    f.store
        .writer()
        .write({
            let acme = f.acme;
            move |tx| tenancy::grant_pool(tx, root, shared, acme, NOW)
        })
        .unwrap();
    assert!(f.store.read(|c| tenancy::epoch(c, f.acme)).unwrap() > epoch0);
    f.store
        .read(|c| tenancy::require_pool_access(c, f.acme, shared))
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| tenancy::require_pool_access(c, f.other, shared)),
        Err(Error::Forbidden)
    ));
    // Only a tenant's own members (or the platform) see its pools.
    let dev = Authority::credential(Principal::new(f.dev, P::ALL, None, None));
    let pools = f
        .store
        .read(|c| tenancy::pools_for_tenant(c, dev, f.acme))
        .unwrap();
    assert_eq!(pools.len(), 2);
    let outsider = UserId::new();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, outsider, "Outsider", false, NOW))
        .unwrap();
    let theirs = Authority::credential(Principal::new(outsider, P::ALL, None, None));
    assert!(matches!(
        f.store
            .read(|c| tenancy::pools_for_tenant(c, theirs, f.acme)),
        Err(Error::NotFound)
    ));
    let refused = f.store.writer().write({
        let acme = f.acme;
        move |tx| {
            tenancy::grant_pool(
                tx,
                Authority::credential(Principal::new(outsider, P::ALL, None, None)),
                shared,
                acme,
                NOW,
            )
        }
    });
    assert!(matches!(refused, Err(Error::Forbidden)));

    f.store
        .writer()
        .write({
            let acme = f.acme;
            move |tx| tenancy::revoke_pool_grant(tx, root, shared, acme, NOW)
        })
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| tenancy::require_pool_access(c, f.acme, shared)),
        Err(Error::Forbidden)
    ));
    let again = f.store.writer().write({
        let acme = f.acme;
        move |tx| tenancy::revoke_pool_grant(tx, root, shared, acme, NOW)
    });
    assert!(matches!(again, Err(Error::NotFound)));

    // A suspended tenant loses its own dedicated pool too.
    f.store
        .writer()
        .write({
            let acme = f.acme;
            move |tx| tenancy::suspend(tx, root, acme, at(5_000))
        })
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| tenancy::require_pool_access(c, f.acme, dedicated)),
        Err(Error::Forbidden)
    ));
    let events: Vec<Event> = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    for expected in [
        Event::PoolCreated,
        Event::PoolGranted,
        Event::PoolGrantRevoked,
    ] {
        assert!(events.contains(&expected), "{expected:?} missing");
    }
}
