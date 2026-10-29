use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    PoolId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn negotiated() -> Negotiated {
    Negotiated {
        protocol: ProtocolVersion(1),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
    }
}

fn fingerprint() -> Digest {
    Secret::generate().digest()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    tenant: TenantId,
    pool: PoolId,
    shared: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, pool, shared) =
        (UserId::new(), TenantId::new(), PoolId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                shared,
                "shared",
                PoolKind::Shared,
                NOW,
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        root,
        tenant,
        pool,
        shared,
    }
}

fn enroll(
    f: &Fixture,
    secret: &Secret,
    worker: WorkerId,
    fp: Digest,
    now: UnixMillis,
) -> Result<workers::Worker, Error> {
    let secret = Secret::parse(&{
        let mut t = String::new();
        secret.expose(&mut t);
        t
    })
    .unwrap();
    f.store.writer().write(move |tx| {
        workers::enroll(
            tx,
            &secret,
            Presentation {
                worker,
                fingerprint: fp,
                name: "builder-1",
                negotiated: negotiated(),
            },
            now,
        )
    })
}

#[test]
fn enrollment_is_platform_issued_pool_bound_single_use_and_expiring() {
    let f = fixture();
    let pool = f.pool;
    let member = Principal::new(UserId::new(), P::ALL, None, None);
    let refused = f.store.writer().write(move |tx| {
        workers::issue_enrollment(tx, Authority::credential(member), pool, 60_000, NOW).map(|_| ())
    });
    assert!(matches!(refused, Err(Error::Forbidden)));
    for lifetime in [0, workers::MAX_ENROLLMENT_MS + 1] {
        let refused = f.store.writer().write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, lifetime, NOW).map(|_| ())
        });
        assert!(matches!(
            refused,
            Err(Error::InvalidInput("enrollment lifetime"))
        ));
    }
    let refused = f.store.writer().write(move |tx| {
        workers::issue_enrollment(tx, Authority::HostLocal, PoolId::new(), 60_000, NOW).map(|_| ())
    });
    assert!(matches!(refused, Err(Error::NotFound)));

    let issued = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    assert_eq!(issued.pool, pool);
    assert_eq!(issued.expires.0, 61_000);

    let (worker, fp) = (WorkerId::new(), fingerprint());
    let enrolled = enroll(&f, &issued.secret, worker, fp, at(2_000)).unwrap();
    assert_eq!((enrolled.id, enrolled.pool), (worker, pool));
    assert!(matches!(
        enroll(
            &f,
            &issued.secret,
            WorkerId::new(),
            fingerprint(),
            at(2_100)
        ),
        Err(Error::NotFound)
    ));
    let fresh = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(2_200))
        })
        .unwrap();
    assert!(matches!(
        enroll(&f, &fresh.secret, worker, fingerprint(), at(2_300)),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        enroll(&f, &fresh.secret, WorkerId::new(), fp, at(2_300)),
        Err(Error::Conflict)
    ));
    enroll(&f, &fresh.secret, WorkerId::new(), fingerprint(), at(2_400)).unwrap();
    let short = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 10, at(3_000)))
        .unwrap();
    assert!(matches!(
        enroll(&f, &short.secret, WorkerId::new(), fingerprint(), at(3_010)),
        Err(Error::NotFound)
    ));
    let revoked = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(3_100))
        })
        .unwrap();
    let id = revoked.id;
    f.store
        .writer()
        .write(move |tx| workers::revoke_enrollment(tx, Authority::HostLocal, id, at(3_200)))
        .unwrap();
    assert!(matches!(
        enroll(
            &f,
            &revoked.secret,
            WorkerId::new(),
            fingerprint(),
            at(3_300)
        ),
        Err(Error::NotFound)
    ));
    let unspend = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE worker_enrollments SET redeemed_ms = NULL, redeemed_worker = NULL",
            [],
        )?;
        Ok(())
    });
    assert!(matches!(unspend, Err(Error::Sqlite(_))));
}

#[test]
fn a_worker_is_known_by_fingerprint_bound_to_its_pool_and_revocable() {
    let f = fixture();
    let pool = f.pool;
    let issued = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    let (worker, fp) = (WorkerId::new(), fingerprint());
    enroll(&f, &issued.secret, worker, fp, at(2_000)).unwrap();

    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(known.id, worker);
    assert!(known.last_seen.is_none());
    assert!(workers::seen_due(&known, at(2_000)));
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fingerprint())),
        Err(Error::NotFound)
    ));

    f.store
        .writer()
        .write(move |tx| workers::seen(tx, worker, at(5_000)))
        .unwrap();
    f.store
        .writer()
        .write(move |tx| workers::seen(tx, worker, at(4_000)))
        .unwrap();
    let known = f.store.read(|c| workers::authenticate(c, &fp)).unwrap();
    assert_eq!(known.last_seen, Some(at(5_000)));
    assert!(!workers::seen_due(
        &known,
        at(5_000 + workers::SEEN_RECORD_INTERVAL_MS - 1)
    ));
    assert!(workers::seen_due(
        &known,
        at(5_000 + workers::SEEN_RECORD_INTERVAL_MS)
    ));

    let shared = f.shared;
    let raw = f.store.writer().write(move |tx| {
        tx.execute("UPDATE workers SET pool_id = ?1", [shared.as_bytes()])?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));

    let live = f
        .store
        .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
        .unwrap();
    assert_eq!(live.len(), 1);
    let outsider = Principal::new(UserId::new(), P::ALL, None, None);
    assert!(matches!(
        f.store
            .read(|c| workers::in_pool(c, Authority::credential(outsider), pool)),
        Err(Error::NotFound)
    ));

    let refused = f
        .store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::credential(outsider), worker, at(6_000)));
    assert!(matches!(refused, Err(Error::Forbidden)));
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, at(6_000)))
        .unwrap();
    assert!(matches!(
        f.store.read(|c| workers::authenticate(c, &fp)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store.writer().write(move |tx| workers::revoke(
            tx,
            Authority::HostLocal,
            worker,
            at(6_100)
        )),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| workers::in_pool(c, Authority::HostLocal, pool))
            .unwrap()
            .is_empty()
    );
    let root = f.root;
    let tenant = f.tenant;
    let issued = f
        .store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, at(7_000))
        })
        .unwrap();
    let fp2 = fingerprint();
    enroll(&f, &issued.secret, WorkerId::new(), fp2, at(7_100)).unwrap();
    f.store
        .writer()
        .write(move |tx| {
            tenancy::suspend(
                tx,
                Authority::Credential {
                    principal: Principal::new(root, P::ALL, None, None),
                    stepped_up: true,
                },
                tenant,
                at(7_200),
            )
        })
        .unwrap();
    // Suspension drops placement, not enrollment: dedicated pool machines still authenticate.
    assert!(f.store.read(|c| workers::authenticate(c, &fp2)).is_ok());
}

fn refuse(f: &Fixture, peer: workers::Peer, now: UnixMillis) {
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            workers::redeem_from(
                tx,
                &Secret::generate(),
                Presentation {
                    worker: WorkerId::new(),
                    fingerprint: fingerprint(),
                    name: "guesser",
                    negotiated: negotiated(),
                },
                now,
                peer,
            )
        })
        .unwrap();
    assert!(refused.is_none());
}

fn refusal_rows(f: &Fixture) -> i64 {
    f.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM auth_audit WHERE event = 45",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap()
}

fn peer(n: u8) -> workers::Peer {
    [n; 16]
}

#[test]
fn refused_enrollments_write_a_bounded_number_of_audit_rows_and_are_counted() {
    let f = fixture();
    let hour = workers::REFUSAL_WINDOW_MS;
    let start = 40 * hour;

    // One peer: its first few refusals leave rows, every later one is only counted.
    for n in 0..200 {
        refuse(&f, peer(1), at(start + n));
    }
    assert_eq!(refusal_rows(&f), workers::REFUSAL_ROWS_PER_PEER);
    let counts = f.store.read(workers::refusal_counts).unwrap();
    assert_eq!(
        counts,
        (
            workers::REFUSAL_ROWS_PER_PEER,
            200 - workers::REFUSAL_ROWS_PER_PEER
        )
    );

    // Many peers: the window as a whole stays under its allowance, and nothing is lost from the count.
    for n in 0..500u16 {
        refuse(
            &f,
            peer(2 + (n % 120) as u8),
            at(start + 1_000 + i64::from(n)),
        );
    }
    assert!(refusal_rows(&f) <= workers::REFUSAL_ROWS_PER_WINDOW);
    let (recorded, suppressed) = f.store.read(workers::refusal_counts).unwrap();
    assert_eq!(recorded, refusal_rows(&f));
    assert_eq!(recorded + suppressed, 700);
    let tracked: i64 = f
        .store
        .read(|c| {
            Ok(
                c.query_row("SELECT COUNT(*) FROM worker_enrollment_refusals", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .unwrap();
    assert!(
        tracked <= workers::REFUSAL_PEERS_PER_WINDOW + 1,
        "{tracked} peer rows"
    );

    // The next hour starts with one summary row for what the last one only counted, then budgets anew.
    let before = refusal_rows(&f);
    refuse(&f, peer(1), at(start + hour + 5));
    assert_eq!(
        refusal_rows(&f),
        before + 2,
        "a summary row and the new refusal"
    );
    refuse(&f, peer(1), at(start + hour + 6));
    assert_eq!(refusal_rows(&f), before + 3, "the summary is written once");
    let details: Vec<String> = f
        .store
        .read(|c| {
            let mut statement =
                c.prepare("SELECT detail FROM auth_audit WHERE event = 45 AND detail IS NOT NULL")?;
            Ok(statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(details.len(), 1);
    assert!(details[0].starts_with("650 more refused"), "{details:?}");
}

#[test]
fn refusal_windows_are_pruned_after_a_week() {
    let f = fixture();
    let hour = workers::REFUSAL_WINDOW_MS;
    for n in 0..20 {
        refuse(&f, peer(1), at(10 * hour + n));
    }
    refuse(&f, peer(1), at(10 * hour + 8 * 24 * hour));
    let windows: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(DISTINCT window_ms) FROM worker_enrollment_refusals",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(windows, 1);
}

#[test]
fn a_secret_that_would_redeem_is_visible_without_recording_anything() {
    let f = fixture();
    let pool = f.pool;
    let issued = f
        .store
        .writer()
        .write(move |tx| workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW))
        .unwrap();
    assert!(
        f.store
            .read(|c| workers::redeemable(c, &issued.secret, at(2_000)))
            .unwrap()
    );
    assert!(
        !f.store
            .read(|c| workers::redeemable(c, &Secret::generate(), at(2_000)))
            .unwrap()
    );
    assert!(
        !f.store
            .read(|c| workers::redeemable(c, &issued.secret, at(NOW.0 + 61_000)))
            .unwrap()
    );
    assert_eq!(refusal_rows(&f), 0);
    enroll(
        &f,
        &issued.secret,
        WorkerId::new(),
        fingerprint(),
        at(3_000),
    )
    .unwrap();
    assert!(
        !f.store
            .read(|c| workers::redeemable(c, &issued.secret, at(4_000)))
            .unwrap(),
        "a spent secret no longer redeems"
    );
}

#[test]
fn known_sources_are_stored_refreshed_expired_and_capped() {
    use sentinel_store::known_sources::{self, MAX_SOURCES};
    let f = fixture();
    let day = 24 * 60 * 60 * 1000;
    let record = |source: [u8; 16], now: i64| {
        f.store
            .writer()
            .write(move |tx| known_sources::record(tx, source, now, day))
            .unwrap()
    };
    record([1; 16], 1_000);
    record([2; 16], 2_000);
    let live = f
        .store
        .read(|c| known_sources::load(c, 3_000, day))
        .unwrap();
    assert_eq!(live, vec![([2; 16], 2_000), ([1; 16], 1_000)]);

    // Refreshing keeps the newer time and never moves it back.
    record([1; 16], 2_500);
    record([1; 16], 500);
    let live = f
        .store
        .read(|c| known_sources::load(c, 3_000, day))
        .unwrap();
    assert_eq!(live[0], ([1; 16], 2_500));

    // A source past the day is not returned and is pruned by the next write.
    let live = f
        .store
        .read(|c| known_sources::load(c, 1_000 + day + 1_600, day))
        .unwrap();
    assert!(live.iter().all(|(s, _)| *s != [2; 16]));
    record([3; 16], 2_400 + day);
    let rows: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM link_known_sources", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(rows, 2, "the source refreshed in time, and the new one");

    // The table never holds more than its cap, keeping the newest.
    f.store
        .writer()
        .write(move |tx| {
            for n in 0..(MAX_SOURCES + 50) {
                let mut source = [0u8; 16];
                source[..8].copy_from_slice(&(n as u64 + 100).to_be_bytes());
                tx.execute(
                    "INSERT INTO link_known_sources(source, seen_ms) VALUES (?1, ?2)",
                    rusqlite::params![source, 10_000 + n],
                )?;
            }
            known_sources::record(tx, [9; 16], 10_000 + MAX_SOURCES + 50, day)
        })
        .unwrap();
    let rows: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM link_known_sources", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(rows, MAX_SOURCES);
}
