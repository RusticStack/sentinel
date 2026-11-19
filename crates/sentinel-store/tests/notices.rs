use std::sync::Arc;

use sentinel_auth::sealed::Key;
use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind},
    email, local_auth,
    local_auth::Event,
    notices::{self, Delivery},
    objects::{Expect, Objects},
    registration::{self, Admission, Applicant},
    retention::{self, Deployment},
    space,
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const QUOTA: u64 = 1_000;
const PASSWORD: &[u8] = b"an operator password";

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    tenant: TenantId,
    /// The tenant's administrator, with a verified address and so a notice's recipient.
    admin: UserId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let deployment = Deployment {
        tenant_quota_bytes: QUOTA,
        ..Deployment::default()
    };
    objects.set_deployment(deployment);
    objects.set_admission(Arc::new(
        space::Admission::with_probe(
            space::Watermarks {
                reserve: 1 << 30,
                low: 2 << 30,
                high: 4 << 30,
                floor: 1 << 27,
            },
            || Ok(1 << 50),
        )
        .unwrap(),
    ));
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD, NOW).unwrap();
    let platform = Principal::new(root, P::ALL, None, None);
    let tenant = TenantId::new();
    let invitation = store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                platform,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            Ok(registration::invite(
                tx,
                Authority::credential(platform),
                registration::Terms {
                    tenant: Some(tenant),
                    role: Some(Role::TenantAdmin),
                    ..registration::Terms::default()
                },
                NOW,
            )?
            .secret)
        })
        .unwrap();
    let admitted = registration::register_with(
        &store,
        Applicant::Email {
            display_name: "Ada",
            email: "ada@example.com",
            password: PASSWORD,
        },
        Some(&invitation),
        None,
        NOW,
    )
    .unwrap();
    let Admission::Admitted(admin) = admitted else {
        panic!("the invitation admits: {admitted:?}");
    };
    let link = store
        .writer()
        .write(move |tx| email::issue_link(tx, Authority::HostLocal, admin, None, NOW))
        .unwrap()
        .secret;
    assert!(matches!(
        email::confirm(&store, &link, NOW).unwrap(),
        email::Confirmation::Verified { .. }
    ));
    Fixture {
        dir,
        store,
        objects,
        tenant,
        admin,
    }
}

impl Fixture {
    fn key(&self) -> Arc<Key> {
        let path = self.dir.path().join("master.key");
        if !path.exists() {
            Key::create(&path).unwrap();
        }
        Arc::new(Key::load(&path).unwrap())
    }

    fn deployment(&self) -> Deployment {
        self.objects.deployment()
    }

    /// Commits one object of `bytes` distinct bytes, so each call adds its own usage.
    fn grow(&self, bytes: u64) -> u64 {
        let content: Vec<u8> = (0..bytes)
            .map(|i| (i.wrapping_mul(31).wrapping_add(bytes) % 251) as u8)
            .collect();
        let staged = self
            .objects
            .stage(self.tenant, content.as_slice(), u64::MAX, Expect::default())
            .unwrap();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        self.used()
    }

    /// Drops every object, the same accounting a reclaim does, and answers the usage left.
    fn empty(&self) -> u64 {
        let tenant = self.tenant;
        self.store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "DELETE FROM objects WHERE tenant_id = ?1",
                    [tenant.as_bytes()],
                )?;
                Ok(())
            })
            .unwrap();
        self.used()
    }

    fn used(&self) -> u64 {
        let tenant = self.tenant;
        self.store
            .read(move |c| Ok(retention::tenant_usage(c, tenant)?.total()))
            .unwrap()
    }

    fn crossings(&self) -> Vec<notices::Crossing> {
        let d = self.deployment();
        self.store
            .read(move |c| notices::crossings(c, &d, 64))
            .unwrap()
    }

    fn recovered(&self) -> Vec<TenantId> {
        let d = self.deployment();
        self.store
            .read(move |c| notices::recovered(c, &d, 64))
            .unwrap()
    }

    fn record(&self, crossing: &notices::Crossing, key: Option<Arc<Key>>) -> Option<Delivery> {
        let (crossing, d) = (crossing.clone(), self.deployment());
        self.store
            .writer()
            .write(move |tx| notices::record(tx, key.as_deref(), &d, &crossing, NOW))
            .unwrap()
    }

    /// One pass of what the controller does: tell every crossing, then give back what fell below the line.
    fn pass(&self, key: Option<Arc<Key>>) -> usize {
        let mut told = 0;
        for crossing in self.crossings() {
            told += usize::from(self.record(&crossing, key.clone()).is_some());
        }
        let recovered = self.recovered();
        if !recovered.is_empty() {
            self.store
                .writer()
                .write(move |tx| notices::rearm(tx, &recovered))
                .unwrap();
        }
        told
    }

    fn notice(&self) -> Option<notices::Notice> {
        let tenant = self.tenant;
        self.store
            .read(move |c| notices::notice(c, tenant))
            .unwrap()
    }

    fn outbox(&self) -> Vec<(u8, String)> {
        self.store
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT kind, recipient FROM mail_outbox ORDER BY created_ms")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })
            .unwrap()
    }

    fn events(&self) -> Vec<Event> {
        self.store
            .read(|c| local_auth::recent_audit(c, 100))
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect()
    }
}

#[test]
fn one_notice_per_crossing_and_none_again_until_use_falls_below_the_release_line() {
    let f = fixture();
    // 79 % of the quota is not a crossing.
    assert_eq!(f.grow(790), 790);
    assert!(f.crossings().is_empty());
    assert_eq!(f.pass(None), 0);
    assert!(f.notice().is_none());

    // 80 % is.
    assert_eq!(f.grow(10), 800);
    let crossings = f.crossings();
    assert_eq!(crossings.len(), 1);
    assert_eq!(crossings[0].slug, "acme");
    assert_eq!(f.pass(None), 1);
    let notice = f.notice().expect("the crossing is told");
    assert_eq!(
        (
            notice.threshold_percent,
            notice.used_bytes,
            notice.limit_bytes
        ),
        (80, 800, QUOTA)
    );
    assert_eq!(notice.delivery, Delivery::InApp);
    assert_eq!(notice.notified_ms, NOW.0);

    // Still crossing, and the latch holds: no second notice, however many passes.
    assert_eq!(f.grow(50), 850);
    assert!(f.crossings().is_empty());
    assert_eq!(f.pass(None), 0);
    assert_eq!(f.pass(None), 0);

    // Below 75 % the arm comes back, and only then: 760 is still armed.
    assert_eq!(f.empty(), 0);
    assert_eq!(f.grow(760), 760);
    assert!(f.recovered().is_empty());
    assert_eq!(f.pass(None), 0);
    assert!(f.notice().is_some());

    // 740 is under the line: the notice goes, and nothing is told while under the threshold.
    assert_eq!(f.empty(), 0);
    assert_eq!(f.grow(740), 740);
    assert_eq!(f.recovered(), vec![f.tenant]);
    assert_eq!(f.pass(None), 0);
    assert!(f.notice().is_none());

    // Oscillating across the band tells once per crossing: up to 810, down to 740, three times.
    for expected in 1..=3 {
        assert_eq!(f.empty(), 0);
        assert_eq!(f.grow(810), 810);
        assert_eq!(f.crossings().len(), 1, "crossing {expected}");
        assert_eq!(f.pass(None), 1, "crossing {expected}");
        assert_eq!(f.pass(None), 0, "crossing {expected} told once");
        assert!(f.notice().is_some());
        // A dip inside the band tells nothing and keeps the notice standing.
        assert_eq!(f.empty(), 0);
        assert_eq!(f.grow(760), 760);
        assert!(f.recovered().is_empty());
        assert_eq!(f.pass(None), 0);
        assert!(f.notice().is_some());
        assert_eq!(f.empty(), 0);
        assert_eq!(f.grow(740), 740);
        assert_eq!(f.pass(None), 0);
        assert!(f.notice().is_none());
    }
    let events = f.events();
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::StorageNotice)
            .count(),
        4,
        "one audit row per crossing, four crossings in all"
    );
}

#[test]
fn a_restart_tells_nobody_again_about_a_crossing_already_told() {
    let f = fixture();
    assert_eq!(f.grow(820), 820);
    assert_eq!(f.pass(None), 1);
    let crossing = f.crossings();
    assert!(crossing.is_empty());

    // The process goes away and comes back on the same database.
    let path = f.dir.path().join("metadata.sqlite");
    let objects = Arc::new(Objects::open(f.dir.path()).unwrap());
    objects.set_deployment(f.deployment());
    drop(f.store);
    let store = Arc::new(Store::open(&path, Durability::Normal).unwrap());
    let d = objects.deployment();
    let tenant = f.tenant;
    assert!(
        store
            .read(move |c| notices::crossings(c, &d, 64))
            .unwrap()
            .is_empty(),
        "the arm state survived the restart"
    );
    assert!(matches!(
        store
            .read(move |c| notices::notice(c, tenant))
            .unwrap()
            .map(|n| n.delivery),
        Some(Delivery::InApp)
    ));
    // A stale crossing the new process read before the restart records nothing.
    let stale = notices::Crossing {
        tenant: f.tenant,
        slug: "acme".to_owned(),
    };
    let wrote = store
        .writer()
        .write(move |tx| notices::record(tx, None, &d, &stale, NOW))
        .unwrap();
    assert!(wrote.is_none());
    let rows: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM storage_notices", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(rows, 1, "still one notice, not two");
}

#[test]
fn mail_reaches_the_tenants_administrators_when_delivery_is_configured() {
    let f = fixture();
    let key = f.key();
    assert_eq!(f.grow(820), 820);
    // Delivery off: the storage page is the channel, and the outbox is untouched.
    assert_eq!(f.pass(Some(Arc::clone(&key))), 1);
    assert_eq!(f.notice().map(|n| n.delivery), Some(Delivery::InApp));
    assert!(f.outbox().is_empty());

    assert_eq!(f.empty(), 0);
    assert_eq!(f.grow(740), 740);
    assert_eq!(f.pass(Some(Arc::clone(&key))), 0);
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), NOW).unwrap();
    assert_eq!(f.grow(70), 810);
    assert_eq!(f.pass(Some(Arc::clone(&key))), 1);
    assert_eq!(f.notice().map(|n| n.delivery), Some(Delivery::Mail));
    assert_eq!(f.outbox(), vec![(3, "ada@example.com".to_owned())]);
}

#[test]
fn a_mail_message_carries_the_numbers_of_the_crossing() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), NOW).unwrap();
    assert_eq!(f.grow(820), 820);
    let crossing = f.crossings().remove(0);
    assert!(f.record(&crossing, Some(Arc::clone(&key))).is_some());
    assert_eq!(f.outbox(), vec![(3, "ada@example.com".to_owned())]);
    let mail = f
        .store
        .read(|c| email::due(c, NOW, 8))
        .unwrap()
        .first()
        .and_then(|p| p.open(&key))
        .expect("the outbox holds a message this key opens");
    assert!(mail.subject().contains("acme"), "{}", mail.subject());
    assert!(mail.subject().contains("82%"), "{}", mail.subject());
    assert!(mail.body().contains("820 bytes"), "{}", mail.body());
    assert!(mail.body().contains("1000 bytes"), "{}", mail.body());
    assert!(mail.body().contains("75%"), "{}", mail.body());
    assert!(mail.body().contains("80%"), "{}", mail.body());
}

#[test]
fn an_administrator_without_a_verified_address_leaves_the_notice_on_the_page() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), NOW).unwrap();
    let admin = f.admin;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE users SET email_verified_ms = NULL WHERE id = ?1",
                [admin.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(f.grow(820), 820);
    assert_eq!(f.pass(Some(key)), 1);
    assert_eq!(f.notice().map(|n| n.delivery), Some(Delivery::InApp));
    assert!(f.outbox().is_empty());
}
