use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    intake,
    poll::{self, Spec, Tip},
    registration::Authority,
    sources::{self, Update},
};

const NOW: UnixMillis = UnixMillis(1_000);
const MAIN: &str = "refs/heads/main";

struct Fixture {
    conn: Connection,
    key: Key,
    _dir: tempfile::TempDir,
    alice: Principal,
    bob: Principal,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let bob = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    provisioning::insert_human(&tx, bob.user, "bob", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        alice,
        tenant,
        Namespace::parse("alice").unwrap(),
        NamespaceKind::Personal(alice.user),
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, alice, tenant, repo, "project", NOW).unwrap();
    tx.commit().unwrap();
    Fixture {
        conn,
        key,
        _dir: dir,
        alice,
        bob,
        tenant,
        repo,
    }
}

fn bind(f: &mut Fixture) {
    let binding = Binding {
        remote: "https://git.example:8443/team/repo.git".into(),
        allowed_refs: vec!["refs/heads/*".into(), "refs/tags/*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let tx = f.conn.transaction().unwrap();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        Update {
            repo: f.repo,
            expected: 0,
            binding: &binding,
            credential: &Credential::Public,
            forge: None,
        },
        &["https://git.example:8443".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
}

fn spec(refs: &[&str]) -> Spec {
    Spec {
        interval_ms: 60_000,
        refs: refs.iter().map(|r| r.to_string()).collect(),
    }
}

fn configure(f: &mut Fixture, authority: Authority, refs: &[&str]) -> sentinel_store::Result<()> {
    let tx = f.conn.transaction()?;
    poll::configure(&tx, authority, None, f.repo, &spec(refs), NOW)?;
    tx.commit()?;
    Ok(())
}

fn tip(name: &str, oid: &str) -> Tip {
    Tip {
        name: name.into(),
        oid: oid.into(),
        peeled: None,
    }
}

fn admit(f: &mut Fixture, tips: &[Tip]) -> sentinel_store::Result<Option<poll::Admitted>> {
    let tx = f.conn.transaction()?;
    let out = poll::admit(&tx, f.repo, tips, NOW)?;
    tx.commit()?;
    Ok(out)
}

fn deliveries(f: &Fixture) -> Vec<(String, String, String, String, String)> {
    let mut q = f
        .conn
        .prepare(
            "SELECT provider,external_id,ref_name,old_sha,new_sha FROM webhook_deliveries ORDER BY ref_name,old_sha,new_sha",
        )
        .unwrap();
    q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        ))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

#[test]
fn polling_is_opt_in_tenant_owned_and_requires_a_binding() {
    let mut f = fixture();
    let (alice, bob) = (f.alice, f.bob);
    assert!(matches!(
        configure(&mut f, Authority::credential(alice), &[MAIN]),
        Err(Error::NotFound)
    ));
    bind(&mut f);
    assert!(configure(&mut f, Authority::credential(bob), &[MAIN]).is_err());
    configure(&mut f, Authority::credential(alice), &[MAIN]).unwrap();
    let config = poll::of_repo(&f.conn, f.repo).unwrap().unwrap();
    assert_eq!(config.tenant, f.tenant);
    assert_eq!(config.refs, vec![MAIN]);
    assert!(!config.baselined);
    for bad in [
        Spec {
            interval_ms: poll::MIN_INTERVAL_MS - 1,
            refs: vec![MAIN.into()],
        },
        Spec {
            interval_ms: 60_000,
            refs: vec![],
        },
        Spec {
            interval_ms: 60_000,
            refs: vec!["main".into()],
        },
        Spec {
            interval_ms: 60_000,
            refs: vec!["refs/heads/a*b".into()],
        },
    ] {
        let tx = f.conn.transaction().unwrap();
        assert!(matches!(
            poll::configure(&tx, Authority::HostLocal, None, f.repo, &bad, NOW),
            Err(Error::InvalidInput("poll spec"))
        ));
        tx.rollback().unwrap();
    }
}

#[test]
fn the_first_poll_records_a_baseline_and_admits_nothing() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    let sha = "a".repeat(40);
    let out = admit(&mut f, &[tip(MAIN, &sha)]).unwrap().unwrap();
    assert_eq!(out.baseline, 1);
    assert_eq!(out.created + out.moved + out.deleted, 0);
    assert!(deliveries(&f).is_empty());
    assert!(poll::of_repo(&f.conn, f.repo).unwrap().unwrap().baselined);
    let out = admit(
        &mut f,
        &[tip(MAIN, &sha), tip("refs/heads/other", &"b".repeat(40))],
    )
    .unwrap()
    .unwrap();
    assert_eq!(out, poll::Admitted::default());
    assert!(deliveries(&f).is_empty());
    configure(&mut f, Authority::HostLocal, &["refs/heads/*"]).unwrap();
    admit(&mut f, &[tip(MAIN, &sha)]).unwrap();
    let out = admit(
        &mut f,
        &[tip(MAIN, &sha), tip("refs/heads/other", &"b".repeat(40))],
    )
    .unwrap()
    .unwrap();
    assert_eq!(out.created, 1);
    assert_eq!(out.deleted, 0);
    let rows = deliveries(&f);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, "refs/heads/other");
    assert_eq!(rows[0].3, "0".repeat(40));
}

#[test]
fn moved_created_and_deleted_refs_become_ref_update_deliveries() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &["refs/heads/*"]).unwrap();
    let (a, b) = ("a".repeat(40), "b".repeat(40));
    admit(&mut f, &[tip(MAIN, &a)]).unwrap();
    let out = admit(&mut f, &[tip(MAIN, &b)]).unwrap().unwrap();
    assert_eq!(out.moved, 1);
    let out = admit(&mut f, &[tip(MAIN, &a)]).unwrap().unwrap();
    assert_eq!(out.moved, 1);
    let out = admit(&mut f, &[]).unwrap().unwrap();
    assert_eq!(out.deleted, 1);
    let rows = deliveries(&f);
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.0, "poll");
        assert!(row.1.starts_with("poll:"));
        assert_eq!(row.1.len(), 5 + 64);
        assert_eq!(row.2, MAIN);
    }
    let transitions: Vec<(String, String)> =
        rows.iter().map(|r| (r.3.clone(), r.4.clone())).collect();
    for expected in [
        (a.clone(), b.clone()),
        (b.clone(), a.clone()),
        (a.clone(), "0".repeat(40)),
    ] {
        assert!(transitions.contains(&expected), "missing {expected:?}");
    }
    let mut ids: Vec<&String> = rows.iter().map(|r| &r.1).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    let out = admit(&mut f, &[tip(MAIN, &b)]).unwrap().unwrap();
    assert_eq!(out.created, 1);
    assert_eq!(rows_len(&f), 4);
    let rows = deliveries(&f);
    assert!(rows.iter().any(|r| r.3 == "0".repeat(40) && r.4 == b));
}

fn rows_len(f: &Fixture) -> usize {
    deliveries(f).len()
}

#[test]
fn a_replayed_advertisement_never_duplicates_a_delivery() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    let (a, b) = ("a".repeat(40), "b".repeat(40));
    admit(&mut f, &[tip(MAIN, &a)]).unwrap();
    admit(&mut f, &[tip(MAIN, &b)]).unwrap();
    // A replayed advertisement emits nothing: the cursor already names it.
    let out = admit(&mut f, &[tip(MAIN, &b)]).unwrap().unwrap();
    assert_eq!(out, poll::Admitted::default());
    assert_eq!(rows_len(&f), 1);
}

#[test]
fn annotated_tags_track_the_tag_object_and_record_the_peel() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &["refs/tags/*"]).unwrap();
    let (tag_obj, commit) = ("c".repeat(40), "d".repeat(40));
    admit(
        &mut f,
        &[Tip {
            name: "refs/tags/v1".into(),
            oid: tag_obj.clone(),
            peeled: Some(commit.clone()),
        }],
    )
    .unwrap();
    let observed = poll::observations(&f.conn, f.repo).unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].oid, tag_obj);
    assert_eq!(observed[0].peeled.as_deref(), Some(commit.as_str()));
    let out = admit(
        &mut f,
        &[Tip {
            name: "refs/tags/v1".into(),
            oid: "e".repeat(40),
            peeled: Some("f".repeat(40)),
        }],
    )
    .unwrap()
    .unwrap();
    assert_eq!(out.moved, 1);
    let rows = deliveries(&f);
    assert_eq!(rows[0].4, "e".repeat(40));
}

#[test]
fn reconfigure_rebind_and_revoke_reset_or_remove_poll_state() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    admit(&mut f, &[tip(MAIN, &"a".repeat(40))]).unwrap();
    // Stale cursors for dropped refs would fabricate deletions, so the baseline is rebuilt.
    configure(&mut f, Authority::HostLocal, &["refs/heads/release-*"]).unwrap();
    assert!(poll::observations(&f.conn, f.repo).unwrap().is_empty());
    assert!(!poll::of_repo(&f.conn, f.repo).unwrap().unwrap().baselined);
    let out = admit(&mut f, &[tip("refs/heads/release-1", &"b".repeat(40))])
        .unwrap()
        .unwrap();
    assert_eq!(out.baseline, 1);
    assert!(deliveries(&f).is_empty());
    let binding = Binding {
        remote: "https://git.example:8443/team/other.git".into(),
        allowed_refs: vec!["refs/heads/*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    let tx = f.conn.transaction().unwrap();
    sources::bind(
        &tx,
        Authority::HostLocal,
        None,
        Update {
            repo: f.repo,
            expected: 1,
            binding: &binding,
            credential: &Credential::Public,
            forge: None,
        },
        &["https://git.example:8443".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(poll::observations(&f.conn, f.repo).unwrap().is_empty());
    assert!(!poll::of_repo(&f.conn, f.repo).unwrap().unwrap().baselined);
    let tx = f.conn.transaction().unwrap();
    sources::revoke(&tx, Authority::HostLocal, None, f.repo, 2, NOW).unwrap();
    tx.commit().unwrap();
    assert!(poll::of_repo(&f.conn, f.repo).unwrap().is_none());
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        poll::configure(&tx, Authority::HostLocal, None, f.repo, &spec(&[MAIN]), NOW),
        Err(Error::NotFound)
    ));
    tx.rollback().unwrap();
}

#[test]
fn disabling_clears_schedule_and_cursor_and_reenabling_rebaselines() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    admit(&mut f, &[tip(MAIN, &"a".repeat(40))]).unwrap();
    let tx = f.conn.transaction().unwrap();
    poll::disable(&tx, Authority::HostLocal, None, f.repo, NOW).unwrap();
    tx.commit().unwrap();
    assert!(poll::of_repo(&f.conn, f.repo).unwrap().is_none());
    assert!(poll::observations(&f.conn, f.repo).unwrap().is_empty());
    assert!(
        poll::due(&f.conn, UnixMillis(i64::MAX), 8)
            .unwrap()
            .is_empty()
    );
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        poll::admit(&tx, f.repo, &[tip(MAIN, &"b".repeat(40))], NOW).unwrap(),
        None
    );
    tx.rollback().unwrap();
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    let out = admit(&mut f, &[tip(MAIN, &"b".repeat(40))])
        .unwrap()
        .unwrap();
    assert_eq!(out.baseline, 1);
}

#[test]
fn a_full_delivery_queue_defers_without_advancing_the_cursor() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    let (a, b) = ("a".repeat(40), "b".repeat(40));
    admit(&mut f, &[tip(MAIN, &a)]).unwrap();
    let tx = f.conn.transaction().unwrap();
    for i in 0..intake::MAX_PENDING_PER_REPO {
        let sha = format!("{:040x}", i + 1);
        intake::accept(
            &tx,
            f.repo,
            &intake::NewDelivery {
                authentication: sentinel_store::intake::Authentication::HookToken,
                provider: "generic",
                external_id: &format!("hook-{i}"),
                event: "ref_update",
                ref_name: "refs/heads/stale",
                old_sha: &sha,
                new_sha: &sha,
            },
            None,
            NOW,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let out = admit(&mut f, &[tip(MAIN, &b)]).unwrap().unwrap();
    assert_eq!(out.deferred, 1);
    assert_eq!(out.moved, 0);
    let observed = poll::observations(&f.conn, f.repo).unwrap();
    assert_eq!(observed[0].oid, a);
}

#[test]
fn a_repeated_transition_after_a_revert_is_a_new_delivery() {
    let mut f = fixture();
    bind(&mut f);
    configure(&mut f, Authority::HostLocal, &[MAIN]).unwrap();
    let (a, b) = ("a".repeat(40), "b".repeat(40));
    admit(&mut f, &[tip(MAIN, &a)]).unwrap();
    for oid in [&b, &a, &b] {
        let out = admit(&mut f, &[tip(MAIN, oid)]).unwrap().unwrap();
        assert_eq!(out.moved, 1, "{out:?}");
    }
    let rows = deliveries(&f);
    assert_eq!(rows.len(), 3, "{rows:?}");
    let repeated = rows.iter().filter(|r| r.3 == a && r.4 == b).count();
    assert_eq!(repeated, 2, "both A→B transitions are deliveries");
    let mut ids: Vec<&String> = rows.iter().map(|r| &r.1).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    let out = admit(&mut f, &[tip(MAIN, &b)]).unwrap().unwrap();
    assert_eq!(out, poll::Admitted::default());
}
