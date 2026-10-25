use sentinel_auth::{mfa::Seed, sealed::Key, secret::Secret};
use sentinel_core::{SessionId, UnixMillis, UserId};
use sentinel_store::{
    Durability, Error, Store,
    auth::{Authority, provisioning},
    local_auth::{self, Event, Policy, Session},
    mfa::{self, Proof},
    registration::{self, DeploymentPolicy, Registration},
};

const PASSWORD: &[u8] = b"an operator password";
const T0: i64 = 1_700_000_000_000;

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    key: Key,
    root: UserId,
    cookie: Secret,
}

impl Fixture {
    fn session(&self, now: UnixMillis) -> Session {
        self.store
            .read(|conn| local_auth::authenticate(conn, &self.cookie, now))
            .unwrap()
    }

    fn authority(&self, now: UnixMillis) -> Authority {
        Authority::session(&self.session(now), Policy::default(), now)
    }

    fn code_for(&self, seed: &Seed, now: UnixMillis) -> String {
        self.code_for_after(seed, now, 0)
    }

    fn code_for_after(&self, seed: &Seed, now: UnixMillis, last_step: u64) -> String {
        let seconds = now.0 as u64 / 1000;
        (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|code| {
                sentinel_auth::mfa::check(seed, code, seconds).is_some_and(|step| step > last_step)
            })
            .expect("some six-digit code matches in a fresh step")
    }

    fn enroll(&self, now: UnixMillis) -> (Seed, Vec<String>) {
        let enrollment = mfa::begin_enrollment(
            &self.store,
            &self.key,
            &self.session(now),
            "Sentinel",
            "root",
            now,
        )
        .unwrap();
        let seed = seed_from_uri(&enrollment.provisioning_uri);
        let code = self.code_for(&seed, now);
        let codes = mfa::confirm_enrollment(
            &self.store,
            &self.key,
            &self.cookie,
            &self.session(now),
            &code,
            now,
        )
        .unwrap();
        (seed, codes.iter().map(|c| c.expose().to_owned()).collect())
    }
}

fn seed_from_uri(uri: &str) -> Seed {
    let start = uri.find("secret=").unwrap() + "secret=".len();
    let end = uri[start..].find('&').map_or(uri.len(), |e| start + e);
    Seed::from_base32(&uri[start..end]).unwrap()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Key::load(&key_path).unwrap();
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD, at(T0)).unwrap();
    let issued =
        match local_auth::login(&store, "root", PASSWORD, Policy::default(), at(T0 + 1)).unwrap() {
            local_auth::Login::Accepted(issued) => issued,
            _ => panic!("login"),
        };
    Fixture {
        _dir: dir,
        store,
        key,
        root,
        cookie: issued.session,
    }
}

#[test]
fn privileged_changes_need_a_fresh_second_factor_not_just_a_session() {
    let f = fixture();
    let now = at(T0 + 10);
    let session = f.session(now);
    assert!(session.super_admin);
    assert!(session.stepped_up.is_none());

    let refused = f.store.writer().write({
        let authority = f.authority(now);
        move |tx| {
            registration::set_policy(
                tx,
                authority,
                DeploymentPolicy {
                    registration: Registration::Closed,
                    ..registration::policy(tx)?
                },
                now,
            )
        }
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)), "{refused:?}");
    let target = UserId::new();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, target, "Target", false, now))
        .unwrap();
    let refused = f.store.writer().write({
        let authority = f.authority(now);
        move |tx| local_auth::set_active(tx, authority, target, false, now)
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));
    let refused = f.store.writer().write({
        let authority = f.authority(now);
        move |tx| local_auth::set_super_admin(tx, authority, target, true, now)
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));

    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(b"wrong"),
            now
        )
        .unwrap()
    );
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(PASSWORD),
            now
        )
        .unwrap()
    );
    let session = f.session(now);
    assert_eq!(session.stepped_up, Some(now));
    f.store
        .writer()
        .write({
            let authority = f.authority(now);
            move |tx| local_auth::set_super_admin(tx, authority, target, true, now)
        })
        .unwrap();

    let later = at(T0 + 10 + Policy::default().step_up_ms);
    assert!(!f.session(later).stepped_up_within(Policy::default(), later));
    let refused = f.store.writer().write({
        let authority = f.authority(later);
        move |tx| local_auth::set_super_admin(tx, authority, target, false, later)
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));
    // Host-local authority needs no step-up: holding the file is stronger.
    f.store
        .writer()
        .write(move |tx| {
            local_auth::set_super_admin(tx, Authority::HostLocal, target, false, later)
        })
        .unwrap();
}

#[test]
fn enrollment_is_confirmed_by_a_code_and_the_seed_is_stored_only_sealed() {
    let f = fixture();
    let now = at(T0 + 10);
    let enrollment =
        mfa::begin_enrollment(&f.store, &f.key, &f.session(now), "Sentinel", "root", now).unwrap();
    assert!(enrollment.provisioning_uri.starts_with("otpauth://totp/"));
    let started = f
        .store
        .read(|c| local_auth::recent_audit(c, 1))
        .unwrap()
        .remove(0);
    assert_eq!(started.event, Event::MfaEnrollmentStarted);
    assert_eq!(started.actor, Some(f.root));
    assert_eq!(started.subject, Some(f.root));
    assert!(!started.host_local);
    assert_eq!(started.detail, None);
    let seed = seed_from_uri(&enrollment.provisioning_uri);

    assert!(!f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
    assert!(matches!(
        mfa::confirm_enrollment(&f.store, &f.key, &f.cookie, &f.session(now), "000000", now),
        Err(Error::Forbidden)
    ));
    let code = f.code_for(&seed, now);
    let codes =
        mfa::confirm_enrollment(&f.store, &f.key, &f.cookie, &f.session(now), &code, now).unwrap();
    assert_eq!(codes.len(), sentinel_auth::mfa::RECOVERY_CODE_COUNT);
    assert!(f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
    assert_eq!(
        f.session(now).stepped_up,
        Some(now),
        "confirming is a step-up"
    );

    let sealed: Vec<u8> = f
        .store
        .read(|c| {
            c.query_row("SELECT sealed_seed FROM mfa_totp", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert!(
        !sealed
            .windows(seed.as_bytes().len())
            .any(|w| w == seed.as_bytes())
    );
    let dumped: Vec<u8> = f
        .store
        .read(|c| {
            c.query_row(
                "SELECT group_concat(hex(code_digest)) FROM mfa_recovery_codes",
                [],
                |r| r.get::<_, String>(0),
            )
            .map(String::into_bytes)
            .map_err(Error::from)
        })
        .unwrap();
    for code in &codes {
        assert!(
            !dumped
                .windows(5)
                .any(|w| w == &code.expose().as_bytes()[..5])
        );
    }
    assert!(matches!(
        mfa::begin_enrollment(&f.store, &f.key, &f.session(now), "Sentinel", "root", now),
        Err(Error::Conflict)
    ));
    assert_eq!(
        f.store
            .read(|c| local_auth::recent_audit(c, 100))
            .unwrap()
            .iter()
            .filter(|row| row.event == Event::MfaEnrollmentStarted)
            .count(),
        1,
        "a conflicting start is not audited"
    );
}

#[test]
fn a_totp_code_steps_up_once_and_the_password_no_longer_can() {
    let f = fixture();
    let now = at(T0 + 10);
    let (seed, _codes) = f.enroll(now);
    let later = at(T0 + 10 + 2 * Policy::default().step_up_ms);
    let session = f.session(later);
    assert!(!session.stepped_up_within(Policy::default(), later));

    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(PASSWORD),
            later
        )
        .unwrap()
    );
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Totp("123456"),
            later
        )
        .unwrap()
    );
    let code = f.code_for(&seed, later);
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Totp(&code),
            later
        )
        .unwrap()
    );
    assert!(f.session(later).stepped_up_within(Policy::default(), later));

    // The same code, within its window, is refused: a step is accepted once.
    let replay = at(later.0 + 5_000);
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Totp(&code),
            replay
        )
        .unwrap()
    );
    let rewind = f.store.writer().write(move |tx| {
        tx.execute("UPDATE mfa_totp SET last_step = last_step - 1", [])?;
        Ok(())
    });
    assert!(matches!(rewind, Err(Error::Sqlite(_))));

    let events: Vec<Event> = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(events.contains(&Event::SteppedUp));
    assert!(events.contains(&Event::StepUpFailed));
    assert!(events.contains(&Event::MfaEnrolled));
}

#[test]
fn recovery_codes_are_one_use_and_a_reissue_invalidates_the_old_set() {
    let f = fixture();
    let now = at(T0 + 10);
    let (_seed, codes) = f.enroll(now);
    assert_eq!(
        f.store
            .read(|c| mfa::recovery_codes_remaining(c, f.root))
            .unwrap(),
        10
    );
    let later = at(T0 + 10 + 2 * Policy::default().step_up_ms);
    let session = f.session(later);

    let retyped = codes[0].replace('-', "").to_uppercase();
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Recovery(&retyped),
            later
        )
        .unwrap()
    );
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Recovery(&codes[0]),
            later
        )
        .unwrap()
    );
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Recovery("nope"),
            later
        )
        .unwrap()
    );
    assert_eq!(
        f.store
            .read(|c| mfa::recovery_codes_remaining(c, f.root))
            .unwrap(),
        9
    );
    let unspend = f.store.writer().write(move |tx| {
        tx.execute("UPDATE mfa_recovery_codes SET used_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(unspend, Err(Error::Sqlite(_))));

    let fresh =
        mfa::reissue_recovery_codes(&f.store, &f.session(later), Policy::default(), later).unwrap();
    assert_eq!(
        f.store
            .read(|c| mfa::recovery_codes_remaining(c, f.root))
            .unwrap(),
        10
    );
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Recovery(&codes[1]),
            later
        )
        .unwrap()
    );
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Recovery(fresh[0].expose()),
            later
        )
        .unwrap()
    );
    let stale = at(later.0 + 2 * Policy::default().step_up_ms);
    assert!(matches!(
        mfa::reissue_recovery_codes(&f.store, &f.session(stale), Policy::default(), stale),
        Err(Error::StepUpRequired)
    ));
}

#[test]
fn removing_a_factor_needs_step_up_and_ends_every_session() {
    let f = fixture();
    let now = at(T0 + 10);
    let (seed, _codes) = f.enroll(now);
    let later = at(T0 + 10 + 2 * Policy::default().step_up_ms);
    assert!(matches!(
        mfa::disable(&f.store, &f.session(later), Policy::default(), later),
        Err(Error::StepUpRequired)
    ));
    let code = f.code_for(&seed, later);
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &f.session(later),
            Proof::Totp(&code),
            later
        )
        .unwrap()
    );
    mfa::disable(&f.store, &f.session(later), Policy::default(), later).unwrap();
    assert!(!f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
    assert_eq!(
        f.store
            .read(|c| mfa::recovery_codes_remaining(c, f.root))
            .unwrap(),
        0
    );
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, later)),
        Err(Error::NotFound)
    ));

    let issued = f
        .store
        .writer()
        .write({
            let root = f.root;
            move |tx| local_auth::issue_session(tx, root, Policy::default(), later)
        })
        .unwrap();
    let f2 = Fixture {
        cookie: issued.session,
        ..f
    };
    f2.enroll(later);
    assert!(matches!(
        mfa::disable_host_local(&f2.store, UserId::new(), later),
        Err(Error::NotFound)
    ));
    mfa::disable_host_local(&f2.store, f2.root, later).unwrap();
    let record = f2
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .find(|r| r.event == Event::MfaDisabled && r.host_local)
        .expect("host-local removal is audited");
    assert_eq!(record.subject, Some(f2.root));
}

#[test]
fn sessions_are_listed_and_revoked_by_name_without_exposing_a_secret() {
    let f = fixture();
    let now = at(T0 + 10);
    let mine = f.session(now);
    let second = f
        .store
        .writer()
        .write({
            let root = f.root;
            move |tx| local_auth::issue_session(tx, root, Policy::default(), now)
        })
        .unwrap();
    let second_id = f
        .store
        .read(|c| local_auth::authenticate(c, &second.session, now))
        .unwrap()
        .id
        .unwrap();

    let records = f
        .store
        .read(|c| local_auth::sessions(c, Authority::credential(mine.principal()), f.root, 10))
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|r| r.id == mine.id));
    assert!(records.iter().all(|r| !r.revoked));
    let mut cookie_text = String::new();
    f.cookie.expose(&mut cookie_text);
    assert!(!format!("{records:?}").contains(&cookie_text));

    let outsider = UserId::new();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, outsider, "Outsider", false, now))
        .unwrap();
    let theirs = Authority::credential(sentinel_core::auth::Principal::new(
        outsider,
        sentinel_core::auth::Permissions::ALL,
        None,
        None,
    ));
    assert!(matches!(
        f.store
            .read(|c| local_auth::sessions(c, theirs, f.root, 10)),
        Err(Error::NotFound)
    ));
    let refused = f.store.writer().write({
        let root = f.root;
        move |tx| local_auth::revoke_session(tx, theirs, root, second_id, now)
    });
    assert!(matches!(refused, Err(Error::NotFound)));

    f.store
        .writer()
        .write({
            let root = f.root;
            let authority = Authority::credential(mine.principal());
            move |tx| local_auth::revoke_session(tx, authority, root, second_id, now)
        })
        .unwrap();
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &second.session, now)),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, now))
            .is_ok()
    );
    assert!(matches!(
        f.store.writer().write({
            let root = f.root;
            let authority = Authority::credential(mine.principal());
            move |tx| local_auth::revoke_session(tx, authority, root, SessionId::new(), now)
        }),
        Err(Error::NotFound)
    ));

    assert_eq!(
        local_auth::revoke_all_host_local(&f.store, f.root, now).unwrap(),
        1
    );
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, now)),
        Err(Error::NotFound)
    ));
    assert!(
        f.store
            .read(|c| local_auth::recent_audit(c, 100))
            .unwrap()
            .iter()
            .any(|r| r.event == Event::LogoutAll && r.host_local)
    );
}

#[test]
fn step_up_freshness_cannot_be_forged_or_rewound() {
    let f = fixture();
    let now = at(T0 + 10);
    let session = f.session(now);
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(PASSWORD),
            now
        )
        .unwrap()
    );
    let rewind = f.store.writer().write(move |tx| {
        tx.execute("UPDATE sessions SET stepped_up_ms = stepped_up_ms - 1", [])?;
        Ok(())
    });
    assert!(matches!(rewind, Err(Error::Sqlite(_))));
    local_auth::logout(&f.store, &f.cookie, now).unwrap();
    let forge = f.store.writer().write(move |tx| {
        tx.execute("UPDATE sessions SET stepped_up_ms = ?1", [now.0 + 1])?;
        Ok(())
    });
    assert!(matches!(forge, Err(Error::Sqlite(_))));
    let earlier = at(T0 + 5);
    let issued = f
        .store
        .writer()
        .write({
            let root = f.root;
            move |tx| local_auth::issue_session(tx, root, Policy::default(), earlier)
        })
        .unwrap();
    let s = f
        .store
        .read(|c| local_auth::authenticate(c, &issued.session, now))
        .unwrap();
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &issued.session,
            &s,
            Proof::Password(PASSWORD),
            now
        )
        .unwrap()
    );
    let s = f
        .store
        .read(|c| local_auth::authenticate(c, &issued.session, earlier))
        .unwrap();
    assert!(!s.stepped_up_within(Policy::default(), earlier));
}

#[test]
fn repeated_failed_step_ups_revoke_the_session_and_a_success_forgives_them() {
    let f = fixture();
    let now = at(T0 + 10);
    let session = f.session(now);
    for _ in 0..mfa::MAX_STEP_UP_FAILURES - 1 {
        assert!(
            !mfa::step_up(
                &f.store,
                &f.key,
                &f.cookie,
                &session,
                Proof::Password(b"guess"),
                now
            )
            .unwrap()
        );
    }
    assert!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, now))
            .is_ok()
    );
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(PASSWORD),
            now
        )
        .unwrap()
    );
    let (failures, revoked): (i64, Option<i64>) = f
        .store
        .read(|c| {
            c.query_row(
                "SELECT step_up_failures, revoked_ms FROM sessions WHERE id = ?1",
                [session.id.unwrap().as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!((failures, revoked), (0, None));

    let later = at(T0 + 10 + Policy::default().step_up_ms + 1);
    let session = f.session(later);
    for _ in 0..mfa::MAX_STEP_UP_FAILURES {
        let _ = mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Totp("000000"),
            later,
        );
    }
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, later)),
        Err(Error::NotFound)
    ));
    let revoked = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .find(|r| r.event == Event::SessionRevoked)
        .expect("revocation is audited");
    assert_eq!(revoked.detail.as_deref(), Some("step-up failures"));
}

#[test]
fn linking_an_identity_and_provisioning_a_password_are_authentication_changes() {
    let f = fixture();
    let now = at(T0 + 10);
    let session = f.session(now);
    assert!(matches!(
        sentinel_store::sign_in::link(&f.store, &session, Policy::default(), "github", "4242", now),
        Err(Error::StepUpRequired)
    ));
    let target = UserId::new();
    let phc = sentinel_auth::password::hash(PASSWORD).unwrap();
    f.store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, target, "Target", false, now))
        .unwrap();
    let refused = f.store.writer().write({
        let authority = f.authority(now);
        let phc = phc.clone();
        move |tx| local_auth::provision_credential(tx, authority, target, "target", &phc, now)
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));

    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &session,
            Proof::Password(PASSWORD),
            now
        )
        .unwrap()
    );
    let session = f.session(now);
    sentinel_store::sign_in::link(&f.store, &session, Policy::default(), "github", "4242", now)
        .unwrap();
    f.store
        .writer()
        .write({
            let authority = f.authority(now);
            move |tx| local_auth::provision_credential(tx, authority, target, "target", &phc, now)
        })
        .unwrap();
    let refused = f.store.writer().write({
        let bearer = Authority::credential(session.principal());
        move |tx| local_auth::set_super_admin(tx, bearer, target, true, now)
    });
    assert!(matches!(refused, Err(Error::StepUpRequired)));
}

fn sign_in(f: &Fixture, now: UnixMillis) -> (Secret, Session) {
    let cookie =
        match local_auth::login(&f.store, "root", PASSWORD, Policy::default(), now).unwrap() {
            local_auth::Login::Accepted(issued) => issued.session,
            _ => panic!("login"),
        };
    let session = f
        .store
        .read(|c| local_auth::authenticate(c, &cookie, now))
        .unwrap();
    (cookie, session)
}

fn wrong_codes(seed: &Seed, now: UnixMillis, n: usize) -> Vec<String> {
    let seconds = now.0 as u64 / 1000;
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .filter(|code| sentinel_auth::mfa::check(seed, code, seconds).is_none())
        .take(n)
        .collect()
}

fn guess(f: &Fixture, seed: &Seed, now: UnixMillis, guesses: usize) {
    let mut current = sign_in(f, now);
    for code in wrong_codes(seed, now, guesses) {
        if f.store
            .read(|c| local_auth::authenticate(c, &current.0, now))
            .is_err()
        {
            current = sign_in(f, now);
        }
        assert!(
            !mfa::step_up(
                &f.store,
                &f.key,
                &current.0,
                &current.1,
                Proof::Totp(&code),
                now
            )
            .unwrap()
        );
    }
}

fn factor_locked(f: &Fixture, now: UnixMillis) -> bool {
    f.store
        .read(|c| {
            c.query_row(
                "SELECT locked_until_ms > ?2 FROM mfa_totp WHERE user_id = ?1",
                rusqlite::params![f.root.as_bytes(), now.0],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap()
}

#[test]
fn step_up_failures_accumulate_across_sessions() {
    let f = fixture();
    let (seed, _) = f.enroll(at(T0 + 10));
    let now = at(T0 + 120_000);
    guess(&f, &seed, now, mfa::MAX_FACTOR_FAILURES as usize - 1);
    assert!(!factor_locked(&f, now));
    let (cookie, session) = sign_in(&f, now);
    let last = wrong_codes(&seed, now, 1).remove(0);
    assert!(!mfa::step_up(&f.store, &f.key, &cookie, &session, Proof::Totp(&last), now).unwrap());
    assert!(factor_locked(&f, now));
    assert!(
        f.store
            .read(|c| local_auth::authenticate(c, &cookie, now))
            .is_err()
    );
    assert!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, now))
            .is_err()
    );
    let audit = f
        .store
        .read(|c| local_auth::recent_audit(c, 5))
        .unwrap()
        .into_iter()
        .find(|r| r.event == Event::SessionRevoked)
        .expect("the lockout is audited");
    assert_eq!(audit.detail.as_deref(), Some("second factor locked"));
}

#[test]
fn an_account_lockout_refuses_even_a_correct_code_until_it_expires() {
    let f = fixture();
    let (seed, recovery) = f.enroll(at(T0 + 10));
    let now = at(T0 + 120_000);
    guess(&f, &seed, now, mfa::MAX_FACTOR_FAILURES as usize);
    assert!(factor_locked(&f, now));
    let during = at(now.0 + 60_000);
    let (cookie, session) = sign_in(&f, during);
    let good = f.code_for(&seed, during);
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &cookie,
            &session,
            Proof::Totp(&good),
            during
        )
        .unwrap()
    );
    let (cookie, session) = sign_in(&f, during);
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &cookie,
            &session,
            Proof::Recovery(&recovery[0]),
            during
        )
        .unwrap()
    );
    assert_eq!(
        f.store
            .read(|c| mfa::recovery_codes_remaining(c, f.root))
            .unwrap(),
        recovery.len()
    );
    let after = at(now.0 + mfa::FACTOR_LOCKOUT_MS + 30_000);
    let (cookie, session) = sign_in(&f, after);
    let good = f.code_for(&seed, after);
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &cookie,
            &session,
            Proof::Totp(&good),
            after
        )
        .unwrap()
    );
    let failures: i64 = f
        .store
        .read(|c| {
            c.query_row(
                "SELECT failures FROM mfa_totp WHERE user_id = ?1",
                [f.root.as_bytes()],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(failures, 0);
}

fn failures_of(f: &Fixture) -> i64 {
    f.store
        .read(|c| {
            c.query_row(
                "SELECT failures FROM mfa_totp WHERE user_id = ?1",
                rusqlite::params![f.root.as_bytes()],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap()
}

#[test]
fn a_password_change_with_a_factor_needs_step_up_and_a_wrong_password_never_counts_against_the_factor()
 {
    let f = fixture();
    let (seed, _) = f.enroll(at(T0 + 10));
    let policy = Policy::default();
    let later = at(T0 + 10 + 2 * policy.step_up_ms);
    let new_password = b"a brand new password";

    let (cookie, session) = sign_in(&f, later);
    assert!(matches!(
        local_auth::change_password(
            &f.store,
            &cookie,
            &session,
            policy,
            PASSWORD,
            new_password,
            later
        ),
        Err(Error::StepUpRequired)
    ));
    let code = f.code_for(&seed, later);
    let used_step = sentinel_auth::mfa::check(&seed, &code, later.0 as u64 / 1000).unwrap();
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &cookie,
            &session,
            Proof::Totp(&code),
            later
        )
        .unwrap()
    );

    let stepped = f
        .store
        .read(|c| local_auth::authenticate(c, &cookie, later))
        .unwrap();
    for _ in 0..mfa::MAX_STEP_UP_FAILURES {
        assert!(
            !local_auth::change_password(
                &f.store,
                &cookie,
                &stepped,
                policy,
                b"not it",
                new_password,
                later
            )
            .unwrap()
        );
    }
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &cookie, later)),
        Err(Error::NotFound)
    ));
    assert_eq!(failures_of(&f), 0);
    assert!(!factor_locked(&f, later));

    let t2 = at(later.0 + 60_000);
    let (cookie, session) = sign_in(&f, t2);
    let code = f.code_for_after(&seed, t2, used_step);
    assert!(mfa::step_up(&f.store, &f.key, &cookie, &session, Proof::Totp(&code), t2).unwrap());
    let stepped = f
        .store
        .read(|c| local_auth::authenticate(c, &cookie, t2))
        .unwrap();
    assert!(
        local_auth::change_password(
            &f.store,
            &cookie,
            &stepped,
            policy,
            PASSWORD,
            new_password,
            t2
        )
        .unwrap()
    );
    assert!(matches!(
        f.store.read(|c| local_auth::authenticate(c, &cookie, t2)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        local_auth::login(&f.store, "root", new_password, policy, t2).unwrap(),
        local_auth::Login::Accepted(_)
    ));
    let events: Vec<Event> = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(events.contains(&Event::PasswordChanged));
}

#[test]
fn host_local_enrollment_needs_the_code_marks_the_audit_and_leaves_sessions_alone() {
    let f = fixture();
    let now = at(T0 + 10);
    let enrollment =
        mfa::begin_enrollment_host_local(&f.store, &f.key, f.root, "Sentinel", "root", now)
            .unwrap();
    let seed = seed_from_uri(&enrollment.provisioning_uri);

    assert!(!f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
    let wrong = wrong_codes(&seed, now, 1);
    assert!(matches!(
        mfa::confirm_enrollment_host_local(&f.store, &f.key, f.root, &wrong[0], now),
        Err(Error::Forbidden)
    ));
    assert!(!f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());

    let code = f.code_for(&seed, now);
    let codes = mfa::confirm_enrollment_host_local(&f.store, &f.key, f.root, &code, now).unwrap();
    assert_eq!(codes.len(), 10);
    assert!(f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
    assert!(f.session(now).stepped_up.is_none());
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &f.session(now),
            Proof::Totp(&code),
            now
        )
        .unwrap()
    );
    assert!(matches!(
        mfa::begin_enrollment_host_local(&f.store, &f.key, f.root, "Sentinel", "root", now),
        Err(Error::Conflict)
    ));

    let fresh = mfa::reissue_recovery_codes_host_local(&f.store, f.root, now).unwrap();
    assert!(
        !mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &f.session(now),
            Proof::Recovery(codes[0].expose()),
            now
        )
        .unwrap()
    );
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &f.cookie,
            &f.session(now),
            Proof::Recovery(fresh[0].expose()),
            now
        )
        .unwrap()
    );
    let audit = f.store.read(|c| local_auth::recent_audit(c, 100)).unwrap();
    for event in [
        Event::MfaEnrollmentStarted,
        Event::MfaEnrolled,
        Event::RecoveryCodesIssued,
    ] {
        let row = audit.iter().find(|r| r.event == event).expect("audited");
        assert!(row.host_local && row.actor.is_none(), "{event:?}");
        assert_eq!(row.subject, Some(f.root));
        assert_eq!(row.detail, None);
    }
}

#[test]
fn wrong_confirmation_codes_count_against_the_session_and_never_lock_a_pending_factor() {
    let f = fixture();
    let now = at(T0 + 10);
    let enrollment =
        mfa::begin_enrollment(&f.store, &f.key, &f.session(now), "Sentinel", "root", now).unwrap();
    let seed = seed_from_uri(&enrollment.provisioning_uri);
    let wrong = wrong_codes(&seed, now, mfa::MAX_STEP_UP_FAILURES as usize);
    for (n, code) in wrong.iter().enumerate() {
        let alive = f
            .store
            .read(|c| local_auth::authenticate(c, &f.cookie, now))
            .is_ok();
        assert!(alive, "revoked before the limit, at guess {n}");
        let session = f.session(now);
        assert!(matches!(
            mfa::confirm_enrollment(&f.store, &f.key, &f.cookie, &session, code, now),
            Err(Error::Forbidden)
        ));
    }
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, now)),
        Err(Error::NotFound)
    ));
    assert!(!factor_locked_pending(&f, now));
    let failed = f
        .store
        .read(|c| local_auth::recent_audit(c, 100))
        .unwrap()
        .into_iter()
        .filter(|r| r.event == Event::StepUpFailed)
        .count();
    assert_eq!(failed, wrong.len());

    let (cookie, session) = sign_in(&f, now);
    let code = f.code_for(&seed, now);
    mfa::confirm_enrollment(&f.store, &f.key, &cookie, &session, &code, now).unwrap();
    assert!(f.store.read(|c| mfa::enrolled(c, f.root)).unwrap());
}

fn factor_locked_pending(f: &Fixture, now: UnixMillis) -> bool {
    f.store
        .read(|c| {
            c.query_row(
                "SELECT locked_until_ms > ?2 OR failures != 0 FROM mfa_totp WHERE user_id = ?1",
                rusqlite::params![f.root.as_bytes(), now.0],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap()
}

#[test]
fn a_session_is_a_fresh_sign_in_only_inside_the_step_up_window() {
    let f = fixture();
    let policy = Policy::default();
    let session = f.session(at(T0 + 2));
    assert!(session.signed_in_within(policy, at(T0 + 2)));
    assert!(session.signed_in_within(policy, at(T0 + policy.step_up_ms)));
    assert!(!session.signed_in_within(policy, at(T0 + 1 + policy.step_up_ms)));
    assert!(!session.signed_in_within(policy, at(T0 - 1)));
}

#[test]
fn enrollment_and_reissue_refuse_an_account_that_cannot_hold_a_factor() {
    let f = fixture();
    let now = at(T0 + 10);
    assert!(matches!(
        mfa::begin_enrollment_host_local(&f.store, &f.key, UserId::new(), "Sentinel", "x", now),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        mfa::reissue_recovery_codes_host_local(&f.store, f.root, now),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        mfa::reissue_recovery_codes(&f.store, &f.session(now), Policy::default(), now),
        Err(Error::StepUpRequired)
    ));
}

#[test]
fn host_local_recovery_clears_the_step_up_lockout() {
    let f = fixture();
    let (seed, _) = f.enroll(at(T0 + 10));
    let now = at(T0 + 120_000);
    guess(&f, &seed, now, mfa::MAX_FACTOR_FAILURES as usize);
    assert!(factor_locked(&f, now));
    local_auth::recover(&f.store, "root", PASSWORD, at(now.0 + 1)).unwrap();
    assert!(!factor_locked(&f, at(now.0 + 1)));
    let later = at(now.0 + 30_000);
    let (cookie, session) = sign_in(&f, later);
    let good = f.code_for(&seed, later);
    assert!(
        mfa::step_up(
            &f.store,
            &f.key,
            &cookie,
            &session,
            Proof::Totp(&good),
            later
        )
        .unwrap()
    );
}
