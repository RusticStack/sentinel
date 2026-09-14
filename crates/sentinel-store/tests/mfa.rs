//! A06 behavior: TOTP enrollment under a sealed seed, one-use recovery codes,
//! step-up gating privileged changes, and session administration that never
//! exposes a credential.

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
/// A fixed instant well past the epoch, in milliseconds.
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

    /// The code an authenticator app would show for this seed at `now`.
    fn code_for(&self, seed: &Seed, now: UnixMillis) -> String {
        let seconds = now.0 as u64 / 1000;
        (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|code| sentinel_auth::mfa::check(seed, code, seconds).is_some())
            .expect("some six-digit code matches")
    }

    /// Enroll, returning the seed the app holds plus the recovery codes.
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

/// What the authenticator app does with the QR code: read the base32 seed.
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

    // A plain session is a platform admin, yet cannot change who may sign in.
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

    // With no second factor enrolled, the password is the step-up proof.
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

    // Freshness expires: the same session is ordinary again afterwards.
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
    let seed = seed_from_uri(&enrollment.provisioning_uri);

    // Unconfirmed, nothing has changed: the password still steps up, and a
    // wrong code does not confirm.
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

    // The stored seed is not the seed, and cannot be opened for another account.
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
    // A confirmed factor cannot be quietly re-enrolled by a live session.
    assert!(matches!(
        mfa::begin_enrollment(&f.store, &f.key, &f.session(now), "Sentinel", "root", now),
        Err(Error::Conflict)
    ));
}

#[test]
fn a_totp_code_steps_up_once_and_the_password_no_longer_can() {
    let f = fixture();
    let now = at(T0 + 10);
    let (seed, _codes) = f.enroll(now);
    let later = at(T0 + 10 + 2 * Policy::default().step_up_ms);
    let session = f.session(later);
    assert!(!session.stepped_up_within(Policy::default(), later));

    // A password is not a second factor once one exists.
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
    // An older step cannot be reintroduced by raw SQL either.
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

    // Retyped in upper case without the separator, it still works — once.
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

    // Reissue needs the step-up the code just provided; old codes then die.
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
    // Without step-up, reissue is refused.
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
    // The session that did it is gone too: no stepped-up window survives.
    assert!(matches!(
        f.store
            .read(|c| local_auth::authenticate(c, &f.cookie, later)),
        Err(Error::NotFound)
    ));

    // Host-local removal for a lost device is audited as host-local.
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

    // Another account can neither list nor revoke them.
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

    // The account revokes one of its own by name; the other keeps working.
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

    // Host-local logout-all reaches everything, and is audited as host-local.
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
    // Moving the stamp backwards, or onto a revoked session, is refused.
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
    // A stamp in the future is not fresh: the clock, not the row, decides.
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
