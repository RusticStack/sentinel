//! A04 behavior: single-use sign-in state, verified identity linking, sign-in
//! by immutable provider subject, and the separation of proof from admission.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    UnixMillis, UserId,
    auth::{Permissions as P, Principal},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{Authority, provisioning},
    local_auth::{self, Event, Policy},
    sign_in::{self, Outcome},
};

const GITHUB: &str = "github";
const SUBJECT: &str = "4242";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    (dir, store)
}

/// An operator who has already been admitted locally, plus their session.
fn admitted(store: &Store) -> (UserId, local_auth::Session) {
    let user =
        local_auth::bootstrap(store, "root", "Root", b"an operator password", at(0)).unwrap();
    let issued = match local_auth::login(
        store,
        "root",
        b"an operator password",
        Policy::default(),
        at(1),
    ) {
        Ok(local_auth::Login::Accepted(issued)) => issued,
        _ => panic!("local login"),
    };
    let session = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2)))
        .unwrap();
    (user, session)
}

/// The session as it looks right after proving a second factor: linking an
/// identity is an authentication change and requires that freshness.
fn stepped(session: &local_auth::Session) -> local_auth::Session {
    local_auth::Session {
        stepped_up: Some(at(0)),
        ..*session
    }
}

fn signed_in(outcome: Outcome) -> local_auth::Issued {
    match outcome {
        Outcome::SignedIn(issued) => issued,
        Outcome::NoAccount => panic!("expected a session"),
    }
}

#[test]
fn sign_in_state_is_single_use_expiring_and_bound_to_its_provider() {
    let (_dir, store) = store();
    let state = sign_in::begin(&store, GITHUB, Some("/runs"), at(1_000), 60_000).unwrap();

    // A different secret, a different provider, and an expired attempt are all
    // the same answer: no pending attempt.
    assert!(matches!(
        sign_in::consume(&store, GITHUB, &Secret::generate(), at(1_100)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        sign_in::consume(&store, "gitlab", &state, at(1_100)),
        Err(Error::NotFound)
    ));

    assert_eq!(
        sign_in::consume(&store, GITHUB, &state, at(1_100)).unwrap(),
        Some("/runs".into())
    );
    // Replay of a spent attempt is refused, and cannot be undone by raw SQL.
    assert!(matches!(
        sign_in::consume(&store, GITHUB, &state, at(1_200)),
        Err(Error::NotFound)
    ));
    let revive = store.writer().write(move |tx| {
        tx.execute("UPDATE sign_in_states SET consumed_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(revive, Err(Error::Sqlite(_))));

    let expiring = sign_in::begin(&store, GITHUB, None, at(2_000), 1_000).unwrap();
    assert!(matches!(
        sign_in::consume(&store, GITHUB, &expiring, at(3_000)),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_sign_in_destination_must_be_a_same_site_path() {
    let (_dir, store) = store();
    for target in [
        "https://evil.example/steal",
        "//evil.example/steal",
        "runs",
        "/runs\\evil",
        "/runs\nX",
    ] {
        assert!(
            matches!(
                sign_in::begin(&store, GITHUB, Some(target), at(1_000), 60_000),
                Err(Error::InvalidInput("redirect target"))
            ),
            "{target} accepted"
        );
    }
    let state = sign_in::begin(&store, GITHUB, Some("/runs/run_1"), at(1_000), 60_000).unwrap();
    assert_eq!(
        sign_in::consume(&store, GITHUB, &state, at(1_100)).unwrap(),
        Some("/runs/run_1".into())
    );
    // An attempt with no destination is fine; the caller uses its own default.
    let state = sign_in::begin(&store, GITHUB, None, at(1_200), 60_000).unwrap();
    assert_eq!(
        sign_in::consume(&store, GITHUB, &state, at(1_300)).unwrap(),
        None
    );
    assert!(sign_in::begin(&store, GITHUB, None, at(1_400), 0).is_err());
    assert!(sign_in::begin(&store, GITHUB, None, at(1_400), sign_in::STATE_TTL_MS + 1).is_err());
}

#[test]
fn a_verified_identity_signs_in_only_after_it_has_been_linked() {
    let (_dir, store) = store();
    let (user, session) = admitted(&store);

    // Proof is not admission: nothing is registered for an unknown subject.
    assert!(matches!(
        sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(10)).unwrap(),
        Outcome::NoAccount
    ));
    let accounts: i64 = store
        .read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(accounts, 1);

    // Linking is an authenticated act by the account that will own it.
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(20),
    )
    .unwrap();
    let issued =
        signed_in(sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(30)).unwrap());
    assert_eq!(issued.user, user);

    // The session it issues is an ordinary one, with the same authority.
    let federated = store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(40)))
        .unwrap();
    assert_eq!(federated.user, user);
    assert!(federated.super_admin);
    assert!(
        federated
            .principal()
            .permissions
            .contains(P::PLATFORM_ADMIN)
    );
}

#[test]
fn identity_is_the_immutable_subject_not_the_renameable_login() {
    let (_dir, store) = store();
    let (user, session) = admitted(&store);
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(20),
    )
    .unwrap();

    // A different subject is a different account, whatever it calls itself.
    assert!(matches!(
        sign_in::complete(&store, GITHUB, "9999", Policy::default(), at(30)).unwrap(),
        Outcome::NoAccount
    ));
    // The same subject under another provider key is also unrelated.
    assert!(matches!(
        sign_in::complete(&store, "gitlab", SUBJECT, Policy::default(), at(30)).unwrap(),
        Outcome::NoAccount
    ));
    let issued =
        signed_in(sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(40)).unwrap());
    assert_eq!(issued.user, user);
}

#[test]
fn an_identity_belongs_to_one_account_and_is_never_silently_moved() {
    let (_dir, store) = store();
    let (_root, session) = admitted(&store);
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(20),
    )
    .unwrap();

    let other = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, other, "Other", false, at(21)))
        .unwrap();
    let other_session = store
        .writer()
        .write(move |tx| local_auth::issue_session(tx, other, Policy::default(), at(22)))
        .unwrap();
    let other_session = store
        .read(|conn| local_auth::authenticate(conn, &other_session.session, at(23)))
        .unwrap();

    // Claiming an identity another account already holds fails; it is not taken.
    assert!(matches!(
        sign_in::link(
            &store,
            &stepped(&other_session),
            Policy::default(),
            GITHUB,
            SUBJECT,
            at(24)
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(
        signed_in(sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(25)).unwrap())
            .user,
        session.user
    );
    // Relinking the same identity to its own account is refused too: the link
    // is immutable, so there is no re-verification side effect to exploit.
    assert!(
        sign_in::link(
            &store,
            &stepped(&session),
            Policy::default(),
            GITHUB,
            SUBJECT,
            at(26)
        )
        .is_err()
    );
}

#[test]
fn a_suspended_account_cannot_sign_in_through_its_provider() {
    let (_dir, store) = store();
    let (root, session) = admitted(&store);
    let member = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, member, "Member", false, at(20)))
        .unwrap();
    let member_session = store
        .writer()
        .write(move |tx| local_auth::issue_session(tx, member, Policy::default(), at(21)))
        .unwrap();
    let member_session = store
        .read(|conn| local_auth::authenticate(conn, &member_session.session, at(22)))
        .unwrap();
    sign_in::link(
        &store,
        &stepped(&member_session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(23),
    )
    .unwrap();

    let admin = Principal::new(root, P::ALL, None, None);
    store
        .writer()
        .write(move |tx| {
            local_auth::set_active(
                tx,
                local_auth::Authority::Credential {
                    principal: admin,
                    stepped_up: true,
                },
                member,
                false,
                at(24),
            )
        })
        .unwrap();
    assert!(matches!(
        sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(25)).unwrap(),
        Outcome::NoAccount
    ));
    let _ = session;
}

#[test]
fn linking_and_unlinking_are_audited_and_authorized() {
    let (_dir, store) = store();
    let (root, session) = admitted(&store);
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(20),
    )
    .unwrap();

    let identities = store
        .read(|conn| sign_in::identities(conn, Authority::credential(session.principal()), root))
        .unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].provider, GITHUB);
    assert_eq!(identities[0].subject, SUBJECT);

    // Another account can neither read nor remove somebody else's link.
    let outsider = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, outsider, "Outsider", false, at(21)))
        .unwrap();
    let theirs = Principal::new(outsider, P::ALL, None, None);
    assert!(matches!(
        store.read(|conn| sign_in::identities(conn, Authority::credential(theirs), root)),
        Err(Error::NotFound)
    ));
    let refused = store
        .writer()
        .write(move |tx| sign_in::unlink(tx, Authority::credential(theirs), root, GITHUB, at(22)));
    assert!(matches!(refused, Err(Error::NotFound)));

    let principal = session.principal();
    store
        .writer()
        .write(move |tx| {
            sign_in::unlink(tx, Authority::credential(principal), root, GITHUB, at(23))
        })
        .unwrap();
    assert!(matches!(
        sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(24)).unwrap(),
        Outcome::NoAccount
    ));
    // Unlinking makes the identity claimable again, by the same account or another.
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(25),
    )
    .unwrap();
    sign_in::unlink_host_local(&store, root, GITHUB, at(26)).unwrap();
    assert!(matches!(
        sign_in::unlink_host_local(&store, root, GITHUB, at(27)),
        Err(Error::NotFound)
    ));

    let events: Vec<Event> = store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap()
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::IdentityLinked)
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::IdentityUnlinked)
            .count(),
        2
    );
    let audit = store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap();
    let linked = audit
        .iter()
        .find(|r| r.event == Event::IdentityLinked)
        .unwrap();
    assert_eq!(linked.detail.as_deref(), Some(GITHUB));
    assert!(!audit.iter().any(|r| r.detail.as_deref() == Some(SUBJECT)));
}

#[test]
fn a_federated_sign_in_is_recorded_whether_or_not_it_resolves() {
    let (_dir, store) = store();
    let (_root, session) = admitted(&store);
    sign_in::complete(&store, GITHUB, "1", Policy::default(), at(10)).unwrap();
    sign_in::link(
        &store,
        &stepped(&session),
        Policy::default(),
        GITHUB,
        SUBJECT,
        at(20),
    )
    .unwrap();
    sign_in::complete(&store, GITHUB, SUBJECT, Policy::default(), at(30)).unwrap();

    let audit = store
        .read(|conn| local_auth::recent_audit(conn, 100))
        .unwrap();
    let rejected = audit
        .iter()
        .find(|r| r.event == Event::LoginRejected)
        .expect("unknown identity is recorded");
    assert_eq!(rejected.detail.as_deref(), Some(GITHUB));
    assert_eq!(rejected.subject, None);
    let accepted = audit
        .iter()
        .find(|r| r.event == Event::LoginAccepted && r.detail.as_deref() == Some(GITHUB))
        .expect("federated sign-in is distinguishable from a password login");
    assert_eq!(accepted.subject, Some(session.user));
}

#[test]
fn spent_and_expired_sign_in_attempts_are_purged() {
    let (_dir, store) = store();
    let spent = sign_in::begin(&store, GITHUB, None, at(0), 60_000).unwrap();
    sign_in::consume(&store, GITHUB, &spent, at(1)).unwrap();
    sign_in::begin(&store, GITHUB, None, at(0), 100).unwrap();
    let live = sign_in::begin(&store, GITHUB, None, at(0), 60_000).unwrap();

    assert_eq!(sign_in::purge_expired(&store, at(1_000), 1).unwrap(), 1);
    assert_eq!(sign_in::purge_expired(&store, at(1_000), 10).unwrap(), 1);
    assert_eq!(sign_in::purge_expired(&store, at(1_000), 10).unwrap(), 0);
    assert!(sign_in::consume(&store, GITHUB, &live, at(1_000)).is_ok());
}
