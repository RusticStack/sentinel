//! Verified email identity, email invitations and the mail outbox: the
//! behavior a person or an attacker can observe, and the failure paths.

use std::sync::Arc;

use rusqlite::params;
use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{
    InstallationId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind},
    email::{self, Confirmation, Requested},
    local_auth::{self, Event, Login, Policy},
    registration::{self, Accepted, Admission, Applicant, Authority, Refusal, Terms},
};

const PASSWORD: &[u8] = b"an acceptable member password";
const TTL: i64 = email::VERIFICATION_TTL_MS;

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    admin: Principal,
    tenant: TenantId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"an operator password", at(0)).unwrap();
    let admin = Principal::new(root, P::ALL, None, None);
    let tenant = TenantId::new();
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                at(1),
            )
        })
        .unwrap();
    Fixture {
        dir,
        store,
        admin,
        tenant,
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

    /// A link-form invitation that admits one account to a deployment that is
    /// invite-only by default.
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

    fn sign_up(&self, address: &str, invitation: &Secret, key: Option<Arc<Key>>) -> Admission {
        registration::register_with(
            &self.store,
            Applicant::Email {
                display_name: "New Person",
                email: address,
                password: PASSWORD,
            },
            Some(invitation),
            key,
            at(10),
        )
        .unwrap()
    }

    fn user_of(&self, admission: Admission) -> UserId {
        match admission {
            Admission::Admitted(user) => user,
            other => panic!("expected admission, got {other:?}"),
        }
    }

    /// The operator's way to a link: host-local, for a deployment without Resend.
    fn link(&self, user: UserId, address: Option<&'static str>, now: i64) -> Secret {
        self.store
            .writer()
            .write(move |tx| email::issue_link(tx, Authority::HostLocal, user, address, at(now)))
            .unwrap()
            .secret
    }

    fn confirm(&self, secret: &Secret, now: i64) -> Confirmation {
        email::confirm(&self.store, secret, at(now)).unwrap()
    }

    fn sign_in(&self, identifier: &str) -> bool {
        matches!(
            local_auth::login(&self.store, identifier, PASSWORD, Policy::default(), at(50))
                .unwrap(),
            Login::Accepted(_)
        )
    }

    fn role_in(&self, tenant: TenantId, user: UserId) -> i64 {
        self.store
            .read(|conn| {
                conn.query_row(
                    "SELECT COALESCE((SELECT role FROM memberships
                      WHERE tenant_id = ?1 AND user_id = ?2), 0)",
                    params![tenant.as_bytes(), user.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(Error::from)
            })
            .unwrap()
    }

    fn address_of(&self, user: UserId) -> Option<(String, bool)> {
        self.store
            .read(|conn| email::account_email(conn, user))
            .unwrap()
    }

    fn events(&self) -> Vec<Event> {
        self.store
            .read(|conn| local_auth::recent_audit(conn, 100))
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect()
    }

    fn email_invitation(&self, address: &'static str) -> registration::Invited {
        let (admin, tenant) = (self.admin, self.tenant);
        self.store
            .writer()
            .write(move |tx| {
                registration::invite_by_email(
                    tx,
                    Authority::credential(admin),
                    Terms {
                        tenant: Some(tenant),
                        role: Some(Role::Reader),
                        ..Terms::default()
                    },
                    address,
                    None,
                    at(3),
                )
            })
            .unwrap()
    }
}

#[test]
fn an_address_signs_in_only_after_it_is_verified_and_in_any_spelling() {
    let f = fixture();
    let invitation = f.admission();
    let user = f.user_of(f.sign_up("Ana.Lima@Example.COM", &invitation, None));

    // The claim is recorded canonically, and is not yet an identity.
    assert_eq!(
        f.address_of(user),
        Some(("ana.lima@example.com".to_owned(), false))
    );
    assert!(!f.sign_in("ana.lima@example.com"));

    let link = f.link(user, None, 20);
    assert!(matches!(
        f.confirm(&link, 21),
        Confirmation::Verified { joined: None, .. }
    ));
    assert_eq!(
        f.address_of(user),
        Some(("ana.lima@example.com".to_owned(), true))
    );
    // Any spelling of the verified address, with the one password.
    assert!(f.sign_in("ana.lima@example.com"));
    assert!(f.sign_in("  ANA.LIMA@example.com"));
    assert!(!f.sign_in("someone.else@example.com"));
    // The generated username keeps working beside it.
    let username = f
        .store
        .read(|conn| local_auth::username_of(conn, user))
        .unwrap()
        .unwrap();
    assert!(username.starts_with("user-") && !username.contains('@'));
    assert!(f.sign_in(&username));
    assert!(f.events().contains(&Event::EmailVerified));
}

#[test]
fn an_existing_username_account_adds_and_verifies_an_address() {
    let f = fixture();
    let invitation = f.admission();
    let user = f.user_of(
        match registration::register(
            &f.store,
            Applicant::Local {
                display_name: "Old Timer",
                username: "oldtimer",
                password: PASSWORD,
            },
            Some(&invitation),
            at(5),
        )
        .unwrap()
        {
            admitted @ Admission::Admitted(_) => admitted,
            other => panic!("{other:?}"),
        },
    );
    assert_eq!(f.address_of(user), None);
    assert!(f.sign_in("oldtimer"));

    let requested = f
        .store
        .writer()
        .write(move |tx| email::request(tx, None, user, "Old@Example.com", None, at(10)))
        .unwrap();
    assert_eq!(requested, Requested::Undelivered, "no Resend key, no queue");
    assert!(!f.sign_in("old@example.com"), "a claim is not an identity");

    let link = f.link(user, None, 11);
    assert!(matches!(
        f.confirm(&link, 12),
        Confirmation::Verified { .. }
    ));
    assert!(f.sign_in("old@example.com"));
    assert!(f.sign_in("oldtimer"), "the username account keeps working");
}

#[test]
fn a_verification_link_is_single_use_and_expires() {
    let f = fixture();
    let user = f.user_of(f.sign_up("one@example.com", &f.admission(), None));

    let first = f.link(user, None, 20);
    // A newer link voids the older one.
    let second = f.link(user, None, 30);
    assert_eq!(f.confirm(&first, 31), Confirmation::Refused);
    assert!(matches!(
        f.confirm(&second, 32),
        Confirmation::Verified { .. }
    ));
    // Replaying the spent link verifies nothing and changes nothing.
    assert_eq!(f.confirm(&second, 33), Confirmation::Refused);

    // Expiry: a link is dead one millisecond past its life.
    let other = f.user_of(f.sign_up("two@example.com", &f.admission(), None));
    let link = f.link(other, None, 100);
    assert_eq!(f.confirm(&link, 100 + TTL), Confirmation::Refused);
    // An unknown secret is the same refusal.
    assert_eq!(f.confirm(&Secret::generate(), 101), Confirmation::Refused);
    assert_eq!(
        f.address_of(other),
        Some(("two@example.com".to_owned(), false))
    );
}

#[test]
fn only_the_digest_of_a_token_is_stored() {
    let f = fixture();
    let user = f.user_of(f.sign_up("digest@example.com", &f.admission(), None));
    let link = f.link(user, None, 20);
    let mut text = String::new();
    link.expose(&mut text);
    let stored: Vec<Vec<u8>> = f
        .store
        .read(|conn| {
            let mut stmt = conn.prepare("SELECT token_digest FROM email_verifications")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<Vec<Vec<u8>>, rusqlite::Error>>()?)
        })
        .unwrap();
    assert!(stored.contains(&link.digest().0.to_vec()));
    assert!(
        stored
            .iter()
            .all(|digest| digest.len() == 32 && digest != text.as_bytes()),
        "the secret itself is never stored"
    );
}

#[test]
fn the_first_account_to_verify_an_address_owns_it_and_a_claim_alone_blocks_nobody() {
    let f = fixture();
    let squatter = f.user_of(f.sign_up("victim@example.com", &f.admission(), None));
    // A claim does not stop the real owner from registering the address.
    let owner = f.user_of(f.sign_up("victim@example.com", &f.admission(), None));
    assert_ne!(squatter, owner);

    let owners_link = f.link(owner, None, 20);
    let squatters_link = f.link(squatter, None, 21);
    assert!(matches!(
        f.confirm(&owners_link, 22),
        Confirmation::Verified { .. }
    ));
    // The squatter's proof arrives second and gets nothing: the address is
    // verified elsewhere, and their claim was cleared by the owner's proof.
    assert_eq!(f.confirm(&squatters_link, 23), Confirmation::Refused);
    assert_eq!(f.address_of(squatter), None);
    assert_eq!(
        f.address_of(owner),
        Some(("victim@example.com".to_owned(), true))
    );

    // From now on registering that address is refused, with the refusal the
    // API answers exactly as it answers a new address.
    let again = f.sign_up("VICTIM@example.com", &f.admission(), None);
    assert!(matches!(
        again,
        Admission::Refused(Refusal::AlreadyRegistered)
    ));
    // And no operator link can verify it for a third account either.
    let third = f.user_of(f.sign_up("third@example.com", &f.admission(), None));
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            email::issue_link(
                tx,
                Authority::HostLocal,
                third,
                Some("victim@example.com"),
                at(30),
            )
        })
        .map(|_| ());
    assert!(matches!(refused, Err(Error::Conflict)));
}

#[test]
fn changing_an_address_keeps_the_old_one_until_the_new_one_is_proved() {
    let f = fixture();
    let user = f.user_of(f.sign_up("old@example.com", &f.admission(), None));
    let first = f.link(user, None, 20);
    assert!(matches!(
        f.confirm(&first, 21),
        Confirmation::Verified { .. }
    ));

    // Ask to move to a new address: nothing about the account changes yet.
    let proof = f.link(user, Some("new@example.com"), 30);
    assert_eq!(
        f.address_of(user),
        Some(("old@example.com".to_owned(), true))
    );
    assert!(f.sign_in("old@example.com"));
    assert!(!f.sign_in("new@example.com"), "trust does not transfer");

    assert!(matches!(
        f.confirm(&proof, 31),
        Confirmation::Verified { .. }
    ));
    assert_eq!(
        f.address_of(user),
        Some(("new@example.com".to_owned(), true))
    );
    assert!(f.sign_in("new@example.com"));
    assert!(
        !f.sign_in("old@example.com"),
        "the old address no longer identifies it"
    );
}

#[test]
fn resends_are_throttled_per_account_and_never_tell_an_address_apart() {
    let f = fixture();
    let user = f.user_of(f.sign_up("busy@example.com", &f.admission(), None));
    let resend = |now: i64| {
        f.store
            .writer()
            .write(move |tx| email::resend(tx, None, user, at(now)))
            .unwrap()
    };
    // Sign-up minted the first link; four more fit in the window.
    for second in 0..(email::RESENDS_PER_WINDOW - 1) {
        assert_eq!(resend(100 + second), Requested::Undelivered);
    }
    assert_eq!(resend(200), Requested::Throttled);
    // The window slides: an hour later the account may ask again.
    assert_eq!(
        resend(200 + email::RESEND_WINDOW_MS + 1),
        Requested::Undelivered
    );

    // The unauthenticated form: a pending address, a verified one and an
    // unknown one all succeed without error; the store never refuses on the
    // address, so the API can answer one way.
    for address in ["busy@example.com", "ghost@example.com", "Ghost@Example.COM"] {
        f.store
            .writer()
            .write(move |tx| email::resend_for_address(tx, None, address, at(10_000_000)))
            .unwrap();
    }
    // A malformed address is a validation error, not an oracle.
    let error = f
        .store
        .writer()
        .write(|tx| email::resend_for_address(tx, None, "not an address", at(1)))
        .map(|_| ());
    assert!(matches!(error, Err(Error::InvalidInput(_))));
}

#[test]
fn a_queued_message_is_sealed_delivered_once_and_its_body_deleted() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), at(1)).unwrap();
    let user = f.user_of(f.sign_up("queued@example.com", &f.admission(), Some(Arc::clone(&key))));

    let due = f.store.read(|c| email::due(c, at(10), 10)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].recipient, "queued@example.com");
    let message = due[0].open(&key).expect("the lane holds the key");
    assert!(
        message
            .body
            .contains("https://ci.example.com/verify-email#token=")
    );

    // The readable link is never in the database, only its sealed form.
    let stored: Vec<u8> = f
        .store
        .read(|conn| {
            conn.query_row("SELECT body FROM mail_outbox", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert!(!stored.windows(10).any(|w| w == b"verify-ema"));
    // A different key cannot open it.
    let other_dir = tempfile::tempdir().unwrap();
    let other_path = other_dir.path().join("master.key");
    Key::create(&other_path).unwrap();
    assert!(due[0].open(&Key::load(&other_path).unwrap()).is_none());

    // The link in the message verifies the account.
    let token = message
        .body
        .split("#token=")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let secret = Secret::parse(token).unwrap();
    assert!(matches!(
        f.confirm(&secret, 11),
        Confirmation::Verified { .. }
    ));
    let _ = user;

    let id = due[0].id;
    f.store
        .writer()
        .write(move |tx| email::delivered(tx, id, at(12)))
        .unwrap();
    assert!(
        f.store
            .read(|c| email::due(c, at(1_000_000), 10))
            .unwrap()
            .is_empty()
    );
    let body_left: Option<Vec<u8>> = f
        .store
        .read(|conn| {
            conn.query_row("SELECT body FROM mail_outbox", [], |r| r.get(0))
                .map_err(Error::from)
        })
        .unwrap();
    assert!(body_left.is_none(), "a delivered message keeps no link");
    // Settling twice is a conflict, not a second delivery record.
    let again = f
        .store
        .writer()
        .write(move |tx| email::delivered(tx, id, at(13)));
    assert!(matches!(again, Err(Error::Conflict)));
}

#[test]
fn without_delivery_or_a_key_nothing_is_queued() {
    let f = fixture();
    // Delivery on, but no key: the link is not queued readable.
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), at(1)).unwrap();
    f.user_of(f.sign_up("nokey@example.com", &f.admission(), None));
    assert!(
        f.store
            .read(|c| email::due(c, at(10), 10))
            .unwrap()
            .is_empty()
    );
    // A key, but delivery off.
    email::set_delivery(&f.store, false, Some("https://ci.example.com"), at(2)).unwrap();
    f.user_of(f.sign_up("off@example.com", &f.admission(), Some(f.key())));
    assert!(
        f.store
            .read(|c| email::due(c, at(10), 10))
            .unwrap()
            .is_empty()
    );
    assert!(!f.store.read(email::delivery_enabled).unwrap());
    // Enabling delivery needs a URL to build links on.
    assert!(email::set_delivery(&f.store, true, None, at(3)).is_err());
}

#[test]
fn failed_delivery_backs_off_and_gives_up_without_keeping_the_link() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), at(1)).unwrap();
    f.user_of(f.sign_up("flaky@example.com", &f.admission(), Some(Arc::clone(&key))));
    let id = f.store.read(|c| email::due(c, at(10), 10)).unwrap()[0].id;

    let mut now = 100;
    let mut last_wait = 0;
    for attempt in 1..email::MAX_ATTEMPTS {
        let outcome = f
            .store
            .writer()
            .write(move |tx| email::retry(tx, id, at(now), "service unreachable", 0))
            .unwrap();
        match outcome {
            email::Retry::Scheduled {
                attempts,
                next_attempt_ms,
            } => {
                assert_eq!(attempts, attempt);
                let wait = next_attempt_ms - now;
                assert!(wait >= last_wait, "backoff never shrinks");
                last_wait = wait;
                // Not due before its time, due at it.
                assert!(
                    f.store
                        .read(|c| email::due(c, at(now), 10))
                        .unwrap()
                        .is_empty()
                );
                now = next_attempt_ms;
                assert_eq!(
                    f.store.read(|c| email::due(c, at(now), 10)).unwrap().len(),
                    1
                );
            }
            email::Retry::GaveUp => break,
        }
    }
    let last = f
        .store
        .writer()
        .write(move |tx| email::retry(tx, id, at(now), "service unreachable", 0))
        .unwrap();
    assert_eq!(last, email::Retry::GaveUp);
    assert!(
        f.store
            .read(|c| email::due(c, at(i64::MAX / 2), 10))
            .unwrap()
            .is_empty()
    );
    assert!(f.events().contains(&Event::MailAbandoned));
    let (pending, delivered, abandoned) = f.store.read(email::counts).unwrap();
    assert_eq!((pending, delivered, abandoned), (0, 0, 1));
}

#[test]
fn a_retry_after_pushes_the_next_attempt_out_but_is_bounded() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), at(1)).unwrap();
    f.user_of(f.sign_up("slow@example.com", &f.admission(), Some(Arc::clone(&key))));
    let id = f.store.read(|c| email::due(c, at(10), 10)).unwrap()[0].id;
    let wait = |retry_after_ms: i64, now: i64| {
        match f
            .store
            .writer()
            .write(move |tx| email::retry(tx, id, at(now), "throttled", retry_after_ms))
            .unwrap()
        {
            email::Retry::Scheduled {
                next_attempt_ms, ..
            } => next_attempt_ms - now,
            email::Retry::GaveUp => panic!("gave up"),
        }
    };
    // Longer than the back-off: honored.
    assert_eq!(wait(120_000, 100), 120_000);
    // Shorter than the back-off: the back-off stands.
    assert!(wait(1, 200) >= email::backoff_ms(2));
    // An absurd request is capped.
    assert_eq!(wait(i64::MAX, 300), email::MAX_RETRY_AFTER_MS);
}

#[test]
fn a_mailbox_cannot_be_buried_in_messages() {
    let f = fixture();
    let key = f.key();
    email::set_delivery(&f.store, true, Some("https://ci.example.com"), at(1)).unwrap();
    // Many accounts, one victim address: the recipient ceiling holds.
    for n in 0..(email::RECIPIENT_PER_WINDOW + 3) {
        let invitation = f.admission();
        let admission = registration::register_with(
            &f.store,
            Applicant::Email {
                display_name: "Spam",
                email: "victim@example.com",
                password: PASSWORD,
            },
            Some(&invitation),
            Some(Arc::clone(&key)),
            at(10 + n),
        )
        .unwrap();
        assert!(matches!(admission, Admission::Admitted(_)));
    }
    let queued = f.store.read(email::counts).unwrap().0;
    assert_eq!(queued, email::RECIPIENT_PER_WINDOW);
}

#[test]
fn an_email_invitation_joins_only_when_its_mailbox_is_verified() {
    let f = fixture();
    let invited = f.email_invitation("Guest@Example.com");
    assert!(
        !invited.queued,
        "no delivery: the inviter passes the link on"
    );
    let secret = &invited.invitation.secret;

    // Someone proving a different mailbox cannot use it.
    assert!(matches!(
        f.sign_up("other@example.com", secret, None),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    // Neither can an applicant who proves no mailbox at all.
    let wrong_kind = registration::register(
        &f.store,
        Applicant::Local {
            display_name: "Local",
            username: "localguest",
            password: PASSWORD,
        },
        Some(secret),
        at(10),
    )
    .unwrap();
    assert!(matches!(
        wrong_kind,
        Admission::Refused(Refusal::InvitationUnusable)
    ));

    // The addressed person registers with the link and the mailbox...
    let user = match f.sign_up("guest@example.com", secret, None) {
        Admission::Pending(user) => user,
        other => panic!("an address-bound invitation admits only on proof: {other:?}"),
    };
    // ...but holds nothing, and is not even an active account, until the
    // mailbox is proved: a leaked link alone yields neither.
    assert_eq!(f.role_in(f.tenant, user), 0);
    assert!(!f.sign_in("guest@example.com"));
    let link = f.link(user, None, 20);
    match f.confirm(&link, 21) {
        Confirmation::Verified { joined, .. } => assert_eq!(joined, Some(f.tenant)),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.role_in(f.tenant, user), Role::Reader as i64);
    // The proof was the admission.
    assert!(f.sign_in("guest@example.com"));
    assert!(f.events().contains(&Event::RegistrationAdmitted));

    // One use: the link is spent, and a second person cannot take it.
    assert!(matches!(
        f.sign_up("guest@example.com", secret, None),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
    let events = f.events();
    assert!(events.contains(&Event::InvitationRedeemed));
    assert!(events.contains(&Event::InvitationCreated));
}

#[test]
fn an_existing_account_accepts_an_invitation_by_proving_the_mailbox() {
    let f = fixture();
    let user = f.user_of(f.sign_up("member@example.com", &f.admission(), None));
    let link = f.link(user, None, 20);
    assert!(matches!(
        f.confirm(&link, 21),
        Confirmation::Verified { .. }
    ));

    // Addressed to the verified address: joins at once.
    let own = f.email_invitation("member@example.com");
    let accepted =
        registration::accept_invitation(&f.store, user, &own.invitation.secret, None, at(30))
            .unwrap();
    assert_eq!(accepted, Accepted::Joined(f.tenant));
    assert_eq!(f.role_in(f.tenant, user), Role::Reader as i64);
    // Spent: the same link does nothing for anyone now.
    let again =
        registration::accept_invitation(&f.store, user, &own.invitation.secret, None, at(31))
            .unwrap();
    assert!(matches!(
        again,
        Accepted::AlreadyMember | Accepted::Unusable
    ));

    // A username account with no address: accepting claims the invited
    // address and sends a verification; the join waits for it.
    let other_invitation = f.admission();
    let old = f.user_of(
        match registration::register(
            &f.store,
            Applicant::Local {
                display_name: "Old",
                username: "oldhand",
                password: PASSWORD,
            },
            Some(&other_invitation),
            at(40),
        )
        .unwrap()
        {
            admitted @ Admission::Admitted(_) => admitted,
            other => panic!("{other:?}"),
        },
    );
    let addressed = f.email_invitation("oldhand@example.com");
    let outcome =
        registration::accept_invitation(&f.store, old, &addressed.invitation.secret, None, at(50))
            .unwrap();
    assert_eq!(outcome, Accepted::VerificationSent);
    assert_eq!(f.role_in(f.tenant, old), 0, "not a member before the proof");
    let proof = f.link(old, None, 51);
    match f.confirm(&proof, 52) {
        Confirmation::Verified { joined, .. } => assert_eq!(joined, Some(f.tenant)),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.role_in(f.tenant, old), Role::Reader as i64);
}

#[test]
fn an_account_with_another_verified_address_cannot_accept_an_invitation_to_a_third() {
    let f = fixture();
    let user = f.user_of(f.sign_up("mine@example.com", &f.admission(), None));
    let link = f.link(user, None, 20);
    f.confirm(&link, 21);
    let invited = f.email_invitation("elsewhere@example.com");
    let outcome =
        registration::accept_invitation(&f.store, user, &invited.invitation.secret, None, at(30))
            .unwrap();
    assert_eq!(outcome, Accepted::Unusable);
    assert_eq!(f.role_in(f.tenant, user), 0);
}

#[test]
fn a_link_form_invitation_still_joins_an_existing_account_at_once() {
    let f = fixture();
    let user = f.user_of(f.sign_up("plain@example.com", &f.admission(), None));
    let (admin, tenant) = (f.admin, f.tenant);
    let invitation = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::credential(admin),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Operator),
                    ..Terms::default()
                },
                at(5),
            )
        })
        .unwrap();
    let outcome =
        registration::accept_invitation(&f.store, user, &invitation.secret, None, at(6)).unwrap();
    assert_eq!(outcome, Accepted::Joined(f.tenant));
    assert_eq!(f.role_in(f.tenant, user), Role::Operator as i64);
    // Unknown, and a secret that is not an invitation at all, look alike.
    let nothing =
        registration::accept_invitation(&f.store, user, &Secret::generate(), None, at(7)).unwrap();
    assert_eq!(nothing, Accepted::Unusable);
}

#[test]
fn a_github_backed_organization_refuses_email_invitations() {
    let f = fixture();
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            let installation: InstallationId =
                registration::record_installation(tx, "github", "424242", "acme", at(4))?;
            registration::bind_installation_trusted(tx, installation, tenant, at(5))
        })
        .unwrap();
    assert!(
        f.store
            .read(|c| registration::tenant_is_github_backed(c, tenant))
            .unwrap()
    );
    let (admin, tenant) = (f.admin, f.tenant);
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(admin),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                "guest@example.com",
                None,
                at(6),
            )
        })
        .map(|_| ());
    assert!(
        matches!(refused, Err(Error::InvalidInput(_))),
        "{refused:?}"
    );
    // Nothing was written for it.
    let invitations: i64 = f
        .store
        .read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM invitations WHERE email IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(invitations, 0);
}

#[test]
fn an_email_invitation_requires_an_organization_a_valid_address_and_the_inviters_authority() {
    let f = fixture();
    let admin = f.admin;
    // No organization named.
    let orgless = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(admin),
                Terms::default(),
                "guest@example.com",
                None,
                at(3),
            )
        })
        .map(|_| ());
    assert!(matches!(orgless, Err(Error::InvalidInput(_))));
    // A malformed address.
    let (tenant, admin) = (f.tenant, f.admin);
    let malformed = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(admin),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                "guest at example.com",
                None,
                at(3),
            )
        })
        .map(|_| ());
    assert!(matches!(malformed, Err(Error::InvalidInput(_))));
    // An ordinary member cannot invite.
    let member = f.user_of(f.sign_up("plain@example.com", &f.admission(), None));
    let principal = Principal::new(member, P::REPOSITORY.union(P::TENANT_ADMIN), None, None);
    let tenant = f.tenant;
    let forbidden = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::credential(principal),
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                "guest@example.com",
                None,
                at(3),
            )
        })
        .map(|_| ());
    assert!(forbidden.is_err(), "an ordinary member cannot invite");
}

#[test]
fn a_revoked_email_invitation_joins_nobody() {
    let f = fixture();
    let invited = f.email_invitation("late@example.com");
    let (admin, id) = (f.admin, invited.invitation.id);
    f.store
        .writer()
        .write(move |tx| {
            registration::revoke_invitation(tx, Authority::credential(admin), id, at(4))
        })
        .unwrap();
    assert!(matches!(
        f.sign_up("late@example.com", &invited.invitation.secret, None),
        Admission::Refused(Refusal::InvitationUnusable)
    ));
}

#[test]
fn the_tenant_scoped_revoke_does_not_reach_another_tenants_invitation() {
    let f = fixture();
    let invited = f.email_invitation("scoped@example.com");
    let (admin, id) = (f.admin, invited.invitation.id);
    let other = TenantId::new();
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                admin,
                other,
                Namespace::parse("other").unwrap(),
                NamespaceKind::Organization,
                at(2),
            )
        })
        .unwrap();
    let result = f.store.writer().write(move |tx| {
        registration::revoke_tenant_invitation(tx, Authority::credential(admin), other, id, at(4))
    });
    assert!(matches!(result, Err(Error::NotFound)));
    let right = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            registration::revoke_tenant_invitation(
                tx,
                Authority::credential(admin),
                right,
                id,
                at(5),
            )
        })
        .unwrap();
}

#[test]
fn an_unknown_account_or_one_claiming_no_address_cannot_be_given_a_link() {
    let f = fixture();
    let ghost = UserId::new();
    let result = f
        .store
        .writer()
        .write(move |tx| {
            email::issue_link(
                tx,
                Authority::HostLocal,
                ghost,
                Some("a@example.com"),
                at(3),
            )
        })
        .map(|_| ());
    assert!(matches!(result, Err(Error::NotFound)));
    // An account that claims no address has nothing to prove unless one is named.
    let invitation = f.admission();
    let local = f.user_of(
        match registration::register(
            &f.store,
            Applicant::Local {
                display_name: "No Address",
                username: "noaddress",
                password: PASSWORD,
            },
            Some(&invitation),
            at(5),
        )
        .unwrap()
        {
            admitted @ Admission::Admitted(_) => admitted,
            other => panic!("{other:?}"),
        },
    );
    let nothing = f
        .store
        .writer()
        .write(move |tx| email::issue_link(tx, Authority::HostLocal, local, None, at(6)))
        .map(|_| ());
    assert!(matches!(nothing, Err(Error::NotFound)));
}

#[test]
fn the_operator_can_vouch_for_an_address_and_only_a_platform_authority_can() {
    let f = fixture();
    let user = f.user_of(f.sign_up("vouched@example.com", &f.admission(), None));
    // A non-platform credential cannot.
    let nobody = Principal::new(user, P::REPOSITORY, None, None);
    let denied = f
        .store
        .writer()
        .write(move |tx| email::verify_host_local(tx, Authority::credential(nobody), user, at(10)));
    assert!(denied.is_err());
    f.store
        .writer()
        .write(move |tx| email::verify_host_local(tx, Authority::HostLocal, user, at(11)))
        .unwrap();
    assert_eq!(
        f.address_of(user),
        Some(("vouched@example.com".to_owned(), true))
    );
    assert!(f.sign_in("vouched@example.com"));
}

#[test]
fn the_cli_names_an_account_by_its_address() {
    let f = fixture();
    let user = f.user_of(f.sign_up("named@example.com", &f.admission(), None));
    let found = f
        .store
        .read(|c| email::user_by_address(c, "Named@Example.com"))
        .unwrap();
    assert_eq!(found, Some(user));
    assert_eq!(
        f.store
            .read(|c| email::user_by_address(c, "nobody@example.com"))
            .unwrap(),
        None
    );
}
