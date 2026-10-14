//! Sign-up by email, verification and email invitations over real HTTP:
//! the answers that must not tell an address apart, the proofs each route
//! needs, and an organization administrator inviting a person by email.

#[path = "support/web_fixture.rs"]
mod fixture;

use fixture::{Fixture, PASSWORD, call};
use sentinel_auth::{secret::Secret, token};
use sentinel_core::{UnixMillis, UserId};
use sentinel_store::{
    email::{self, Confirmation},
    registration::{self, Authority, DeploymentPolicy, Registration, Terms},
};
use serde_json::{Value, json};

fn session(f: &Fixture, username: &str) -> (String, String) {
    let (status, headers, body) = call(
        &f.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let cookie = headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .unwrap();
    (cookie, body["csrf"].as_str().unwrap().to_owned())
}

fn send(
    f: &Fixture,
    method: &str,
    path: &str,
    body: Option<Value>,
    s: &(String, String),
) -> (u16, Value) {
    let (status, _, body) = call(
        &f.base,
        method,
        path,
        body.as_ref(),
        &[("cookie", &s.0), ("x-sentinel-csrf", &s.1)],
    );
    (status, body)
}

fn as_root(f: &Fixture, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let (status, _, body) = call(
        &f.base,
        method,
        path,
        body.as_ref(),
        &[("authorization", &f.auth)],
    );
    (status, body)
}

fn public(f: &Fixture, path: &str, body: Value) -> (u16, Value) {
    let (status, _, body) = call(&f.base, "POST", path, Some(&body), &[]);
    (status, body)
}

/// The operator's way to a link, as `sentinel admin account email-link`.
fn operator_link(f: &Fixture, user: UserId, address: Option<&'static str>) -> String {
    let issued = f
        .store
        .writer()
        .write(move |tx| {
            email::issue_link(tx, Authority::HostLocal, user, address, UnixMillis::now())
        })
        .unwrap();
    let mut text = String::new();
    issued.secret.expose(&mut text);
    text
}

fn verify_address(f: &Fixture, user: UserId, address: &'static str) {
    let issued = f
        .store
        .writer()
        .write(move |tx| {
            email::issue_link(
                tx,
                Authority::HostLocal,
                user,
                Some(address),
                UnixMillis::now(),
            )
        })
        .unwrap();
    assert!(matches!(
        email::confirm(&f.store, &issued.secret, UnixMillis::now()).unwrap(),
        Confirmation::Verified { .. }
    ));
}

fn set_registration(f: &Fixture, registration: Registration) {
    f.store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration,
                    ..registration::policy(tx)?
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

fn accounts_claiming(f: &Fixture, address: &str) -> i64 {
    let address = address.to_owned();
    f.store
        .read(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM users WHERE email = ?1",
                [&address],
                |r| r.get(0),
            )
            .map_err(sentinel_store::Error::from)
        })
        .unwrap()
}

#[test]
fn registering_a_registered_address_is_answered_like_a_new_one() {
    let f = Fixture::new(1);
    verify_address(&f, f.dana, "dana@example.com");
    // The fixture admits by approval: an application waits as pending.
    let (new_status, new_body) = public(
        &f,
        "/api/v1/register",
        json!({ "email": "newcomer@example.com", "password": PASSWORD }),
    );
    let (known_status, known_body) = public(
        &f,
        "/api/v1/register",
        json!({ "email": "Dana@Example.COM", "password": PASSWORD }),
    );
    assert_eq!(new_status, 202, "{new_body}");
    assert_eq!((known_status, &known_body), (new_status, &new_body));
    // Nothing leaked and nothing was taken from the verified owner.
    assert_eq!(accounts_claiming(&f, "dana@example.com"), 1);
    assert_eq!(accounts_claiming(&f, "newcomer@example.com"), 1);
    // A pending account holds nothing and cannot sign in, verified or not.
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": "newcomer@example.com", "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 401);
}

#[test]
fn registration_policy_refusals_do_not_depend_on_the_address() {
    let f = Fixture::new(1);
    verify_address(&f, f.dana, "dana@example.com");
    for (policy, message) in [
        (Registration::Closed, "registration is closed"),
        (Registration::InviteOnly, "registration needs an invitation"),
    ] {
        set_registration(&f, policy);
        for address in ["dana@example.com", "stranger@example.com"] {
            let (status, body) = public(
                &f,
                "/api/v1/register",
                json!({ "email": address, "password": PASSWORD }),
            );
            assert_eq!(status, 403, "{body}");
            assert_eq!(body["message"], message);
        }
    }
    // A malformed address is a plain validation error, not an oracle.
    set_registration(&f, Registration::ApprovalRequired);
    let (status, _) = public(
        &f,
        "/api/v1/register",
        json!({ "email": "not an address", "password": PASSWORD }),
    );
    assert_eq!(status, 400);
}

#[test]
fn only_a_verified_address_signs_in() {
    let f = Fixture::new(1);
    verify_address(&f, f.dana, "dana@example.com");
    let login = |name: &str, password: &str| {
        call(
            &f.base,
            "POST",
            "/api/v1/login",
            Some(&json!({ "username": name, "password": password })),
            &[],
        )
        .0
    };
    assert_eq!(login("Dana@Example.com", PASSWORD), 200);
    assert_eq!(login("dana", PASSWORD), 200, "the username keeps working");
    assert_eq!(login("dana@example.com", "wrong password"), 401);
    assert_eq!(login("nobody@example.com", PASSWORD), 401);

    // Rui claims an address and has not proved it: a claim is not a login.
    let rui = session(&f, "rui");
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "rui@example.com" })),
        &rui,
    );
    assert_eq!(status, 202, "{body}");
    assert_eq!(login("rui@example.com", PASSWORD), 401);
    let (_, me) = send(&f, "GET", "/api/v1/me", None, &rui);
    assert_eq!(me["email"], "rui@example.com");
    assert_eq!(me["email_verified"], false);
}

#[test]
fn a_verification_link_works_once_and_a_bad_one_is_one_answer() {
    let f = Fixture::new(1);
    let rui = session(&f, "rui");
    send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "rui@example.com" })),
        &rui,
    );
    let link = operator_link(&f, f.rui, None);

    let (status, body) = public(&f, "/api/v1/email/verify", json!({ "token": link }));
    assert_eq!((status, &body["verified"]), (200, &json!(true)), "{body}");
    let (_, me) = send(&f, "GET", "/api/v1/me", None, &rui);
    assert_eq!(me["email_verified"], true);

    let replay = public(&f, "/api/v1/email/verify", json!({ "token": link }));
    let mut never_issued = String::new();
    Secret::generate().expose(&mut never_issued);
    let unknown = public(&f, "/api/v1/email/verify", json!({ "token": never_issued }));
    let malformed = public(&f, "/api/v1/email/verify", json!({ "token": "nope" }));
    assert_eq!(replay.0, 400);
    assert_eq!(replay, unknown);
    assert_eq!(replay, malformed);
}

#[test]
fn the_public_mail_routes_refuse_a_foreign_origin() {
    let f = Fixture::new(1);
    for (path, body) in [
        (
            "/api/v1/register",
            json!({ "email": "x@example.com", "password": PASSWORD }),
        ),
        ("/api/v1/email/resend", json!({ "email": "x@example.com" })),
        ("/api/v1/email/verify", json!({ "token": "abc" })),
    ] {
        let (status, _, _) = call(
            &f.base,
            "POST",
            path,
            Some(&body),
            &[("origin", "https://evil.example")],
        );
        assert_eq!(status, 403, "{path}");
    }
    assert_eq!(accounts_claiming(&f, "x@example.com"), 0);
}

#[test]
fn resend_answers_the_same_for_a_pending_and_an_unknown_address() {
    let f = Fixture::new(1);
    let rui = session(&f, "rui");
    send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "rui@example.com" })),
        &rui,
    );
    let pending = public(
        &f,
        "/api/v1/email/resend",
        json!({ "email": "rui@example.com" }),
    );
    let unknown = public(
        &f,
        "/api/v1/email/resend",
        json!({ "email": "ghost@example.com" }),
    );
    assert_eq!(pending.0, 202);
    assert_eq!(pending, unknown);
}

#[test]
fn an_account_cannot_quietly_take_an_address_another_account_verified() {
    let f = Fixture::new(1);
    verify_address(&f, f.dana, "dana@example.com");
    let rui = session(&f, "rui");

    // Browser sessions only, with their CSRF header.
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/me/email",
        Some(&json!({ "email": "rui@example.com" })),
        &[("authorization", &f.auth)],
    );
    assert_eq!(status, 400);
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/me/email",
        Some(&json!({ "email": "rui@example.com" })),
        &[("cookie", &rui.0)],
    );
    assert_eq!(status, 403);

    // Asking for Dana's address is answered like any other, and changes nothing.
    let (own, own_body) = send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "rui@example.com" })),
        &rui,
    );
    let (taken, taken_body) = send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "dana@example.com" })),
        &rui,
    );
    assert_eq!((own, &own_body), (taken, &taken_body));
    let (_, me) = send(&f, "GET", "/api/v1/me", None, &rui);
    assert_eq!(me["email"], "rui@example.com");
    assert_eq!(accounts_claiming(&f, "dana@example.com"), 1);

    // The account's resend allowance is its own: it runs out and is told so.
    let mut throttled = false;
    for _ in 0..(email::RESENDS_PER_WINDOW + 2) {
        let (status, _) = send(&f, "POST", "/api/v1/me/email/resend", None, &rui);
        if status == 429 {
            throttled = true;
            break;
        }
        assert_eq!(status, 202);
    }
    assert!(throttled, "the per-account resend allowance is enforced");
}

#[test]
fn changing_a_verified_address_leaves_the_old_one_in_force_until_the_new_one_is_proved() {
    let f = Fixture::new(1);
    verify_address(&f, f.dana, "dana@example.com");
    let dana = session(&f, "dana");
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/me/email",
        Some(json!({ "email": "dana.new@example.com" })),
        &dana,
    );
    assert_eq!(status, 202, "{body}");
    // Nothing changed: the old address is still the verified identity.
    let (_, me) = send(&f, "GET", "/api/v1/me", None, &dana);
    assert_eq!(
        (me["email"].as_str(), me["email_verified"].as_bool()),
        (Some("dana@example.com"), Some(true))
    );
    let login = |name: &str| {
        call(
            &f.base,
            "POST",
            "/api/v1/login",
            Some(&json!({ "username": name, "password": PASSWORD })),
            &[],
        )
        .0
    };
    assert_eq!(login("dana@example.com"), 200);
    assert_eq!(
        login("dana.new@example.com"),
        401,
        "trust does not transfer"
    );

    // Proving the new address moves the identity to it.
    let link = operator_link(&f, f.dana, None);
    let (status, _) = public(&f, "/api/v1/email/verify", json!({ "token": link }));
    assert_eq!(status, 200);
    assert_eq!(login("dana.new@example.com"), 200);
    assert_eq!(login("dana@example.com"), 401);
}

#[test]
fn an_organization_administrator_invites_by_email_and_a_member_cannot() {
    let f = Fixture::new(1);
    let (status, body) = as_root(
        &f,
        "POST",
        "/api/v1/tenants/acme/invitations",
        Some(json!({ "email": "Guest@Example.com", "role": "operator", "expires_in_secs": 3600 })),
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["delivery"], "link",
        "no SMTP: the inviter passes the link on"
    );
    assert_eq!(body["role"], "operator");
    assert!(token::parse(body["token"].as_str().unwrap()).is_some());
    let id = body["id"].as_str().unwrap().to_owned();

    let (status, listing) = as_root(&f, "GET", "/api/v1/tenants/acme/invitations", None);
    assert_eq!(status, 200);
    let row = &listing["invitations"][0];
    assert_eq!(
        (row["email"].as_str(), row["state"].as_str()),
        (Some("guest@example.com"), Some("pending"))
    );
    // The listing never carries the secret.
    assert!(!listing.to_string().contains("sntl_"));

    // An operator (not an administrator) is refused; so are bad inputs.
    let dana = session(&f, "dana");
    let (status, _) = send(
        &f,
        "POST",
        "/api/v1/tenants/acme/invitations",
        Some(json!({ "email": "x@example.com" })),
        &dana,
    );
    assert!(status == 403 || status == 404, "{status}");
    for bad in [
        json!({ "email": "not an address" }),
        json!({ "email": "ok@example.com", "role": "owner" }),
        json!({ "email": "ok@example.com", "expires_in_secs": 0 }),
        json!({ "email": "ok@example.com", "expires_in_secs": 99999999 }),
    ] {
        let (status, _) = as_root(&f, "POST", "/api/v1/tenants/acme/invitations", Some(bad));
        assert_eq!(status, 400);
    }

    // Revocation is the tenant's own: another tenant's path cannot reach it.
    let (status, _) = as_root(
        &f,
        "DELETE",
        &format!("/api/v1/tenants/beta/invitations/{id}"),
        None,
    );
    assert_eq!(status, 404);
    let (status, _) = as_root(
        &f,
        "DELETE",
        &format!("/api/v1/tenants/acme/invitations/{id}"),
        None,
    );
    assert_eq!(status, 200);
    let (_, listing) = as_root(&f, "GET", "/api/v1/tenants/acme/invitations", None);
    assert_eq!(listing["invitations"][0]["state"], "revoked");
}

#[test]
fn a_github_backed_organization_cannot_be_invited_into_by_email() {
    let f = Fixture::new(1);
    let beta = f.beta;
    f.store
        .writer()
        .write(move |tx| {
            let installation = registration::record_installation(
                tx,
                "github",
                "8675309",
                "beta-org",
                UnixMillis::now(),
            )?;
            registration::bind_installation_trusted(tx, installation, beta, UnixMillis::now())
        })
        .unwrap();
    let (status, body) = as_root(
        &f,
        "POST",
        "/api/v1/tenants/beta/invitations",
        Some(json!({ "email": "guest@example.com" })),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["message"].as_str().unwrap().contains("GitHub"));
    // The app-created organization beside it is unaffected.
    let (status, _) = as_root(
        &f,
        "POST",
        "/api/v1/tenants/acme/invitations",
        Some(json!({ "email": "guest@example.com" })),
    );
    assert_eq!(status, 201);
}

#[test]
fn a_signed_in_account_accepts_an_invitation_and_an_addressed_one_waits_for_the_mailbox() {
    let f = Fixture::new(1);
    let rui = session(&f, "rui");
    let joined = |f: &Fixture| -> Vec<String> {
        let (_, body) = send(f, "GET", "/api/v1/tenants", None, &rui);
        body["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["slug"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(joined(&f), vec!["acme".to_owned()]);

    // A link-form invitation joins at once.
    let beta = f.beta;
    let plain = f
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms {
                    tenant: Some(beta),
                    role: Some(sentinel_core::auth::Role::Reader),
                    ..Terms::default()
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/invitations/accept",
        Some(json!({ "token": token::format(&plain.secret) })),
        &rui,
    );
    assert_eq!(
        (status, body["status"].as_str(), body["tenant"].as_str()),
        (200, Some("joined"), Some("beta")),
        "{body}"
    );
    assert!(joined(&f).contains(&"beta".to_owned()));
    // Spent, unknown and malformed secrets are one `not_found`.
    for secret in [
        token::format(&plain.secret),
        token::format(&Secret::generate()),
        "nonsense".to_owned(),
    ] {
        let (status, _) = send(
            &f,
            "POST",
            "/api/v1/invitations/accept",
            Some(json!({ "token": secret })),
            &rui,
        );
        assert_eq!(status, 404);
    }
}

#[test]
fn an_email_invitation_joins_when_its_mailbox_is_proved() {
    let f = Fixture::new(1);
    // Beta's administrator invites Rui's address; Rui is not in beta yet.
    let (status, body) = as_root(
        &f,
        "POST",
        "/api/v1/tenants/beta/invitations",
        Some(json!({ "email": "rui@example.com" })),
    );
    assert_eq!(status, 201, "{body}");
    let secret = body["token"].as_str().unwrap().to_owned();

    let rui = session(&f, "rui");
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/invitations/accept",
        Some(json!({ "token": secret })),
        &rui,
    );
    assert_eq!(
        (status, body["status"].as_str()),
        (202, Some("verification_sent")),
        "{body}"
    );
    let (_, tenants) = send(&f, "GET", "/api/v1/tenants", None, &rui);
    assert!(
        !tenants.to_string().contains("beta"),
        "nothing is granted before the mailbox is proved"
    );

    // Opening the link in the mail proves the mailbox and joins.
    let link = operator_link(&f, f.rui, None);
    let (status, body) = public(&f, "/api/v1/email/verify", json!({ "token": link }));
    assert_eq!((status, &body["joined"]), (200, &json!(true)), "{body}");
    let (_, tenants) = send(&f, "GET", "/api/v1/tenants", None, &rui);
    assert!(tenants.to_string().contains("beta"));
}

#[test]
fn sign_up_with_an_email_invitation_for_another_address_is_refused() {
    let f = Fixture::new(1);
    let (_, body) = as_root(
        &f,
        "POST",
        "/api/v1/tenants/acme/invitations",
        Some(json!({ "email": "guest@example.com" })),
    );
    let secret = body["token"].as_str().unwrap().to_owned();
    set_registration(&f, Registration::InviteOnly);
    let (status, body) = public(
        &f,
        "/api/v1/register",
        json!({ "email": "intruder@example.com", "password": PASSWORD, "invitation": secret }),
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(accounts_claiming(&f, "intruder@example.com"), 0);
    // The addressed person registers with it.
    let (status, body) = public(
        &f,
        "/api/v1/register",
        json!({ "email": "guest@example.com", "password": PASSWORD, "invitation": secret }),
    );
    assert_eq!(status, 202, "{body}");
    assert_eq!(accounts_claiming(&f, "guest@example.com"), 1);
}
