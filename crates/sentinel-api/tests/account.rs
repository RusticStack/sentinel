#[path = "support/web_fixture.rs"]
mod fixture;

use fixture::{Fixture, PASSWORD, call};
use sentinel_auth::mfa::{Seed, check};
use serde_json::{Value, json};

fn session_with(f: &Fixture, username: &str, password: &str) -> Option<(String, String)> {
    let (status, headers, body) = call(
        &f.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": password })),
        &[],
    );
    if status != 200 {
        return None;
    }
    let cookie = headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .unwrap();
    Some((cookie, body["csrf"].as_str().unwrap().to_owned()))
}

fn session(f: &Fixture, username: &str) -> (String, String) {
    session_with(f, username, PASSWORD).expect("sign-in accepted")
}

fn send(
    f: &Fixture,
    method: &str,
    path: &str,
    body: Option<Value>,
    session: &(String, String),
) -> (u16, Vec<(String, String)>, Value) {
    call(
        &f.base,
        method,
        path,
        body.as_ref(),
        &[("cookie", &session.0), ("x-sentinel-csrf", &session.1)],
    )
}

fn post(f: &Fixture, path: &str, body: Value, s: &(String, String)) -> (u16, Value) {
    let (status, _, body) = send(f, "POST", path, Some(body), s);
    (status, body)
}

fn code_from(uri: &str) -> String {
    let start = uri.find("secret=").unwrap() + "secret=".len();
    let end = uri[start..].find('&').map_or(uri.len(), |e| start + e);
    let seed = Seed::from_base32(&uri[start..end]).unwrap();
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        // Only the current step: a previous-step code could lapse while a slow host searches.
        .find(|code| check(&seed, code, seconds) == Some(seconds / 30))
        .expect("some code matches")
}

fn enroll(f: &Fixture, s: &(String, String)) -> (String, Vec<String>) {
    let (status, body) = post(f, "/api/v1/mfa/enroll", json!({ "password": PASSWORD }), s);
    assert_eq!(status, 200, "{body}");
    let uri = body["provisioning_uri"].as_str().unwrap().to_owned();
    let (status, body) = post(
        f,
        "/api/v1/mfa/enroll/confirm",
        json!({ "code": code_from(&uri) }),
        s,
    );
    assert_eq!(status, 200, "{body}");
    let codes = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    (uri, codes)
}

fn security(f: &Fixture, s: &(String, String)) -> Value {
    let (status, _, body) = send(f, "GET", "/api/v1/me/security", None, s);
    assert_eq!(status, 200, "{body}");
    body
}

#[test]
fn enrollment_needs_a_browser_session_with_csrf_and_the_password() {
    let f = Fixture::new(1);
    let root = session(&f, "root");

    let (status, _, body) = call(
        &f.base,
        "POST",
        "/api/v1/mfa/enroll",
        Some(&json!({ "password": PASSWORD })),
        &[("authorization", &f.auth)],
    );
    assert_eq!(status, 400, "{body}");
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/mfa/enroll",
        Some(&json!({ "password": PASSWORD })),
        &[("cookie", &root.0)],
    );
    assert_eq!(status, 403);

    let (status, _) = post(&f, "/api/v1/mfa/enroll", json!({}), &root);
    assert_eq!(status, 400);
    let (status, body) = post(
        &f,
        "/api/v1/mfa/enroll",
        json!({ "password": "not the password" }),
        &root,
    );
    assert_eq!(
        (status, body["message"].as_str()),
        (403, Some("enrollment refused"))
    );
    assert_eq!(security(&f, &root)["mfa"]["pending"], false);

    let (status, body) = post(
        &f,
        "/api/v1/mfa/enroll",
        json!({ "password": PASSWORD }),
        &root,
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        body["provisioning_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Sentinel:root?"),
        "{body}"
    );
    let state = security(&f, &root);
    assert_eq!(
        (
            state["password"].as_bool(),
            state["mfa"]["enrolled"].as_bool(),
            state["mfa"]["pending"].as_bool()
        ),
        (Some(true), Some(false), Some(true))
    );
    assert!(!state.to_string().contains("secret="));
}

#[test]
fn a_wrong_code_confirms_nothing_and_a_confirmed_code_cannot_step_up_again() {
    let f = Fixture::new(1);
    let root = session(&f, "root");

    let (status, _) = post(
        &f,
        "/api/v1/mfa/enroll/confirm",
        json!({ "code": "123456" }),
        &root,
    );
    assert_eq!(status, 404);

    let (_, body) = {
        let (s, b) = post(
            &f,
            "/api/v1/mfa/enroll",
            json!({ "password": PASSWORD }),
            &root,
        );
        (s, b)
    };
    let uri = body["provisioning_uri"].as_str().unwrap().to_owned();
    let right = code_from(&uri);
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    for bad in [wrong, "", "12345", "not a code"] {
        let (status, _) = post(
            &f,
            "/api/v1/mfa/enroll/confirm",
            json!({ "code": bad }),
            &root,
        );
        assert!(matches!(status, 400 | 403), "{bad}: {status}");
    }
    assert_eq!(security(&f, &root)["mfa"]["enrolled"], false);

    let (status, body) = post(
        &f,
        "/api/v1/mfa/enroll/confirm",
        json!({ "code": right }),
        &root,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stepped_up"], true);
    let codes = body["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    let state = security(&f, &root);
    assert_eq!(
        (
            state["mfa"]["enrolled"].as_bool(),
            state["mfa"]["pending"].as_bool(),
            state["mfa"]["recovery_codes_remaining"].as_u64()
        ),
        (Some(true), Some(false), Some(10))
    );
    let (_, _, me) = send(&f, "GET", "/api/v1/me", None, &root);
    assert_eq!(
        (me["stepped_up"].as_bool(), me["mfa"].as_bool()),
        (Some(true), Some(true))
    );

    let other = session(&f, "root");
    let (status, _) = post(
        &f,
        "/api/v1/step-up",
        json!({ "method": "totp", "code": right }),
        &other,
    );
    assert_eq!(status, 403);
    let (status, _) = post(
        &f,
        "/api/v1/mfa/enroll",
        json!({ "password": PASSWORD }),
        &root,
    );
    assert_eq!(status, 409);
}

#[test]
fn recovery_codes_are_reissued_only_after_a_step_up_and_the_old_set_dies() {
    let f = Fixture::new(1);
    let first = session(&f, "root");
    let (_, codes) = enroll(&f, &first);

    let other = session(&f, "root");
    let (status, body) = post(&f, "/api/v1/mfa/recovery-codes", json!({}), &other);
    assert_eq!(
        (status, body["details"]["step_up"].as_bool()),
        (403, Some(true)),
        "{body}"
    );
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/mfa/recovery-codes",
        Some(&json!({})),
        &[("authorization", &f.auth)],
    );
    assert_eq!(status, 400);

    let (status, body) = post(
        &f,
        "/api/v1/step-up",
        json!({ "method": "recovery", "code": codes[0] }),
        &other,
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = post(&f, "/api/v1/mfa/recovery-codes", json!({}), &other);
    assert_eq!(status, 200, "{body}");
    let fresh: Vec<&str> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(fresh.len(), 10);
    assert_eq!(security(&f, &other)["mfa"]["recovery_codes_remaining"], 10);

    let third = session(&f, "root");
    let (status, _) = post(
        &f,
        "/api/v1/step-up",
        json!({ "method": "recovery", "code": codes[1] }),
        &third,
    );
    assert_eq!(status, 403);
    let (status, _) = post(
        &f,
        "/api/v1/step-up",
        json!({ "method": "recovery", "code": fresh[0] }),
        &third,
    );
    assert_eq!(status, 200);
}

#[test]
fn a_password_change_needs_the_current_password_and_ends_every_session() {
    let f = Fixture::new(1);
    let (one, two) = (session(&f, "root"), session(&f, "root"));
    let new_password = "a different long passphrase";

    let (status, body) = post(
        &f,
        "/api/v1/password",
        json!({ "current": "not it", "new": new_password }),
        &one,
    );
    assert_eq!(
        (status, body["message"].as_str()),
        (403, Some("password change refused"))
    );
    assert!(session_with(&f, "root", PASSWORD).is_some());
    let (status, _) = post(
        &f,
        "/api/v1/password",
        json!({ "current": PASSWORD, "new": "short" }),
        &one,
    );
    assert_eq!(status, 400);
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/password",
        Some(&json!({ "current": PASSWORD, "new": new_password })),
        &[("authorization", &f.auth)],
    );
    assert_eq!(status, 400);

    let (status, headers, body) = send(
        &f,
        "POST",
        "/api/v1/password",
        Some(json!({ "current": PASSWORD, "new": new_password })),
        &one,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["signed_out"], true);
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "set-cookie" && v.contains("Max-Age=0")),
        "{headers:?}"
    );
    for s in [&one, &two] {
        let (status, _, _) = send(&f, "GET", "/api/v1/me", None, s);
        assert_eq!(status, 401);
    }
    assert!(session_with(&f, "root", PASSWORD).is_none());
    assert!(session_with(&f, "root", new_password).is_some());
}

#[test]
fn five_wrong_current_passwords_revoke_the_session() {
    let f = Fixture::new(1);
    let s = session(&f, "root");
    for _ in 0..5 {
        let (status, _) = post(
            &f,
            "/api/v1/password",
            json!({ "current": "not it", "new": "another long passphrase" }),
            &s,
        );
        assert_eq!(status, 403);
    }
    let (status, _, _) = send(&f, "GET", "/api/v1/me", None, &s);
    assert_eq!(status, 401);
    assert!(session_with(&f, "root", PASSWORD).is_some());
}

#[test]
fn five_wrong_confirmation_codes_revoke_the_session_and_the_enrollment_survives() {
    let f = Fixture::new(1);
    let s = session(&f, "root");
    let (_, body) = post(
        &f,
        "/api/v1/mfa/enroll",
        json!({ "password": PASSWORD }),
        &s,
    );
    let uri = body["provisioning_uri"].as_str().unwrap().to_owned();
    let right = code_from(&uri);
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    for _ in 0..5 {
        let (status, _) = post(
            &f,
            "/api/v1/mfa/enroll/confirm",
            json!({ "code": wrong }),
            &s,
        );
        assert_eq!(status, 403);
    }
    let (status, _, _) = send(&f, "GET", "/api/v1/me", None, &s);
    assert_eq!(status, 401);

    let again = session(&f, "root");
    let state = security(&f, &again);
    assert_eq!(state["mfa"]["pending"], true);
    let (status, body) = post(
        &f,
        "/api/v1/mfa/enroll/confirm",
        json!({ "code": right }),
        &again,
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn with_a_second_factor_a_password_change_asks_for_the_step_up_first() {
    let f = Fixture::new(1);
    let first = session(&f, "root");
    let (_, codes) = enroll(&f, &first);

    let cold = session(&f, "root");
    for current in [PASSWORD, "not it"] {
        let (status, body) = post(
            &f,
            "/api/v1/password",
            json!({ "current": current, "new": "yet another long passphrase" }),
            &cold,
        );
        assert_eq!(
            (status, body["details"]["step_up"].as_bool()),
            (403, Some(true)),
            "{body}"
        );
    }
    assert!(session_with(&f, "root", PASSWORD).is_some());

    let (status, _) = post(
        &f,
        "/api/v1/step-up",
        json!({ "method": "recovery", "code": codes[0] }),
        &cold,
    );
    assert_eq!(status, 200);
    let (status, body) = post(
        &f,
        "/api/v1/password",
        json!({ "current": PASSWORD, "new": "yet another long passphrase" }),
        &cold,
    );
    assert_eq!(status, 200, "{body}");
}
