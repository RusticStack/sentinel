//! The whole A04 path in one place: a browser is sent to GitHub, comes back
//! with a code and a state, the code is exchanged for a verified account ID,
//! and that ID decides whether a Sentinel session exists.
//!
//! `sentinel-github` cannot depend on `sentinel-store` (it is the provider
//! adapter, not the identity store), so this test lives here and drives both
//! crates the way the eventual W08 route will.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
};

use sentinel_auth::{cookie, secret::Secret};
use sentinel_core::UnixMillis;
use sentinel_github::{
    PROVIDER,
    http::Client,
    oauth::{self, App},
};
use sentinel_store::{
    Durability, Store,
    local_auth::{self, Policy},
    sign_in::{self, Outcome},
};

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

/// A GitHub-shaped server answering the token and user endpoints once each.
fn stub_github(account_id: u64) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for body in [
            r#"{"access_token":"gho_user_token","token_type":"bearer","scope":""}"#.to_owned(),
            format!(r#"{{"id":{account_id},"login":"octocat","name":"The Octocat"}}"#),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            reader.read_exact(&mut vec![0u8; length]).unwrap();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    port
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    app: App,
    endpoints: oauth::Endpoints,
    http: Client,
}

fn fixture(account_id: u64) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let port = stub_github(account_id);
    Fixture {
        _dir: dir,
        store,
        app: App::new(
            "Iv1.0123456789abcdef",
            "shhh-client-secret".into(),
            "https://ci.example/auth/github/callback",
        )
        .unwrap(),
        endpoints: oauth::Endpoints::loopback(port),
        http: Client::new(),
    }
}

/// Everything a callback handler does, in order.
fn callback(
    f: &Fixture,
    query: &str,
    cookie_header: &str,
    now: UnixMillis,
) -> Result<Outcome, String> {
    let callback = oauth::callback(query).map_err(|e| e.to_string())?;
    // The browser's half of the state, and the parameter, must agree.
    let presented = cookie::read(cookie::SIGN_IN_COOKIE, cookie_header)
        .ok_or_else(|| "no sign-in cookie".to_owned())?;
    let mut expected = String::new();
    presented.expose(&mut expected);
    if expected != callback.state {
        return Err("state mismatch".into());
    }
    sign_in::consume(&f.store, PROVIDER, &presented, now).map_err(|e| e.to_string())?;
    let token = f
        .app
        .exchange(&f.http, &f.endpoints, &callback.code)
        .map_err(|e| e.to_string())?;
    let identity =
        oauth::verified_identity(&f.http, &f.endpoints, &token).map_err(|e| e.to_string())?;
    sign_in::complete(
        &f.store,
        PROVIDER,
        &identity.subject,
        Policy::default(),
        now,
    )
    .map_err(|e| e.to_string())
}

#[test]
fn a_linked_github_account_signs_in_end_to_end() {
    let f = fixture(4242);
    // An operator admitted locally links their GitHub account while signed in.
    let user =
        local_auth::bootstrap(&f.store, "root", "Root", b"an operator password", at(0)).unwrap();
    let issued = f
        .store
        .writer()
        .write(move |tx| local_auth::issue_session(tx, user, Policy::default(), at(1)))
        .unwrap();
    let session = f
        .store
        .read(|conn| local_auth::authenticate(conn, &issued.session, at(2)))
        .unwrap();
    let session = local_auth::Session {
        stepped_up: Some(at(2)),
        ..session
    };
    sign_in::link(
        &f.store,
        &session,
        Policy::default(),
        PROVIDER,
        "4242",
        at(3),
    )
    .unwrap();

    // Sign-in begins: state is minted, stored as a digest and set as a cookie.
    let state = sign_in::begin(&f.store, PROVIDER, Some("/runs"), at(10), 60_000).unwrap();
    let mut state_text = String::new();
    state.expose(&mut state_text);
    let set_cookie = cookie::issue(cookie::SIGN_IN_COOKIE, &state, 600);
    assert!(set_cookie.contains("SameSite=Strict") && set_cookie.contains("HttpOnly"));
    let url = f.app.authorize_url(&f.endpoints, &state_text);
    assert!(url.contains(&format!("state={state_text}")));

    let cookie_header = format!("{}={state_text}", cookie::SIGN_IN_COOKIE);
    let outcome = callback(
        &f,
        &format!("code=the-code&state={state_text}"),
        &cookie_header,
        at(20),
    )
    .unwrap();
    let session = match outcome {
        Outcome::SignedIn(issued) => issued,
        Outcome::NoAccount => panic!("the linked account should have signed in"),
    };
    assert_eq!(session.user, user);
    assert_eq!(
        f.store
            .read(|conn| local_auth::authenticate(conn, &session.session, at(21)))
            .unwrap()
            .user,
        user
    );
}

#[test]
fn a_callback_without_the_browsers_own_state_is_refused() {
    let f = fixture(4242);
    let state = sign_in::begin(&f.store, PROVIDER, None, at(10), 60_000).unwrap();
    let mut state_text = String::new();
    state.expose(&mut state_text);

    // A stolen or guessed `state` parameter with no matching cookie: the
    // attacker's callback never reaches the exchange.
    let failure = callback(
        &f,
        &format!("code=the-code&state={state_text}"),
        "other=1",
        at(20),
    )
    .unwrap_err();
    assert_eq!(failure, "no sign-in cookie");

    // A cookie that disagrees with the parameter is equally useless.
    let other = Secret::generate();
    let mut other_text = String::new();
    other.expose(&mut other_text);
    let failure = callback(
        &f,
        &format!("code=the-code&state={state_text}"),
        &format!("{}={other_text}", cookie::SIGN_IN_COOKIE),
        at(20),
    )
    .unwrap_err();
    assert_eq!(failure, "state mismatch");

    // The attempt is still pending: nothing was spent by the failed attempts.
    assert!(sign_in::consume(&f.store, PROVIDER, &state, at(30)).is_ok());
}

#[test]
fn an_unlinked_github_account_is_verified_but_admitted_to_nothing() {
    let f = fixture(9999);
    local_auth::bootstrap(&f.store, "root", "Root", b"an operator password", at(0)).unwrap();
    let state = sign_in::begin(&f.store, PROVIDER, None, at(10), 60_000).unwrap();
    let mut state_text = String::new();
    state.expose(&mut state_text);

    let outcome = callback(
        &f,
        &format!("code=the-code&state={state_text}"),
        &format!("{}={state_text}", cookie::SIGN_IN_COOKIE),
        at(20),
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::NoAccount));
    let sessions: i64 = f
        .store
        .read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
                .map_err(sentinel_store::Error::from)
        })
        .unwrap();
    assert_eq!(sessions, 0);
}
