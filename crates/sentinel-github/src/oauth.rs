//! The authorization-code flow for signing a human in with GitHub.
//!
//! Sentinel is a confidential client here: the exchange is a server-to-server
//! POST carrying the client secret, so there is no PKCE (GitHub's web flow does
//! not offer it). Replay and login-CSRF protection come from the `state` value,
//! which the caller mints, stores server-side as a digest and also sets as a
//! host-only cookie: a callback must present both halves.
//!
//! Nothing here is persisted. The login token is read once, used once to learn
//! the account's immutable ID, and dropped.

use std::{fmt, path::Path};

use crate::{Error, Result, http::Client};

/// Where the flow talks to. Separate from the application so a GitHub
/// Enterprise Server deployment is a configuration change, not a fork.
#[derive(Clone, Debug)]
pub struct Endpoints {
    authorize: String,
    token: String,
    user: String,
}

impl Endpoints {
    /// github.com, the only endpoints a normal deployment needs.
    pub fn github() -> Endpoints {
        Endpoints {
            authorize: "https://github.com/login/oauth/authorize".into(),
            token: "https://github.com/login/oauth/access_token".into(),
            user: "https://api.github.com/user".into(),
        }
    }

    /// GitHub Enterprise Server. Both bases must be HTTPS: a sign-in flow
    /// carries a client secret and an access token, and this is the only place
    /// that could decide otherwise.
    pub fn enterprise(web_base: &str, api_base: &str) -> Result<Endpoints> {
        for base in [web_base, api_base] {
            if !base.starts_with("https://") || base.contains('?') || base.contains('#') {
                return Err(Error::Config("endpoint base"));
            }
        }
        let (web, api) = (
            web_base.trim_end_matches('/'),
            api_base.trim_end_matches('/'),
        );
        Ok(Endpoints {
            authorize: format!("{web}/login/oauth/authorize"),
            token: format!("{web}/login/oauth/access_token"),
            user: format!("{api}/user"),
        })
    }

    /// Plain-HTTP endpoints on this machine's loopback interface, for tests and
    /// local fakes. It can only ever address `127.0.0.1`, so it cannot be used
    /// to reach a real provider without TLS, and no configuration path selects
    /// it: a deployment reaches GitHub through [`Self::github`] or
    /// [`Self::enterprise`], both of which require HTTPS.
    pub fn loopback(port: u16) -> Endpoints {
        Endpoints {
            authorize: format!("http://127.0.0.1:{port}/login/oauth/authorize"),
            token: format!("http://127.0.0.1:{port}/login/oauth/access_token"),
            user: format!("http://127.0.0.1:{port}/user"),
        }
    }
}

/// The registered OAuth application. The secret is held in memory only for as
/// long as the process runs; it is loaded from an operator-controlled file, not
/// from the database and not from a command line.
pub struct App {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl App {
    /// One exact, absolute HTTPS redirect URI: no wildcard, no query, no
    /// fragment. GitHub compares it too, but a deployment must not be able to
    /// register a pattern here and rely on the other side to be strict.
    pub fn new(client_id: &str, client_secret: String, redirect_uri: &str) -> Result<App> {
        if client_id.is_empty()
            || client_id.len() > 128
            || !client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(Error::Config("client id"));
        }
        if client_secret.is_empty() || client_secret.len() > 512 {
            return Err(Error::Config("client secret"));
        }
        if !redirect_uri.starts_with("https://")
            || redirect_uri.len() > 512
            || redirect_uri.contains(['?', '#', '*', ' '])
        {
            return Err(Error::Config("redirect uri"));
        }
        Ok(App {
            client_id: client_id.to_owned(),
            client_secret,
            redirect_uri: redirect_uri.to_owned(),
        })
    }

    /// Load the client secret from an operator-controlled file.
    ///
    /// The secret never reaches a command line, an environment variable or the
    /// database: those are readable by other processes, or backed up. One
    /// trailing newline is dropped so an ordinary text file works; nothing else
    /// is trimmed, because a secret is bytes.
    pub fn load(client_id: &str, secret_path: &Path, redirect_uri: &str) -> Result<App> {
        let metadata =
            std::fs::metadata(secret_path).map_err(|_| Error::Config("client secret file"))?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(Error::Config("client secret file"));
        }
        let mut secret = std::fs::read_to_string(secret_path)
            .map_err(|_| Error::Config("client secret file"))?;
        if secret.ends_with('\n') {
            secret.pop();
            if secret.ends_with('\r') {
                secret.pop();
            }
        }
        App::new(client_id, secret, redirect_uri)
    }

    /// Where to send the browser. `state` is the caller's single-use secret; it
    /// is opaque here, and the caller is responsible for storing its digest and
    /// setting the matching cookie before this URL is followed.
    ///
    /// No scopes are requested: signing in needs identity, not repository
    /// access. Repository permissions come from the App installation (Part 05).
    pub fn authorize_url(&self, endpoints: &Endpoints, state: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&scope=&state={}&allow_signup=false",
            endpoints.authorize,
            encode(&self.client_id),
            encode(&self.redirect_uri),
            encode(state)
        )
    }

    /// Exchange an authorization code for a user login token.
    ///
    /// The redirect URI is sent again so GitHub rejects a code minted for a
    /// different registration, and the secret travels in the request body.
    pub fn exchange(&self, http: &Client, endpoints: &Endpoints, code: &str) -> Result<LoginToken> {
        if code.is_empty() || code.len() > 512 || !code.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Callback("code"));
        }
        let body = http.post_form(
            &endpoints.token,
            &[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
            ],
        )?;
        // GitHub reports refusals with HTTP 200 and an `error` member.
        if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
            return Err(Error::Denied(bounded(error)));
        }
        let token = body
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or(Error::Response("no access token"))?;
        if token.is_empty() || token.len() > 512 {
            return Err(Error::Response("access token length"));
        }
        // A token type other than bearer would mean a different protocol.
        match body.get("token_type").and_then(|t| t.as_str()) {
            Some(kind) if kind.eq_ignore_ascii_case("bearer") => {}
            _ => return Err(Error::Response("token type")),
        }
        Ok(LoginToken(token.to_owned()))
    }
}

/// A GitHub **user** access token. Never stored, never logged, never given to a
/// job: it exists to make exactly one identity request. It is not an
/// installation token and cannot be used as one.
pub struct LoginToken(String);

impl fmt::Debug for LoginToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginToken(redacted)")
    }
}

impl Drop for LoginToken {
    fn drop(&mut self) {
        // Best effort: the allocation is overwritten before it is released.
        let bytes = unsafe { self.0.as_bytes_mut() };
        // SAFETY: ASCII spaces are valid UTF-8, so the string stays well-formed.
        bytes.fill(b' ');
        std::hint::black_box(bytes);
    }
}

/// What GitHub says about the signed-in account. Only `subject` is identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The immutable numeric GitHub account ID, as text. Survives renames, and
    /// is never reused when an account is deleted.
    pub subject: String,
    /// Current login handle. Display metadata: it can be renamed, and a freed
    /// handle can be taken by somebody else.
    pub login: String,
    /// Current display name, when the account has one. Metadata.
    pub name: Option<String>,
}

/// Read the account behind a login token. The numeric ID is required and must
/// be a positive integer; a response without one is not an identity.
pub fn verified_identity(
    http: &Client,
    endpoints: &Endpoints,
    token: &LoginToken,
) -> Result<VerifiedIdentity> {
    let body = http.get_authenticated(&endpoints.user, &token.0)?;
    let subject = match body.get("id") {
        // Accept only an exact integer: a float or a string here means the
        // response is not the user record this contract expects.
        Some(value) => value.as_u64().filter(|id| *id > 0),
        None => None,
    }
    .ok_or(Error::Response("no account id"))?;
    let login = body
        .get("login")
        .and_then(|l| l.as_str())
        .filter(|l| !l.is_empty() && l.len() <= 64)
        .ok_or(Error::Response("no login"))?;
    Ok(VerifiedIdentity {
        subject: subject.to_string(),
        login: login.to_owned(),
        name: body
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| !n.is_empty())
            .map(bounded),
    })
}

/// What came back on the redirect. Parsed from the query string before any
/// database or network work, so malformed callbacks cost nothing.
#[derive(Debug, PartialEq, Eq)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

/// Parse and validate a callback query string.
///
/// Duplicated parameters are rejected rather than resolved: a repeated `state`
/// is parameter smuggling, not a formatting quirk. GitHub's `error` is reported
/// as a denial, and both values are length- and charset-bounded.
pub fn callback(query: &str) -> Result<Callback> {
    if query.len() > 2048 {
        return Err(Error::Callback("query length"));
    }
    let (mut code, mut state, mut error) = (None, None, None);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match key {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            // Unknown parameters are ignored: GitHub adds descriptive ones.
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::Callback("duplicate parameter"));
        }
        *slot = Some(decode(value)?);
    }
    if let Some(error) = error {
        return Err(Error::Denied(bounded(&error)));
    }
    let (code, state) = (
        code.ok_or(Error::Callback("code"))?,
        state.ok_or(Error::Callback("state"))?,
    );
    if code.is_empty() || code.len() > 512 || !code.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Callback("code"));
    }
    if state.is_empty() || state.len() > 256 || !state.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Callback("state"));
    }
    Ok(Callback { code, state })
}

/// Percent-encode for a query value: everything that is not unreserved.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Decode a query value. Rejects malformed escapes and non-UTF-8 rather than
/// substituting replacement characters.
fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' => {
                let hex = bytes
                    .get(at + 1..at + 3)
                    .ok_or(Error::Callback("percent escape"))?;
                let text =
                    std::str::from_utf8(hex).map_err(|_| Error::Callback("percent escape"))?;
                out.push(
                    u8::from_str_radix(text, 16).map_err(|_| Error::Callback("percent escape"))?,
                );
                at += 3;
            }
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            other => {
                out.push(other);
                at += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Callback("encoding"))
}

/// Bound a value GitHub controls before it reaches a diagnostic or an audit row.
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    fn app() -> App {
        App::new(
            "Iv1.0123456789abcdef",
            "shhh-client-secret".into(),
            "https://ci.example/auth/github/callback",
        )
        .unwrap()
    }

    /// A GitHub-shaped server: answers the token and user endpoints from a
    /// script and reports what it actually received.
    fn stub(responses: Vec<(u16, String)>) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut request = String::new();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    let done = line == "\r\n";
                    request.push_str(&line);
                    if done {
                        break;
                    }
                }
                let mut payload = vec![0u8; length];
                reader.read_exact(&mut payload).unwrap();
                request.push_str(&String::from_utf8_lossy(&payload));
                tx.send(request).unwrap();
                write!(
                    socket,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (port, rx)
    }

    #[test]
    fn a_code_becomes_a_verified_immutable_account_id() {
        let (port, received) = stub(vec![
            (
                200,
                r#"{"access_token":"gho_secret","token_type":"bearer","scope":""}"#.into(),
            ),
            (
                200,
                r#"{"id":4242,"login":"octocat","name":"The Octocat","email":"o@example"}"#.into(),
            ),
        ]);
        let endpoints = Endpoints::loopback(port);
        let http = Client::new();
        let token = app().exchange(&http, &endpoints, "the-code").unwrap();
        let identity = verified_identity(&http, &endpoints, &token).unwrap();
        assert_eq!(
            identity,
            VerifiedIdentity {
                subject: "4242".into(),
                login: "octocat".into(),
                name: Some("The Octocat".into()),
            }
        );

        // The secret is posted in the body with the redirect URI, never in a URL.
        let exchange = received.recv().unwrap();
        assert!(
            exchange.starts_with("POST /login/oauth/access_token"),
            "{exchange}"
        );
        assert!(exchange.contains("client_secret=shhh-client-secret"));
        assert!(
            exchange.contains("redirect_uri=https%3A%2F%2Fci.example%2Fauth%2Fgithub%2Fcallback")
        );
        assert!(!exchange.lines().next().unwrap().contains("client_secret"));
        // The login token is presented as a header, once.
        let user = received.recv().unwrap();
        assert!(user.starts_with("GET /user"), "{user}");
        assert!(
            user.to_ascii_lowercase()
                .contains("authorization: bearer gho_secret")
        );
        assert_eq!(format!("{token:?}"), "LoginToken(redacted)");
    }

    #[test]
    fn github_refusals_and_malformed_records_are_not_identities() {
        let cases: Vec<(u16, String, Error)> = vec![
            (
                200,
                r#"{"error":"bad_verification_code","error_description":"expired"}"#.into(),
                Error::Denied("bad_verification_code".into()),
            ),
            (
                200,
                r#"{"access_token":"gho_x","token_type":"jwt"}"#.into(),
                Error::Response("token type"),
            ),
            (
                200,
                r#"{"token_type":"bearer"}"#.into(),
                Error::Response("no access token"),
            ),
            (500, "{}".into(), Error::Transport("status 500".into())),
            (200, "not json".into(), Error::Response("body is not JSON")),
        ];
        for (status, body, expected) in cases {
            let (port, _received) = stub(vec![(status, body.clone())]);
            let failure = app()
                .exchange(&Client::new(), &Endpoints::loopback(port), "the-code")
                .unwrap_err();
            assert_eq!(failure, expected, "{body}");
        }

        for body in [
            r#"{"login":"octocat"}"#,
            r#"{"id":0,"login":"octocat"}"#,
            r#"{"id":"4242","login":"octocat"}"#,
            r#"{"id":4242}"#,
            r#"{"id":4242,"login":""}"#,
        ] {
            let (port, _received) = stub(vec![
                (
                    200,
                    r#"{"access_token":"gho_x","token_type":"bearer"}"#.into(),
                ),
                (200, body.into()),
            ]);
            let endpoints = Endpoints::loopback(port);
            let http = Client::new();
            let token = app().exchange(&http, &endpoints, "the-code").unwrap();
            assert!(
                matches!(
                    verified_identity(&http, &endpoints, &token),
                    Err(Error::Response(_))
                ),
                "{body} was accepted"
            );
        }
    }

    #[test]
    fn the_authorize_url_pins_the_registration_and_requests_no_repository_scope() {
        let url = app().authorize_url(&Endpoints::github(), "the+state/value");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=Iv1.0123456789abcdef"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fci.example%2Fauth%2Fgithub%2Fcallback"));
        assert!(url.contains("state=the%2Bstate%2Fvalue"));
        assert!(url.contains("scope=&"), "{url}");
        assert!(!url.contains("client_secret"));
    }

    #[test]
    fn application_and_endpoint_configuration_is_strict() {
        for (id, secret, redirect) in [
            ("", "s3cret value", "https://ci.example/cb"),
            ("id with space", "s3cret value", "https://ci.example/cb"),
            ("Iv1.abc", "", "https://ci.example/cb"),
            ("Iv1.abc", "s3cret value", "http://ci.example/cb"),
            ("Iv1.abc", "s3cret value", "https://ci.example/cb?next=/"),
            ("Iv1.abc", "s3cret value", "https://*.example/cb"),
        ] {
            assert!(
                App::new(id, secret.into(), redirect).is_err(),
                "{id}/{redirect} accepted"
            );
        }
        assert!(Endpoints::enterprise("http://gh.corp", "https://gh.corp/api/v3").is_err());
        assert!(Endpoints::enterprise("https://gh.corp/", "https://gh.corp/api/v3").is_ok());
        let app = app();
        assert!(!format!("{app:?}").contains("shhh-client-secret"));
    }

    #[test]
    fn the_client_secret_is_loaded_from_a_file_not_a_command_line() {
        let dir = std::env::temp_dir().join(format!("sentinel-gh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client-secret");
        std::fs::write(&path, "shhh-client-secret\n").unwrap();
        let app = App::load(
            "Iv1.0123456789abcdef",
            &path,
            "https://ci.example/auth/github/callback",
        )
        .unwrap();
        assert_eq!(
            app.client_secret, "shhh-client-secret",
            "newline is dropped"
        );

        std::fs::write(&path, "").unwrap();
        assert_eq!(
            App::load("Iv1.abc", &path, "https://ci.example/cb").unwrap_err(),
            Error::Config("client secret")
        );
        assert_eq!(
            App::load("Iv1.abc", &dir.join("absent"), "https://ci.example/cb").unwrap_err(),
            Error::Config("client secret file")
        );
        assert_eq!(
            App::load("Iv1.abc", &dir, "https://ci.example/cb").unwrap_err(),
            Error::Config("client secret file")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn callbacks_are_validated_before_any_work_happens() {
        assert_eq!(
            callback("code=abc&state=xyz").unwrap(),
            Callback {
                code: "abc".into(),
                state: "xyz".into()
            }
        );
        // GitHub adds descriptive parameters; unknown ones are ignored.
        assert!(callback("code=abc&state=xyz&extra=1").is_ok());
        assert_eq!(
            callback("error=access_denied&error_description=no").unwrap_err(),
            Error::Denied("access_denied".into())
        );
        for query in [
            "code=abc",
            "state=xyz",
            "",
            "code=abc&state=xyz&state=other",
            "code=&state=xyz",
            "code=abc&state=",
            "code=a%2&state=xyz",
            "code=a b&state=xyz",
        ] {
            assert!(callback(query).is_err(), "{query} accepted");
        }
        assert!(callback(&format!("code=abc&state={}", "x".repeat(4096))).is_err());
    }
}
