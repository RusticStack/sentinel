//! GitHub web sign-in over HTTP: the verified flow (`sentinel_github::oauth`,
//! `sentinel_store::sign_in`) behind the `/auth/github/*` routes, so the OAuth
//! consent page, the device page and the first page can sign in an account
//! that exists only through GitHub.
//!
//! - `GET /auth/github/start?return_to=<path>` records a single-use state with
//!   its destination, sets the browser's half as the `__Host-sentinel_signin`
//!   cookie and answers `303` to GitHub. The destination may only be `/`,
//!   `/oauth/authorize?…` or `/device[?…]`: an issuer-relative path, never a
//!   URL, so a finished sign-in cannot be an open redirect.
//! - `GET /auth/github/callback?code&state` requires the cookie and the
//!   parameter to agree, spends the state once, exchanges the code (the
//!   client secret in the body, the exact redirect URI repeated), reads the
//!   immutable account ID and resolves it only through a linked identity of
//!   an active account. Nothing is matched by login or email.
//!
//! A successful callback issues no session itself. It is a navigation GitHub
//! started, and a browser never sends the `SameSite=Strict` session cookie
//! on it, so the session this browser already holds cannot be seen there.
//! The callback parks a hand-off — the resolved account, keyed by the digest
//! of this browser's `__Host-sentinel_signin` cookie, for at most
//! [`HANDOFF_TTL`] — and answers a small page that moves the browser on to
//! `GET /auth/github/finish`. That navigation is started by a Sentinel page,
//! so it is same-origin and carries the Strict cookie: `finish` revokes the
//! session the browser held and issues the new one in one transaction, then
//! answers the page that moves on to the destination, where
//! the consent page mints its form token from the new session's CSRF digest.
//! `finish` refuses a request a browser marks as not same-origin
//! (`Sec-Fetch-Site`), so another site cannot complete it without the old
//! session; a hand-off is bound to the sign-in cookie, so nobody can
//! complete another browser's.
//!
//! `POST /api/v1/identities/github/link` is the same round trip for a browser
//! that is already signed in: a session with a fresh step-up asks for the
//! authorization URL, the callback verifies the identity and parks it with the
//! digest of the session that asked, and `finish` links it to that account
//! ([`sentinel_store::sign_in::link`]) only if that same session is presented
//! on the same-origin hop. No session is issued or ended, and an identity
//! already linked anywhere is never moved.
//!
//! The routes are admitted per client ([`crate::oauth::limit`]). The code
//! exchange and the identity read are outbound calls of up to ten seconds
//! each, so they draw on their own [`crate::OUTBOUND`] budget (not shared
//! with CIMD metadata fetches, which cannot make sign-in busy); a callback
//! past it is told to reload, with its state still unspent.

use std::{
    collections::VecDeque,
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

use sentinel_auth::{
    cookie,
    secret::{Secret, digest_eq},
};
use sentinel_core::{UnixMillis, UserId};
use sentinel_github::{
    PROVIDER,
    http::Client,
    oauth::{self, App, Endpoints},
};
use sentinel_store::sign_in::{self, MAX_REDIRECT_BYTES, Outcome, STATE_TTL_MS};

use crate::{
    State,
    http::Request,
    oauth::{
        html,
        limit::{Limiter, Rate},
    },
    routes::{self, Reply, Route},
};

/// GitHub web sign-in settings (`<data_dir>/github-sign-in.json` in the
/// server). The redirect URI is not configured: it is always
/// `{issuer}/auth/github/callback`, which is what the GitHub OAuth app must
/// register.
pub struct GithubSignIn {
    /// The OAuth app's client ID (public).
    pub client_id: String,
    /// The OAuth app's client secret, read from an operator-controlled file.
    pub client_secret: String,
    /// github.com, or a GitHub Enterprise Server's endpoints.
    pub endpoints: Endpoints,
}

impl fmt::Debug for GithubSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubSignIn")
            .field("client_id", &self.client_id)
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

/// Per client: a burst of 10, then one sign-in step every 2 s. One sign-in
/// is two steps (start and callback).
const CLIENT: Rate = Rate::new(std::time::Duration::from_secs(2), 10);
/// Deployment-wide: 20/s, burst 40. Pending states live ten minutes, so the
/// table holds at most about 12,000 rows even at the ceiling, and the
/// maintenance tick purges them in bounded batches.
const CEILING: Rate = Rate::per_sec(20, 40);

/// The live configuration: the app (secret and exact redirect URI), where
/// GitHub is, and the bounds.
pub(crate) struct Github {
    app: App,
    endpoints: Endpoints,
    http: Client,
    /// `{issuer}/auth/github/start`, linked from the sign-in pages.
    pub start_url: String,
    budget: Mutex<Limiter>,
    /// Callbacks waiting for their same-origin hop, oldest first.
    handoffs: Mutex<VecDeque<Handoff>>,
    /// Link attempts begun by a signed-in browser and not yet called back,
    /// oldest first.
    links: Mutex<VecDeque<PendingLink>>,
}

/// An identity-linking attempt: which account, through which session, begun
/// when. Held in memory only, like a hand-off — nothing in it is secret (two
/// digests and an account ID), and an attempt lost to a restart is started
/// again.
struct PendingLink {
    /// Digest of the state secret, which is also the browser's sign-in cookie.
    state: sentinel_auth::secret::Digest,
    user: UserId,
    /// Digest of the session cookie that began it.
    session: sentinel_auth::secret::Digest,
    deadline: Instant,
}

/// Link attempts held at once. Starting one costs an admitted request (20/s
/// deployment-wide) and lives at most [`STATE_TTL_MS`]; past the bound the
/// oldest is dropped and that browser starts again.
const MAX_LINKS: usize = 256;

/// What a parked callback completes.
enum Purpose {
    /// Sign in as the resolved account.
    SignIn,
    /// Link the verified GitHub identity to the session that began the attempt.
    Link {
        subject: String,
        session: sentinel_auth::secret::Digest,
    },
}

/// How long a verified callback waits for its same-origin hop: the page
/// moves on at once, so this only covers a slow browser.
pub(crate) const HANDOFF_TTL: Duration = Duration::from_secs(60);
/// Pending hand-offs held at once. Callbacks are admitted at 20/s
/// deployment-wide, so a minute's worth fits; past it the oldest is dropped
/// and that browser starts again. Nothing secret is held: a digest and an
/// account ID.
const MAX_HANDOFFS: usize = 1024;

struct Handoff {
    /// Digest of the browser's sign-in cookie.
    cookie: sentinel_auth::secret::Digest,
    user: UserId,
    destination: Option<String>,
    purpose: Purpose,
    deadline: Instant,
}

impl Github {
    /// Build from the configuration and the issuer. Fails on an invalid
    /// client ID or secret, or an issuer that cannot be a redirect URI (plain
    /// HTTP to a non-loopback host); the error names the field, never a value.
    pub(crate) fn new(
        config: GithubSignIn,
        issuer: &str,
    ) -> Result<Github, sentinel_github::Error> {
        let redirect = format!("{issuer}/auth/github/callback");
        let app = App::new(&config.client_id, config.client_secret, &redirect)?;
        Ok(Github {
            app,
            endpoints: config.endpoints,
            http: Client::new(),
            start_url: format!("{issuer}/auth/github/start"),
            budget: Mutex::new(Limiter::new(CLIENT, Some(CEILING), Instant::now())),
            handoffs: Mutex::new(VecDeque::new()),
            links: Mutex::new(VecDeque::new()),
        })
    }

    fn park_link(&self, link: PendingLink, now: Instant) {
        let mut queue = self.links.lock().unwrap_or_else(|p| p.into_inner());
        while queue.front().is_some_and(|l| l.deadline <= now) || queue.len() >= MAX_LINKS {
            queue.pop_front();
        }
        queue.push_back(link);
    }

    /// Take the live link attempt of this state, once. `None` for a sign-in.
    fn take_link(
        &self,
        state: &sentinel_auth::secret::Digest,
        now: Instant,
    ) -> Option<PendingLink> {
        let mut queue = self.links.lock().unwrap_or_else(|p| p.into_inner());
        while queue.front().is_some_and(|l| l.deadline <= now) {
            queue.pop_front();
        }
        let at = queue.iter().position(|l| digest_eq(&l.state, state))?;
        queue.remove(at)
    }

    fn park(&self, handoff: Handoff, now: Instant) {
        let mut queue = self.handoffs.lock().unwrap_or_else(|p| p.into_inner());
        while queue.front().is_some_and(|h| h.deadline <= now) || queue.len() >= MAX_HANDOFFS {
            queue.pop_front();
        }
        queue.push_back(handoff);
    }

    /// Take the live hand-off of this sign-in cookie, once.
    fn take(&self, cookie: &sentinel_auth::secret::Digest, now: Instant) -> Option<Handoff> {
        let mut queue = self.handoffs.lock().unwrap_or_else(|p| p.into_inner());
        while queue.front().is_some_and(|h| h.deadline <= now) {
            queue.pop_front();
        }
        let at = queue.iter().position(|h| digest_eq(&h.cookie, cookie))?;
        queue.remove(at)
    }

    fn admit(&self, state: &State, request: &Request) -> bool {
        let client = crate::oauth::client_of(state, request);
        self.budget
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit(client, Instant::now())
    }
}

/// Route `/auth/github/*`; `None` passes the request on (and without a
/// configuration, every such path is an ordinary unknown route).
pub(crate) fn route(
    state: &State,
    request: &Request,
    method: &str,
    parts: &[&str],
    query: &str,
) -> Option<Route> {
    let github = state.github.as_ref()?;
    Some(match (method, parts) {
        ("GET", ["auth", "github", "start"]) => Ok(start(state, github, request, query)),
        ("GET", ["auth", "github", "callback"]) => Ok(callback(state, github, request, query)),
        ("GET", ["auth", "github", "finish"]) => Ok(finish(state, github, request)),
        ("POST", ["api", "v1", "identities", "github", "link"]) => {
            link_start(state, github, request)
        }
        _ => return None,
    })
}

/// `POST /api/v1/identities/github/link`: a signed-in browser (session and
/// CSRF header) with a fresh step-up begins linking a GitHub account to its
/// own. Answers the GitHub authorization URL to navigate to and sets the
/// browser's half of the state; the rest is the sign-in round trip
/// ([`callback`], [`finish`]), which ends in [`sign_in::link`] under the same
/// session. Linking changes who can authenticate, so a step-up is asked for
/// here (`forbidden` with `details.step_up`) and judged again at the end.
fn link_start(state: &State, github: &Github, request: &Request) -> routes::Route {
    let (presented, session, now) = routes::account::browser_session(state, request, true)?;
    if !github.admit(state, request) {
        return Err(routes::err(
            sentinel_protocol::error::ErrorCode::RateLimited,
            "too many sign-in attempts; retry shortly",
        )
        .with_detail("retry_after_ms", 2000));
    }
    session
        .require_step_up(state.sessions, now)
        .map_err(routes::store_error)?;
    let secret = Secret::generate();
    let mut text = String::with_capacity(Secret::TEXT_LEN);
    secret.expose(&mut text);
    let authorize_url = github.app.authorize_url(&github.endpoints, &text);
    let at = Instant::now();
    github.park_link(
        PendingLink {
            state: secret.digest(),
            user: session.user,
            session: presented.digest(),
            deadline: at + Duration::from_millis(STATE_TTL_MS as u64),
        },
        at,
    );
    let max_age = u32::try_from(STATE_TTL_MS / 1000).unwrap_or(600);
    Ok(Reply::Json(
        200,
        serde_json::json!({
            "authorize_url": authorize_url,
            "expires_in": STATE_TTL_MS / 1000,
        }),
        vec![routes::header(
            "set-cookie",
            &cookie::issue_sign_in(&secret, max_age),
        )],
    ))
}

/// Whether `path` may be where a finished sign-in lands: the first page, the
/// consent page or the device page, as an issuer-relative path with only
/// URL-safe characters (so it is inert in a header, an attribute and a
/// script string alike). Anything else is an open redirect waiting to happen.
pub(crate) fn return_acceptable(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_REDIRECT_BYTES {
        return false;
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~%/?&=+:@!$,*()".contains(&b))
    {
        return false;
    }
    match path.split_once('?') {
        None => matches!(path, "/" | "/oauth/authorize" | "/device"),
        Some((route, _)) => matches!(route, "/oauth/authorize" | "/device"),
    }
}

/// Append `return_to` for `path`, percent-encoded as a query value.
pub(crate) fn start_link(start_url: &str, path: &str) -> String {
    let mut out = String::with_capacity(start_url.len() + 12 + path.len() * 3);
    out.push_str(start_url);
    out.push_str("?return_to=");
    out.extend(form_urlencoded::byte_serialize(path.as_bytes()));
    out
}

fn busy_page(status: u16, message: &str) -> Reply {
    let mut reply = html::error_page(status, message);
    if let Reply::Html(_, _, headers) = &mut reply {
        headers.push(routes::header("retry-after", "2"));
    }
    reply
}

fn start(state: &State, github: &Github, request: &Request, query: &str) -> Reply {
    if !github.admit(state, request) {
        return busy_page(
            429,
            "Too many sign-in attempts from this address. Wait a moment, then try again.",
        );
    }
    let mut return_to = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name == "return_to" {
            if return_to.is_some() {
                return html::error_page(400, "This sign-in link is malformed.");
            }
            return_to = Some(value.into_owned());
        }
    }
    let return_to = return_to.unwrap_or_else(|| "/".to_owned());
    if !return_acceptable(&return_to) {
        return html::error_page(
            400,
            "This sign-in link cannot return to that page. Start again from the page you were on.",
        );
    }
    let secret = match sign_in::begin(
        &state.store,
        PROVIDER,
        Some(&return_to),
        UnixMillis::now(),
        STATE_TTL_MS,
    ) {
        Ok(secret) => secret,
        Err(_) => return busy_page(503, "Sentinel is busy. Try again in a moment."),
    };
    let mut text = String::with_capacity(Secret::TEXT_LEN);
    secret.expose(&mut text);
    let location = github.app.authorize_url(&github.endpoints, &text);
    let max_age = u32::try_from(STATE_TTL_MS / 1000).unwrap_or(600);
    Reply::Html(
        303,
        String::new(),
        vec![
            routes::header("location", &location),
            routes::header("set-cookie", &cookie::issue_sign_in(&secret, max_age)),
        ],
    )
}

/// A refusal after the state was spent (or can never be spent): the sign-in
/// cookie is cleared with it, so a stale one is not presented again.
fn ended(status: u16, message: &str) -> Reply {
    let mut reply = html::error_page(status, message);
    if let Reply::Html(_, _, headers) = &mut reply {
        headers.push(routes::header(
            "set-cookie",
            &cookie::clear(cookie::SIGN_IN_COOKIE),
        ));
    }
    reply
}

const START_AGAIN: &str = "This sign-in did not start in this browser, or it has already been used. Start again from the page you were on.";

fn callback(state: &State, github: &Github, request: &Request, query: &str) -> Reply {
    if !github.admit(state, request) {
        return busy_page(
            429,
            "Too many sign-in attempts from this address. Wait a moment, then reload this page.",
        );
    }
    let callback = match oauth::callback(query) {
        Ok(callback) => callback,
        Err(sentinel_github::Error::Denied(_)) => {
            return ended(403, "GitHub sign-in was cancelled.");
        }
        Err(_) => return html::error_page(400, "The GitHub sign-in response is malformed."),
    };
    // The browser's half of the state must be the parameter: a callback URL
    // alone — stolen, guessed, or an attacker's own — completes nothing.
    let presented = routes::header_value(request, "cookie")
        .and_then(|header| cookie::read(cookie::SIGN_IN_COOKIE, header));
    let parameter = Secret::parse(&callback.state);
    let (Some(presented), Some(parameter)) = (presented, parameter) else {
        return html::error_page(400, START_AGAIN);
    };
    if !digest_eq(&presented.digest(), &parameter.digest()) {
        return html::error_page(400, START_AGAIN);
    }
    // Taken before the state is spent, so a busy answer leaves it pending
    // and a reload of this same URL completes.
    let Some(_slot) = state.exchanges.take() else {
        return busy_page(
            503,
            "Sentinel is busy signing someone else in. Reload this page in a moment.",
        );
    };
    // A link attempt is held in memory and spent by this take; a sign-in is
    // spent in the store. Neither can be spent twice.
    let link = github.take_link(&presented.digest(), Instant::now());
    let destination = if link.is_some() {
        None
    } else {
        match sign_in::consume(&state.store, PROVIDER, &presented, UnixMillis::now()) {
            Ok(destination) => destination,
            Err(sentinel_store::Error::NotFound) => return ended(400, START_AGAIN),
            Err(_) => return busy_page(503, "Sentinel is busy. Reload this page in a moment."),
        }
    };
    let identity = github
        .app
        .exchange(&github.http, &github.endpoints, &callback.code)
        .and_then(|token| oauth::verified_identity(&github.http, &github.endpoints, &token));
    let Ok(identity) = identity else {
        return ended(
            502,
            "GitHub did not confirm the sign-in. Start again from the page you were on.",
        );
    };
    // A link attempt names its account already; the identity is carried to the
    // hop that holds the session. A sign-in resolves it through a link.
    let (user, purpose) = match link {
        Some(link) => (
            link.user,
            Purpose::Link {
                subject: identity.subject,
                session: link.session,
            },
        ),
        None => match sign_in::resolve(&state.store, PROVIDER, &identity.subject) {
            Ok(Some(user)) => (user, Purpose::SignIn),
            // One answer for "never linked", pending, rejected and suspended.
            Ok(None) => return ended(403, NO_ACCOUNT),
            Err(_) => return ended(503, "Sentinel is busy. Start again in a moment."),
        },
    };
    let now = Instant::now();
    github.park(
        Handoff {
            cookie: presented.digest(),
            user,
            destination,
            purpose,
            deadline: now + HANDOFF_TTL,
        },
        now,
    );
    // The sign-in cookie stays: `finish` finds the hand-off by it.
    let mut target = String::with_capacity(state.oauth.path.len() + 20);
    target.push_str(&state.oauth.path);
    target.push_str("/auth/github/finish");
    let mut body = String::with_capacity(256 + 2 * target.len());
    body.push_str("<meta http-equiv=\"refresh\" content=\"0; url=");
    html::escape_into(&mut body, &target);
    body.push_str("\">\n<p>GitHub confirmed the sign-in. <a href=\"");
    html::escape_into(&mut body, &target);
    body.push_str("\">Continue</a></p>");
    Reply::Html(200, html::document("Signing in", &body), Vec::new())
}

const NO_ACCOUNT: &str = "No active Sentinel account is linked to this GitHub account. Ask an administrator for an invitation, or sign in with a password and link GitHub from your account.";

/// The same-origin hop after a verified callback: revoke the session this
/// browser held (its Strict cookie is sent here) and issue the new one, in
/// one transaction, then move on to the destination.
fn finish(state: &State, github: &Github, request: &Request) -> Reply {
    // A browser labels every navigation; one another site started is
    // refused without spending the hand-off, so only the real hop — which
    // carries the old session's cookie — completes it. A client that sends
    // no label is not a browser and has no ambient cookies to protect.
    if routes::header_value(request, "sec-fetch-site").is_some_and(|site| site != "same-origin") {
        return html::error_page(
            403,
            "Finish signing in from the page Sentinel showed after GitHub.",
        );
    }
    let cookies = routes::header_value(request, "cookie");
    let Some(presented) = cookies.and_then(|header| cookie::read(cookie::SIGN_IN_COOKIE, header))
    else {
        return html::error_page(400, START_AGAIN);
    };
    let Some(handoff) = github.take(&presented.digest(), Instant::now()) else {
        return ended(400, START_AGAIN);
    };
    if let Purpose::Link { subject, session } = &handoff.purpose {
        return finish_link(state, cookies, handoff.user, subject, session);
    }
    let previous = cookies.and_then(|header| cookie::read(cookie::SESSION_COOKIE, header));
    let issued = match sign_in::finish(
        &state.store,
        PROVIDER,
        handoff.user,
        previous.as_ref(),
        state.sessions,
        UnixMillis::now(),
    ) {
        Ok(Outcome::SignedIn(issued)) => issued,
        Ok(Outcome::NoAccount) => return ended(403, NO_ACCOUNT),
        Err(_) => return ended(503, "Sentinel is busy. Start again in a moment."),
    };
    let destination = handoff
        .destination
        .filter(|d| return_acceptable(d))
        .unwrap_or_else(|| "/".to_owned());
    let mut target = String::with_capacity(state.oauth.path.len() + destination.len());
    target.push_str(&state.oauth.path);
    target.push_str(&destination);
    let mut body = String::with_capacity(512 + 2 * target.len());
    if destination == "/" {
        // The web interface makes its own API calls and needs this session's
        // CSRF secret, which exists in plain text only now; the login
        // response hands it over the same way. It goes to `localStorage` so
        // every tab of the browser can act, as the interface keeps it. OAuth
        // pages need no copy.
        let mut csrf = String::with_capacity(Secret::TEXT_LEN);
        issued.csrf.expose(&mut csrf);
        body.push_str("<script>try { localStorage.setItem(\"sentinel-csrf\", \"");
        body.push_str(&csrf);
        body.push_str("\"); } catch (e) {}</script>\n");
    }
    body.push_str("<meta http-equiv=\"refresh\" content=\"0; url=");
    html::escape_into(&mut body, &target);
    body.push_str("\">\n<p>Signed in with GitHub. <a href=\"");
    html::escape_into(&mut body, &target);
    body.push_str("\">Continue</a></p>");
    Reply::Html(
        200,
        html::document("Signed in", &body),
        vec![
            routes::header(
                "set-cookie",
                &cookie::issue(cookie::SESSION_COOKIE, &issued.session, issued.max_age_secs),
            ),
            routes::header("set-cookie", &cookie::clear(cookie::SIGN_IN_COOKIE)),
        ],
    )
}

const LINK_AGAIN: &str = "Sign in again, then link GitHub from your account page.";

/// The same-origin hop of a link attempt: the session that began it must be
/// the one presented here (its Strict cookie is sent on this hop only), and
/// still fresh enough to link. Nothing about the sign-in changes: the session
/// stays, and the browser moves on to the first page.
fn finish_link(
    state: &State,
    cookies: Option<&str>,
    user: UserId,
    subject: &str,
    began_with: &sentinel_auth::secret::Digest,
) -> Reply {
    let now = UnixMillis::now();
    let session = cookies
        .and_then(|header| cookie::read(cookie::SESSION_COOKIE, header))
        .filter(|presented| digest_eq(&presented.digest(), began_with))
        .and_then(|presented| {
            state
                .store
                .read(|c| sentinel_store::local_auth::authenticate(c, &presented, now))
                .ok()
        })
        .filter(|session| session.user == user);
    let Some(session) = session else {
        return ended(403, LINK_AGAIN);
    };
    match sign_in::link(
        &state.store,
        &session,
        state.sessions,
        PROVIDER,
        subject,
        now,
    ) {
        Ok(()) => {}
        Err(sentinel_store::Error::StepUpRequired) => {
            return ended(
                403,
                "Confirm it is you again, then link GitHub from your account page.",
            );
        }
        Err(sentinel_store::Error::Conflict) => {
            return ended(
                409,
                "That GitHub account is already linked to a Sentinel account.",
            );
        }
        Err(_) => return ended(503, "Sentinel is busy. Start again in a moment."),
    }
    let mut target = String::with_capacity(state.oauth.path.len() + 1);
    target.push_str(&state.oauth.path);
    target.push('/');
    let mut body = String::with_capacity(256 + 2 * target.len());
    body.push_str("<meta http-equiv=\"refresh\" content=\"0; url=");
    html::escape_into(&mut body, &target);
    body.push_str("\">\n<p>GitHub is linked to your account. <a href=\"");
    html::escape_into(&mut body, &target);
    body.push_str("\">Continue</a></p>");
    Reply::Html(
        200,
        html::document("GitHub linked", &body),
        vec![routes::header(
            "set-cookie",
            &cookie::clear(cookie::SIGN_IN_COOKIE),
        )],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_sign_in_pages_are_destinations() {
        for good in [
            "/",
            "/device",
            "/device?user_code=ABCD-EFGH",
            "/oauth/authorize?response_type=code&client_id=sentinel-cli&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback",
        ] {
            assert!(return_acceptable(good), "{good}");
        }
        for bad in [
            "",
            "//evil.example/",
            "https://evil.example/",
            "/\\evil.example",
            "/api/v1/runs",
            "/?x=1",
            "/device/../api",
            "/oauth/authorize/../../x",
            "/oauth/authorizex",
            "/device?x=\"><script>",
            "/device?x=1#frag",
            "/device?x=a b",
            "/device?x='",
            "/device?x=;",
            "evil.example",
        ] {
            assert!(!return_acceptable(bad), "{bad}");
        }
        assert!(!return_acceptable(&format!(
            "/device?{}",
            "a".repeat(MAX_REDIRECT_BYTES)
        )));
    }

    #[test]
    fn the_start_link_encodes_the_destination_as_one_value() {
        assert_eq!(
            start_link("https://ci.example/s/auth/github/start", "/device?a=1&b=2"),
            "https://ci.example/s/auth/github/start?return_to=%2Fdevice%3Fa%3D1%26b%3D2"
        );
    }
}
