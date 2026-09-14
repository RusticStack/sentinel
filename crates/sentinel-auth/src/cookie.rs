//! Browser session transport policy: cookie attributes and CSRF checking.
//!
//! No HTTP server exists yet (W08/Part 12). These are the exact bytes and the
//! exact decision the eventual handlers must use, so the policy is written and
//! tested once instead of being reinvented per route.

use crate::secret::{Digest, Secret, digest_eq};

/// Host-only cookies: no `Domain`, so a sibling hostname cannot set or read
/// them. `__Host-` additionally requires `Secure` and `Path=/` in conforming
/// browsers.
pub const SESSION_COOKIE: &str = "__Host-sentinel_session";

/// Carries the pending sign-in state during an external authorization round
/// trip, so a callback must present the browser's own half of it (A04).
pub const SIGN_IN_COOKIE: &str = "__Host-sentinel_signin";

/// The header carrying the session's CSRF secret. A header cannot be set by a
/// cross-site form post, and `SameSite=Strict` keeps the cookie off those requests.
pub const CSRF_HEADER: &str = "x-sentinel-csrf";

/// `Strict` rather than `Lax`: Sentinel has no cross-site entry flow that must
/// arrive already authenticated, and top-level GET navigation mutates nothing.
const ATTRIBUTES: &str = "; Path=/; Secure; HttpOnly; SameSite=Strict";

/// `Set-Cookie` value issuing `secret` under `name` for `max_age_secs`. The
/// secret appears here and nowhere else; the caller must not log the result.
pub fn issue(name: &str, secret: &Secret, max_age_secs: u32) -> String {
    let mut header = String::with_capacity(name.len() + Secret::TEXT_LEN + 64);
    header.push_str(name);
    header.push('=');
    secret.expose(&mut header);
    header.push_str(ATTRIBUTES);
    header.push_str("; Max-Age=");
    header.push_str(itoa(max_age_secs).as_str());
    header
}

/// `Set-Cookie` value that removes a cookie. Used on logout, on every rejected
/// session, and on a completed sign-in, so a spent secret is not presented again.
pub fn clear(name: &str) -> String {
    format!("{name}={ATTRIBUTES}; Max-Age=0")
}

/// Read one named secret out of a `Cookie` header. Returns `None` for a
/// missing, duplicated or malformed value rather than trying the first match:
/// two cookies of one name mean something is injecting them.
pub fn read(name: &str, header: &str) -> Option<Secret> {
    let mut found = None;
    for pair in header.split(';') {
        let pair = pair.trim_start();
        let Some(value) = pair
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(value);
    }
    Secret::parse(found?)
}

/// Whether a state-changing request carries this session's CSRF secret.
/// Safe methods are the caller's business; this is the check, not the routing.
#[must_use]
pub fn csrf_accepted(expected: &Digest, presented_header: Option<&str>) -> bool {
    let Some(secret) = presented_header.and_then(Secret::parse) else {
        return false;
    };
    digest_eq(&secret.digest(), expected)
}

fn itoa(mut value: u32) -> String {
    if value == 0 {
        return "0".into();
    }
    let mut buf = [0u8; 10];
    let mut at = buf.len();
    while value > 0 {
        at -= 1;
        buf[at] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    String::from_utf8_lossy(&buf[at..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_cookies_carry_the_full_transport_policy() {
        let secret = Secret::generate();
        let header = issue(SESSION_COOKIE, &secret, 43200);
        let mut text = String::new();
        secret.expose(&mut text);
        assert!(
            header.starts_with(&format!("{SESSION_COOKIE}={text};")),
            "{header}"
        );
        for attribute in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=43200",
        ] {
            assert!(
                header.contains(attribute),
                "{attribute} missing from {header}"
            );
        }
        assert!(!header.contains("Domain="), "{header}");
        assert!(clear(SESSION_COOKIE).contains("Max-Age=0"));
        let pending = issue(SIGN_IN_COOKIE, &secret, 600);
        assert!(pending.starts_with(SIGN_IN_COOKIE), "{pending}");
        assert!(pending.contains("SameSite=Strict") && pending.contains("Max-Age=600"));
    }

    #[test]
    fn cookie_reading_refuses_ambiguous_or_malformed_headers() {
        let secret = Secret::generate();
        let mut text = String::new();
        secret.expose(&mut text);
        let single = format!("other=1; {SESSION_COOKIE}={text}; last=2");
        assert!(digest_eq(
            &read(SESSION_COOKIE, &single).unwrap().digest(),
            &secret.digest()
        ));
        assert!(
            read(SIGN_IN_COOKIE, &single).is_none(),
            "names are distinct"
        );
        assert!(
            read(
                SESSION_COOKIE,
                &format!("{SESSION_COOKIE}={text}; {SESSION_COOKIE}={text}")
            )
            .is_none()
        );
        assert!(read(SESSION_COOKIE, &format!("{SESSION_COOKIE}_other={text}")).is_none());
        assert!(
            read(
                SESSION_COOKIE,
                &format!("{SESSION_COOKIE}=zz{}", &text[2..])
            )
            .is_none()
        );
        assert!(read(SESSION_COOKIE, "").is_none());
    }

    #[test]
    fn csrf_requires_the_matching_session_secret_in_the_header() {
        let csrf = Secret::generate();
        let mut text = String::new();
        csrf.expose(&mut text);
        assert!(csrf_accepted(&csrf.digest(), Some(&text)));
        assert!(!csrf_accepted(&csrf.digest(), None));
        assert!(!csrf_accepted(&csrf.digest(), Some("")));
        let mut other = String::new();
        Secret::generate().expose(&mut other);
        assert!(!csrf_accepted(&csrf.digest(), Some(&other)));
    }
}
