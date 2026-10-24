use crate::secret::{Digest, Secret, digest_eq};

/// Host-only (no `Domain`): a sibling hostname cannot set or read it.
pub const SESSION_COOKIE: &str = "__Host-sentinel_session";

pub const SIGN_IN_COOKIE: &str = "__Host-sentinel_signin";

pub const CSRF_HEADER: &str = "x-sentinel-csrf";

const ATTRIBUTES: &str = "; Path=/; Secure; HttpOnly; SameSite=Strict";

const SIGN_IN_ATTRIBUTES: &str = "; Path=/; Secure; HttpOnly; SameSite=Lax";

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

pub fn issue_sign_in(secret: &Secret, max_age_secs: u32) -> String {
    let mut header = String::with_capacity(SIGN_IN_COOKIE.len() + Secret::TEXT_LEN + 64);
    header.push_str(SIGN_IN_COOKIE);
    header.push('=');
    secret.expose(&mut header);
    header.push_str(SIGN_IN_ATTRIBUTES);
    header.push_str("; Max-Age=");
    header.push_str(itoa(max_age_secs).as_str());
    header
}

pub fn clear(name: &str) -> String {
    format!("{name}={ATTRIBUTES}; Max-Age=0")
}

/// Returns `None` on a duplicate name: two cookies of one name mean something is injecting them.
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

#[must_use]
pub fn csrf_accepted(expected: &Digest, presented_header: Option<&str>) -> bool {
    let Some(secret) = presented_header.and_then(Secret::parse) else {
        return false;
    };
    digest_eq(&secret.digest(), expected)
}

#[must_use]
pub fn form_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("operating system entropy");
    key
}

pub const FORM_TOKEN_LEN: usize = 64;

#[must_use]
pub fn form_token(key: &[u8; 32], csrf: &Digest) -> String {
    let mut out = String::with_capacity(FORM_TOKEN_LEN);
    out.push_str(blake3::keyed_hash(key, &csrf.0).to_hex().as_str());
    out
}

/// Compares in constant time over the full length, so timing reveals nothing about the token.
#[must_use]
pub fn form_token_accepted(key: &[u8; 32], csrf: &Digest, presented: Option<&str>) -> bool {
    let Some(presented) = presented.filter(|p| p.len() == FORM_TOKEN_LEN) else {
        return false;
    };
    let expected = blake3::keyed_hash(key, &csrf.0).to_hex();
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(presented.as_bytes()) {
        diff |= a ^ b;
    }
    core::hint::black_box(diff) == 0
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
        let pending = issue_sign_in(&secret, 600);
        assert!(
            pending.starts_with(&format!("{SIGN_IN_COOKIE}={text};")),
            "{pending}"
        );
        for attribute in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=600",
        ] {
            assert!(
                pending.contains(attribute),
                "{attribute} missing from {pending}"
            );
        }
        assert!(!pending.contains("Domain="), "{pending}");
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
    fn form_tokens_bind_to_the_key_and_the_session() {
        let (key, other_key) = ([7u8; 32], [8u8; 32]);
        let (csrf, other_csrf) = (Secret::generate().digest(), Secret::generate().digest());
        let token = form_token(&key, &csrf);
        assert_eq!(token.len(), FORM_TOKEN_LEN);
        assert!(form_token_accepted(&key, &csrf, Some(&token)));
        assert!(!form_token_accepted(&other_key, &csrf, Some(&token)));
        assert!(!form_token_accepted(&key, &other_csrf, Some(&token)));
        assert!(!form_token_accepted(&key, &csrf, None));
        assert!(!form_token_accepted(&key, &csrf, Some("")));
        assert!(!form_token_accepted(&key, &csrf, Some(&token[..63])));
        assert!(!form_token_accepted(
            &key,
            &csrf,
            Some(&token.to_uppercase())
        ));
        assert_ne!(token, form_token(&other_key, &csrf));
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
