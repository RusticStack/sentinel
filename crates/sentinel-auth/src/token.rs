//! Text form of an API credential.
//!
//! The same 256-bit opaque secret as a session, presented with a fixed prefix.
//! The prefix is not security: it exists so secret scanners, log filters and a
//! human reading a pasted string can recognize a Sentinel credential, and so a
//! session cookie value can never be presented as a bearer token by accident.
//!
//! The secret appears in text exactly once, when it is issued. Only its digest
//! is stored, so the deployment cannot show a token again or recover a lost one.

use crate::secret::Secret;

/// Chosen to be greppable and unambiguous. Changing it invalidates nothing
/// stored (only digests are stored), but it does invalidate credentials
/// already in operators' hands, so treat it as a compatibility surface.
pub const PREFIX: &str = "sntl_";

/// Full text length of a presented credential.
pub const TEXT_LEN: usize = PREFIX.len() + Secret::TEXT_LEN;

/// Render for the one response that issues it. The caller must not log it.
#[must_use]
pub fn format(secret: &Secret) -> String {
    let mut text = String::with_capacity(TEXT_LEN);
    text.push_str(PREFIX);
    secret.expose(&mut text);
    text
}

/// Accept a presented credential. Rejects a wrong prefix, wrong length or
/// non-hex body before any database work, so a malformed `Authorization`
/// header costs a length check rather than a lookup.
#[must_use]
pub fn parse(text: &str) -> Option<Secret> {
    if text.len() != TEXT_LEN {
        return None;
    }
    Secret::parse(text.strip_prefix(PREFIX)?)
}

/// Read a credential from an `Authorization` header value. The scheme is
/// matched case-insensitively, as HTTP requires; the credential is not.
#[must_use]
pub fn from_authorization(header: &str) -> Option<Secret> {
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    parse(value.trim_start_matches(' '))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::digest_eq;

    #[test]
    fn credentials_round_trip_through_their_prefixed_text_form() {
        let secret = Secret::generate();
        let text = format(&secret);
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.len(), TEXT_LEN);
        assert!(digest_eq(&parse(&text).unwrap().digest(), &secret.digest()));
    }

    #[test]
    fn a_session_cookie_value_is_not_a_bearer_credential() {
        let secret = Secret::generate();
        let mut bare = String::new();
        secret.expose(&mut bare);
        assert!(parse(&bare).is_none());
        assert!(parse(&format!("other_{bare}")).is_none());
        assert!(parse(&format!("{}{bare}x", PREFIX)).is_none());
        assert!(parse(PREFIX).is_none());
    }

    #[test]
    fn authorization_headers_accept_only_a_bearer_credential() {
        let secret = Secret::generate();
        let text = format(&secret);
        for header in [format!("Bearer {text}"), format!("bearer  {text}")] {
            let parsed = from_authorization(&header).expect("{header}");
            assert!(digest_eq(&parsed.digest(), &secret.digest()));
        }
        assert!(from_authorization(&text).is_none());
        assert!(from_authorization(&format!("Basic {text}")).is_none());
        assert!(from_authorization(&format!("Bearer {text} extra")).is_none());
        assert!(from_authorization("Bearer ").is_none());
    }
}
