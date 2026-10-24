//! The prefix is not a security boundary; it keeps session cookie values from passing as bearer credentials.

use crate::secret::Secret;

/// Changing it breaks credentials already in operators' hands; treat it as a compatibility surface.
pub const PREFIX: &str = "sntl_";

pub const TEXT_LEN: usize = PREFIX.len() + Secret::TEXT_LEN;

/// The caller must not log it.
#[must_use]
pub fn format(secret: &Secret) -> String {
    let mut text = String::with_capacity(TEXT_LEN);
    text.push_str(PREFIX);
    secret.expose(&mut text);
    text
}

#[must_use]
pub fn parse(text: &str) -> Option<Secret> {
    if text.len() != TEXT_LEN {
        return None;
    }
    Secret::parse(text.strip_prefix(PREFIX)?)
}

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
