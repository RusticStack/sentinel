//! OAuth token text forms (O02), PKCE (RFC 7636), device user codes and the
//! loopback redirect rule. Pure: nothing here reads a clock, a database or a
//! request, and no token material is formatted through `Debug`/`Display`.
//!
//! Every token is the same 256-bit opaque [`Secret`] a session or an API
//! credential is, behind a kind-specific prefix. Only the digest is stored.
//! The prefixes exist so each kind is refused wherever another is expected
//! before any database work: a refresh token, an authorization code or a
//! device code presented as a bearer is not a bearer, and none of them has
//! the 69-character shape of a `sntl_` credential.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

use crate::{secret::Secret, token};

/// The kinds of OAuth token text. The prefix is part of the compatibility
/// surface: changing one invalidates tokens already in clients' hands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `sntl_at_`: presented as `Authorization: Bearer`.
    Access,
    /// `sntl_rt_`: presented only to the token and revocation endpoints.
    Refresh,
    /// `sntl_ac_`: an authorization code, delivered to a loopback redirect.
    Code,
    /// `sntl_dc_`: a device code, held by the polling client only.
    Device,
}

impl Kind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Kind::Access => ACCESS_PREFIX,
            Kind::Refresh => REFRESH_PREFIX,
            Kind::Code => CODE_PREFIX,
            Kind::Device => DEVICE_PREFIX,
        }
    }
}

pub const ACCESS_PREFIX: &str = "sntl_at_";
pub const REFRESH_PREFIX: &str = "sntl_rt_";
pub const CODE_PREFIX: &str = "sntl_ac_";
pub const DEVICE_PREFIX: &str = "sntl_dc_";

/// Full text length of every OAuth token: an 8-byte prefix and 64 hex.
pub const TEXT_LEN: usize = 8 + Secret::TEXT_LEN;

/// Render for the one response that issues it. The caller must not log it.
#[must_use]
pub fn format(kind: Kind, secret: &Secret) -> String {
    let mut text = String::with_capacity(TEXT_LEN);
    text.push_str(kind.prefix());
    secret.expose(&mut text);
    text
}

/// Accept a presented token of exactly this kind: prefix, length and
/// lower-case hex body, checked before any lookup.
#[must_use]
pub fn parse(kind: Kind, text: &str) -> Option<Secret> {
    if text.len() != TEXT_LEN {
        return None;
    }
    Secret::parse(text.strip_prefix(kind.prefix())?)
}

/// What an `Authorization: Bearer` header may carry.
pub enum Bearer {
    /// A `sntl_` API credential (A03).
    Credential(Secret),
    /// A `sntl_at_` OAuth access token.
    Access(Secret),
}

/// Classify an `Authorization` header value. Refresh tokens, codes, device
/// codes, bare hex and foreign tokens (`gho_…`, `ghp_…`, `github_pat_…`)
/// are `None`, decided by length and prefix alone.
#[must_use]
pub fn bearer(header: &str) -> Option<Bearer> {
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let value = value.trim_start_matches(' ');
    match value.len() {
        token::TEXT_LEN => token::parse(value).map(Bearer::Credential),
        TEXT_LEN => parse(Kind::Access, value).map(Bearer::Access),
        _ => None,
    }
}

/// The device-flow user code alphabet: consonants only, no vowels (no words)
/// and no look-alikes. 20 symbols, 8 of them: about 34.6 bits.
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
/// Canonical user code length, without the display dash.
pub const USER_CODE_LEN: usize = 8;

/// A fresh user code in canonical form (8 characters, no dash). Sampling
/// rejects bytes past the largest multiple of 20, so every symbol is
/// equally likely.
#[must_use]
pub fn user_code() -> String {
    const LIMIT: u8 = 240; // 12 * 20
    let mut out = String::with_capacity(USER_CODE_LEN);
    let mut pool = [0u8; 16];
    while out.len() < USER_CODE_LEN {
        getrandom::fill(&mut pool).expect("operating system entropy");
        for byte in pool {
            if byte < LIMIT && out.len() < USER_CODE_LEN {
                out.push(USER_CODE_ALPHABET[usize::from(byte % 20)] as char);
            }
        }
    }
    out
}

/// A user code as typed by a person: case-insensitive, dashes and spaces
/// ignored. Anything outside the alphabet, or the wrong length, is `None`.
#[must_use]
pub fn normalize_user_code(text: &str) -> Option<String> {
    if text.len() > 32 {
        return None;
    }
    let mut out = String::with_capacity(USER_CODE_LEN);
    for byte in text.bytes() {
        if byte == b'-' || byte == b' ' {
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        if !USER_CODE_ALPHABET.contains(&upper) || out.len() == USER_CODE_LEN {
            return None;
        }
        out.push(upper as char);
    }
    (out.len() == USER_CODE_LEN).then_some(out)
}

/// The display form `XXXX-XXXX` of a canonical user code.
#[must_use]
pub fn display_user_code(canonical: &str) -> String {
    let mut out = String::with_capacity(USER_CODE_LEN + 1);
    // A character boundary, not a byte count: a non-canonical input must
    // never panic here.
    let (a, b) = canonical.split_at(canonical.floor_char_boundary(4));
    out.push_str(a);
    out.push('-');
    out.push_str(b);
    out
}

/// PKCE with the S256 method only (RFC 7636); `plain` is not offered.
pub mod pkce {
    use super::*;

    /// Challenge text length: base64url of a SHA-256 digest, unpadded.
    pub const CHALLENGE_LEN: usize = 43;

    /// A fresh verifier: 32 random bytes as 43 base64url characters.
    #[must_use]
    pub fn verifier() -> String {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn encode_challenge(verifier: &str, out: &mut [u8; CHALLENGE_LEN]) {
        let digest = Sha256::digest(verifier.as_bytes());
        let written = URL_SAFE_NO_PAD
            .encode_slice(digest.as_slice(), out)
            .expect("43 bytes hold a base64url SHA-256");
        debug_assert_eq!(written, CHALLENGE_LEN);
    }

    /// `BASE64URL(SHA256(verifier))`, unpadded.
    #[must_use]
    pub fn challenge(verifier: &str) -> String {
        let mut out = [0u8; CHALLENGE_LEN];
        encode_challenge(verifier, &mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Whether `verifier` is a well-formed RFC 7636 verifier (43–128 of
    /// `ALPHA / DIGIT / "-" / "." / "_" / "~"`).
    #[must_use]
    pub fn verifier_valid(verifier: &str) -> bool {
        (43..=128).contains(&verifier.len())
            && verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    }

    /// Whether a challenge is shaped like an S256 challenge.
    #[must_use]
    pub fn challenge_valid(challenge: &str) -> bool {
        challenge.len() == CHALLENGE_LEN
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// Check a presented verifier against a stored challenge in constant
    /// time. Malformed verifiers and challenges are refused outright.
    #[must_use]
    pub fn verify(verifier: &str, challenge: &str) -> bool {
        if !verifier_valid(verifier) || !challenge_valid(challenge) {
            return false;
        }
        let mut expected = [0u8; CHALLENGE_LEN];
        encode_challenge(verifier, &mut expected);
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(challenge.as_bytes()) {
            diff |= a ^ b;
        }
        core::hint::black_box(diff) == 0
    }
}

/// The port of an acceptable loopback redirect URI (RFC 8252 §7.3), or
/// `None`. Only `http://127.0.0.1:PORT<path>` and `http://[::1]:PORT<path>`
/// with an explicit port 1–65535 and exactly `required_path`: no
/// `localhost` (it can resolve elsewhere), no userinfo, query or fragment.
#[must_use]
pub fn loopback_redirect(uri: &str, required_path: &str) -> Option<u16> {
    let rest = uri.strip_prefix("http://")?;
    let rest = rest
        .strip_prefix("127.0.0.1:")
        .or_else(|| rest.strip_prefix("[::1]:"))?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (port, path) = rest.split_at(digits);
    if port.is_empty() || port.len() > 5 || port.starts_with('0') || path != required_path {
        return None;
    }
    port.parse::<u16>().ok().filter(|p| *p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::digest_eq;

    const KINDS: [Kind; 4] = [Kind::Access, Kind::Refresh, Kind::Code, Kind::Device];

    #[test]
    fn prefixes_are_distinct_and_kinds_do_not_cross() {
        let secret = Secret::generate();
        for (at, kind) in KINDS.iter().enumerate() {
            let text = format(*kind, &secret);
            assert_eq!(text.len(), TEXT_LEN);
            assert!(text.starts_with(kind.prefix()));
            assert_ne!(text.len(), token::TEXT_LEN);
            assert!(digest_eq(
                &parse(*kind, &text).unwrap().digest(),
                &secret.digest()
            ));
            for (other_at, other) in KINDS.iter().enumerate() {
                if other_at != at {
                    assert_ne!(kind.prefix(), other.prefix());
                    assert!(parse(*other, &text).is_none(), "{kind:?} as {other:?}");
                }
            }
            assert!(token::parse(&text).is_none());
        }
    }

    #[test]
    fn only_credentials_and_access_tokens_are_bearers() {
        let secret = Secret::generate();
        let access = format(Kind::Access, &secret);
        let Some(Bearer::Access(parsed)) = bearer(&format!("Bearer {access}")) else {
            panic!("an access token is a bearer");
        };
        assert!(digest_eq(&parsed.digest(), &secret.digest()));
        assert!(matches!(
            bearer(&format!("bearer  {}", token::format(&secret))),
            Some(Bearer::Credential(_))
        ));
        let mut hex = String::new();
        secret.expose(&mut hex);
        for refused in [
            format(Kind::Refresh, &secret),
            format(Kind::Code, &secret),
            format(Kind::Device, &secret),
            hex.clone(),
            format!("gho_{}", &hex[..36]),
            format!("ghp_{}", &hex[..36]),
            format!("github_pat_{}", &hex[..60]),
            format!("sntl_at_{}", hex.to_uppercase()),
            format!("{access}0"),
        ] {
            assert!(bearer(&format!("Bearer {refused}")).is_none(), "{refused}");
        }
        assert!(bearer(&format!("Basic {access}")).is_none());
        assert!(bearer(&access).is_none());
        assert!(bearer(&format!("Bearer {access} extra")).is_none());
    }

    #[test]
    fn pkce_matches_the_rfc_7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce::challenge(verifier), challenge);
        assert!(pkce::verify(verifier, challenge));
        let fresh = pkce::verifier();
        assert_eq!(fresh.len(), 43);
        assert!(pkce::verify(&fresh, &pkce::challenge(&fresh)));
        assert!(!pkce::verify(&fresh, challenge));
    }

    #[test]
    fn plain_short_and_illegal_verifiers_are_refused() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // `plain`: the challenge is the verifier itself.
        assert!(!pkce::verify(verifier, verifier));
        let short = &verifier[..42];
        assert!(!pkce::verify(short, &pkce::challenge(short)));
        let long = "a".repeat(129);
        assert!(!pkce::verify(&long, &pkce::challenge(&long)));
        let max = "a".repeat(128);
        assert!(pkce::verify(&max, &pkce::challenge(&max)));
        let illegal = format!("{}+", &verifier[..42]);
        assert!(!pkce::verify(&illegal, &pkce::challenge(&illegal)));
        let spaced = format!("{} ", &verifier[..42]);
        assert!(!pkce::verify(&spaced, &pkce::challenge(&spaced)));
        assert!(!pkce::verify(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM="
        ));
    }

    #[test]
    fn displaying_a_non_canonical_code_never_splits_a_character() {
        // Byte 4 falls inside the second `é`: the split moves to a boundary.
        assert_eq!(display_user_code("aéé"), "aé-é");
        assert_eq!(display_user_code("€€"), "€-€");
        assert_eq!(display_user_code(""), "-");
    }

    #[test]
    fn user_codes_are_canonical_and_typing_is_forgiving() {
        for _ in 0..64 {
            let code = user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
            let shown = display_user_code(&code);
            assert_eq!(shown.len(), 9);
            assert_eq!(normalize_user_code(&shown).as_deref(), Some(code.as_str()));
            assert_eq!(
                normalize_user_code(&shown.to_lowercase()).as_deref(),
                Some(code.as_str())
            );
        }
        assert_eq!(
            normalize_user_code(" bcdf - ghjk ").as_deref(),
            Some("BCDFGHJK")
        );
        for refused in [
            "BCDFGHJ",
            "BCDFGHJKL",
            "BCDFGHJA",
            "BCDF_GHJK",
            "BCDFGHJ1",
            "",
        ] {
            assert!(normalize_user_code(refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn loopback_redirects_are_exact() {
        assert_eq!(
            loopback_redirect("http://127.0.0.1:53682/callback", "/callback"),
            Some(53682)
        );
        assert_eq!(
            loopback_redirect("http://[::1]:1/callback", "/callback"),
            Some(1)
        );
        assert_eq!(
            loopback_redirect("http://127.0.0.1:65535/callback", "/callback"),
            Some(65535)
        );
        for refused in [
            "http://localhost:53682/callback",
            "https://127.0.0.1:53682/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:053682/callback",
            "http://127.0.0.1:53682/other",
            "http://127.0.0.1:53682/callback/",
            "http://127.0.0.1:53682/callback?x=1",
            "http://127.0.0.1:53682/callback#frag",
            "http://user@127.0.0.1:53682/callback",
            "http://127.0.0.1.evil.example:53682/callback",
            "http://127.0.0.2:53682/callback",
            "HTTP://127.0.0.1:53682/callback",
            "http://[::1]/callback",
        ] {
            assert_eq!(loopback_redirect(refused, "/callback"), None, "{refused}");
        }
    }
}
