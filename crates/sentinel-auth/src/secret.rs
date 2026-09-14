//! Opaque 256-bit session and CSRF secrets.
//!
//! A secret is never stored: the database holds its BLAKE3 digest, so a stolen
//! snapshot cannot be replayed as a cookie. Lookup is by digest, a full 32-byte
//! primary key probe, so validation costs one index search and no scan.

use core::fmt;

/// Bytes of a freshly minted or presented secret. Carries no `Debug`/`Display`.
pub struct Secret([u8; Secret::LEN]);

/// The stored form: `BLAKE3(secret)`. Safe to log, index and compare.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Secret {
    pub const LEN: usize = 32;
    /// Hex, so `Display`/parse need no allocation and no encoding dependency.
    pub const TEXT_LEN: usize = Secret::LEN * 2;

    /// Fresh secret from the operating system CSPRNG. Failing to obtain entropy
    /// is fatal: issuing a guessable session is not an acceptable degradation.
    pub fn generate() -> Secret {
        let mut bytes = [0u8; Secret::LEN];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        Secret(bytes)
    }

    /// Accept a presented secret. Rejects anything that is not exactly the
    /// expected lower-case hex length, before any database work.
    pub fn parse(text: &str) -> Option<Secret> {
        let text = text.as_bytes();
        if text.len() != Secret::TEXT_LEN {
            return None;
        }
        let mut bytes = [0u8; Secret::LEN];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(Secret(bytes))
    }

    pub fn digest(&self) -> Digest {
        Digest(*blake3::hash(&self.0).as_bytes())
    }

    /// Render for the one place it may appear: the response that issues it.
    pub fn expose(&self, out: &mut String) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.reserve(Secret::TEXT_LEN);
        for byte in self.0 {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best effort only: copies made by the caller are the caller's problem.
        self.0 = core::hint::black_box([0u8; Secret::LEN]);
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the first bytes: enough to correlate audit records, useless as a key.
        write!(
            f,
            "digest:{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Constant-time equality for digests of secrets. `black_box` keeps the
/// accumulator from being turned back into an early-exit comparison.
#[must_use]
pub fn digest_eq(a: &Digest, b: &Digest) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a.0[i] ^ b.0[i];
    }
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_round_trip_through_their_only_text_form() {
        let secret = Secret::generate();
        let mut text = String::new();
        secret.expose(&mut text);
        assert_eq!(text.len(), Secret::TEXT_LEN);
        let parsed = Secret::parse(&text).expect("round trip");
        assert!(digest_eq(&parsed.digest(), &secret.digest()));
    }

    #[test]
    fn malformed_presentations_are_rejected_before_lookup() {
        let mut text = String::new();
        Secret::generate().expose(&mut text);
        assert!(Secret::parse("").is_none());
        assert!(Secret::parse(&text[..Secret::TEXT_LEN - 1]).is_none());
        assert!(Secret::parse(&format!("{text}0")).is_none());
        assert!(Secret::parse(&text.to_uppercase()).is_none());
        assert!(Secret::parse(&format!("{}zz", &text[..Secret::TEXT_LEN - 2])).is_none());
    }

    #[test]
    fn distinct_secrets_have_distinct_digests_and_hide_their_material() {
        let (a, b) = (Secret::generate(), Secret::generate());
        assert!(!digest_eq(&a.digest(), &b.digest()));
        let mut text = String::new();
        a.expose(&mut text);
        assert!(!format!("{a:?}").contains(&text));
        assert!(!format!("{:?}", a.digest()).contains(&text));
    }
}
