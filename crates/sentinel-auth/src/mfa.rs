//! Second factors: time-based one-time passwords and one-use recovery codes.
//!
//! The TOTP construction itself comes from the maintained `totp-rs` crate;
//! Sentinel supplies the seed, the policy (SHA-1, 6 digits, 30 seconds, one
//! step of drift — what every authenticator app implements) and, importantly,
//! the replay rule, which RFC 6238 leaves to the caller: a step that has been
//! accepted once is never accepted again.
//!
//! Recovery codes are ordinary high-entropy secrets, stored as digests like
//! every other credential here, and spent one at a time.

use totp_rs::{Algorithm, Builder, Totp};

use crate::secret::Digest;

/// RFC 6238 defaults, and what authenticator apps assume.
const DIGITS: u8 = 6;
const STEP_SECONDS: u64 = 30;
/// One step either side: enough for ordinary clock drift, and no more. A wider
/// window multiplies the codes valid at any instant.
const SKEW: u16 = 1;
/// 160 bits, the size RFC 4226 recommends for HMAC-SHA1.
const SEED_LEN: usize = 20;

pub const RECOVERY_CODE_COUNT: usize = 10;
/// 50 bits of entropy per code, in an alphabet without look-alike characters.
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const RECOVERY_LEN: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub enum MfaError {
    /// The seed is not a usable TOTP secret (wrong length, or unreadable).
    Seed,
    /// The account name or issuer cannot appear in a provisioning URI.
    Label,
}

/// A fresh TOTP seed. Sealed before storage; shown to the enrolling person once.
pub struct Seed([u8; SEED_LEN]);

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed(redacted)")
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0 = core::hint::black_box([0u8; SEED_LEN]);
    }
}

impl Seed {
    pub fn generate() -> Seed {
        let mut bytes = [0u8; SEED_LEN];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        Seed(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Seed, MfaError> {
        let bytes: [u8; SEED_LEN] = bytes.try_into().map_err(|_| MfaError::Seed)?;
        Ok(Seed(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The base32 form authenticator apps display and accept (RFC 4648, no
    /// padding), as carried in a provisioning URI's `secret=` parameter.
    pub fn from_base32(text: &str) -> Result<Seed, MfaError> {
        let secret = totp_rs::Secret::try_from_base32(text).map_err(|_| MfaError::Seed)?;
        Seed::from_bytes(secret.as_ref())
    }

    /// The `otpauth://` provisioning URI, which is what a QR code encodes and
    /// what an app accepts when typed. It contains the seed, so it is shown
    /// exactly once, at enrollment.
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> Result<String, MfaError> {
        self.totp(issuer, account)?
            .to_url()
            .map_err(|_| MfaError::Label)
    }

    fn totp(&self, issuer: &str, account: &str) -> Result<Totp, MfaError> {
        Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(DIGITS)
            .with_step_duration(STEP_SECONDS)
            .with_skew(SKEW)
            .with_secret(self.0.as_slice())
            .with_issuer(Some(issuer))
            .with_account_name(account)
            .build()
            .map_err(|_| MfaError::Label)
    }
}

/// Check a presented code at `unix_seconds`, returning the time step it
/// matched. The caller **must** refuse a step it has already accepted: that is
/// what stops a code shoulder-surfed or replayed within its 30-second window.
#[must_use]
pub fn check(seed: &Seed, code: &str, unix_seconds: u64) -> Option<u64> {
    // Reject anything that is not exactly the expected shape before doing HMAC
    // work, and before the library sees it.
    if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seed.totp("sentinel", "check")
        .ok()?
        .check(code, unix_seconds)
}

/// A recovery code as shown to the person, once.
pub struct RecoveryCode(String);

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(redacted)")
    }
}

impl RecoveryCode {
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// What gets stored. Recovery codes are high-entropy, so a digest is the
    /// right form: no password KDF, and nothing presentable in a backup.
    pub fn digest(&self) -> Digest {
        Digest(*blake3::hash(self.0.as_bytes()).as_bytes())
    }
}

/// A fresh set of recovery codes. Issuing a set replaces any previous one, so
/// codes from an old set stop working the moment new ones are handed out.
pub fn recovery_codes() -> Vec<RecoveryCode> {
    (0..RECOVERY_CODE_COUNT).map(|_| recovery_code()).collect()
}

fn recovery_code() -> RecoveryCode {
    let mut bytes = [0u8; RECOVERY_LEN];
    getrandom::fill(&mut bytes).expect("operating system entropy");
    let mut code = String::with_capacity(RECOVERY_LEN + 1);
    for (at, byte) in bytes.iter().enumerate() {
        if at == RECOVERY_LEN / 2 {
            code.push('-');
        }
        // Modulo bias over a 31-character alphabet is under 1% per character
        // and costs under a bit of the code's 50; rejection sampling here would
        // buy nothing an attacker could use.
        code.push(RECOVERY_ALPHABET[usize::from(*byte) % RECOVERY_ALPHABET.len()] as char);
    }
    RecoveryCode(code)
}

/// Digest a presented recovery code. Normalizes the separator and case that a
/// person may retype, and nothing else.
#[must_use]
pub fn recovery_digest(presented: &str) -> Option<Digest> {
    let normalized: String = presented
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if normalized.len() != RECOVERY_LEN || !normalized.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let mut canonical = normalized;
    canonical.insert(RECOVERY_LEN / 2, '-');
    Some(Digest(*blake3::hash(canonical.as_bytes()).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::digest_eq;

    /// RFC 6238 appendix B, SHA-1, seed "12345678901234567890".
    #[test]
    fn codes_match_the_rfc_6238_reference_vectors() {
        let seed = Seed::from_bytes(b"12345678901234567890").unwrap();
        for (time, code) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
        ] {
            assert_eq!(
                check(&seed, code, time),
                Some(time / STEP_SECONDS),
                "{code}"
            );
        }
        assert_eq!(check(&seed, "287082", 1_234_567_890), None);
    }

    #[test]
    fn drift_is_one_step_either_side_and_the_step_is_reported() {
        let seed = Seed::generate();
        let now = 1_700_000_000u64;
        let code = {
            let totp = seed.totp("sentinel", "check").unwrap();
            totp.generate(now).to_string()
        };
        assert_eq!(check(&seed, &code, now), Some(now / STEP_SECONDS));
        // One step late or early still matches, two does not.
        assert!(check(&seed, &code, now + STEP_SECONDS).is_some());
        assert!(check(&seed, &code, now - STEP_SECONDS).is_some());
        assert!(check(&seed, &code, now + 2 * STEP_SECONDS).is_none());
        assert!(check(&seed, &code, now - 2 * STEP_SECONDS).is_none());
    }

    #[test]
    fn malformed_codes_are_refused_before_any_hmac_work() {
        let seed = Seed::generate();
        for code in ["", "12345", "1234567", "12345a", " 123456", "abcdef"] {
            assert_eq!(check(&seed, code, 1_700_000_000), None, "{code}");
        }
        assert!(Seed::from_bytes(b"short").is_err());
    }

    #[test]
    fn a_provisioning_uri_carries_the_policy_and_the_seed_hides_itself() {
        let seed = Seed::generate();
        let uri = seed.provisioning_uri("Sentinel", "root").unwrap();
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("issuer=Sentinel"));
        assert!(uri.contains("secret="));
        // Defaults (SHA-1, 6 digits, 30 seconds) are omitted from the URI by
        // the library, which is what authenticator apps assume anyway.
        for explicit in ["digits=", "period=", "algorithm="] {
            assert!(!uri.contains(explicit), "{uri}");
        }
        assert_eq!(format!("{seed:?}"), "Seed(redacted)");
    }

    #[test]
    fn recovery_codes_are_distinct_one_use_secrets_that_survive_retyping() {
        let codes = recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(code.expose().to_owned()), "duplicate code");
            assert_eq!(code.expose().len(), RECOVERY_LEN + 1);
            let digest = recovery_digest(code.expose()).unwrap();
            assert!(digest_eq(&digest, &code.digest()));
            // Retyped without the separator, in upper case, with stray spaces.
            let retyped = code.expose().replace('-', "").to_uppercase();
            assert!(digest_eq(
                &recovery_digest(&retyped).unwrap(),
                &code.digest()
            ));
            assert!(digest_eq(
                &recovery_digest(&format!("  {retyped} ")).unwrap(),
                &code.digest()
            ));
        }
        assert_eq!(format!("{:?}", codes[0]), "RecoveryCode(redacted)");
        for malformed in ["", "abc", "abcdefghijk", "abcde-fghi!"] {
            assert!(recovery_digest(malformed).is_none(), "{malformed}");
        }
    }
}
