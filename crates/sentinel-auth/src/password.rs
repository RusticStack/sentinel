//! Local password verification with a maintained Argon2id implementation.
//!
//! Sentinel does not implement the KDF: `argon2` (RustCrypto) owns the hashing
//! and the constant-time comparison, and the stored PHC string owns the
//! parameters so an upgrade can rehash instead of invalidating every account.
//!
//! Hashing deliberately costs ~19 MiB and tens of milliseconds. It must never
//! run inside a database write transaction; callers verify first, then write.

use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::phc::PasswordHash,
};

/// OWASP's second Argon2id option: 19 MiB, two passes, one lane. One lane keeps
/// a login from stealing a whole core's worth of parallel work from job scheduling.
const M_COST: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;

/// Bounds checked before hashing. The lower bound is an admission rule, not a
/// composition rule: no character-class theatre, no silent truncation.
pub const MIN_LEN: usize = 12;
pub const MAX_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    /// Shorter than [`MIN_LEN`] bytes, longer than [`MAX_LEN`], or only spacing.
    Unacceptable,
    /// The maintained implementation refused; never surfaced with the input.
    Hashing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected,
    /// The stored record is unreadable (corrupt or written by a newer build).
    /// Treated as a rejection by callers, but recorded differently.
    Unusable,
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(M_COST, T_COST, P_COST, None).expect("constant argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Reject unusable input before spending the KDF's memory on it.
pub fn acceptable(password: &[u8]) -> Result<(), PasswordError> {
    if password.len() < MIN_LEN
        || password.len() > MAX_LEN
        || password.iter().all(|b| b.is_ascii_whitespace())
    {
        return Err(PasswordError::Unacceptable);
    }
    Ok(())
}

/// Hash with a fresh random salt, returning the PHC string to store verbatim.
pub fn hash(password: &[u8]) -> Result<String, PasswordError> {
    acceptable(password)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).expect("operating system entropy");
    let hash = argon2()
        .hash_password_with_salt(password, &salt)
        .map_err(|_| PasswordError::Hashing)?;
    Ok(hash.to_string())
}

/// Verify a presented password against a stored PHC string. The parameters come
/// from the record, so records written under older parameters still verify.
pub fn verify(stored: &str, password: &[u8]) -> Verdict {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return Verdict::Unusable;
    };
    match argon2().verify_password(password, &parsed) {
        Ok(()) => Verdict::Accepted,
        Err(_) => Verdict::Rejected,
    }
}

/// True when the record was written under weaker parameters than current policy
/// and should be rewritten after a successful verification.
pub fn needs_rehash(stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return true;
    };
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return true;
    }
    match Params::try_from(&parsed) {
        Ok(params) => {
            params.m_cost() < M_COST || params.t_cost() < T_COST || params.p_cost() < P_COST
        }
        Err(_) => true,
    }
}

/// Verify against this when the account does not exist, so an unknown user and
/// a wrong password cost the same wall-clock time and reveal nothing.
pub fn spend_equal_work(password: &[u8]) {
    let _ = verify(placeholder(), password);
}

/// A real Argon2id record under current parameters whose password is unknown
/// and unreachable: it is generated once per process from fresh entropy.
fn placeholder() -> &'static str {
    use std::sync::OnceLock;
    static PLACEHOLDER: OnceLock<String> = OnceLock::new();
    PLACEHOLDER.get_or_init(|| {
        let mut unknown = [0u8; 32];
        getrandom::fill(&mut unknown).expect("operating system entropy");
        hash(&unknown).expect("placeholder record")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_record_accepts_only_its_own_password() {
        let stored = hash(b"correct horse battery staple").unwrap();
        assert_eq!(
            verify(&stored, b"correct horse battery staple"),
            Verdict::Accepted
        );
        assert_eq!(
            verify(&stored, b"correct horse battery stapl"),
            Verdict::Rejected
        );
        assert_eq!(verify(&stored, b""), Verdict::Rejected);
    }

    #[test]
    fn records_are_salted_argon2id_under_current_parameters() {
        let (a, b) = (
            hash(b"same password here").unwrap(),
            hash(b"same password here").unwrap(),
        );
        assert_ne!(a, b, "each record must carry its own salt");
        assert!(a.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{a}");
        assert!(!needs_rehash(&a));
        assert!(!a.contains("same password"));
    }

    #[test]
    fn weaker_or_unreadable_records_verify_but_ask_for_rehash() {
        let weak = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password_with_salt(b"legacy password", b"sixteen-byte-sal")
        .unwrap()
        .to_string();
        assert_eq!(verify(&weak, b"legacy password"), Verdict::Accepted);
        assert!(needs_rehash(&weak));
        assert_eq!(
            verify("not a phc string", b"legacy password"),
            Verdict::Unusable
        );
        assert!(needs_rehash("not a phc string"));
    }

    #[test]
    fn unacceptable_passwords_never_reach_the_kdf() {
        assert_eq!(hash(b"short").unwrap_err(), PasswordError::Unacceptable);
        assert_eq!(
            hash(b"              ").unwrap_err(),
            PasswordError::Unacceptable
        );
        assert_eq!(
            hash(&[b'x'; MAX_LEN + 1]).unwrap_err(),
            PasswordError::Unacceptable
        );
        assert!(hash(&[b'x'; MAX_LEN]).is_ok());
    }
}
