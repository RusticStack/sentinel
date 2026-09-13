//! Mutation idempotency. A client supplies an `Idempotency-Key`; the server
//! scopes it to (tenant, principal, route) and stores the request body
//! fingerprint with the first response. A repeat with the same fingerprint
//! replays that response; a repeat with a different body is rejected with
//! `idempotency_mismatch`. Keys expire after [`IDEMPOTENCY_TTL_MS`].
use std::fmt;

use crate::limits::MAX_IDEMPOTENCY_KEY_BYTES;

pub const IDEMPOTENCY_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Client-chosen key: 1..=64 bytes of printable ASCII without spaces.
/// Stored inline; no allocation on the request path.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    len: u8,
    bytes: [u8; MAX_IDEMPOTENCY_KEY_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    Empty,
    TooLong,
    InvalidByte,
}

impl IdempotencyKey {
    pub fn parse(raw: &str) -> Result<Self, KeyError> {
        let src = raw.as_bytes();
        if src.is_empty() {
            return Err(KeyError::Empty);
        }
        if src.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(KeyError::TooLong);
        }
        if src.iter().any(|&b| !(0x21..=0x7E).contains(&b)) {
            return Err(KeyError::InvalidByte);
        }
        let mut bytes = [0u8; MAX_IDEMPOTENCY_KEY_BYTES];
        bytes[..src.len()].copy_from_slice(src);
        Ok(Self {
            len: src.len() as u8,
            bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        // Validated ASCII at construction.
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable 128-bit fingerprint of a request body (FNV-1a, 128-bit). Not a
/// cryptographic hash: the only party who can collide it is the caller
/// against their own earlier request, which changes nothing for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Fingerprint(pub u128);

impl Fingerprint {
    pub fn of(body: &[u8]) -> Self {
        const OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
        const PRIME: u128 = 0x0000000001000000000000000000013B;
        let mut h = OFFSET;
        for &b in body {
            h ^= b as u128;
            h = h.wrapping_mul(PRIME);
        }
        Self(h)
    }
}

/// What the server should do with a mutation carrying a key, given what it
/// has stored for that scope and key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// No record (or an expired one): execute and store the response.
    Execute,
    /// Same body seen before: return the stored response without executing.
    Replay,
    /// Same key, different body.
    Mismatch,
    /// First request still in flight: the client should retry shortly.
    InFlight,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored {
    pub fingerprint: Fingerprint,
    pub stored_at_ms: i64,
    /// `false` while the first execution has not completed.
    pub completed: bool,
}

pub const fn decide(stored: Option<Stored>, fingerprint: Fingerprint, now_ms: i64) -> Decision {
    match stored {
        None => Decision::Execute,
        Some(s) if now_ms - s.stored_at_ms > IDEMPOTENCY_TTL_MS => Decision::Execute,
        Some(s) if s.fingerprint.0 != fingerprint.0 => Decision::Mismatch,
        Some(s) if !s.completed => Decision::InFlight,
        Some(_) => Decision::Replay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_bounded_printable_ascii() {
        assert_eq!(IdempotencyKey::parse("").unwrap_err(), KeyError::Empty);
        assert_eq!(
            IdempotencyKey::parse(&"k".repeat(65)).unwrap_err(),
            KeyError::TooLong
        );
        assert_eq!(
            IdempotencyKey::parse("a b").unwrap_err(),
            KeyError::InvalidByte
        );
        assert_eq!(
            IdempotencyKey::parse("ключ").unwrap_err(),
            KeyError::InvalidByte
        );
        let k = IdempotencyKey::parse("dispatch-7f3a").unwrap();
        assert_eq!(k.as_str(), "dispatch-7f3a");
        assert_eq!(
            IdempotencyKey::parse(&"k".repeat(64))
                .unwrap()
                .as_str()
                .len(),
            64
        );
        assert_eq!(std::mem::size_of::<IdempotencyKey>(), 65);
    }

    #[test]
    fn fingerprint_is_stable_and_body_sensitive() {
        assert_eq!(Fingerprint::of(b"{}"), Fingerprint::of(b"{}"));
        assert_ne!(Fingerprint::of(b"{}"), Fingerprint::of(b"{ }"));
        assert_eq!(Fingerprint::of(b"").0, 0x6c62272e07bb014262b821756295c58d);
    }

    #[test]
    fn decisions_follow_body_ttl_and_completion() {
        let f = Fingerprint::of(b"a");
        let rec = |completed, at| {
            Some(Stored {
                fingerprint: f,
                stored_at_ms: at,
                completed,
            })
        };
        assert_eq!(decide(None, f, 0), Decision::Execute);
        assert_eq!(decide(rec(true, 0), f, 1), Decision::Replay);
        assert_eq!(decide(rec(false, 0), f, 1), Decision::InFlight);
        assert_eq!(
            decide(rec(true, 0), Fingerprint::of(b"b"), 1),
            Decision::Mismatch
        );
        assert_eq!(
            decide(rec(true, 0), Fingerprint::of(b"b"), IDEMPOTENCY_TTL_MS + 1),
            Decision::Execute
        );
    }
}
