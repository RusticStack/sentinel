//! The generic ref-update event contract (G02).
//!
//! One authenticated delivery is one ref transition: a stable delivery ID
//! chosen by the sender, the full ref name, and the old and new object IDs.
//! A commit ID alone is not a delivery identity — returning a ref to an
//! earlier commit is a distinct transition — so both ends are carried and the
//! delivery ID exists to make redelivery idempotent.
//!
//! Field bounds here are the wire's; the store's CHECK constraints repeat
//! them, so a route cannot insert anything this contract would not have
//! accepted.
use serde::{Deserialize, Serialize};

/// Body cap for the generic intake route. The payload is a handful of fields.
pub const MAX_HOOK_BODY_BYTES: usize = 64 * 1024;
/// Body cap for provider webhooks. A push payload with a long commit list can
/// outgrow the generic contract; GitHub truncates that list, so this bounds
/// the request rather than the event.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DELIVERY_ID_BYTES: usize = 128;
pub const MAX_REF_BYTES: usize = 1024;
pub const MAX_SHA_BYTES: usize = 64;
/// The one presentation of a repository hook secret. The prefix keeps it
/// distinguishable from an API credential and from a Git remote credential.
pub const HOOK_TOKEN_PREFIX: &str = "sentinel_hook_";

/// A sender-chosen, stable delivery identity. Bounded printable ASCII: it is
/// stored, indexed and compared, never parsed.
pub fn valid_delivery_id(value: &str) -> bool {
    (1..=MAX_DELIVERY_ID_BYTES).contains(&value.len())
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A full Git ref as a sender may report it. The *binding* decides which refs
/// a repository accepts; this only rejects values that are not refs at all.
pub fn valid_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() <= MAX_REF_BYTES
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.ends_with(".lock")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
        && value
            .split('/')
            .all(|s| !s.is_empty() && !s.starts_with('.'))
}

/// A SHA-1 (40) or SHA-256 (64) object ID in canonical lower-case hex.
pub fn valid_sha(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The all-zero object ID Git reports for a creation or a deletion.
pub fn is_zero_sha(value: &str) -> bool {
    valid_sha(value) && value.bytes().all(|b| b == b'0')
}

/// The generic relay's request body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefUpdate {
    /// Stable across redeliveries of the same event; unique across events.
    pub delivery_id: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
}

impl RefUpdate {
    /// Bounded, canonical shape. Returns the first violation, never the value.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_delivery_id(&self.delivery_id) {
            return Err("delivery id");
        }
        if !valid_ref(&self.ref_name) {
            return Err("ref");
        }
        if !valid_sha(&self.old_sha) || !valid_sha(&self.new_sha) {
            return Err("object id");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_ids_refs_and_object_ids_are_exactly_bounded() {
        assert!(valid_delivery_id("d-1"));
        assert!(!valid_delivery_id(""));
        assert!(!valid_delivery_id("with space"));
        assert!(!valid_delivery_id("with\ttab"));
        assert!(!valid_delivery_id(&"x".repeat(MAX_DELIVERY_ID_BYTES + 1)));

        assert!(valid_ref("refs/heads/main"));
        assert!(valid_ref("refs/tags/v1.0.0"));
        assert!(!valid_ref("main"));
        assert!(!valid_ref("refs/heads/"));
        assert!(!valid_ref("refs/heads/x..y"));
        assert!(!valid_ref("refs/heads/x y"));
        assert!(!valid_ref("refs/heads/x~1"));
        assert!(!valid_ref(&format!(
            "refs/heads/{}",
            "x".repeat(MAX_REF_BYTES)
        )));

        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert!(valid_sha(sha));
        assert!(!valid_sha(&sha.to_uppercase()));
        assert!(!valid_sha(&sha[..39]));
        assert!(is_zero_sha(&"0".repeat(40)));
        assert!(!is_zero_sha(sha));
    }

    #[test]
    fn a_wire_update_rejects_a_foreign_shape_without_echoing_it() {
        let body = serde_json::json!({
            "delivery_id": "hook-1",
            "ref": "refs/heads/main",
            "old_sha": "0".repeat(40),
            "new_sha": "a".repeat(40),
        });
        let update: RefUpdate = serde_json::from_value(body).unwrap();
        assert!(update.validate().is_ok());
        // Unknown keys are refused: a sender cannot smuggle fields in.
        let extra = serde_json::json!({
            "delivery_id": "hook-1", "ref": "refs/heads/main",
            "old_sha": "0".repeat(40), "new_sha": "a".repeat(40), "extra": 1,
        });
        assert!(serde_json::from_value::<RefUpdate>(extra).is_err());
        let bad = RefUpdate {
            delivery_id: "hook-2".into(),
            ref_name: "not-a-ref".into(),
            old_sha: "0".repeat(40),
            new_sha: "a".repeat(40),
        };
        assert_eq!(bad.validate(), Err("ref"));
    }
}
