//! GitHub webhook intake: raw-body signature verification and the ref-update
//! fields the shared intake needs.
//!
//! The signature is HMAC-SHA256 over the **raw body** exactly as received —
//! re-serializing JSON would change bytes and invalidate it — compared in
//! constant time by the ring implementation. The secret is the App's webhook
//! secret, configured out of band; this module never stores or prints it.
use serde_json::Value;

use crate::{Error, Result};

pub const SIGNATURE_HEADER: &str = "x-hub-signature-256";
pub const DELIVERY_HEADER: &str = "x-github-delivery";
pub const EVENT_HEADER: &str = "x-github-event";

/// GitHub's own delivery IDs are UUIDs; the shared contract allows a little
/// more so a relay can reuse this shape.
const MAX_BODY_FIELDS: usize = 64;

/// True when `signature` (`sha256=<hex>`) authenticates `body` under `secret`.
/// A malformed header, wrong length or different key is `false`, and the
/// comparison itself is constant time.
pub fn verify_signature(secret: &[u8], body: &[u8], signature: &str) -> bool {
    if secret.is_empty() || secret.len() > 256 {
        return false;
    }
    let Some(hex) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Some(expected) = decode_hex32(hex) else {
        return false;
    };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    ring::hmac::verify(&key, body, &expected).is_ok()
}

/// A parsed `push` payload: the ref transition plus the immutable identifiers
/// that decide which tenant it belongs to. Everything else in the payload is
/// deliberately ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push {
    /// Numeric installation ID, when the delivery came through the App.
    pub installation: u64,
    /// Immutable numeric repository ID.
    pub repository: u64,
    pub ref_name: String,
    pub before: String,
    pub after: String,
    pub created: bool,
    pub deleted: bool,
    pub forced: bool,
}

/// Parse the fields of a `push` event. Bounds every string it keeps, so a
/// hostile payload cannot make the controller store or compare unbounded data.
pub fn parse_push(body: &[u8]) -> Result<Push> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Error::Response("payload is not JSON"))?;
    let object = value
        .as_object()
        .filter(|o| o.len() <= MAX_BODY_FIELDS + 32)
        .ok_or(Error::Response("payload shape"))?;
    let installation = object
        .get("installation")
        .and_then(|v| v.get("id"))
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(Error::Response("installation id"))?;
    let repository = object
        .get("repository")
        .and_then(|v| v.get("id"))
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(Error::Response("repository id"))?;
    let text = |key: &'static str, max: usize| -> Result<String> {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= max && !s.bytes().any(|b| b < 32 || b == 127))
            .map(str::to_owned)
            .ok_or(Error::Response(key))
    };
    let flag = |key: &'static str| object.get(key).and_then(Value::as_bool).unwrap_or(false);
    Ok(Push {
        installation,
        repository,
        ref_name: text("ref", 1024)?,
        before: text("before", 64)?,
        after: text("after", 64)?,
        created: flag("created"),
        deleted: flag("deleted"),
        forced: flag("forced"),
    })
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented GitHub example: HMAC-SHA256("It's a Secret to
    /// Everybody", body) with the well-known secret.
    fn sign(secret: &[u8], body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let tag = ring::hmac::sign(&key, body);
        let mut out = String::from("sha256=");
        for byte in tag.as_ref() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn raw_body_hmac_is_required_and_exact() {
        let secret = b"a-webhook-secret-value";
        let body = br#"{"ref":"refs/heads/main"}"#;
        let header = sign(secret, body);
        assert!(verify_signature(secret, body, &header));
        // One byte different: refused.
        assert!(!verify_signature(
            secret,
            br#"{"ref":"refs/heads/main "}"#,
            &header
        ));
        // Whitespace-reformatted JSON is a different body.
        assert!(!verify_signature(
            secret,
            br#"{ "ref": "refs/heads/main" }"#,
            &header
        ));
        assert!(!verify_signature(b"another-secret-value", body, &header));
        // Malformed headers never reach the comparison.
        for bad in [
            "",
            "sha256=",
            "sha1=deadbeef",
            &header[..header.len() - 1],
            "sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(!verify_signature(secret, body, bad), "{bad:?}");
        }
        assert!(!verify_signature(b"", body, &header));
    }

    #[test]
    fn push_payloads_keep_only_bounded_identifiers() {
        let body = serde_json::json!({
            "ref": "refs/heads/main",
            "before": "0".repeat(40),
            "after": "a".repeat(40),
            "created": true,
            "deleted": false,
            "forced": true,
            "installation": {"id": 42},
            "repository": {"id": 73, "full_name": "acme/app", "private": true},
            "commits": [{"id": "a".repeat(40)}],
            "sender": {"login": "someone"},
        });
        let push = parse_push(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(push.installation, 42);
        assert_eq!(push.repository, 73);
        assert_eq!(push.ref_name, "refs/heads/main");
        assert!(push.created && push.forced && !push.deleted);

        let without = |key: &str| {
            let mut body = body.clone();
            body.as_object_mut().unwrap().remove(key);
            parse_push(&serde_json::to_vec(&body).unwrap())
        };
        assert!(without("installation").is_err(), "app deliveries only");
        assert!(without("repository").is_err());
        assert!(matches!(without("ref"), Err(Error::Response("ref"))));

        let mut oversize = body.clone();
        oversize["ref"] = Value::String(format!("refs/heads/{}", "x".repeat(2000)));
        assert!(oversize_ref_rejected(&oversize));
        let mut wrong_type = body;
        wrong_type["after"] = Value::Bool(true);
        assert!(parse_push(&serde_json::to_vec(&wrong_type).unwrap()).is_err());
    }

    fn oversize_ref_rejected(body: &Value) -> bool {
        parse_push(&serde_json::to_vec(body).unwrap()).is_err()
    }
}
