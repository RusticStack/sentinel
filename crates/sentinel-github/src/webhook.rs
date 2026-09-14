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

/// A parsed `pull_request` payload. Git refs alone prove nothing about a pull
/// request; these are the fields the adapter did verify, and the resolver
/// decides trust from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequest {
    /// The repository the delivery is for (the base repository).
    pub installation: u64,
    pub repository: u64,
    pub number: u64,
    pub action: String,
    pub draft: bool,
    pub head_ref: String,
    pub head_sha: String,
    /// The immutable numeric repository the head branch lives in: different
    /// from `repository` means a fork.
    pub head_repo: u64,
    pub base_ref: String,
    pub base_sha: String,
    /// The merge commit the change would be tested at, when GitHub computed
    /// one. `None` means there is nothing truthful to check out.
    pub merge_sha: Option<String>,
}

/// Parse the fields of a `pull_request` event, bounded exactly like `push`.
pub fn parse_pull_request(body: &[u8]) -> Result<PullRequest> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Error::Response("payload is not JSON"))?;
    let object = value
        .as_object()
        .filter(|o| o.len() <= MAX_BODY_FIELDS + 32)
        .ok_or(Error::Response("payload shape"))?;
    let map_number = |v: &serde_json::Map<String, Value>, key: &'static str| -> Result<u64> {
        v.get(key)
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(Error::Response(key))
    };
    let installation = map_number(
        object
            .get("installation")
            .and_then(Value::as_object)
            .ok_or(Error::Response("installation id"))?,
        "id",
    )?;
    let repository = map_number(
        object
            .get("repository")
            .and_then(Value::as_object)
            .ok_or(Error::Response("repository id"))?,
        "id",
    )?;
    let pull = object
        .get("pull_request")
        .and_then(Value::as_object)
        .ok_or(Error::Response("pull request"))?;
    let head = pull
        .get("head")
        .and_then(Value::as_object)
        .ok_or(Error::Response("head"))?;
    let base = pull
        .get("base")
        .and_then(Value::as_object)
        .ok_or(Error::Response("base"))?;
    let text = |v: &serde_json::Map<String, Value>,
                key: &'static str,
                max: usize|
     -> Result<String> {
        v.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= max && !s.bytes().any(|b| b < 32 || b == 127))
            .map(str::to_owned)
            .ok_or(Error::Response(key))
    };
    let merge_sha = match pull.get("merge_commit_sha") {
        None | Some(Value::Null) => None,
        Some(Value::String(sha))
            if !sha.is_empty() && sha.len() <= 64 && !sha.bytes().any(|b| b < 32 || b == 127) =>
        {
            Some(sha.clone())
        }
        Some(_) => return Err(Error::Response("merge commit")),
    };
    Ok(PullRequest {
        installation,
        repository,
        // The event carries `number`; older payloads also repeat it under
        // `pull_request`, which is where the bounds of this contract live.
        number: map_number(object, "number").or_else(|_| map_number(pull, "number"))?,
        action: text(object, "action", 32)?,
        draft: pull.get("draft").and_then(Value::as_bool).unwrap_or(false),
        head_ref: text(head, "ref", 512)?,
        head_sha: text(head, "sha", 64)?,
        head_repo: map_number(
            head.get("repo")
                .and_then(Value::as_object)
                .ok_or(Error::Response("head repository"))?,
            "id",
        )?,
        base_ref: text(base, "ref", 512)?,
        base_sha: text(base, "sha", 64)?,
        merge_sha,
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

#[derive(Debug)]
pub enum Control {
    Rerequest {
        installation: u64,
        repository: u64,
        head: String,
        check: Option<(i64, String)>,
        suite: i64,
    },
    Installation {
        installation: u64,
        disable: bool,
    },
    Repositories {
        installation: u64,
        removed: Vec<u64>,
    },
    Repository {
        installation: u64,
        repository: u64,
    },
}

/// Only retained identifiers are trusted. A body is bounded by the HTTP route;
/// repository arrays have an additional admission bound before any write.
pub fn parse_control(event: &str, body: &[u8]) -> Result<Option<Control>> {
    let v: Value = serde_json::from_slice(body).map_err(|_| Error::Response("payload"))?;
    let number = |v: &Value| {
        v.as_u64()
            .filter(|n| *n > 0 && *n <= i64::MAX as u64)
            .ok_or(Error::Response("identifier"))
    };
    let installation = number(&v["installation"]["id"])?;
    let action = v["action"].as_str().ok_or(Error::Response("action"))?;
    Ok(match event {
        "check_run" | "check_suite" if action == "rerequested" => {
            let c = &v[event];
            let head = c["head_sha"]
                .as_str()
                .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or(Error::Response("head sha"))?
                .to_owned();
            let check = if event == "check_run" {
                let external = c["external_id"]
                    .as_str()
                    .filter(|s| s.starts_with("sentinel:") && s.len() <= 128)
                    .ok_or(Error::Response("external id"))?;
                Some((number(&c["id"])? as i64, external.to_owned()))
            } else {
                None
            };
            let suite = number(if check.is_some() {
                &c["check_suite"]["id"]
            } else {
                &c["id"]
            })? as i64;
            Some(Control::Rerequest {
                installation,
                repository: number(&v["repository"]["id"])?,
                head,
                check,
                suite,
            })
        }
        "installation"
            if matches!(
                action,
                "created" | "deleted" | "suspend" | "unsuspend" | "new_permissions_accepted"
            ) =>
        {
            Some(Control::Installation {
                installation,
                disable: matches!(action, "deleted" | "suspend"),
            })
        }
        "installation_repositories" if matches!(action, "added" | "removed") => {
            // GitHub sends both arrays; a relay may carry only the populated
            // one. Absence of `repositories_removed` means nothing was removed.
            let removed = match v["repositories_removed"].as_array() {
                Some(list) if list.len() <= 1024 => list
                    .iter()
                    .map(|r| number(&r["id"]))
                    .collect::<Result<Vec<_>>>()?,
                Some(_) => return Err(Error::Response("repository limit")),
                None => Vec::new(),
            };
            Some(Control::Repositories {
                installation,
                removed,
            })
        }
        "repository" if matches!(action, "renamed" | "transferred" | "deleted" | "archived") => {
            Some(Control::Repository {
                installation,
                repository: number(&v["repository"]["id"])?,
            })
        }
        _ => None,
    })
}

/// Event kind is part of the receipt digest: replay under a different header
/// must not be mistaken for the original control event.
pub fn control_digest(event: &str, body: &[u8]) -> [u8; 32] {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(event.as_bytes());
    digest.update(&[0]);
    digest.update(body);
    digest.finish().as_ref().try_into().expect("SHA256 length")
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
    fn pull_request_payloads_keep_only_verified_fields() {
        let body = serde_json::json!({
            "action": "opened",
            "number": 7,
            "installation": {"id": 42},
            "repository": {"id": 91, "full_name": "account/widget"},
            "pull_request": {
                "draft": false,
                "head": {"ref": "feature", "sha": "c".repeat(40), "repo": {"id": 91}},
                "base": {"ref": "main", "sha": "d".repeat(40)},
                "merge_commit_sha": "e".repeat(40),
            },
        });
        let pr = parse_pull_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(pr.installation, 42);
        assert_eq!(pr.repository, 91);
        assert_eq!(pr.number, 7);
        assert_eq!(pr.action, "opened");
        assert_eq!(pr.head_ref, "feature");
        assert_eq!(pr.head_repo, 91);
        assert_eq!(pr.base_ref, "main");
        assert_eq!(pr.merge_sha.as_deref().unwrap().len(), 40);
        assert!(!pr.draft);

        // A null merge commit is a fact, not an error: there is nothing
        // truthful to test.
        let mut no_merge = body.clone();
        no_merge["pull_request"]["merge_commit_sha"] = Value::Null;
        assert!(
            parse_pull_request(&serde_json::to_vec(&no_merge).unwrap())
                .unwrap()
                .merge_sha
                .is_none()
        );
        // A fork head is recorded, never flattened into the base repository.
        let mut fork = body.clone();
        fork["pull_request"]["head"]["repo"]["id"] = Value::from(999);
        assert_eq!(
            parse_pull_request(&serde_json::to_vec(&fork).unwrap())
                .unwrap()
                .head_repo,
            999
        );
        // Missing or malformed pieces are refused without echoing them.
        for (path, value) in [
            ("pull_request", Value::Null),
            ("number", Value::Null),
            ("action", Value::from("")),
            ("pull_request", Value::Null),
        ] {
            let mut broken = body.clone();
            match path {
                "pull_request" => broken["pull_request"] = value,
                other => broken[other] = value,
            }
            assert!(parse_pull_request(&serde_json::to_vec(&broken).unwrap()).is_err());
        }
        let mut bad_sha = body;
        bad_sha["pull_request"]["head"]["sha"] = Value::from("not a sha");
        assert!(
            parse_pull_request(&serde_json::to_vec(&bad_sha).unwrap()).is_ok(),
            "bounds are the ingest's job"
        );
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

    #[test]
    fn control_events_keep_only_bounded_identifiers() {
        let base = |action: &str| {
            serde_json::json!({
                "action": action,
                "installation": {"id": 42},
                "repository": {"id": 91},
            })
        };
        // A check-run rerequest carries the check's handles; a suite
        // rerequest carries the suite's.
        let mut run = base("rerequested");
        run["check_run"] = serde_json::json!({
            "id": 4242,
            "head_sha": "b".repeat(40),
            "external_id": "sentinel:run:job",
            "check_suite": {"id": 9001},
        });
        let parsed = parse_control("check_run", &serde_json::to_vec(&run).unwrap())
            .unwrap()
            .unwrap();
        let Control::Rerequest {
            installation,
            repository,
            head,
            check,
            suite,
        } = parsed
        else {
            panic!("not a rerequest")
        };
        assert_eq!((installation, repository, suite), (42, 91, 9001));
        assert_eq!(head, "b".repeat(40));
        assert_eq!(check, Some((4242, "sentinel:run:job".to_owned())));
        let mut suite_event = base("rerequested");
        suite_event["check_suite"] = serde_json::json!({"id": 9001, "head_sha": "b".repeat(40)});
        let parsed = parse_control("check_suite", &serde_json::to_vec(&suite_event).unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(
            parsed,
            Control::Rerequest {
                check: None,
                suite: 9001,
                ..
            }
        ));
        // An external ID that is not ours is refused, not parsed.
        run["check_run"]["external_id"] = Value::from("other:123");
        assert!(parse_control("check_run", &serde_json::to_vec(&run).unwrap()).is_err());
        // A non-rerequest action and an unknown event are ignored, not errors.
        let edited = base("edited");
        assert!(
            parse_control("repository", &serde_json::to_vec(&edited).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_control("unknown_event", &serde_json::to_vec(&edited).unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn installation_and_repository_control_events_parse() {
        let installation =
            |action: &str| serde_json::json!({"action": action, "installation": {"id": 42}});
        for (action, disable) in [
            ("created", false),
            ("deleted", true),
            ("suspend", true),
            ("unsuspend", false),
            ("new_permissions_accepted", false),
        ] {
            let parsed = parse_control(
                "installation",
                &serde_json::to_vec(&installation(action)).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert!(
                matches!(parsed, Control::Installation { installation: 42, disable: d } if d == disable),
                "{action}"
            );
        }
        let removed = serde_json::json!({
            "action": "removed",
            "installation": {"id": 42},
            "repositories_removed": [{"id": 91}, {"id": 92}],
        });
        let parsed = parse_control(
            "installation_repositories",
            &serde_json::to_vec(&removed).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            parsed,
            Control::Repositories { installation: 42, ref removed } if *removed == vec![91, 92]
        ));
        // An `added` delivery may carry only the populated array.
        let added = serde_json::json!({
            "action": "added",
            "installation": {"id": 42},
            "repositories_added": [{"id": 91}],
        });
        assert!(matches!(
            parse_control("installation_repositories", &serde_json::to_vec(&added).unwrap())
                .unwrap()
                .unwrap(),
            Control::Repositories { ref removed, .. } if removed.is_empty()
        ));
        for action in ["renamed", "transferred", "deleted", "archived"] {
            let body = serde_json::json!({
                "action": action,
                "installation": {"id": 42},
                "repository": {"id": 91},
            });
            assert!(matches!(
                parse_control("repository", &serde_json::to_vec(&body).unwrap())
                    .unwrap()
                    .unwrap(),
                Control::Repository {
                    installation: 42,
                    repository: 91
                }
            ));
        }
        // The repository array is bounded before any of it is stored.
        let over = serde_json::json!({
            "action": "removed",
            "installation": {"id": 42},
            "repositories_removed": vec![serde_json::json!({"id": 1}); 1025],
        });
        assert!(matches!(
            parse_control(
                "installation_repositories",
                &serde_json::to_vec(&over).unwrap()
            ),
            Err(Error::Response("repository limit"))
        ));
    }

    #[test]
    fn the_control_receipt_digest_binds_event_and_body() {
        let body = br#"{"action":"rerequested"}"#;
        let digest = control_digest("check_run", body);
        assert_eq!(digest, control_digest("check_run", body));
        // The same body under a different event header is a different event.
        assert_ne!(digest, control_digest("check_suite", body));
        assert_ne!(digest, control_digest("check_run", b"{}"));
    }
}
