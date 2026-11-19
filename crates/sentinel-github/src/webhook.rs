//! Verification runs over the raw body: re-serializing JSON changes its bytes and breaks the signature.
use serde_json::Value;

use crate::{Error, Result};

pub const SIGNATURE_HEADER: &str = "x-hub-signature-256";
pub const DELIVERY_HEADER: &str = "x-github-delivery";
pub const EVENT_HEADER: &str = "x-github-event";

const MAX_BODY_FIELDS: usize = 64;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push {
    pub installation: u64,
    pub repository: u64,
    pub ref_name: String,
    pub before: String,
    pub after: String,
    pub created: bool,
    pub deleted: bool,
    pub forced: bool,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequest {
    pub installation: u64,
    pub repository: u64,
    pub number: u64,
    pub action: String,
    pub draft: bool,
    pub head_ref: String,
    pub head_sha: String,
    pub head_repo: u64,
    pub base_ref: String,
    pub base_sha: String,
    pub merge_sha: Option<String>,
}

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

/// A merge-queue group: the commits GitHub merged into its own queue branch. The
/// queue branch names the group — GitHub builds it for the base commit it merged
/// onto — so the pair identifies it for a redelivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeGroup {
    pub installation: u64,
    pub repository: u64,
    pub action: String,
    pub head_ref: String,
    pub head_sha: String,
    pub base_ref: String,
    pub base_sha: String,
    /// Why GitHub destroyed the group (`merged`, `dequeued`, `invalidated`), if it said.
    pub reason: Option<String>,
}

pub fn parse_merge_group(body: &[u8]) -> Result<MergeGroup> {
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
    let group = object
        .get("merge_group")
        .and_then(Value::as_object)
        .ok_or(Error::Response("merge group"))?;
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
    let bounded = |v: Option<&Value>| -> Result<Option<String>> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s))
                if !s.is_empty() && s.len() <= 32 && !s.bytes().any(|b| b < 32 || b == 127) =>
            {
                Ok(Some(s.clone()))
            }
            Some(_) => Err(Error::Response("reason")),
        }
    };
    // GitHub documents the reason beside the action; it has also been delivered
    // inside the group, so either place counts and both are bounded.
    let reason = match bounded(object.get("reason"))? {
        Some(reason) => Some(reason),
        None => bounded(group.get("reason"))?,
    };
    Ok(MergeGroup {
        installation,
        repository,
        action: text(object, "action", 32)?,
        head_ref: text(group, "head_ref", 512)?,
        head_sha: text(group, "head_sha", 64)?,
        base_ref: text(group, "base_ref", 512)?,
        base_sha: text(group, "base_sha", 64)?,
        reason,
    })
}

/// A `workflow_job`: one job of a GitHub-orchestrated workflow, and the label set its
/// `runs-on:` asked for. GitHub delivers `queued`, `in_progress` and `completed` for the
/// same job id, so the job and its run are the identity a Sentinel job is kept under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowJob {
    pub installation: u64,
    pub repository: u64,
    pub action: String,
    pub job: u64,
    pub run: u64,
    /// The labels the workflow asked for; a Sentinel label among them names the class.
    pub labels: Vec<String>,
    /// The runner GitHub assigned, once it has one.
    pub runner: Option<String>,
    /// GitHub's conclusion for a completed job.
    pub conclusion: Option<String>,
}

/// At most this many labels are read from one job; GitHub's own limit is far smaller.
const MAX_JOB_LABELS: usize = 32;
/// The longest single label this build keeps.
const MAX_LABEL_LEN: usize = 128;
/// A job's labels together with their separators, which is what intake stores.
pub const MAX_LABEL_SET_LEN: usize = 512;

pub fn parse_workflow_job(body: &[u8]) -> Result<WorkflowJob> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Error::Response("payload is not JSON"))?;
    let object = value
        .as_object()
        .filter(|o| o.len() <= MAX_BODY_FIELDS + 32)
        .ok_or(Error::Response("payload shape"))?;
    let map_number = |v: &serde_json::Map<String, Value>, key: &'static str| -> Result<u64> {
        v.get(key)
            .and_then(Value::as_u64)
            .filter(|id| *id > 0 && *id <= i64::MAX as u64)
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
    let job = object
        .get("workflow_job")
        .and_then(Value::as_object)
        .ok_or(Error::Response("workflow job"))?;
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
    let bounded = |v: Option<&Value>, key: &'static str, max: usize| -> Result<Option<String>> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s))
                if !s.is_empty() && s.len() <= max && !s.bytes().any(|b| b < 32 || b == 127) =>
            {
                Ok(Some(s.clone()))
            }
            Some(_) => Err(Error::Response(key)),
        }
    };
    let labels = match job.get("labels") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => {
            if values.len() > MAX_JOB_LABELS {
                return Err(Error::Response("labels"));
            }
            let mut labels = Vec::with_capacity(values.len());
            let mut total = 0usize;
            for value in values {
                // A comma separates labels in the runner's own configuration, so one
                // cannot contain one; joining the set for storage therefore round-trips.
                let label = value
                    .as_str()
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= MAX_LABEL_LEN
                            && !s.bytes().any(|b| b < 32 || b == 127 || b == b',')
                    })
                    .ok_or(Error::Response("labels"))?;
                total = total.saturating_add(label.len() + 1);
                labels.push(label.to_owned());
            }
            if total > MAX_LABEL_SET_LEN {
                return Err(Error::Response("labels"));
            }
            labels
        }
        Some(_) => return Err(Error::Response("labels")),
    };
    Ok(WorkflowJob {
        installation,
        repository,
        action: text(object, "action", 32)?,
        job: map_number(job, "id")?,
        run: map_number(job, "run_id")?,
        labels,
        runner: bounded(job.get("runner_name"), "runner", 128)?,
        conclusion: bounded(job.get("conclusion"), "conclusion", 32)?,
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
    Members {
        installation: u64,
        user: Option<u64>,
        removed: bool,
    },
}

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
            // A relay may send only the populated array; absence means nothing was removed.
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
        "organization" if matches!(action, "member_added" | "member_removed") => {
            Some(Control::Members {
                installation,
                user: Some(number(&v["membership"]["user"]["id"])?),
                removed: action == "member_removed",
            })
        }
        "membership" if matches!(action, "added" | "removed") => Some(Control::Members {
            installation,
            user: Some(number(&v["member"]["id"])?),
            removed: false,
        }),
        "member" if matches!(action, "added" | "removed" | "edited") => Some(Control::Members {
            installation,
            user: Some(number(&v["member"]["id"])?),
            removed: false,
        }),
        "team"
            if matches!(
                action,
                "created"
                    | "deleted"
                    | "edited"
                    | "added_to_repository"
                    | "removed_from_repository"
            ) =>
        {
            Some(Control::Members {
                installation,
                user: None,
                removed: false,
            })
        }
        _ => None,
    })
}

/// The event kind is hashed in, so a replay under another event header is a different receipt.
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
        assert!(!verify_signature(
            secret,
            br#"{"ref":"refs/heads/main "}"#,
            &header
        ));
        assert!(!verify_signature(
            secret,
            br#"{ "ref": "refs/heads/main" }"#,
            &header
        ));
        assert!(!verify_signature(b"another-secret-value", body, &header));
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

        let mut no_merge = body.clone();
        no_merge["pull_request"]["merge_commit_sha"] = Value::Null;
        assert!(
            parse_pull_request(&serde_json::to_vec(&no_merge).unwrap())
                .unwrap()
                .merge_sha
                .is_none()
        );
        let mut fork = body.clone();
        fork["pull_request"]["head"]["repo"]["id"] = Value::from(999);
        assert_eq!(
            parse_pull_request(&serde_json::to_vec(&fork).unwrap())
                .unwrap()
                .head_repo,
            999
        );
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
    fn merge_group_payloads_name_the_queue_branch_and_the_commits_github_merged() {
        let body = serde_json::json!({
            "action": "checks_requested",
            "merge_group": {
                "head_ref": "refs/heads/gh-readonly-queue/main/pr-123-abc",
                "head_sha": "a".repeat(40),
                "base_ref": "refs/heads/main",
                "base_sha": "b".repeat(40),
                "head_commit": {"id": "a".repeat(40)},
            },
            "installation": {"id": 42},
            "repository": {"id": 91, "full_name": "account/widget"},
        });
        let group = parse_merge_group(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(group.installation, 42);
        assert_eq!(group.repository, 91);
        assert_eq!(group.action, "checks_requested");
        assert_eq!(
            group.head_ref,
            "refs/heads/gh-readonly-queue/main/pr-123-abc"
        );
        assert_eq!(group.head_sha, "a".repeat(40));
        assert_eq!(group.base_ref, "refs/heads/main");
        assert_eq!(group.base_sha, "b".repeat(40));
        assert_eq!(group.reason, None);

        for placed in [true, false] {
            let mut destroyed = body.clone();
            destroyed["action"] = Value::from("destroyed");
            if placed {
                destroyed["reason"] = Value::from("merged");
            } else {
                destroyed["merge_group"]["reason"] = Value::from("invalidated");
            }
            let group = parse_merge_group(&serde_json::to_vec(&destroyed).unwrap()).unwrap();
            assert_eq!(group.action, "destroyed");
            assert_eq!(
                group.reason.as_deref(),
                Some(if placed { "merged" } else { "invalidated" })
            );
        }

        for (path, value) in [
            ("merge_group", Value::Null),
            ("merge_group", Value::from("refs/heads/main")),
        ] {
            let mut broken = body.clone();
            broken[path] = value;
            assert!(parse_merge_group(&serde_json::to_vec(&broken).unwrap()).is_err());
        }
        let mut missing_base = body.clone();
        missing_base["merge_group"]
            .as_object_mut()
            .unwrap()
            .remove("base_sha");
        assert!(parse_merge_group(&serde_json::to_vec(&missing_base).unwrap()).is_err());
        let mut long_reason = body;
        long_reason["action"] = Value::from("destroyed");
        long_reason["reason"] = Value::String("x".repeat(64));
        assert!(parse_merge_group(&serde_json::to_vec(&long_reason).unwrap()).is_err());
    }

    #[test]
    fn workflow_job_payloads_keep_the_job_its_run_and_its_labels() {
        let body = serde_json::json!({
            "action": "queued",
            "workflow_job": {
                "id": 4001,
                "run_id": 3002,
                "labels": ["self-hosted", "sentinel-4vcpu-ubuntu-2404"],
                "runner_name": null,
                "conclusion": null,
                "steps": [{"name": "Set up job", "status": "queued"}],
            },
            "installation": {"id": 42},
            "repository": {"id": 91, "full_name": "account/widget"},
            "sender": {"login": "someone"},
        });
        let job = parse_workflow_job(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!((job.installation, job.repository), (42, 91));
        assert_eq!(job.action, "queued");
        assert_eq!((job.job, job.run), (4001, 3002));
        assert_eq!(
            job.labels,
            ["self-hosted", "sentinel-4vcpu-ubuntu-2404"]
                .map(str::to_owned)
                .to_vec()
        );
        assert_eq!(job.runner, None);
        assert_eq!(job.conclusion, None);

        let mut started = body.clone();
        started["action"] = Value::from("in_progress");
        started["workflow_job"]["runner_name"] = Value::from("sentinel-runner-7");
        // A field this build does not read is never kept, whatever the sender puts in it.
        started["workflow_job"]["encoded_jit_config"] = Value::from("a-credential-value");
        let job = parse_workflow_job(&serde_json::to_vec(&started).unwrap()).unwrap();
        assert_eq!(job.action, "in_progress");
        assert_eq!(job.runner.as_deref(), Some("sentinel-runner-7"));
        assert!(!format!("{job:?}").contains("a-credential-value"));

        let mut finished = body.clone();
        finished["action"] = Value::from("completed");
        finished["workflow_job"]["conclusion"] = Value::from("success");
        let job = parse_workflow_job(&serde_json::to_vec(&finished).unwrap()).unwrap();
        assert_eq!(job.conclusion.as_deref(), Some("success"));

        let without = |path: &str| {
            let mut body = body.clone();
            if let Some((object, key)) = path.split_once('.') {
                body[object].as_object_mut().unwrap().remove(key);
            } else {
                body.as_object_mut().unwrap().remove(path);
            }
            parse_workflow_job(&serde_json::to_vec(&body).unwrap())
        };
        assert!(without("installation").is_err(), "App deliveries only");
        assert!(without("repository").is_err());
        assert!(without("action").is_err());
        assert!(without("workflow_job.id").is_err());
        assert!(without("workflow_job.run_id").is_err());
        let mut many = body.clone();
        many["workflow_job"]["labels"] = Value::from(
            (0..64)
                .map(|n| Value::String(format!("label-{n}")))
                .collect::<Vec<_>>(),
        );
        assert!(parse_workflow_job(&serde_json::to_vec(&many).unwrap()).is_err());
        let mut long = body.clone();
        long["workflow_job"]["labels"] = Value::from(vec![
            Value::String("x".repeat(200)),
            Value::String("y".into()),
        ]);
        assert!(parse_workflow_job(&serde_json::to_vec(&long).unwrap()).is_err());
        let mut wide = body.clone();
        wide["workflow_job"]["labels"] = Value::from(
            (0..10)
                .map(|n| Value::String(format!("{n}{}", "z".repeat(60))))
                .collect::<Vec<_>>(),
        );
        assert!(parse_workflow_job(&serde_json::to_vec(&wide).unwrap()).is_err());
        let mut no_labels = body;
        no_labels["workflow_job"]
            .as_object_mut()
            .unwrap()
            .remove("labels");
        assert!(
            parse_workflow_job(&serde_json::to_vec(&no_labels).unwrap())
                .unwrap()
                .labels
                .is_empty()
        );
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
        run["check_run"]["external_id"] = Value::from("other:123");
        assert!(parse_control("check_run", &serde_json::to_vec(&run).unwrap()).is_err());
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
    fn membership_events_carry_the_numeric_id_and_only_a_removal_acts() {
        let organization = |action: &str| {
            serde_json::json!({
                "action": action,
                "installation": {"id": 42},
                "membership": {"user": {"id": 1001, "login": "someone"}},
                "organization": {"id": 73},
            })
        };
        for (action, removed) in [("member_removed", true), ("member_added", false)] {
            let parsed = parse_control(
                "organization",
                &serde_json::to_vec(&organization(action)).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert!(
                matches!(
                    parsed,
                    Control::Members { installation: 42, user: Some(1001), removed: r } if r == removed
                ),
                "{action}"
            );
        }
        assert!(
            parse_control(
                "organization",
                &serde_json::to_vec(&organization("renamed")).unwrap()
            )
            .unwrap()
            .is_none()
        );
        for event in ["membership", "member"] {
            let body = serde_json::json!({
                "action": "added",
                "installation": {"id": 42},
                "member": {"id": 2002},
            });
            assert!(matches!(
                parse_control(event, &serde_json::to_vec(&body).unwrap())
                    .unwrap()
                    .unwrap(),
                Control::Members {
                    user: Some(2002),
                    removed: false,
                    ..
                }
            ));
        }
        let team = serde_json::json!({"action": "edited", "installation": {"id": 42}});
        assert!(matches!(
            parse_control("team", &serde_json::to_vec(&team).unwrap())
                .unwrap()
                .unwrap(),
            Control::Members {
                user: None,
                removed: false,
                ..
            }
        ));
        for broken in [
            serde_json::json!({"action":"member_removed","installation":{"id":42},"membership":{"user":{"login":"someone"}}}),
            serde_json::json!({"action":"member_removed","installation":{"id":42},"membership":{"user":{"id":0}}}),
            serde_json::json!({"action":"member_removed","installation":{"id":42}}),
        ] {
            assert!(parse_control("organization", &serde_json::to_vec(&broken).unwrap()).is_err());
        }
    }

    #[test]
    fn the_control_receipt_digest_binds_event_and_body() {
        let body = br#"{"action":"rerequested"}"#;
        let digest = control_digest("check_run", body);
        assert_eq!(digest, control_digest("check_run", body));
        assert_ne!(digest, control_digest("check_suite", body));
        assert_ne!(digest, control_digest("check_run", b"{}"));
    }
}
