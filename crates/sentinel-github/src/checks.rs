use serde_json::{Value, json};

use crate::{Error, Result, http::Client};

pub const MAX_NAME: usize = 255;
pub const MAX_TITLE: usize = 128;
pub const MAX_SUMMARY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    InProgress,
    Completed,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }

    pub fn parse(text: &str) -> Option<Status> {
        Some(match text {
            "queued" => Self::Queued,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    TimedOut,
    ActionRequired,
    Skipped,
}

impl Conclusion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::ActionRequired => "action_required",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(text: &str) -> Option<Conclusion> {
        Some(match text {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "neutral" => Self::Neutral,
            "cancelled" => Self::Cancelled,
            "timed_out" => Self::TimedOut,
            "action_required" => Self::ActionRequired,
            "skipped" => Self::Skipped,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub head_sha: String,
    pub status: Status,
    pub conclusion: Option<Conclusion>,
    pub title: String,
    pub summary: String,
    pub external_id: String,
    pub details_url: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    pub check_run_id: i64,
    pub check_suite_id: Option<i64>,
}

fn suite_id(body: &Value) -> Option<i64> {
    body["check_suite"]["id"].as_i64().filter(|id| *id > 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    RateLimited { retry_after_ms: i64 },
    Unauthorized,
    Refused { reason: String },
    Unavailable { reason: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited { retry_after_ms } => {
                write!(f, "rate limited for {retry_after_ms} ms")
            }
            Self::Unauthorized => f.write_str("token refused"),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::Unavailable { reason } => write!(f, "unavailable: {reason}"),
        }
    }
}

fn validate(check: &Check) -> Result<()> {
    if !(1..=MAX_NAME).contains(&check.name.len())
        || check.title.is_empty()
        || check.title.len() > MAX_TITLE
        || check.summary.is_empty()
        || check.summary.len() > MAX_SUMMARY
        || !valid_sha(&check.head_sha)
        || check.external_id.is_empty()
        || check.external_id.len() > 128
        || check.details_url.as_ref().is_some_and(|u| u.len() > 1024)
        || check
            .completed_at
            .as_ref()
            .is_some_and(|at| at.is_empty() || at.len() > 64)
        || (check.status == Status::Completed) != check.conclusion.is_some()
    {
        return Err(Error::Config("check payload"));
    }
    Ok(())
}

fn payload(check: &Check) -> std::result::Result<Value, Refusal> {
    validate(check).map_err(|_| Refusal::Refused {
        reason: "local payload".into(),
    })?;
    let mut body = json!({
        "name": check.name,
        "head_sha": check.head_sha,
        "status": check.status.as_str(),
        "external_id": check.external_id,
        "output": {"title": check.title, "summary": check.summary},
    });
    let map = body.as_object_mut().expect("object");
    if let Some(conclusion) = check.conclusion {
        map.insert("conclusion".into(), Value::from(conclusion.as_str()));
    }
    if let Some(url) = &check.details_url {
        map.insert("details_url".into(), Value::from(url.as_str()));
    }
    if let Some(at) = &check.completed_at {
        map.insert("completed_at".into(), Value::from(at.as_str()));
    }
    Ok(body)
}

fn valid_sha(sha: &str) -> bool {
    (sha.len() == 40 || sha.len() == 64)
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn create(
    client: &Client,
    endpoint: &str,
    token: &str,
    owner: &str,
    repo: &str,
    check: &Check,
) -> std::result::Result<Published, Refusal> {
    let body = payload(check)?;
    let url = format!("{endpoint}/repos/{owner}/{repo}/check-runs");
    let reply = client
        .send_json("POST", &url, token, Some(&body))
        .map_err(|e| Refusal::Unavailable {
            reason: format!("request: {e}"),
        })?;
    match reply.status {
        200 | 201 => match reply.body["id"].as_i64() {
            Some(id) if id > 0 => Ok(Published {
                check_run_id: id,
                check_suite_id: suite_id(&reply.body),
            }),
            _ => Err(Refusal::Refused {
                reason: "no check id".into(),
            }),
        },
        401 => Err(Refusal::Unauthorized),
        403 | 429 => Err(github_refusal(&reply)),
        404 => Err(Refusal::Refused {
            reason: "repository not found".into(),
        }),
        422 => Err(Refusal::Refused {
            reason: bounded_message(&reply.body),
        }),
        _ => Err(Refusal::Unavailable {
            reason: format!("status {}", reply.status),
        }),
    }
}

pub fn update(
    client: &Client,
    endpoint: &str,
    token: &str,
    owner: &str,
    repo: &str,
    check_run_id: i64,
    check: &Check,
) -> std::result::Result<Published, Refusal> {
    let body = payload(check)?;
    let url = format!("{endpoint}/repos/{owner}/{repo}/check-runs/{check_run_id}");
    let reply = client
        .send_json("PATCH", &url, token, Some(&body))
        .map_err(|e| Refusal::Unavailable {
            reason: format!("request: {e}"),
        })?;
    match reply.status {
        200 => Ok(Published {
            check_run_id,
            check_suite_id: suite_id(&reply.body),
        }),
        401 => Err(Refusal::Unauthorized),
        403 | 429 => Err(github_refusal(&reply)),
        404 => Err(Refusal::Refused {
            reason: "check run not found".into(),
        }),
        422 => Err(Refusal::Refused {
            reason: bounded_message(&reply.body),
        }),
        _ => Err(Refusal::Unavailable {
            reason: format!("status {}", reply.status),
        }),
    }
}

pub struct Lookup<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
    pub head_sha: &'a str,
    pub name: &'a str,
    pub external_id: &'a str,
    pub any_status: bool,
}

const FIND_PER_PAGE: usize = 100;
const FIND_MAX_PAGES: usize = 10;
const FIND_MAX_BODY: u64 = 1024 * 1024;

pub fn find(
    client: &Client,
    endpoint: &str,
    token: &str,
    lookup: &Lookup<'_>,
) -> std::result::Result<Option<Published>, Refusal> {
    let (owner, repo, head_sha) = (lookup.owner, lookup.repo, lookup.head_sha);
    let (name, external_id) = (lookup.name, lookup.external_id);
    let name = percent_encode(name);
    for page in 1..=FIND_MAX_PAGES {
        let url = format!(
            "{endpoint}/repos/{owner}/{repo}/commits/{head_sha}/check-runs?filter=all&per_page={FIND_PER_PAGE}&page={page}&check_name={name}"
        );
        let reply = client
            .send_json_bounded("GET", &url, token, None, FIND_MAX_BODY)
            .map_err(|e| Refusal::Unavailable {
                reason: format!("request: {e}"),
            })?;
        match reply.status {
            200 => {
                let Some(list) = reply.body["check_runs"].as_array() else {
                    return Err(Refusal::Refused {
                        reason: "unreadable list".into(),
                    });
                };
                if let Some(found) = select(list, external_id, lookup.any_status) {
                    return Ok(Some(found));
                }
                if list.len() < FIND_PER_PAGE {
                    return Ok(None);
                }
            }
            401 => return Err(Refusal::Unauthorized),
            403 | 429 => return Err(github_refusal(&reply)),
            404 => return Ok(None),
            _ => {
                return Err(Refusal::Unavailable {
                    reason: format!("status {}", reply.status),
                });
            }
        }
    }
    Ok(None)
}

/// A legacy identity is shared by every generation, and GitHub silently ignores a PATCH
/// that reopens an older completed run, so only a live match is adopted.
fn select(list: &[Value], external_id: &str, any_status: bool) -> Option<Published> {
    list.iter()
        .find(|run| {
            run["external_id"].as_str() == Some(external_id)
                && (any_status || run["status"].as_str() != Some("completed"))
        })
        .and_then(|run| {
            run["id"]
                .as_i64()
                .filter(|id| *id > 0)
                .map(|check_run_id| Published {
                    check_run_id,
                    check_suite_id: suite_id(run),
                })
        })
}

pub fn timestamp(now_ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
        .ok()
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

pub fn repository_path(remote: &str) -> Option<(String, String)> {
    let rest = remote.strip_prefix("https://github.com/")?;
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, name) = rest.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.!".contains(&b))
    };
    (valid(owner) && valid(name)).then(|| (owner.to_owned(), name.to_owned()))
}

fn github_refusal(reply: &crate::http::Reply) -> Refusal {
    let now_ms = crate::now_ms();
    let retry_after_ms = reply
        .retry_after_s
        .map(|s| s.clamp(1, 3600).saturating_mul(1000));
    let reset_ms = reply
        .rate_limit_reset_s
        .map(|epoch| epoch.saturating_mul(1000).saturating_sub(now_ms).max(0));
    match retry_after_ms.or(reset_ms) {
        Some(retry_after_ms) => Refusal::RateLimited { retry_after_ms },
        None if reply.status == 429 => Refusal::RateLimited {
            retry_after_ms: 60_000,
        },
        None => Refusal::Refused {
            reason: "forbidden".into(),
        },
    }
}

fn bounded_message(body: &Value) -> String {
    let text = body["message"].as_str().unwrap_or("invalid request");
    let bounded = text
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned();
    // The store's reason column rejects an empty string.
    if bounded.is_empty() {
        "invalid request".to_owned()
    } else {
        bounded
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_paths_are_exact_and_bounded() {
        assert_eq!(
            repository_path("https://github.com/acme/app.git"),
            Some(("acme".into(), "app".into()))
        );
        assert_eq!(
            repository_path("https://github.com/acme/app"),
            Some(("acme".into(), "app".into()))
        );
        for bad in [
            "https://gitlab.com/acme/app.git",
            "https://github.com/acme",
            "https://github.com/acme/app/sub.git",
            "https://github.com//app.git",
            "https://github.com/acme/app.git?x=1",
        ] {
            assert!(repository_path(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn payloads_are_bounded_and_conclusions_match_status() {
        let mut check = Check {
            name: "sentinel / test".into(),
            head_sha: "a".repeat(40),
            status: Status::Completed,
            conclusion: Some(Conclusion::Success),
            title: "Passed".into(),
            summary: "run run_1".into(),
            external_id: "sentinel:run_1:test".into(),
            details_url: Some("https://ci.example/runs/run_1".into()),
            completed_at: None,
        };
        assert!(payload(&check).is_ok());
        check.conclusion = None;
        assert!(payload(&check).is_err());
        check.conclusion = Some(Conclusion::Success);
        check.status = Status::Queued;
        assert!(payload(&check).is_err());
        check.status = Status::Completed;
        check.head_sha = "not a sha".into();
        assert!(payload(&check).is_err());
        check.head_sha = "A".repeat(40);
        assert!(payload(&check).is_err());
        check.head_sha = "b".repeat(40);
        check.summary = "x".repeat(MAX_SUMMARY + 1);
        assert!(payload(&check).is_err());
        assert_eq!(Status::parse("in_progress"), Some(Status::InProgress));
        assert_eq!(Conclusion::parse("timed_out"), Some(Conclusion::TimedOut));
        assert_eq!(Status::parse("done"), None);
        assert_eq!(percent_encode("sentinel / test"), "sentinel%20%2F%20test");
        assert!(timestamp(1_789_344_000_000).starts_with("2026-"));
        check.summary = "run run_1".into();
        check.completed_at = Some("2026-09-14T00:00:00Z".into());
        assert!(payload(&check).is_ok());
        check.completed_at = Some(String::new());
        assert!(payload(&check).is_err());
    }

    #[test]
    fn a_refusal_reason_is_never_empty_and_stays_bounded() {
        for body in [
            serde_json::json!({"message": ""}),
            serde_json::json!({"message": "   "}),
            serde_json::json!({"message": "\u{7}\n\t"}),
            serde_json::json!({}),
        ] {
            assert_eq!(bounded_message(&body), "invalid request", "{body}");
        }
        let long = serde_json::json!({"message": "x".repeat(500)});
        assert_eq!(bounded_message(&long).len(), 120);
    }

    #[test]
    fn a_legacy_identity_adopts_only_a_live_run() {
        let ext = "sentinel:run_1:aggregate";
        let list = serde_json::json!([
            {"id": 7, "external_id": ext, "status": "completed",
             "check_suite": {"id": 90}},
            {"id": 8, "external_id": ext, "status": "in_progress",
             "check_suite": {"id": 91}},
            {"id": 9, "external_id": "sentinel:other", "status": "in_progress"},
        ]);
        let found = select(list.as_array().unwrap(), ext, false).unwrap();
        assert_eq!(found.check_run_id, 8);
        assert_eq!(found.check_suite_id, Some(91));
        let done = serde_json::json!([
            {"id": 7, "external_id": ext, "status": "completed"},
        ]);
        assert!(select(done.as_array().unwrap(), ext, false).is_none());
        assert!(select(&[], ext, false).is_none());
    }

    #[test]
    fn a_per_create_identity_adopts_its_run_whatever_its_status() {
        let ext = "sentinel:run_1:aggregate:3";
        let list = serde_json::json!([
            {"id": 6, "external_id": "sentinel:run_1:aggregate:1", "status": "completed"},
            {"id": 7, "external_id": ext, "status": "completed",
             "check_suite": {"id": 90}},
        ]);
        let found = select(list.as_array().unwrap(), ext, true).unwrap();
        assert_eq!(found.check_run_id, 7);
        assert_eq!(found.check_suite_id, Some(90));
        assert!(select(list.as_array().unwrap(), "sentinel:run_1:aggregate:2", true).is_none());
    }
}
