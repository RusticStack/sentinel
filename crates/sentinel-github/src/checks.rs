//! The Checks API, as much of it as G04 needs: create one check run, update
//! it, and find one we already created after an ambiguous timeout.
//!
//! Statuses and conclusions are GitHub's own text, validated here rather than
//! by the database: a caller cannot publish an unknown conclusion. A refusal
//! carries a short reason suitable for an operator; bodies are never echoed
//! (they can quote the request).

use serde_json::{Value, json};

use crate::{Error, Result, http::Client};

/// Longest check-run name GitHub accepts.
pub const MAX_NAME: usize = 255;
/// Longest output title we send.
pub const MAX_TITLE: usize = 128;
/// Longest output summary we send (GitHub allows 65,535; ours is one line).
pub const MAX_SUMMARY: usize = 1024;

/// `status` of a check run.
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

/// `conclusion` of a completed check run, exactly GitHub's vocabulary.
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

/// One check run to create or update.
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
    /// Used only when the status is `completed`.
    pub completed_at: Option<String>,
}

/// A check run GitHub accepted: the numeric id the update path needs, and
/// the suite it landed in when the response carried one — that suite id is
/// what a `check_suite` rerequest names (G05).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    pub check_run_id: i64,
    pub check_suite_id: Option<i64>,
}

/// The check suite of a check-run object, when present.
fn suite_id(body: &Value) -> Option<i64> {
    body["check_suite"]["id"].as_i64().filter(|id| *id > 0)
}

/// Why a publication did not land. The caller decides what is retryable; this
/// module never guesses on its behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The rate limit is spent; try again after this many milliseconds.
    RateLimited { retry_after_ms: i64 },
    /// The token was refused (expired, or the installation lost the
    /// permission). A fresh token may work; a fresh token that is refused
    /// again will not.
    Unauthorized,
    /// GitHub understood the request and said no: a bounded reason only.
    Refused { reason: String },
    /// The request did not complete, or GitHub answered 5xx.
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

/// Bounds the payload before any request; a caller bug must not reach GitHub.
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

/// Create one check run for `owner/name`.
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

/// Update the check run GitHub already knows.
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

/// What an adoption lookup is about: the commit, the check name and the
/// `external_id` we set when we created it.
pub struct Lookup<'a> {
    pub owner: &'a str,
    pub repo: &'a str,
    pub head_sha: &'a str,
    pub name: &'a str,
    pub external_id: &'a str,
    /// The identity names exactly one create (it carries the generation), so
    /// a match is ours whatever its status — including a run created already
    /// `completed`. A legacy identity shared by every generation of a row
    /// adopts only a live run.
    pub any_status: bool,
}

/// Runs per lookup page, pages per lookup, and the byte ceiling of one page.
/// A check run object with its app and output is a few KiB; a page of 100 is
/// comfortably inside 1 MiB, and ten pages cover a thousand reruns of one
/// check on one commit.
const FIND_PER_PAGE: usize = 100;
const FIND_MAX_PAGES: usize = 10;
const FIND_MAX_BODY: u64 = 1024 * 1024;

/// Find a check run we already created for this commit and name, by the
/// `external_id` we set. This is how an ambiguous create is reconciled: the
/// request timed out, GitHub may or may not have made the run, so the retry
/// looks before it writes. The listing is paged and every page is bounded,
/// so a commit with many reruns neither overflows one answer nor hides the
/// run we are looking for past the first page.
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

/// Pick the adoptable run from a lookup list. With a per-create identity
/// the exact match is the run that create made, whatever its status. With a
/// legacy identity a `completed` match may be an older generation's run —
/// immutable on GitHub, where a PATCH reopening it is silently ignored — so
/// only a live run is adopted.
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

/// An RFC3339 UTC timestamp for `completed_at`; empty when the clock is
/// outside what `time` can represent, which the payload validator refuses.
pub fn timestamp(now_ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
        .ok()
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// The `owner/name` a GitHub HTTPS clone URL names, if it is one. The binding
/// verified this URL against the repository's own `clone_url`, so the path is
/// the repository's canonical name rather than a guess from user input.
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

/// GitHub's rate-limit refusals are the one case a caller must schedule
/// rather than refuse: prefer `Retry-After`, else the reset epoch.
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

/// One bounded, control-free line from a GitHub error body.
fn bounded_message(body: &Value) -> String {
    let text = body["message"].as_str().unwrap_or("invalid request");
    text.chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Minimal percent-encoding for a query value: names may contain spaces and
/// slashes from the job name charset.
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
    fn a_legacy_identity_adopts_only_a_live_run() {
        // A bare row identity is shared by every generation: a completed
        // match may be an older generation's immutable run, so adoption
        // passes it by.
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
        // The create for generation 3 carried `…:3`: a completed run with
        // exactly that identity is the one that create made.
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
