//! The Actions jobs endpoint (`GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs`), decoded for
//! the shadow-parity report: what GitHub states each job concluded, the commit it ran, the labels
//! its `runs-on:` asked for, and how long it took.
//!
//! The parity gate reads a recorded response rather than a live one, so [`decode_page`] is a pure
//! function of the body with a bound on everything it keeps: at most one page of jobs, each with a
//! bounded name, labels and duration. An entry it cannot read is dropped, because a page with one
//! malformed job is still evidence about the others, and the parity report lists what it could not
//! pair rather than guessing. The per-step records the same response carries are not decoded: the
//! comparison is per job pair, and a step's own timing is what the job's duration already holds.

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Error, Result};

/// One page of jobs. GitHub's own maximum `per_page` is 100, so a body past it was not one page.
pub const MAX_JOBS: usize = 100;
pub const MAX_NAME: usize = 512;
pub const MAX_LABELS: usize = 32;
pub const MAX_LABEL: usize = 64;

/// One job of a workflow run, as the response stated it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// GitHub's job id: the identity a `workflow_job` delivery and a runner lease carry.
    pub id: u64,
    /// The run this job belongs to.
    pub run: u64,
    /// The name GitHub shows, which is the check's name and, for a matrix job, already expanded.
    pub name: String,
    /// The commit the job ran: what makes two jobs of different runs comparable.
    pub head_sha: String,
    /// GitHub's conclusion text (`success`, `failure`, `neutral`, `cancelled`, `skipped`,
    /// `timed_out` and the states it adds later), `None` while the job has not concluded.
    pub conclusion: Option<String>,
    pub labels: Vec<String>,
    /// Wall time from `started_at` to `completed_at`, absent when either is missing or unreadable.
    pub duration_ms: Option<u64>,
}

/// The jobs of one run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub total_count: u64,
    pub jobs: Vec<Job>,
}

/// Decode one page of the jobs response. A body that is not the response's shape at all is
/// `Response`; a job entry that is not a job is dropped.
pub fn decode_page(body: &Value) -> Result<Page> {
    let jobs = body
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or(Error::Response("actions jobs"))?;
    if jobs.len() > MAX_JOBS {
        return Err(Error::Response("actions jobs page"));
    }
    let total_count = body
        .get("total_count")
        .and_then(Value::as_u64)
        .unwrap_or(jobs.len() as u64);
    let mut page = Page {
        total_count,
        jobs: Vec::with_capacity(jobs.len()),
    };
    for job in jobs {
        let Some(id) = job.get("id").and_then(Value::as_u64).filter(|id| *id > 0) else {
            continue;
        };
        let name = match job.get("name").and_then(Value::as_str) {
            Some(name) if valid_text(name, MAX_NAME) => name.to_owned(),
            _ => continue,
        };
        let Some(head_sha) = job
            .get("head_sha")
            .and_then(Value::as_str)
            .and_then(commit_id)
        else {
            continue;
        };
        let run = job
            .get("run_id")
            .and_then(Value::as_u64)
            .filter(|run| *run > 0)
            .unwrap_or(0);
        let conclusion = job
            .get("conclusion")
            .and_then(Value::as_str)
            .filter(|text| valid_text(text, 32))
            .map(str::to_owned);
        let labels = job
            .get("labels")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .filter(|label| valid_text(label, MAX_LABEL))
                    .take(MAX_LABELS)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let duration_ms = match (
            timestamp_ms(job.get("started_at")),
            timestamp_ms(job.get("completed_at")),
        ) {
            (Some(started), Some(completed)) if completed >= started => {
                Some(u64::try_from(completed - started).unwrap_or(u64::MAX))
            }
            _ => None,
        };
        page.jobs.push(Job {
            id,
            run,
            name,
            head_sha,
            conclusion,
            labels,
            duration_ms,
        });
    }
    Ok(page)
}

/// A full commit id, lower-cased: what a run's provenance, a check's `head_sha` and this response
/// all key on, so two of them can be compared at all.
fn commit_id(text: &str) -> Option<String> {
    if text.len() == 40 || text.len() == 64 {
        let lower = text.to_ascii_lowercase();
        if lower.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(lower);
        }
    }
    None
}

fn valid_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn timestamp_ms(value: Option<&Value>) -> Option<i64> {
    let text = value?.as_str()?;
    let parsed = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A recorded page in the response's shape: one matrix job that passed, one that failed, and
    /// the fields this decoder reads beside the ones it ignores.
    fn recorded() -> Value {
        json!({
            "total_count": 2,
            "jobs": [
                {
                    "id": 8_100_000_001u64,
                    "run_id": 4_400_000_001u64,
                    "name": "build (1.24)",
                    "head_sha": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "status": "completed",
                    "conclusion": "success",
                    "labels": ["ubuntu-latest", "self-hosted"],
                    "started_at": "2026-11-02T10:00:00Z",
                    "completed_at": "2026-11-02T10:02:30Z",
                    "steps": [
                        {"name": "Set up job", "status": "completed", "conclusion": "success", "number": 1},
                        {"name": "Run tests", "status": "completed", "conclusion": "success", "number": 2}
                    ]
                },
                {
                    "id": 8_100_000_002u64,
                    "run_id": 4_400_000_001u64,
                    "name": "build (1.99)",
                    "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "status": "in_progress",
                    "conclusion": null,
                    "labels": [],
                    "started_at": "2026-11-02T10:00:00Z"
                }
            ]
        })
    }

    #[test]
    fn a_page_carries_each_jobs_commit_conclusion_and_wall_time() {
        let page = decode_page(&recorded()).unwrap();
        assert_eq!(page.total_count, 2);
        assert_eq!(page.jobs.len(), 2);
        let first = &page.jobs[0];
        assert_eq!(first.id, 8_100_000_001);
        assert_eq!(first.run, 4_400_000_001);
        assert_eq!(first.name, "build (1.24)");
        // A commit id compare with a run's provenance is one spelling, whichever case GitHub sent.
        assert_eq!(first.head_sha, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(first.conclusion.as_deref(), Some("success"));
        assert_eq!(first.labels, vec!["ubuntu-latest", "self-hosted"]);
        assert_eq!(first.duration_ms, Some(150_000));
        // A job still running has run for nothing the response states: absent, never zero.
        let second = &page.jobs[1];
        assert_eq!(second.conclusion, None);
        assert_eq!(second.duration_ms, None);
    }

    #[test]
    fn an_entry_that_is_not_a_job_is_dropped_not_the_page() {
        let mut body = recorded();
        body["jobs"].as_array_mut().unwrap().extend([
            json!({"id": 0, "name": "no id", "head_sha": "a"}),
            json!({"id": 8_100_000_003u64, "name": "", "head_sha": "a"}),
            json!({"id": 8_100_000_004u64, "name": "short commit", "head_sha": "abc123"}),
            json!({"id": 8_100_000_005u64, "name": "not a job"}),
        ]);
        let page = decode_page(&body).unwrap();
        assert_eq!(page.jobs.len(), 2);
        assert_eq!(page.total_count, 2);

        assert_eq!(
            decode_page(&json!({})),
            Err(Error::Response("actions jobs"))
        );
        let mut oversized = json!({"jobs": []});
        let jobs = (1..=MAX_JOBS as u64 + 1)
            .map(|id| json!({"id": id, "name": "j", "head_sha": "a".repeat(40)}))
            .collect::<Vec<_>>();
        oversized["jobs"] = Value::Array(jobs);
        assert_eq!(
            decode_page(&oversized),
            Err(Error::Response("actions jobs page"))
        );
    }

    #[test]
    fn a_duration_the_response_contradicts_is_absent() {
        let body = json!({"jobs": [{
            "id": 1,
            "name": "j",
            "head_sha": "a".repeat(40),
            "started_at": "2026-11-02T10:02:30Z",
            "completed_at": "2026-11-02T10:00:00Z"
        }]});
        assert_eq!(decode_page(&body).unwrap().jobs[0].duration_ms, None);
    }
}
