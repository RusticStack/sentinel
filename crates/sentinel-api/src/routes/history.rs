//! History views of a repository: duration percentiles per job, a two-attempt phase comparison and a bounded
//! literal log search across its recent runs ([API](../../../../docs/api.md)). Each authorizes the repository exactly as the run
//! list does, so another repository's runs, attempts and logs answer as if they did not exist.

use sentinel_core::{
    AttemptId, RunId,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::{error::ErrorCode, limits::page_size};
use sentinel_store::{
    Error as StoreError, auth as authz,
    history::{self, Phases},
    logs, lookup, outcomes,
};
use serde_json::{Map, Value, json};

use super::{Route, err, id, identify, ok, query_param, store_error, views::decoded};
use crate::{State, auth};

fn number<T: std::str::FromStr>(
    query: &str,
    name: &str,
) -> Result<Option<T>, sentinel_protocol::error::ApiError> {
    query_param(query, name)
        .map(|v| {
            v.parse()
                .map_err(|_| err(ErrorCode::InvalidRequest, format!("malformed {name}")))
        })
        .transpose()
}

fn timings(phases: &Phases) -> Value {
    let mut out = Map::new();
    for (name, value) in history::PHASE_NAMES.iter().zip(phases) {
        if let Some(ns) = value {
            out.insert((*name).to_owned(), json!(ns));
        }
    }
    Value::Object(out)
}

fn percentiles(p: Option<history::Percentiles>) -> Value {
    p.map_or(
        Value::Null,
        |p| json!({ "count": p.count, "p50_ns": p.p50_ns, "p95_ns": p.p95_ns }),
    )
}

pub(super) fn durations(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let runs = number::<u16>(query, "runs")?
        .filter(|n| *n > 0)
        .unwrap_or(history::DEFAULT_WINDOW_RUNS)
        .min(history::MAX_WINDOW_RUNS);
    let job = decoded(query, "job")?;
    if job
        .as_ref()
        .is_some_and(|j| j.is_empty() || j.len() > sentinel_protocol::limits::MAX_NAME_BYTES)
    {
        return Err(err(ErrorCode::InvalidRequest, "malformed job"));
    }
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let found = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            history::durations(c, tenant, repo, runs, job.as_deref())
        })
        .map_err(store_error)?;
    ok(json!({
        "window": {
            "requested": found.requested,
            "runs": found.runs,
            "oldest_ms": found.oldest_ms,
            "newest_ms": found.newest_ms,
        },
        "jobs": found.jobs.iter().map(|j| {
            let mut phases = Map::new();
            for (phase, p) in history::PHASE_NAMES.iter().zip(j.phases) {
                if p.is_some() {
                    phases.insert((*phase).to_owned(), percentiles(p));
                }
            }
            let mut out = json!({
                "job": j.job,
                "attempts": j.attempts,
                "total": percentiles(j.total),
                "phases": phases,
            });
            if job.is_some() {
                out["samples"] = j.samples.iter().map(|s| {
                    let mut sample = json!({
                        "run": s.run.to_string(),
                        "attempt": s.attempt.to_string(),
                        "fence": s.fence,
                        "created_ms": s.created_ms,
                        "timings_ns": timings(&s.phases),
                    });
                    if let Some(total) = s.total_ns {
                        sample["total_ns"] = json!(total);
                    }
                    sample
                }).collect();
            }
            out
        }).collect::<Vec<_>>(),
        "truncated": found.truncated,
        "unreadable": found.unreadable,
    }))
}

fn side(side: &history::Side) -> Value {
    let mut out = json!({
        "attempt": side.attempt.to_string(),
        "run": side.run.to_string(),
        "fence": side.fence,
        "created_ms": side.created_ms,
        "present": side.phases.is_some(),
    });
    if let Some(phases) = &side.phases {
        out["timings_ns"] = timings(phases);
    }
    if let Some(total) = side.total_ns {
        out["total_ns"] = json!(total);
    }
    out
}

pub(super) fn compare(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let attempt = |key: &str| -> Result<AttemptId, sentinel_protocol::error::ApiError> {
        id(
            query_param(query, key)
                .ok_or_else(|| err(ErrorCode::InvalidRequest, format!("{key} is required")))?,
            "attempt",
        )
    };
    let (base, head) = (attempt("base")?, attempt("head")?);
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let found = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            history::compare(c, tenant, repo, base, head)
        })
        .map_err(store_error)?;
    let mut delta = Map::new();
    if let (Some(b), Some(h)) = (&found.base.phases, &found.head.phases) {
        for (phase, (b, h)) in history::PHASE_NAMES.iter().zip(b.iter().zip(h)) {
            if let Some(d) = history::delta(*b, *h) {
                delta.insert((*phase).to_owned(), json!(d));
            }
        }
    }
    if let Some(d) = history::delta(found.base.total_ns, found.head.total_ns) {
        delta.insert("total".to_owned(), json!(d));
    }
    ok(json!({
        "job": found.job,
        "base": side(&found.base),
        "head": side(&found.head),
        "delta_ns": delta,
    }))
}

/// Attempts one search request looks at, however small their logs: a missing or expired log still costs a lookup.
const MAX_SEARCH_ATTEMPTS: usize = 256;

/// The longest window a flaky list may ask for, whatever the deployment's log retention is: a repository's
/// outcomes never outlive its logs, so a longer window states the same rows.
const MAX_FLAKE_DAYS: u32 = 366;
const DAY_MS: i64 = 24 * 3_600_000;

/// The flaky tests of one repository over a window: deterministic counts, never an inference. The window
/// defaults to the deployment's log retention, because a test's outcomes are kept exactly as long as the log
/// its report was read beside.
pub(super) fn flakes(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let retention_days = u32::try_from(state.objects.deployment().log_retention_ms / DAY_MS)
        .unwrap_or(MAX_FLAKE_DAYS)
        .clamp(1, MAX_FLAKE_DAYS);
    let days = number::<u32>(query, "days")?
        .filter(|days| (1..=MAX_FLAKE_DAYS).contains(days))
        .unwrap_or(retention_days);
    let limit = number::<usize>(query, "limit")?
        .filter(|limit| (1..=outcomes::MAX_TESTS).contains(limit))
        .unwrap_or(outcomes::DEFAULT_TESTS);
    let since_ms = sentinel_core::UnixMillis::now()
        .0
        .saturating_sub(i64::from(days) * DAY_MS);
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let (repository, found) = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            let found = outcomes::flakes(c, tenant, repo, since_ms, limit)?;
            Ok((name, found))
        })
        .map_err(store_error)?;
    ok(json!({
        "repository": repository,
        "window": {
            "days": days,
            "since_ms": since_ms,
            "rows": found.rows,
            "oldest_ms": found.oldest_ms,
            "newest_ms": found.newest_ms,
        },
        "tests": found.tests.iter().map(|test| json!({
            "identity": test.identity,
            "suite": test.suite,
            "name": test.name,
            "attempts": test.attempts,
            "failed": test.failed,
            "passed": test.passed,
            "skipped": test.skipped,
            "commits": test.commits,
            "flakes": test.flakes,
            "rate_bps": test.rate_bps(),
            "last_failed_ms": test.last_failed_ms,
        })).collect::<Vec<_>>(),
        "broken": found.broken,
        "truncated": found.truncated,
    }))
}
pub(super) fn log_search(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let mut needle = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == "q" {
            if needle.is_some() {
                return Err(err(ErrorCode::InvalidRequest, "q given twice"));
            }
            needle = Some(value);
        }
    }
    let needle = needle
        .filter(|q| (1..=logs::MAX_NEEDLE).contains(&q.len()))
        .ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                format!("q must be 1..{} bytes", logs::MAX_NEEDLE),
            )
        })?;
    let window = number::<u16>(query, "runs")?
        .filter(|n| *n > 0)
        .unwrap_or(history::DEFAULT_SEARCH_RUNS)
        .min(history::MAX_SEARCH_RUNS);
    let limit = page_size(number::<usize>(query, "limit")?);
    let resume: Option<RunId> = query_param(query, "run")
        .map(|v| id(v, "run"))
        .transpose()?;
    let resume_attempt: Option<AttemptId> = query_param(query, "attempt")
        .map(|v| id(v, "attempt"))
        .transpose()?;
    let resume_after = number::<u64>(query, "after")?;
    let resume_carry = query_param(query, "carry");
    if resume.is_some() != resume_attempt.is_some()
        || (resume.is_none() && (resume_after.is_some() || resume_carry.is_some()))
    {
        return Err(err(
            ErrorCode::InvalidRequest,
            "run and attempt resume together, with after and carry",
        ));
    }
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let (tenant, runs, first) = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            let runs = history::search_runs(c, tenant, repo, resume, window)?;
            let first = match (resume, resume_attempt) {
                (Some(run), Some(attempt)) => Some(history::log_target(c, tenant, run, attempt)?),
                _ => None,
            };
            Ok((tenant, runs, first))
        })
        .map_err(store_error)?;

    let mut matches = Vec::new();
    let (mut scanned, mut attempts, mut expired, mut missing) = (0u64, 0, 0u32, 0u32);
    let mut next: Option<Value> = None;
    let mut resumed = first;
    'runs: for (at, run) in runs.iter().enumerate() {
        let left = runs.len() - at;
        let targets = match resumed.take() {
            Some(first) if at == 0 => {
                let spec_index = first.spec_index;
                let mut targets = vec![first];
                targets.extend(
                    state
                        .store
                        .read(|c| history::log_targets(c, tenant, *run, Some(spec_index)))
                        .map_err(store_error)?,
                );
                targets
            }
            _ => state
                .store
                .read(|c| history::log_targets(c, tenant, *run, None))
                .map_err(store_error)?,
        };
        for (n, target) in targets.iter().enumerate() {
            if matches.len() >= limit
                || scanned >= logs::SEARCH_SCAN_BYTES
                || attempts >= MAX_SEARCH_ATTEMPTS
            {
                next = Some(json!({
                    "run": run.to_string(),
                    "attempt": target.attempt.to_string(),
                    "after": 0,
                    "carry": null,
                    "runs": left,
                }));
                break 'runs;
            }
            attempts += 1;
            if target.expired_ms.is_some() {
                expired += 1;
                continue;
            }
            let carried = at == 0 && n == 0 && resume_attempt.is_some();
            let search = logs::SearchQuery {
                needle: needle.as_bytes(),
                after: if carried {
                    resume_after.unwrap_or(0)
                } else {
                    0
                },
                limit: limit - matches.len(),
                budget: logs::SEARCH_SCAN_BYTES - scanned,
                carry: if carried { resume_carry } else { None },
            };
            let found = match state
                .logs
                .search(*run, target.job, target.attempt, search)
                .or_else(|e| match e {
                    StoreError::NotFound => state.logs.search_legacy(target.attempt, search),
                    e => Err(e),
                }) {
                Ok(found) => found,
                Err(StoreError::NotFound) => {
                    missing += 1;
                    continue;
                }
                Err(e) => return Err(store_error(e)),
            };
            scanned += found.scanned;
            matches.extend(found.matches.iter().map(|m| {
                json!({
                    "run": run.to_string(),
                    "job": target.name,
                    "attempt": target.attempt.to_string(),
                    "seq": m.seq,
                    "step": m.step,
                    "stream": super::stream_name(m.stream),
                    "text": String::from_utf8_lossy(&m.text),
                })
            }));
            if let Some(after) = found.next_after {
                next = Some(json!({
                    "run": run.to_string(),
                    "attempt": target.attempt.to_string(),
                    "after": after,
                    "carry": found.carry,
                    "runs": left,
                }));
                break 'runs;
            }
        }
    }
    ok(json!({
        "matches": matches,
        "attempts_scanned": attempts,
        "scanned_bytes": scanned,
        "expired_attempts": expired,
        "missing_logs": missing,
        "runs_in_window": runs.len(),
        "next": next,
        "complete": next.is_none(),
    }))
}
