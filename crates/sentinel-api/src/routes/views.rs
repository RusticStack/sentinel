//! Read routes behind the web interface's run, worker and synchronization
//! views (U02, U04). Each is the same authenticate → scope → store
//! predicate path as every other route; nothing here is page-only.

use sentinel_core::{
    AttemptId, RunId, UnixMillis,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::{
    error::ErrorCode,
    limits::{MAX_PAGE_ITEMS, page_size},
    summary::{AttemptSummary, StepOutcome},
};
use sentinel_store::{
    auth as authz, auth::Authority, dispatch, lookup, oauth::code::consent_choices, status,
    status::RunFilter, tenancy, views, workers,
};
use serde_json::{Value, json};

use super::{Route, err, id, identify, ok, query_param, store_error};
use crate::{State, auth};

/// One query parameter, percent-decoded (`+` is a space); `None` when absent,
/// `invalid_request` when repeated.
fn decoded(query: &str, name: &str) -> Result<Option<String>, sentinel_protocol::error::ApiError> {
    let mut found = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == name {
            if found.is_some() {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!("{name} given twice"),
                ));
            }
            found = Some(value.into_owned());
        }
    }
    Ok(found)
}

/// `GET /api/v1/tenants`: the tenants the caller is a member of, by slug,
/// with the caller's role in each — what the page's tenant switcher offers.
/// A credential narrowed to one tenant lists that tenant only. The server
/// still authorizes every request by membership; this list is convenience.
pub(super) fn my_tenants(state: &State, request: &crate::http::Request) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let choices = state
        .store
        .read(|c| consent_choices(c, who.user))
        .map_err(store_error)?;
    ok(json!({
        "tenants": choices
            .iter()
            .filter(|c| who.principal.tenant.is_none_or(|t| t == c.tenant))
            .map(|c| json!({
                "slug": c.slug,
                "role": match c.role {
                    sentinel_core::auth::Role::Reader => "reader",
                    sentinel_core::auth::Role::Operator => "operator",
                    sentinel_core::auth::Role::TenantAdmin => "admin",
                },
            }))
            .collect::<Vec<_>>(),
        "super_admin": who.super_admin,
    }))
}

/// `GET /tenants/{slug}/repos/{name}/runs?limit&before&ref|pr|sha`: newest
/// runs first, optionally narrowed to one ref, one pull request or a commit
/// prefix — at most one filter, each an index range.
pub(super) fn runs(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()))
        .min(MAX_PAGE_ITEMS) as u16;
    let before: Option<RunId> = query_param(query, "before")
        .map(|v| id(v, "run"))
        .transpose()?;
    let ref_name = decoded(query, "ref")?;
    let pr = decoded(query, "pr")?
        .map(|v| {
            v.parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "malformed pr"))
        })
        .transpose()?;
    let sha = decoded(query, "sha")?.map(|v| v.to_ascii_lowercase());
    // A bare branch name means the branch: intake records full refs.
    let ref_name = ref_name.map(|r| {
        if r.starts_with("refs/") {
            r
        } else {
            format!("refs/heads/{r}")
        }
    });
    let filter = match (&ref_name, pr, &sha) {
        (None, None, None) => None,
        (Some(r), None, None) => Some(RunFilter::Ref(r)),
        (None, Some(n), None) => Some(RunFilter::Pr(n)),
        (None, None, Some(s)) => {
            if !(7..=64).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    "sha must be 7 to 64 hex digits",
                ));
            }
            Some(RunFilter::Sha(s))
        }
        _ => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "ref, pr and sha are exclusive",
            ));
        }
    };
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let page = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            match filter {
                None => status::runs_page(c, tenant, repo, before, limit),
                Some(filter) => status::filtered_runs(c, tenant, repo, filter, before, limit),
            }
        })
        .map_err(store_error)?;
    ok(json!({
        "runs": page.runs.iter().map(|r| json!({
            "id": r.id.to_string(),
            "sha": r.sha,
            "created_ms": r.created.0,
            "state": super::run_state(r.state),
            "trigger": r.trigger,
            "ref": r.ref_name,
            "pr": r.pr_number,
        })).collect::<Vec<_>>(),
        "next": page.next.map(|r| r.to_string()),
    }))
}

pub(super) fn step_outcome_name(outcome: StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Passed => "passed",
        StepOutcome::Skipped => "skipped",
        StepOutcome::Failed { .. } => "failed",
        StepOutcome::Signaled { .. } => "signaled",
        StepOutcome::OutOfMemory => "out_of_memory",
        StepOutcome::TimedOut => "timed_out",
        StepOutcome::Runtime => "runtime",
        StepOutcome::NotRun => "not_run",
    }
}

/// `GET /attempts/{att}/steps`: the attempt's measured phases and each
/// step's outcome and duration from its terminal summary, or
/// `{present:false}` while it has not reported. What was never measured is
/// absent, never zero.
pub(super) fn attempt_steps(state: &State, request: &crate::http::Request, attempt: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
    let bytes = state
        .store
        .read(|c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            let tenant = authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            dispatch::attempt_summary(c, tenant, attempt)
        })
        .map_err(store_error)?;
    let Some(bytes) = bytes else {
        return ok(json!({ "attempt": attempt.to_string(), "present": false }));
    };
    let summary = AttemptSummary::decode(&bytes)
        .map_err(|_| err(ErrorCode::Internal, "stored summary unreadable"))?;
    let mut timings = serde_json::Map::new();
    for (name, value) in [
        ("checkout", summary.checkout_ns),
        ("checkout_fetch", summary.checkout_fetch_ns),
        ("checkout_materialize", summary.checkout_materialize_ns),
        ("image_pull", summary.image_pull_ns),
        ("container_start", summary.container_start_ns),
        ("steps", summary.steps_ns),
        ("finalize", summary.finalize_ns),
    ] {
        if let Some(ns) = value {
            timings.insert(name.to_owned(), json!(ns));
        }
    }
    ok(json!({
        "attempt": attempt.to_string(),
        "present": true,
        "timings_ns": timings,
        "image_present": summary.image_present,
        "steps": summary.steps.iter().map(|s| {
            let mut step = json!({
                "index": s.index,
                "id": s.id,
                "outcome": step_outcome_name(s.outcome),
            });
            match s.outcome {
                StepOutcome::Failed { code } => step["exit_code"] = json!(code),
                StepOutcome::Signaled { signal } => step["signal"] = json!(signal),
                _ => {}
            }
            if let Some(ns) = s.duration_ns {
                step["duration_ns"] = json!(ns);
            }
            step
        }).collect::<Vec<_>>(),
        "detail": summary.detail,
    }))
}

/// `GET /workers?tenant=slug`: the pools the tenant may use and their
/// workers — live connection and transport from the fleet, and from the
/// store each worker's reported capacity, what is still free on its host,
/// the attempts it holds (as totals: a shared worker's reservations belong
/// to other tenants too), its labels and whether it is draining.
pub(super) fn workers_view(state: &State, request: &crate::http::Request, query: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let slug = query_param(query, "tenant")
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "tenant query parameter required"))?
        .to_owned();
    let connected = state.controller.connected();
    let pools = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let authority = Authority::credential(who.principal);
            let pools = tenancy::pools_for_tenant(c, authority, tenant)?;
            let mut out = Vec::with_capacity(pools.len());
            for pool in pools {
                let live = workers::in_pool(c, authority, pool.id)?;
                let mut loads = Vec::with_capacity(live.len());
                for worker in &live {
                    loads.push(views::worker_load(c, worker.id)?);
                }
                out.push((pool, live, loads));
            }
            Ok(out)
        })
        .map_err(store_error)?;
    ok(json!({
        "pools": pools.iter().map(|(pool, live, loads)| json!({
            "id": pool.id.to_string(), "name": pool.name, "active": pool.active,
            "kind": match pool.kind { tenancy::PoolKind::Shared => "shared", tenancy::PoolKind::Dedicated(_) => "dedicated" },
            "workers": live.iter().zip(loads).map(|(w, load)| {
                let mut worker = json!({
                    "id": w.id.to_string(), "name": w.name,
                    "arch": format!("{:?}", w.negotiated.arch).to_lowercase(),
                    "connected": connected.contains(&w.id),
                    "last_seen_ms": w.last_seen.map(|t| t.0),
                    "transport": state.controller.transport(w.id).map(|t| super::transport_json(&t)),
                    "draining": load.draining_since.is_some(),
                    "labels": load.labels,
                    "held_attempts": load.held_attempts,
                    "held": capacity_json(&load.held),
                    "free": capacity_json(&load.free),
                });
                // A capacity the worker never reported is absent, not zero.
                if load.capacity.cpu_millis > 0 || load.capacity.memory_bytes > 0 {
                    worker["capacity"] = capacity_json(&load.capacity);
                }
                if let Some(since) = load.draining_since {
                    worker["draining_since_ms"] = json!(since);
                }
                if let Some(bytes) = load.cache_bytes {
                    worker["cache_bytes"] = json!(bytes);
                }
                if let Some(n) = load.host_workers {
                    worker["host_workers"] = json!(n);
                }
                worker
            }).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()
    }))
}

fn capacity_json(c: &dispatch::Capacity) -> Value {
    let mut out = json!({ "cpu_millis": c.cpu_millis, "memory_bytes": c.memory_bytes });
    // Disk 0 is "not reported" on a worker row, and no subtraction applies.
    if c.disk_bytes != 0 {
        out["disk_bytes"] = json!(c.disk_bytes);
    }
    out
}

/// How far back `GET /tenants/{slug}/sync` counts refused publications by
/// default: a day.
const SYNC_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// `GET /tenants/{slug}/sync?since_ms&after&limit`: per repository the
/// caller may read, GitHub check publications still pending (and the oldest
/// one's age), refused since `since_ms` (default the last 24 h), the last
/// successful publication, and deliveries not yet resolved into runs.
pub(super) fn sync(
    state: &State,
    request: &crate::http::Request,
    slug: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let now = UnixMillis::now();
    let since = match query_param(query, "since_ms") {
        None => UnixMillis(now.0 - SYNC_WINDOW_MS),
        Some(v) => UnixMillis(
            v.parse::<i64>()
                .ok()
                .filter(|ms| *ms >= 0)
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "malformed since_ms"))?,
        ),
    };
    let after = query_param(query, "after")
        .map(|v| id(v, "repository"))
        .transpose()?;
    let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()))
        .min(views::MAX_PAGE as usize) as u16;
    let slug = slug.to_owned();
    let rows = state
        .store
        .read(|c| {
            let tenant = authz::member_tenant_by_slug(c, who.principal, &slug)?;
            views::sync(c, who.principal, tenant, since, after, limit)
        })
        .map_err(store_error)?;
    let next = (rows.len() == usize::from(limit))
        .then(|| rows.last().map(|r| r.repo.to_string()))
        .flatten();
    ok(json!({
        "now_ms": now.0,
        "since_ms": since.0,
        "repos": rows.iter().map(|r| json!({
            "id": r.repo.to_string(),
            "name": r.name,
            "pending": r.pending,
            "oldest_pending_ms": r.oldest_pending_ms,
            "refused": r.refused,
            "last_refused_ms": r.last_refused_ms,
            "last_published_ms": r.last_published_ms,
            "open_deliveries": r.open_deliveries,
            "oldest_delivery_ms": r.oldest_delivery_ms,
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}
