//! Worker enrollment for platform administrators (Q11): issue a pool-bound, single-use enrollment with the
//! host ceilings and priority the controller approves, read its state, withdraw it, and download the
//! worker-only bootstrap script. The secret leaves the controller once, in the issuing response; the
//! script carries none.
//!
//! The same module holds the controller's authority over an enrolled host (Q12): read and replace the
//! ceilings and priority approved for one worker, and request its uninstall. A worker's own report can
//! never raise either.

use sentinel_core::{PoolId, TokenId, UnixMillis, WorkerId};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::workers::{
    self, DEFAULT_ENROLLMENT_MS, EnrollmentState, EnrollmentStatus, EnrollmentTerms, HostPolicy,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Reply, Route, body, err, id, ok, parse, store_error};
use crate::{
    State,
    auth::Identity,
    http::Request,
    oauth::{self, Budget},
    worker_bootstrap::{Unavailable, WorkerBootstrap},
};

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("POST", ["api", "v1", "admin", "worker-enrollments"]) => issue(state, request),
        ("GET", ["api", "v1", "admin", "worker-enrollments", enrollment]) => {
            show(state, request, enrollment)
        }
        ("DELETE", ["api", "v1", "admin", "worker-enrollments", enrollment]) => {
            withdraw(state, request, enrollment)
        }
        (
            "GET",
            [
                "api",
                "v1",
                "admin",
                "worker-enrollments",
                enrollment,
                "bootstrap.sh",
            ],
        ) => script(state, request, enrollment),
        ("GET", ["api", "v1", "admin", "workers", worker, "policy"]) => {
            host_policy(state, request, worker)
        }
        ("PUT", ["api", "v1", "admin", "workers", worker, "policy"]) => {
            set_host_policy(state, request, worker)
        }
        ("GET", ["api", "v1", "admin", "placement"]) => placement(state, request),
        ("POST", ["api", "v1", "admin", "workers", worker, "uninstall"]) => {
            uninstall(state, request, worker)
        }
        _ => return None,
    })
}

fn configured(state: &State) -> Result<&WorkerBootstrap, ApiError> {
    state.worker_bootstrap.as_deref().ok_or_else(|| {
        err(
            ErrorCode::Conflict,
            "worker enrollment is not configured: add a [worker_bootstrap] section to the server configuration",
        )
    })
}

/// Budgets are kept per administrator, so one account cannot starve another and a shared address cannot
/// lock a legitimate one out.
fn limited(state: &State, who: &Identity, budget: Budget) -> Result<(), ApiError> {
    let actor = u128::from_be_bytes(*who.user.as_bytes());
    if oauth::admitted_as(state, actor, budget) {
        return Ok(());
    }
    Err(
        err(ErrorCode::RateLimited, "too many requests; retry later")
            .with_detail("retry_after_ms", 6_000),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueBody {
    pool: String,
    #[serde(default)]
    lifetime_ms: Option<i64>,
    #[serde(default)]
    cpu_millis: Option<i64>,
    #[serde(default)]
    memory_bytes: Option<i64>,
    #[serde(default)]
    disk_bytes: Option<i64>,
    #[serde(default)]
    priority: Option<i32>,
    /// `tailcat` (the default) or `direct`.
    #[serde(default)]
    transport: Option<String>,
}

fn transport_name(tailcat: bool) -> &'static str {
    if tailcat { "tailcat" } else { "direct" }
}

fn policy_json(policy: &HostPolicy) -> Value {
    json!({
        "cpu_millis": policy.cpu_millis,
        "memory_bytes": policy.memory_bytes,
        "disk_bytes": policy.disk_bytes,
        "priority": policy.priority,
    })
}

fn script_path(enrollment: TokenId) -> String {
    format!("/api/v1/admin/worker-enrollments/{enrollment}/bootstrap.sh")
}

fn issue(state: &State, request: &mut Request) -> Route {
    let who = super::admin::platform(state, request, true)?;
    let bootstrap = configured(state)?;
    let body: IssueBody = parse(&body(request)?)?;
    let pool: PoolId = id(&body.pool, "pool")?;
    let tailcat = match body.transport.as_deref() {
        None | Some("tailcat") => true,
        Some("direct") => false,
        Some(_) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "transport must be tailcat or direct",
            ));
        }
    };
    let address = if tailcat {
        if !bootstrap.tailcat_configured() {
            return Err(err(
                ErrorCode::Conflict,
                "this controller has no Tailcat helper configured; choose transport \"direct\"",
            ));
        }
        Some(bootstrap.tailcat_address().ok_or_else(|| {
            err(
                ErrorCode::Conflict,
                "the controller has not written its Tailcat address yet; retry once it is serving",
            )
        })?)
    } else {
        None
    };
    // Fail before the write for the one thing that could make the script unrenderable.
    bootstrap
        .render(tailcat)
        .map_err(|Unavailable::NoTailcat| {
            err(
                ErrorCode::Conflict,
                "this controller pins no Tailcat helper; choose transport \"direct\"",
            )
        })?;
    let terms = EnrollmentTerms {
        pool,
        lifetime_ms: body.lifetime_ms.unwrap_or(DEFAULT_ENROLLMENT_MS),
        policy: HostPolicy {
            cpu_millis: body.cpu_millis,
            memory_bytes: body.memory_bytes,
            disk_bytes: body.disk_bytes,
            priority: body.priority.unwrap_or(0),
        },
        tailcat,
    };
    // Charged where a request would write, so a malformed one costs the administrator nothing.
    limited(state, &who, Budget::Enrollment)?;
    let authority = who.authority();
    let enrollment = state
        .store
        .writer()
        .write(move |tx| {
            // The secret admits a machine to the fleet: it needs a fresh step-up like any other credential issue.
            authority.require_privileged(tx)?;
            workers::issue_enrollment_with(tx, authority, terms, UnixMillis::now())
        })
        .map_err(store_error)?;
    Ok(Reply::Json(
        201,
        json!({
            "id": enrollment.id.to_string(),
            "pool": enrollment.pool.to_string(),
            "transport": transport_name(tailcat),
            "expires_ms": enrollment.expires.0,
            "host": policy_json(&enrollment.policy),
            "release_version": bootstrap.release_version(),
            "bootstrap_path": script_path(enrollment.id),
            // Shown once. The worker reads them from a 0600 file or standard input: line one the secret,
            // line two (Tailcat only) the address.
            "secret": sentinel_auth::token::format(&enrollment.secret),
            "tailcat_address": address.as_ref().map(|a| a.expose()),
        }),
        Vec::new(),
    ))
}

fn state_name(state: EnrollmentState) -> &'static str {
    match state {
        EnrollmentState::Pending => "pending",
        EnrollmentState::Redeemed => "redeemed",
        EnrollmentState::Revoked => "revoked",
        EnrollmentState::Expired => "expired",
    }
}

fn status_json(status: &EnrollmentStatus) -> Value {
    json!({
        "id": status.id.to_string(),
        "pool": status.pool.to_string(),
        "state": state_name(status.state),
        "transport": transport_name(status.tailcat),
        "created_ms": status.created.0,
        "expires_ms": status.expires.0,
        "host": policy_json(&status.policy),
    })
}

fn show(state: &State, request: &Request, enrollment: &str) -> Route {
    let who = super::admin::platform(state, request, false)?;
    let enrollment: TokenId = id(enrollment, "enrollment")?;
    let authority = who.authority();
    let status = state
        .store
        .read(move |c| workers::enrollment_status(c, authority, enrollment, UnixMillis::now()))
        .map_err(store_error)?;
    ok(status_json(&status))
}

fn withdraw(state: &State, request: &Request, enrollment: &str) -> Route {
    let who = super::admin::platform(state, request, true)?;
    limited(state, &who, Budget::Enrollment)?;
    let enrollment: TokenId = id(enrollment, "enrollment")?;
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| workers::revoke_enrollment(tx, authority, enrollment, UnixMillis::now()))
        .map_err(store_error)?;
    Ok(Reply::Empty(204, Vec::new()))
}

fn script(state: &State, request: &Request, enrollment: &str) -> Route {
    let who = super::admin::platform(state, request, false)?;
    limited(state, &who, Budget::Bootstrap)?;
    let bootstrap = configured(state)?;
    let enrollment: TokenId = id(enrollment, "enrollment")?;
    let authority = who.authority();
    let known = state
        .store
        .read(move |c| workers::enrollment_status(c, authority, enrollment, UnixMillis::now()))
        .map_err(store_error)?;
    let rendered = bootstrap
        .render(known.tailcat)
        .map_err(|Unavailable::NoTailcat| {
            err(
                ErrorCode::Conflict,
                "this controller pins no Tailcat helper for this enrollment",
            )
        })?;
    // The audit row and the pending check commit together, so a script is handed out only for an
    // enrollment that can still be redeemed.
    state
        .store
        .writer()
        .write(move |tx| {
            workers::note_bootstrap_download(tx, authority, enrollment, UnixMillis::now())
        })
        .map_err(|e| match e {
            sentinel_store::Error::Conflict => err(
                ErrorCode::Conflict,
                "the enrollment is no longer pending: it was redeemed, withdrawn or has expired",
            ),
            e => store_error(e),
        })?;
    Ok(Reply::Script(200, rendered))
}

fn view_json(view: &workers::HostView) -> Value {
    let over = view.over_cap();
    json!({
        "approved": policy_json(&view.policy),
        "reported": {
            "cpu_millis": view.reported_cpu_millis,
            "memory_bytes": view.reported_memory_bytes,
            "disk_bytes": view.reported_disk_bytes,
        },
        "effective": {
            "cpu_millis": view.effective_cpu_millis,
            "memory_bytes": view.effective_memory_bytes,
            "disk_bytes": view.effective_disk_bytes,
        },
        "reserved": {
            "cpu_millis": view.reserved_cpu_millis,
            "memory_bytes": view.reserved_memory_bytes,
            "disk_bytes": view.reserved_disk_bytes,
        },
        "over_cap": {
            "over": over.is_over(),
            "cpu_millis": over.cpu_millis,
            "memory_bytes": over.memory_bytes,
            "disk_bytes": over.disk_bytes,
        },
    })
}

/// The order the next placement round uses for the free workers, and why each is ahead of the next.
fn placement(state: &State, request: &Request) -> Route {
    super::admin::platform(state, request, false)?;
    let ranking = state.controller.placement_ranking();
    let ranked: Vec<Value> = ranking
        .iter()
        .enumerate()
        .map(|(position, r)| {
            json!({
                "position": position + 1,
                "worker": r.worker.to_string(),
                "priority": r.priority,
                "expected_finish_ns": r.expected_finish_ns,
                "ahead_because": r.ahead_because.map(|factor| factor.as_str()),
            })
        })
        .collect();
    ok(json!({
        "order": state.controller.placement_order().as_str(),
        "workers": ranked,
    }))
}

fn host_policy(state: &State, request: &Request, worker: &str) -> Route {
    let who = super::admin::platform(state, request, false)?;
    let worker: WorkerId = id(worker, "worker")?;
    let authority = who.authority();
    let view = state
        .store
        .read(move |c| workers::host_view(c, authority, worker))
        .map_err(store_error)?;
    ok(view_json(&view))
}

/// The whole approved policy: an absent or `null` ceiling removes it, an absent priority is neutral.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBody {
    #[serde(default)]
    cpu_millis: Option<i64>,
    #[serde(default)]
    memory_bytes: Option<i64>,
    #[serde(default)]
    disk_bytes: Option<i64>,
    #[serde(default)]
    priority: Option<i32>,
}

fn set_host_policy(state: &State, request: &mut Request, worker: &str) -> Route {
    let who = super::admin::platform(state, request, true)?;
    let worker: WorkerId = id(worker, "worker")?;
    let body: PolicyBody = parse(&body(request)?)?;
    let policy = HostPolicy {
        cpu_millis: body.cpu_millis,
        memory_bytes: body.memory_bytes,
        disk_bytes: body.disk_bytes,
        priority: body.priority.unwrap_or(0),
    };
    limited(state, &who, Budget::HostPolicy)?;
    let authority = who.authority();
    let view = state
        .store
        .writer()
        .write(move |tx| {
            // A ceiling decides how much of the machine tenants can use: it needs a fresh step-up.
            authority.require_privileged(tx)?;
            workers::set_policy(tx, authority, worker, policy)?;
            workers::host_view(tx, authority, worker)
        })
        .map_err(store_error)?;
    // Placement reads the recorded size on its next pass; wake it so a raise is used at once.
    state.controller.wake();
    ok(view_json(&view))
}

fn uninstall(state: &State, request: &Request, worker: &str) -> Route {
    let who = super::admin::platform(state, request, true)?;
    let worker: WorkerId = id(worker, "worker")?;
    limited(state, &who, Budget::HostPolicy)?;
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| {
            authority.require_privileged(tx)?;
            workers::request_uninstall(tx, authority, worker, UnixMillis::now())
        })
        .map_err(store_error)?;
    state.controller.wake();
    Ok(Reply::Json(
        202,
        json!({ "worker": worker.to_string(), "uninstall": "requested" }),
        Vec::new(),
    ))
}
