//! Worker enrollment for platform administrators (Q11): issue a pool-bound, single-use enrollment with the
//! host ceilings and priority the controller approves, read its state, withdraw it, and download the
//! worker-only bootstrap script. The secret leaves the controller once, in the issuing response; the
//! script carries none.
//!
//! The same module holds the controller's authority over an enrolled host (Q12): read and replace the
//! ceilings and priority approved for one worker, and request its uninstall. A worker's own report can
//! never raise either.

use sentinel_auth::secret::Digest;
use sentinel_core::{PoolId, TokenId, UnixMillis, WorkerId};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::workers::{
    self, DEFAULT_ENROLLMENT_MS, EnrollmentState, EnrollmentStatus, EnrollmentTerms, HostPolicy,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    JSON, Reply, Route, body, err, header, header_value, id, ok, parse, public_body_limit,
    query_param, store_error,
};
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
    query: &str,
) -> Option<Route> {
    Some(match (method, parts) {
        ("POST", ["api", "v1", "worker-enrollments", "redeem"]) => redeem(state, request),
        ("POST", ["api", "v1", "admin", "worker-enrollments"]) => issue(state, request),
        ("GET", ["api", "v1", "admin", "worker-enrollments"]) => {
            list_enrollments(state, request, query)
        }
        ("GET", ["api", "v1", "admin", "workers"]) => list_hosts(state, request, query),
        ("GET", ["api", "v1", "admin", "worker-bootstrap"]) => bootstrap_options(state, request),
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
        (
            "POST",
            [
                "api",
                "v1",
                "admin",
                "worker-enrollments",
                enrollment,
                "node-key",
            ],
        ) => authorize_key(state, request, enrollment),
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

fn redeem_mode(bootstrap: &WorkerBootstrap) -> &'static str {
    if bootstrap.redeems_over_https() {
        "https"
    } else {
        "link"
    }
}

/// What an enrollment page needs before it offers a form: whether enrollment is configured, which
/// transports work now, and the digest of the script each one serves. Nothing here is a credential: no
/// address, no secret, no URL with user information.
fn bootstrap_options(state: &State, request: &Request) -> Route {
    super::admin::platform(state, request, false)?;
    let Some(bootstrap) = state.worker_bootstrap.as_deref() else {
        return ok(json!({ "configured": false }));
    };
    let tailcat_script = bootstrap.script(true).ok();
    ok(json!({
        "configured": true,
        "release_version": bootstrap.release_version(),
        "redeem": redeem_mode(bootstrap),
        "archs": bootstrap.archs().collect::<Vec<_>>(),
        "transports": {
            "direct": {
                "available": true,
                "bootstrap_sha256": bootstrap.script(false).ok().map(|s| s.sha256()),
            },
            "tailcat": {
                "available": bootstrap.tailcat_configured(),
                "address_ready": bootstrap.tailcat_configured() && bootstrap.tailcat_address().is_some(),
                "helper_version": bootstrap.tailcat_version(),
                "bootstrap_sha256": tailcat_script.map(|s| s.sha256()),
            },
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeKeyBody {
    worker: String,
    /// `nodekey:<64 hex>`, the line `sh bootstrap identity` prints on the worker.
    node_key: String,
}

/// An administrator names the worker identifier and Tailcat node key a pending Tailcat enrollment is
/// for, when the worker cannot reach an API of its own before its tunnel exists (no `api_url`). Admitting
/// a key to the Tailcat network is the same class of act as issuing the secret, so it needs the same fresh
/// step-up and is never available to a bearer credential.
fn authorize_key(state: &State, request: &mut Request, enrollment: &str) -> Route {
    let who = super::admin::platform(state, request, true)?;
    let enrollment: TokenId = id(enrollment, "enrollment")?;
    let body: NodeKeyBody = parse(&body(request)?)?;
    let worker: WorkerId = id(&body.worker, "worker")?;
    let key = workers::parse_node_key(&body.node_key).ok_or_else(|| {
        err(
            ErrorCode::InvalidRequest,
            "node_key must be nodekey:<64 hex>",
        )
    })?;
    limited(state, &who, Budget::Enrollment)?;
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| {
            authority.require_privileged(tx)?;
            workers::authorize_node_key(tx, authority, enrollment, worker, key, UnixMillis::now())
        })
        .map_err(|e| match e {
            sentinel_store::Error::Conflict => err(
                ErrorCode::Conflict,
                "the enrollment is no longer pending, already names another worker or key, or the identity is already enrolled",
            ),
            e => store_error(e),
        })?;
    // Wakes the Tailcat allow-list pass, so the key is admitted before the worker's first attempt.
    if let Some(notify) = &state.on_worker_enrolled {
        (notify.0)();
    }
    Ok(Reply::Empty(204, Vec::new()))
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
    // Fail before the write for the one thing that could make the script unavailable.
    let script = bootstrap
        .script(tailcat)
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
            // Of the exact bytes `bootstrap_path` serves, so a page can show that its copy is intact.
            "bootstrap_sha256": script.sha256(),
            // How the worker presents its secret: `https` redeems at the API, `link` presents it with the
            // first link hello (a Tailcat worker then needs its node key authorized by an administrator).
            "redeem": redeem_mode(bootstrap),
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
        .script(known.tailcat)
        .map_err(|Unavailable::NoTailcat| {
            err(
                ErrorCode::Conflict,
                "this controller pins no Tailcat helper for this enrollment",
            )
        })?
        .text()
        .to_owned();
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

/// The pool a listing is narrowed to, if the query names one.
fn pool_filter(query: &str) -> Result<Option<PoolId>, ApiError> {
    query_param(query, "pool")
        .filter(|v| !v.is_empty())
        .map(|v| id(v, "pool"))
        .transpose()
}

/// Enrollments newest first, optionally for one pool: terms and state, never a secret.
fn list_enrollments(state: &State, request: &Request, query: &str) -> Route {
    let who = super::admin::platform(state, request, false)?;
    let pool = pool_filter(query)?;
    let before = super::admin::before(query)?.map(UnixMillis);
    let limit = super::admin::limit(query);
    let authority = who.authority();
    let found = state
        .store
        .read(move |c| {
            workers::list_enrollments(c, authority, pool, before, limit, UnixMillis::now())
        })
        .map_err(store_error)?;
    let next = (found.len() == usize::from(limit))
        .then(|| found.last().map(|e| e.created.0))
        .flatten();
    ok(json!({
        "enrollments": found.iter().map(status_json).collect::<Vec<_>>(),
        "next_before": next,
    }))
}

/// Every live worker with the host policy the controller approved, what it reported and what it is
/// offered, optionally for one pool. No fingerprint, node key or enrollment secret is part of it.
fn list_hosts(state: &State, request: &Request, query: &str) -> Route {
    let who = super::admin::platform(state, request, false)?;
    let pool = pool_filter(query)?;
    let authority = who.authority();
    let hosts = state
        .store
        .read(move |c| workers::hosts(c, authority, pool))
        .map_err(store_error)?;
    let connected = state.controller.connected();
    ok(json!({
        "workers": hosts.iter().map(|(w, view)| {
            let mut host = json!({
                "id": w.id.to_string(),
                "pool": w.pool.to_string(),
                "name": w.name,
                "arch": format!("{:?}", w.negotiated.arch).to_lowercase(),
                "enrolled_ms": w.enrolled.0,
                "last_seen_ms": w.last_seen.map(|t| t.0),
                "connected": connected.contains(&w.id),
                "software": w.software,
                "transport": if w.node_key.is_some() { "tailcat" } else { "direct" },
                "uninstall_requested_ms": w.uninstall_requested.map(|t| t.0),
            });
            host["host"] = view_json(view);
            host
        }).collect::<Vec<_>>(),
    }))
}

/// The most a redemption body can be: a secret, an identifier, a name, a fingerprint and a node key.
const MAX_REDEEM_BODY_BYTES: usize = 2 << 10;
/// One answer for every way a secret can fail, so the response never says which case applied.
const REDEEM_REFUSED: &str = "the enrollment secret is not valid, was already used or has expired";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemBody {
    secret: String,
    worker: String,
    name: String,
    /// BLAKE3 of the worker's link certificate, 64 lower-case hex characters.
    fingerprint: String,
    arch: String,
    /// `nodekey:<64 hex>`; present for a Tailcat enrollment and absent for a direct one.
    #[serde(default)]
    node_key: Option<String>,
}

fn digest_of(text: &str) -> Option<Digest> {
    if text.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(Digest(out))
}

/// A machine redeems its enrollment: the secret, in the body and never in a URL, authorizes the TLS
/// fingerprint and the Tailcat node key it presents, and one store transaction binds both to the pool
/// and spends the secret. The answer is the controller's trust data, so the worker can pin it and
/// connect. Unauthenticated by design (the secret is the credential), so it is bounded: a small body,
/// per-address and overall budgets, one uniform refusal and a capped audit trail.
fn redeem(state: &State, request: &mut Request) -> Route {
    let Some(bootstrap) = state
        .worker_bootstrap
        .as_deref()
        .filter(|b| b.redeems_over_https())
    else {
        return Err(err(ErrorCode::NotFound, "not found"));
    };
    let json_body = header_value(request, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(JSON))
    });
    if !json_body {
        return Err(err(
            ErrorCode::InvalidRequest,
            "this route takes an application/json body",
        ));
    }
    if header_value(request, "origin").is_some() {
        return Err(err(
            ErrorCode::Forbidden,
            "requests from a browser page are refused",
        ));
    }
    if !oauth::admitted(state, request, Budget::Redeem) {
        return Err(
            err(ErrorCode::RateLimited, "too many requests; retry later")
                .with_detail("retry_after_ms", 12_000),
        );
    }
    let body: RedeemBody = parse(&public_body_limit(request, MAX_REDEEM_BODY_BYTES)?)?;
    // A malformed secret is refused before the store: only well-formed guesses reach the audit trail.
    let Some(secret) = sentinel_auth::token::parse(&body.secret) else {
        return Err(err(ErrorCode::Forbidden, REDEEM_REFUSED));
    };
    let worker: WorkerId = id(&body.worker, "worker")?;
    let fingerprint = digest_of(&body.fingerprint).ok_or_else(|| {
        err(
            ErrorCode::InvalidRequest,
            "fingerprint must be 64 lower-case hex characters",
        )
    })?;
    let arch = match body.arch.as_str() {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        _ => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "arch must be x86_64 or aarch64",
            ));
        }
    };
    let node_key = match body.node_key.as_deref() {
        None => None,
        Some(text) => Some(workers::parse_node_key(text).ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                "node_key must be nodekey:<64 hex>",
            )
        })?),
    };
    // Checked before the write: the answer for a Tailcat machine carries the controller's address, and a
    // secret must not be spent on a reply the controller cannot yet complete.
    let tailcat_address = match node_key {
        Some(_) => Some(
            bootstrap
                .tailcat_configured()
                .then(|| bootstrap.tailcat_address())
                .flatten()
                .ok_or_else(|| {
                    err(
                        ErrorCode::RateLimited,
                        "the controller is not serving Tailcat yet; retry shortly",
                    )
                    .with_detail("retry_after_ms", 5_000)
                })?,
        ),
        None => None,
    };
    let name = body.name;
    let enrolled = state
        .store
        .writer()
        .write(move |tx| {
            workers::redeem_presented(
                tx,
                &secret,
                workers::Presentation {
                    worker,
                    fingerprint,
                    name: &name,
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(1),
                        capabilities: Capabilities::REQUIRED,
                        arch,
                    },
                },
                node_key,
                UnixMillis::now(),
            )
        })
        .map_err(|e| match e {
            sentinel_store::Error::Conflict => err(
                ErrorCode::Conflict,
                "this worker identity or node key is already enrolled",
            ),
            e => store_error(e),
        })?;
    let Some(enrolled) = enrolled else {
        return Err(err(ErrorCode::Forbidden, REDEEM_REFUSED));
    };
    if let Some(notify) = &state.on_worker_enrolled {
        (notify.0)();
    }
    Ok(Reply::Json(
        200,
        json!({
            "worker": enrolled.id.to_string(),
            "pool": enrolled.pool.to_string(),
            "transport": transport_name(node_key.is_some()),
            "host": policy_json(&enrolled.policy),
            "controller": bootstrap.controller().to_string(),
            "controller_fingerprint": bootstrap.fingerprint(),
            // A credential: shown to the holder of the secret only, and never logged.
            "tailcat_address": tailcat_address.as_ref().map(|a| a.expose()),
        }),
        vec![header("cache-control", "no-store")],
    ))
}
