//! Route handling: one function per route, all through the same
//! authenticate → authorize → store → JSON path, with `sentinel.error/1`
//! for every refusal. Nothing here reads a tenant's rows without the
//! `auth` predicate that says the caller may.

use std::io::Read;

use sentinel_auth::cookie;
use sentinel_core::{
    AttemptId, JobId, JobState, RunId, RunState, UnixMillis,
    auth::{Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str, schema::Arch};
use sentinel_protocol::{
    error::{ApiError, ErrorCode},
    idempotency::{Fingerprint, IdempotencyKey},
    limits::{MAX_API_BODY_BYTES, MAX_PAGE_ITEMS, page_size},
};
use sentinel_store::{
    Error as StoreError, auth as authz, auth::Authority, dispatch, idempotency, local_auth, lookup,
    runs, status, tenancy, workers,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tiny_http::{Header, Request, Response, StatusCode};

use crate::{
    LOG_WAIT, State,
    auth::{self, Identity, Refusal},
    web,
};

type Reply = Result<(u16, Value, Vec<Header>), ApiError>;

const JSON: &str = "application/json";

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn ok(value: Value) -> Reply {
    Ok((200, value, Vec::new()))
}

fn err(code: ErrorCode, message: impl Into<String>) -> ApiError {
    ApiError::new(code, message)
}

/// The store's refusals as the API's.
fn store_error(e: StoreError) -> ApiError {
    match e {
        StoreError::NotFound => err(ErrorCode::NotFound, "not found"),
        StoreError::Forbidden => err(ErrorCode::Forbidden, "not permitted"),
        StoreError::StepUpRequired => {
            err(ErrorCode::Forbidden, "step-up required").with_detail("step_up", true)
        }
        StoreError::Conflict | StoreError::Transition(_) => {
            err(ErrorCode::Conflict, "not allowed from the current state")
        }
        StoreError::InvalidInput(what) => err(ErrorCode::InvalidRequest, format!("invalid {what}")),
        StoreError::Unresolved => err(
            ErrorCode::InvalidRequest,
            "image digest and platform not resolved",
        ),
        StoreError::WriterUnavailable | StoreError::Overloaded | StoreError::WriteAmbiguous => {
            err(ErrorCode::RateLimited, "controller busy; retry")
        }
        _ => err(ErrorCode::Internal, "controller fault"),
    }
}

/// Serve one request end to end; nothing here panics on client input.
pub(crate) fn handle(state: &State, mut request: Request) {
    let method = request.method().as_str().to_owned();
    let url = request.url().to_owned();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (url.clone(), String::new()),
    };
    if method == "GET" && path == "/" {
        let response = Response::from_string(web::INDEX_HTML)
            .with_header(header("content-type", "text/html; charset=utf-8"));
        let _ = request.respond(response);
        return;
    }
    let outcome = route(state, &mut request, &method, &path, &query);
    let (status, body, headers) = match outcome {
        Ok(reply) => reply,
        Err(error) => (error.http_status(), json!(error), Vec::new()),
    };
    let mut response = Response::from_string(body.to_string())
        .with_status_code(StatusCode(status))
        .with_header(header("content-type", JSON))
        .with_header(header("cache-control", "no-store"));
    for h in headers {
        response = response.with_header(h);
    }
    let _ = request.respond(response);
}

fn header_value<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// Read a JSON body within the protocol limit.
fn body(request: &mut Request) -> Result<Vec<u8>, ApiError> {
    if request
        .body_length()
        .is_some_and(|n| n > MAX_API_BODY_BYTES)
    {
        return Err(err(ErrorCode::PayloadTooLarge, "body too large")
            .with_detail("limit_bytes", MAX_API_BODY_BYTES));
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_API_BODY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| err(ErrorCode::InvalidRequest, "unreadable body"))?;
    if bytes.len() > MAX_API_BODY_BYTES {
        return Err(err(ErrorCode::PayloadTooLarge, "body too large")
            .with_detail("limit_bytes", MAX_API_BODY_BYTES));
    }
    Ok(bytes)
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|_| err(ErrorCode::InvalidRequest, "invalid JSON body"))
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn identify(state: &State, request: &Request, mutation: bool) -> Result<Identity, ApiError> {
    auth::identify(
        &state.store,
        header_value(request, "authorization"),
        header_value(request, "cookie"),
        header_value(request, cookie::CSRF_HEADER),
        mutation,
        UnixMillis::now(),
    )
    .map_err(|refusal| match refusal {
        Refusal::Unauthenticated => err(
            ErrorCode::Unauthenticated,
            "sign in or present a credential",
        ),
        Refusal::Csrf => err(ErrorCode::Forbidden, "missing or wrong CSRF header"),
    })
}

fn id<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, ApiError> {
    text.parse().map_err(|_| {
        err(
            ErrorCode::InvalidRequest,
            format!("malformed {what} identifier"),
        )
    })
}

fn route(state: &State, request: &mut Request, method: &str, path: &str, query: &str) -> Reply {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["api", "v1", "health"]) => ok(json!({ "ok": true })),
        ("POST", ["api", "v1", "login"]) => login(state, request),
        ("POST", ["api", "v1", "logout"]) => logout(state, request),
        ("GET", ["api", "v1", "me"]) => {
            let who = identify(state, request, false)?;
            ok(json!({
                "user": who.user.to_string(),
                "super_admin": who.super_admin,
                "via": match who.via { auth::Via::Bearer => "bearer", auth::Via::Session => "session" },
                "tenant": who.principal.tenant.map(|t| t.to_string()),
                "repo": who.principal.repo.map(|r| r.to_string()),
            }))
        }
        ("GET", ["api", "v1", "tenants", slug, "repos"]) => {
            let who = identify(state, request, false)?;
            let slug = (*slug).to_owned();
            let repos = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    authz::list_repos(c, who.principal, tenant, None, 100)
                })
                .map_err(store_error)?;
            ok(json!({
                "repos": repos.iter().map(|r| json!({ "id": r.id.to_string(), "name": r.name })).collect::<Vec<_>>()
            }))
        }
        ("GET", ["api", "v1", "tenants", slug, "repos", name, "runs"]) => {
            let who = identify(state, request, false)?;
            let (slug, name) = ((*slug).to_owned(), (*name).to_owned());
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()))
                .min(MAX_PAGE_ITEMS) as u16;
            let runs = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    let repo = lookup::repo_by_name(c, tenant, &name)?;
                    authz::require_repo(c, who.principal, repo, Permissions::READ)?;
                    status::recent_runs(c, tenant, repo, limit)
                })
                .map_err(store_error)?;
            ok(json!({
                "runs": runs.iter().map(|r| json!({
                    "id": r.id.to_string(), "sha": r.sha, "created_ms": r.created.0,
                    "state": run_state(r.state),
                })).collect::<Vec<_>>()
            }))
        }
        ("POST", ["api", "v1", "tenants", slug, "repos", name, "runs"]) => {
            dispatch_run(state, request, slug, name)
        }
        ("GET", ["api", "v1", "runs", run]) => {
            let who = identify(state, request, false)?;
            let run: RunId = id(run, "run")?;
            let view = state
                .store
                .read(|c| {
                    let repo = lookup::run_repo(c, run)?;
                    let tenant = authz::require_repo(c, who.principal, repo, Permissions::READ)?;
                    status::run(c, tenant, run)
                })
                .map_err(store_error)?;
            ok(run_json(&view))
        }
        ("POST", ["api", "v1", "runs", run, "cancel"]) => {
            let who = identify(state, request, true)?;
            let run: RunId = id(run, "run")?;
            let tenant = authorize_run(state, who.principal, run, Permissions::RUN)?;
            let count = state
                .store
                .writer()
                .write(move |tx| dispatch::cancel_run(tx, tenant, run, UnixMillis::now()))
                .map_err(store_error)?;
            state.controller.wake();
            ok(json!({ "run": run.to_string(), "canceled": count }))
        }
        ("POST", ["api", "v1", "jobs", job, "cancel"]) => {
            let who = identify(state, request, true)?;
            let job: JobId = id(job, "job")?;
            let tenant = authorize_job(state, who.principal, job, Permissions::RUN)?;
            let outcome = state
                .store
                .writer()
                .write(move |tx| dispatch::cancel(tx, tenant, job, UnixMillis::now()))
                .map_err(store_error)?;
            state.controller.wake();
            ok(json!({ "job": job.to_string(), "outcome": format!("{outcome:?}").to_lowercase() }))
        }
        ("POST", ["api", "v1", "jobs", job, "rerun"]) => {
            let who = identify(state, request, true)?;
            let job: JobId = id(job, "job")?;
            let tenant = authorize_job(state, who.principal, job, Permissions::RUN)?;
            let next = state
                .store
                .writer()
                .write(move |tx| runs::rerun_job(tx, tenant, job, UnixMillis::now()))
                .map_err(store_error)?;
            state.controller.wake();
            ok(json!({ "job": job.to_string(), "state": next.as_str() }))
        }
        ("GET", ["api", "v1", "attempts", attempt, "logs"]) => {
            let who = identify(state, request, false)?;
            let attempt: AttemptId = id(attempt, "attempt")?;
            state
                .store
                .read(|c| {
                    let job = lookup::attempt_job(c, attempt)?;
                    let run = lookup::job_run(c, job)?;
                    let repo = lookup::run_repo(c, run)?;
                    authz::require_repo(c, who.principal, repo, Permissions::READ)
                })
                .map_err(store_error)?;
            let after: u64 = query_param(query, "after")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()));
            let wait = query_param(query, "wait").is_some_and(|v| v == "1" || v == "true");
            let deadline = std::time::Instant::now() + LOG_WAIT;
            let tail = loop {
                let tail = state
                    .logs
                    .tail(attempt, after, limit)
                    .map_err(store_error)?;
                if !wait || !tail.frames.is_empty() || tail.complete {
                    break tail;
                }
                if std::time::Instant::now() >= deadline
                    || state.stop.load(std::sync::atomic::Ordering::Acquire)
                {
                    break tail;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            };
            ok(json!({
                "attempt": attempt.to_string(),
                "complete": tail.complete,
                "gaps": tail.gaps,
                "frames": tail.frames.iter().map(|f| json!({
                    "seq": f.seq, "step": f.step,
                    "stream": match f.stream { sentinel_protocol::logs::Stream::Stdout => "stdout", sentinel_protocol::logs::Stream::Stderr => "stderr" },
                    "text": String::from_utf8_lossy(&f.bytes),
                })).collect::<Vec<_>>(),
            }))
        }
        ("GET", ["api", "v1", "workers"]) => {
            let who = identify(state, request, false)?;
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
                        out.push((pool, live));
                    }
                    Ok(out)
                })
                .map_err(store_error)?;
            ok(json!({
                "pools": pools.iter().map(|(pool, live)| json!({
                    "id": pool.id.to_string(), "name": pool.name, "active": pool.active,
                    "kind": match pool.kind { tenancy::PoolKind::Shared => "shared", tenancy::PoolKind::Dedicated(_) => "dedicated" },
                    "workers": live.iter().map(|w| json!({
                        "id": w.id.to_string(), "name": w.name,
                        "arch": format!("{:?}", w.negotiated.arch).to_lowercase(),
                        "connected": connected.contains(&w.id),
                        "last_seen_ms": w.last_seen.map(|t| t.0),
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>()
            }))
        }
        _ => Err(err(ErrorCode::NotFound, "no such route")),
    }
}

fn authorize_run(
    state: &State,
    principal: Principal,
    run: RunId,
    required: Permissions,
) -> Result<sentinel_core::TenantId, ApiError> {
    state
        .store
        .read(|c| {
            let repo = lookup::run_repo(c, run)?;
            authz::require_repo(c, principal, repo, required)
        })
        .map_err(store_error)
}

fn authorize_job(
    state: &State,
    principal: Principal,
    job: JobId,
    required: Permissions,
) -> Result<sentinel_core::TenantId, ApiError> {
    state
        .store
        .read(|c| {
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            authz::require_repo(c, principal, repo, required)
        })
        .map_err(store_error)
}

fn run_state(state: RunState) -> &'static str {
    match state {
        RunState::Pending => "pending",
        RunState::Active => "active",
        RunState::Terminal(outcome) => outcome.as_str(),
    }
}

fn run_json(view: &status::RunStatus) -> Value {
    json!({
        "id": view.id.to_string(),
        "tenant": view.tenant.to_string(),
        "repo": view.repo.to_string(),
        "sha": view.sha,
        "created_ms": view.created.0,
        "cancel_requested": view.cancel_requested,
        "state": run_state(view.state),
        "jobs": view.jobs.iter().map(|j| json!({
            "id": j.id.to_string(),
            "name": j.name,
            "state": j.state.as_str(),
            "terminal": matches!(j.state, JobState::Terminal(_)),
            "failure_class": j.failure_class.map(|c| c.as_str()),
            "cancel_requested": j.cancel_requested,
            "attempt": j.attempt.map(|a| a.to_string()),
            "fence": j.fence,
            "timestamps": {
                "queued_ms": j.timestamps.queued.map(|t| t.0),
                "leased_ms": j.timestamps.leased.map(|t| t.0),
                "preparing_ms": j.timestamps.preparing.map(|t| t.0),
                "running_ms": j.timestamps.running.map(|t| t.0),
                "finalizing_ms": j.timestamps.finalizing.map(|t| t.0),
                "terminal_ms": j.timestamps.terminal.map(|t| t.0),
            },
        })).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

fn login(state: &State, request: &mut Request) -> Reply {
    let bytes = body(request)?;
    let creds: LoginBody = parse(&bytes)?;
    let outcome = local_auth::login(
        &state.store,
        &creds.username,
        creds.password.as_bytes(),
        state.sessions,
        UnixMillis::now(),
    )
    .map_err(store_error)?;
    match outcome {
        local_auth::Login::Accepted(issued) => {
            let mut csrf = String::new();
            issued.csrf.expose(&mut csrf);
            let set_cookie =
                cookie::issue(cookie::SESSION_COOKIE, &issued.session, issued.max_age_secs);
            Ok((
                200,
                json!({ "user": issued.user.to_string(), "csrf": csrf }),
                vec![header("set-cookie", &set_cookie)],
            ))
        }
        // One answer for every non-accepted outcome; the audit trail has the detail.
        local_auth::Login::Rejected | local_auth::Login::Locked { .. } => {
            Err(err(ErrorCode::Unauthenticated, "sign-in refused"))
        }
    }
}

fn logout(state: &State, request: &mut Request) -> Reply {
    let who = identify(state, request, true)?;
    if who.via != auth::Via::Session {
        return Err(err(
            ErrorCode::InvalidRequest,
            "logout applies to a session",
        ));
    }
    if let Some(secret) =
        header_value(request, "cookie").and_then(|h| cookie::read(cookie::SESSION_COOKIE, h))
    {
        let _ = local_auth::logout(&state.store, &secret, UnixMillis::now());
    }
    Ok((
        200,
        json!({ "ok": true }),
        vec![header("set-cookie", &cookie::clear(cookie::SESSION_COOKIE))],
    ))
}

#[derive(Deserialize)]
struct SourceBody {
    repo: String,
    sha: String,
    #[serde(rename = "ref")]
    ref_name: Option<String>,
}

#[derive(Deserialize)]
struct DispatchBody {
    pipeline: String,
    source: SourceBody,
}

/// Dispatch: compile the pipeline, pin the source, create the run and its
/// jobs under the caller's `run` grant, resolve every digest-pinned image,
/// and wake the dispatcher. Idempotent under `Idempotency-Key`.
fn dispatch_run(state: &State, request: &mut Request, slug: &str, name: &str) -> Reply {
    let who = identify(state, request, true)?;
    let key = header_value(request, "idempotency-key")
        .map(|raw| {
            IdempotencyKey::parse(raw)
                .map_err(|_| err(ErrorCode::InvalidRequest, "malformed Idempotency-Key"))
        })
        .transpose()?;
    let bytes = body(request)?;
    let fingerprint = Fingerprint::of(&bytes);
    let dispatch: DispatchBody = parse(&bytes)?;
    if dispatch.pipeline.len() > sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES {
        return Err(
            err(ErrorCode::PayloadTooLarge, "pipeline too large").with_detail(
                "limit_bytes",
                sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES,
            ),
        );
    }
    let compiled = compile_str(&dispatch.pipeline)
        .map_err(|e| err(ErrorCode::InvalidRequest, format!("pipeline: {e}")))?;
    let source = PinnedSource::new(
        &dispatch.source.repo,
        &dispatch.source.sha,
        dispatch.source.ref_name.as_deref(),
    )
    .map_err(|e| err(ErrorCode::InvalidRequest, format!("source: {e:?}")))?;
    let spec = RunSpec::new(source, compiled)
        .map_err(|e| err(ErrorCode::InvalidRequest, format!("spec: {e:?}")))?;
    // Every image must be pinned by digest: the worker pulls exactly those
    // bytes, and no resolver exists yet for a tag.
    let mut images = Vec::with_capacity(spec.pipeline.jobs.len());
    for job in &spec.pipeline.jobs {
        let image = sentinel_pipeline::ImageRef::parse(&job.spec.image)
            .map_err(|_| err(ErrorCode::InvalidRequest, "image reference"))?;
        let digest = image.digest.ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                format!("jobs.{}: image must be pinned by digest", job.name),
            )
        })?;
        let platform = match job.spec.runs_on.arch {
            Some(Arch::Arm64) => "linux/arm64",
            _ => "linux/amd64",
        };
        images.push((digest, platform));
    }
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    let principal_text = who.user.to_string();
    let created = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = lookup::tenant_by_slug(tx, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            let scope = idempotency::Scope {
                tenant,
                principal: &principal_text,
                route: "runs.create",
            };
            let now = UnixMillis::now();
            if let Some(key) = key {
                match idempotency::begin(tx, scope, key, fingerprint, now)? {
                    idempotency::Begin::Execute => {}
                    idempotency::Begin::Replay(run) => return Ok(Err(Some(run))),
                    idempotency::Begin::Mismatch => return Ok(Err(None)),
                    idempotency::Begin::InFlight => return Err(StoreError::WriteAmbiguous),
                }
            }
            let run = RunId::new();
            let jobs = authz::create_run(tx, principal, repo, run, &spec, now)?;
            for (job, (digest, platform)) in jobs.iter().zip(&images) {
                runs::resolve_image(tx, tenant, *job, digest, platform)?;
            }
            if let Some(key) = key {
                idempotency::complete(tx, scope, key, run)?;
            }
            Ok(Ok((tenant, run, jobs)))
        })
        .map_err(store_error)?;
    match created {
        Ok((tenant, run, _)) => {
            state.controller.wake();
            let view = state
                .store
                .read(|c| status::run(c, tenant, run))
                .map_err(store_error)?;
            Ok((201, run_json(&view), Vec::new()))
        }
        Err(Some(run)) => {
            let view = state
                .store
                .read(|c| {
                    let repo = lookup::run_repo(c, run)?;
                    let tenant = authz::require_repo(c, principal, repo, Permissions::READ)?;
                    status::run(c, tenant, run)
                })
                .map_err(store_error)?;
            Ok((200, run_json(&view), Vec::new()))
        }
        Err(None) => Err(err(
            ErrorCode::IdempotencyMismatch,
            "Idempotency-Key was used with a different body",
        )),
    }
}
