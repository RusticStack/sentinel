//! Route handling: one function per route, all through the same
//! authenticate → authorize → store → JSON path, with `sentinel.error/1`
//! for every refusal. Nothing here reads a tenant's rows without the
//! `auth` predicate that says the caller may.

use std::{io::Read, io::Seek, io::SeekFrom, sync::Arc};

use crate::http::{Header, Request, Response, StatusCode};
use sentinel_auth::cookie;
use sentinel_core::{
    ArtifactId, AttemptId, JobId, JobState, RepoId, RunId, RunState, UnixMillis, UploadId,
    WorkerId,
    auth::{Permissions, Principal, Scopes},
};
use sentinel_intake::ingest;
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    error::{ApiError, ErrorCode},
    idempotency::{Fingerprint, IdempotencyKey},
    intake::{MAX_HOOK_BODY_BYTES, MAX_WEBHOOK_BODY_BYTES},
    limits::{MAX_API_BODY_BYTES, MAX_PAGE_ITEMS, page_size},
};
use sentinel_store::{
    Error as StoreError, artifacts, auth as authz, auth::Authority, checks, dispatch, idempotency,
    local_auth, logs, lookup, objects::Digest, provenance, runs, status, tenancy, workers,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    LOG_WAIT, MAX_UPLOAD_CHUNK, State, TRANSFERS,
    auth::{self, Identity, Refusal},
    web,
};

/// What a route answers: a JSON body, a bounded stream from the object
/// store, or an HTML page (OAuth consent and device pages, and `303`
/// redirects with an empty body and a `location`). Streams carry an
/// explicit length so the response is never chunked. HTML replies always
/// carry the page security headers ([`crate::oauth::html`]).
pub(crate) enum Reply {
    Json(u16, Value, Vec<Header>),
    Stream(u16, Box<dyn Read + Send>, u64, Vec<Header>),
    Html(u16, String, Vec<Header>),
}
pub(crate) type Route = Result<Reply, ApiError>;

const JSON: &str = "application/json";

pub(crate) fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

pub(crate) fn ok(value: Value) -> Route {
    Ok(Reply::Json(200, value, Vec::new()))
}

pub(crate) fn err(code: ErrorCode, message: impl Into<String>) -> ApiError {
    ApiError::new(code, message)
}

/// The store's refusals as the API's.
pub(crate) fn store_error(e: StoreError) -> ApiError {
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
        StoreError::WriterUnavailable | StoreError::Overloaded => {
            err(ErrorCode::RateLimited, "controller busy; retry")
        }
        // The write is still queued or running and may yet commit: an
        // identical unkeyed retry could apply it twice (P02-1).
        StoreError::WriteAmbiguous => err(
            ErrorCode::OutcomeUnknown,
            "the write may still commit; re-read before retrying",
        )
        .with_detail("retry_with_idempotency_key", true),
        StoreError::StorageFull => err(ErrorCode::StorageFull, "storage below watermark; retry"),
        StoreError::QuotaExceeded => err(ErrorCode::QuotaExceeded, "tenant storage quota exceeded"),
        _ => err(ErrorCode::Internal, "controller fault"),
    }
}

/// Serve one request end to end; nothing here panics on client input.
pub(crate) fn handle(state: &State, request: &mut Request) {
    let method = request.method().to_owned();
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
    let outcome = route(state, request, &method, &path, &query);
    let reply = match outcome {
        Ok(reply) => reply,
        Err(error) => {
            let headers = challenge(state, request, &path, &error);
            Reply::Json(error.http_status(), json!(error), headers)
        }
    };
    match reply {
        Reply::Json(status, body, headers) => {
            let mut response = Response::from_string(body.to_string())
                .with_status_code(StatusCode(status))
                .with_header(header("content-type", JSON))
                .with_header(header("cache-control", "no-store"));
            for h in headers {
                response = response.with_header(h);
            }
            let _ = request.respond(response);
        }
        Reply::Html(status, body, headers) => {
            let mut response = Response::from_string(body)
                .with_status_code(StatusCode(status))
                .with_header(header("content-type", "text/html; charset=utf-8"));
            for (name, value) in crate::oauth::html::SECURITY_HEADERS {
                response = response.with_header(header(name, value));
            }
            for h in headers {
                response = response.with_header(h);
            }
            let _ = request.respond(response);
        }
        Reply::Stream(status, reader, len, headers) => {
            let mut response = Response::new(
                StatusCode(status),
                vec![
                    header("content-type", "application/octet-stream"),
                    header("cache-control", "no-store"),
                ],
                reader,
                Some(len as usize),
                None,
            );
            for h in headers {
                response = response.with_header(h);
            }
            let _ = request.respond(response);
        }
    }
}

/// The `WWW-Authenticate` challenge of an `/api/v1` refusal (RFC 6750 §3,
/// RFC 9728 §5.1): every `401` names the protected-resource metadata, plus
/// `error="invalid_token"` when a token was presented; a scope refusal
/// names the missing scope. The GitHub and intake hooks have their own
/// secrets and are not OAuth resources.
fn challenge(state: &State, request: &Request, path: &str, error: &ApiError) -> Vec<Header> {
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return Vec::new();
    };
    if rest.starts_with("hooks/") || rest.starts_with("intake/") || rest == "login" {
        return Vec::new();
    }
    match error.code {
        ErrorCode::Unauthenticated => {
            let mut value = format!(
                "Bearer realm=\"sentinel\", resource_metadata=\"{}{}\"",
                state.oauth.issuer,
                sentinel_protocol::oauth::PROTECTED_RESOURCE_PATH
            );
            if header_value(request, "authorization").is_some() {
                value.push_str(", error=\"invalid_token\"");
            }
            vec![header("www-authenticate", &value)]
        }
        ErrorCode::Forbidden => match error
            .details
            .as_ref()
            .and_then(|d| d.get("scope"))
            .and_then(Value::as_str)
        {
            Some(scope) => vec![header(
                "www-authenticate",
                &format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\""),
            )],
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

pub(crate) fn header_value<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// Read a JSON body within the protocol limit.
pub(crate) fn body(request: &mut Request) -> Result<Vec<u8>, ApiError> {
    body_limit(request, MAX_API_BODY_BYTES)
}

/// Read a body within a route-specific limit, before anything is buffered.
pub(crate) fn body_limit(request: &mut Request, limit: usize) -> Result<Vec<u8>, ApiError> {
    if request.body_length().is_some_and(|n| n > limit) {
        return Err(
            err(ErrorCode::PayloadTooLarge, "body too large").with_detail("limit_bytes", limit)
        );
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| err(ErrorCode::InvalidRequest, "unreadable body"))?;
    if bytes.len() > limit {
        return Err(
            err(ErrorCode::PayloadTooLarge, "body too large").with_detail("limit_bytes", limit)
        );
    }
    Ok(bytes)
}

pub(crate) fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|_| err(ErrorCode::InvalidRequest, "invalid JSON body"))
}

pub(crate) fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

pub(crate) fn identify(
    state: &State,
    request: &Request,
    mutation: bool,
) -> Result<Identity, ApiError> {
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

pub(crate) fn id<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, ApiError> {
    text.parse().map_err(|_| {
        err(
            ErrorCode::InvalidRequest,
            format!("malformed {what} identifier"),
        )
    })
}

fn route(state: &State, request: &mut Request, method: &str, path: &str, query: &str) -> Route {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // The OAuth authorization server owns `/.well-known/*`, `/oauth/*`,
    // `/device`, `/api/v1/grants*` and `/api/v1/tenants/*/service-accounts*`.
    if let Some(reply) = crate::oauth::route(state, request, method, &parts, query) {
        return reply;
    }
    match (method, parts.as_slice()) {
        ("GET", ["api", "v1", "health"]) => ok(json!({ "ok": true })),
        ("POST", ["api", "v1", "hooks", "github"]) => github_hook(state, request),
        ("POST", ["api", "v1", "intake", repo]) => generic_intake(state, request, repo),
        ("POST", ["api", "v1", "login"]) => login(state, request),
        ("POST", ["api", "v1", "logout"]) => logout(state, request),
        ("GET", ["api", "v1", "me"]) => {
            let who = identify(state, request, false)?;
            let username = state
                .store
                .read(|c| local_auth::username_of(c, who.user))
                .map_err(store_error)?;
            ok(json!({
                "user": who.user.to_string(),
                "username": username,
                "super_admin": who.super_admin,
                "via": match who.via {
                    auth::Via::Bearer => "bearer",
                    auth::Via::Session => "session",
                    auth::Via::OAuth => "oauth",
                },
                "tenant": who.principal.tenant.map(|t| t.to_string()),
                "repo": who.principal.repo.map(|r| r.to_string()),
                "scopes": who.scopes.names().collect::<Vec<_>>(),
                "grant": who.grant.map(|g| g.to_string()),
                "expires_ms": who.expires.map(|t| t.0),
            }))
        }
        ("GET", ["api", "v1", "tenants", slug, "repos"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
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
            auth::require_scope(&who, Scopes::RUNS_READ)?;
            let (slug, name) = ((*slug).to_owned(), (*name).to_owned());
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()))
                .min(MAX_PAGE_ITEMS) as u16;
            // Keyset cursor: the last run of the previous page.
            let before: Option<RunId> = query_param(query, "before")
                .map(|v| id(v, "run"))
                .transpose()?;
            let page = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    let repo = lookup::repo_by_name(c, tenant, &name)?;
                    authz::require_repo(c, who.principal, repo, Permissions::READ)?;
                    status::runs_page(c, tenant, repo, before, limit)
                })
                .map_err(store_error)?;
            ok(json!({
                "runs": page.runs.iter().map(|r| json!({
                    "id": r.id.to_string(), "sha": r.sha, "created_ms": r.created.0,
                    "state": run_state(r.state),
                })).collect::<Vec<_>>(),
                "next": page.next.map(|r| r.to_string()),
            }))
        }
        ("POST", ["api", "v1", "tenants", slug, "repos", name, "runs"]) => {
            dispatch_run(state, request, slug, name)
        }
        ("GET", ["api", "v1", "runs", run, "wait"]) => run_wait(state, request, run, query),
        ("GET", ["api", "v1", "attempts", attempt, "logs", "search"]) => {
            log_search(state, request, attempt, query)
        }
        ("GET", ["api", "v1", "attempts", attempt, "summary"]) => {
            attempt_summary(state, request, attempt)
        }
        ("GET", ["api", "v1", "runs", run]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
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
            auth::require_scope(&who, Scopes::RUNS_WRITE)?;
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
            auth::require_scope(&who, Scopes::RUNS_WRITE)?;
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
            auth::require_scope(&who, Scopes::RUNS_WRITE)?;
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
        ("GET", ["api", "v1", "runs", run, "artifacts"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::ARTIFACTS_READ)?;
            let run: RunId = id(run, "run")?;
            let (slug, rows) = state
                .store
                .read(|c| {
                    let repo = lookup::run_repo(c, run)?;
                    let (tenant, slug) =
                        authz::require_repo_slug(c, who.principal, repo, Permissions::READ)?;
                    Ok((slug, artifacts::for_run(c, tenant, run)?))
                })
                .map_err(store_error)?;
            ok(json!({
                "tenant": slug,
                "artifacts": rows.iter().map(artifact_json).collect::<Vec<_>>()
            }))
        }
        ("GET", ["api", "v1", "runs", run, "artifacts", art]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::ARTIFACTS_READ)?;
            let (run, art): (RunId, ArtifactId) = (id(run, "run")?, id(art, "artifact")?);
            let (slug, row, manifest) = state
                .store
                .read(|c| {
                    let repo = lookup::run_repo(c, run)?;
                    let (tenant, slug) =
                        authz::require_repo_slug(c, who.principal, repo, Permissions::READ)?;
                    let row = artifacts::get(c, tenant, run, art)?;
                    let manifest = match row.manifest_version {
                        Some(version) => Some(state.objects.manifest(
                            c,
                            tenant,
                            sentinel_store::objects::Kind::Artifact,
                            &artifacts::manifest_name(row.job, &row.name),
                            Some(version),
                        )?),
                        None => None,
                    };
                    Ok((slug, row, manifest))
                })
                .map_err(store_error)?;
            let mut body = artifact_json(&row);
            body["tenant"] = Value::String(slug);
            if let Some(manifest) = manifest {
                body["manifest"] = json!({
                    "version": manifest.version,
                    "digest": manifest.digest.to_string(),
                    "payload_len": manifest.payload_len,
                    "entries": manifest.entries.iter().map(|e| json!({
                        "path": e.path,
                        "digest": e.digest.to_string(),
                        "len": e.len,
                        "mode": e.mode,
                    })).collect::<Vec<_>>(),
                });
            }
            ok(body)
        }
        ("GET", ["api", "v1", "attempts", attempt, "logs"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::LOGS_READ)?;
            let attempt: AttemptId = id(attempt, "attempt")?;
            let (run, job) = attempt_log(state, who.principal, attempt)?;
            let after: u64 = query_param(query, "after")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()));
            let step: Option<u32> = query_param(query, "step").and_then(|v| v.parse().ok());
            let wait = query_param(query, "wait").is_some_and(|v| v == "1" || v == "true");
            let deadline = std::time::Instant::now() + LOG_WAIT;
            // Parking holds a handler permit: the poll takes one of the
            // SUBSCRIBERS slots it shares with run waits before it parks.
            let mut parked: Option<Slot<'_>> = None;
            let tail = loop {
                let tail = state
                    .logs
                    .tail(run, job, attempt, after, limit, step)
                    .or_else(|e| match e {
                        // A pre-D04 flat log file is the only fallback.
                        sentinel_store::Error::NotFound => {
                            state.logs.tail_legacy(attempt, after, limit, step)
                        }
                        e => Err(e),
                    })
                    .map_err(store_error)?;
                if !wait || !tail.frames.is_empty() || tail.complete {
                    break tail;
                }
                if std::time::Instant::now() >= deadline
                    || state.stop.load(std::sync::atomic::Ordering::Acquire)
                {
                    break tail;
                }
                if parked.is_none() {
                    parked = Some(subscriber(state)?);
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            };
            drop(parked);
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
        ("GET", ["api", "v1", "queue"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
            let slug = query_param(query, "tenant")
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "tenant query parameter required"))?
                .to_owned();
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()));
            // Placement is decided per transaction against the live session
            // set, so the explanation must use the same set.
            let connected = state.controller.connected();
            let rows = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    authz::require_tenant_member(c, who.principal, tenant, false)?;
                    dispatch::list_queue(c, tenant, &connected)
                })
                .map_err(store_error)?;
            let shown = rows.len().min(limit);
            ok(json!({
                "jobs": rows.iter().take(shown).map(queued_json).collect::<Vec<_>>(),
                "total": rows.len(),
                "truncated": rows.len() > shown,
            }))
        }
        ("POST", ["api", "v1", "workers", worker, "drain"]) => {
            worker_drain(state, request, worker, true)
        }
        ("POST", ["api", "v1", "workers", worker, "undrain"]) => {
            worker_drain(state, request, worker, false)
        }
        ("POST", ["api", "v1", "tenants", slug, "uploads"]) => upload_begin(state, request, slug),
        ("GET", ["api", "v1", "uploads", upload]) => upload_status(state, request, upload),
        ("PUT", ["api", "v1", "uploads", upload]) => upload_chunk(state, request, upload, query),
        ("POST", ["api", "v1", "uploads", upload, "commit"]) => {
            upload_commit(state, request, upload)
        }
        ("DELETE", ["api", "v1", "uploads", upload]) => upload_abort(state, request, upload),
        ("GET", ["api", "v1", "tenants", slug, "objects", digest]) => {
            object_download(state, request, slug, digest)
        }
        _ => Err(err(ErrorCode::NotFound, "no such route")),
    }
}

fn intake_error(error: ingest::Error) -> ApiError {
    match error {
        ingest::Error::Unauthenticated => err(ErrorCode::Unauthenticated, "invalid credential"),
        ingest::Error::InvalidRequest(what) => {
            err(ErrorCode::InvalidRequest, format!("invalid {what}"))
        }
        ingest::Error::NotFound => err(ErrorCode::NotFound, "not found"),
        ingest::Error::Forbidden(what) => err(ErrorCode::Forbidden, format!("forbidden: {what}")),
        ingest::Error::Conflict => err(
            ErrorCode::Conflict,
            "delivery identity reused with different content",
        ),
        ingest::Error::RateLimited => err(ErrorCode::RateLimited, "intake queue full; retry"),
        ingest::Error::Internal => err(ErrorCode::Internal, "controller fault"),
    }
}

/// A header value copied out of the request before its body is read, bounded
/// so a hostile client cannot make the controller buffer unbounded headers.
fn bounded_header(request: &Request, name: &'static str, max: usize) -> Option<String> {
    header_value(request, name)
        .filter(|value| value.len() <= max)
        .map(str::to_owned)
}

/// The `Bearer` value of an Authorization header, scheme case-insensitive.
fn authorization_value(header: &str) -> Option<&str> {
    let (scheme, value) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| value.trim_start())
}

fn wake_intake(state: &State, duplicate: bool) {
    if !duplicate && let Some(waker) = &state.intake {
        waker.wake();
    }
}

/// GitHub App webhooks: signature over the raw body, then the shared intake.
/// Once the signature verifies, everything GitHub may legitimately send is
/// answered 2xx — an unbound repository is a normal state, and an error would
/// make GitHub disable the hook and hide future real events.
fn github_hook(state: &State, request: &mut Request) -> Route {
    let Some(secret) = state.github_webhook_secret.as_deref() else {
        return Err(err(ErrorCode::NotFound, "no such route"));
    };
    let event =
        bounded_header(request, sentinel_github::webhook::EVENT_HEADER, 64).unwrap_or_default();
    let delivery = bounded_header(request, sentinel_github::webhook::DELIVERY_HEADER, 128);
    let signature = bounded_header(request, sentinel_github::webhook::SIGNATURE_HEADER, 128);
    let body = body_limit(request, MAX_WEBHOOK_BODY_BYTES)?;
    let outcome = ingest::github(
        &state.store,
        secret,
        &event,
        delivery.as_deref(),
        signature.as_deref(),
        &body,
        UnixMillis::now(),
    )
    .map_err(intake_error)?;
    match outcome {
        ingest::Github::Pong => ok(json!({ "pong": true })),
        ingest::Github::Ignored(why) => ok(json!({ "ignored": why })),
        ingest::Github::Controlled { outcome, duplicate } => {
            // A rerequest re-queued terminal jobs inside the same receipt
            // transaction; the dispatcher still needs its wake.
            if outcome == "rerequested" && !duplicate {
                state.controller.wake();
            }
            ok(json!({ "controlled": outcome, "duplicate": duplicate }))
        }
        ingest::Github::Ingested(ingested) => {
            wake_intake(state, ingested.duplicate);
            Ok(Reply::Json(
                202,
                json!({ "delivery": ingested.id.to_string(), "duplicate": ingested.duplicate }),
                Vec::new(),
            ))
        }
    }
}

/// Generic ref-update intake: a repository hook secret over the raw body.
fn generic_intake(state: &State, request: &mut Request, repo: &str) -> Route {
    let repo: RepoId = id(repo, "repository")?;
    let presented = bounded_header(request, "authorization", 128)
        .and_then(|header| authorization_value(&header).map(str::to_owned))
        .ok_or_else(|| {
            err(
                ErrorCode::Unauthenticated,
                "present the repository hook secret",
            )
        })?;
    let body = body_limit(request, MAX_HOOK_BODY_BYTES)?;
    let ingested = ingest::generic(&state.store, &presented, repo, &body, UnixMillis::now())
        .map_err(intake_error)?;
    wake_intake(state, ingested.duplicate);
    Ok(Reply::Json(
        202,
        json!({ "delivery": ingested.id.to_string(), "duplicate": ingested.duplicate }),
        Vec::new(),
    ))
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
        "trigger": view.trigger,
        "jobs": view.jobs.iter().map(|j| json!({
            "id": j.id.to_string(),
            "name": j.name,
            "state": j.state.as_str(),
            "terminal": matches!(j.state, JobState::Terminal(_)),
            "failure_class": j.failure_class.map(|c| c.as_str()),
            "cancel_requested": j.cancel_requested,
            "attempt": j.attempt.map(|a| a.to_string()),
            "log_state": j.log_state.map(|s| s.as_str()),
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

fn login(state: &State, request: &mut Request) -> Route {
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
            Ok(Reply::Json(
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

fn logout(state: &State, request: &mut Request) -> Route {
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
        // The session row must go before the client is told it logged out:
        // a failed delete leaves the secret valid, so the error surfaces
        // rather than letting `ok` stand over a live session.
        local_auth::logout(&state.store, &secret, UnixMillis::now()).map_err(store_error)?;
    }
    Ok(Reply::Json(
        200,
        json!({ "ok": true }),
        vec![header("set-cookie", &cookie::clear(cookie::SESSION_COOKIE))],
    ))
}

/// Drain or undrain one worker: it keeps the attempts it already holds, takes
/// no new offers, and stays visible in its pool, so the work it would have
/// taken is explained by `GET /queue` rather than disappearing. Platform
/// administration, like everything else that changes a pool's capacity, and
/// checked against the live platform-admin rows rather than the credential's
/// expired claims.
fn worker_drain(state: &State, request: &mut Request, worker: &str, drain: bool) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::PLATFORM_ADMIN)?;
    let worker: WorkerId = id(worker, "worker")?;
    let authority = Authority::credential(who.principal);
    state
        .store
        .read(move |c| authority.require_platform(c))
        .map_err(store_error)?;
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| {
            if drain {
                workers::drain(tx, authority, worker, now)
            } else {
                workers::undrain(tx, authority, worker)
            }
        })
        .map_err(store_error)?;
    // Placement is decided per transaction from the worker's stored drain
    // state, so a change to it is what the dispatcher's next pass must see.
    state.controller.wake();
    ok(json!({ "worker": worker.to_string(), "draining": drain }))
}

/// One waiting job as the API explains it: how long it has been waiting and
/// what it is waiting for. A queued job and a job blocked on its dependencies
/// are the same question to a person staring at a stuck pipeline.
fn queued_json(row: &dispatch::QueuedJob) -> Value {
    json!({
        "job": row.job.to_string(),
        "run": row.run.to_string(),
        "repo": row.repo.to_string(),
        "age_ms": row.age_ms,
        "reason": wait_reason_json(row.reason),
    })
}

/// The scheduler's reason as a code plus whatever says what is missing. The
/// enum belongs to the store, which gains reasons as placement learns new
/// ones, so a reason this build does not name still reports its own name and
/// numbers instead of an "unknown" the client cannot act on.
fn wait_reason_json(reason: dispatch::WaitReason) -> Value {
    match reason {
        dispatch::WaitReason::Dependency => json!({ "code": "dependency" }),
        dispatch::WaitReason::Policy(what) => json!({ "code": "policy", "detail": what }),
        dispatch::WaitReason::NoMatchingWorker {
            cpu_short,
            memory_short,
        } => json!({
            "code": "no_matching_worker",
            "cpu_short": cpu_short,
            "memory_short": memory_short,
        }),
        dispatch::WaitReason::WorkerOffline => json!({ "code": "worker_offline" }),
        dispatch::WaitReason::Capacity => json!({ "code": "capacity" }),
        other => {
            let text = format!("{other:?}");
            match text.split_once(' ') {
                Some((name, fields)) => json!({
                    "code": reason_code(name),
                    "detail": fields.trim_matches(|c| c == '{' || c == '}' || c == ' '),
                }),
                None => json!({ "code": reason_code(&text) }),
            }
        }
    }
}

/// `DiskShort` -> `disk_short`: the variant's own name in the shape the rest
/// of the API writes enum values in.
fn reason_code(variant: &str) -> String {
    let mut out = String::with_capacity(variant.len() + 4);
    for (index, ch) in variant.char_indices() {
        if ch.is_ascii_uppercase() {
            if index != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
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
fn dispatch_run(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
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
    let images = runs::pinned_images(&spec).map_err(|error| match error {
        StoreError::InvalidInput(_) => err(ErrorCode::InvalidRequest, "image reference"),
        _ => err(
            ErrorCode::InvalidRequest,
            "every image must be pinned by digest",
        ),
    })?;
    let digest = spec.pipeline.digest.to_le_bytes();
    let pipeline_sha = spec.source.sha.clone();
    let source_ref = spec.source.ref_name.clone();
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
            // The explicit manual mode is a separately identified provenance:
            // no delivery and no provider, and the submitted pipeline was the
            // authority rather than a bound path at a selected revision.
            provenance::insert(
                tx,
                &provenance::Provenance {
                    tenant,
                    repo,
                    trigger: "manual".into(),
                    delivery: None,
                    provider: None,
                    ref_name: source_ref.clone(),
                    old_sha: None,
                    new_sha: Some(pipeline_sha.clone()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: pipeline_sha.clone(),
                    pipeline_path: None,
                    pipeline_digest: digest,
                    pr_number: None,
                },
                run,
                now,
            )?;
            // A manual run publishes nothing: its inline pipeline is a
            // diagnostic and must never satisfy the required aggregate. The
            // call is explicit so the rule lives in one place.
            checks::record_run(tx, tenant, run, now)?;
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
            Ok(Reply::Json(201, run_json(&view), Vec::new()))
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
            Ok(Reply::Json(200, run_json(&view), Vec::new()))
        }
        Err(None) => Err(err(
            ErrorCode::IdempotencyMismatch,
            "Idempotency-Key was used with a different body",
        )),
    }
}

/// A held upload/download slot; dropping frees it for the next request.
/// The bound exists so bounded-heap processes never queue unbounded
/// transfer work.
struct Slot<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

fn slot(state: &State) -> Result<Slot<'_>, ApiError> {
    use std::sync::atomic::Ordering;
    let mut held = state.transfers.load(Ordering::Acquire);
    loop {
        if held >= TRANSFERS {
            return Err(err(
                ErrorCode::RateLimited,
                "transfer slots exhausted; retry",
            ));
        }
        match state.transfers.compare_exchange_weak(
            held,
            held + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(Slot(&state.transfers)),
            Err(next) => held = next,
        }
    }
}

/// Long-poll subscribers parked at once — run waits and `wait=1` log polls
/// together. Each holds a handler permit ([`crate::WORKERS`]) while parked,
/// so the cap keeps half of them for everything else; beyond it a poll is
/// `rate_limited` with `details.retry_after_ms`.
pub(crate) const SUBSCRIBERS: usize = 4;
/// What a refused subscriber is told to wait before trying again.
const SUBSCRIBER_RETRY_MS: u64 = 1_000;
/// The longest a run wait parks (`timeout_ms` bound and default), the same
/// bound as a `wait=1` log poll.
const MAX_WAIT_MS: u64 = LOG_WAIT.as_millis() as u64;
/// A parked wait re-reads the run at most this often however fast commits
/// arrive: every commit in the store bumps the notifier, so a busy
/// controller would otherwise cost one status read per commit per waiter.
const RECHECK: std::time::Duration = std::time::Duration::from_millis(10);
/// How often a parked wait looks at the shutdown flag.
const STOP_SLICE: std::time::Duration = std::time::Duration::from_millis(250);

fn subscriber(state: &State) -> Result<Slot<'_>, ApiError> {
    use std::sync::atomic::Ordering;
    let mut held = state.subscribers.load(Ordering::Acquire);
    loop {
        if held >= SUBSCRIBERS {
            return Err(
                err(ErrorCode::RateLimited, "too many parked subscribers; retry")
                    .with_detail("retry_after_ms", SUBSCRIBER_RETRY_MS),
            );
        }
        match state.subscribers.compare_exchange_weak(
            held,
            held + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(Slot(&state.subscribers)),
            Err(next) => held = next,
        }
    }
}

/// An attempt's run and job, after the caller's `read` on its repository.
fn attempt_log(
    state: &State,
    principal: Principal,
    attempt: AttemptId,
) -> Result<(RunId, JobId), ApiError> {
    state
        .store
        .read(|c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            authz::require_repo(c, principal, repo, Permissions::READ)?;
            Ok((run, job))
        })
        .map_err(store_error)
}

/// `GET /runs/{run}/wait?since=<16 hex>&timeout_ms=1..25000`: answer as
/// soon as the run's version differs from `since` (at once without one) or
/// the run is finished; otherwise park on the store's commit notifier until
/// something commits, re-reading only the allocation-free version, until
/// the deadline or shutdown. The answer always carries the current run.
fn run_wait(state: &State, request: &Request, run: &str, query: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let run: RunId = id(run, "run")?;
    let since = query_param(query, "since")
        .map(|v| {
            (v.len() == 16)
                .then(|| u64::from_str_radix(v, 16).ok())
                .flatten()
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "since must be 16 hex digits"))
        })
        .transpose()?;
    let timeout_ms = match query_param(query, "timeout_ms") {
        None => MAX_WAIT_MS,
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|ms| (1..=MAX_WAIT_MS).contains(ms))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("timeout_ms must be 1..{MAX_WAIT_MS}"),
                )
            })?,
    };
    let tenant = authorize_run(state, who.principal, run, Permissions::READ)?;
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_millis(timeout_ms);
    let changes = state.store.changes();
    let version = || {
        state
            .store
            .read(|c| status::run_version(c, tenant, run))
            .map_err(store_error)
    };
    // The generation is read before the version: a commit landing between
    // the two moves the generation past `seen`, so the park below returns
    // at once instead of missing it.
    let mut seen = changes.generation();
    let mut current = version()?;
    let mut checked = std::time::Instant::now();
    let mut parked: Option<Slot<'_>> = None;
    while since == Some(current.version) && !current.finished {
        if parked.is_none() {
            parked = Some(subscriber(state)?);
        }
        let now = std::time::Instant::now();
        if now >= deadline || state.stop.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let next = changes.wait_past(seen, deadline.min(now + STOP_SLICE));
        if next == seen {
            continue;
        }
        seen = next;
        let since_check = checked.elapsed();
        if since_check < RECHECK {
            std::thread::sleep((RECHECK - since_check).min(deadline - now));
            seen = changes.generation();
        }
        current = version()?;
        checked = std::time::Instant::now();
    }
    drop(parked);
    let view = state
        .store
        .read(|c| status::run(c, tenant, run))
        .map_err(store_error)?;
    ok(json!({
        "version": format!("{:016x}", current.version),
        "changed": since != Some(current.version),
        "finished": current.finished,
        "run": run_json(&view),
    }))
}

/// `GET /attempts/{att}/logs/search?q=…&after&limit&carry`: a bounded
/// literal scan ([`sentinel_store::logs::LogStore::search`]). `q` is
/// percent-decoded (`+` is a space), 1..=256 bytes; `carry` is the previous
/// page's `next_carry`, which keeps a literal split across the cut found.
fn log_search(state: &State, request: &Request, attempt: &str, query: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
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
        .filter(|q| (1..=MAX_SEARCH_TEXT).contains(&q.len()))
        .ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                format!("q must be 1..{MAX_SEARCH_TEXT} bytes"),
            )
        })?;
    let after: u64 = match query_param(query, "after") {
        None => 0,
        Some(v) => v
            .parse()
            .map_err(|_| err(ErrorCode::InvalidRequest, "malformed after"))?,
    };
    let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()));
    // The previous page's `next_carry`: opaque, hex, checked by the store.
    let carry = query_param(query, "carry");
    let (run, job) = attempt_log(state, who.principal, attempt)?;
    let search = logs::SearchQuery {
        needle: needle.as_bytes(),
        after,
        limit,
        budget: logs::SEARCH_SCAN_BYTES,
        carry,
    };
    let found = state
        .logs
        .search(run, job, attempt, search)
        .or_else(|e| match e {
            StoreError::NotFound => state.logs.search_legacy(attempt, search),
            e => Err(e),
        })
        .map_err(store_error)?;
    ok(json!({
        "attempt": attempt.to_string(),
        "matches": found.matches.iter().map(|m| json!({
            "seq": m.seq,
            "step": m.step,
            "stream": stream_name(m.stream),
            "text": String::from_utf8_lossy(&m.text),
        })).collect::<Vec<_>>(),
        "next_after": found.next_after,
        "next_carry": found.carry,
        "complete": found.complete,
    }))
}

/// Longest `q` a log search accepts, in bytes.
const MAX_SEARCH_TEXT: usize = logs::MAX_NEEDLE;

fn stream_name(stream: sentinel_protocol::logs::Stream) -> &'static str {
    match stream {
        sentinel_protocol::logs::Stream::Stdout => "stdout",
        sentinel_protocol::logs::Stream::Stderr => "stderr",
    }
}

/// `GET /attempts/{att}/summary`: the cache records (K08) the attempt's
/// terminal report carried, or `{present:false}` before there is one.
fn attempt_summary(state: &State, request: &Request, attempt: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::CACHE_READ)?;
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
    let summary = sentinel_protocol::summary::AttemptSummary::decode(&bytes)
        .map_err(|_| err(ErrorCode::Internal, "stored summary unreadable"))?;
    ok(json!({
        "attempt": attempt.to_string(),
        "present": true,
        "image_present": summary.image_present,
        "caches": summary.caches,
    }))
}

#[derive(Deserialize)]
struct UploadBody {
    len: u64,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    ttl_ms: Option<i64>,
}

/// Resolve an upload's owning tenant and require the caller's live
/// membership of it. Foreign and missing ids answer identically.
fn upload_tenant(
    state: &State,
    principal: Principal,
    upload: UploadId,
    write: bool,
) -> Result<sentinel_core::TenantId, ApiError> {
    state
        .store
        .read(|c| {
            let tenant = state.objects.upload_owner(c, upload)?;
            authz::require_tenant_member(c, principal, tenant, write)?;
            Ok(tenant)
        })
        .map_err(store_error)
}

/// One artifact row as JSON; the detail route adds `manifest` on top.
fn artifact_json(row: &artifacts::Row) -> Value {
    json!({
        "id": row.id.to_string(),
        "job": row.job.to_string(),
        "job_name": row.job_name,
        "attempt": row.attempt.to_string(),
        "name": row.name,
        "state": row.state.as_str(),
        "manifest_version": row.manifest_version,
        "entries": row.entries,
        "bytes": row.bytes,
        "retain_until_ms": row.retain_until_ms.0,
        "created_ms": row.created_ms.0,
    })
}

fn upload_json(upload: UploadId, status: &sentinel_store::objects::UploadStatus) -> Value {
    json!({
        "upload": upload.to_string(),
        "state": match status.state {
            sentinel_store::objects::UploadState::Open => "open",
            sentinel_store::objects::UploadState::Committed => "committed",
            sentinel_store::objects::UploadState::Aborted => "aborted",
        },
        "declared_len": status.declared_len,
        "received": status.received,
        "ranges": status.ranges.iter().map(|(s, e)| json!([s, e])).collect::<Vec<_>>(),
        "expires_ms": status.expires_ms,
    })
}

/// Begin a resumable upload against a tenant the caller operates in.
fn upload_begin(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let body: UploadBody = parse(&body(request)?)?;
    let digest = body
        .digest
        .map(|text| {
            Digest::parse(&text).map_err(|_| err(ErrorCode::InvalidRequest, "malformed digest"))
        })
        .transpose()?;
    let ttl = body
        .ttl_ms
        .unwrap_or(sentinel_store::objects::MAX_UPLOAD_TTL_MS);
    let (slug, principal) = (slug.to_owned(), who.principal);
    let objects = Arc::clone(&state.objects);
    let upload = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = lookup::tenant_by_slug(tx, &slug)?;
            authz::require_tenant_member(tx, principal, tenant, true)?;
            objects.begin_upload(tx, tenant, body.len, digest, ttl, UnixMillis::now())
        })
        .map_err(store_error)?;
    let status = state
        .store
        .read(|c| {
            let tenant = state.objects.upload_owner(c, upload)?;
            state.objects.upload(c, tenant, upload)
        })
        .map_err(store_error)?;
    Ok(Reply::Json(201, upload_json(upload, &status), Vec::new()))
}

/// Where a resumable upload stands; the client's resume plan.
fn upload_status(state: &State, request: &mut Request, upload: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let upload: UploadId = id(upload, "upload")?;
    let tenant = upload_tenant(state, who.principal, upload, true)?;
    let status = state
        .store
        .read(|c| state.objects.upload(c, tenant, upload))
        .map_err(store_error)?;
    ok(upload_json(upload, &status))
}

/// One chunk: `PUT /api/v1/uploads/<upl>?offset=N` with a raw body.
fn upload_chunk(state: &State, request: &mut Request, upload: &str, query: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let upload: UploadId = id(upload, "upload")?;
    let tenant = upload_tenant(state, who.principal, upload, true)?;
    let offset: u64 = query_param(query, "offset")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "offset query parameter required"))?;
    let _slot = slot(state)?;
    let bytes = body_limit(request, MAX_UPLOAD_CHUNK)?;
    if bytes.is_empty() {
        return Err(err(ErrorCode::InvalidRequest, "empty chunk"));
    }
    let objects = Arc::clone(&state.objects);
    let received = state
        .store
        .writer()
        .write(move |tx| objects.put_chunk(tx, tenant, upload, offset, &bytes, UnixMillis::now()))
        .map_err(store_error)?;
    ok(json!({ "upload": upload.to_string(), "received": received }))
}

/// Seal: the ranges must tile the declared length and match the digest.
fn upload_commit(state: &State, request: &mut Request, upload: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let upload: UploadId = id(upload, "upload")?;
    let tenant = upload_tenant(state, who.principal, upload, true)?;
    let objects = Arc::clone(&state.objects);
    let digest = state
        .store
        .writer()
        .write(move |tx| objects.seal_upload(tx, tenant, upload, UnixMillis::now()))
        .map_err(store_error)?;
    ok(json!({ "upload": upload.to_string(), "digest": digest.to_string() }))
}

/// Give up an open upload and drop its staged bytes.
fn upload_abort(state: &State, request: &mut Request, upload: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let upload: UploadId = id(upload, "upload")?;
    let tenant = upload_tenant(state, who.principal, upload, true)?;
    let objects = Arc::clone(&state.objects);
    state
        .store
        .writer()
        .write(move |tx| objects.abort_upload(tx, tenant, upload))
        .map_err(store_error)?;
    ok(json!({ "upload": upload.to_string(), "aborted": true }))
}

/// `Range: bytes=a-b`, `bytes=a-` or `bytes=-n` to a `[start, end)` pair.
/// Multiple ranges are refused rather than served partially.
fn byte_range(spec: &str, len: u64) -> Result<(u64, u64), ApiError> {
    let invalid = || err(ErrorCode::InvalidRequest, "unsatisfiable range");
    let spec = spec.strip_prefix("bytes=").ok_or_else(invalid)?;
    if spec.contains(',') {
        return Err(err(
            ErrorCode::InvalidRequest,
            "multiple ranges unsupported",
        ));
    }
    let (a, b) = spec.split_once('-').ok_or_else(invalid)?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| invalid())?;
        if n == 0 || len == 0 {
            return Err(invalid());
        }
        (len.saturating_sub(n), len)
    } else {
        let start: u64 = a.parse().map_err(|_| invalid())?;
        let end = if b.is_empty() {
            len
        } else {
            b.parse::<u64>()
                .map_err(|_| invalid())?
                .checked_add(1)
                .ok_or_else(invalid)?
                .min(len)
        };
        (start, end)
    };
    if start >= end {
        return Err(invalid());
    }
    Ok((start, end))
}

/// Stream a committed object, whole or a `Range`. The reader registration
/// keeps the file un-reclaimable until the response finishes.
fn object_download(state: &State, request: &mut Request, slug: &str, digest: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::ARTIFACTS_READ)?;
    let digest =
        Digest::parse(digest).map_err(|_| err(ErrorCode::InvalidRequest, "malformed digest"))?;
    let (slug, principal) = (slug.to_owned(), who.principal);
    let (mut reader, len) = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            authz::require_tenant_member(c, principal, tenant, false)?;
            state.objects.open_read(c, tenant, digest)
        })
        .map_err(store_error)?;
    let _slot = slot(state)?;
    let tag = digest.to_string();
    let mut headers = vec![
        header("accept-ranges", "bytes"),
        header("etag", &format!("\"{tag}\"")),
    ];
    match header_value(request, "range") {
        None => Ok(Reply::Stream(200, Box::new(reader.take(len)), len, headers)),
        Some(spec) => {
            let (start, end) = byte_range(spec, len)?;
            reader
                .seek(SeekFrom::Start(start))
                .map_err(|_| err(ErrorCode::Internal, "controller fault"))?;
            headers.push(header(
                "content-range",
                &format!("bytes {start}-{}/{len}", end - 1),
            ));
            Ok(Reply::Stream(
                206,
                Box::new(reader.take(end - start)),
                end - start,
                headers,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_write_that_may_commit_is_reported_as_outcome_unknown() {
        // Nothing was attempted, or a read was refused: an identical retry is safe.
        for refused in [StoreError::WriterUnavailable, StoreError::Overloaded] {
            let e = store_error(refused);
            assert_eq!(
                (e.code, e.http_status(), e.retryable),
                (ErrorCode::RateLimited, 429, true)
            );
        }
        // P02-1: the write may still commit, so no blind retry is invited.
        let e = store_error(StoreError::WriteAmbiguous);
        assert_eq!(
            (e.code, e.http_status(), e.retryable),
            (ErrorCode::OutcomeUnknown, 503, false)
        );
        assert_eq!(
            e.details
                .as_ref()
                .and_then(|d| d.get("retry_with_idempotency_key")),
            Some(&Value::Bool(true))
        );
    }
}
