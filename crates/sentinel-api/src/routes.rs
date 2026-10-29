use std::{
    io::{Read, Seek, SeekFrom},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::http::{BodyErr, Header, Request, Response, StatusCode};
use sentinel_auth::cookie;
use sentinel_core::{
    ArtifactId, AttemptId, JobId, JobState, RepoId, RunId, RunState, UnixMillis, UploadId, UserId,
    WorkerId,
    auth::{Permissions, Principal, Scopes},
};
use sentinel_intake::ingest;
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    cursor::{Cursor, Seq, StreamKind},
    error::{ApiError, ErrorCode},
    idempotency::{Fingerprint, IdempotencyKey},
    intake::{MAX_HOOK_BODY_BYTES, MAX_WEBHOOK_BODY_BYTES},
    limits::{MAX_API_BODY_BYTES, page_size},
};
use sentinel_store::{
    Error as StoreError, artifacts, auth as authz,
    auth::Authority,
    checks, dispatch, idempotency, local_auth, logs, lookup,
    objects::{Digest, Touch},
    operations, provenance, runs, status, workers,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    LOG_WAIT, MAX_UPLOAD_CHUNK, State, TRANSFERS,
    auth::{self, Identity, Refusal, Via},
};

pub(crate) mod account;
mod admin;
mod email;
mod failure;
mod setup;
mod views;
mod worker_enrollment;
use failure::attempt_failure;

pub(crate) enum Reply {
    Json(u16, Value, Vec<Header>),
    JsonText(u16, String, Vec<Header>),
    Empty(u16, Vec<Header>),
    Stream(u16, Box<dyn Read + Send>, u64, Vec<Header>),
    Html(u16, String, Vec<Header>),
    Text(u16, &'static str, String),
    /// A generated shell script for the administrator to save and run: an attachment, never rendered.
    Script(u16, String),
}
pub(crate) type Route = Result<Reply, ApiError>;

const JSON: &str = "application/json";

const MAX_LOGIN_BODY_BYTES: usize = 16 << 10;

pub(crate) fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

pub(crate) fn ok(value: Value) -> Route {
    Ok(Reply::Json(200, value, Vec::new()))
}

pub(crate) fn err(code: ErrorCode, message: impl Into<String>) -> ApiError {
    ApiError::new(code, message)
}

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
        // The write may still commit; an identical unkeyed retry could apply it twice.
        StoreError::WriteAmbiguous => err(
            ErrorCode::OutcomeUnknown,
            "the write may still commit; re-read before retrying",
        )
        .with_detail("retry_with_idempotency_key", true),
        StoreError::StorageFull => err(ErrorCode::StorageFull, "storage below watermark; retry"),
        StoreError::QuotaExceeded => err(ErrorCode::QuotaExceeded, "tenant storage quota exceeded"),
        StoreError::IdempotencyMismatch => err(
            ErrorCode::IdempotencyMismatch,
            "Idempotency-Key was used with a different request",
        ),
        _ => err(ErrorCode::Internal, "controller fault"),
    }
}

pub(crate) fn handle(state: &State, request: &mut Request) {
    let started = std::time::Instant::now();
    let method = request.method().to_owned();
    let url = request.url().to_owned();
    let (full_path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (url.clone(), String::new()),
    };
    let path = state.oauth.local_path(&full_path);
    let outcome = route(state, request, &method, path, &query);
    let reply = match outcome {
        Ok(reply) => reply,
        Err(error) => {
            let headers = challenge(state, request, path, &error);
            Reply::Json(error.http_status(), json!(error), headers)
        }
    };
    let status = match &reply {
        Reply::Json(s, ..)
        | Reply::JsonText(s, ..)
        | Reply::Empty(s, ..)
        | Reply::Stream(s, ..)
        | Reply::Html(s, ..)
        | Reply::Text(s, ..)
        | Reply::Script(s, ..) => *s,
    };
    state.requests.observe(status, started.elapsed());
    match reply {
        Reply::Text(status, content_type, body) => {
            let response = Response::from_string(body)
                .with_status_code(StatusCode(status))
                .with_header(header("content-type", content_type))
                .with_header(header("cache-control", "no-store"));
            let _ = request.respond(response);
        }
        Reply::Script(status, body) => {
            let response = Response::from_string(body)
                .with_status_code(StatusCode(status))
                .with_header(header("content-type", "text/x-shellscript; charset=utf-8"))
                .with_header(header(
                    "content-disposition",
                    "attachment; filename=\"sentinel-worker-bootstrap.sh\"",
                ))
                .with_header(header("x-content-type-options", "nosniff"))
                .with_header(header("cache-control", "no-store"));
            let _ = request.respond(response);
        }
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
        Reply::JsonText(status, body, headers) => {
            let mut response = Response::from_string(body)
                .with_status_code(StatusCode(status))
                .with_header(header("content-type", JSON))
                .with_header(header("cache-control", "no-store"));
            for h in headers {
                response = response.with_header(h);
            }
            let _ = request.respond(response);
        }
        Reply::Empty(status, headers) => {
            let mut response =
                Response::from_string(String::new()).with_status_code(StatusCode(status));
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

fn challenge(state: &State, request: &Request, path: &str, error: &ApiError) -> Vec<Header> {
    if path == "/mcp" {
        return match error.code {
            ErrorCode::Unauthenticated => {
                let mut value = format!(
                    "Bearer realm=\"sentinel-mcp\", resource_metadata=\"{}\"",
                    state.oauth.mcp_resource_metadata
                );
                if header_value(request, "authorization").is_some() {
                    value.push_str(", error=\"invalid_token\"");
                }
                vec![header("www-authenticate", &value)]
            }
            ErrorCode::Forbidden => error.details.as_ref()
                .and_then(|details| details.get("scope"))
                .and_then(Value::as_str)
                .map(|scope| vec![header("www-authenticate", &format!(
                    "Bearer error=\"insufficient_scope\", scope=\"{scope}\", resource_metadata=\"{}\"",
                    state.oauth.mcp_resource_metadata
                ))])
                .unwrap_or_default(),
            _ => Vec::new(),
        };
    }
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return Vec::new();
    };
    if rest.starts_with("hooks/")
        || rest.starts_with("intake/")
        || matches!(
            rest,
            "login" | "register" | "email/verify" | "email/resend" | "setup" | "setup/mail-test"
        )
    {
        return Vec::new();
    }
    match error.code {
        ErrorCode::Unauthenticated => {
            let mut value = format!(
                "Bearer realm=\"sentinel\", resource_metadata=\"{}\"",
                state.oauth.resource_metadata
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

fn actor(who: &Identity) -> operations::Actor {
    match (who.via, who.grant) {
        (Via::OAuth, Some(grant)) => operations::Actor::OAuth(who.user, grant),
        (Via::Session, _) => operations::Actor::Session(who.user),
        _ => operations::Actor::Credential(who.user),
    }
}

pub(crate) fn header_value<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

pub(crate) fn body(request: &mut Request) -> Result<Vec<u8>, ApiError> {
    body_limit(request, MAX_API_BODY_BYTES)
}

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

pub(crate) fn public_body_limit(request: &mut Request, limit: usize) -> Result<Vec<u8>, ApiError> {
    request.public_body(limit).map_err(|e| match e {
        BodyErr::TooLarge => {
            err(ErrorCode::PayloadTooLarge, "body too large").with_detail("limit_bytes", limit)
        }
        BodyErr::Busy => err(ErrorCode::RateLimited, "busy; retry shortly"),
        BodyErr::Unreadable => err(ErrorCode::InvalidRequest, "unreadable body"),
    })
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
    if let Some(identity) = request.trusted_identity() {
        return Ok(identity);
    }
    auth::identify(
        &state.store,
        state.sessions,
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
        // Never `401`: an OAuth client answers `401` by spending its refresh token.
        Refusal::Busy => err(ErrorCode::RateLimited, "controller busy; retry")
            .with_detail("retry_after_ms", 1000),
        Refusal::Fault => err(ErrorCode::Internal, "controller fault"),
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

pub(crate) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    path: &str,
    query: &str,
) -> Route {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if let Some(reply) = crate::oauth::route(state, request, method, &parts, query) {
        return reply;
    }
    if let Some(reply) = crate::github::route(state, request, method, &parts, query) {
        return reply;
    }
    if let Some(reply) = crate::github_app::route(state, request, method, &parts) {
        return reply;
    }
    if let Some(reply) = account::route(state, request, method, &parts) {
        return reply;
    }
    if let Some(reply) = setup::route(state, request, method, &parts) {
        return reply;
    }
    if let Some(reply) = email::route(state, request, method, &parts) {
        return reply;
    }
    if let Some(reply) = admin::route(state, request, method, &parts, query) {
        return reply;
    }
    if let Some(reply) = worker_enrollment::route(state, request, method, &parts, query) {
        return reply;
    }
    match (method, parts.as_slice()) {
        ("GET", ["metrics"]) | ("GET", ["api", "v1", "metrics"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::PLATFORM_ADMIN)?;
            let authority = who.authority();
            state
                .store
                .read(move |c| authority.require_platform(c))
                .map_err(store_error)?;
            Ok(Reply::Text(
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                crate::metrics::render(state),
            ))
        }
        ("GET", ["api", "v1", "version"]) => {
            identify(state, request, false)?;
            let schema: i64 = state
                .store
                .read(|c| {
                    Ok(c.query_row(
                        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                        [],
                        |r| r.get(0),
                    )?)
                })
                .map_err(store_error)?;
            ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "api": "v1",
                "schema": { "database": schema, "binary": sentinel_store::schema::LATEST },
                "worker_protocol": {
                    "min": sentinel_protocol::negotiate::SUPPORTED_MIN.0,
                    "max": sentinel_protocol::negotiate::SUPPORTED_MAX.0,
                },
            }))
        }
        ("GET", ["api", "v1", "health"]) => {
            ok(json!({ "ok": true, "github_sign_in": state.github.get().is_some() }))
        }
        ("GET", ["api", "v1", "ready"]) => ready(state),
        ("POST", ["mcp"]) => crate::mcp::post(state, request),
        ("GET", ["mcp"]) => crate::mcp::get(state, request),
        ("DELETE", ["mcp"]) => crate::mcp::delete(state, request),
        ("POST", ["api", "v1", "hooks", "github"]) => github_hook(state, request),
        ("POST", ["api", "v1", "intake", repo]) => generic_intake(state, request, repo),
        ("POST", ["api", "v1", "login"]) => login(state, request),
        ("POST", ["api", "v1", "logout"]) => logout(state, request),
        ("GET", ["api", "v1", "me"]) => {
            let who = identify(state, request, false)?;
            let (username, address) = state
                .store
                .read(|c| {
                    Ok((
                        local_auth::username_of(c, who.user)?,
                        sentinel_store::email::account_email(c, who.user)?,
                    ))
                })
                .map_err(store_error)?;
            ok(json!({
                "user": who.user.to_string(),
                "username": username,
                "email": address.as_ref().map(|(email, _)| email),
                "email_verified": address.as_ref().is_some_and(|(_, verified)| *verified),
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
                "stepped_up": who.stepped_up,
                "mfa": admin::mfa_enrolled(state, who.user)?,
            }))
        }
        ("GET", ["api", "v1", "tenants"]) => views::my_tenants(state, request),
        ("GET", ["api", "v1", "tenants", slug, "sync"]) => views::sync(state, request, slug, query),
        ("GET", ["api", "v1", "attempts", attempt, "steps"]) => {
            views::attempt_steps(state, request, attempt)
        }
        ("GET", ["api", "v1", "tenants", slug, "repos"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
            let slug = (*slug).to_owned();
            let now = UnixMillis::now();
            let (repos, stale) = state
                .store
                .read(|c| {
                    let tenant = authz::member_tenant_by_slug(c, who.principal, &slug)?;
                    let repos = authz::list_repos(c, who.principal, tenant, None, 100)?;
                    let stale = sentinel_store::github_members::touch(
                        c,
                        tenant,
                        who.principal.user,
                        sentinel_store::github_members::OPEN_TTL_MS,
                        now,
                    )?;
                    Ok((repos, stale))
                })
                .map_err(store_error)?;
            if stale {
                // Off the request path: the refresh is filed, never written here.
                state
                    .refresh
                    .request(who.principal.user, std::time::Instant::now());
            }
            ok(json!({
                "repos": repos.iter().map(|r| json!({ "id": r.id.to_string(), "name": r.name })).collect::<Vec<_>>()
            }))
        }
        ("GET", ["api", "v1", "tenants", slug, "repos", name, "runs"]) => {
            views::runs(state, request, slug, name, query)
        }
        (
            _,
            [
                "api",
                "v1",
                "tenants",
                slug,
                "secrets" | "secret-bindings",
                rest @ ..,
            ],
        ) => crate::secret_routes::route(state, request, method, slug, parts[4], rest, query),
        ("POST", ["api", "v1", "tenants", slug, "repos", name, "runs"]) => {
            dispatch_run(state, request, slug, name)
        }
        ("GET", ["api", "v1", "runs", run, "wait"]) => run_wait(state, request, run, query),
        ("GET", ["api", "v1", "runs", run, "pipeline"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
            let run: RunId = id(run, "run")?;
            let spec = state
                .store
                .read(|c| {
                    let repo = lookup::run_repo(c, run)?;
                    let tenant = authz::require_repo(c, who.principal, repo, Permissions::READ)?;
                    runs::get_run_spec(c, tenant, run)
                })
                .map_err(store_error)?;
            ok(json!(sentinel_pipeline::Explanation::of(&spec.pipeline)))
        }
        ("GET", ["api", "v1", "attempts", attempt, "logs", "search"]) => {
            log_search(state, request, attempt, query)
        }
        ("GET", ["api", "v1", "attempts", attempt, "summary"]) => {
            attempt_summary(state, request, attempt)
        }
        ("GET", ["api", "v1", "attempts", attempt, "failure"]) => {
            attempt_failure(state, request, attempt, query)
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
                .write(move |tx| {
                    let now = UnixMillis::now();
                    let count = dispatch::cancel_run(tx, tenant, run, UnixMillis::steady())?;
                    operations::record(
                        tx,
                        tenant,
                        operations::Action::CancelRun,
                        *run.as_bytes(),
                        actor(&who),
                        now,
                    )?;
                    Ok(count)
                })
                .map_err(store_error)?;
            state.controller.cancel_hint();
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
                .write(move |tx| {
                    let now = UnixMillis::now();
                    let outcome = dispatch::cancel(tx, tenant, job, UnixMillis::steady())?;
                    operations::record(
                        tx,
                        tenant,
                        operations::Action::CancelJob,
                        *job.as_bytes(),
                        actor(&who),
                        now,
                    )?;
                    Ok(outcome)
                })
                .map_err(store_error)?;
            state.controller.cancel_hint();
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
                .write(move |tx| {
                    let now = UnixMillis::now();
                    let next = runs::rerun_job(tx, tenant, job, UnixMillis::steady())?;
                    operations::record(
                        tx,
                        tenant,
                        operations::Action::RerunJob,
                        *job.as_bytes(),
                        actor(&who),
                        now,
                    )?;
                    Ok(next)
                })
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
            attempt_logs(state, request, attempt, query)
        }
        ("GET", ["api", "v1", "workers"]) => views::workers_view(state, request, query),
        ("GET", ["api", "v1", "queue"]) => {
            let who = identify(state, request, false)?;
            auth::require_scope(&who, Scopes::RUNS_READ)?;
            let slug = query_param(query, "tenant")
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "tenant query parameter required"))?
                .to_owned();
            let limit = page_size(query_param(query, "limit").and_then(|v| v.parse().ok()));
            let connected = state.controller.connected();
            let page = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    authz::require_tenant_member(c, who.principal, tenant, false)?;
                    dispatch::list_queue(c, who.principal, tenant, &connected, limit)
                })
                .map_err(store_error)?;
            let storage = state.objects.admission().filter(|a| !a.is_open()).map(|a| {
                if a.backlog_full() {
                    "external_copy_backlog"
                } else {
                    "disk_below_watermark"
                }
            });
            ok(json!({
                "jobs": page.jobs.iter().map(|row| {
                    let mut job = queued_json(row);
                    if let Some(detail) = storage
                        && matches!(row.reason, dispatch::WaitReason::Ready | dispatch::WaitReason::Capacity)
                    {
                        job["reason"] = json!({ "code": "storage", "detail": detail });
                    }
                    job
                }).collect::<Vec<_>>(),
                "total": page.total,
                "truncated": page.total > page.jobs.len(),
                "placement_paused": storage,
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

fn bounded_header(request: &Request, name: &'static str, max: usize) -> Option<String> {
    header_value(request, name)
        .filter(|value| value.len() <= max)
        .map(str::to_owned)
}

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

fn github_hook(state: &State, request: &mut Request) -> Route {
    let Some(secret) = state.github_webhook_secret.get().map(|s| &**s) else {
        return Err(err(ErrorCode::NotFound, "no such route"));
    };
    let event =
        bounded_header(request, sentinel_github::webhook::EVENT_HEADER, 64).unwrap_or_default();
    let delivery = bounded_header(request, sentinel_github::webhook::DELIVERY_HEADER, 128);
    let signature = bounded_header(request, sentinel_github::webhook::SIGNATURE_HEADER, 128);
    let body = public_body_limit(request, MAX_WEBHOOK_BODY_BYTES)?;
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
    let body = public_body_limit(request, MAX_HOOK_BODY_BYTES)?;
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
    // Login CSRF: a cross-site form cannot send application/json without a CORS preflight.
    let json_body = header_value(request, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(JSON))
    });
    if !json_body {
        return Err(err(
            ErrorCode::InvalidRequest,
            "sign-in takes an application/json body",
        ));
    }
    if header_value(request, "origin").is_some_and(|origin| origin != state.oauth.origin) {
        return Err(err(
            ErrorCode::Forbidden,
            "sign-in from another site is refused",
        ));
    }
    if !crate::oauth::admitted(state, request, crate::oauth::Budget::Login) {
        return Err(err(
            ErrorCode::RateLimited,
            "too many sign-in attempts; retry shortly",
        )
        .with_detail("retry_after_ms", 2000));
    }
    let bytes = public_body_limit(request, MAX_LOGIN_BODY_BYTES)?;
    let creds: LoginBody = parse(&bytes)?;
    let identifier = if creds.username.contains('@') {
        sentinel_store::email::normalize(&creds.username).unwrap_or_else(|_| creds.username.clone())
    } else {
        creds.username.clone()
    };
    let creds = LoginBody {
        username: identifier,
        ..creds
    };
    let client = crate::oauth::client_of(state, request);
    let now = std::time::Instant::now();
    if !state.logins.allowed(client, &creds.username, now) {
        return Err(err(ErrorCode::Unauthenticated, "sign-in refused"));
    }
    let account_policy = local_auth::Policy {
        max_failures: state
            .sessions
            .max_failures
            .saturating_mul(crate::login_guard::ACCOUNT_LOCK_FACTOR),
        ..state.sessions
    };
    let outcome = local_auth::login(
        &state.store,
        &creds.username,
        creds.password.as_bytes(),
        account_policy,
        UnixMillis::now(),
    )
    .map_err(store_error)?;
    match outcome {
        local_auth::Login::Accepted(issued) => {
            state.logins.succeeded(client, &creds.username);
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
        local_auth::Login::Rejected | local_auth::Login::Locked { .. } => {
            state.logins.failed(
                client,
                &creds.username,
                state.sessions.max_failures,
                std::time::Duration::from_millis(state.sessions.lockout_ms.max(0) as u64),
                now,
            );
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
        // The session row must go before the client is told it logged out.
        local_auth::logout(&state.store, &secret, UnixMillis::now()).map_err(store_error)?;
    }
    Ok(Reply::Json(
        200,
        json!({ "ok": true }),
        vec![header("set-cookie", &cookie::clear(cookie::SESSION_COOKIE))],
    ))
}

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
    state.controller.wake();
    ok(json!({ "worker": worker.to_string(), "draining": drain }))
}

fn transport_json(t: &sentinel_link::session::TransportStats) -> Value {
    let mut out = json!({
        "path": match t.path {
            sentinel_link::session::Path::Unknown => "unknown",
            sentinel_link::session::Path::Direct => "direct",
            sentinel_link::session::Path::Relay => "relay",
        },
        "reconnects": t.reconnects,
        "bytes_in": t.bytes_in,
        "bytes_out": t.bytes_out,
    });
    if let Some(rtt) = t.rtt_ns {
        out["rtt_ns"] = json!(rtt);
    }
    if let Some(version) = &t.helper_version {
        out["helper_version"] = json!(version);
    }
    out
}

fn queued_json(row: &dispatch::QueuedJob) -> Value {
    json!({
        "job": row.job.to_string(),
        "run": row.run.to_string(),
        "repo": row.repo.to_string(),
        "age_ms": row.age_ms,
        "reason": wait_reason_json(row.reason),
    })
}

fn wait_reason_json(reason: dispatch::WaitReason) -> Value {
    use dispatch::WaitReason as R;
    match reason {
        R::Dependency => json!({ "code": "dependency" }),
        R::Policy(what) => json!({ "code": "policy", "detail": what }),
        R::NoMatchingWorker {
            cpu_short,
            memory_short,
        } => json!({
            "code": "no_matching_worker",
            "cpu_short": cpu_short,
            "memory_short": memory_short,
        }),
        R::DiskShort { disk_short } => json!({ "code": "disk_short", "disk_short": disk_short }),
        R::ArchMismatch => json!({ "code": "arch_mismatch" }),
        R::LabelMissing => json!({ "code": "label_missing" }),
        R::RuntimeMissing { runtime } => runtime_missing_json(runtime),
        R::ConcurrencyLimit => json!({ "code": "concurrency_limit" }),
        R::WorkerOffline => json!({ "code": "worker_offline" }),
        R::Capacity => json!({ "code": "capacity" }),
        R::Drain => json!({ "code": "drain" }),
        R::FairnessHold => json!({ "code": "fairness_hold" }),
        R::LocalityWait => json!({ "code": "locality_wait" }),
        R::Ready => json!({ "code": "ready" }),
        other => debug_reason_json(&format!("{other:?}")),
    }
}

/// The OS and isolation a job states, from the capability bits it requires.
fn runtime_missing_json(runtime: i64) -> Value {
    use sentinel_protocol::negotiate::Capabilities as C;
    let bits = C(runtime as u64);
    let os = if bits.contains(C::OS_WINDOWS) {
        "windows"
    } else {
        "linux"
    };
    let isolation = [
        (C::ISOLATION_CONTAINER, "container"),
        (C::ISOLATION_MICROVM, "microvm"),
        (C::ISOLATION_NATIVE, "native"),
    ]
    .into_iter()
    .find(|(bit, _)| bits.contains(*bit))
    .map(|(_, name)| name);
    json!({ "code": "runtime_missing", "os": os, "isolation": isolation })
}

fn debug_reason_json(text: &str) -> Value {
    let end = text.find([' ', '(']).unwrap_or(text.len());
    let (name, rest) = text.split_at(end);
    let mut out = json!({ "code": reason_code(name) });
    let rest = rest.trim();
    if let Some(fields) = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        for field in fields.split(',') {
            if let Some((key, value)) = field.split_once(':') {
                out[key.trim()] = debug_value(value.trim());
            }
        }
    } else if let Some(value) = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        out["detail"] = debug_value(value.trim());
    }
    out
}

fn debug_value(value: &str) -> Value {
    if let Ok(n) = value.parse::<i64>() {
        return json!(n);
    }
    if let Ok(n) = value.parse::<u64>() {
        return json!(n);
    }
    match value {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => json!(
            value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value)
        ),
    }
}

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
    if compiled
        .jobs
        .iter()
        .any(|job| job.spec.requires_secret_delivery())
    {
        return Err(err(
            ErrorCode::Forbidden,
            "a manually dispatched pipeline cannot use secrets; \
             push the pipeline to a bound revision",
        )
        .with_detail("reason", "manual_run_secrets"));
    }
    let source = PinnedSource::new(
        &dispatch.source.repo,
        &dispatch.source.sha,
        dispatch.source.ref_name.as_deref(),
    )
    .map_err(|e| err(ErrorCode::InvalidRequest, format!("source: {e:?}")))?;
    let spec = RunSpec::new(source, compiled)
        .map_err(|e| err(ErrorCode::InvalidRequest, format!("spec: {e:?}")))?;
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
            let steady = UnixMillis::steady();
            if let Some(key) = key {
                match idempotency::begin(tx, scope, key, fingerprint, steady)? {
                    idempotency::Begin::Execute => {}
                    idempotency::Begin::Replay(run) => return Ok(Err(Some(run))),
                    idempotency::Begin::Mismatch => return Ok(Err(None)),
                    idempotency::Begin::InFlight => return Err(StoreError::WriteAmbiguous),
                }
            }
            let run = RunId::new();
            let jobs = authz::create_run(tx, principal, repo, run, &spec, steady)?;
            for (job, (digest, platform)) in jobs.iter().zip(&images) {
                runs::resolve_image(tx, tenant, *job, digest, platform)?;
            }
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
            // A manual run publishes nothing: it must never satisfy the required aggregate.
            checks::record_run(tx, tenant, run, now)?;
            if let Some(key) = key {
                idempotency::complete(tx, scope, key, run)?;
            }
            Ok(Ok((tenant, run, jobs)))
        })
        .map_err(store_error)?;
    match created {
        Ok((tenant, run, _)) => {
            state.controller.cancel_hint();
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

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

fn take_slot(counter: &Arc<AtomicUsize>, cap: usize) -> Option<Slot> {
    let mut held = counter.load(Ordering::Acquire);
    loop {
        if held >= cap {
            return None;
        }
        match counter.compare_exchange_weak(held, held + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(Slot(Arc::clone(counter))),
            Err(next) => held = next,
        }
    }
}

fn slot(state: &State) -> Result<Slot, ApiError> {
    take_slot(&state.transfers, TRANSFERS)
        .ok_or_else(|| err(ErrorCode::RateLimited, "transfer slots exhausted; retry"))
}

const SUBSCRIBER_RETRY_MS: u64 = 1_000;
const MAX_WAIT_MS: u64 = LOG_WAIT.as_millis() as u64;
const RECHECK: std::time::Duration = std::time::Duration::from_millis(10);
const STOP_SLICE: std::time::Duration = std::time::Duration::from_millis(250);

struct Standing {
    tenant: sentinel_core::TenantId,
    epoch: i64,
    checked: std::time::Instant,
}

impl Standing {
    fn new(state: &State, tenant: sentinel_core::TenantId) -> Result<Standing, ApiError> {
        let epoch = state
            .store
            .read(|c| sentinel_store::tenancy::epoch(c, tenant))
            .map_err(store_error)?;
        Ok(Standing {
            tenant,
            epoch,
            checked: std::time::Instant::now(),
        })
    }

    fn recheck(
        &mut self,
        state: &State,
        request: &Request,
        reauthorize: impl FnOnce() -> Result<(), ApiError>,
    ) -> Result<(), ApiError> {
        if self.checked.elapsed() < STOP_SLICE {
            return Ok(());
        }
        self.checked = std::time::Instant::now();
        if request.peer_gone() {
            return Err(err(ErrorCode::InvalidRequest, "the client went away"));
        }
        let tenant = self.tenant;
        let epoch = state
            .store
            .read(|c| sentinel_store::tenancy::epoch(c, tenant))
            .map_err(store_error)?;
        if epoch != self.epoch {
            reauthorize()?;
            self.epoch = epoch;
        }
        Ok(())
    }
}

fn subscriber(state: &State, user: UserId) -> Result<crate::Subscriber<'_>, ApiError> {
    state.subscribers.take(user).map_err(|refusal| {
        let message = match refusal {
            crate::SubscriberRefusal::Full => "too many parked subscribers; retry",
            crate::SubscriberRefusal::UserFull => {
                "too many parked subscribers for this user; retry"
            }
        };
        err(ErrorCode::RateLimited, message).with_detail("retry_after_ms", SUBSCRIBER_RETRY_MS)
    })
}

fn attempt_log(
    state: &State,
    principal: Principal,
    attempt: AttemptId,
) -> Result<(sentinel_core::TenantId, RunId, JobId), ApiError> {
    state
        .store
        .read(|c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            let tenant = authz::require_repo(c, principal, repo, Permissions::READ)?;
            Ok((tenant, run, job))
        })
        .map_err(store_error)
}

fn attempt_logs(state: &State, request: &mut Request, attempt: &str, query: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
    let after: Option<u64> = query_param(query, "after")
        .map(|v| {
            v.parse()
                .map_err(|_| err(ErrorCode::InvalidRequest, "malformed after"))
        })
        .transpose()?;
    let limit = page_size(
        query_param(query, "limit")
            .map(|v| {
                v.parse()
                    .map_err(|_| err(ErrorCode::InvalidRequest, "malformed limit"))
            })
            .transpose()?,
    );
    let step: Option<u32> = query_param(query, "step")
        .map(|v| {
            v.parse()
                .map_err(|_| err(ErrorCode::InvalidRequest, "malformed step"))
        })
        .transpose()?;
    let wait = query_param(query, "wait").is_some_and(|v| v == "1" || v == "true");
    let (tenant, run, job) = attempt_log(state, who.principal, attempt)?;
    if let Some(expired) = state
        .store
        .read(|c| sentinel_store::retention::log_expired(c, attempt))
        .map_err(store_error)?
    {
        return ok(json!({
            "attempt": attempt.to_string(),
            "complete": true,
            "gaps": [],
            "next_after": null,
            "step_done": false,
            "frames": [],
            "expired_ms": expired.0,
        }));
    }
    let after = match (after, query_param(query, "cursor")) {
        (Some(_), Some(_)) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "after and cursor are exclusive",
            ));
        }
        (Some(after), None) => after,
        (None, Some(text)) => {
            let cursor = Cursor::parse(text, tenant)
                .ok()
                .filter(|c| c.kind == StreamKind::AttemptLog && c.stream == *attempt.as_bytes())
                .ok_or_else(|| err(ErrorCode::InvalidCursor, "invalid cursor"))?;
            cursor.seq.0
        }
        (None, None) => 0,
    };
    let page = logs::Page {
        limit,
        bytes: logs::PAGE_BYTES,
        scan: logs::PAGE_SCAN_BYTES,
    };
    let read = || {
        state
            .logs
            .tail_page(run, job, attempt, after, page, step)
            .or_else(|e| match e {
                StoreError::NotFound => state.logs.tail_legacy_page(attempt, after, page, step),
                e => Err(e),
            })
            .map_err(store_error)
    };
    let changes = state.logs.changes();
    // Take the generation and frontier before the read, so a park never misses a frame.
    let mut seen = changes.generation();
    let mut frontier = state.logs.frontier(attempt);
    let mut tail = read()?;
    let deadline = std::time::Instant::now() + LOG_WAIT;
    let mut parked: Option<crate::Subscriber<'_>> = None;
    let mut standing: Option<Standing> = None;
    while wait
        && tail.frames.is_empty()
        && !tail.complete
        && !tail.step_done
        && tail.next_after.is_none()
    {
        if parked.is_none() {
            parked = Some(subscriber(state, who.principal.user)?);
            standing = Some(Standing::new(state, tenant)?);
            request.yield_handler();
        }
        if let Some(standing) = standing.as_mut() {
            standing.recheck(state, request, || {
                attempt_log(state, who.principal, attempt).map(|_| ())
            })?;
        }
        let now = std::time::Instant::now();
        if now >= deadline || state.stop.load(Ordering::Acquire) {
            break;
        }
        let next = changes.wait_past(seen, deadline.min(now + STOP_SLICE));
        if next == seen {
            continue;
        }
        seen = next;
        let moved = state.logs.frontier(attempt);
        if moved == frontier {
            continue;
        }
        frontier = moved;
        tail = read()?;
    }
    drop(parked);
    let position = tail
        .next_after
        .or_else(|| tail.frames.last().map(|f| f.seq))
        .unwrap_or(after)
        .max(after);
    let next = Cursor {
        tenant,
        kind: StreamKind::AttemptLog,
        stream: *attempt.as_bytes(),
        seq: Seq(position),
    };
    ok(json!({
        "attempt": attempt.to_string(),
        "complete": tail.complete,
        "gaps": tail.gaps,
        "next_after": tail.next_after,
        "next": next.to_string(),
        "step_done": tail.step_done,
        "frames": tail.frames.iter().map(|f| json!({
            "seq": f.seq, "step": f.step,
            "stream": stream_name(f.stream),
            "text": String::from_utf8_lossy(&f.bytes),
        })).collect::<Vec<_>>(),
    }))
}

fn ready(state: &State) -> Route {
    let stopping = state.stop.load(Ordering::Acquire);
    let reads = state
        .store
        .read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
        .is_ok();
    let commits = !stopping && state.store.writer().write(|_| Ok(())).is_ok();
    let mut degraded: Vec<&str> = Vec::new();
    if let Some(a) = state.objects.admission()
        && !a.is_open()
    {
        degraded.push(if a.backlog_full() {
            "external_copy_backlog"
        } else {
            "disk_below_watermark"
        });
    }
    if state
        .objects
        .replication()
        .is_some_and(|r| r.state() == "degraded")
    {
        degraded.push("external_copy");
    }
    if let Some(backups) = state.objects.backups() {
        let status = backups.status();
        if !status["last_failure"].is_null() {
            degraded.push("backup_failing");
        }
        if crate::metrics::backup_objects_lost(&status).is_some_and(|lost| lost > 0) {
            degraded.push("backup_incomplete");
        }
    }
    if state.controller.connected().is_empty() {
        degraded.push("no_workers_connected");
    }
    let ready = !stopping && reads && commits;
    Ok(Reply::Json(
        if ready { 200 } else { 503 },
        json!({
            "ready": ready,
            "checks": { "stopping": stopping, "store_reads": reads, "store_commits": commits },
            "degraded": degraded,
        }),
        Vec::new(),
    ))
}

fn run_wait(state: &State, request: &mut Request, run: &str, query: &str) -> Route {
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
    let mut seen = changes.generation();
    let mut current = version()?;
    let mut checked = std::time::Instant::now();
    let mut parked: Option<crate::Subscriber<'_>> = None;
    let mut standing: Option<Standing> = None;
    while since == Some(current.version) && !current.finished {
        if parked.is_none() {
            parked = Some(subscriber(state, who.principal.user)?);
            standing = Some(Standing::new(state, tenant)?);
            request.yield_handler();
        }
        if let Some(standing) = standing.as_mut() {
            standing.recheck(state, request, || {
                authorize_run(state, who.principal, run, Permissions::READ).map(|_| ())
            })?;
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
    let (current, view) = state
        .store
        .read(|c| {
            let snapshot = c.unchecked_transaction()?;
            Ok((
                status::run_version(&snapshot, tenant, run)?,
                status::run(&snapshot, tenant, run)?,
            ))
        })
        .map_err(store_error)?;
    ok(json!({
        "version": format!("{:016x}", current.version),
        "changed": since != Some(current.version),
        "finished": current.finished,
        "run": run_json(&view),
    }))
}

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
    let carry = query_param(query, "carry");
    let (_, run, job) = attempt_log(state, who.principal, attempt)?;
    if let Some(expired) = state
        .store
        .read(|c| sentinel_store::retention::log_expired(c, attempt))
        .map_err(store_error)?
    {
        return ok(json!({
            "attempt": attempt.to_string(),
            "matches": [],
            "next_after": null,
            "next_carry": null,
            "complete": true,
            "expired_ms": expired.0,
        }));
    }
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

const MAX_SEARCH_TEXT: usize = logs::MAX_NEEDLE;

fn stream_name(stream: sentinel_protocol::logs::Stream) -> &'static str {
    match stream {
        sentinel_protocol::logs::Stream::Stdout => "stdout",
        sentinel_protocol::logs::Stream::Stderr => "stderr",
    }
}

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
    let now = UnixMillis::now();
    let written = state
        .store
        .read(|c| {
            state
                .objects
                .write_chunk(c, tenant, upload, offset, &bytes, now)
        })
        .map_err(store_error)?;
    let chunk = match written {
        Touch::Ready(chunk) => chunk,
        Touch::Expired => return Err(retire_expired(state, tenant, upload)),
    };
    let objects = Arc::clone(&state.objects);
    let received = state
        .store
        .writer()
        .write(move |tx| objects.record_chunk(tx, chunk))
        .map_err(store_error)?;
    ok(json!({ "upload": upload.to_string(), "received": received }))
}

/// Retire in its own transaction: inside the refused request's, it would roll back.
fn retire_expired(state: &State, tenant: sentinel_core::TenantId, upload: UploadId) -> ApiError {
    let objects = Arc::clone(&state.objects);
    if let Ok(true) = state
        .store
        .writer()
        .write(move |tx| objects.retire_expired(tx, tenant, upload, UnixMillis::now()))
    {
        state.objects.drop_upload(upload);
    }
    err(ErrorCode::InvalidRequest, "invalid upload expired")
}

fn upload_commit(state: &State, request: &mut Request, upload: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::RUNS_WRITE)?;
    let upload: UploadId = id(upload, "upload")?;
    let tenant = upload_tenant(state, who.principal, upload, true)?;
    let _slot = slot(state)?;
    let now = UnixMillis::now();
    let prepared = state
        .store
        .read(|c| state.objects.prepare_seal(c, tenant, upload, now))
        .map_err(store_error)?;
    let plan = match prepared {
        Touch::Ready(plan) => plan,
        Touch::Expired => return Err(retire_expired(state, tenant, upload)),
    };
    let objects = Arc::clone(&state.objects);
    let digest = state
        .store
        .writer()
        .write(move |tx| objects.finish_seal(tx, plan))
        .map_err(store_error)?;
    ok(json!({ "upload": upload.to_string(), "digest": digest.to_string() }))
}

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
            authz::require_object_read(c, principal, tenant, digest.as_bytes())?;
            state.objects.open_read(c, tenant, digest)
        })
        .map_err(store_error)?;
    let slot = slot(state)?;
    let tag = digest.to_string();
    let mut headers = vec![
        header("accept-ranges", "bytes"),
        header("etag", &format!("\"{tag}\"")),
    ];
    match header_value(request, "range") {
        None => Ok(Reply::Stream(
            200,
            Box::new(Verified {
                inner: reader,
                left: len,
                hasher: blake3::Hasher::new(),
                digest,
                _slot: slot,
            }),
            len,
            headers,
        )),
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
                Box::new(Held {
                    inner: reader.take(end - start),
                    _slot: slot,
                }),
                end - start,
                headers,
            ))
        }
    }
}

struct Held<R> {
    inner: R,
    _slot: Slot,
}

impl<R: Read> Read for Held<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

struct Verified {
    inner: sentinel_store::objects::Reader,
    left: u64,
    hasher: blake3::Hasher,
    digest: Digest,
    _slot: Slot,
}

impl Read for Verified {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let got = self.inner.read(&mut buf[..want])?;
        if got == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "object shorter than recorded",
            ));
        }
        self.hasher.update(&buf[..got]);
        self.left -= got as u64;
        if self.left == 0 && self.hasher.finalize().as_bytes() != self.digest.as_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "object content does not match its digest",
            ));
        }
        Ok(got)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_write_that_may_commit_is_reported_as_outcome_unknown() {
        for refused in [StoreError::WriterUnavailable, StoreError::Overloaded] {
            let e = store_error(refused);
            assert_eq!(
                (e.code, e.http_status(), e.retryable),
                (ErrorCode::RateLimited, 429, true)
            );
        }
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

    #[test]
    fn queue_reasons_carry_their_quantities_as_numeric_fields() {
        use dispatch::WaitReason as R;
        let disk = wait_reason_json(R::DiskShort {
            disk_short: 5_368_709_120,
        });
        assert_eq!(
            disk,
            json!({ "code": "disk_short", "disk_short": 5_368_709_120_i64 })
        );
        assert_eq!(
            wait_reason_json(R::NoMatchingWorker {
                cpu_short: 2_000,
                memory_short: 0,
            }),
            json!({ "code": "no_matching_worker", "cpu_short": 2_000, "memory_short": 0 })
        );
        assert_eq!(
            wait_reason_json(R::Policy("image unresolved")),
            json!({ "code": "policy", "detail": "image unresolved" })
        );
        use sentinel_protocol::negotiate::Capabilities as C;
        assert_eq!(
            wait_reason_json(R::RuntimeMissing {
                runtime: C::OS_LINUX.union(C::ISOLATION_MICROVM).0 as i64
            }),
            json!({ "code": "runtime_missing", "os": "linux", "isolation": "microvm" })
        );
        assert_eq!(
            wait_reason_json(R::RuntimeMissing {
                runtime: C::OS_WINDOWS.0 as i64
            }),
            json!({ "code": "runtime_missing", "os": "windows", "isolation": null })
        );
        for (reason, code) in [
            (R::ArchMismatch, "arch_mismatch"),
            (R::LabelMissing, "label_missing"),
            (R::ConcurrencyLimit, "concurrency_limit"),
            (R::Drain, "drain"),
            (R::FairnessHold, "fairness_hold"),
            (R::LocalityWait, "locality_wait"),
        ] {
            assert_eq!(wait_reason_json(reason), json!({ "code": code }));
        }
    }

    #[test]
    fn an_unnamed_reason_still_reports_structured_fields() {
        assert_eq!(
            debug_reason_json("GpuShort { gpus: 2, vram_short: 1024, shared: false }"),
            json!({ "code": "gpu_short", "gpus": 2, "vram_short": 1024, "shared": false })
        );
        assert_eq!(
            debug_reason_json("QuotaHold(\"tenant minutes\")"),
            json!({ "code": "quota_hold", "detail": "tenant minutes" })
        );
        assert_eq!(
            debug_reason_json("MaintenanceWindow"),
            json!({ "code": "maintenance_window" })
        );
    }

    #[test]
    fn transport_telemetry_leaves_unmeasured_fields_out() {
        use sentinel_link::session::{Path, TransportStats};
        let bare = transport_json(&TransportStats::default());
        assert_eq!(bare["path"], "unknown");
        assert!(bare.get("rtt_ns").is_none() && bare.get("helper_version").is_none());
        let measured = transport_json(&TransportStats {
            path: Path::Relay,
            rtt_ns: Some(12_000_000),
            reconnects: 2,
            helper_version: Some("tailcat 0.6.0".into()),
            bytes_out: 10,
            bytes_in: 20,
        });
        assert_eq!(measured["path"], "relay");
        assert_eq!(measured["rtt_ns"], 12_000_000);
        assert_eq!(measured["helper_version"], "tailcat 0.6.0");
        assert_eq!(
            (
                measured["reconnects"].as_u64(),
                measured["bytes_in"].as_u64()
            ),
            (Some(2), Some(20))
        );
    }
}
