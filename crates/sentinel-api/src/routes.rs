//! Route handling: one function per route, all through the same
//! authenticate → authorize → store → JSON path, with `sentinel.error/1`
//! for every refusal. Nothing here reads a tenant's rows without the
//! `auth` predicate that says the caller may.

use std::{
    io::{Read, Seek, SeekFrom},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::http::{Header, Request, Response, StatusCode};
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
    limits::{MAX_API_BODY_BYTES, MAX_PAGE_ITEMS, page_size},
};
use sentinel_store::{
    Error as StoreError, artifacts, auth as authz,
    auth::Authority,
    checks, dispatch, idempotency, local_auth, logs, lookup,
    objects::{Digest, Touch},
    provenance, runs, secrets, status, tenancy, workers,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    LOG_WAIT, MAX_UPLOAD_CHUNK, State, TRANSFERS,
    auth::{self, Identity, Refusal},
};

mod failure;
use failure::attempt_failure;

/// What a route answers: a JSON body, a bounded stream from the object
/// store, or an HTML page (OAuth consent and device pages, and `303`
/// redirects with an empty body and a `location`). Streams carry an
/// explicit length so the response is never chunked. HTML replies always
/// carry the page security headers ([`crate::oauth::html`]).
pub(crate) enum Reply {
    Json(u16, Value, Vec<Header>),
    /// A JSON document encoded once by a bounded protocol endpoint.
    JsonText(u16, String, Vec<Header>),
    Empty(u16, Vec<Header>),
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
    let (full_path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (url.clone(), String::new()),
    };
    // A proxy that forwards a path-carrying issuer's paths unstripped.
    let path = state.oauth.local_path(&full_path);
    if method == "GET" && path == "/" {
        let response = Response::from_string(state.index.as_str())
            .with_header(header("content-type", "text/html; charset=utf-8"));
        let _ = request.respond(response);
        return;
    }
    let outcome = route(state, request, &method, path, &query);
    let reply = match outcome {
        Ok(reply) => reply,
        Err(error) => {
            let headers = challenge(state, request, path, &error);
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

/// The `WWW-Authenticate` challenge of an `/api/v1` refusal (RFC 6750 §3,
/// RFC 9728 §5.1): every `401` names the protected-resource metadata, plus
/// `error="invalid_token"` when a token was presented; a scope refusal
/// names the missing scope. The GitHub and intake hooks have their own
/// secrets and are not OAuth resources.
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
    if rest.starts_with("hooks/") || rest.starts_with("intake/") || rest == "login" {
        return Vec::new();
    }
    match error.code {
        ErrorCode::Unauthenticated => {
            let metadata = if path == "/mcp" {
                &state.oauth.mcp_resource_metadata
            } else {
                &state.oauth.resource_metadata
            };
            let mut value = format!(
                "Bearer realm=\"sentinel\", resource_metadata=\"{}\"",
                metadata
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
            Some(scope) => {
                let metadata = if path == "/mcp" {
                    format!(
                        ", resource_metadata=\"{}\"",
                        state.oauth.mcp_resource_metadata
                    )
                } else {
                    String::new()
                };
                vec![header(
                    "www-authenticate",
                    &format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\"{metadata}"),
                )]
            }
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
        // Never `401`: the credential was not judged, and an OAuth client
        // answers `401` by spending its refresh token.
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
    // The OAuth authorization server owns `/.well-known/*`, `/oauth/*`,
    // `/device`, `/api/v1/grants*` and `/api/v1/tenants/*/service-accounts*`.
    if let Some(reply) = crate::oauth::route(state, request, method, &parts, query) {
        return reply;
    }
    if let Some(reply) = crate::github::route(state, request, method, &parts, query) {
        return reply;
    }
    match (method, parts.as_slice()) {
        ("GET", ["api", "v1", "health"]) => ok(json!({ "ok": true })),
        ("POST", ["mcp"]) => crate::mcp::post(state, request),
        ("GET", ["mcp"]) => crate::mcp::get(state, request),
        ("DELETE", ["mcp"]) => crate::mcp::delete(state, request),
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
                    // Membership-checked, so a foreign tenant is the same
                    // `not_found` as an absent one, never an empty list.
                    let tenant = authz::member_tenant_by_slug(c, who.principal, &slug)?;
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
        ("GET", ["api", "v1", "tenants", slug, "secrets"]) => {
            secret_list(state, request, slug, query)
        }
        ("GET", ["api", "v1", "tenants", slug, "secrets", name]) => {
            secret_describe(state, request, slug, name, query)
        }
        ("PUT", ["api", "v1", "tenants", slug, "secrets", name]) => {
            secret_put(state, request, slug, name, query)
        }
        ("DELETE", ["api", "v1", "tenants", slug, "secrets", name]) => {
            secret_delete(state, request, slug, name, query)
        }
        ("POST", ["api", "v1", "tenants", slug, "secrets", "import"]) => {
            secret_import(state, request, slug, query)
        }
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
            attempt_logs(state, request, attempt, query)
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
                        "transport": state.controller.transport(w.id).map(|t| transport_json(&t)),
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
            // The limit goes into the query: only the jobs shown are read and
            // explained, and `total` is an index count (P08-8).
            let page = state
                .store
                .read(|c| {
                    let tenant = lookup::tenant_by_slug(c, &slug)?;
                    authz::require_tenant_member(c, who.principal, tenant, false)?;
                    dispatch::list_queue(c, tenant, &connected, limit)
                })
                .map_err(store_error)?;
            ok(json!({
                "jobs": page.jobs.iter().map(queued_json).collect::<Vec<_>>(),
                "total": page.total,
                "truncated": page.total > page.jobs.len(),
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

/// A plaintext request body that is cleared on every return path after it has
/// been moved into a writer closure.
struct WipeBytes(Vec<u8>);
impl Drop for WipeBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct WipeRecords(Vec<(String, Vec<u8>)>);
impl Drop for WipeRecords {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.fill(0);
        }
    }
}

fn secret_metadata(value: &secrets::Metadata) -> Value {
    json!({
        "id": value.id.to_string(),
        "tenant": value.tenant.to_string(),
        "repo": value.repo.map(|id| id.to_string()),
        "name": value.name,
        "version": value.version,
        "active": value.active,
        "created_ms": value.created_ms,
        "updated_ms": value.updated_ms,
    })
}

fn secret_scope(
    state: &State,
    slug: &str,
    repo_name: Option<&str>,
) -> Result<(sentinel_core::TenantId, secrets::Scope), ApiError> {
    let slug = slug.to_owned();
    let repo_name = repo_name.map(str::to_owned);
    state
        .store
        .read(|conn| {
            let tenant = lookup::tenant_by_slug(conn, &slug)?;
            let scope = match repo_name {
                Some(name) => secrets::Scope::Repo(lookup::repo_by_name(conn, tenant, &name)?),
                None => secrets::Scope::Tenant(tenant),
            };
            Ok((tenant, scope))
        })
        .map_err(store_error)
}

fn secret_scope_repo(scope: secrets::Scope) -> Option<sentinel_core::RepoId> {
    match scope {
        secrets::Scope::Tenant(_) => None,
        secrets::Scope::Repo(repo) => Some(repo),
    }
}

fn secret_name_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn secret_read_identity(state: &State, request: &mut Request) -> Result<Identity, ApiError> {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::SECRETS_METADATA)?;
    Ok(who)
}

fn secret_write_identity(state: &State, request: &mut Request) -> Result<Identity, ApiError> {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::SECRETS_WRITE)?;
    Ok(who)
}

fn secret_page(query: &str) -> Result<(String, u16), ApiError> {
    let after = query_param(query, "after").unwrap_or("").to_owned();
    let limit = query_param(query, "limit")
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| err(ErrorCode::InvalidRequest, "invalid secret page size"))?
        .unwrap_or(100);
    if !(1..=100).contains(&limit) || after.len() > 64 {
        return Err(err(ErrorCode::InvalidRequest, "invalid secret page"));
    }
    Ok((after, limit))
}

fn secret_list(state: &State, request: &mut Request, slug: &str, query: &str) -> Route {
    let who = secret_read_identity(state, request)?;
    let repo = query_param(query, "repo");
    let (tenant, scope) = secret_scope(state, slug, repo)?;
    let (after, limit) = secret_page(query)?;
    let rows = state
        .store
        .read(|conn| secrets::list(conn, who.principal, scope, &after, limit))
        .map_err(store_error)?;
    let next = (rows.len() == limit as usize)
        .then(|| rows.last().map(|row| row.name.clone()))
        .flatten();
    ok(json!({
        "tenant": tenant.to_string(),
        "repo": secret_scope_repo(scope).map(|id| id.to_string()),
        "secrets": rows.iter().map(secret_metadata).collect::<Vec<_>>(),
        "next": next,
    }))
}

fn secret_describe(
    state: &State,
    request: &mut Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = secret_read_identity(state, request)?;
    if !secret_name_valid(name) {
        return Err(err(ErrorCode::InvalidRequest, "invalid secret name"));
    }
    let (tenant, scope) = secret_scope(state, slug, query_param(query, "repo"))?;
    let metadata = state
        .store
        .read(|conn| secrets::describe(conn, who.principal, scope, name))
        .map_err(store_error)?;
    ok(json!({"tenant":tenant.to_string(),"secret":secret_metadata(&metadata)}))
}

fn secret_write_key(state: &State) -> Result<Arc<sentinel_auth::sealed::Key>, ApiError> {
    state
        .secret_key
        .as_ref()
        .cloned()
        .ok_or_else(|| err(ErrorCode::Internal, "secret storage key is unavailable"))
}

fn secret_if_match(request: &Request) -> Result<u64, ApiError> {
    header_value(request, "if-match")
        .ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                "If-Match current version is required",
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            err(
                ErrorCode::InvalidRequest,
                "If-Match must be a secret version",
            )
        })
}

fn secret_idempotency(
    request: &Request,
) -> Result<sentinel_protocol::idempotency::IdempotencyKey, ApiError> {
    header_value(request, "idempotency-key")
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "Idempotency-Key is required"))
        .and_then(|value| {
            sentinel_protocol::idempotency::IdempotencyKey::parse(value)
                .map_err(sentinel_protocol::ApiError::from)
        })
}

fn secret_fingerprint(
    scope: secrets::Scope,
    name: &str,
    expected: &[u8],
    body: &[u8],
) -> sentinel_protocol::idempotency::Fingerprint {
    const OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
    const PRIME: u128 = 0x0000000001000000000000000000013B;
    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= byte as u128;
            hash = hash.wrapping_mul(PRIME);
        }
    };
    match scope {
        secrets::Scope::Tenant(tenant) => {
            feed(&[0]);
            feed(tenant.as_bytes());
        }
        secrets::Scope::Repo(repo) => {
            feed(&[1]);
            feed(repo.as_bytes());
        }
    }
    feed(&(name.len() as u32).to_be_bytes());
    feed(name.as_bytes());
    feed(&(expected.len() as u32).to_be_bytes());
    feed(expected);
    feed(&(body.len() as u64).to_be_bytes());
    feed(body);
    sentinel_protocol::idempotency::Fingerprint(hash)
}

fn secret_replay_json(bytes: &[u8]) -> Result<Value, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("secret idempotency response"))
}

fn secret_put(state: &State, request: &mut Request, slug: &str, name: &str, query: &str) -> Route {
    let who = secret_write_identity(state, request)?;
    if !secret_name_valid(name) {
        return Err(err(ErrorCode::InvalidRequest, "invalid secret name"));
    }
    let expected = secret_if_match(request)?;
    let idempotency = secret_idempotency(request)?;
    let tenant_slug = slug.to_owned();
    let repo_name = query_param(query, "repo").map(str::to_owned);
    let (tenant, scope) = secret_scope(state, &tenant_slug, repo_name.as_deref())?;
    let mut bytes = WipeBytes(body_limit(request, secrets::MAX_VALUE)?);
    if bytes.0.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret value must not be empty",
        ));
    }
    let fingerprint = secret_fingerprint(scope, name, &expected.to_be_bytes(), &bytes.0);
    let principal = who.user.to_string();
    let name = name.to_owned();
    let key = secret_write_key(state)?;
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.put",
                key: idempotency,
                fingerprint,
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                bytes.0.fill(0);
                return secret_replay_json(&response);
            }
            let metadata = secrets::put(
                tx,
                who.principal,
                secrets::Update {
                    scope,
                    name: &name,
                    expected,
                    value: &bytes.0,
                },
                &key,
                now,
            )?;
            bytes.0.fill(0);
            let response = json!({"tenant":tenant.to_string(),"secret":secret_metadata(&metadata)});
            let encoded = response.to_string();
            secrets::idempotency_save(tx, idempotency, encoded.as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    Ok(Reply::Json(200, value, Vec::new()))
}

fn secret_delete(
    state: &State,
    request: &mut Request,
    slug: &str,
    name: &str,
    query: &str,
) -> Route {
    let who = secret_write_identity(state, request)?;
    if !secret_name_valid(name) {
        return Err(err(ErrorCode::InvalidRequest, "invalid secret name"));
    }
    let expected = secret_if_match(request)?;
    let idempotency = secret_idempotency(request)?;
    let (tenant, scope) = secret_scope(state, slug, query_param(query, "repo"))?;
    let fingerprint = secret_fingerprint(scope, name, &expected.to_be_bytes(), b"delete");
    let principal = who.user.to_string();
    let name = name.to_owned();
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.delete",
                key: idempotency,
                fingerprint,
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                return secret_replay_json(&response);
            }
            let metadata = secrets::delete(tx, who.principal, scope, &name, expected, now)?;
            let response = json!({"tenant":tenant.to_string(),"secret":secret_metadata(&metadata)});
            let encoded = response.to_string();
            secrets::idempotency_save(tx, idempotency, encoded.as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    ok(value)
}

fn parse_expected_versions(
    value: &str,
) -> Result<std::collections::HashMap<String, u64>, ApiError> {
    if value.len() > 12_000 {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret import version list is too large",
        ));
    }
    let mut out = std::collections::HashMap::new();
    for item in value.split(',') {
        let Some((name, version)) = item.split_once('=') else {
            return Err(err(
                ErrorCode::InvalidRequest,
                "invalid secret import version list",
            ));
        };
        if !secret_name_valid(name) || out.contains_key(name) {
            return Err(err(
                ErrorCode::InvalidRequest,
                "invalid secret import version list",
            ));
        }
        let version = version.parse::<u64>().map_err(|_| {
            err(
                ErrorCode::InvalidRequest,
                "invalid secret import version list",
            )
        })?;
        out.insert(name.to_owned(), version);
    }
    if out.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret import version list is empty",
        ));
    }
    Ok(out)
}

fn secret_import(state: &State, request: &mut Request, slug: &str, query: &str) -> Route {
    let who = secret_write_identity(state, request)?;
    let idempotency = secret_idempotency(request)?;
    let expected_raw = header_value(request, "if-match")
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "If-Match versions are required"))?
        .to_owned();
    let expected = parse_expected_versions(&expected_raw)?;
    let (tenant, scope) = secret_scope(state, slug, query_param(query, "repo"))?;
    let mut bytes = WipeBytes(body_limit(
        request,
        sentinel_protocol::secrets::MAX_IMPORT_BYTES,
    )?);
    let records = sentinel_protocol::secrets::parse_env_file(&bytes.0)
        .map_err(|error| err(ErrorCode::InvalidRequest, error.to_string()))?;
    let mut records = WipeRecords(records);
    if records.0.len() != expected.len()
        || records
            .0
            .iter()
            .any(|(name, _)| !expected.contains_key(name))
    {
        return Err(err(
            ErrorCode::InvalidRequest,
            "If-Match must name every imported secret exactly once",
        ));
    }
    let fingerprint = secret_fingerprint(scope, "import", expected_raw.as_bytes(), &bytes.0);
    let principal = who.user.to_string();
    let key = secret_write_key(state)?;
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.import",
                key: idempotency,
                fingerprint,
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                bytes.0.fill(0);
                for (_, value) in &mut records.0 {
                    value.fill(0);
                }
                return secret_replay_json(&response);
            }
            let mut metadata = Vec::with_capacity(records.0.len());
            for (name, value) in &records.0 {
                let version = *expected
                    .get(name)
                    .ok_or(StoreError::Corrupt("secret import versions"))?;
                metadata.push(secrets::put(
                    tx,
                    who.principal,
                    secrets::Update {
                        scope,
                        name,
                        expected: version,
                        value,
                    },
                    &key,
                    now,
                )?);
            }
            bytes.0.fill(0);
            for (_, value) in &mut records.0 {
                value.fill(0);
            }
            let response = json!({
                "tenant":tenant.to_string(),
                "secrets":metadata.iter().map(secret_metadata).collect::<Vec<_>>(),
            });
            let encoded = response.to_string();
            secrets::idempotency_save(tx, idempotency, encoded.as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    ok(value)
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
    // Login CSRF: a cross-site form can post `text/plain` (whose body can be
    // shaped to parse as JSON) but not `application/json` without a CORS
    // preflight this server never grants; and a browser's `Origin`, when
    // sent, must be this deployment's.
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

/// A connected worker's transport telemetry (Q07), as it last reported it.
/// Unmeasured fields are absent, never zero: `path` is `unknown` until a
/// probe measured it, `rtt_ns` and `helper_version` are left out until set.
/// Nothing here is a credential: no address or key is ever reported.
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

/// The scheduler's reason as a code plus whatever says what is missing, each
/// quantity as its own numeric field. Every reason the store has today is
/// named here. The enum belongs to the store and is non-exhaustive, so a
/// reason added there before this match names it falls to the guard, which
/// still reports its own name and fields instead of an "unknown" the client
/// cannot act on.
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

/// The guard's rendering of a reason's `Debug` text: `Name { a: 1, b: 2 }`
/// becomes `{"code":"name","a":1,"b":2}`, `Name(x)` puts `x` in `detail`,
/// and `Name` is the code alone. Reasons are `Copy`, so their fields are
/// numbers, flags or static text, which this reads back as such.
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

/// One `Debug` field value as JSON: an integer or a flag as itself, quoted
/// text without its quotes, anything else as written.
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

/// A held transfer slot; dropping it frees the slot for the next
/// request. It owns its counter, so a download's slot can travel with the
/// body the connection streams after the route returned. The bounds exist
/// so bounded-heap processes never queue unbounded transfer work and long
/// polls and slow bodies never take the handler permits
/// [`crate::RESERVED_HANDLERS`] keeps for everything else.
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

/// A parked long poll's slot for `user`: refused `rate_limited` (with
/// `details.retry_after_ms`) when every slot is parked or this user already
/// holds its [`crate::SUBSCRIBERS_PER_USER`].
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

/// An attempt's tenant, run and job, after the caller's `read` on its
/// repository.
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

/// How often a parked log poll may re-read its attempt, however fast that
/// attempt appends.
const LOG_RECHECK: std::time::Duration = std::time::Duration::from_millis(100);

/// `GET /attempts/{att}/logs?after|cursor&limit&step&wait=1`: frames past a
/// position. `after` is a sequence number; `cursor` is the versioned
/// tenant- and attempt-bound `c1` form of the same position (the answer's
/// `next`). A page carries at most `limit` frames and
/// [`logs::PAGE_BYTES`] of payload and decodes at most
/// [`logs::PAGE_SCAN_BYTES`]; a page cut short says where to continue in
/// `next_after`/`next`. `wait=1` parks — on the log store's append
/// notifier, re-reading only when this attempt's stored frontier moved —
/// until something arrives, the log completes, the step has finished, or
/// the deadline.
fn attempt_logs(state: &State, request: &Request, attempt: &str, query: &str) -> Route {
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
    let after = match (after, query_param(query, "cursor")) {
        (Some(_), Some(_)) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "after and cursor are exclusive",
            ));
        }
        (Some(after), None) => after,
        (None, Some(text)) => {
            // Malformed, another tenant's, another stream's: one answer.
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
                // A pre-D04 flat log file is the only fallback.
                StoreError::NotFound => state.logs.tail_legacy_page(attempt, after, page, step),
                e => Err(e),
            })
            .map_err(store_error)
    };
    let changes = state.logs.changes();
    // The generation and the frontier are taken before the read: an append
    // landing after them moves one or both, so the park below never sleeps
    // through a frame the read missed.
    let mut seen = changes.generation();
    let mut frontier = state.logs.frontier(attempt);
    let mut tail = read()?;
    let deadline = std::time::Instant::now() + LOG_WAIT;
    // Parking holds a handler permit: the poll takes one of the
    // SUBSCRIBERS slots it shares with run waits before it parks.
    let mut parked: Option<crate::Subscriber<'_>> = None;
    let mut checked = std::time::Instant::now();
    while wait
        && tail.frames.is_empty()
        && !tail.complete
        && !tail.step_done
        && tail.next_after.is_none()
    {
        if parked.is_none() {
            parked = Some(subscriber(state, who.principal.user)?);
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
        // Every append in the store wakes the poll; only this attempt's
        // moving frontier (or its writer closing) is worth a read.
        let moved = state.logs.frontier(attempt);
        if moved == frontier {
            continue;
        }
        let since_check = checked.elapsed();
        if since_check < LOG_RECHECK {
            std::thread::sleep((LOG_RECHECK - since_check).min(deadline - now));
            seen = changes.generation();
        }
        frontier = state.logs.frontier(attempt);
        tail = read()?;
        checked = std::time::Instant::now();
    }
    drop(parked);
    // Where the next page starts: past the last frame this one covered.
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
        "frames": tail.frames.iter().map(|f| json!({
            "seq": f.seq, "step": f.step,
            "stream": stream_name(f.stream),
            "text": String::from_utf8_lossy(&f.bytes),
        })).collect::<Vec<_>>(),
    }))
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
    let mut parked: Option<crate::Subscriber<'_>> = None;
    while since == Some(current.version) && !current.finished {
        if parked.is_none() {
            parked = Some(subscriber(state, who.principal.user)?);
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
    let (_, run, job) = attempt_log(state, who.principal, attempt)?;
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

/// One chunk: `PUT /api/v1/uploads/<upl>?offset=N` with a raw body. The
/// bytes are written and synced outside the store's writer; the writer
/// only records the range.
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

/// A session touched past its expiry is retired in its own transaction —
/// then the request is refused. Retiring inside the refused request's
/// transaction would roll back with it.
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

/// Seal: the ranges must tile the declared length and match the digest.
/// Hashing and the rename run outside the writer (holding a transfer slot:
/// a seal reads the whole object); the writer flips the row and inserts
/// the object.
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

/// Stream a committed object, whole or a `Range`. The bytes are repository
/// evidence: the caller must be able to read an artifact that references
/// them, or be an operator of the tenant it was uploaded to
/// ([`authz::require_object_read`]). The reader registration keeps the file
/// un-reclaimable and the transfer slot stays held until the body has been
/// written. A whole-object body is rehashed while it streams and cut short
/// before its last byte if it does not match its digest.
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

/// A streamed range body that holds its transfer slot until dropped —
/// after the connection wrote it, not when the route returned.
struct Held<R> {
    inner: R,
    _slot: Slot,
}

impl<R: Read> Read for Held<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

/// A whole-object body: holds its slot like [`Held`] and rehashes as it
/// streams. The read that would deliver the final byte first finishes the
/// hash; on a mismatch (or a file shorter than its row) it fails instead,
/// so a client sees a truncated body rather than complete wrong bytes.
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

    /// Every quantity a reason carries is its own numeric field: a client
    /// reads `disk_short` as bytes, never parses a `detail` string.
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

    /// The guard for a reason the API does not name yet keeps its fields
    /// structured, whether the variant has named fields, a tuple or none.
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

    /// What a worker never measured stays out of the answer (AGENTS.md:
    /// unmeasured is absent, never zero).
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
