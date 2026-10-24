use sentinel_core::{
    PoolId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Role, Scopes},
};
use sentinel_protocol::{
    error::{ApiError, ErrorCode},
    limits::page_size,
};
use sentinel_store::{
    auth as authz, local_auth, lookup, mfa, operations,
    registration::{self, DeploymentPolicy, InstallationBinding, Registration, TenantCreation},
    retention, sources, tenancy, views,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Reply, Route, body, err, id, identify, ok, parse, query_param, store_error};
use crate::{State, auth, auth::Identity, http::Request};

/// Checks live platform rows, not the credential's claims, so a revoked super admin is refused at once.
fn platform(state: &State, request: &Request, mutation: bool) -> Result<Identity, ApiError> {
    let who = identify(state, request, mutation)?;
    auth::require_scope(&who, Scopes::PLATFORM_ADMIN)?;
    let authority = who.authority();
    state
        .store
        .read(move |c| authority.require_platform(c))
        .map_err(store_error)?;
    Ok(who)
}

fn tenant_admin(state: &State, request: &Request, mutation: bool) -> Result<Identity, ApiError> {
    let who = identify(state, request, mutation)?;
    auth::require_scope(&who, Scopes::TENANT_ADMIN)?;
    Ok(who)
}

fn limit(query: &str) -> u16 {
    page_size(query_param(query, "limit").and_then(|v| v.parse().ok()))
        .min(usize::from(views::MAX_PAGE)) as u16
}

fn before(query: &str) -> Result<Option<i64>, ApiError> {
    query_param(query, "before")
        .map(|v| {
            v.parse::<i64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| err(ErrorCode::InvalidRequest, "malformed before"))
        })
        .transpose()
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Reader => "reader",
        Role::Operator => "operator",
        Role::TenantAdmin => "admin",
    }
}

fn parse_role(text: &str) -> Result<Role, ApiError> {
    match text {
        "reader" => Ok(Role::Reader),
        "operator" => Ok(Role::Operator),
        "admin" => Ok(Role::TenantAdmin),
        _ => Err(err(
            ErrorCode::InvalidRequest,
            "role must be reader, operator or admin",
        )),
    }
}

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
    query: &str,
) -> Option<Route> {
    Some(match (method, parts) {
        ("POST", ["api", "v1", "step-up"]) => step_up(state, request),
        ("GET", ["api", "v1", "admin", "tenants"]) => list_tenants(state, request, query),
        ("POST", ["api", "v1", "admin", "tenants"]) => create_tenant(state, request),
        (
            "POST",
            [
                "api",
                "v1",
                "admin",
                "tenants",
                slug,
                action @ ("suspend" | "reactivate"),
            ],
        ) => suspend(state, request, slug, *action == "suspend"),
        ("PUT" | "DELETE", ["api", "v1", "admin", "tenants", slug, "quota"]) => {
            quota(state, request, slug, method == "PUT")
        }
        ("PUT", ["api", "v1", "admin", "tenants", slug, "storage"]) => {
            set_storage(state, request, slug, None)
        }
        ("GET", ["api", "v1", "admin", "storage"]) => deployment_storage(state, request),
        ("GET", ["api", "v1", "admin", "backups"]) => list_backups(state, request),
        ("POST", ["api", "v1", "admin", "backups"]) => start_backup(state, request),
        ("GET", ["api", "v1", "admin", "diagnostics"]) => diagnostics(state, request, query),
        ("GET", ["api", "v1", "tenants", slug, "storage"]) => tenant_storage(state, request, slug),
        ("PUT", ["api", "v1", "tenants", slug, "repos", name, "storage"]) => {
            set_storage(state, request, slug, Some(name))
        }
        ("GET", ["api", "v1", "admin", "registrations"]) => registrations(state, request, query),
        (
            "POST",
            [
                "api",
                "v1",
                "admin",
                "registrations",
                user,
                action @ ("approve" | "reject"),
            ],
        ) => decide(state, request, user, *action == "approve"),
        ("GET", ["api", "v1", "admin", "policy"]) => get_policy(state, request),
        ("PUT", ["api", "v1", "admin", "policy"]) => set_policy(state, request),
        ("GET", ["api", "v1", "admin", "pools"]) => list_pools(state, request),
        ("POST", ["api", "v1", "admin", "pools"]) => create_pool(state, request),
        ("PUT" | "DELETE", ["api", "v1", "admin", "pools", pool, "grants", slug]) => {
            pool_grant(state, request, pool, slug, method == "PUT")
        }
        ("GET", ["api", "v1", "admin", "audit"]) => audit(state, request, query),
        ("GET", ["api", "v1", "tenants", slug, "members"]) => members(state, request, slug, query),
        ("PUT" | "DELETE", ["api", "v1", "tenants", slug, "members", user]) => {
            set_member(state, request, slug, user, method == "PUT")
        }
        ("PUT", ["api", "v1", "tenants", slug, "membership-source"]) => {
            set_backing(state, request, slug)
        }
        ("POST", ["api", "v1", "tenants", slug, "repos"]) => create_repo(state, request, slug),
        ("GET", ["api", "v1", "tenants", slug, "repos", name, "source"]) => {
            source(state, request, slug, name)
        }
        ("PUT", ["api", "v1", "tenants", slug, "repos", name, "grants", user]) => {
            repo_grant(state, request, slug, name, user)
        }
        ("GET", ["api", "v1", "tenants", slug, "audit"]) => {
            tenant_audit(state, request, slug, query)
        }
        _ => return None,
    })
}

#[derive(Deserialize)]
struct StepUpBody {
    method: String,
    code: String,
}

fn step_up(state: &State, request: &mut Request) -> Route {
    let who = identify(state, request, true)?;
    if who.via != auth::Via::Session {
        return Err(err(
            ErrorCode::InvalidRequest,
            "only a browser session steps up",
        ));
    }
    let Some(key) = state.secret_key.as_deref() else {
        return Err(err(
            ErrorCode::Forbidden,
            "step-up needs the deployment master key; initialize it first",
        ));
    };
    let presented = super::header_value(request, "cookie")
        .and_then(|h| sentinel_auth::cookie::read(sentinel_auth::cookie::SESSION_COOKIE, h))
        .ok_or_else(|| err(ErrorCode::Unauthenticated, "sign in"))?;
    let bytes = body(request)?;
    let proof: StepUpBody = parse(&bytes)?;
    if proof.code.is_empty() || proof.code.len() > 1024 {
        return Err(err(ErrorCode::InvalidRequest, "invalid code"));
    }
    let proof_kind = match proof.method.as_str() {
        "totp" => mfa::Proof::Totp(&proof.code),
        "recovery" => mfa::Proof::Recovery(&proof.code),
        "password" => mfa::Proof::Password(proof.code.as_bytes()),
        _ => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "method must be totp, recovery or password",
            ));
        }
    };
    let now = UnixMillis::now();
    let session = state
        .store
        .read(|c| local_auth::authenticate(c, &presented, now))
        .map_err(|_| err(ErrorCode::Unauthenticated, "sign in"))?;
    let accepted = mfa::step_up(&state.store, key, &presented, &session, proof_kind, now)
        .map_err(store_error)?;
    if !accepted {
        return Err(err(ErrorCode::Forbidden, "step-up refused").with_detail("step_up", true));
    }
    ok(json!({
        "stepped_up": true,
        "until_ms": now.0.saturating_add(state.sessions.step_up_ms),
    }))
}

fn list_tenants(state: &State, request: &Request, query: &str) -> Route {
    let who = platform(state, request, false)?;
    let after = query_param(query, "after").map(str::to_owned);
    let limit = limit(query);
    let rows = state
        .store
        .read(|c| {
            let rows = views::tenants(c, who.authority(), after.as_deref(), limit)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let effective = state.objects.quota(c, row.id)?;
                out.push((row, effective));
            }
            Ok(out)
        })
        .map_err(store_error)?;
    let next = (rows.len() == usize::from(limit))
        .then(|| rows.last().map(|(r, _)| r.slug.clone()))
        .flatten();
    ok(json!({
        "tenants": rows.iter().map(|(t, effective)| json!({
            "id": t.id.to_string(),
            "slug": t.slug,
            "kind": if t.personal { "personal" } else { "organization" },
            "active": t.active,
            "created_ms": t.created.0,
            "members": t.members,
            "usage_bytes": t.usage_bytes,
            "quota_bytes": effective,
            "quota_set": t.quota_bytes.is_some(),
            "log_retention_ms": t.log_retention_ms,
            "artifact_retention_ms": t.artifact_retention_ms,
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}

#[derive(Deserialize)]
struct CreateTenant {
    slug: String,
}

fn create_tenant(state: &State, request: &mut Request) -> Route {
    let who = platform(state, request, true)?;
    let body: CreateTenant = parse(&body(request)?)?;
    if Namespace::parse(&body.slug).is_none() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "slug must be 1-63 lowercase letters, digits or inner hyphens",
        ));
    }
    let tenant = TenantId::new();
    let authority = who.authority();
    let slug = body.slug.clone();
    state
        .store
        .writer()
        .write(move |tx| {
            let parsed =
                Namespace::parse(&slug).ok_or(sentinel_store::Error::InvalidInput("slug"))?;
            tenancy::create_organization(tx, authority, tenant, parsed, UnixMillis::now())
        })
        .map_err(|e| match e {
            sentinel_store::Error::Sqlite(_) => err(ErrorCode::Conflict, "slug already taken"),
            e => store_error(e),
        })?;
    Ok(Reply::Json(
        201,
        json!({ "id": tenant.to_string(), "slug": body.slug }),
        Vec::new(),
    ))
}

fn suspend(state: &State, request: &mut Request, slug: &str, suspend: bool) -> Route {
    let who = platform(state, request, true)?;
    let authority = who.authority();
    let slug = slug.to_owned();
    let now = UnixMillis::now();
    let outcome = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = views::tenant_for_platform(tx, authority, &slug)?;
            if suspend {
                tenancy::suspend(tx, authority, tenant, now).map(Some)
            } else {
                tenancy::reactivate(tx, authority, tenant, now).map(|()| None)
            }
        })
        .map_err(store_error)?;
    state.controller.wake();
    ok(match outcome {
        Some(s) => json!({
            "active": false,
            "tokens_revoked": s.tokens_revoked,
            "invitations_revoked": s.invitations_revoked,
            "jobs_canceled": s.jobs_canceled,
            "jobs_cancel_requested": s.jobs_cancel_requested,
        }),
        None => json!({ "active": true }),
    })
}

#[derive(Deserialize)]
struct QuotaBody {
    bytes: u64,
}

fn quota(state: &State, request: &mut Request, slug: &str, set: bool) -> Route {
    let who = platform(state, request, true)?;
    let bytes = if set {
        let body: QuotaBody = parse(&body(request)?)?;
        if body.bytes == 0 || body.bytes > i64::MAX as u64 {
            return Err(err(ErrorCode::InvalidRequest, "bytes must be positive"));
        }
        Some(body.bytes)
    } else {
        None
    };
    let authority = who.authority();
    let slug = slug.to_owned();
    let objects = std::sync::Arc::clone(&state.objects);
    let effective = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = views::tenant_for_platform(tx, authority, &slug)?;
            match bytes {
                Some(bytes) => objects.set_quota(tx, tenant, bytes)?,
                None => objects.clear_quota(tx, tenant)?,
            }
            objects.quota(tx, tenant)
        })
        .map_err(store_error)?;
    ok(json!({ "quota_bytes": effective, "quota_set": bytes.is_some() }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageBody {
    #[serde(default)]
    quota_bytes: Option<u64>,
    #[serde(default)]
    log_retention_secs: Option<u64>,
    #[serde(default)]
    artifact_retention_secs: Option<u64>,
}

fn secs_ms(secs: Option<u64>) -> Result<Option<i64>, ApiError> {
    secs.map(|s| {
        s.checked_mul(1000)
            .and_then(|ms| i64::try_from(ms).ok())
            .filter(|ms| (retention::MIN_RETENTION_MS..=retention::MAX_RETENTION_MS).contains(ms))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    "retention must be between 1 hour and 366 days",
                )
            })
    })
    .transpose()
}

fn storage_policy_json(p: &retention::Policy) -> Value {
    json!({
        "quota_bytes": p.quota_bytes,
        "log_retention_ms": p.log_retention_ms,
        "artifact_retention_ms": p.artifact_retention_ms,
    })
}

fn effective_json(e: &retention::Effective) -> Value {
    json!({
        "tenant_quota_bytes": e.tenant_quota_bytes,
        "repo_quota_bytes": e.repo_quota_bytes,
        "log_retention_ms": e.log_retention_ms,
        "artifact_retention_ms": e.artifact_retention_ms,
    })
}

fn set_storage(state: &State, request: &mut Request, slug: &str, repo: Option<&str>) -> Route {
    let who = if repo.is_some() {
        tenant_admin(state, request, true)?
    } else {
        platform(state, request, true)?
    };
    let body: StorageBody = parse(&body(request)?)?;
    if body.quota_bytes == Some(0) || body.quota_bytes.is_some_and(|q| q > i64::MAX as u64) {
        return Err(err(
            ErrorCode::InvalidRequest,
            "quota_bytes must be positive",
        ));
    }
    let policy = retention::Policy {
        quota_bytes: body.quota_bytes,
        log_retention_ms: secs_ms(body.log_retention_secs)?,
        artifact_retention_ms: secs_ms(body.artifact_retention_secs)?,
    };
    let authority = who.authority();
    let principal = who.principal;
    let d = state.objects.deployment();
    let (slug, repo) = (slug.to_owned(), repo.map(str::to_owned));
    let (own, effective, (tenant, repo, rest)) = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, repo) = match repo {
                None => (views::tenant_for_platform(tx, authority, &slug)?, None),
                Some(name) => {
                    let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
                    authz::require_tenant_admin(tx, principal, tenant)?;
                    (tenant, Some(lookup::repo_by_name(tx, tenant, &name)?))
                }
            };
            let rest = retention::set(tx, &authority, &d, tenant, repo, policy, UnixMillis::now())?;
            Ok((
                retention::policy(tx, tenant, repo)?,
                retention::effective(tx, &d, tenant, repo)?,
                (tenant, repo, rest),
            ))
        })
        .map_err(store_error)?;
    // Re-stamping runs a bounded write at a time, so the writer serves other requests between batches.
    retention::finish_reapply(&state.store, &d, tenant, repo, rest).map_err(store_error)?;
    ok(json!({ "policy": storage_policy_json(&own), "effective": effective_json(&effective) }))
}

fn tenant_storage(state: &State, request: &Request, slug: &str) -> Route {
    let who = tenant_admin(state, request, false)?;
    let principal = who.principal;
    let d = state.objects.deployment();
    let slug = slug.to_owned();
    let (usage, own, effective, repos) = state
        .store
        .read(move |c| {
            let tenant = authz::member_tenant_by_slug(c, principal, &slug)?;
            authz::require_tenant_admin(c, principal, tenant)?;
            let repos = retention::repos(c, tenant)?
                .into_iter()
                .map(|r| {
                    let e = retention::effective(c, &d, tenant, Some(r.repo))?;
                    Ok((r, e))
                })
                .collect::<sentinel_store::Result<Vec<_>>>()?;
            Ok((
                retention::tenant_usage(c, tenant)?,
                retention::policy(c, tenant, None)?,
                retention::effective(c, &d, tenant, None)?,
                repos,
            ))
        })
        .map_err(store_error)?;
    ok(json!({
        "usage": { "object_bytes": usage.object_bytes, "log_bytes": usage.log_bytes },
        "policy": storage_policy_json(&own),
        "effective": effective_json(&effective),
        "repos": repos.iter().map(|(r, e)| json!({
            "id": r.repo.to_string(),
            "name": r.name,
            "usage": { "artifact_bytes": r.usage.artifact_bytes, "log_bytes": r.usage.log_bytes },
            "policy": storage_policy_json(&r.policy),
            "effective": effective_json(e),
        })).collect::<Vec<_>>(),
    }))
}

fn deployment_storage(state: &State, request: &Request) -> Route {
    platform(state, request, false)?;
    let d = state.objects.deployment();
    let stored = state
        .store
        .read(retention::deployment_usage)
        .map_err(store_error)?;
    let total = sentinel_store::space::total_bytes(state.objects.root()).ok();
    let admission = state.objects.admission();
    ok(json!({
        "filesystem_bytes": total,
        "free_bytes": admission.map(|a| a.free()),
        "metadata_bytes": state.store.metadata_bytes(),
        "admission_open": admission.map(|a| a.is_open()),
        "inflight_bytes": admission.map(|a| a.total_inflight()),
        "watermarks": admission.map(|a| {
            let m = a.watermarks();
            json!({
                "reserve_bytes": a.reserve(),
                "configured_reserve_bytes": m.reserve,
                "low_watermark_bytes": m.low,
                "high_watermark_bytes": m.high,
                "log_floor_bytes": m.floor,
            })
        }),
        "stored_bytes": stored,
        "quota_bytes": d.quota_bytes,
        "tenant_quota_bytes": d.tenant_quota_bytes,
        "log_retention_ms": d.log_retention_ms,
        "artifact_retention_ms": d.artifact_retention_ms,
        "run_artifact_bytes": d.run_artifact_bytes,
        "s3": state.objects.replication().map(|r| {
            use std::sync::atomic::Ordering::Relaxed;
            let at = |v: i64| (v > 0).then_some(v);
            json!({
                "state": r.state(),
                "backlog_bytes": r.backlog_bytes.load(Relaxed),
                "backlog_full": r.backlog_full.load(Relaxed),
                "oldest_unreplicated_ms": at(r.oldest_unreplicated_ms.load(Relaxed)),
                "unreplicated_logs": r.unreplicated_logs.load(Relaxed),
                "local_bytes": r.local_bytes.load(Relaxed),
                "last_success_ms": at(r.last_success_ms.load(Relaxed)),
                "last_failure_ms": at(r.last_failure_ms.load(Relaxed)),
                "consecutive_failures": r.consecutive_failures.load(Relaxed),
                "last_error": r.last_error.lock().unwrap_or_else(|p| p.into_inner()).clone(),
                "last_local_fault": r.last_local_fault.lock().unwrap_or_else(|p| p.into_inner()).clone(),
                "replicated_objects": r.replicated_objects.load(Relaxed),
                "replicated_bytes": r.replicated_bytes.load(Relaxed),
                "replicated_logs": r.replicated_logs.load(Relaxed),
                "evicted_objects": r.evicted_objects.load(Relaxed),
                "fetched_objects": r.fetched_objects.load(Relaxed),
                "deleted_copies": r.deleted_copies.load(Relaxed),
                "aborted_uploads": r.aborted_uploads.load(Relaxed),
                "local_faults": r.local_faults.load(Relaxed),
            })
        }),
    }))
}

fn list_backups(state: &State, request: &Request) -> Route {
    platform(state, request, false)?;
    let Some(backups) = state.objects.backups() else {
        return ok(json!({ "configured": false, "backups": [] }));
    };
    let target = backups.target().to_path_buf();
    let ids = sentinel_store::backup::list(&target).map_err(store_error)?;
    let listed: Vec<Value> = ids
        .iter()
        .rev()
        .filter_map(|id| sentinel_store::backup::manifest(&target, id).ok())
        .map(|m| {
            json!({
                "id": m["id"],
                "started_ms": m["started_ms"],
                "took_ms": m["took_ms"],
                "schema": m["schema"],
                "version": m["version"],
                "metadata_bytes": m["metadata"]["bytes"],
                "objects": m["objects"]["rows"],
                "objects_remote_only": m["objects"]["remote_only"],
                "key_required": m["key"]["required"],
                "key_ids": m["key"]["key_ids"],
            })
        })
        .collect();
    ok(json!({ "configured": true, "scheduler": backups.status(), "backups": listed }))
}

fn diagnostics(state: &State, request: &Request, query: &str) -> Route {
    use std::sync::atomic::Ordering::Relaxed;
    platform(state, request, false)?;
    let integrity = query_param(query, "integrity") == Some("1");
    let now = UnixMillis::now().0;
    let mut bundle = state
        .store
        .read(move |c| sentinel_store::bundle::collect(c, now, integrity))
        .map_err(store_error)?;
    let process = sentinel_core::process::figures();
    let s = state.controller.stats();
    let ready = match super::ready(state) {
        Ok(Reply::Json(_, v, _)) => v,
        _ => Value::Null,
    };
    let backups = state.objects.backups().map(|b| {
        let mut status = b.status();
        if let Some(o) = status.as_object_mut() {
            o.remove("target");
        }
        status
    });
    bundle["runtime"] = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_binary": sentinel_store::schema::LATEST,
        "worker_protocol": [
            sentinel_protocol::negotiate::SUPPORTED_MIN.0,
            sentinel_protocol::negotiate::SUPPORTED_MAX.0,
        ],
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "process": {
            "resident_bytes": process.resident_bytes,
            "cpu_seconds": process.cpu_seconds,
            "open_fds": process.open_fds,
            "threads": process.threads,
        },
        "ready": ready,
        "workers_connected": state.controller.connected().len(),
        "link": {
            "admitted": s.admitted.load(Relaxed),
            "rejected": s.rejected.load(Relaxed),
            "lapsed": s.lapsed.load(Relaxed),
            "expired": s.expired.load(Relaxed),
            "abandoned": s.abandoned.load(Relaxed),
            "log_refused": s.log_refused.load(Relaxed),
            "placement_errors": s.placement_errors.load(Relaxed),
            "sweep_errors": s.sweep_errors.load(Relaxed),
        },
        "http": state.requests.snapshot(),
        "storage": {
            "metadata_bytes": state.store.metadata_bytes(),
            "admission": state.objects.admission().map(|a| json!({
                "open": a.is_open(),
                "free_bytes": a.free(),
                "reserve_bytes": a.reserve(),
                "backlog_full": a.backlog_full(),
            })),
            "external_copy": state.objects.replication().map(|r| json!({
                "state": r.state(),
                "backlog_bytes": r.backlog_bytes.load(Relaxed),
                "consecutive_failures": r.consecutive_failures.load(Relaxed),
            })),
            "backups": backups,
        },
    });
    ok(bundle)
}

fn start_backup(state: &State, request: &mut Request) -> Route {
    platform(state, request, true)?;
    let Some(backups) = state.objects.backups() else {
        return Err(err(
            ErrorCode::Conflict,
            "backups are not configured: set [backup] dir in the controller's configuration",
        ));
    };
    if !backups.trigger() {
        return Err(err(ErrorCode::Conflict, "a backup is already running"));
    }
    Ok(Reply::Json(202, json!({ "started": true }), Vec::new()))
}

fn registrations(state: &State, request: &Request, query: &str) -> Route {
    let who = platform(state, request, false)?;
    let limit = limit(query);
    let pending = state
        .store
        .read(|c| registration::pending(c, who.authority(), limit))
        .map_err(store_error)?;
    ok(json!({
        "pending": pending.iter().map(|a| json!({
            "user": a.user.to_string(),
            "display_name": a.display_name,
            "applied_ms": a.applied.0,
        })).collect::<Vec<_>>(),
    }))
}

fn decide(state: &State, request: &mut Request, user: &str, approve: bool) -> Route {
    let who = platform(state, request, true)?;
    let user: UserId = id(user, "user")?;
    let authority = who.authority();
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| {
            if approve {
                registration::approve(tx, authority, user, now)
            } else {
                registration::reject(tx, authority, user, now)
            }
        })
        .map_err(store_error)?;
    ok(json!({ "user": user.to_string(), "approved": approve }))
}

fn policy_json(p: DeploymentPolicy) -> Value {
    json!({
        "registration": match p.registration {
            Registration::Closed => "closed",
            Registration::InviteOnly => "invite_only",
            Registration::ApprovalRequired => "approval_required",
        },
        "tenant_creation": match p.tenant_creation {
            TenantCreation::SuperAdminOnly => "super_admin_only",
            TenantCreation::ApprovedUsers => "approved_users",
        },
        "installation_binding": match p.installation_binding {
            InstallationBinding::SuperAdminOnly => "super_admin_only",
            InstallationBinding::TenantAdmins => "tenant_admins",
        },
    })
}

fn get_policy(state: &State, request: &Request) -> Route {
    platform(state, request, false)?;
    let policy = state
        .store
        .read(registration::policy)
        .map_err(store_error)?;
    ok(policy_json(policy))
}

#[derive(Deserialize)]
struct PolicyBody {
    registration: String,
    tenant_creation: String,
    installation_binding: String,
}

fn set_policy(state: &State, request: &mut Request) -> Route {
    let who = platform(state, request, true)?;
    let body: PolicyBody = parse(&body(request)?)?;
    let invalid = |what: &str| err(ErrorCode::InvalidRequest, format!("invalid {what}"));
    let policy = DeploymentPolicy {
        registration: match body.registration.as_str() {
            "closed" => Registration::Closed,
            "invite_only" => Registration::InviteOnly,
            "approval_required" => Registration::ApprovalRequired,
            _ => return Err(invalid("registration")),
        },
        tenant_creation: match body.tenant_creation.as_str() {
            "super_admin_only" => TenantCreation::SuperAdminOnly,
            "approved_users" => TenantCreation::ApprovedUsers,
            _ => return Err(invalid("tenant_creation")),
        },
        installation_binding: match body.installation_binding.as_str() {
            "super_admin_only" => InstallationBinding::SuperAdminOnly,
            "tenant_admins" => InstallationBinding::TenantAdmins,
            _ => return Err(invalid("installation_binding")),
        },
    };
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| registration::set_policy(tx, authority, policy, UnixMillis::now()))
        .map_err(store_error)?;
    ok(policy_json(policy))
}

fn list_pools(state: &State, request: &Request) -> Route {
    let who = platform(state, request, false)?;
    let pools = state
        .store
        .read(|c| views::pools(c, who.authority()))
        .map_err(store_error)?;
    ok(json!({
        "pools": pools.iter().map(|p| json!({
            "id": p.id.to_string(),
            "name": p.name,
            "kind": match p.kind { tenancy::PoolKind::Shared => "shared", tenancy::PoolKind::Dedicated(_) => "dedicated" },
            "owner": p.owner,
            "active": p.active,
            "grants": p.grants,
            "workers": p.workers,
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct PoolBody {
    name: String,
    kind: String,
    #[serde(default)]
    tenant: Option<String>,
}

fn create_pool(state: &State, request: &mut Request) -> Route {
    let who = platform(state, request, true)?;
    let body: PoolBody = parse(&body(request)?)?;
    if body.name.is_empty() || body.name.len() > 64 {
        return Err(err(ErrorCode::InvalidRequest, "name must be 1-64 bytes"));
    }
    let dedicated = match (body.kind.as_str(), &body.tenant) {
        ("shared", None) => false,
        ("dedicated", Some(_)) => true,
        _ => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "a shared pool takes no tenant; a dedicated pool needs one",
            ));
        }
    };
    let pool = PoolId::new();
    let authority = who.authority();
    let name = body.name.clone();
    state
        .store
        .writer()
        .write(move |tx| {
            let kind = if dedicated {
                let slug = body.tenant.as_deref().unwrap_or_default();
                tenancy::PoolKind::Dedicated(views::tenant_for_platform(tx, authority, slug)?)
            } else {
                tenancy::PoolKind::Shared
            };
            tenancy::create_pool(tx, authority, pool, &name, kind, UnixMillis::now())
        })
        .map_err(|e| match e {
            sentinel_store::Error::Sqlite(_) => err(ErrorCode::Conflict, "pool name already taken"),
            e => store_error(e),
        })?;
    Ok(Reply::Json(
        201,
        json!({ "id": pool.to_string(), "name": body.name }),
        Vec::new(),
    ))
}

fn pool_grant(state: &State, request: &mut Request, pool: &str, slug: &str, grant: bool) -> Route {
    let who = platform(state, request, true)?;
    let pool: PoolId = id(pool, "pool")?;
    let authority = who.authority();
    let slug = slug.to_owned();
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = views::tenant_for_platform(tx, authority, &slug)?;
            let now = UnixMillis::now();
            if grant {
                tenancy::grant_pool(tx, authority, pool, tenant, now)
            } else {
                tenancy::revoke_pool_grant(tx, authority, pool, tenant, now)
            }
        })
        .map_err(store_error)?;
    state.controller.wake();
    ok(json!({ "pool": pool.to_string(), "granted": grant }))
}

fn audit(state: &State, request: &Request, query: &str) -> Route {
    let who = platform(state, request, false)?;
    let before = before(query)?;
    let limit = limit(query);
    let records = state
        .store
        .read(|c| views::audit(c, who.authority(), before, limit))
        .map_err(store_error)?;
    let next = (records.len() == usize::from(limit))
        .then(|| records.last().map(|r| r.seq))
        .flatten();
    ok(json!({
        "events": records.iter().map(|r| json!({
            "seq": r.seq,
            "at_ms": r.at.0,
            "event": r.event.name(),
            "actor": r.actor.map(|u| u.to_string()),
            "subject": r.subject.map(|u| u.to_string()),
            "host_local": r.host_local,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}

fn members(state: &State, request: &Request, slug: &str, query: &str) -> Route {
    let who = tenant_admin(state, request, false)?;
    let after: Option<UserId> = query_param(query, "after")
        .map(|v| id(v, "user"))
        .transpose()?;
    let limit = limit(query);
    let slug = slug.to_owned();
    let rows = state
        .store
        .read(|c| {
            let tenant = authz::member_tenant_by_slug(c, who.principal, &slug)?;
            views::members(c, who.principal, tenant, after, limit)
        })
        .map_err(store_error)?;
    let next = (rows.len() == usize::from(limit))
        .then(|| rows.last().map(|m| m.user.to_string()))
        .flatten();
    ok(json!({
        "members": rows.iter().map(|m| json!({
            "user": m.user.to_string(),
            "display_name": m.display_name,
            "username": m.username,
            "kind": if m.service { "service" } else { "person" },
            "role": role_name(m.role),
            "active": m.active,
            "source": if m.synced.is_some() { "github" } else { "app" },
            "synced_ms": m.synced.map(|t| t.0),
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}

#[derive(Deserialize)]
struct BackingBody {
    source: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Converting removes members GitHub does not confirm, so the admin must have linked GitHub first.
fn set_backing(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = tenant_admin(state, request, true)?;
    let body: BackingBody = parse(&body(request)?)?;
    let github = match body.source.as_str() {
        "github" => true,
        "app" => false,
        _ => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "source must be github or app",
            ));
        }
    };
    let (slug, reason, authority) = (slug.to_owned(), body.reason, who.authority());
    let principal = who.principal;
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            authz::require_tenant_admin(tx, principal, tenant)?;
            sentinel_store::github_members::set_backing(
                tx,
                authority,
                tenant,
                github,
                reason.as_deref(),
                UnixMillis::now(),
            )
        })
        .map_err(|e| match e {
            sentinel_store::Error::Conflict => err(
                ErrorCode::Conflict,
                "bind an installation of a GitHub organization to the tenant first",
            ),
            e => store_error(e),
        })?;
    ok(json!({ "source": body.source }))
}

#[derive(Deserialize)]
struct MemberBody {
    role: String,
    #[serde(default)]
    reason: Option<String>,
}

fn set_member(state: &State, request: &mut Request, slug: &str, user: &str, put: bool) -> Route {
    let who = tenant_admin(state, request, true)?;
    let (role, reason) = if put {
        let body: MemberBody = parse(&body(request)?)?;
        (Some(parse_role(&body.role)?), body.reason)
    } else {
        (None, None)
    };
    let (slug, user) = (slug.to_owned(), user.to_owned());
    let (principal, authority) = (who.principal, who.authority());
    let member = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            // Check administration before resolving the name: resolving first would reveal which accounts exist.
            authz::require_tenant_admin(tx, principal, tenant)?;
            let user = authz::resolve_member(tx, tenant, &user)?;
            match role {
                Some(role) => {
                    authz::set_membership_as(tx, authority, tenant, user, role, reason.as_deref())?
                }
                None => authz::remove_membership(tx, principal, tenant, user, UnixMillis::now())?,
            }
            Ok(user)
        })
        .map_err(|e| match e {
            sentinel_store::Error::Conflict => err(
                ErrorCode::Conflict,
                "the tenant's last administrator keeps the admin role",
            ),
            e => store_error(e),
        })?;
    ok(json!({
        "user": member.to_string(),
        "role": role.map(role_name),
    }))
}

#[derive(Deserialize)]
struct RepoBody {
    name: String,
}

/// Hook secrets are set host-locally, so their credentials never cross the API.
fn create_repo(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = tenant_admin(state, request, true)?;
    let body: RepoBody = parse(&body(request)?)?;
    let valid = !body.name.is_empty()
        && body.name.len() <= 128
        && body
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !valid {
        return Err(err(
            ErrorCode::InvalidRequest,
            "name must be 1-128 letters, digits, '-', '_' or '.'",
        ));
    }
    let repo = RepoId::new();
    let principal = who.principal;
    let (slug, name) = (slug.to_owned(), body.name.clone());
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            authz::create_repo(tx, principal, tenant, repo, &name, UnixMillis::now())
        })
        .map_err(|e| match e {
            sentinel_store::Error::Sqlite(_) => {
                err(ErrorCode::Conflict, "repository name already taken")
            }
            e => store_error(e),
        })?;
    Ok(Reply::Json(
        201,
        json!({ "id": repo.to_string(), "name": body.name }),
        Vec::new(),
    ))
}

fn source(state: &State, request: &Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let meta = state
        .store
        .read(|c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            match sources::metadata(c, who.principal, repo) {
                Ok(meta) => Ok(Some(meta)),
                Err(sentinel_store::Error::NotFound) => {
                    authz::require_repo(c, who.principal, repo, Permissions::READ)?;
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        })
        .map_err(store_error)?;
    ok(match meta {
        None => json!({ "bound": false }),
        Some(m) => json!({
            "bound": true,
            "remote": m.binding.remote,
            "allowed_refs": m.binding.allowed_refs,
            "pipeline_path": m.binding.pipeline_path,
            "trust_pinned": !m.binding.trust.is_empty(),
            "version": m.version,
            "revoked": m.revoked,
            "github_repository_id": m.forge.map(|(_, id)| id),
        }),
    })
}

#[derive(Deserialize)]
struct GrantBody {
    access: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn repo_grant(state: &State, request: &mut Request, slug: &str, name: &str, user: &str) -> Route {
    let who = tenant_admin(state, request, true)?;
    let body: GrantBody = parse(&body(request)?)?;
    let mut permissions = Permissions::NONE;
    for access in &body.access {
        let bit = match access.as_str() {
            "read" => Permissions::READ,
            "run" => Permissions::RUN,
            "secrets" => Permissions::WRITE_SECRETS,
            _ => {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    "access entries are read, run or secrets",
                ));
            }
        };
        permissions = permissions.union(bit);
    }
    let (principal, authority, reason) = (who.principal, who.authority(), body.reason.clone());
    let (slug, name, user) = (slug.to_owned(), name.to_owned(), user.to_owned());
    let user = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            authz::require_tenant_admin(tx, principal, tenant).map_err(|e| match e {
                sentinel_store::Error::Forbidden => sentinel_store::Error::NotFound,
                other => other,
            })?;
            let user = authz::resolve_member(tx, tenant, &user)?;
            authz::set_repo_grant_as(tx, authority, repo, user, permissions, reason.as_deref())?;
            Ok(user)
        })
        .map_err(store_error)?;
    ok(json!({ "user": user.to_string(), "access": body.access }))
}

fn tenant_audit(state: &State, request: &Request, slug: &str, query: &str) -> Route {
    let who = tenant_admin(state, request, false)?;
    let before = before(query)?;
    let limit = limit(query);
    let slug = slug.to_owned();
    let records = state
        .store
        .read(|c| {
            let tenant = authz::member_tenant_by_slug(c, who.principal, &slug)?;
            views::operations(c, who.principal, tenant, before, limit)
        })
        .map_err(store_error)?;
    let next = (records.len() == usize::from(limit))
        .then(|| records.last().map(|(seq, _)| *seq))
        .flatten();
    ok(json!({
        "events": records.iter().map(|(seq, r)| {
            let (via, actor) = match r.actor {
                operations::Actor::HostLocal => ("host_local", None),
                operations::Actor::Credential(u) => ("credential", Some(u)),
                operations::Actor::Session(u) => ("session", Some(u)),
                operations::Actor::OAuth(u, _) => ("oauth", Some(u)),
            };
            let target = match r.action {
                operations::Action::CancelRun => {
                    sentinel_core::RunId::from_bytes(r.target).map(|id| id.to_string()).ok()
                }
                _ => sentinel_core::JobId::from_bytes(r.target).map(|id| id.to_string()).ok(),
            };
            json!({
                "seq": seq,
                "at_ms": r.at.0,
                "action": match r.action {
                    operations::Action::CancelRun => "cancel_run",
                    operations::Action::CancelJob => "cancel_job",
                    operations::Action::RerunJob => "rerun_job",
                },
                "target": target,
                "actor": actor.map(|u| u.to_string()),
                "via": via,
                "client": r.client,
            })
        }).collect::<Vec<_>>(),
        "next": next,
    }))
}

pub(super) fn mfa_enrolled(state: &State, user: UserId) -> Result<bool, ApiError> {
    state
        .store
        .read(|c| mfa::enrolled(c, user))
        .map_err(store_error)
}
