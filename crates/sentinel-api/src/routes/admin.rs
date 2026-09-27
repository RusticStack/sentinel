//! Administration over the API (U05): the platform's registrations,
//! tenants, quotas, pools, policy and audit (`platform:admin`), a tenant's
//! members, repositories and run control audit (`tenant:admin`), and the
//! session step-up that privileged platform changes require (A06).
//!
//! Every mutation goes through the same store functions the host-local
//! `sentinel admin` commands use, with the caller's own authority instead
//! of the host's: platform rows are checked live, a privileged change needs
//! a session stepped up within the policy window, and nothing ever returns
//! a stored secret.

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
    sources, tenancy, views,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Reply, Route, body, err, id, identify, ok, parse, query_param, store_error};
use crate::{State, auth, auth::Identity, http::Request};

/// A platform administrator: the scope, then the live platform rows (not
/// the credential's claims), so a revoked super admin is refused at once.
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

/// Route one request under `/api/v1/admin/…`, `/api/v1/step-up` or the
/// tenant administration paths; `None` when the path is not one of them.
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
    /// `totp`, `recovery` or `password` (the last only without TOTP).
    method: String,
    code: String,
}

/// `POST /api/v1/step-up {method, code}`: a browser session proves presence
/// again (A06) — a TOTP code, an unused recovery code, or the password for
/// an account without TOTP — and is stamped for the policy's window. Only a
/// session can step up; a wrong proof is one `forbidden` whatever was wrong,
/// and the store counts failures against the session and the factor.
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
                // The effective quota: the tenant's own row or the default.
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
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}

#[derive(Deserialize)]
struct CreateTenant {
    slug: String,
}

/// `POST /admin/tenants {slug}`: a new organization tenant (audited). It has
/// no members yet; a platform administrator adds its first admin through
/// the members route.
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
            // The slug is unique: an existing tenant is a conflict, not a fault.
            sentinel_store::Error::Sqlite(_) => err(ErrorCode::Conflict, "slug already taken"),
            e => store_error(e),
        })?;
    Ok(Reply::Json(
        201,
        json!({ "id": tenant.to_string(), "slug": body.slug }),
        Vec::new(),
    ))
}

/// Suspend or reactivate a tenant: privileged (a fresh step-up), audited,
/// and a suspension revokes the tenant's credentials and invitations and
/// cancels its jobs in the same transaction.
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

/// `PUT /admin/tenants/{slug}/quota {bytes}` sets the tenant's storage quota;
/// `DELETE` returns it to the deployment default.
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

/// Approve or reject a pending application. Rejecting an account that was
/// already approved is privileged (it ends a live account) and needs a
/// fresh step-up; the store decides which case applies.
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

/// `PUT /admin/policy`: the deployment's admission policy. Privileged.
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
    /// `shared` or `dedicated`.
    kind: String,
    /// The owning tenant's slug for a dedicated pool.
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
        })).collect::<Vec<_>>(),
        "next": next,
    }))
}

#[derive(Deserialize)]
struct MemberBody {
    role: String,
}

/// `PUT /tenants/{slug}/members/{user} {role}` adds or changes a member;
/// `DELETE` removes one (revoking credentials narrowed to the tenant). The
/// user is a `usr_…` id or a local sign-in name. Taking the admin role from
/// the tenant's last administrator is `conflict`.
fn set_member(state: &State, request: &mut Request, slug: &str, user: &str, put: bool) -> Route {
    let who = tenant_admin(state, request, true)?;
    let role = if put {
        let body: MemberBody = parse(&body(request)?)?;
        Some(parse_role(&body.role)?)
    } else {
        None
    };
    let (slug, user) = (slug.to_owned(), user.to_owned());
    let principal = who.principal;
    let member = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let user = views::resolve_user(tx, &user)?;
            match role {
                Some(role) => authz::set_membership(tx, principal, tenant, user, role)?,
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

/// `POST /tenants/{slug}/repos {name}`: a repository record under the
/// tenant (tenant admin). Its source binding and hook secrets are set
/// host-locally, where their credentials never cross the API.
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

/// `GET /tenants/{slug}/repos/{name}/source`: the repository's source
/// binding as metadata — remote, allowed refs, pipeline path, whether trust
/// roots are pinned, version, revocation, forge association. The binding
/// holds no credential; credentials are sealed elsewhere and never read.
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
                // An authorized repository without a binding yet.
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
    /// Any of `read`, `run`, `secrets`; empty withdraws the grant.
    access: Vec<String>,
}

/// `PUT /tenants/{slug}/repos/{name}/grants/{user} {access}`: a member's
/// repository access. Membership stays the ceiling: a reader granted `run`
/// still cannot run.
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
    let principal = who.principal;
    let (slug, name, user) = (slug.to_owned(), name.to_owned(), user.to_owned());
    let user = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            let user = views::resolve_user(tx, &user)?;
            authz::set_repo_grant(tx, principal, repo, user, permissions)?;
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

/// Whether the caller's account has TOTP: what the step-up dialog asks for.
pub(super) fn mfa_enrolled(state: &State, user: UserId) -> Result<bool, ApiError> {
    state
        .store
        .read(|c| mfa::enrolled(c, user))
        .map_err(store_error)
}
