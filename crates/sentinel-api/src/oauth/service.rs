use sentinel_auth::oauth::{self as forms, Kind};
use sentinel_core::{
    GrantId, UnixMillis, UserId,
    auth::{Permissions, Role, Scopes},
};
use sentinel_protocol::error::ErrorCode;
use sentinel_store::{
    auth as authz,
    auth::Authority,
    lookup,
    oauth::{self as grants, GrantRecord, SERVICE_DEFAULT_MS, service},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    State,
    auth::{Identity, Via, require_scope},
    http::Request,
    routes::{Reply, Route, body, err, id, identify, ok, parse, store_error},
};

pub(crate) fn grants(state: &State, request: &mut Request, method: &str, rest: &[&str]) -> Route {
    match (method, rest) {
        ("GET", []) => {
            let who = identify(state, request, false)?;
            let records = match who.grant {
                _ if manages_grants(&who) => state.store.read(|c| {
                    grants::grants(c, Authority::credential(who.principal), who.user, 100)
                }),
                Some(own) => state
                    .store
                    .read(|c| grants::own_grant(c, who.user, own).map(|g| vec![g])),
                None => {
                    require_scope(&who, Scopes::TENANT_ADMIN)?;
                    return Err(err(ErrorCode::Forbidden, "not permitted"));
                }
            }
            .map_err(store_error)?;
            ok(json!({ "grants": records.iter().map(grant_json).collect::<Vec<_>>() }))
        }
        ("DELETE", [grant]) => {
            let who = identify(state, request, true)?;
            let grant: GrantId = id(grant, "grant")?;
            if !manages_grants(&who) && who.grant != Some(grant) {
                require_scope(&who, Scopes::TENANT_ADMIN)?;
            }
            let authority = Authority::credential(who.principal);
            state
                .store
                .writer()
                .write(move |tx| grants::revoke_grant(tx, authority, grant, UnixMillis::now()))
                .map_err(store_error)?;
            ok(json!({ "grant": grant.to_string(), "revoked": true }))
        }
        _ => Err(err(ErrorCode::NotFound, "no such route")),
    }
}

fn manages_grants(who: &Identity) -> bool {
    who.via == Via::Session || who.scopes.contains(Scopes::TENANT_ADMIN)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAccount {
    name: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoAccess {
    access: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewServiceGrant {
    name: String,
    scope: String,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    expires_in_ms: Option<i64>,
    #[serde(default)]
    reason: Option<String>,
}

// Credential-minting routes need a recently stepped-up browser session: a bearer or OAuth token
// can never do it, so a stolen token cannot mint a longer-lived one.
pub(crate) fn accounts(
    state: &State,
    request: &mut Request,
    method: &str,
    slug: &str,
    rest: &[&str],
    _query: &str,
) -> Route {
    match (method, rest) {
        ("POST", []) => create(state, request, slug),
        ("PUT", [account, "repos", repo]) => allow(state, request, slug, account, repo),
        ("POST", [account, "grants"]) => issue(state, request, slug, account),
        ("GET", [account, "grants"]) => list(state, request, slug, account),
        _ => Err(err(ErrorCode::NotFound, "no such route")),
    }
}

fn created(value: Value) -> Route {
    Ok(Reply::Json(201, value, Vec::new()))
}

fn create(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = identify(state, request, true)?;
    require_scope(&who, Scopes::TENANT_ADMIN)?;
    let spec: NewAccount = parse(&body(request)?)?;
    let role = match spec.role.as_deref() {
        None | Some("operator") => Role::Operator,
        Some("reader") => Role::Reader,
        Some(_) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "role must be reader or operator",
            ));
        }
    };
    let (slug, principal, user) = (slug.to_owned(), who.principal, UserId::new());
    let authority = who.authority();
    let (name, reason) = (spec.name, spec.reason);
    let echoed = name.clone();
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            authz::create_service_account(
                tx,
                authority,
                tenant,
                user,
                &name,
                role,
                reason.as_deref(),
                UnixMillis::now(),
            )
        })
        .map_err(store_error)?;
    created(json!({
        "user": user.to_string(),
        "name": echoed,
        "role": match role { Role::Reader => "reader", _ => "operator" },
    }))
}

fn allow(state: &State, request: &mut Request, slug: &str, account: &str, repo: &str) -> Route {
    let who = identify(state, request, true)?;
    require_scope(&who, Scopes::TENANT_ADMIN)?;
    let account: UserId = id(account, "user")?;
    let spec: RepoAccess = parse(&body(request)?)?;
    let mut permissions = Permissions::NONE;
    for access in &spec.access {
        permissions = permissions.union(match access.as_str() {
            "read" => Permissions::READ,
            "run" => Permissions::RUN,
            _ => {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    "access entries are read or run",
                ));
            }
        });
    }
    let (slug, name, principal) = (slug.to_owned(), repo.to_owned(), who.principal);
    let (authority, reason) = (who.authority(), spec.reason);
    state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            service::allow_repo(
                tx,
                authority,
                tenant,
                account,
                repo,
                permissions,
                reason.as_deref(),
            )
        })
        .map_err(store_error)?;
    let access: Vec<&str> = [(Permissions::READ, "read"), (Permissions::RUN, "run")]
        .into_iter()
        .filter(|(bit, _)| permissions.contains(*bit))
        .map(|(_, name)| name)
        .collect();
    ok(json!({ "user": account.to_string(), "repo": repo, "access": access }))
}

fn issue(state: &State, request: &mut Request, slug: &str, account: &str) -> Route {
    let who = identify(state, request, true)?;
    require_scope(&who, Scopes::TENANT_ADMIN)?;
    let account: UserId = id(account, "user")?;
    let spec: NewServiceGrant = parse(&body(request)?)?;
    let scopes =
        Scopes::parse(&spec.scope).map_err(|_| err(ErrorCode::InvalidRequest, "unknown scope"))?;
    let lifetime = spec.expires_in_ms.unwrap_or(SERVICE_DEFAULT_MS);
    let (slug, principal, name, repo) = (slug.to_owned(), who.principal, spec.name, spec.repo);
    let (authority, reason) = (who.authority(), spec.reason);
    let now = UnixMillis::now();
    let (grant, refresh, expires) = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = repo
                .map(|name| lookup::repo_by_name(tx, tenant, &name))
                .transpose()?;
            service::issue_service_grant(
                tx,
                authority,
                tenant,
                account,
                &name,
                scopes,
                repo,
                lifetime,
                reason.as_deref(),
                now,
            )
        })
        .map_err(store_error)?;
    created(json!({
        "grant": grant.to_string(),
        "refresh_token": forms::format(Kind::Refresh, &refresh),
        "expires_ms": expires.0,
        "scope": scopes.to_names(),
    }))
}

fn list(state: &State, request: &mut Request, slug: &str, account: &str) -> Route {
    let who = identify(state, request, false)?;
    require_scope(&who, Scopes::TENANT_ADMIN)?;
    let account: UserId = id(account, "user")?;
    let records = state
        .store
        .read(|c| {
            let tenant = authz::member_tenant_by_slug(c, who.principal, slug)?;
            service::service_grants(c, who.principal, tenant, account)
        })
        .map_err(store_error)?;
    ok(json!({ "grants": records.iter().map(grant_json).collect::<Vec<_>>() }))
}

// Metadata only: never a token or a digest.
fn grant_json(g: &GrantRecord) -> Value {
    json!({
        "id": g.id.to_string(),
        "user": g.user.to_string(),
        "client_id": g.client_id,
        "kind": g.kind.as_str(),
        "scope": g.scopes.to_names(),
        "tenant": g.tenant.map(|t| t.to_string()),
        "repo": g.repo.map(|r| r.to_string()),
        "name": g.name,
        "created_ms": g.created.0,
        "expires_ms": g.expires.0,
        "last_used_ms": g.last_used.map(|t| t.0),
        "revoked": g.revoked,
    })
}
