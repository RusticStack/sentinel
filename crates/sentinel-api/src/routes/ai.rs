//! AI assistance policy (Part 22 Y01): the providers a deployment allows, set by a
//! platform administrator, and the opt-in and data policy a tenant's administrator
//! chooses. No route here reaches a provider: with no tenant opted in there is no
//! request to make, and the gate Y03 calls (`sentinel_store::ai::admit`) reads this
//! policy on every request, so a disable applies at once.

use sentinel_core::UnixMillis;
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{ai, auth as authz};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Route, admin, body, err, ok, parse, store_error};
use crate::{State, http::Request};

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", ["api", "v1", "admin", "ai"]) => deployment_policy(state, request),
        ("PUT", ["api", "v1", "admin", "ai"]) => set_deployment(state, request),
        ("GET", ["api", "v1", "tenants", slug, "ai"]) => tenant_policy(state, request, slug),
        ("PUT", ["api", "v1", "tenants", slug, "ai"]) => set_tenant(state, request, slug),
        _ => return None,
    })
}

fn deployment_json(policy: ai::Deployment) -> Value {
    json!({
        "enabled": policy.enabled,
        "providers": policy.providers.list().map(ai::Provider::as_str).collect::<Vec<_>>(),
    })
}

fn tenant_json(policy: Option<ai::Tenant>, providers: ai::Providers) -> Value {
    json!({
        "enabled": policy.is_some_and(|p| p.enabled),
        "data_policy": policy.map(|p| p.data_policy.as_str()),
        "providers": providers.list().map(ai::Provider::as_str).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBody {
    enabled: bool,
    providers: Vec<String>,
}

fn deployment_policy(state: &State, request: &Request) -> Route {
    admin::platform(state, request, false)?;
    let policy = state.store.read(ai::deployment).map_err(store_error)?;
    ok(deployment_json(policy))
}

fn set_deployment(state: &State, request: &mut Request) -> Route {
    let who = admin::platform(state, request, true)?;
    let body: DeploymentBody = parse(&body(request)?)?;
    let mut providers = ai::Providers::NONE;
    for name in &body.providers {
        let provider = ai::Provider::parse(name).ok_or_else(|| unknown_provider(name))?;
        providers.insert(provider);
    }
    if body.enabled && providers.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "enabling AI needs at least one provider",
        ));
    }
    let policy = ai::Deployment {
        enabled: body.enabled,
        providers,
    };
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| ai::set_deployment(tx, authority, policy, UnixMillis::now()))
        .map_err(store_error)?;
    ok(deployment_json(policy))
}

fn unknown_provider(name: &str) -> ApiError {
    err(ErrorCode::InvalidRequest, "unknown provider").with_detail("provider", name)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantBody {
    enabled: bool,
    data_policy: String,
}

fn tenant_policy(state: &State, request: &Request, slug: &str) -> Route {
    let who = admin::tenant_admin(state, request, false)?;
    let principal = who.principal;
    let slug = slug.to_owned();
    let (policy, providers) = state
        .store
        .read(move |c| {
            let tenant = authz::member_tenant_by_slug(c, principal, &slug)?;
            authz::require_tenant_admin(c, principal, tenant)?;
            Ok((ai::tenant(c, tenant)?, ai::effective(c, tenant)?.0))
        })
        .map_err(store_error)?;
    ok(tenant_json(policy, providers))
}

fn set_tenant(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = admin::tenant_admin(state, request, true)?;
    let body: TenantBody = parse(&body(request)?)?;
    let data_policy = ai::DataPolicy::parse(&body.data_policy).ok_or_else(|| {
        err(
            ErrorCode::InvalidRequest,
            "data_policy must be local_only, zero_retention or provider_terms",
        )
        .with_detail("data_policy", body.data_policy.as_str())
    })?;
    let policy = ai::Tenant {
        enabled: body.enabled,
        data_policy,
    };
    let (principal, authority) = (who.principal, who.authority());
    let slug = slug.to_owned();
    let providers = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            ai::set_tenant(tx, authority, tenant, policy, UnixMillis::now())?;
            Ok(ai::effective(tx, tenant)?.0)
        })
        .map_err(store_error)?;
    ok(tenant_json(Some(policy), providers))
}
