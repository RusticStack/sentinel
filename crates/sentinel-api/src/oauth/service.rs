//! Grant and service-account routes (O06): `GET /api/v1/grants`, `DELETE
//! /api/v1/grants/{grt}`, and `/api/v1/tenants/{slug}/service-accounts…`
//! (create, repository access, grant issue and listing). These answer
//! `sentinel.error/1` like the rest of `/api/v1`.
//!
//! Stub: the router and the signatures are the contract; Unit C implements
//! the bodies. Until then the routes do not exist.

use sentinel_protocol::error::ErrorCode;

use crate::{
    State,
    http::Request,
    routes::{Route, err},
};

/// `/api/v1/grants` and below; `rest` is the path after `grants`.
pub(crate) fn grants(state: &State, request: &mut Request, method: &str, rest: &[&str]) -> Route {
    let _ = (state, request, method, rest);
    Err(err(ErrorCode::NotFound, "no such route"))
}

/// `/api/v1/tenants/{slug}/service-accounts` and below; `rest` is the path
/// after `service-accounts`.
pub(crate) fn accounts(
    state: &State,
    request: &mut Request,
    method: &str,
    slug: &str,
    rest: &[&str],
    query: &str,
) -> Route {
    let _ = (state, request, method, slug, rest, query);
    Err(err(ErrorCode::NotFound, "no such route"))
}
