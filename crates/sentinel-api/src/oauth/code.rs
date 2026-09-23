//! The authorization-code flow over HTTP (O01): `GET`/`POST
//! /oauth/authorize` (sign-in, consent, approve or deny, `303` back to the
//! client) and the `authorization_code` branch of the token endpoint.
//!
//! Stub: the router and the signatures are the contract; Unit B implements
//! the bodies. Until then the endpoint says so and the grant type is refused.

use sentinel_protocol::oauth::OAuthErrorCode;
use sentinel_store::oauth::Client;

use super::{Form, html};
use crate::{
    State,
    http::Request,
    routes::{Reply, Route},
};

/// `GET` renders sign-in or consent; `POST` records the decision.
pub(crate) fn authorize(state: &State, request: &mut Request, method: &str, query: &str) -> Route {
    let _ = (state, request, method, query);
    Ok(html::error_page(
        404,
        "The authorization endpoint is not available yet.",
    ))
}

/// `grant_type=authorization_code` at the token endpoint. `client` is the
/// looked-up `client_id`; `resource` has already been checked.
pub(crate) fn token(state: &State, client: &Client, form: &Form) -> Reply {
    let _ = (state, client, form);
    super::error(
        OAuthErrorCode::UnsupportedGrantType,
        "the authorization_code grant is not available yet",
    )
}
