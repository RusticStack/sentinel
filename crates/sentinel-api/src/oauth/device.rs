//! The device authorization flow over HTTP (O03): `POST
//! /oauth/device_authorization`, the device-code branch of the token
//! endpoint with its in-memory `slow_down` limiter, and the `GET`/`POST
//! /device` approval page.
//!
//! Stub: the router and the signatures are the contract; Unit C implements
//! the bodies. Until then every entry point says it is not available.

use sentinel_protocol::oauth::OAuthErrorCode;
use sentinel_store::oauth::Client;

use super::{Form, html};
use crate::{
    State,
    http::Request,
    routes::{Reply, Route},
};

/// `POST /oauth/device_authorization` (RFC 8628 §3.1).
pub(crate) fn authorization(state: &State, request: &mut Request) -> Route {
    let _ = (state, request);
    Ok(super::error(
        OAuthErrorCode::UnauthorizedClient,
        "device authorization is not available yet",
    ))
}

/// `GET`/`POST /device`: enter a user code, then approve or deny.
pub(crate) fn page(state: &State, request: &mut Request, method: &str, query: &str) -> Route {
    let _ = (state, request, method, query);
    Ok(html::error_page(
        404,
        "Device approval is not available yet.",
    ))
}

/// `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
pub(crate) fn token(state: &State, client: &Client, form: &Form) -> Reply {
    let _ = (state, client, form);
    super::error(
        OAuthErrorCode::UnsupportedGrantType,
        "the device_code grant is not available yet",
    )
}
