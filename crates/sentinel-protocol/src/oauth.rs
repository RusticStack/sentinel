//! The OAuth 2.0 wire contract (O01–O03): endpoint paths, the CLI client,
//! authorization-server and protected-resource metadata (RFC 8414, RFC
//! 9728), token and device-authorization responses, and the RFC 6749 error
//! shape the `/oauth/*` endpoints answer with. `/api/v1/*` keeps
//! `sentinel.error/1`.
//!
//! Token-bearing types redact their secrets in `Debug`.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource/api/v1";
pub const MCP_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const TOKEN_PATH: &str = "/oauth/token";
pub const REVOKE_PATH: &str = "/oauth/revoke";
pub const DEVICE_AUTHORIZATION_PATH: &str = "/oauth/device_authorization";
pub const DEVICE_VERIFICATION_PATH: &str = "/device";
pub const REGISTRATION_PATH: &str = "/oauth/register";
/// Appended to the issuer to name the API resource (`Audience::Api`).
pub const API_RESOURCE_SUFFIX: &str = "/api/v1";
/// Appended to the issuer to name the remote MCP resource (`Audience::Mcp`).
pub const MCP_RESOURCE_SUFFIX: &str = "/mcp";

/// The first-party public client every deployment seeds.
pub const CLI_CLIENT_ID: &str = "sentinel-cli";
/// The only path a loopback redirect of the CLI client may use.
pub const CLI_REDIRECT_PATH: &str = "/callback";

pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Authorization-server metadata (RFC 8414).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub client_id_metadata_document_supported: bool,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
}

impl Metadata {
    /// The metadata this deployment publishes under `issuer`.
    pub fn for_issuer(issuer: &str, scopes: &[&str]) -> Self {
        let owned = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect();
        Self {
            issuer: issuer.to_owned(),
            authorization_endpoint: format!("{issuer}{AUTHORIZE_PATH}"),
            token_endpoint: format!("{issuer}{TOKEN_PATH}"),
            revocation_endpoint: format!("{issuer}{REVOKE_PATH}"),
            device_authorization_endpoint: format!("{issuer}{DEVICE_AUTHORIZATION_PATH}"),
            registration_endpoint: format!("{issuer}{REGISTRATION_PATH}"),
            client_id_metadata_document_supported: true,
            response_types_supported: owned(&["code"]),
            response_modes_supported: owned(&["query"]),
            grant_types_supported: owned(&[
                GRANT_AUTHORIZATION_CODE,
                GRANT_REFRESH_TOKEN,
                GRANT_DEVICE_CODE,
            ]),
            code_challenge_methods_supported: owned(&["S256"]),
            token_endpoint_auth_methods_supported: owned(&["none"]),
            revocation_endpoint_auth_methods_supported: owned(&["none"]),
            scopes_supported: owned(scopes),
            authorization_response_iss_parameter_supported: true,
        }
    }
}

/// Protected-resource metadata for `/api/v1` (RFC 9728).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResource {
    pub fn for_issuer(issuer: &str, scopes: &[&str]) -> Self {
        Self::for_resource(&format!("{issuer}{API_RESOURCE_SUFFIX}"), issuer, scopes)
    }

    /// Metadata for one resource served by this deployment.
    pub fn for_resource(resource: &str, issuer: &str, scopes: &[&str]) -> Self {
        Self {
            resource: resource.to_owned(),
            authorization_servers: vec![issuer.to_owned()],
            scopes_supported: scopes.iter().map(|s| (*s).to_owned()).collect(),
            bearer_methods_supported: vec!["header".to_owned()],
        }
    }
}

/// A successful token-endpoint answer. `sentinel_grant` names the grant so a
/// client can show and revoke it; `sentinel_refresh_expires_in` is the
/// refresh token's remaining life in seconds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
    pub sentinel_grant: String,
    pub sentinel_refresh_expires_in: u64,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"redacted")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &"redacted")
            .field("scope", &self.scope)
            .field("sentinel_grant", &self.sentinel_grant)
            .field(
                "sentinel_refresh_expires_in",
                &self.sentinel_refresh_expires_in,
            )
            .finish()
    }
}

/// The device-authorization answer (RFC 8628 §3.2). `user_code` is the
/// display form `XXXX-XXXX`; the device code is for the polling client only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"redacted")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// RFC 6749 §5.2 / RFC 7009 / RFC 8628 error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidClientMetadata,
    InvalidRedirectUri,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    InvalidTarget,
    AccessDenied,
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    ServerError,
    TemporarilyUnavailable,
}

impl OAuthErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::AccessDenied => "access_denied",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidClient => 401,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

/// `{"error": "...", "error_description": "..."}`. The description is for
/// humans and never echoes a submitted value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthError {
    pub error: OAuthErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl OAuthError {
    pub fn new(error: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: Some(description.into()),
        }
    }

    pub const fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error.as_str())?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}
impl std::error::Error for OAuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_names_every_endpoint_under_the_issuer() {
        let meta = Metadata::for_issuer("https://ci.example", &["runs:read"]);
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["issuer"], "https://ci.example");
        assert_eq!(json["token_endpoint"], "https://ci.example/oauth/token");
        assert_eq!(
            json["device_authorization_endpoint"],
            "https://ci.example/oauth/device_authorization"
        );
        assert_eq!(json["code_challenge_methods_supported"][0], "S256");
        assert_eq!(json["grant_types_supported"][2], GRANT_DEVICE_CODE);
        assert_eq!(json["authorization_response_iss_parameter_supported"], true);
        let resource = ProtectedResource::for_issuer("https://ci.example", &["runs:read"]);
        assert_eq!(resource.resource, "https://ci.example/api/v1");
        assert_eq!(resource.authorization_servers, ["https://ci.example"]);
    }

    #[test]
    fn errors_have_the_rfc_shape_and_status() {
        let e = OAuthError::new(OAuthErrorCode::InvalidGrant, "refresh token is not valid");
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"error":"invalid_grant","error_description":"refresh token is not valid"}"#
        );
        assert_eq!(e.http_status(), 400);
        assert_eq!(OAuthErrorCode::InvalidClient.http_status(), 401);
        assert_eq!(OAuthErrorCode::ServerError.http_status(), 500);
        assert_eq!(OAuthErrorCode::TemporarilyUnavailable.http_status(), 503);
        assert_eq!(OAuthErrorCode::SlowDown.as_str(), "slow_down");
        let bare: OAuthError = serde_json::from_str(r#"{"error":"slow_down"}"#).unwrap();
        assert_eq!(bare.error, OAuthErrorCode::SlowDown);
    }

    #[test]
    fn token_bearing_types_redact_their_secrets() {
        let response = TokenResponse {
            access_token: "sntl_at_secret".into(),
            token_type: "Bearer".into(),
            expires_in: 600,
            refresh_token: "sntl_rt_secret".into(),
            scope: "runs:read".into(),
            sentinel_grant: "grt_x".into(),
            sentinel_refresh_expires_in: 1,
        };
        assert!(!format!("{response:?}").contains("secret"));
        let device = DeviceAuthorization {
            device_code: "sntl_dc_secret".into(),
            user_code: "BCDF-GHJK".into(),
            verification_uri: "https://ci.example/device".into(),
            verification_uri_complete: "https://ci.example/device?user_code=BCDFGHJK".into(),
            expires_in: 600,
            interval: 5,
        };
        assert!(!format!("{device:?}").contains("secret"));
    }
}
