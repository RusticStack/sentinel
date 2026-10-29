//! Never put payload echoes or secrets in `message`.
use std::fmt;

use serde::{Deserialize, Serialize};

pub const ERROR_SCHEMA: &str = "sentinel.error/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ErrorCode {
    InvalidRequest = 0,
    Unauthenticated = 1,
    Forbidden = 2,
    /// Also returned for other tenants' resources, so their existence is not leaked.
    NotFound = 3,
    Conflict = 4,
    IdempotencyMismatch = 5,
    PayloadTooLarge = 6,
    RateLimited = 7,
    UnsupportedVersion = 8,
    InvalidCursor = 9,
    Internal = 10,
    StorageFull = 11,
    QuotaExceeded = 12,
    /// Not retryable as is: repeating an unkeyed mutation can apply it twice.
    OutcomeUnknown = 13,
    /// A third party (GitHub) refused or failed the call; its body is never echoed.
    UpstreamFailed = 14,
    #[serde(other)]
    Unknown = 255,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::IdempotencyMismatch => "idempotency_mismatch",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidCursor => "invalid_cursor",
            Self::Internal => "internal",
            Self::StorageFull => "storage_full",
            Self::QuotaExceeded => "quota_exceeded",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::UpstreamFailed => "upstream_failed",
            Self::Unknown => "unknown",
        }
    }

    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::InvalidCursor => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PayloadTooLarge => 413,
            Self::IdempotencyMismatch => 422,
            Self::RateLimited => 429,
            Self::UnsupportedVersion => 426,
            Self::Internal | Self::Unknown => 500,
            Self::StorageFull => 507,
            Self::QuotaExceeded => 403,
            Self::OutcomeUnknown => 503,
            Self::UpstreamFailed => 502,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Internal | Self::StorageFull)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub schema: ErrorSchema,
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ErrorSchema;

impl Serialize for ErrorSchema {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(ERROR_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for ErrorSchema {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: std::borrow::Cow<'de, str> = Deserialize::deserialize(d)?;
        if s == ERROR_SCHEMA {
            Ok(ErrorSchema)
        } else {
            Err(serde::de::Error::custom("unsupported error schema"))
        }
    }
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema: ErrorSchema,
            code,
            message: message.into(),
            retryable: code.retryable(),
            request_id: None,
            details: None,
        }
    }

    #[must_use]
    pub fn with_request_id(mut self, id: impl fmt::Display) -> Self {
        self.request_id = Some(id.to_string());
        self
    }

    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.details
            .get_or_insert_with(serde_json::Map::new)
            .insert(key.to_owned(), value.into());
        self
    }

    pub const fn http_status(&self) -> u16 {
        self.code.http_status()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}
impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shape_is_stable() {
        let e = ApiError::new(ErrorCode::PayloadTooLarge, "body exceeds limit")
            .with_request_id("req_1")
            .with_detail("limit_bytes", 1_048_576u64);
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"sentinel.error/1","code":"payload_too_large","message":"body exceeds limit","retryable":false,"request_id":"req_1","details":{"limit_bytes":1048576}}"#
        );
        let back: ApiError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.http_status(), 413);
        let foreign = json.replace("sentinel.error/1", "sentinel.error/2");
        assert!(serde_json::from_str::<ApiError>(&foreign).is_err());
    }

    #[test]
    fn codes_map_to_status_and_retry_policy() {
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::UnsupportedVersion.http_status(), 426);
        assert!(ErrorCode::RateLimited.retryable());
        assert!(!ErrorCode::Conflict.retryable());
        assert_eq!(ErrorCode::StorageFull.http_status(), 507);
        assert!(ErrorCode::StorageFull.retryable());
        assert_eq!(ErrorCode::QuotaExceeded.http_status(), 403);
        assert!(!ErrorCode::QuotaExceeded.retryable());
        let minimal = serde_json::to_string(&ApiError::new(ErrorCode::Internal, "x")).unwrap();
        assert!(!minimal.contains("request_id"), "absent fields are omitted");
    }

    #[test]
    fn an_ambiguous_write_is_unavailable_and_never_blindly_retryable() {
        assert_eq!(ErrorCode::OutcomeUnknown.http_status(), 503);
        assert!(!ErrorCode::OutcomeUnknown.retryable());
        let json = serde_json::to_string(&ApiError::new(ErrorCode::OutcomeUnknown, "x")).unwrap();
        assert!(json.contains(r#""code":"outcome_unknown","message":"x","retryable":false"#));
    }

    #[test]
    fn an_upstream_failure_is_a_bad_gateway_and_not_retryable_as_is() {
        assert_eq!(ErrorCode::UpstreamFailed.http_status(), 502);
        assert!(!ErrorCode::UpstreamFailed.retryable());
        let json = serde_json::to_string(&ApiError::new(ErrorCode::UpstreamFailed, "x")).unwrap();
        assert!(json.contains(r#""code":"upstream_failed","message":"x","retryable":false"#));
    }

    #[test]
    fn an_unknown_code_from_a_newer_server_still_parses() {
        let json = r#"{"schema":"sentinel.error/1","code":"brand_new_code","message":"m","retryable":true}"#;
        let e: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(e.code, ErrorCode::Unknown);
        assert!(e.retryable, "the wire's retryable flag is kept");
        assert!(!ErrorCode::Unknown.retryable());
    }
}
