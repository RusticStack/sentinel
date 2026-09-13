//! Structured API errors. The wire shape is versioned by `schema`; codes are
//! stable strings that clients switch on, HTTP status is derived, and the
//! message is for humans only. Never put payload echoes or secrets in `message`.
use std::fmt;

use serde::{Deserialize, Serialize};

pub const ERROR_SCHEMA: &str = "sentinel.error/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ErrorCode {
    /// Malformed or semantically invalid request.
    InvalidRequest = 0,
    /// Missing or invalid credentials.
    Unauthenticated = 1,
    /// Authenticated but not permitted for this tenant/resource.
    Forbidden = 2,
    /// Also returned for resources owned by other tenants.
    NotFound = 3,
    /// State changed concurrently or a transition is not allowed from the current state.
    Conflict = 4,
    /// Same idempotency key reused with a different request body.
    IdempotencyMismatch = 5,
    /// Body, frame or field exceeds a protocol limit.
    PayloadTooLarge = 6,
    /// Client exceeded its rate or the writer queue is full; retry with back-off.
    RateLimited = 7,
    /// Protocol version or capability set cannot be served.
    UnsupportedVersion = 8,
    /// Cursor is malformed, expired, or belongs to another tenant/stream.
    InvalidCursor = 9,
    /// Unexpected server failure; the request ID identifies the log record.
    Internal = 10,
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
            Self::Internal => 500,
        }
    }

    /// Whether an identical retry can succeed without the client changing anything.
    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Internal)
    }
}

/// One error response. `details` carries machine-readable, non-sensitive
/// context (field names, limits, supported ranges), never user payload.
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

/// Zero-sized marker that serializes as [`ERROR_SCHEMA`] and only
/// deserializes from it, so a newer or foreign error shape is a parse error.
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
        let minimal = serde_json::to_string(&ApiError::new(ErrorCode::Internal, "x")).unwrap();
        assert!(!minimal.contains("request_id"), "absent fields are omitted");
    }
}
