//! Shared protocol contracts for the HTTP API, CLI/MCP clients and worker
//! sessions: versioned structured errors, mutation idempotency, resumable
//! event cursors, size limits, and worker capability negotiation. Pure
//! types and functions; transports plug in above this crate.

pub mod cursor;
pub mod error;
pub mod idempotency;
pub mod limits;
pub mod logs;
pub mod negotiate;
pub mod summary;

pub use cursor::{Cursor, CursorError, Page, Seq, StreamKind};
pub use error::{ApiError, ERROR_SCHEMA, ErrorCode, ErrorSchema};
pub use idempotency::{Decision, Fingerprint, IdempotencyKey, KeyError, Stored};
pub use negotiate::{
    Arch, Capabilities, Hello, Negotiated, ProtocolVersion, Rejected, SUPPORTED_MAX, SUPPORTED_MIN,
    negotiate,
};

impl From<CursorError> for ApiError {
    fn from(e: CursorError) -> Self {
        // Wrong tenant is reported as malformed: never confirm another tenant's cursor exists.
        let _ = e;
        ApiError::new(
            ErrorCode::InvalidCursor,
            "cursor is invalid for this stream",
        )
    }
}

impl From<KeyError> for ApiError {
    fn from(e: KeyError) -> Self {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "Idempotency-Key must be 1 to 64 printable ASCII bytes without spaces",
        )
        .with_detail(
            "reason",
            match e {
                KeyError::Empty => "empty",
                KeyError::TooLong => "too_long",
                KeyError::InvalidByte => "invalid_byte",
            },
        )
    }
}

impl From<Rejected> for ApiError {
    fn from(r: Rejected) -> Self {
        let base = ApiError::new(ErrorCode::UnsupportedVersion, "worker session rejected");
        match r {
            Rejected::UnsupportedVersion {
                supported_min,
                supported_max,
                upgrade_worker,
            } => base
                .with_detail("supported_min", supported_min.0)
                .with_detail("supported_max", supported_max.0)
                .with_detail("upgrade_worker", upgrade_worker),
            Rejected::MissingCapabilities { missing } => base.with_detail("missing", missing.0),
            Rejected::InvalidRange => ApiError::new(
                ErrorCode::InvalidRequest,
                "protocol_min must not exceed protocol_max",
            ),
        }
    }
}
