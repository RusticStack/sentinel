//! Protocol size limits. Every bound is enforced before parsing: a request
//! that exceeds one is rejected with `payload_too_large` without reading
//! the rest. Values are deliberately small; raise one only with a measured
//! need and a note in `docs/protocol.md`.

/// JSON API request body (dispatch, cancel, secrets, pipeline validation).
pub const MAX_API_BODY_BYTES: usize = 1 << 20; // 1 MiB
/// GitHub webhook body before signature verification.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 25 << 20; // GitHub's own cap is 25 MB
/// A single `.sentinel.yml` file as read from the repository.
pub const MAX_PIPELINE_FILE_BYTES: usize = 256 << 10;
/// One worker-session control message (offers, acks, heartbeats, transitions).
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 64 << 10;
/// One log frame payload; larger output is split, never dropped.
pub const MAX_LOG_FRAME_BYTES: usize = 32 << 10;
/// Log frames a worker may send before an acknowledgement.
pub const MAX_UNACKED_LOG_FRAMES: usize = 256;
/// Items returned by any list endpoint; the default page is smaller.
pub const MAX_PAGE_ITEMS: usize = 500;
pub const DEFAULT_PAGE_ITEMS: usize = 100;
/// `Idempotency-Key` header value.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 64;
/// Diagnostic text budget for agent-facing responses (default and hard ceiling).
pub const DEFAULT_DIAGNOSTIC_TEXT_BYTES: usize = 8 << 10;
pub const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 64 << 10;
/// Human-facing names (job, step, pipeline, repo) and free-text labels.
pub const MAX_NAME_BYTES: usize = 128;
/// Capability strings, worker labels and similar enumerations per message.
pub const MAX_LIST_ITEMS: usize = 64;

// Invariants between limits, checked at compile time.
const _: () = {
    assert!(MAX_LOG_FRAME_BYTES < MAX_CONTROL_MESSAGE_BYTES);
    assert!(MAX_PIPELINE_FILE_BYTES < MAX_API_BODY_BYTES);
    assert!(DEFAULT_DIAGNOSTIC_TEXT_BYTES < MAX_DIAGNOSTIC_TEXT_BYTES);
    assert!(DEFAULT_PAGE_ITEMS <= MAX_PAGE_ITEMS);
};

/// Clamp a requested page size to the allowed range; `None` means default.
pub const fn page_size(requested: Option<usize>) -> usize {
    match requested {
        None | Some(0) => DEFAULT_PAGE_ITEMS,
        Some(n) if n > MAX_PAGE_ITEMS => MAX_PAGE_ITEMS,
        Some(n) => n,
    }
}

/// Check a declared length against a limit before reading a body.
pub const fn within(declared: usize, limit: usize) -> Result<(), usize> {
    if declared <= limit {
        Ok(())
    } else {
        Err(limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_clamps() {
        assert_eq!(page_size(None), DEFAULT_PAGE_ITEMS);
        assert_eq!(page_size(Some(0)), DEFAULT_PAGE_ITEMS);
        assert_eq!(page_size(Some(7)), 7);
        assert_eq!(page_size(Some(10_000)), MAX_PAGE_ITEMS);
    }

    #[test]
    fn within_checks_declared_length() {
        assert_eq!(within(MAX_API_BODY_BYTES, MAX_API_BODY_BYTES), Ok(()));
        assert_eq!(
            within(MAX_API_BODY_BYTES + 1, MAX_API_BODY_BYTES),
            Err(MAX_API_BODY_BYTES)
        );
    }
}
