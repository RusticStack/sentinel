pub const MAX_API_BODY_BYTES: usize = 1 << 20;
pub const MAX_PIPELINE_FILE_BYTES: usize = 256 << 10;
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 64 << 10;
pub const MAX_LOG_FRAME_BYTES: usize = 32 << 10;
pub const MAX_UNACKED_LOG_FRAMES: usize = 256;
// The worker times its lease from its own heartbeat send, on a monotonic clock.
// Lowering it breaks older workers, which would act too late.
pub const LEASE_MS: i64 = 30_000;
pub const MAX_PAGE_ITEMS: usize = 500;
pub const DEFAULT_PAGE_ITEMS: usize = 100;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 64;
pub const DEFAULT_DIAGNOSTIC_TEXT_BYTES: usize = 8 << 10;
pub const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 64 << 10;
pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_LIST_ITEMS: usize = 64;
pub const MAX_ARTIFACT_CHUNK_BYTES: usize = 48 << 10;
/// One cache chunk per frame: a chunk carries the running digest of the prefix it extends, which split pieces
/// could not reproduce. The cache crate sizes its serve chunks and the link its frame check from this one value.
pub const MAX_CACHE_CHUNK_BYTES: usize = 48 << 10;
pub const MAX_ARTIFACT_ENTRIES: usize = 4096;
pub const MAX_ARTIFACT_BYTES: u64 = 4 << 30;
pub const MAX_RUN_ARTIFACT_BYTES: u64 = 16 << 30;
pub const MAX_OAUTH_FORM_BYTES: usize = 8 << 10;
pub const MAX_ARTIFACT_NAME_BYTES: usize = 64;
pub const MAX_ARTIFACT_PATH_BYTES: usize = 1024;
/// The text one artifact entry may hand to an MCP client. A longer entry is refused with the bound named rather
/// than cut, because half a report reads as evidence: the entry downloads whole through a short-lived link.
pub const MAX_ARTIFACT_TEXT_BYTES: usize = 1 << 20;
/// Entries in one offer message. A batch holds a path, a 32-byte digest, a length and a mode per entry, which the
/// assert below keeps inside one control frame: the widest entry is MAX_ARTIFACT_PATH_BYTES plus room for the
/// length prefix and the three numbers. A larger artifact is offered in batches, answered once at the last.
pub const MAX_ARTIFACT_OFFER_ENTRIES: usize = 32;

const _: () = {
    assert!(MAX_LOG_FRAME_BYTES < MAX_CONTROL_MESSAGE_BYTES);
    // The 64 bytes cover the postcard envelope (ids and sequence) of an artifact frame.
    assert!(MAX_ARTIFACT_CHUNK_BYTES + 64 <= MAX_CONTROL_MESSAGE_BYTES);
    // A cache chunk frame also holds the attempt id (16), a 32-byte prefix digest, an offset (at most 10) and
    // a length prefix (at most 5); 128 covers them with room for the message tag.
    assert!(MAX_CACHE_CHUNK_BYTES + 128 <= MAX_CONTROL_MESSAGE_BYTES);
    assert!(
        MAX_ARTIFACT_OFFER_ENTRIES * (MAX_ARTIFACT_PATH_BYTES + 40) + 64
            <= MAX_CONTROL_MESSAGE_BYTES
    );
    assert!(MAX_PIPELINE_FILE_BYTES < MAX_API_BODY_BYTES);
    assert!(DEFAULT_DIAGNOSTIC_TEXT_BYTES < MAX_DIAGNOSTIC_TEXT_BYTES);
    assert!(DEFAULT_PAGE_ITEMS <= MAX_PAGE_ITEMS);
};

pub const fn page_size(requested: Option<usize>) -> usize {
    match requested {
        None | Some(0) => DEFAULT_PAGE_ITEMS,
        Some(n) if n > MAX_PAGE_ITEMS => MAX_PAGE_ITEMS,
        Some(n) => n,
    }
}

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
