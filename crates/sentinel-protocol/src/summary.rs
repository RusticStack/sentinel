//! Durations are monotonic nanoseconds on the worker; absent means not measured, never zero.

use serde::{Deserialize, Serialize};

pub const SUMMARY_FORMAT: u8 = 4;
// Old formats stay decodable forever: keep their shadow structs when the format changes.
const SUMMARY_FORMAT_V1: u8 = 1;
const SUMMARY_FORMAT_V2: u8 = 2;
const SUMMARY_FORMAT_V3: u8 = 3;
pub const MAX_SUMMARY_BYTES: usize = 32 * 1024;
// Must fit one control frame; receivers drop a summary the store column cannot hold, never fail the job.
const _: () = assert!(MAX_SUMMARY_BYTES < crate::limits::MAX_CONTROL_MESSAGE_BYTES);
pub const MAX_STEP_RECORDS: usize = 256;
pub const MAX_CACHE_RECORDS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    Passed,
    Skipped,
    Failed { code: i32 },
    Signaled { signal: i32 },
    OutOfMemory,
    TimedOut,
    Runtime,
    NotRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub index: u32,
    pub id: String,
    pub outcome: StepOutcome,
    pub duration_ns: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckoutRoute {
    Direct,
    Mirror,
    MirrorFallback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRecord {
    pub name: String,
    pub class: u8,
    pub outcome: String,
    pub lookup_ns: Option<u64>,
    pub lock_wait_ns: Option<u64>,
    pub clone_ns: Option<u64>,
    pub first_touch_ns: Option<u64>,
    pub files: u64,
    pub bytes: u64,
    pub copied_bytes: u64,
    pub reflink: bool,
    pub commit_ns: Option<u64>,
    pub staged_bytes: Option<u64>,
    pub reused_bytes: Option<u64>,
    pub dirty_bytes: Option<u64>,
    pub publish: Option<String>,
    pub costly_hit: bool,
}

/// The guest image a microVM attempt ran: the digest its root file system was built from and checked against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestImageRecord {
    /// The pinned `sha256:` digest, the one the controller offered the job.
    pub digest: String,
    /// Apparent size of the read-only root file system, in bytes.
    pub rootfs_bytes: u64,
    /// Whether this attempt built the root file system; false when a cached one was reused.
    pub built: bool,
    /// Monotonic time spent building it; absent when it was reused.
    pub build_ns: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSummary {
    pub checkout_ns: Option<u64>,
    pub checkout_fetch_ns: Option<u64>,
    pub checkout_materialize_ns: Option<u64>,
    pub checkout_route: Option<CheckoutRoute>,
    pub image_pull_ns: Option<u64>,
    pub image_present: Option<bool>,
    pub container_start_ns: Option<u64>,
    pub steps_ns: Option<u64>,
    pub finalize_ns: Option<u64>,
    pub steps: Vec<StepRecord>,
    pub caches: Vec<CacheRecord>,
    /// Present for microVM attempts only (format 4).
    pub guest_image: Option<GuestImageRecord>,
    pub detail: String,
}

#[derive(Deserialize, Serialize)]
struct AttemptSummaryV3 {
    checkout_ns: Option<u64>,
    checkout_fetch_ns: Option<u64>,
    checkout_materialize_ns: Option<u64>,
    checkout_route: Option<CheckoutRoute>,
    image_pull_ns: Option<u64>,
    image_present: Option<bool>,
    container_start_ns: Option<u64>,
    steps_ns: Option<u64>,
    finalize_ns: Option<u64>,
    steps: Vec<StepRecord>,
    caches: Vec<CacheRecord>,
    detail: String,
}

#[derive(Deserialize, Serialize)]
struct AttemptSummaryV1 {
    checkout_ns: Option<u64>,
    image_pull_ns: Option<u64>,
    container_start_ns: Option<u64>,
    steps_ns: Option<u64>,
    finalize_ns: Option<u64>,
    steps: Vec<StepRecord>,
    detail: String,
}

#[derive(Deserialize, Serialize)]
struct AttemptSummaryV2 {
    checkout_ns: Option<u64>,
    checkout_fetch_ns: Option<u64>,
    checkout_materialize_ns: Option<u64>,
    checkout_route: Option<CheckoutRoute>,
    image_pull_ns: Option<u64>,
    container_start_ns: Option<u64>,
    steps_ns: Option<u64>,
    finalize_ns: Option<u64>,
    steps: Vec<StepRecord>,
    detail: String,
}

impl From<AttemptSummaryV3> for AttemptSummary {
    fn from(v3: AttemptSummaryV3) -> Self {
        Self {
            checkout_ns: v3.checkout_ns,
            checkout_fetch_ns: v3.checkout_fetch_ns,
            checkout_materialize_ns: v3.checkout_materialize_ns,
            checkout_route: v3.checkout_route,
            image_pull_ns: v3.image_pull_ns,
            image_present: v3.image_present,
            container_start_ns: v3.container_start_ns,
            steps_ns: v3.steps_ns,
            finalize_ns: v3.finalize_ns,
            steps: v3.steps,
            caches: v3.caches,
            detail: v3.detail,
            guest_image: None,
        }
    }
}

impl From<AttemptSummaryV1> for AttemptSummary {
    fn from(v1: AttemptSummaryV1) -> Self {
        Self {
            checkout_ns: v1.checkout_ns,
            image_pull_ns: v1.image_pull_ns,
            container_start_ns: v1.container_start_ns,
            steps_ns: v1.steps_ns,
            finalize_ns: v1.finalize_ns,
            steps: v1.steps,
            detail: v1.detail,
            ..Self::default()
        }
    }
}

impl From<AttemptSummaryV2> for AttemptSummary {
    fn from(v2: AttemptSummaryV2) -> Self {
        Self {
            checkout_ns: v2.checkout_ns,
            checkout_fetch_ns: v2.checkout_fetch_ns,
            checkout_materialize_ns: v2.checkout_materialize_ns,
            checkout_route: v2.checkout_route,
            image_pull_ns: v2.image_pull_ns,
            container_start_ns: v2.container_start_ns,
            steps_ns: v2.steps_ns,
            finalize_ns: v2.finalize_ns,
            steps: v2.steps,
            detail: v2.detail,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryError {
    Encode,
    Decode,
    TooLarge,
}

impl AttemptSummary {
    pub fn encode(&self) -> Result<Vec<u8>, SummaryError> {
        if self.steps.len() > MAX_STEP_RECORDS || self.caches.len() > MAX_CACHE_RECORDS {
            return Err(SummaryError::TooLarge);
        }
        let out =
            postcard::to_extend(self, vec![SUMMARY_FORMAT]).map_err(|_| SummaryError::Encode)?;
        if out.len() > MAX_SUMMARY_BYTES {
            return Err(SummaryError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SummaryError> {
        if bytes.len() > MAX_SUMMARY_BYTES {
            return Err(SummaryError::TooLarge);
        }
        match bytes.split_first() {
            Some((&SUMMARY_FORMAT, body)) => {
                postcard::from_bytes(body).map_err(|_| SummaryError::Decode)
            }
            Some((&SUMMARY_FORMAT_V3, body)) => postcard::from_bytes::<AttemptSummaryV3>(body)
                .map(AttemptSummary::from)
                .map_err(|_| SummaryError::Decode),
            Some((&SUMMARY_FORMAT_V2, body)) => postcard::from_bytes::<AttemptSummaryV2>(body)
                .map(AttemptSummary::from)
                .map_err(|_| SummaryError::Decode),
            Some((&SUMMARY_FORMAT_V1, body)) => postcard::from_bytes::<AttemptSummaryV1>(body)
                .map(AttemptSummary::from)
                .map_err(|_| SummaryError::Decode),
            _ => Err(SummaryError::Decode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_cache_record() -> CacheRecord {
        CacheRecord {
            name: "deps".into(),
            class: 1,
            outcome: "hit".into(),
            lookup_ns: Some(10),
            lock_wait_ns: Some(11),
            clone_ns: Some(12),
            first_touch_ns: Some(13),
            files: 40,
            bytes: 900,
            copied_bytes: 0,
            reflink: true,
            commit_ns: Some(20),
            staged_bytes: Some(950),
            reused_bytes: Some(800),
            dirty_bytes: Some(150),
            publish: Some("sealed".into()),
            costly_hit: false,
        }
    }

    #[test]
    fn round_trips_and_refuses_other_formats() {
        let summary = AttemptSummary {
            checkout_ns: Some(1),
            checkout_fetch_ns: Some(7),
            checkout_materialize_ns: Some(9),
            checkout_route: Some(CheckoutRoute::Mirror),
            image_pull_ns: None,
            image_present: Some(true),
            container_start_ns: Some(3),
            steps_ns: Some(4),
            finalize_ns: Some(5),
            steps: vec![
                StepRecord {
                    index: 0,
                    id: "build".into(),
                    outcome: StepOutcome::Passed,
                    duration_ns: Some(7),
                },
                StepRecord {
                    index: 1,
                    id: "test".into(),
                    outcome: StepOutcome::Failed { code: 3 },
                    duration_ns: Some(8),
                },
                StepRecord {
                    index: 2,
                    id: "deploy".into(),
                    outcome: StepOutcome::NotRun,
                    duration_ns: None,
                },
            ],
            caches: vec![
                full_cache_record(),
                CacheRecord {
                    name: "cc".into(),
                    class: 2,
                    outcome: "wrong_key".into(),
                    publish: Some("unchanged".into()),
                    ..full_cache_record()
                },
            ],
            guest_image: Some(GuestImageRecord {
                digest: format!("sha256:{}", "ab".repeat(32)),
                rootfs_bytes: 123_456_789,
                built: true,
                build_ns: Some(9_000_000_000),
            }),
            detail: "step 1 exited with 3".into(),
        };
        let bytes = summary.encode().unwrap();
        assert_eq!(bytes[0], SUMMARY_FORMAT);
        assert_eq!(AttemptSummary::decode(&bytes).unwrap(), summary);
        assert_eq!(AttemptSummary::decode(&[9, 0]), Err(SummaryError::Decode));
        assert_eq!(AttemptSummary::decode(&[]), Err(SummaryError::Decode));
        let too_many = AttemptSummary {
            steps: vec![
                StepRecord {
                    index: 0,
                    id: String::new(),
                    outcome: StepOutcome::NotRun,
                    duration_ns: None,
                };
                MAX_STEP_RECORDS + 1
            ],
            ..AttemptSummary::default()
        };
        assert_eq!(too_many.encode(), Err(SummaryError::TooLarge));
        let too_many_caches = AttemptSummary {
            caches: vec![full_cache_record(); MAX_CACHE_RECORDS + 1],
            ..AttemptSummary::default()
        };
        assert_eq!(too_many_caches.encode(), Err(SummaryError::TooLarge));
        let full = AttemptSummary {
            steps: vec![
                StepRecord {
                    index: 0,
                    id: "s".repeat(64),
                    outcome: StepOutcome::NotRun,
                    duration_ns: None,
                };
                MAX_STEP_RECORDS
            ],
            caches: vec![full_cache_record(); MAX_CACHE_RECORDS],
            detail: "d".repeat(500),
            ..AttemptSummary::default()
        };
        assert!(full.encode().unwrap().len() <= MAX_SUMMARY_BYTES);
    }

    #[test]
    fn format_three_blobs_decode_with_no_guest_image() {
        let v3 = AttemptSummaryV3 {
            checkout_ns: Some(1),
            checkout_fetch_ns: Some(2),
            checkout_materialize_ns: Some(3),
            checkout_route: Some(CheckoutRoute::Direct),
            image_pull_ns: Some(4),
            image_present: Some(true),
            container_start_ns: Some(5),
            steps_ns: Some(6),
            finalize_ns: Some(7),
            steps: vec![StepRecord {
                index: 0,
                id: "s".into(),
                outcome: StepOutcome::Passed,
                duration_ns: Some(1),
            }],
            caches: vec![full_cache_record()],
            detail: "kept".into(),
        };
        let mut bytes = vec![SUMMARY_FORMAT_V3];
        bytes.extend(postcard::to_allocvec(&v3).unwrap());
        let decoded = AttemptSummary::decode(&bytes).unwrap();
        assert_eq!(decoded.guest_image, None);
        assert_eq!(decoded.image_present, Some(true));
        assert_eq!(decoded.caches, vec![full_cache_record()]);
        assert_eq!(decoded.detail, "kept");
        assert_eq!(
            AttemptSummary::decode(&bytes[..bytes.len() - 1]),
            Err(SummaryError::Decode)
        );
    }

    #[test]
    fn format_two_blobs_decode_with_the_availability_fields_absent() {
        let v2 = AttemptSummaryV2 {
            checkout_ns: Some(11),
            checkout_fetch_ns: Some(2),
            checkout_materialize_ns: Some(9),
            checkout_route: Some(CheckoutRoute::MirrorFallback),
            image_pull_ns: Some(12),
            container_start_ns: None,
            steps_ns: Some(13),
            finalize_ns: None,
            steps: vec![StepRecord {
                index: 0,
                id: "s".into(),
                outcome: StepOutcome::Passed,
                duration_ns: Some(1),
            }],
            detail: "mirror busy".into(),
        };
        let mut bytes = vec![SUMMARY_FORMAT_V2];
        bytes.extend(postcard::to_allocvec(&v2).unwrap());
        let decoded = AttemptSummary::decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            AttemptSummary {
                checkout_ns: Some(11),
                checkout_fetch_ns: Some(2),
                checkout_materialize_ns: Some(9),
                checkout_route: Some(CheckoutRoute::MirrorFallback),
                image_pull_ns: Some(12),
                steps_ns: Some(13),
                steps: v2.steps.clone(),
                detail: "mirror busy".into(),
                ..AttemptSummary::default()
            }
        );
        assert_eq!(decoded.image_present, None);
        assert!(decoded.caches.is_empty());
        assert_eq!(
            AttemptSummary::decode(&bytes[..bytes.len() - 1]),
            Err(SummaryError::Decode)
        );
    }

    #[test]
    fn format_one_blobs_decode_with_the_new_fields_absent() {
        let v1 = AttemptSummaryV1 {
            checkout_ns: Some(11),
            image_pull_ns: Some(12),
            container_start_ns: None,
            steps_ns: Some(13),
            finalize_ns: None,
            steps: vec![StepRecord {
                index: 0,
                id: "s".into(),
                outcome: StepOutcome::Passed,
                duration_ns: Some(1),
            }],
            detail: String::new(),
        };
        let mut bytes = vec![SUMMARY_FORMAT_V1];
        bytes.extend(postcard::to_allocvec(&v1).unwrap());
        let decoded = AttemptSummary::decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            AttemptSummary {
                checkout_ns: Some(11),
                image_pull_ns: Some(12),
                steps_ns: Some(13),
                steps: v1.steps.clone(),
                ..AttemptSummary::default()
            }
        );
        assert_eq!(decoded.checkout_fetch_ns, None);
        assert_eq!(decoded.checkout_materialize_ns, None);
        assert_eq!(decoded.checkout_route, None);
        assert_eq!(decoded.image_present, None);
        assert!(decoded.caches.is_empty());
        assert_eq!(
            AttemptSummary::decode(&bytes[..bytes.len() - 1]),
            Err(SummaryError::Decode)
        );
    }
}
