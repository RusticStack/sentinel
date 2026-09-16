//! What an attempt measured about itself, sent with its terminal report
//! and stored beside the attempt (W04). Durations are monotonic
//! nanoseconds measured on the worker; absent means not measured, never
//! zero. Versioned by a leading format byte like the run spec.

use serde::{Deserialize, Serialize};

pub const SUMMARY_FORMAT: u8 = 3;
/// Format 1 predates the separate fetch/materialize timings; it stays
/// decodable forever, mapping onto the new shape with the added fields
/// absent.
const SUMMARY_FORMAT_V1: u8 = 1;
/// Format 2 predates the cache/image availability records (K08); it stays
/// decodable through its own shadow struct, like format 1.
const SUMMARY_FORMAT_V2: u8 = 2;
/// A summary crosses the link inside one control frame with room to spare.
pub const MAX_SUMMARY_BYTES: usize = 32 * 1024;
/// Steps recorded per attempt; a job has at most this many steps anyway.
pub const MAX_STEP_RECORDS: usize = 256;
/// Cache records per attempt (K08). The schema caps a job at
/// `MAX_CACHES` (8) declarations; 16 leaves headroom for a spec built by
/// hand while keeping the summary well under [`MAX_SUMMARY_BYTES`].
pub const MAX_CACHE_RECORDS: usize = 16;

/// How one step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Exit status zero.
    Passed,
    /// Its `if` evaluated to false; nothing ran.
    Skipped,
    /// Non-zero exit status.
    Failed { code: i32 },
    /// Killed by a signal that was not the memory limit.
    Signaled { signal: i32 },
    /// The cgroup memory limit killed a process of this step.
    OutOfMemory,
    /// Ran past its budget and was stopped.
    TimedOut,
    /// The container runtime could not run it; not the command's fault.
    Runtime,
    /// A step after the failing one: never started.
    NotRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub index: u32,
    pub id: String,
    pub outcome: StepOutcome,
    pub duration_ns: Option<u64>,
}

/// Which checkout path produced the workspace. Format 1 has no notion of
/// it, so a decoded old summary reports `None` rather than guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckoutRoute {
    /// The exact revision was fetched straight into the workspace.
    Direct,
    /// The worker-local object mirror was updated, then the worktree was
    /// materialized from it with a private object store.
    Mirror,
    /// The mirror could not serve (lock, IO or store damage); the direct
    /// fetch produced the checkout. `detail` names the mirror's reason.
    MirrorFallback,
}

/// What one declared `cache:` entry did for the attempt (K08): the
/// restore's outcome and measured phases, then the commit's answer.
/// Durations are `Option` — a phase that never ran is absent, never zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRecord {
    /// The declared name (schema-bounded).
    pub name: String,
    /// The class's wire code (`Class::to_u8`) — a class newer than the
    /// reader still records as a number.
    pub class: u8,
    /// `"hit"` or the stable `Miss` reason (`Miss::as_str`).
    pub outcome: String,
    /// Manifest read plus compatibility check.
    pub lookup_ns: Option<u64>,
    /// Lease-acquisition wait.
    pub lock_wait_ns: Option<u64>,
    /// Payload materialization (clone or copy).
    pub clone_ns: Option<u64>,
    /// The bounded first-read sample after a hit's clone: the largest
    /// listed file's first bytes, once per target — cold-extent cost the
    /// clone wall time hides.
    pub first_touch_ns: Option<u64>,
    /// Files and payload bytes materialized.
    pub files: u64,
    pub bytes: u64,
    /// Bytes actually copied — reflinked files share extents instead.
    pub copied_bytes: u64,
    /// The clone backend was reflink-capable.
    pub reflink: bool,
    /// The commit's wall time; `None` when no publish ran.
    pub commit_ns: Option<u64>,
    /// Payload bytes the sealed generation lists.
    pub staged_bytes: Option<u64>,
    /// Of `staged_bytes`, hardlinked out of the source generation.
    pub reused_bytes: Option<u64>,
    /// `staged_bytes - reused_bytes`: what the job's view rewrote.
    pub dirty_bytes: Option<u64>,
    /// `"sealed"`, a `SkipReason` string or `"failed"`; `None` when the
    /// verdict left nothing to publish.
    pub publish: Option<String>,
    /// The costly-hit rule tripped (docs/cache.md): a nominal hit that
    /// paid rebuild-scale cost — diagnostics, never a verdict.
    pub costly_hit: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSummary {
    /// Whole checkout, fetch plus materialization.
    pub checkout_ns: Option<u64>,
    /// The fetch side alone (mirror update, or the direct fetch into the
    /// workspace); `None` when not measured separately — format 1 and
    /// checkouts that never completed a fetch.
    pub checkout_fetch_ns: Option<u64>,
    /// The materialization side alone (worktree plus object store);
    /// `None` under the same conditions as `checkout_fetch_ns`.
    pub checkout_materialize_ns: Option<u64>,
    pub checkout_route: Option<CheckoutRoute>,
    pub image_pull_ns: Option<u64>,
    /// Format 3 (K08): `Some(true)` when the image was already in the
    /// worker's store — the `podman image exists` fast path, nothing
    /// downloaded — `Some(false)` when the pull fetched it, and `None`
    /// when preparation never reached the pull or the pull failed.
    pub image_present: Option<bool>,
    pub container_start_ns: Option<u64>,
    pub steps_ns: Option<u64>,
    pub finalize_ns: Option<u64>,
    pub steps: Vec<StepRecord>,
    /// Format 3 (K08): one record per declared `cache:` entry, in
    /// declaration order, at most [`MAX_CACHE_RECORDS`].
    pub caches: Vec<CacheRecord>,
    /// One bounded line on why the attempt did not pass, or — with
    /// `CheckoutRoute::MirrorFallback` — why the mirror did not serve;
    /// never output.
    pub detail: String,
}

/// The format-1 wire shape: everything format 2 adds is absent on decode.
/// `Serialize` only so tests can produce a genuine format-1 blob.
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

/// The format-2 wire shape: the availability records format 3 adds are
/// absent on decode. `Serialize` only so tests can produce a genuine
/// format-2 blob.
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

    /// A cache record with every phase filled — the biggest honest shape.
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
        // The cache record set is bounded too.
        let too_many_caches = AttemptSummary {
            caches: vec![full_cache_record(); MAX_CACHE_RECORDS + 1],
            ..AttemptSummary::default()
        };
        assert_eq!(too_many_caches.encode(), Err(SummaryError::TooLarge));
        // A full format-3 summary — every step and cache record slot in
        // use — still fits the frame.
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
        // What format 2 could not express stays absent, never zero.
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
        // What format 1 could not express stays absent, never zero.
        assert_eq!(decoded.checkout_fetch_ns, None);
        assert_eq!(decoded.checkout_materialize_ns, None);
        assert_eq!(decoded.checkout_route, None);
        assert_eq!(decoded.image_present, None);
        assert!(decoded.caches.is_empty());
        // A truncated format-1 body is still a decode error.
        assert_eq!(
            AttemptSummary::decode(&bytes[..bytes.len() - 1]),
            Err(SummaryError::Decode)
        );
    }
}
