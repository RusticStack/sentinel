//! What an attempt measured about itself, sent with its terminal report
//! and stored beside the attempt (W04). Durations are monotonic
//! nanoseconds measured on the worker; absent means not measured, never
//! zero. Versioned by a leading format byte like the run spec.

use serde::{Deserialize, Serialize};

pub const SUMMARY_FORMAT: u8 = 2;
/// Format 1 predates the separate fetch/materialize timings; it stays
/// decodable forever, mapping onto the new shape with the added fields
/// absent.
const SUMMARY_FORMAT_V1: u8 = 1;
/// A summary crosses the link inside one control frame with room to spare.
pub const MAX_SUMMARY_BYTES: usize = 32 * 1024;
/// Steps recorded per attempt; a job has at most this many steps anyway.
pub const MAX_STEP_RECORDS: usize = 256;

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
    pub container_start_ns: Option<u64>,
    pub steps_ns: Option<u64>,
    pub finalize_ns: Option<u64>,
    pub steps: Vec<StepRecord>,
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

impl From<AttemptSummaryV1> for AttemptSummary {
    fn from(v1: AttemptSummaryV1) -> Self {
        Self {
            checkout_ns: v1.checkout_ns,
            checkout_fetch_ns: None,
            checkout_materialize_ns: None,
            checkout_route: None,
            image_pull_ns: v1.image_pull_ns,
            container_start_ns: v1.container_start_ns,
            steps_ns: v1.steps_ns,
            finalize_ns: v1.finalize_ns,
            steps: v1.steps,
            detail: v1.detail,
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
        if self.steps.len() > MAX_STEP_RECORDS {
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

    #[test]
    fn round_trips_and_refuses_other_formats() {
        let summary = AttemptSummary {
            checkout_ns: Some(1),
            checkout_fetch_ns: Some(7),
            checkout_materialize_ns: Some(9),
            checkout_route: Some(CheckoutRoute::Mirror),
            image_pull_ns: None,
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
        // A truncated format-1 body is still a decode error.
        assert_eq!(
            AttemptSummary::decode(&bytes[..bytes.len() - 1]),
            Err(SummaryError::Decode)
        );
    }
}
