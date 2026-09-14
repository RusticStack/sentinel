//! What an attempt measured about itself, sent with its terminal report
//! and stored beside the attempt (W04). Durations are monotonic
//! nanoseconds measured on the worker; absent means not measured, never
//! zero. Versioned by a leading format byte like the run spec.

use serde::{Deserialize, Serialize};

pub const SUMMARY_FORMAT: u8 = 1;
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSummary {
    pub checkout_ns: Option<u64>,
    pub image_pull_ns: Option<u64>,
    pub container_start_ns: Option<u64>,
    pub steps_ns: Option<u64>,
    pub finalize_ns: Option<u64>,
    pub steps: Vec<StepRecord>,
    /// One bounded line on why the attempt did not pass; never output.
    pub detail: String,
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
        assert_eq!(AttemptSummary::decode(&[2, 0]), Err(SummaryError::Decode));
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
}
