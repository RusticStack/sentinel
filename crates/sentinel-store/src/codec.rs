use sentinel_core::{FailureClass, Fence, JobState, Outcome};

// The ready-queue partial index tests `state_code = READY`, and `>= TERMINAL_BASE` selects every terminal row.
pub const TERMINAL_BASE: i64 = 16;
pub const READY: i64 = 1;

/// A stored fence is a non-negative integer. Wrapping a negative one into `u64` would turn a damaged
/// row into a live job at `u64::MAX`, which no lease can advance and no worker can report on.
pub const fn decode_fence(code: i64) -> Option<Fence> {
    if code < 0 {
        return None;
    }
    Some(Fence(code as u64))
}

/// The stored cancellation flag is 0 or 1; anything else is not a value this store wrote.
pub const fn decode_flag(code: i64) -> Option<bool> {
    match code {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

pub const fn encode_state(state: JobState) -> i64 {
    match state {
        JobState::Blocked => 0,
        JobState::Queued => 1,
        JobState::Leased => 2,
        JobState::Preparing => 3,
        JobState::Running => 4,
        JobState::Finalizing => 5,
        JobState::Terminal(o) => TERMINAL_BASE + o as i64,
    }
}

pub const fn decode_state(code: i64) -> Option<JobState> {
    Some(match code {
        0 => JobState::Blocked,
        1 => JobState::Queued,
        2 => JobState::Leased,
        3 => JobState::Preparing,
        4 => JobState::Running,
        5 => JobState::Finalizing,
        16 => JobState::Terminal(Outcome::Passed),
        17 => JobState::Terminal(Outcome::Skipped),
        18 => JobState::Terminal(Outcome::Canceled),
        19 => JobState::Terminal(Outcome::TimedOut),
        20 => JobState::Terminal(Outcome::Failed),
        21 => JobState::Terminal(Outcome::InfraFailed),
        _ => return None,
    })
}

pub const fn encode_failure(class: FailureClass) -> i64 {
    class as i64
}

pub const fn decode_failure(code: i64) -> Option<FailureClass> {
    Some(match code {
        0 => FailureClass::CommandFailed,
        1 => FailureClass::CommandSignaled,
        2 => FailureClass::OutOfMemory,
        3 => FailureClass::ExecutionTimeout,
        4 => FailureClass::QueueTimeout,
        5 => FailureClass::Canceled,
        6 => FailureClass::Preparation,
        7 => FailureClass::LeaseExpired,
        8 => FailureClass::WorkerLost,
        9 => FailureClass::Reconciled,
        10 => FailureClass::Publication,
        11 => FailureClass::Runtime,
        12 => FailureClass::ResourceLock,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_codes_round_trip_and_keep_ready_at_one() {
        let all = [
            JobState::Blocked,
            JobState::Queued,
            JobState::Leased,
            JobState::Preparing,
            JobState::Running,
            JobState::Finalizing,
            JobState::Terminal(Outcome::Passed),
            JobState::Terminal(Outcome::Skipped),
            JobState::Terminal(Outcome::Canceled),
            JobState::Terminal(Outcome::TimedOut),
            JobState::Terminal(Outcome::Failed),
            JobState::Terminal(Outcome::InfraFailed),
        ];
        for s in all {
            assert_eq!(decode_state(encode_state(s)), Some(s));
            assert_eq!(encode_state(s) >= TERMINAL_BASE, s.is_terminal());
        }
        assert_eq!(encode_state(JobState::Queued), READY);
        assert_eq!(decode_state(6), None);
        assert_eq!(decode_state(22), None);
    }

    #[test]
    fn failure_codes_round_trip() {
        for code in 0..=12 {
            let class = decode_failure(code).unwrap();
            assert_eq!(encode_failure(class), code);
        }
        assert_eq!(decode_failure(13), None);
    }

    #[test]
    fn a_negative_fence_or_an_off_flag_is_not_a_stored_value() {
        assert_eq!(decode_fence(0), Some(Fence::NONE));
        assert_eq!(decode_fence(i64::MAX), Some(Fence(i64::MAX as u64)));
        assert_eq!(decode_fence(-1), None);
        assert_eq!(decode_fence(i64::MIN), None);
        assert_eq!(decode_flag(0), Some(false));
        assert_eq!(decode_flag(1), Some(true));
        for wrong in [-1, 2, i64::MAX] {
            assert_eq!(decode_flag(wrong), None);
        }
    }
}
