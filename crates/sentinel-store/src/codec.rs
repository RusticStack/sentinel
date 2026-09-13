//! Persisted encodings of core types. Kept separate so the database column
//! format is one place to audit and the enums in `sentinel-core` stay free of
//! storage knowledge.
use sentinel_core::{FailureClass, JobState, Outcome};

/// Non-terminal states use their discriminant (0..=5); terminal states are
/// `TERMINAL_BASE + outcome` so the ready-queue partial index can test
/// `state_code = 1` and a range check `>= 16` selects everything terminal.
pub const TERMINAL_BASE: i64 = 16;
pub const READY: i64 = 1;

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
        for code in 0..=10 {
            let class = decode_failure(code).unwrap();
            assert_eq!(encode_failure(class), code);
        }
        assert_eq!(decode_failure(11), None);
    }
}
