//! Persisted timestamps are UTC wall-clock provenance only. Durations are
//! measured with the monotonic clock in the process that observed both ends
//! (see the runtime foundations contract) and stored as separate nanosecond
//! fields; never subtract two `UnixMillis` to produce a latency figure.
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, UTC. `i64` covers ±292 million years and
/// matches SQLite's INTEGER affinity without conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct UnixMillis(pub i64);

impl UnixMillis {
    #[must_use]
    pub fn now() -> Self {
        // A clock before 1970 is a misconfigured host; clamp rather than panic.
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or(0);
        Self(ms)
    }
}

/// When each state was entered for one attempt, recorded by the controller
/// when it commits the transition (single clock domain). Absent means the
/// state was never entered; a rerun starts a fresh record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptTimestamps {
    pub queued: Option<UnixMillis>,
    pub leased: Option<UnixMillis>,
    pub preparing: Option<UnixMillis>,
    pub running: Option<UnixMillis>,
    pub finalizing: Option<UnixMillis>,
    pub terminal: Option<UnixMillis>,
}

impl AttemptTimestamps {
    /// Record entry into `state` at `at`; the first entry wins so a duplicate
    /// or reordered delivery cannot move a timestamp later.
    pub const fn enter(&mut self, state: crate::state::JobState, at: UnixMillis) {
        use crate::state::JobState as S;
        let slot = match state {
            S::Blocked => return,
            S::Queued => &mut self.queued,
            S::Leased => &mut self.leased,
            S::Preparing => &mut self.preparing,
            S::Running => &mut self.running,
            S::Finalizing => &mut self.finalizing,
            S::Terminal(_) => &mut self.terminal,
        };
        if slot.is_none() {
            *slot = Some(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{JobState, Outcome};

    #[test]
    fn first_entry_wins_and_blocked_is_not_recorded() {
        let mut t = AttemptTimestamps::default();
        t.enter(JobState::Blocked, UnixMillis(5));
        t.enter(JobState::Running, UnixMillis(10));
        t.enter(JobState::Running, UnixMillis(20));
        t.enter(JobState::Terminal(Outcome::Passed), UnixMillis(30));
        assert_eq!(t.running, Some(UnixMillis(10)));
        assert_eq!(t.terminal, Some(UnixMillis(30)));
        assert_eq!(t.queued, None);
        assert!(UnixMillis::now().0 > 1_700_000_000_000);
    }
}
