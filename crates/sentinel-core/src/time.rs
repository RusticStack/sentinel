//! Persisted timestamps are UTC wall-clock provenance only. Durations are
//! measured with the monotonic clock in the process that observed both ends
//! (see the runtime foundations contract) and stored as separate nanosecond
//! fields; never subtract two `UnixMillis` to produce a latency figure.
//!
//! Deadline decisions (lease expiry, offer acknowledgement, queue and
//! execution timeouts, idempotency TTL) are not provenance: they read
//! [`UnixMillis::steady`], a process clock that advances with the monotonic
//! clock and is anchored to the wall clock once, at its first read. The values
//! it yields are stored in the same columns as before and stay comparable
//! across a restart (the next process anchors to the wall clock again), but a
//! wall-clock step while the process runs can never expire or extend a lease.
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

    /// The controller process's deadline clock: the wall clock at the first
    /// call plus the monotonic time elapsed since, so an NTP step or a VM
    /// resume moves it by the time that really passed and no more. It is the
    /// only clock deadline decisions and the timestamps they compare against
    /// may use; every process of one controller shares it. Never moves back.
    #[must_use]
    pub fn steady() -> Self {
        static ANCHOR: OnceLock<(i64, Instant)> = OnceLock::new();
        let (wall, at) = ANCHOR.get_or_init(|| (Self::now().0, Instant::now()));
        Self(wall.saturating_add(at.elapsed().as_millis().min(i64::MAX as u128) as i64))
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

    #[test]
    fn the_steady_clock_never_goes_back_and_starts_at_the_wall_clock() {
        let a = UnixMillis::steady();
        let b = UnixMillis::steady();
        assert!(b >= a);
        // Anchored to the wall clock: within a generous bound of it in a test
        // process that has not seen a wall-clock step.
        assert!((UnixMillis::now().0 - a.0).abs() < 60_000);
    }
}
