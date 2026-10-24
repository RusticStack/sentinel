//! Persisted timestamps are wall-clock provenance: never subtract two `UnixMillis` to get a latency.
//! Deadline decisions read `UnixMillis::steady`, which a wall-clock step can neither move nor extend.
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct UnixMillis(pub i64);

impl UnixMillis {
    #[must_use]
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or(0);
        Self(ms)
    }

    #[must_use]
    pub fn steady() -> Self {
        static ANCHOR: OnceLock<(i64, Instant)> = OnceLock::new();
        let (wall, at) = ANCHOR.get_or_init(|| (Self::now().0, Instant::now()));
        Self(wall.saturating_add(at.elapsed().as_millis().min(i64::MAX as u128) as i64))
    }
}

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
    /// The first entry wins, so a duplicate or reordered delivery cannot move a timestamp later.
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
        assert!((UnixMillis::now().0 - a.0).abs() < 60_000);
    }
}
