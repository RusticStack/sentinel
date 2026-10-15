//! Per client and account: the store's account-wide lock alone lets anyone lock out an account owner, so this guard locks only the guessing client.

use std::{
    collections::HashMap,
    hash::{BuildHasher, RandomState},
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_PAIRS: usize = 4096;
pub(crate) const ACCOUNT_LOCK_FACTOR: i64 = 4;
const REMEMBER_WINDOWS: u32 = 4;

struct Entry {
    failures: i64,
    until: Option<Instant>,
    last: Instant,
}

pub(crate) struct LoginGuard {
    pairs: Mutex<HashMap<(u128, u64), Entry>>,
    keys: RandomState,
}

impl Default for LoginGuard {
    fn default() -> Self {
        LoginGuard {
            pairs: Mutex::new(HashMap::new()),
            keys: RandomState::new(),
        }
    }
}

impl LoginGuard {
    fn key(&self, client: u128, account: &str) -> (u128, u64) {
        (client, self.keys.hash_one(account))
    }

    pub(crate) fn allowed(&self, client: u128, account: &str, now: Instant) -> bool {
        let key = self.key(client, account);
        let pairs = self.pairs.lock().unwrap_or_else(|p| p.into_inner());
        pairs
            .get(&key)
            .is_none_or(|entry| entry.until.is_none_or(|until| until <= now))
    }

    pub(crate) fn failed(
        &self,
        client: u128,
        account: &str,
        max_failures: i64,
        lockout: Duration,
        now: Instant,
    ) {
        let key = self.key(client, account);
        let mut pairs = self.pairs.lock().unwrap_or_else(|p| p.into_inner());
        if !pairs.contains_key(&key) && pairs.len() >= MAX_PAIRS {
            let remember = lockout * REMEMBER_WINDOWS;
            pairs.retain(|_, e| now.saturating_duration_since(e.last) < remember);
            if pairs.len() >= MAX_PAIRS {
                return;
            }
        }
        let entry = pairs.entry(key).or_insert(Entry {
            failures: 0,
            until: None,
            last: now,
        });
        if entry.until.is_some_and(|until| until <= now) {
            // One failure of credit, not a fresh allowance: a patient guesser gets one guess per window.
            entry.until = None;
            entry.failures = (max_failures - 1).max(0);
        }
        entry.failures += 1;
        entry.last = now;
        if entry.failures >= max_failures {
            entry.until = Some(now + lockout);
        }
    }

    pub(crate) fn succeeded(&self, client: u128, account: &str) {
        let key = self.key(client, account);
        self.pairs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.pairs.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKOUT: Duration = Duration::from_secs(900);

    #[test]
    fn one_client_is_locked_out_of_an_account_and_others_are_not() {
        let guard = LoginGuard::default();
        let start = Instant::now();
        let (attacker, owner) = (1u128, 2u128);
        for _ in 0..3 {
            assert!(guard.allowed(attacker, "root", start));
            guard.failed(attacker, "root", 3, LOCKOUT, start);
        }
        assert!(!guard.allowed(attacker, "root", start));
        assert!(guard.allowed(owner, "root", start));
        assert!(guard.allowed(attacker, "someone", start));
    }

    #[test]
    fn a_served_lockout_leaves_one_failure_of_credit() {
        let guard = LoginGuard::default();
        let start = Instant::now();
        for _ in 0..3 {
            guard.failed(1, "root", 3, LOCKOUT, start);
        }
        let later = start + LOCKOUT + Duration::from_secs(1);
        assert!(guard.allowed(1, "root", later));
        guard.failed(1, "root", 3, LOCKOUT, later);
        assert!(!guard.allowed(1, "root", later));
    }

    #[test]
    fn a_success_clears_the_pair() {
        let guard = LoginGuard::default();
        let start = Instant::now();
        guard.failed(1, "root", 3, LOCKOUT, start);
        guard.failed(1, "root", 3, LOCKOUT, start);
        guard.succeeded(1, "root");
        guard.failed(1, "root", 3, LOCKOUT, start);
        assert!(guard.allowed(1, "root", start));
    }

    #[test]
    fn the_map_stays_bounded_and_sweeps_only_expired_pairs() {
        let guard = LoginGuard::default();
        let start = Instant::now();
        for n in 0..(MAX_PAIRS as u128 + 50) {
            guard.failed(n, "root", 3, LOCKOUT, start);
        }
        assert_eq!(guard.tracked(), MAX_PAIRS);
        let later = start + LOCKOUT * (REMEMBER_WINDOWS + 1);
        guard.failed(u128::MAX, "root", 3, LOCKOUT, later);
        assert_eq!(guard.tracked(), 1);
    }
}
