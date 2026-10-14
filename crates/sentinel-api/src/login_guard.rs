//! Password-guessing limits for `POST /api/v1/login`, per client and
//! account.
//!
//! The store locks an account after consecutive failures, which alone is a
//! denial of service: anyone who knows a login name (the super admin's is
//! usually `root`) can lock its owner out with a handful of requests. So
//! the lock that stops *one client* guessing lives here, keyed by client and
//! account: a client past [`LoginGuard::max_failures`] failures against an
//! account is refused (no password hash, no audit row, no writer) until its
//! lockout ends, while every other client still reaches the account. The
//! store's own account-wide lock stays as the ceiling against many clients
//! guessing together; the API gives it a multiple of the policy's
//! threshold ([`ACCOUNT_LOCK_FACTOR`]), so no single client can reach it.
//!
//! After a lockout ends the client keeps one failure of credit, not a fresh
//! allowance: the next failure locks it again, so a patient guesser gets
//! one guess per lockout window instead of a full allowance each time. A
//! success clears the entry.
//!
//! The map is bounded: when it is full, expired entries are swept; if none
//! expired, a new pair goes untracked (the per-client admission budget and
//! the account ceiling still bound it) rather than growing memory.

use std::{
    collections::HashMap,
    hash::{BuildHasher, RandomState},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Client and account pairs tracked at once.
const MAX_PAIRS: usize = 4096;
/// The store's account-wide lock threshold is the policy's per-client
/// threshold times this: it takes several clients to lock an account.
pub(crate) const ACCOUNT_LOCK_FACTOR: i64 = 4;
/// Idle lifetime of an entry, in lockout windows.
const REMEMBER_WINDOWS: u32 = 4;

struct Entry {
    failures: i64,
    /// Refused until then, when locked.
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
        // Names are compared exactly, as the store does; a keyed hash keeps an
        // attacker's strings from costing memory per byte.
        (client, self.keys.hash_one(account))
    }

    /// Whether `client` may try `account` at `now`.
    pub(crate) fn allowed(&self, client: u128, account: &str, now: Instant) -> bool {
        let key = self.key(client, account);
        let pairs = self.pairs.lock().unwrap_or_else(|p| p.into_inner());
        pairs
            .get(&key)
            .is_none_or(|entry| entry.until.is_none_or(|until| until <= now))
    }

    /// Count one failed attempt; `max_failures` of them lock the pair for
    /// `lockout`.
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
            // The window was served: one failure of credit remains.
            entry.until = None;
            entry.failures = (max_failures - 1).max(0);
        }
        entry.failures += 1;
        entry.last = now;
        if entry.failures >= max_failures {
            entry.until = Some(now + lockout);
        }
    }

    /// A password was accepted: forget the pair.
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
        // The owner, from elsewhere, and the attacker against another
        // account are untouched.
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
        // Long after, every entry is stale: the next new pair sweeps them.
        let later = start + LOCKOUT * (REMEMBER_WINDOWS + 1);
        guard.failed(u128::MAX, "root", 3, LOCKOUT, later);
        assert_eq!(guard.tracked(), 1);
    }
}
