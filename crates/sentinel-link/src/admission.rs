//! Pre-authentication limits of the controller's listener: who may hold the
//! small pool of connections that have proved nothing yet, how fast an
//! unknown certificate may try enrollment secrets, and how many sessions the
//! process's descriptor limit can carry.
//!
//! Everything here is decided from the peer's address and counters alone,
//! before TLS or the store is involved, and every table is bounded.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Connections one unknown source may have in their handshake at once. A
/// handshake takes milliseconds; eight is a worker (it holds two at most)
/// behind a retrying proxy, and a fifth of the default pool at most one
/// attacker address.
pub const PENDING_PER_SOURCE: usize = 8;
/// The same for a source that has authenticated a worker before: a site
/// whose whole fleet reconnects through one NAT address after a restart.
pub const PENDING_PER_KNOWN_SOURCE: usize = 64;
/// How long an authenticated source stays known.
const KNOWN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Known sources remembered; a full table of live entries forgets nobody
/// but admits no new one until some expire.
const KNOWN_MAX: usize = 4096;

/// IPv6 sources are accounted by their /64: the unit a host or an attacker
/// controls, so rotating the low bits of an address buys nothing. IPv4-mapped
/// addresses count as the IPv4 address they carry.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        },
        v4 => v4,
    }
}

/// The pool of connections still in their handshake and hello.
///
/// Two limits beyond the pool's size. A source is held to a few slots, so no
/// single address can fill the pool. And the last quarter of the pool is a
/// reserve only sources that have authenticated a worker may use: a flood
/// from addresses never seen before cannot take it, so a known worker's
/// reconnect still finds a slot while the flood lasts. Loopback (the only
/// address a Tailcat helper carries peers from) is exempt from the
/// per-source share, since many workers legitimately share it.
#[derive(Default)]
pub struct Pending {
    book: Mutex<Book>,
}

#[derive(Default)]
struct Book {
    total: usize,
    by_source: HashMap<IpAddr, usize>,
    known: HashMap<IpAddr, Instant>,
}

impl Pending {
    /// Take a slot for a connection from `ip`, or refuse it.
    pub fn enter(&self, ip: IpAddr, max_pending: usize, now: Instant) -> bool {
        let loopback = ip.is_loopback();
        let key = source_key(ip);
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        let known = book
            .known
            .get(&key)
            .is_some_and(|at| now.saturating_duration_since(*at) < KNOWN_TTL);
        let ceiling = if known {
            max_pending
        } else {
            max_pending - max_pending / 4
        };
        if book.total >= ceiling {
            return false;
        }
        if !loopback {
            let share = if known {
                PENDING_PER_KNOWN_SOURCE
            } else {
                PENDING_PER_SOURCE
            };
            if book.by_source.get(&key).copied().unwrap_or(0) >= share {
                return false;
            }
        }
        book.total += 1;
        *book.by_source.entry(key).or_insert(0) += 1;
        true
    }

    /// Give the slot back: the handshake and hello ended, whichever way.
    pub fn leave(&self, ip: IpAddr) {
        let key = source_key(ip);
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        book.total = book.total.saturating_sub(1);
        if let Some(count) = book.by_source.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                book.by_source.remove(&key);
            }
        }
    }

    /// `ip` just authenticated a worker: it may use the reserve.
    pub fn vouch(&self, ip: IpAddr, now: Instant) {
        let key = source_key(ip);
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        if book.known.len() >= KNOWN_MAX && !book.known.contains_key(&key) {
            book.known
                .retain(|_, at| now.saturating_duration_since(*at) < KNOWN_TTL);
            if book.known.len() >= KNOWN_MAX {
                return;
            }
        }
        book.known.insert(key, now);
    }

    /// Connections in their handshake right now.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.book.lock().unwrap_or_else(|p| p.into_inner()).total
    }
}

/// A token bucket in thousandths of a token, so refills are integers.
#[derive(Clone, Copy)]
struct Bucket {
    milli: u64,
    at: Instant,
}

impl Bucket {
    fn full(burst: u64, now: Instant) -> Self {
        Self {
            milli: burst * 1000,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant, burst: u64, every: Duration) {
        let elapsed = now.saturating_duration_since(self.at);
        let gained = elapsed.as_millis() * 1000 / every.as_millis().max(1);
        self.milli = (self.milli + gained.min(u128::from(u64::MAX / 2)) as u64).min(burst * 1000);
        self.at = now;
    }
}

/// Enrollment attempts per source: five at once, then one every 12 s.
const ENROLL_SOURCE_BURST: u64 = 5;
const ENROLL_SOURCE_EVERY: Duration = Duration::from_secs(12);
/// Enrollment attempts from everywhere together: twenty at once, then one
/// every 3 s (twenty a minute). A refused secret commits an audit row on the
/// single writer, so this caps what unauthenticated peers can write to the
/// audit log however many addresses they use, at the price of an operator's
/// real enrollment waiting out a flood (the worker retries on its back-off).
const ENROLL_GLOBAL_BURST: u64 = 20;
const ENROLL_GLOBAL_EVERY: Duration = Duration::from_secs(3);
/// Sources with a bucket; past it only a source whose bucket has refilled
/// completely is forgotten, and a table still full refuses new sources.
const ENROLL_SOURCES_MAX: usize = 4096;

/// Rate limit on enrollment-secret attempts by unknown certificates.
pub struct Enrollments {
    state: Mutex<EnrollState>,
}

struct EnrollState {
    global: Bucket,
    sources: HashMap<IpAddr, Bucket>,
}

impl Enrollments {
    pub fn new(now: Instant) -> Self {
        Self {
            state: Mutex::new(EnrollState {
                global: Bucket::full(ENROLL_GLOBAL_BURST, now),
                sources: HashMap::new(),
            }),
        }
    }

    /// Whether `ip` may present an enrollment secret now; spends a token of
    /// its own bucket and of the global one when it may.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let key = source_key(ip);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state
            .global
            .refill(now, ENROLL_GLOBAL_BURST, ENROLL_GLOBAL_EVERY);
        if state.global.milli < 1000 {
            return false;
        }
        if state.sources.len() >= ENROLL_SOURCES_MAX && !state.sources.contains_key(&key) {
            state.sources.retain(|_, bucket| {
                let mut idle = *bucket;
                idle.refill(now, ENROLL_SOURCE_BURST, ENROLL_SOURCE_EVERY);
                idle.milli < ENROLL_SOURCE_BURST * 1000
            });
            if state.sources.len() >= ENROLL_SOURCES_MAX {
                return false;
            }
        }
        let bucket = state
            .sources
            .entry(key)
            .or_insert_with(|| Bucket::full(ENROLL_SOURCE_BURST, now));
        bucket.refill(now, ENROLL_SOURCE_BURST, ENROLL_SOURCE_EVERY);
        if bucket.milli < 1000 {
            return false;
        }
        bucket.milli -= 1000;
        state.global.milli -= 1000;
        true
    }
}

/// Descriptors each session holds: the socket and its clone for the reading
/// half.
#[cfg(unix)]
const FDS_PER_SESSION: usize = 2;
/// Descriptors kept for everything that is not a session: the store, the
/// listeners, log and object files, helper pipes.
#[cfg(unix)]
const FD_HEADROOM: usize = 256;

/// How many sessions the process's descriptor limit can carry, at most
/// `wanted`. Raises the soft limit toward the hard one first (a session
/// needs `FDS_PER_SESSION` descriptors, so the common soft limit of 1024
/// would otherwise stop the controller at about 380 sessions with `EMFILE`).
#[cfg(unix)]
pub fn session_cap(wanted: usize) -> usize {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` for the whole call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return wanted;
    }
    let needed = (wanted * FDS_PER_SESSION + FD_HEADROOM) as libc::rlim_t;
    if limit.rlim_cur < needed && limit.rlim_cur < limit.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: needed.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `raised` is a valid `rlimit`; failure leaves the limit as
        // it was, which the re-read below accounts for.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit.rlim_cur = raised.rlim_cur;
        }
    }
    let usable = usize::try_from(limit.rlim_cur)
        .unwrap_or(usize::MAX)
        .saturating_sub(FD_HEADROOM)
        / FDS_PER_SESSION;
    usable.clamp(1, wanted)
}

#[cfg(not(unix))]
pub fn session_cap(wanted: usize) -> usize {
    wanted
}

/// How long the acceptor sleeps after `failures` accept errors in a row that
/// are not one peer's doing (descriptor or memory exhaustion): doubling from
/// 10 ms to 250 ms, so a full descriptor table costs a few wakeups a second
/// rather than a spinning core, and the backlog drains the moment a
/// descriptor frees.
pub fn accept_backoff(failures: u32) -> Duration {
    Duration::from_millis(10u64 << failures.min(5)).min(Duration::from_millis(250))
}

/// Whether an accept error belongs to the one connection it concerns (the
/// peer gave up between the SYN and the accept) and says nothing about the
/// process's own resources.
pub fn accept_error_is_peer_local(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionReset, Interrupted};
    matches!(
        error.kind(),
        ConnectionAborted | ConnectionReset | Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn one_source_cannot_fill_the_pool_and_others_still_enter() {
        let pending = Pending::default();
        let now = Instant::now();
        for _ in 0..PENDING_PER_SOURCE {
            assert!(pending.enter(ip(1), 256, now));
        }
        assert!(!pending.enter(ip(1), 256, now));
        assert!(pending.enter(ip(2), 256, now));
        pending.leave(ip(1));
        assert!(pending.enter(ip(1), 256, now));
    }

    #[test]
    fn the_last_quarter_of_the_pool_is_for_known_sources() {
        let pending = Pending::default();
        let now = Instant::now();
        pending.vouch(ip(200), now);
        // 192 slots for strangers, spread so no per-source share trips.
        let mut taken = 0;
        'fill: for host in 1..=60u8 {
            for _ in 0..PENDING_PER_SOURCE {
                if !pending.enter(ip(host), 256, now) {
                    break 'fill;
                }
                taken += 1;
            }
        }
        assert_eq!(taken, 192);
        assert!(!pending.enter(ip(100), 256, now), "a stranger is shed");
        assert!(pending.enter(ip(200), 256, now), "a known worker enters");
        assert_eq!(pending.len(), 193);
    }

    #[test]
    fn ipv6_sources_are_held_to_one_share_per_prefix() {
        let pending = Pending::default();
        let now = Instant::now();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:2".parse().unwrap();
        assert_eq!(source_key(a), source_key(b));
        for _ in 0..PENDING_PER_SOURCE {
            assert!(pending.enter(a, 256, now));
        }
        assert!(!pending.enter(b, 256, now));
    }

    #[test]
    fn loopback_is_not_held_to_a_per_source_share() {
        let pending = Pending::default();
        let now = Instant::now();
        for _ in 0..PENDING_PER_SOURCE * 4 {
            assert!(pending.enter(IpAddr::from([127, 0, 0, 1]), 256, now));
        }
    }

    #[test]
    fn enrollment_attempts_are_rate_limited_per_source_and_overall() {
        let start = Instant::now();
        let limiter = Enrollments::new(start);
        for _ in 0..ENROLL_SOURCE_BURST {
            assert!(limiter.allow(ip(1), start));
        }
        assert!(!limiter.allow(ip(1), start), "the source is spent");
        assert!(limiter.allow(ip(2), start), "another source is not");
        assert!(limiter.allow(ip(1), start + ENROLL_SOURCE_EVERY));
        // Many sources together still share the global budget.
        let limiter = Enrollments::new(start);
        let allowed = (1..=100u8).filter(|n| limiter.allow(ip(*n), start)).count();
        assert_eq!(allowed as u64, ENROLL_GLOBAL_BURST);
    }

    #[test]
    fn accept_backoff_grows_and_is_capped() {
        assert_eq!(accept_backoff(0), Duration::from_millis(10));
        assert!(accept_backoff(2) > accept_backoff(1));
        assert_eq!(accept_backoff(100), Duration::from_millis(250));
    }
}
