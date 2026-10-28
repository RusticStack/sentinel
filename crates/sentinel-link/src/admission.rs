use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

pub const PENDING_PER_SOURCE: usize = 8;
pub const PENDING_PER_KNOWN_SOURCE: usize = 64;
pub const KNOWN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const KNOWN_MAX: usize = 4096;
/// A known source is written to the store when first seen and then at most this often.
const KNOWN_PERSIST_EVERY: Duration = Duration::from_secs(60 * 60);

/// Whether an address says nothing about who is behind it: a local process or, under Tailcat, any tunnelled peer.
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
        || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
}

/// The key the store keeps a known source under.
pub fn source_bytes(ip: IpAddr) -> [u8; 16] {
    match source_key(ip) {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Who a refused enrollment is charged to in the store: a hash of the source key, so the audit log holds no address.
/// Behind a Tailcat helper every peer shares one source, so there this is a per-tunnel cap, not a per-node one.
pub fn peer_key(ip: IpAddr) -> [u8; 16] {
    let hash = blake3::hash(&source_bytes(ip));
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

fn source_from_bytes(bytes: [u8; 16]) -> IpAddr {
    source_key(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// IPv6 is counted per /64: the unit an attacker controls, so rotating low bits buys nothing.
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

fn stranger_ceiling(max_pending: usize) -> usize {
    max_pending - max_pending / 4
}

#[derive(Default)]
pub struct Pending {
    book: Mutex<Book>,
}

#[derive(Default)]
struct Book {
    total: usize,
    by_source: HashMap<IpAddr, usize>,
    known: HashMap<IpAddr, Known>,
}

#[derive(Clone, Copy)]
struct Known {
    seen: Instant,
    persisted: Option<Instant>,
}

impl Pending {
    /// A loopback source gets the whole pool: the address cannot tell tunnelled peers apart, so the
    /// reserve is closed to strangers later, at the hello, by `stranger_room`.
    pub fn enter(&self, ip: IpAddr, max_pending: usize, now: Instant) -> bool {
        let loopback = is_loopback(ip);
        let key = source_key(ip);
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        let known = loopback
            || book
                .known
                .get(&key)
                .is_some_and(|k| now.saturating_duration_since(k.seen) < KNOWN_TTL);
        let ceiling = if known {
            max_pending
        } else {
            stranger_ceiling(max_pending)
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

    /// Whether a connection that has completed its handshake as an unknown identity may go on: the
    /// reserve is for authenticated workers, so a stranger needs room in the unreserved part. The
    /// connection being asked about holds one slot itself.
    pub fn stranger_room(&self, max_pending: usize) -> bool {
        self.book.lock().unwrap_or_else(|p| p.into_inner()).total <= stranger_ceiling(max_pending)
    }

    /// Record that `ip` authenticated a worker. Returns the key to persist when the store should hear
    /// of it (first sight, or not written for an hour). Loopback is never recorded.
    pub fn vouch(&self, ip: IpAddr, now: Instant) -> Option<[u8; 16]> {
        if is_loopback(ip) {
            return None;
        }
        let key = source_key(ip);
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        if book.known.len() >= KNOWN_MAX && !book.known.contains_key(&key) {
            book.known
                .retain(|_, k| now.saturating_duration_since(k.seen) < KNOWN_TTL);
            if book.known.len() >= KNOWN_MAX {
                return None;
            }
        }
        let stale = book.known.get(&key).is_none_or(|k| {
            k.persisted
                .is_none_or(|at| now.saturating_duration_since(at) >= KNOWN_PERSIST_EVERY)
        });
        let persisted = if stale {
            Some(now)
        } else {
            book.known.get(&key).and_then(|k| k.persisted)
        };
        book.known.insert(
            key,
            Known {
                seen: now,
                persisted,
            },
        );
        stale.then(|| source_bytes(key))
    }

    /// Load sources stored by an earlier run: each `(key, age)` is how long ago it was last seen.
    pub fn restore(&self, sources: impl IntoIterator<Item = ([u8; 16], Duration)>, now: Instant) {
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        for (bytes, age) in sources {
            if book.known.len() >= KNOWN_MAX {
                break;
            }
            let ip = source_from_bytes(bytes);
            if age >= KNOWN_TTL || is_loopback(ip) {
                continue;
            }
            let Some(seen) = now.checked_sub(age) else {
                continue;
            };
            book.known.insert(
                ip,
                Known {
                    seen,
                    persisted: Some(seen),
                },
            );
        }
    }

    /// Sources currently vouched for (expired ones included until the next prune).
    pub fn known(&self) -> usize {
        self.book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .known
            .len()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.book.lock().unwrap_or_else(|p| p.into_inner()).total
    }
}

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

const ENROLL_SOURCE_BURST: u64 = 5;
const ENROLL_SOURCE_EVERY: Duration = Duration::from_secs(12);
/// Each refused secret writes an audit row on the single writer, so this bounds those writes.
const ENROLL_GLOBAL_BURST: u64 = 20;
const ENROLL_GLOBAL_EVERY: Duration = Duration::from_secs(3);
const ENROLL_SOURCES_MAX: usize = 4096;

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

/// Descriptors one session holds on the link: its socket and the clone its writer half uses.
pub const FDS_PER_SESSION: usize = 2;
/// Descriptors a session's attempt adds: an open log writer is two files. The store keeps at most
/// `MAX_OPEN_WRITERS` writers open and `MAX_SESSIONS` does not exceed it, so one pair per session bounds them all.
pub const LOG_FDS_PER_SESSION: usize = 2;
/// Descriptors outside any session: standard streams, the link and API listeners, the API's connection pool
/// (`CONNECTIONS` is 64), the database files, the object and log directories, the Tailcat helper's pipes and a margin
/// for outbound sockets (GitHub, mail, S3, checks).
pub const FD_BASE: usize = 192;
/// Fewer sessions than this is not a controller worth starting: refuse with a message instead.
pub const MIN_SESSIONS: usize = 16;

/// The descriptors the controller needs to hold `sessions` sessions at once: the fixed base plus a share per session,
/// so the headroom follows the configured session limit instead of a constant.
pub const fn descriptors_for(sessions: usize) -> usize {
    FD_BASE + sessions * (FDS_PER_SESSION + LOG_FDS_PER_SESSION)
}

/// How many sessions a soft descriptor limit holds, at most `wanted`; the pure half of [`session_cap`].
pub fn sessions_within(soft: u64, wanted: usize) -> usize {
    let usable = usize::try_from(soft)
        .unwrap_or(usize::MAX)
        .saturating_sub(FD_BASE)
        / (FDS_PER_SESSION + LOG_FDS_PER_SESSION);
    usable.min(wanted)
}

/// The session cap for the process's current soft descriptor limit. This only reads the limit: raising it is the
/// service's one startup decision (it owns the process), never a side effect of constructing a controller. A limit that
/// cannot hold [`MIN_SESSIONS`] fails with the numbers an operator needs instead of shedding every worker at runtime.
pub fn session_cap(wanted: usize) -> crate::Result<usize> {
    let Some(soft) = soft_limit() else {
        return Ok(wanted);
    };
    let cap = sessions_within(soft, wanted);
    if cap < MIN_SESSIONS.min(wanted) {
        return Err(crate::Error::Descriptors(format!(
            "the soft open-files limit is {soft}, which holds {cap} worker sessions; at least {} are required              ({} for {wanted}). Raise it (systemd: LimitNOFILE=, shell: ulimit -n) and restart",
            MIN_SESSIONS.min(wanted),
            descriptors_for(wanted),
        )));
    }
    Ok(cap)
}

/// The soft `RLIMIT_NOFILE`, `None` where it cannot be read or does not apply.
#[cfg(unix)]
pub fn soft_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` for the whole call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    Some(if limit.rlim_cur == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        limit.rlim_cur as u64
    })
}

#[cfg(not(unix))]
pub fn soft_limit() -> Option<u64> {
    None
}

pub fn accept_backoff(failures: u32) -> Duration {
    Duration::from_millis(10u64 << failures.min(5)).min(Duration::from_millis(250))
}

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
    fn the_descriptor_headroom_follows_the_session_limit() {
        assert_eq!(descriptors_for(0), FD_BASE);
        assert_eq!(descriptors_for(1024), FD_BASE + 1024 * 4);
        for wanted in [16, 100, 1024] {
            assert_eq!(
                sessions_within(descriptors_for(wanted) as u64, 4096),
                wanted
            );
            assert_eq!(
                sessions_within(descriptors_for(wanted) as u64 - 1, 4096),
                wanted - 1
            );
        }
        assert_eq!(sessions_within(u64::MAX, 1024), 1024);
        assert_eq!(sessions_within(100, 1024), 0, "below the base nothing fits");
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

    /// Fill the unreserved part of the pool with strangers, one share each; returns how many slots are held.
    fn fill_unreserved(pending: &Pending, now: Instant) -> usize {
        let mut taken = 0;
        'fill: for host in 1..=60u8 {
            for _ in 0..PENDING_PER_SOURCE {
                if !pending.enter(ip(host), 256, now) {
                    break 'fill;
                }
                taken += 1;
            }
        }
        taken
    }

    #[test]
    fn a_restart_restores_known_sources_so_the_reserve_still_admits_them() {
        use sentinel_store::{Durability, Store, known_sources};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
        let ttl = KNOWN_TTL.as_millis() as i64;
        let start = Instant::now();

        let before = Pending::default();
        let key = before.vouch(ip(200), start).expect("first sight is stored");
        assert!(
            before
                .vouch(ip(200), start + Duration::from_secs(600))
                .is_none(),
            "a source seen again within the hour is not rewritten"
        );
        assert!(
            before
                .vouch(
                    ip(200),
                    start + KNOWN_PERSIST_EVERY + Duration::from_secs(1)
                )
                .is_some(),
            "and is refreshed once the hour is past"
        );
        let seen_ms = 5_000_000;
        store
            .writer()
            .write(move |tx| known_sources::record(tx, key, seen_ms, ttl))
            .unwrap();

        // The controller restarts three hours later and reads the set back.
        let wall = seen_ms + 3 * 60 * 60 * 1000;
        let stored = store.read(|c| known_sources::load(c, wall, ttl)).unwrap();
        let after = Pending::default();
        let now = Instant::now();
        after.restore(
            stored
                .into_iter()
                .map(|(source, at)| (source, Duration::from_millis((wall - at) as u64))),
            now,
        );
        assert_eq!(after.known(), 1);
        assert_eq!(fill_unreserved(&after, now), 192);
        assert!(!after.enter(ip(100), 256, now), "a stranger is still shed");
        assert!(
            after.enter(ip(200), 256, now),
            "the restored worker enters the reserve"
        );

        let forgetful = Pending::default();
        assert_eq!(fill_unreserved(&forgetful, now), 192);
        assert!(
            !forgetful.enter(ip(200), 256, now),
            "without the stored set the same worker is shed"
        );
    }

    #[test]
    fn restoring_skips_what_is_past_the_day_and_never_stores_loopback() {
        let pending = Pending::default();
        let now = Instant::now() + KNOWN_TTL * 2;
        let fresh = source_bytes(ip(7));
        let old = source_bytes(ip(8));
        let local = source_bytes(IpAddr::from([127, 0, 0, 1]));
        pending.restore(
            [
                (fresh, Duration::from_secs(3600)),
                (old, KNOWN_TTL + Duration::from_secs(1)),
                (local, Duration::from_secs(1)),
            ],
            now,
        );
        assert_eq!(pending.known(), 1);
        assert!(pending.vouch(IpAddr::from([127, 0, 0, 1]), now).is_none());
        assert!(pending.vouch("::1".parse().unwrap(), now).is_none());
        assert!(
            pending
                .vouch("::ffff:127.0.0.1".parse().unwrap(), now)
                .is_none()
        );
        assert_eq!(pending.known(), 1);
    }

    #[test]
    fn peers_behind_a_loopback_tunnel_are_told_apart_by_identity_not_address() {
        let pending = Pending::default();
        let now = Instant::now();
        let tunnel = IpAddr::from([127, 0, 0, 1]);
        // A worker through the tunnel does not make the tunnel "known": nothing is stored for it, and
        // loopback needs no vouch to use the whole pool.
        assert!(pending.vouch(tunnel, now).is_none());
        for _ in 0..PENDING_PER_SOURCE * 32 {
            assert!(pending.enter(tunnel, 256, now));
        }
        // The pool is full of tunnelled handshakes; an identity that turns out to be unknown is shed at
        // the hello, while one the store knows is never asked.
        assert_eq!(pending.len(), 256);
        assert!(!pending.stranger_room(256));
        for _ in 0..64 {
            pending.leave(tunnel);
        }
        assert!(
            pending.stranger_room(256),
            "at the stranger ceiling it still has room"
        );
        pending.leave(tunnel);
        assert!(pending.stranger_room(256));
        // The same pool seen from a direct address keeps the reserve closed to strangers.
        let direct = Pending::default();
        assert_eq!(fill_unreserved(&direct, now), 192);
        assert!(!direct.enter(ip(100), 256, now));
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
