//! Admission for the unauthenticated OAuth endpoints (O02/O03): bounded,
//! and fair enough that one client cannot take every other client's turn.
//!
//! Each [`Budget`] is a [`Limiter`]: a per-client bucket in a bounded map,
//! checked first, then an optional deployment-wide ceiling. A client that
//! floods is refused by its own bucket and never spends the ceiling, so it
//! cannot starve anyone else. The token endpoint (refresh, code exchange,
//! device polling) has a budget of its own, so flooding revocation or
//! device authorization cannot stop anyone's refresh. Device authorization
//! also passes a slow per-client bucket, which bounds how much of the
//! deployment's pending-request cap one client can hold.
//!
//! Buckets are GCRA (a theoretical arrival time per bucket): exact at any
//! arrival rate — nothing is lost to rounding when requests come less than a
//! millisecond apart — and one `Instant` of state. A bucket whose arrival
//! time has passed is indistinguishable from a new one, so dropping it loses
//! nothing; that is what keeps the map bounded without forgetting a flood.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// A rate: one admission per `interval`, with `burst` back to back.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rate {
    interval: Duration,
    /// How far ahead of now a bucket's arrival time may run: `burst - 1`
    /// intervals.
    tolerance: Duration,
}

impl Rate {
    pub(crate) const fn new(interval: Duration, burst: u32) -> Rate {
        let burst = if burst == 0 { 1 } else { burst };
        Rate {
            interval,
            tolerance: Duration::from_nanos(interval.as_nanos() as u64 * (burst as u64 - 1)),
        }
    }

    /// `per_sec` admissions per second, `burst` back to back.
    pub(crate) const fn per_sec(per_sec: u64, burst: u32) -> Rate {
        Rate::new(Duration::from_nanos(1_000_000_000 / per_sec), burst)
    }
}

/// One GCRA bucket.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bucket {
    /// The theoretical arrival time of the next admission.
    tat: Instant,
}

impl Bucket {
    pub(crate) fn new(now: Instant) -> Bucket {
        Bucket { tat: now }
    }

    /// Admit one request at `now` under `rate`.
    pub(crate) fn take(&mut self, now: Instant, rate: Rate) -> bool {
        let tat = self.tat.max(now);
        if tat.saturating_duration_since(now) > rate.tolerance {
            return false;
        }
        self.tat = tat + rate.interval;
        true
    }

    /// Whether this bucket is back to a new bucket's state.
    fn idle(&self, now: Instant) -> bool {
        self.tat <= now
    }
}

/// Clients tracked per budget. Past it, new clients share one overflow
/// bucket at the per-client rate until the map has room again.
pub(crate) const MAX_CLIENTS: usize = 4096;
/// Least time between two sweeps of a full map.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// A per-client bucket map with an optional deployment-wide ceiling.
pub(crate) struct Limiter {
    client_rate: Rate,
    ceiling: Option<(Bucket, Rate)>,
    clients: HashMap<u128, Bucket>,
    overflow: Bucket,
    swept: Instant,
}

impl Limiter {
    pub(crate) fn new(client_rate: Rate, ceiling: Option<Rate>, now: Instant) -> Limiter {
        Limiter {
            client_rate,
            ceiling: ceiling.map(|rate| (Bucket::new(now), rate)),
            clients: HashMap::new(),
            overflow: Bucket::new(now),
            swept: now,
        }
    }

    /// Admit one request from `client` at `now`: its own bucket first, then
    /// the ceiling. A refusal by its own bucket spends nothing shared.
    pub(crate) fn admit(&mut self, client: u128, now: Instant) -> bool {
        let rate = self.client_rate;
        let own = match self.clients.get_mut(&client) {
            Some(bucket) => bucket.take(now, rate),
            None => {
                if self.clients.len() >= MAX_CLIENTS
                    && now.saturating_duration_since(self.swept) >= SWEEP_INTERVAL
                {
                    self.swept = now;
                    self.clients.retain(|_, bucket| !bucket.idle(now));
                }
                if self.clients.len() < MAX_CLIENTS {
                    let mut bucket = Bucket::new(now);
                    let admitted = bucket.take(now, rate);
                    self.clients.insert(client, bucket);
                    admitted
                } else {
                    self.overflow.take(now, rate)
                }
            }
        };
        if !own {
            return false;
        }
        match &mut self.ceiling {
            Some((bucket, rate)) => bucket.take(now, *rate),
            None => true,
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.clients.len()
    }
}

/// A network whose peers are the deployment's reverse proxy: a request from
/// one is counted under the address its `X-Forwarded-For` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    /// Loopback only, `127.0.0.0/8` and `::1/128`: the default, right for a
    /// proxy on the controller's own host.
    pub fn loopback() -> Vec<TrustedProxy> {
        vec![
            TrustedProxy {
                network: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 0)),
                prefix: 8,
            },
            TrustedProxy {
                network: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                prefix: 128,
            },
        ]
    }

    /// `ADDRESS` or `ADDRESS/PREFIX` (CIDR). Host bits must be zero, so a
    /// typo cannot silently widen or shift the network.
    pub fn parse(text: &str) -> Option<TrustedProxy> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address.parse().ok()?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 3 => {
                p.parse::<u8>().ok().filter(|p| *p <= width)?
            }
            Some(_) => return None,
        };
        let proxy = TrustedProxy { network, prefix };
        (proxy.masked(network) == network).then_some(proxy)
    }

    fn masked(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4((u32::from(v4) & mask).into())
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(v6) & mask).into())
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.network.is_ipv4() && self.masked(ip) == self.network
    }
}

/// The key a client is counted under. IPv6 clients are counted per /64,
/// the smallest block a single subscriber is normally given, so one host
/// cannot mint itself fresh buckets from its own prefix.
///
/// A request that arrives from a configured `trusted` proxy network is
/// counted under the last address in its `X-Forwarded-For`, which that
/// proxy appended. Any other request is counted under its own address,
/// whatever headers it carries, so a client reaching the server directly —
/// from the internet or from a neighbouring private host — cannot choose
/// its own key.
pub(crate) fn client_key(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted: &[TrustedProxy],
) -> u128 {
    let peer = peer.map(canonical);
    let via_proxy = peer.is_some_and(|ip| trusted.iter().any(|proxy| proxy.contains(ip)));
    let client = match (via_proxy, forwarded_for) {
        (true, Some(header)) => header
            .rsplit(',')
            .next()
            .and_then(|last| last.trim().parse::<IpAddr>().ok())
            .map(canonical)
            .or(peer),
        _ => peer,
    };
    match client {
        None => 0,
        Some(IpAddr::V4(v4)) => u128::from(u32::from(v4)),
        // The /64 prefix, tagged so it can never equal an IPv4 key.
        Some(IpAddr::V6(v6)) => (u128::from(v6) & !0xffff_ffff_ffff_ffff) | 1,
    }
}

/// IPv4-mapped IPv6 addresses count as the IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: Rate = Rate::per_sec(20, 40);

    #[test]
    fn a_bucket_admits_a_burst_then_the_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        for _ in 0..40 {
            assert!(bucket.take(start, RATE));
        }
        assert!(!bucket.take(start, RATE));
        // 50 ms at 20/s is one admission.
        assert!(bucket.take(start + Duration::from_millis(50), RATE));
        assert!(!bucket.take(start + Duration::from_millis(50), RATE));
        assert!(bucket.take(start + Duration::from_secs(60), RATE));
    }

    /// The old bucket credited whole milliseconds and then reset its clock,
    /// so arrivals under a millisecond apart never refilled it.
    #[test]
    fn sub_millisecond_arrivals_still_refill_at_the_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::new(start);
        let admitted = (0..2000u32)
            .filter(|n| bucket.take(start + Duration::from_micros(500) * *n, RATE))
            .count();
        // One second of arrivals: the burst of 40 plus 20 per second.
        assert!((59..=61).contains(&admitted), "{admitted}");
    }

    #[test]
    fn a_flooding_client_does_not_spend_anyone_elses_turn() {
        let start = Instant::now();
        let mut limiter = Limiter::new(Rate::per_sec(5, 10), Some(RATE), start);
        let (flood, other) = (1u128, 2u128);
        let mut flooded = 0;
        for n in 0..10_000u32 {
            if limiter.admit(flood, start + Duration::from_micros(100) * n) {
                flooded += 1;
            }
        }
        // One second: its own burst of 10 plus 5 per second.
        assert!(flooded <= 16, "{flooded}");
        assert!(limiter.admit(other, start + Duration::from_secs(1)));
    }

    #[test]
    fn the_client_map_stays_bounded_and_forgets_only_idle_buckets() {
        let start = Instant::now();
        let mut limiter = Limiter::new(Rate::per_sec(5, 10), None, start);
        for n in 0..(MAX_CLIENTS as u128 + 100) {
            limiter.admit(n + 10, start);
        }
        assert!(limiter.tracked() <= MAX_CLIENTS);
        // A second later every bucket above has refilled: a new client
        // triggers one sweep and gets its own bucket.
        let later = start + Duration::from_secs(2);
        assert!(limiter.admit(1, later));
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn keys_trust_forwarding_only_from_a_proxy_address() {
        let trusted = TrustedProxy::loopback();
        let key = |peer: IpAddr, via| client_key(Some(peer), via, &trusted);
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "203.0.113.9".parse().unwrap();
        let via = Some("198.51.100.1, 198.51.100.7");
        assert_eq!(key(local, via), key("198.51.100.7".parse().unwrap(), None));
        assert_eq!(key(public, via), key(public, None));
        assert_eq!(key(local, None), key(local, Some("junk")));
        // One IPv6 /64 is one client; a mapped IPv4 address is that address.
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(key(a, None), key(b, None));
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert_eq!(key(mapped, None), key(public, None));
    }

    /// P09S-9: a neighbour on a private network reaching the listener
    /// directly is not the proxy, and cannot mint keys through the header.
    #[test]
    fn private_peers_are_proxies_only_when_configured() {
        let neighbour: IpAddr = "10.0.0.7".parse().unwrap();
        let spoofed = Some("198.51.100.7");
        let loopback = TrustedProxy::loopback();
        assert_eq!(
            client_key(Some(neighbour), spoofed, &loopback),
            client_key(Some(neighbour), None, &loopback)
        );
        let configured = [TrustedProxy::parse("10.0.0.0/24").unwrap()];
        assert_eq!(
            client_key(Some(neighbour), spoofed, &configured),
            client_key(Some("198.51.100.7".parse().unwrap()), None, &configured)
        );
        let outside: IpAddr = "10.0.1.7".parse().unwrap();
        assert_eq!(
            client_key(Some(outside), spoofed, &configured),
            client_key(Some(outside), None, &configured)
        );
        assert_eq!(
            TrustedProxy::parse("fd00::/8"),
            Some(TrustedProxy {
                network: "fd00::".parse().unwrap(),
                prefix: 8
            })
        );
        assert!(TrustedProxy::parse("::1").is_some());
        for bad in [
            "10.0.0.1/24",
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "x",
            "",
        ] {
            assert!(TrustedProxy::parse(bad).is_none(), "{bad}");
        }
    }
}
