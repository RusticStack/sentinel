//! Destination policy for a manual (unbound) remote.
//!
//! A client with the run permission names the remote of an unbound
//! repository, and the worker fetches it from inside the deployment's
//! network. Without a policy that is a probe of internal HTTPS endpoints
//! (cloud metadata at 169.254.169.254, loopback services, RFC 1918 hosts).
//! The controller refuses non-public names at admission
//! (`sentinel_protocol::source::manual_destination_allowed`); this module is
//! the worker's own check, which a spec that bypassed the API still meets:
//!
//! 1. the host must be a public DNS name — never an IP literal in any
//!    notation, never a bare hostname;
//! 2. the name is resolved here and **every** address must be public;
//! 3. Git is then told to connect to exactly those addresses
//!    (`http.curloptResolve`), so a second, different DNS answer — rebinding
//!    — cannot redirect the connection after the check. That option exists
//!    from Git 2.37; an older Git (or one whose version cannot be read)
//!    refuses the manual remote rather than fetch it unpinned.
//!
//! A deployment-allowlisted authority
//! (`sentinel_protocol::source::MANUAL_DESTINATIONS_ENV`) skips all three.
//! Every refusal and every failure of an unbound remote surfaces as the one
//! [`UNREACHABLE`] message, so neither the policy nor Git's own stderr is an
//! oracle for what the worker's network can reach.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use sentinel_protocol::source::{https_host_port, manual_destination_listed, public_dns_name};

use crate::{Error, Result};

/// The only diagnostic an unbound remote's refusal or fetch failure carries.
pub(crate) const UNREACHABLE: &str = "the manual remote was refused or could not be fetched";

/// Longest the name lookup may take, within the checkout's own deadline.
const RESOLVE_LIMIT: Duration = Duration::from_secs(15);
/// Addresses pinned for one host; a larger answer is truncated, not refused.
const MAX_PINNED: usize = 16;

fn refused() -> Error {
    Error::Preparation(UNREACHABLE.into())
}

/// Whether `ip` is a globally routable unicast address.
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => public_v6(a),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && o[1] & 0xc0 == 64) // 100.64.0.0/10 shared address space
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 protocol assignments
        || (o[0] == 198 && o[1] & 0xfe == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // reserved
}

fn public_v6(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = a.segments();
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || s[0] & 0xfe00 == 0xfc00 // fc00::/7 unique local
        || s[0] & 0xffc0 == 0xfe80 // fe80::/10 link local
        || s[0] & 0xffc0 == 0xfec0 // fec0::/10 site local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0100 && s[1..4] == [0; 3]) // 100::/64 discard
        || s[..6] == [0; 6]
    // ::/96 IPv4-compatible (deprecated)
    {
        return false;
    }
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4 address that
    // must itself be public.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return public_v4(embedded(s[6], s[7]));
    }
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return false; // 64:ff9b:1::/48 local-use NAT64
    }
    if s[0] == 0x2002 {
        return public_v4(embedded(s[1], s[2]));
    }
    true
}

/// Parse `git version 2.39.5` (or a vendor-suffixed variant) into
/// `(major, minor)`.
fn parse_version(output: &str) -> Option<(u32, u32)> {
    let version = output.trim().strip_prefix("git version ")?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor))
}

/// Whether the installed Git honors `http.curloptResolve` (2.37). Decided
/// once per process; an unreadable version fails closed.
fn git_can_pin() -> bool {
    static CAN: OnceLock<bool> = OnceLock::new();
    *CAN.get_or_init(|| {
        let mut cmd = crate::unix::git(Path::new("/"));
        cmd.arg("--version");
        crate::unix::run(cmd, Instant::now() + Duration::from_secs(10), "git version")
            .ok()
            .filter(crate::unix::Output::success)
            .and_then(|o| parse_version(&String::from_utf8_lossy(&o.stdout)))
            .is_some_and(|v| v >= (2, 37))
    })
}

/// Judge the destination of a manual `remote` and return the
/// `http.curloptResolve` value that pins Git's connection to the addresses
/// judged, or `None` when no pin applies (a local path, which the controller
/// refuses as a client-named source, or an allowlisted authority).
pub(crate) fn pin(remote: &str, deadline: Instant) -> Result<Option<String>> {
    if !remote.starts_with("https://") {
        return Ok(None);
    }
    if manual_destination_listed(remote) {
        return Ok(None);
    }
    let (host, port) = https_host_port(remote).ok_or_else(refused)?;
    if !public_dns_name(host) || !git_can_pin() {
        return Err(refused());
    }
    let (tx, rx) = mpsc::channel();
    let name = host.to_owned();
    std::thread::spawn(move || {
        let _ = tx.send(
            (name.as_str(), port)
                .to_socket_addrs()
                .map(|found| found.map(|a| a.ip()).collect::<Vec<_>>()),
        );
    });
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .min(RESOLVE_LIMIT);
    let mut ips = match rx.recv_timeout(wait) {
        Ok(Ok(ips)) => ips,
        _ => return Err(refused()),
    };
    ips.sort_unstable();
    ips.dedup();
    ips.truncate(MAX_PINNED);
    if ips.is_empty() || !ips.iter().all(|ip| public_ip(*ip)) {
        return Err(refused());
    }
    let list: Vec<String> = ips
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => format!("[{a}]"),
        })
        .collect();
    Ok(Some(format!("+{host}:{port}:{}", list.join(","))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn only_global_unicast_addresses_are_public() {
        for ok in [
            "93.184.216.34",
            "140.82.112.3",
            "8.8.8.8",
            "2606:4700::6810:85e5",
        ] {
            let ip: IpAddr = ok.parse().unwrap();
            assert!(public_ip(ip), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "2002:a9fe:a9fe::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!public_ip(ip), "{bad}");
        }
        assert!(public_ip(v4("1.1.1.1")) && public_ip(v6("64:ff9b::101:101")));
    }

    #[test]
    fn git_versions_parse_and_compare() {
        assert_eq!(parse_version("git version 2.39.5\n"), Some((2, 39)));
        assert_eq!(
            parse_version("git version 2.50.1 (Apple Git-155)"),
            Some((2, 50))
        );
        assert_eq!(parse_version("git version 2.37.0.windows.1"), Some((2, 37)));
        assert_eq!(parse_version("not git"), None);
    }

    #[test]
    fn internal_hosts_are_refused_before_any_lookup() {
        let deadline = Instant::now() + Duration::from_secs(5);
        for remote in [
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1:8443/repo.git",
            "https://metadata/computeMetadata/v1",
            "https://localhost/repo.git",
            "https://printer.local/repo.git",
        ] {
            let Err(Error::Preparation(message)) = pin(remote, deadline) else {
                panic!("{remote} must be refused");
            };
            assert_eq!(message, UNREACHABLE);
        }
        // A local path is the controller's concern, not a network destination.
        assert!(matches!(pin("/srv/repo.git", deadline), Ok(None)));
    }
}
