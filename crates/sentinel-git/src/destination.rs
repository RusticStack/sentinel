//! A manual remote is fetched by the worker from inside the network, so it must never reach internal hosts.
//! Every resolved address must be public, and Git is pinned to those addresses so DNS rebinding cannot redirect the fetch.
//! Git 2.37 or newer is required for the pin; an older or unreadable Git refuses the remote.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use sentinel_protocol::source::{https_host_port, manual_destination_listed, public_dns_name};

use crate::{Error, Result};

pub(crate) const UNREACHABLE: &str = "the manual remote was refused or could not be fetched";

const RESOLVE_LIMIT: Duration = Duration::from_secs(15);
const MAX_PINNED: usize = 16;

fn refused() -> Error {
    Error::Preparation(UNREACHABLE.into())
}

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
        || (o[0] == 100 && o[1] & 0xc0 == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && o[1] & 0xfe == 18)
        || o[0] >= 240)
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
        || s[0] & 0xfe00 == 0xfc00
        || s[0] & 0xffc0 == 0xfe80
        || s[0] & 0xffc0 == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x0100 && s[1..4] == [0; 3])
        || s[..6] == [0; 6]
    {
        return false;
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return public_v4(embedded(s[6], s[7]));
    }
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return false;
    }
    if s[0] == 0x2002 {
        return public_v4(embedded(s[1], s[2]));
    }
    true
}

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
        assert!(matches!(pin("/srv/repo.git", deadline), Ok(None)));
    }
}
