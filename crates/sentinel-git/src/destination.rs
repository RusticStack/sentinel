//! A manual remote is fetched by the worker from inside the network, so it must never reach internal hosts.
//! Every resolved address must be public, and Git is pinned to those addresses so DNS rebinding cannot redirect the fetch.
//! Git 2.37 or newer is required for the pin; an older or unreadable Git refuses the remote.
//! Names are resolved by a bounded `getent ahosts` subprocess; a missing or failing resolver refuses the remote.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sentinel_protocol::source::{https_host_port, manual_destination_listed, public_dns_name};

use crate::{Error, Result};

pub(crate) const UNREACHABLE: &str = "the manual remote was refused or could not be fetched";

const RESOLVE_LIMIT: Duration = Duration::from_secs(15);
const MAX_PINNED: usize = 16;
const RESOLVE_OUTPUT: usize = 256 * 1024;

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

/// Only a successfully parsed probe is cached: a missing, slow or garbled `git --version` is
/// a transient condition that must not refuse every later manual remote for the process life.
fn git_can_pin() -> bool {
    static CAN: OnceLock<bool> = OnceLock::new();
    can_pin_cached(&CAN, probe_git_version)
}

fn can_pin_cached(cell: &OnceLock<bool>, probe: impl FnOnce() -> Option<(u32, u32)>) -> bool {
    if let Some(known) = cell.get() {
        return *known;
    }
    match probe() {
        Some(version) => *cell.get_or_init(|| version >= (2, 37)),
        None => false,
    }
}

fn probe_git_version() -> Option<(u32, u32)> {
    let mut cmd = crate::unix::git(Path::new("/"));
    cmd.arg("--version");
    crate::unix::run(cmd, Instant::now() + Duration::from_secs(10), "git version")
        .ok()
        .filter(crate::unix::Output::success)
        .and_then(|o| parse_version(&String::from_utf8_lossy(&o.stdout)))
}

/// The resolver runs as a child in its own process group under the same deadline, cancel and
/// output controls as every other subprocess, so a hung resolver is killed rather than left
/// blocking a detached thread.
fn getent_command(host: &str) -> Command {
    let mut cmd = Command::new("getent");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LC_ALL", "C")
        .current_dir("/")
        .arg("ahosts")
        .arg(host);
    cmd
}

/// Every non-blank line must start with an address; anything else fails closed. IPv4-mapped
/// forms are folded to IPv4 so the pin and the classification see the same address.
fn parse_ahosts(text: &str) -> Option<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let ip: IpAddr = line.split_whitespace().next()?.parse().ok()?;
        ips.push(match ip {
            IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        });
    }
    Some(ips)
}

fn lookup(command: Command, deadline: Instant) -> Result<Vec<IpAddr>> {
    let until = deadline.min(Instant::now() + RESOLVE_LIMIT);
    let output = crate::unix::run_capped(command, until, "resolve", Some(RESOLVE_OUTPUT))
        .map_err(|_| refused())?;
    if !output.success() {
        return Err(refused());
    }
    parse_ahosts(&String::from_utf8_lossy(&output.stdout)).ok_or_else(refused)
}

fn resolve(host: &str, deadline: Instant) -> Result<Vec<IpAddr>> {
    if host.starts_with('-') {
        return Err(refused());
    }
    lookup(getent_command(host), deadline)
}

pub(crate) fn pin(remote: &str, deadline: Instant) -> Result<Option<String>> {
    pin_with(remote, deadline, git_can_pin, resolve)
}

fn pin_with(
    remote: &str,
    deadline: Instant,
    can_pin: impl FnOnce() -> bool,
    resolve: impl FnOnce(&str, Instant) -> Result<Vec<IpAddr>>,
) -> Result<Option<String>> {
    if !remote.starts_with("https://") {
        return Ok(None);
    }
    if manual_destination_listed(remote) {
        return Ok(None);
    }
    let (host, port) = https_host_port(remote).ok_or_else(refused)?;
    if !public_dns_name(host) || !can_pin() {
        return Err(refused());
    }
    let mut ips = resolve(host, deadline)?;
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

    fn refusal_message(result: Result<Option<String>>) -> String {
        let Err(Error::Preparation(message)) = result else {
            panic!("expected a refusal, got {result:?}");
        };
        message
    }

    #[test]
    fn a_failed_version_probe_is_retried_and_only_a_parsed_one_is_cached() {
        let cell = OnceLock::new();
        let mut probes = 0;
        assert!(!can_pin_cached(&cell, || {
            probes += 1;
            None
        }));
        assert!(!can_pin_cached(&cell, || {
            probes += 1;
            None
        }));
        assert!(cell.get().is_none(), "a failure must not latch");
        assert!(can_pin_cached(&cell, || {
            probes += 1;
            Some((2, 43))
        }));
        assert!(can_pin_cached(&cell, || panic!(
            "a cached success is not probed again"
        )));
        assert_eq!(probes, 3);
    }

    #[test]
    fn an_old_parsed_version_is_a_stable_refusal() {
        let cell = OnceLock::new();
        assert!(!can_pin_cached(&cell, || Some((2, 30))));
        assert!(!can_pin_cached(&cell, || panic!(
            "an old version is cached"
        )));
    }

    #[test]
    fn ahosts_output_is_parsed_strictly_and_mapped_forms_fold_to_v4() {
        let text = "93.184.216.34   STREAM example.com
93.184.216.34   DGRAM

                    2606:2800:220:1::1 STREAM example.com
::ffff:1.2.3.4 STREAM x
";
        assert_eq!(
            parse_ahosts(text),
            Some(vec![
                v4("93.184.216.34"),
                v4("93.184.216.34"),
                v6("2606:2800:220:1::1"),
                v4("1.2.3.4"),
            ])
        );
        assert_eq!(parse_ahosts(""), Some(vec![]));
        assert_eq!(
            parse_ahosts(
                "getent: error
"
            ),
            None
        );
        assert_eq!(
            parse_ahosts(
                "93.184.216.34 STREAM
not-an-ip STREAM
"
            ),
            None
        );
    }

    #[test]
    fn pin_uses_injected_helpers_and_refuses_one_private_answer() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let remote = "https://git.example.org:8443/r.git";
        let pinned = pin_with(
            remote,
            deadline,
            || true,
            |host, _| {
                assert_eq!(host, "git.example.org");
                Ok(vec![
                    v4("93.184.216.34"),
                    v4("93.184.216.34"),
                    v6("2606:4700::1"),
                ])
            },
        );
        assert_eq!(
            pinned.unwrap().as_deref(),
            Some("+git.example.org:8443:93.184.216.34,[2606:4700::1]")
        );
        let mixed = pin_with(
            remote,
            deadline,
            || true,
            |_, _| Ok(vec![v4("93.184.216.34"), v4("10.0.0.1")]),
        );
        assert_eq!(refusal_message(mixed), UNREACHABLE);
        let empty = pin_with(remote, deadline, || true, |_, _| Ok(vec![]));
        assert_eq!(refusal_message(empty), UNREACHABLE);
        let old_git = pin_with(
            remote,
            deadline,
            || false,
            |_, _| panic!("no lookup without a pin"),
        );
        assert_eq!(refusal_message(old_git), UNREACHABLE);
        let failed = pin_with(remote, deadline, || true, |_, _| Err(refused()));
        assert_eq!(refusal_message(failed), UNREACHABLE);
    }

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        cmd
    }

    #[test]
    fn lookup_reads_a_resolver_answer_and_rejects_failures() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let found = lookup(
            sh("echo '93.184.216.34 STREAM h'; echo '93.184.216.34 DGRAM'"),
            deadline,
        );
        assert_eq!(
            found.unwrap(),
            vec![v4("93.184.216.34"), v4("93.184.216.34")]
        );
        for script in ["exit 2", "echo garbage", "echo 93.184.216.34; exit 1"] {
            assert!(lookup(sh(script), deadline).is_err(), "{script}");
        }
        assert!(lookup(Command::new("/nonexistent/getent"), deadline).is_err());
    }

    #[test]
    fn a_flooding_resolver_is_cut_off_at_the_output_cap() {
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(lookup(sh("yes 93.184.216.34"), deadline).is_err());
    }

    #[cfg(target_os = "linux")]
    fn threads() -> usize {
        std::fs::read_dir("/proc/self/task").unwrap().count()
    }

    #[cfg(target_os = "linux")]
    fn alive(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat
                .rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z'),
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_hung_resolver_is_killed_at_the_deadline_and_leaves_no_thread_or_process() {
        let dir = tempfile::tempdir().unwrap();
        let before = threads();
        let mut children = Vec::new();
        for n in 0..12 {
            let pidfile = dir.path().join(format!("pid{n}"));
            let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
            let started = Instant::now();
            let result = lookup(sh(&script), Instant::now() + Duration::from_millis(400));
            assert!(result.is_err());
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{:?}",
                started.elapsed()
            );
            let pid: i32 = std::fs::read_to_string(&pidfile)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            children.push(pid);
        }
        let until = Instant::now() + Duration::from_secs(5);
        while children.iter().any(|pid| alive(*pid)) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            children.iter().all(|pid| !alive(*pid)),
            "resolver descendants survived: {children:?}"
        );
        let grown = threads().saturating_sub(before);
        assert!(grown < 6, "{grown} threads left behind by 12 hung lookups");
    }
}
