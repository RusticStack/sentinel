//! The network of a microVM job (plan 16.8, TODO M05).
//!
//! A job has no network unless the worker's operator sets `job_network = "egress"`, as for containers. Then
//! the VM gets one virtio-net interface backed by a tap device, all of it inside the VM's own network
//! namespace (created rootless by `podman unshare` + `unshare --mount --net`, so no host interface, bridge or rule is
//! touched and the tap goes away with the VM):
//!
//! ```text
//! guest eth0 10.211.0.2 --- vmtap 10.211.0.1 [ netns: nftables forward + masquerade ] --- pasta tap --- host
//! ```
//!
//! `pasta` (the same helper `--network pasta:--no-map-gw` uses for containers) is attached to the namespace
//! from outside and forwards the namespace's outbound connections through the worker account's sockets. The
//! namespace's nftables rules ([`Policy::rules`]) are what give the guest the container policy: it may open
//! connections outward, but not to the host's own addresses, loopback, link-local and metadata addresses, or the
//! controller's link endpoint, and it cannot speak IPv6 or reach the namespace itself.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// The tap device inside the VM's network namespace.
pub const TAP: &str = "vmtap";
/// The namespace's side of the tap: the guest's gateway.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 211, 0, 1);
/// The guest's address. The same in every VM: each VM has a network namespace of its own.
pub const GUEST: Ipv4Addr = Ipv4Addr::new(10, 211, 0, 2);
pub const PREFIX: u8 = 30;
/// The resolver address the guest is given. `pasta --dns-forward` answers it with the host's resolver, so the
/// guest needs no route to the host's resolver address itself. TEST-NET-1 never names a real host.
pub const DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
pub const GUEST_MAC: &str = "06:00:0a:d3:00:02";

/// What a guest may never reach, whatever the operator grants: the unspecified, loopback, link-local (which
/// holds the cloud metadata endpoints 169.254.169.254 and 169.254.170.2), Alibaba Cloud's metadata address,
/// the IETF protocol block (192.0.0.192 is a metadata address on some clouds), multicast, reserved and
/// broadcast ranges, and the VM's own link.
const ALWAYS_DENIED: [(Ipv4Addr, u8); 8] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 211, 0, 0), 30),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(100, 100, 100, 200), 32),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// The worker's own endpoints a guest must not reach, supplied by the operator's configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Guard {
    /// Where the worker dials the controller (its configured address, and the local forward when the link goes
    /// through the Tailcat helper). The IPv4 ones are refused by address and port; an IPv6 endpoint needs no
    /// rule because a guest has no IPv6.
    pub link: Vec<SocketAddr>,
}

/// The destinations a granted guest is refused, as an nftables rule set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    nets: BTreeSet<(u32, u8)>,
    endpoints: BTreeSet<(u32, u16)>,
}

impl Policy {
    /// The built-in refusals, every address the host itself holds (a guest reaching one would reach a service
    /// of the host through the worker account's sockets) and the worker's guarded endpoints.
    pub fn new(host_addresses: &[Ipv4Addr], guard: &Guard) -> Policy {
        let mut nets: BTreeSet<(u32, u8)> = ALWAYS_DENIED
            .iter()
            .map(|(addr, prefix)| (u32::from(*addr), *prefix))
            .collect();
        nets.extend(host_addresses.iter().map(|addr| (u32::from(*addr), 32)));
        // An interval set refuses overlapping intervals, so a network inside another one is dropped.
        let all: Vec<(u32, u8)> = nets.iter().copied().collect();
        nets.retain(|&(addr, prefix)| {
            !all.iter()
                .any(|&(other, wider)| wider < prefix && addr & mask(wider) == other & mask(wider))
        });
        let endpoints = guard
            .link
            .iter()
            .filter_map(|endpoint| match endpoint {
                SocketAddr::V4(v4) => Some((u32::from(*v4.ip()), v4.port())),
                SocketAddr::V6(_) => None,
            })
            .collect();
        Policy { nets, endpoints }
    }

    /// The nftables script the VM's namespace loads before the VMM starts: the guest's connections go outward
    /// through the namespace (masqueraded behind the namespace's own address) unless they are refused.
    pub fn rules(&self) -> String {
        let mut nets = String::new();
        for (addr, prefix) in &self.nets {
            if !nets.is_empty() {
                nets.push_str(", ");
            }
            let _ = write!(nets, "{}/{}", Ipv4Addr::from(*addr), prefix);
        }
        let mut endpoints = String::new();
        for (addr, port) in &self.endpoints {
            if !endpoints.is_empty() {
                endpoints.push_str(", ");
            }
            let _ = write!(endpoints, "{} . {}", Ipv4Addr::from(*addr), port);
        }
        let mut out = String::new();
        let _ = writeln!(out, "table ip sentinel_vm {{");
        let _ = writeln!(out, "\tset denied_nets {{");
        let _ = writeln!(out, "\t\ttype ipv4_addr");
        let _ = writeln!(out, "\t\tflags interval");
        let _ = writeln!(out, "\t\telements = {{ {nets} }}");
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "\tset denied_endpoints {{");
        let _ = writeln!(out, "\t\ttype ipv4_addr . inet_service");
        if !endpoints.is_empty() {
            let _ = writeln!(out, "\t\telements = {{ {endpoints} }}");
        }
        let _ = writeln!(out, "\t}}");
        // The namespace itself offers the guest nothing.
        let _ = writeln!(out, "\tchain input {{");
        let _ = writeln!(
            out,
            "\t\ttype filter hook input priority filter; policy accept;"
        );
        let _ = writeln!(out, "\t\tiifname \"{TAP}\" drop");
        let _ = writeln!(out, "\t}}");
        // Forwarding is closed unless a rule below opens it, and the guest speaks only as its own address.
        let _ = writeln!(out, "\tchain forward {{");
        let _ = writeln!(
            out,
            "\t\ttype filter hook forward priority filter; policy drop;"
        );
        let _ = writeln!(out, "\t\tct state established,related accept");
        let _ = writeln!(
            out,
            "\t\tiifname \"{TAP}\" ip saddr {GUEST} ip daddr {DNS} meta l4proto {{ udp, tcp }} th dport 53 accept"
        );
        let _ = writeln!(out, "\t\tiifname \"{TAP}\" ip daddr @denied_nets drop");
        let _ = writeln!(
            out,
            "\t\tiifname \"{TAP}\" ip daddr . th dport @denied_endpoints drop"
        );
        let _ = writeln!(
            out,
            "\t\tiifname \"{TAP}\" oifname != \"{TAP}\" ip saddr {GUEST} accept"
        );
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "\tchain postrouting {{");
        let _ = writeln!(
            out,
            "\t\ttype nat hook postrouting priority srcnat; policy accept;"
        );
        let _ = writeln!(
            out,
            "\t\tiifname \"{TAP}\" oifname != \"{TAP}\" ip saddr {GUEST} masquerade"
        );
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "}}");
        // A guest has no IPv6: nothing is forwarded and the namespace answers nothing.
        let _ = writeln!(out, "table ip6 sentinel_vm6 {{");
        let _ = writeln!(out, "\tchain input {{");
        let _ = writeln!(
            out,
            "\t\ttype filter hook input priority filter; policy accept;"
        );
        let _ = writeln!(out, "\t\tiifname \"{TAP}\" drop");
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "\tchain forward {{");
        let _ = writeln!(
            out,
            "\t\ttype filter hook forward priority filter; policy drop;"
        );
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "}}");
        out
    }
}

fn mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

/// The IPv4 addresses of the host's interfaces, loopback included.
pub fn host_addresses() -> io::Result<Vec<Ipv4Addr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a linked list that freeifaddrs releases below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is a node of the list getifaddrs returned, valid until freeifaddrs.
        let entry = unsafe { &*at };
        if !entry.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr whose family says how to read the rest of it.
            let family = unsafe { (*entry.ifa_addr).sa_family };
            if i32::from(family) == libc::AF_INET {
                // SAFETY: an AF_INET sockaddr is a sockaddr_in.
                let sin = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                out.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: `list` came from getifaddrs and is not used after this.
    unsafe { libc::freeifaddrs(list) };
    out.sort();
    out.dedup();
    Ok(out)
}

/// The tools a VM with a network needs.
const TOOLS: [&str; 3] = ["ip", "nft", "pasta"];

/// The tools of `tools` that no directory of `dirs` holds as an executable file.
fn missing_in(dirs: &[PathBuf], tools: &[&str]) -> Vec<String> {
    tools
        .iter()
        .filter(|tool| {
            !dirs.iter().any(|dir| {
                fs::metadata(dir.join(tool))
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
        })
        .map(|tool| (*tool).to_owned())
        .collect()
}

/// What a VM with a network needs that this host lacks (`ip`, `nft`, `pasta` on the worker's `PATH` or in the
/// system directories the launch script adds, and `/dev/net/tun`), for a start-up warning: a VM that cannot set
/// its network up fails its start with the script's error.
pub fn missing_prerequisites() -> Vec<String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    dirs.extend(["/usr/sbin", "/sbin"].map(PathBuf::from));
    let mut missing = missing_in(&dirs, &TOOLS);
    if !Path::new("/dev/net/tun").exists() {
        missing.push("/dev/net/tun".to_owned());
    }
    missing
}

/// The kernel command line additions that give the guest agent its address, gateway and resolver.
pub fn boot_args() -> String {
    format!(" sentinel.ip={GUEST}/{PREFIX} sentinel.gw={GATEWAY} sentinel.dns={DNS}")
}

/// The Firecracker `network-interfaces` entry.
pub fn interface() -> serde_json::Value {
    serde_json::json!([{ "iface_id": "eth0", "host_dev_name": TAP, "guest_mac": GUEST_MAC }])
}

/// Runs as the root of the VM's own mount and network namespaces (inside the user namespace `podman unshare`
/// joins; that user namespace's mount namespace is shared by every `podman unshare` of the account, so the VMM
/// takes a mount namespace of its own or its bind mounts would be every other VM's): builds the tap and loads the
/// rules when the VM has a network, then puts the VMM in a chroot that is the VM's directory and becomes it.
/// The chroot holds exactly what the VMM opens, as bind mounts made in this mount namespace: the VMM binary,
/// the guest kernel and initramfs, the guest image, `/dev/kvm`, `/dev/net/tun` (a VM with a network) and, for a
/// restore, the snapshot's directory at `/snap`; the VM's own files (scratch disk, sockets, configuration) are
/// the directory itself. Every path a snapshot saves is therefore the same in every VM and independent of where
/// the worker's data directory is.
/// Arguments: the VM directory, the kernel, the initramfs, the guest image, the snapshot directory (or `-`),
/// then the VMM binary and its arguments.
const NETNS_SCRIPT: &str = r#"#!/bin/sh
set -eu
dir=$1
kernel=$2
initrd=$3
image=$4
snap=$5
shift 5
PATH="$PATH:/usr/sbin:/sbin"
if [ -f "$dir/egress.nft" ]; then
	echo "$$" > "$dir/netns.pid.tmp"
	mv "$dir/netns.pid.tmp" "$dir/netns.pid"
	ip link set lo up
	ip tuntap add dev vmtap mode tap
	ip addr add 10.211.0.1/30 dev vmtap
	ip link set vmtap up
	echo 1 > /proc/sys/net/ipv4/ip_forward
	nft -f "$dir/egress.nft"
fi
jail_file() {
	: > "$dir/$2"
	mount --bind "$1" "$dir/$2"
}
vmm=$1
shift
jail_file "$vmm" firecracker
jail_file "$kernel" kernel
jail_file "$initrd" initrd
jail_file "$image" image.ext4
mount -o remount,bind,ro "$dir/image.ext4" 2>/dev/null || true
# Plain mkdir: a VM directory removed under this script (a worker killed during the start, then recovered) must
# stay removed, and mkdir -p would make it again.
mkdir "$dir/dev" "$dir/dev/net"
jail_file /dev/kvm dev/kvm
if [ -f "$dir/egress.nft" ]; then
	jail_file /dev/net/tun dev/net/tun
fi
if [ "$snap" != "-" ]; then
	mkdir "$dir/snap"
	mount --bind "$snap" "$dir/snap"
	mount -o remount,bind,ro "$dir/snap" 2>/dev/null || true
fi
exec chroot "$dir" /firecracker "$@"
"#;

/// Runs in the VM's systemd scope as the worker account: starts the namespaces and the VMM, and when the VM
/// has an uplink attaches `pasta` to the new network namespace once its first process has said its pid.
/// Everything it starts is in the scope, so stopping the scope ends the VMM and `pasta` together.
const LAUNCH_SCRIPT: &str = r#"#!/bin/sh
dir=$1
shift
if [ ! -f "$dir/uplink" ]; then
	exec podman unshare unshare --mount --net --fork -- /bin/sh "$dir/netns.sh" "$dir" "$@"
fi
podman unshare unshare --mount --net --fork -- /bin/sh "$dir/netns.sh" "$dir" "$@" &
inner=$!
until [ -s "$dir/netns.pid" ]; do
	if ! kill -0 "$inner" 2>/dev/null; then
		wait "$inner"
		exit $?
	fi
	sleep 0.005
done
if ! pasta --quiet --config-net --ipv4-only --no-map-gw --no-dhcp --no-ndp --no-ra --no-dhcpv6 \
	-t none -u none -T none -U none --dns-forward 192.0.2.53 --pid "$dir/pasta.pid" "$(cat "$dir/netns.pid")"; then
	echo "sentinel: pasta could not attach to the VM's network namespace" >&2
	kill "$inner" 2>/dev/null
	wait "$inner"
	exit 1
fi
wait "$inner"
rc=$?
if [ -s "$dir/pasta.pid" ]; then
	kill "$(cat "$dir/pasta.pid")" 2>/dev/null
fi
exit "$rc"
"#;

/// The launch script's path in a VM directory.
pub fn launch_script(dir: &Path) -> std::path::PathBuf {
    dir.join("launch.sh")
}

/// Writes the launch scripts into the VM's directory and, for a VM with a network, its rules; `uplink` marks
/// a VM that reaches out (a snapshot template has a tap but no uplink).
pub fn install(dir: &Path, rules: Option<&str>, uplink: bool) -> io::Result<()> {
    let script = |name: &str, text: &str| -> io::Result<()> {
        let path = dir.join(name);
        fs::write(&path, text)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
    };
    script("netns.sh", NETNS_SCRIPT)?;
    script("launch.sh", LAUNCH_SCRIPT)?;
    if let Some(rules) = rules {
        fs::write(dir.join("egress.nft"), rules)?;
    }
    if uplink {
        fs::write(dir.join("uplink"), b"")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(
            &[
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 7, 20),
                Ipv4Addr::new(172, 17, 0, 1),
            ],
            &Guard {
                link: vec![
                    "198.51.100.9:7443".parse().unwrap(),
                    "[2001:db8::1]:7443".parse().unwrap(),
                    "127.0.0.1:9001".parse().unwrap(),
                ],
            },
        )
    }

    #[test]
    fn the_built_in_refusals_cover_loopback_link_local_and_metadata() {
        let rules = policy().rules();
        for net in [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.100.100.200/32",
            "192.0.0.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "10.211.0.0/30",
        ] {
            assert!(rules.contains(net), "{net} is not refused:\n{rules}");
        }
    }

    #[test]
    fn every_address_of_the_host_is_refused() {
        let rules = policy().rules();
        assert!(rules.contains("192.168.7.20/32"), "{rules}");
        assert!(rules.contains("172.17.0.1/32"), "{rules}");
        // Loopback is refused as a whole, and an interval set takes no overlapping entries.
        assert!(
            rules.contains("127.0.0.0/8") && !rules.contains("127.0.0.1/32"),
            "{rules}"
        );
    }

    #[test]
    fn a_network_inside_a_wider_refusal_is_not_listed_twice() {
        let rules = Policy::new(
            &[Ipv4Addr::new(169, 254, 1, 1), Ipv4Addr::new(10, 211, 0, 1)],
            &Guard::default(),
        )
        .rules();
        assert!(!rules.contains("169.254.1.1/32"), "{rules}");
        assert!(!rules.contains("10.211.0.1/32"), "{rules}");
        assert!(rules.contains("169.254.0.0/16") && rules.contains("10.211.0.0/30"));
    }

    #[test]
    fn the_controller_link_is_refused_by_address_and_port() {
        let rules = policy().rules();
        assert!(rules.contains("198.51.100.9 . 7443"), "{rules}");
        assert!(rules.contains("127.0.0.1 . 9001"), "{rules}");
        // A guest has no IPv6, so an IPv6 endpoint needs no entry (and none that nft could not parse).
        assert!(!rules.contains("2001:db8"), "{rules}");
        assert!(
            rules.contains("ip daddr . th dport @denied_endpoints drop"),
            "{rules}"
        );
    }

    #[test]
    fn a_guest_forwards_outward_only_as_its_own_address_after_the_refusals() {
        let rules = policy().rules();
        let line = |needle: &str| {
            rules
                .lines()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no rule {needle}:\n{rules}"))
        };
        let dns = line("th dport 53 accept");
        let nets = line("@denied_nets drop");
        let endpoints = line("@denied_endpoints drop");
        let out = line("oifname != \"vmtap\" ip saddr 10.211.0.2 accept");
        assert!(
            nets < out && endpoints < out,
            "refusals must precede the accept:\n{rules}"
        );
        assert!(dns < out);
        assert!(rules.contains("policy drop;"));
        // Replies are matched by connection state, nothing else is accepted from outside.
        assert!(rules.contains("ct state established,related accept"));
        assert!(rules.contains("masquerade"));
    }

    #[test]
    fn the_namespace_and_ipv6_are_closed_to_the_guest() {
        let rules = policy().rules();
        assert_eq!(
            rules.matches("iifname \"vmtap\" drop").count(),
            2,
            "{rules}"
        );
        let v6 = rules.split("table ip6 sentinel_vm6").nth(1).unwrap();
        assert!(v6.contains("hook forward priority filter; policy drop;"));
        assert!(!v6.contains("accept\n\t\tiifname"));
    }

    #[test]
    fn the_rules_do_not_depend_on_the_order_the_addresses_arrive() {
        let a = Policy::new(
            &[Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1)],
            &Guard::default(),
        );
        let b = Policy::new(
            &[
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
            ],
            &Guard::default(),
        );
        assert_eq!(a.rules(), b.rules());
    }

    #[test]
    fn a_policy_without_endpoints_has_an_empty_set_nft_accepts() {
        let rules = Policy::new(&[], &Guard::default()).rules();
        let set = rules.split("set denied_endpoints").nth(1).unwrap();
        let set = set.split("chain input").next().unwrap();
        assert!(!set.contains("elements"), "{set}");
    }

    #[test]
    fn the_guest_is_told_its_address_gateway_and_resolver() {
        assert_eq!(
            boot_args(),
            " sentinel.ip=10.211.0.2/30 sentinel.gw=10.211.0.1 sentinel.dns=192.0.2.53"
        );
        let nic = interface();
        assert_eq!(nic[0]["host_dev_name"], TAP);
        assert_eq!(nic.as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_scripts_and_rules_are_installed_with_the_uplink_marker_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path(), Some("table ip x {}\n"), false).unwrap();
        assert!(dir.path().join("netns.sh").is_file());
        assert!(dir.path().join("egress.nft").is_file());
        assert!(!dir.path().join("uplink").exists());
        let mode = fs::metadata(dir.path().join("launch.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let none = tempfile::tempdir().unwrap();
        install(none.path(), None, false).unwrap();
        assert!(!none.path().join("egress.nft").exists());
        install(none.path(), Some("x"), true).unwrap();
        assert!(none.path().join("uplink").exists());
    }

    #[test]
    fn missing_tools_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let exe = |name: &str, mode: u32| {
            let path = dir.path().join(name);
            fs::write(
                &path,
                b"#!/bin/sh
",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        };
        exe("ip", 0o755);
        exe("nft", 0o644);
        let dirs = [dir.path().to_path_buf(), PathBuf::from("/nonexistent")];
        assert_eq!(missing_in(&dirs, &TOOLS), ["nft", "pasta"]);
        assert!(missing_in(&dirs, &["ip"]).is_empty());
    }

    #[test]
    fn the_host_reports_at_least_its_loopback() {
        let addresses = host_addresses().unwrap();
        assert!(addresses.contains(&Ipv4Addr::LOCALHOST), "{addresses:?}");
    }
}
