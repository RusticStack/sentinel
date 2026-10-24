use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ProtocolVersion(pub u16);

pub const SUPPORTED_MIN: ProtocolVersion = ProtocolVersion(1);
pub const SUPPORTED_MAX: ProtocolVersion = ProtocolVersion(11);

pub const DIGEST_AT_END_MIN: ProtocolVersion = ProtocolVersion(9);

pub const PREFETCH_MIN: ProtocolVersion = ProtocolVersion(9);

/// The controller may push `Cancel` the moment a cancel commits instead of waiting for the next heartbeat.
pub const CANCEL_PUSH_MIN: ProtocolVersion = ProtocolVersion(11);

pub const MAX_CANCEL_PUSH: usize = 1024;

pub const MAX_PREFETCH_IMAGES: usize = 8;
pub const MAX_PREFETCH_REFERENCE_BYTES: usize = 512;

pub const CACHE_CANCEL_MIN: ProtocolVersion = ProtocolVersion(8);

pub const PROFILE_MIN: ProtocolVersion = ProtocolVersion(7);

pub const MAX_PROFILE_LABELS: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Capabilities(pub u64);

impl Capabilities {
    pub const NONE: Capabilities = Capabilities(0);
    pub const OCI_ROOTLESS: Capabilities = Capabilities(1 << 0);
    pub const CGROUP_CPU: Capabilities = Capabilities(1 << 1);
    pub const CGROUP_MEMORY: Capabilities = Capabilities(1 << 2);
    pub const CGROUP_PIDS: Capabilities = Capabilities(1 << 3);
    pub const CGROUP_IO: Capabilities = Capabilities(1 << 4);
    pub const REFLINK: Capabilities = Capabilities(1 << 5);
    pub const TAILCAT: Capabilities = Capabilities(1 << 6);
    pub const NETWORK_NONE: Capabilities = Capabilities(1 << 7);
    pub const HANDOFF_ANSWER: Capabilities = Capabilities(1 << 8);
    pub const SECRET_DELIVERY: Capabilities = Capabilities(1 << 9);
    /// `/dev/kvm` opened by the worker account and a throwaway VM created.
    pub const KVM: Capabilities = Capabilities(1 << 10);
    /// The worker's host is itself a guest (KVM reached through nested virtualization).
    pub const KVM_NESTED: Capabilities = Capabilities(1 << 11);
    pub const ISOLATION_CONTAINER: Capabilities = Capabilities(1 << 12);
    pub const ISOLATION_MICROVM: Capabilities = Capabilities(1 << 13);
    pub const ISOLATION_NATIVE: Capabilities = Capabilities(1 << 14);
    pub const OS_LINUX: Capabilities = Capabilities(1 << 15);
    pub const OS_WINDOWS: Capabilities = Capabilities(1 << 16);
    /// The bits a worker states about what it can run. A worker that states none of them predates them
    /// and runs Linux jobs in containers; jobs that state an OS or isolation need a worker that states it.
    pub const RUNTIME: Capabilities = Capabilities(
        Self::ISOLATION_CONTAINER.0
            | Self::ISOLATION_MICROVM.0
            | Self::ISOLATION_NATIVE.0
            | Self::OS_LINUX.0
            | Self::OS_WINDOWS.0,
    );

    pub const REQUIRED: Capabilities = Capabilities(
        Self::OCI_ROOTLESS.0 | Self::CGROUP_CPU.0 | Self::CGROUP_MEMORY.0 | Self::CGROUP_PIDS.0,
    );

    pub const fn contains(self, other: Capabilities) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn union(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 | other.0)
    }
    pub const fn intersection(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 & other.0)
    }
    pub const fn difference(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 & !other.0)
    }
    pub const KNOWN: Capabilities = Capabilities((1 << 17) - 1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

// Postcard is not self-describing: a new trailing Hello field breaks older workers, so extras go in ClientMessage::Profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_min: ProtocolVersion,
    pub protocol_max: ProtocolVersion,
    pub capabilities: Capabilities,
    pub arch: Arch,
    pub software: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub labels: Vec<String>,
    pub host_id: [u8; 16],
    pub disk_bytes: u64,
    pub availability: Availability,
}

impl Profile {
    pub fn invalid(&self) -> Option<&'static str> {
        if self.labels.len() > MAX_PROFILE_LABELS {
            return Some("labels");
        }
        if self.labels.iter().any(|label| {
            label.is_empty()
                || label.len() > crate::limits::MAX_NAME_BYTES
                || label.as_bytes().iter().any(|b| *b == b'\n' || *b == b'\r')
        }) {
            return Some("label");
        }
        if self.availability.images.len() > crate::limits::MAX_LIST_ITEMS {
            return Some("images");
        }
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Availability {
    pub images: Vec<[u8; 8]>,
    pub cache_bytes: u64,
    pub load_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Negotiated {
    pub protocol: ProtocolVersion,
    pub capabilities: Capabilities,
    pub arch: Arch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    UnsupportedVersion {
        supported_min: ProtocolVersion,
        supported_max: ProtocolVersion,
        upgrade_worker: bool,
    },
    /// Required capabilities the worker did not advertise.
    MissingCapabilities { missing: Capabilities },
    /// `protocol_min > protocol_max`.
    InvalidRange,
}

pub const fn negotiate(hello: &Hello) -> Result<Negotiated, Rejected> {
    if hello.protocol_min.0 > hello.protocol_max.0 {
        return Err(Rejected::InvalidRange);
    }
    let low = if hello.protocol_min.0 > SUPPORTED_MIN.0 {
        hello.protocol_min
    } else {
        SUPPORTED_MIN
    };
    let high = if hello.protocol_max.0 < SUPPORTED_MAX.0 {
        hello.protocol_max
    } else {
        SUPPORTED_MAX
    };
    if low.0 > high.0 {
        return Err(Rejected::UnsupportedVersion {
            supported_min: SUPPORTED_MIN,
            supported_max: SUPPORTED_MAX,
            upgrade_worker: hello.protocol_max.0 < SUPPORTED_MIN.0,
        });
    }
    let known = hello.capabilities.intersection(Capabilities::KNOWN);
    let missing = Capabilities::REQUIRED.difference(known);
    if missing.0 != 0 {
        return Err(Rejected::MissingCapabilities { missing });
    }
    Ok(Negotiated {
        protocol: high,
        capabilities: known,
        arch: hello.arch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(min: u16, max: u16, caps: Capabilities) -> Hello {
        Hello {
            protocol_min: ProtocolVersion(min),
            protocol_max: ProtocolVersion(max),
            capabilities: caps,
            arch: Arch::X86_64,
            software: "sentinel-worker 0.1.0-dev".into(),
        }
    }

    #[test]
    fn picks_highest_common_version_and_masks_unknown_bits() {
        let future_bit = Capabilities(1 << 40);
        let h = hello(
            1,
            11,
            Capabilities::REQUIRED
                .union(Capabilities::REFLINK)
                .union(future_bit),
        );
        let n = negotiate(&h).unwrap();
        assert_eq!(n.protocol, SUPPORTED_MAX);
        assert_eq!(
            negotiate(&hello(1, 2, Capabilities::REQUIRED))
                .unwrap()
                .protocol,
            ProtocolVersion(2)
        );
        assert_eq!(
            negotiate(&hello(1, 1, Capabilities::REQUIRED))
                .unwrap()
                .protocol,
            ProtocolVersion(1)
        );
        assert!(n.capabilities.contains(Capabilities::REFLINK));
        assert!(!n.capabilities.contains(future_bit));
    }

    #[test]
    fn version_mismatch_says_who_must_upgrade() {
        assert_eq!(
            negotiate(&hello(
                SUPPORTED_MAX.0 + 1,
                SUPPORTED_MAX.0 + 2,
                Capabilities::REQUIRED
            )),
            Err(Rejected::UnsupportedVersion {
                supported_min: SUPPORTED_MIN,
                supported_max: SUPPORTED_MAX,
                upgrade_worker: false
            })
        );
        assert_eq!(
            negotiate(&hello(0, 0, Capabilities::REQUIRED)),
            Err(Rejected::UnsupportedVersion {
                supported_min: SUPPORTED_MIN,
                supported_max: SUPPORTED_MAX,
                upgrade_worker: true
            })
        );
        assert_eq!(
            negotiate(&hello(2, 1, Capabilities::REQUIRED)),
            Err(Rejected::InvalidRange)
        );
    }

    #[test]
    fn missing_required_capabilities_are_named() {
        let partial = Capabilities::OCI_ROOTLESS.union(Capabilities::CGROUP_CPU);
        assert_eq!(
            negotiate(&hello(1, 1, partial)),
            Err(Rejected::MissingCapabilities {
                missing: Capabilities::CGROUP_MEMORY.union(Capabilities::CGROUP_PIDS)
            })
        );
    }

    #[test]
    fn profile_bounds_are_checked() {
        let mut profile = Profile::default();
        assert_eq!(profile.invalid(), None);
        profile.labels = vec!["linux".to_string(); MAX_PROFILE_LABELS + 1];
        assert_eq!(profile.invalid(), Some("labels"));
        profile.labels = vec!["bad\nlabel".to_string()];
        assert_eq!(profile.invalid(), Some("label"));
        profile.labels = vec!["ok".to_string()];
        assert_eq!(profile.invalid(), None);
        profile.availability.images = vec![[0u8; 8]; crate::limits::MAX_LIST_ITEMS + 1];
        assert_eq!(profile.invalid(), Some("images"));
    }

    #[test]
    fn profile_round_trips_and_absent_fields_default() {
        let profile = Profile {
            labels: vec!["linux".to_string(), "gpu".to_string()],
            host_id: [7u8; 16],
            disk_bytes: 1 << 30,
            availability: Availability {
                images: vec![[1, 2, 3, 4, 5, 6, 7, 8]],
                cache_bytes: 1024,
                load_ns: 5,
            },
        };
        let bytes = postcard::to_allocvec(&profile).unwrap();
        assert_eq!(postcard::from_bytes::<Profile>(&bytes).unwrap(), profile);
        let sparse: Profile = serde_json::from_str(r#"{"labels":["linux"]}"#).unwrap();
        assert_eq!(sparse.labels, vec!["linux".to_string()]);
        assert_eq!(sparse.host_id, [0u8; 16]);
        assert_eq!(sparse.disk_bytes, 0);
        assert_eq!(sparse.availability, Availability::default());
    }

    #[test]
    fn wire_shapes_are_stable() {
        let r = Rejected::MissingCapabilities {
            missing: Capabilities::CGROUP_IO,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"reason":"missing_capabilities","missing":16}"#
        );
        let h = hello(1, 1, Capabilities::REQUIRED);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(
            json,
            r#"{"protocol_min":1,"protocol_max":1,"capabilities":15,"arch":"x86_64","software":"sentinel-worker 0.1.0-dev"}"#
        );
        assert_eq!(serde_json::from_str::<Hello>(&json).unwrap(), h);
    }
}
