//! Worker session negotiation. The worker opens with a `Hello` naming the
//! protocol versions it speaks and the capabilities it can prove; the
//! controller answers with one version and the capability set it will rely
//! on, or a typed rejection the worker can log and act on without guessing.
use serde::{Deserialize, Serialize};

/// Wire protocol version. Bump on any incompatible change to messages,
/// framing or semantics; additive optional fields do not bump it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ProtocolVersion(pub u16);

/// Versions this controller build can serve, inclusive.
pub const SUPPORTED_MIN: ProtocolVersion = ProtocolVersion(1);
pub const SUPPORTED_MAX: ProtocolVersion = ProtocolVersion(2);

/// Capabilities are a bit set: cheap to store, compare and intersect, and
/// unknown bits from a newer worker are ignored rather than rejected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Capabilities(pub u64);

impl Capabilities {
    pub const NONE: Capabilities = Capabilities(0);
    /// Rootless OCI runtime (Podman) with user namespaces.
    pub const OCI_ROOTLESS: Capabilities = Capabilities(1 << 0);
    pub const CGROUP_CPU: Capabilities = Capabilities(1 << 1);
    pub const CGROUP_MEMORY: Capabilities = Capabilities(1 << 2);
    pub const CGROUP_PIDS: Capabilities = Capabilities(1 << 3);
    /// `io` controller delegated: I/O weight limits are enforceable.
    pub const CGROUP_IO: Capabilities = Capabilities(1 << 4);
    /// Cache volume supports `FICLONE` reflinks.
    pub const REFLINK: Capabilities = Capabilities(1 << 5);
    /// Pinned Tailcat helper available for the transport.
    pub const TAILCAT: Capabilities = Capabilities(1 << 6);
    /// Worker can run without egress for jobs that request `network: none`.
    pub const NETWORK_NONE: Capabilities = Capabilities(1 << 7);

    /// The minimum a worker must prove before it may receive any job.
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
    /// Bits this controller build knows; unknown bits are masked on receipt.
    pub const KNOWN: Capabilities = Capabilities((1 << 8) - 1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// First message on a worker session. Bounded: every field is fixed-size or
/// capped by `limits::MAX_NAME_BYTES`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_min: ProtocolVersion,
    pub protocol_max: ProtocolVersion,
    pub capabilities: Capabilities,
    pub arch: Arch,
    /// Worker software version string for diagnostics only; never a compatibility input.
    pub software: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Negotiated {
    pub protocol: ProtocolVersion,
    /// Worker capabilities the controller knows about; scheduling uses this set.
    pub capabilities: Capabilities,
    pub arch: Arch,
}

/// Typed rejection. The worker must not retry a `Rejected` hello unchanged:
/// only an upgrade (or a host fix for capabilities) can change the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// No overlap between the worker's range and the controller's range.
    /// `upgrade_worker` says which side is behind.
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

/// Choose the highest version both sides support and verify required
/// capabilities. Pure and constant-time in the size of the sets.
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
            3,
            Capabilities::REQUIRED
                .union(Capabilities::REFLINK)
                .union(future_bit),
        );
        let n = negotiate(&h).unwrap();
        assert_eq!(n.protocol, ProtocolVersion(2));
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
            negotiate(&hello(3, 5, Capabilities::REQUIRED)),
            Err(Rejected::UnsupportedVersion {
                supported_min: SUPPORTED_MIN,
                supported_max: SUPPORTED_MAX,
                upgrade_worker: false
            })
        );
        // A worker stuck below the minimum (simulate with an invalid low range 0..0).
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
