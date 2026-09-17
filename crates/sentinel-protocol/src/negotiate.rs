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

/// Versions this controller build can serve, inclusive. Protocol 4 adds the
/// artifact publication messages (`ArtifactBegin`…`ArtifactAbsent` and the
/// `ArtifactGrant`/`ArtifactVerdict` answers). Protocol 5 adds `LogEndAck`:
/// the controller answers `LogEnd` once the end marker is durable, and the
/// worker drops its spool only then. Protocol 6 adds `Context2`, the job
/// context carrying the tenant and the cache trust class. Protocol 7 adds
/// the scheduling `Profile`, the second bulk connection (`BulkHello`), the
/// transport telemetry (`Transport`) and the remote-cache transfer messages;
/// see `Profile` for why the extras are a message rather than new `Hello`
/// fields.
pub const SUPPORTED_MIN: ProtocolVersion = ProtocolVersion(1);
pub const SUPPORTED_MAX: ProtocolVersion = ProtocolVersion(7);

/// First protocol whose sessions carry the `Profile`, the bulk connection
/// and the remote-cache messages. The worker sends the profile immediately
/// after `Welcome` when the negotiated version is at least this.
pub const PROFILE_MIN: ProtocolVersion = ProtocolVersion(7);

/// Scheduling labels one worker may advertise. Bounded like every wire
/// list: a profile that exceeds a bound is a protocol error, never a silent
/// truncation.
pub const MAX_PROFILE_LABELS: usize = 16;

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

impl Arch {
    /// The stable lowercase spelling used in cache scope paths and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// First message on a worker session. Bounded: every field is fixed-size or
/// capped by `limits::MAX_NAME_BYTES`.
///
/// Protocol 7's scheduling extras (labels, host, disk, availability) are
/// deliberately **not** fields here. Postcard is not self-describing: a
/// struct decodes exactly the field list its reader knows, so a trailing
/// field added to `Hello` would make every older worker undecodable, and a
/// `#[serde(default)]` field never fires because the reader hits the end of
/// the frame instead of an end-of-sequence. The extras therefore travel in
/// `ClientMessage::Profile`, sent immediately after `Welcome` once the
/// session negotiated protocol 7 or later — append-only exactly like every
/// other wire addition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_min: ProtocolVersion,
    pub protocol_max: ProtocolVersion,
    pub capabilities: Capabilities,
    pub arch: Arch,
    /// Worker software version string for diagnostics only; never a compatibility input.
    pub software: String,
}

/// What a worker offers the scheduler beyond raw CPU and memory (protocol 7):
/// the labels it selects work by, the machine identity it shares with sibling
/// worker processes, the scratch disk it can give jobs, and the images and
/// cache state it already holds. Every field is what the worker measured at
/// this hello; a worker that cannot measure one reports the default, never a
/// guess.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// Scheduling labels, at most [`MAX_PROFILE_LABELS`], each at most
    /// `limits::MAX_NAME_BYTES`. A job that selects labels a worker did not
    /// report never places there.
    pub labels: Vec<String>,
    /// The machine hosting this worker, so a host-level failure or drain can
    /// be told apart from one process's; all zero when the worker does not
    /// report one (then it is treated as unknown, never as a shared host).
    pub host_id: [u8; 16],
    /// Free scratch disk the worker can give jobs, in bytes. Zero means "not
    /// reported": jobs that require scratch disk never place on it.
    pub disk_bytes: u64,
    pub availability: Availability,
}

impl Profile {
    /// The first bounded field that is out of range, if any. A profile that
    /// exceeds a bound is a protocol error, never a silent truncation.
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

/// What the worker's runtime already holds, as it measures at this hello.
/// `images` names the first 8 bytes of each resident image digest — enough to
/// tell "this worker would not need to pull it again" without shipping a
/// digest per image.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Availability {
    pub images: Vec<[u8; 8]>,
    /// Local cache bytes the worker can serve without fetching them.
    pub cache_bytes: u64,
    /// The worker's last measured CPU load, in nanoseconds of busy time over
    /// its measurement window; zero means "not measured", never "idle".
    pub load_ns: u64,
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
            9,
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
            negotiate(&hello(8, 9, Capabilities::REQUIRED)),
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
        // The wire form is postcard; the shape is also a JSON contract, where
        // `serde(default)` lets a shorter document decode to the defaults.
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
