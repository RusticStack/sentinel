use crate::manifest::Manifest;

/// Variants follow the order `Manifest::compatible` checks them; the first mismatch is the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    Absent,
    Corrupt,
    UnsupportedVersion,
    Unsealed,
    WrongClass,
    WrongTenant,
    WrongRepo,
    WrongTrust,
    WrongPlatform,
    WrongToolchain,
    WrongName,
    WrongKey,
    Incompatible,
    Invalid,
    /// Not `Corrupt`: the bytes may be fine, so a retry is worthwhile.
    Unavailable,
}

impl Miss {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Corrupt => "corrupt",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Unsealed => "unsealed",
            Self::WrongClass => "wrong_class",
            Self::WrongTenant => "wrong_tenant",
            Self::WrongRepo => "wrong_repo",
            Self::WrongTrust => "wrong_trust",
            Self::WrongPlatform => "wrong_platform",
            Self::WrongToolchain => "wrong_toolchain",
            Self::WrongName => "wrong_name",
            Self::WrongKey => "wrong_key",
            Self::Incompatible => "incompatible",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
        }
    }
}

impl std::fmt::Display for Miss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub manifest: Manifest,
    pub bytes: u64,
}

/// Boxed so a miss stays small; a hit payload is only carried when it is served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Hit(Box<Hit>),
    Miss(Miss),
}

impl Outcome {
    pub const fn is_hit(&self) -> bool {
        matches!(self, Self::Hit(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_a_stable_name() {
        let all = [
            (Miss::Absent, "absent"),
            (Miss::Corrupt, "corrupt"),
            (Miss::UnsupportedVersion, "unsupported_version"),
            (Miss::Unsealed, "unsealed"),
            (Miss::WrongClass, "wrong_class"),
            (Miss::WrongTenant, "wrong_tenant"),
            (Miss::WrongRepo, "wrong_repo"),
            (Miss::WrongTrust, "wrong_trust"),
            (Miss::WrongPlatform, "wrong_platform"),
            (Miss::WrongToolchain, "wrong_toolchain"),
            (Miss::WrongName, "wrong_name"),
            (Miss::WrongKey, "wrong_key"),
            (Miss::Incompatible, "incompatible"),
            (Miss::Invalid, "invalid"),
            (Miss::Unavailable, "unavailable"),
        ];
        for (miss, name) in all {
            assert_eq!(miss.as_str(), name);
            assert_eq!(miss.to_string(), name);
        }
    }
}
