//! The explainable vocabulary every lookup answers with. A miss is data,
//! not an error: corrupt, incompatible or absent state all mean "build as
//! if there were no cache", and the `Miss` variant is the whole reason —
//! for logs, the `sentinel.cache` report and tests alike.

use crate::manifest::Manifest;

/// Why an entry could not serve. The order `compatible` checks is the
/// order these read: the outermost broken boundary is the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    /// Nothing where the entry or generation should be: no directory, no
    /// `current` pointer, no manifest file.
    Absent,
    /// Bytes existed but could not be trusted: short head, bad magic,
    /// undecodable body, unreadable file, oversize manifest.
    Corrupt,
    /// The manifest version is one this build does not know.
    UnsupportedVersion,
    /// The generation was never sealed — an interrupted write.
    Unsealed,
    /// The manifest was written for a different cache class.
    WrongClass,
    /// The manifest records a different tenant.
    WrongTenant,
    /// The manifest records a different repository.
    WrongRepo,
    /// The manifest was sealed under the other trust class.
    WrongTrust,
    /// The manifest was sealed on another `os-arch`.
    WrongPlatform,
    /// The manifest was sealed under another toolchain digest.
    WrongToolchain,
    /// The manifest names a different cache entry.
    WrongName,
    /// The rendered key differs — or, for `downloads`, is not under the
    /// stored key's prefix.
    WrongKey,
    /// The class's own inputs differ: lockfile digest, installer, flags,
    /// ABI tag or tool identity.
    Incompatible,
    /// The manifest decoded but is semantically wrong: bad IDs, an
    /// invalid name, a `compat` payload from another class.
    Invalid,
}

impl Miss {
    /// The stable lowercase spelling for logs and reports.
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
        }
    }
}

impl std::fmt::Display for Miss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lookup that can serve: the verified manifest plus the payload size it
/// recorded, so reports can say how much a hit is worth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub manifest: Manifest,
    /// Total payload bytes (`files` blob total at seal time).
    pub bytes: u64,
}

/// What a lookup found — always total, never an error. The hit boxes its
/// manifest: a miss is one byte, and the lookup path should never carry a
/// 288-byte payload it did not earn.
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
        // The strings are the report vocabulary; renaming them is a
        // docs/compatibility.md change.
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
        ];
        for (miss, name) in all {
            assert_eq!(miss.as_str(), name);
            assert_eq!(miss.to_string(), name);
        }
    }
}
