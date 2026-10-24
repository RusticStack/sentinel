//! IDs convey no ownership: authorization always joins through the owning tenant row.
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a typed, canonical lowercase UUID v4 identifier")
    }
}
impl std::error::Error for InvalidId {}

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub const PREFIX: &'static str = $prefix;
            pub const TEXT_LEN: usize = $prefix.len() + 1 + 36;

            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub const fn from_bytes(bytes: [u8; 16]) -> Result<Self, InvalidId> {
                let uuid = Uuid::from_bytes(bytes);
                // Version nibble 4, RFC 4122 variant (10xx).
                if bytes[6] >> 4 != 4 || bytes[8] & 0xC0 != 0x80 {
                    return Err(InvalidId);
                }
                Ok(Self(uuid))
            }
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut buf = [0u8; 36];
                f.write_str($prefix)?;
                f.write_str("_")?;
                f.write_str(self.0.hyphenated().encode_lower(&mut buf))
            }
        }
        impl FromStr for $name {
            type Err = InvalidId;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != Self::TEXT_LEN {
                    return Err(InvalidId);
                }
                let raw = value
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or(InvalidId)?;
                if raw.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(InvalidId);
                }
                let uuid = Uuid::try_parse(raw).map_err(|_| InvalidId)?;
                Self::from_bytes(*uuid.as_bytes())
            }
        }
    };
}

identifier!(UserId, "usr");
identifier!(TenantId, "tnt");
identifier!(RepoId, "rep");
identifier!(SecretId, "sec");
identifier!(RunId, "run");
identifier!(JobId, "job");
identifier!(AttemptId, "att");
identifier!(WorkerId, "wrk");
identifier!(TokenId, "tok");
identifier!(PoolId, "pol");
identifier!(SessionId, "ses");
identifier!(InvitationId, "inv");
identifier!(MailId, "mal");
identifier!(InstallationId, "ins");
identifier!(DeliveryId, "dlv");
identifier!(CheckId, "chk");
identifier!(UploadId, "upl");
identifier!(ArtifactId, "arf");
identifier!(GrantId, "grt");

/// Steps are referenced by index; `u16` caps a job at 65,536 steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct StepIndex(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Fence(pub u64);

impl Fence {
    pub const NONE: Fence = Fence(0);

    #[must_use]
    pub const fn next(self) -> Fence {
        Fence(self.0.saturating_add(1))
    }
    #[must_use]
    pub const fn is_set(self) -> bool {
        self.0 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_is_canonical_and_typed() {
        let id = RunId::new();
        let text = id.to_string();
        assert_eq!(text.len(), RunId::TEXT_LEN);
        assert!(text.starts_with("run_"));
        assert_eq!(text.parse::<RunId>(), Ok(id));
        assert_eq!(
            text.parse::<JobId>(),
            Err(InvalidId),
            "prefix is part of the type"
        );
        assert_eq!(text.to_uppercase().parse::<RunId>(), Err(InvalidId));
        assert_eq!("run_".parse::<RunId>(), Err(InvalidId));
        assert_eq!(format!("{text} ").parse::<RunId>(), Err(InvalidId));
    }

    #[test]
    fn bytes_round_trip_rejects_non_v4() {
        let id = WorkerId::new();
        assert_eq!(WorkerId::from_bytes(*id.as_bytes()), Ok(id));
        assert_eq!(WorkerId::from_bytes([0; 16]), Err(InvalidId));
        let mut v1 = *id.as_bytes();
        v1[6] = (v1[6] & 0x0F) | 0x10;
        assert_eq!(WorkerId::from_bytes(v1), Err(InvalidId));
    }

    #[test]
    fn fence_never_returns_to_none() {
        assert!(!Fence::NONE.is_set());
        assert!(Fence::NONE.next().is_set());
        assert_eq!(Fence(u64::MAX).next(), Fence(u64::MAX));
        assert!(Fence(3) < Fence(4));
    }

    #[test]
    fn identifiers_stay_inline() {
        assert_eq!(std::mem::size_of::<TenantId>(), 16);
    }
}
