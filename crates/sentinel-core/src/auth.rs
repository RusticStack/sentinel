//! Authorization inputs constructed by trusted authentication code, never from
//! request JSON or a caller's selected tenant. No role snapshot is cached here.
use crate::{RepoId, TenantId, UserId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Reader = 1,
    Operator = 2,
    TenantAdmin = 3,
}

/// Stable database bit positions, not OAuth wire scope names. A repository
/// operator does not implicitly gain secret-write or administration rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const RUN: Self = Self(2);
    pub const WRITE_SECRETS: Self = Self(4);
    pub const TENANT_ADMIN: Self = Self(8);
    pub const PLATFORM_ADMIN: Self = Self(16);
    pub const REPOSITORY: Self = Self(7);
    pub const ALL: Self = Self(31);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    /// Reconstruct from a persisted value, rejecting undefined bits so a corrupt
    /// or newer row cannot widen authority by setting one.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}

/// OAuth scopes (O02). Bit positions are STORED (grants, codes, access
/// tokens) and stable; the names are the wire form. A scope is a ceiling on
/// [`Permissions`], never a grant of its own: every repository and tenant
/// decision is still a live check against membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Scopes(u32);

/// A scope name this deployment does not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownScope;

impl core::fmt::Display for UnknownScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown scope")
    }
}
impl std::error::Error for UnknownScope {}

impl Scopes {
    pub const NONE: Self = Self(0);
    pub const RUNS_READ: Self = Self(1 << 0);
    pub const RUNS_WRITE: Self = Self(1 << 1);
    pub const LOGS_READ: Self = Self(1 << 2);
    pub const ARTIFACTS_READ: Self = Self(1 << 3);
    pub const CACHE_READ: Self = Self(1 << 4);
    pub const CACHE_WRITE: Self = Self(1 << 5);
    pub const SECRETS_METADATA: Self = Self(1 << 6);
    pub const SECRETS_WRITE: Self = Self(1 << 7);
    pub const TENANT_ADMIN: Self = Self(1 << 8);
    pub const PLATFORM_ADMIN: Self = Self(1 << 9);
    pub const ALL: Self = Self(0x3FF);
    /// What `sentinel auth login` asks for unless told otherwise.
    pub const CLI_DEFAULT: Self = Self(
        Self::RUNS_READ.0
            | Self::RUNS_WRITE.0
            | Self::LOGS_READ.0
            | Self::ARTIFACTS_READ.0
            | Self::CACHE_READ.0,
    );
    /// Wire names in bit order; index `i` names bit `1 << i`.
    pub const NAMES: [&'static str; 10] = [
        "runs:read",
        "runs:write",
        "logs:read",
        "artifacts:read",
        "cache:read",
        "cache:write",
        "secrets:metadata",
        "secrets:write",
        "tenant:admin",
        "platform:admin",
    ];
    /// Every scope whose ceiling is [`Permissions::READ`].
    const READS: Self = Self(
        Self::RUNS_READ.0
            | Self::LOGS_READ.0
            | Self::ARTIFACTS_READ.0
            | Self::CACHE_READ.0
            | Self::SECRETS_METADATA.0,
    );
    /// Every scope whose ceiling is [`Permissions::RUN`].
    const RUNS: Self = Self(Self::RUNS_WRITE.0 | Self::CACHE_WRITE.0);

    pub const fn bits(self) -> u32 {
        self.0
    }
    /// Reconstruct from a persisted value, rejecting undefined bits.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    /// `self` without the scopes in `other`.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parse a space-separated scope list. An unknown name refuses the whole
    /// list; a repeated name is harmless. Empty input is [`Scopes::NONE`].
    pub fn parse(text: &str) -> Result<Self, UnknownScope> {
        let mut bits = 0;
        for name in text.split(' ').filter(|n| !n.is_empty()) {
            let at = Self::NAMES
                .iter()
                .position(|known| *known == name)
                .ok_or(UnknownScope)?;
            bits |= 1 << at;
        }
        Ok(Self(bits))
    }

    /// Append the canonical, space-separated names in bit order.
    pub fn write_names(self, out: &mut String) {
        for (index, name) in self.names().enumerate() {
            if index != 0 {
                out.push(' ');
            }
            out.push_str(name);
        }
    }

    /// The canonical text form, as [`Scopes::write_names`] writes it.
    #[must_use]
    pub fn to_names(self) -> String {
        let mut out = String::with_capacity(self.0.count_ones() as usize * 16);
        self.write_names(&mut out);
        out
    }

    /// The names present, in bit order.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .iter()
            .enumerate()
            .filter(move |(at, _)| self.0 & (1 << at) != 0)
            .map(|(_, name)| *name)
    }

    /// The permission ceiling these scopes allow.
    pub const fn ceiling(self) -> Permissions {
        let mut bits = 0;
        if self.0 & Self::READS.0 != 0 {
            bits |= Permissions::READ.0;
        }
        if self.0 & Self::RUNS.0 != 0 {
            bits |= Permissions::RUN.0;
        }
        if self.0 & Self::SECRETS_WRITE.0 != 0 {
            bits |= Permissions::WRITE_SECRETS.0;
        }
        if self.0 & Self::TENANT_ADMIN.0 != 0 {
            bits |= Permissions::TENANT_ADMIN.0;
        }
        if self.0 & Self::PLATFORM_ADMIN.0 != 0 {
            bits |= Permissions::PLATFORM_ADMIN.0;
        }
        Permissions(bits)
    }

    /// The scopes a pre-OAuth credential or a session implicitly carries, so
    /// that scope checks leave their authority exactly as it was.
    pub const fn from_permissions(permissions: Permissions) -> Self {
        let mut bits = 0;
        if permissions.0 & Permissions::READ.0 != 0 {
            bits |= Self::READS.0;
        }
        if permissions.0 & Permissions::RUN.0 != 0 {
            bits |= Self::RUNS.0;
        }
        if permissions.0 & Permissions::WRITE_SECRETS.0 != 0 {
            bits |= Self::SECRETS_WRITE.0;
        }
        if permissions.0 & Permissions::TENANT_ADMIN.0 != 0 {
            bits |= Self::TENANT_ADMIN.0;
        }
        if permissions.0 & Permissions::PLATFORM_ADMIN.0 != 0 {
            bits |= Self::PLATFORM_ADMIN.0;
        }
        Self(bits)
    }
}

/// Who a token may be presented to (RFC 8707 resource). Stored as its
/// integer in `oauth_* .resource`; the historical `audience` column remains
/// API-only for migration compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Audience {
    /// `{issuer}/api/v1`.
    Api = 1,
    /// `{issuer}/mcp`.
    Mcp = 2,
}

impl Audience {
    pub const fn code(self) -> u8 {
        self as u8
    }
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Api),
            2 => Some(Self::Mcp),
            _ => None,
        }
    }
}

/// A validated credential's upper bound. Identity authenticators must intersect
/// token/client scopes before constructing this value. Membership/grants remain
/// live database checks; this is not a transferable authorization decision.
#[derive(Clone, Copy, Debug)]
pub struct Principal {
    pub user: UserId,
    pub permissions: Permissions,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
}

impl Principal {
    pub const fn new(
        user: UserId,
        permissions: Permissions,
        tenant: Option<TenantId>,
        repo: Option<RepoId>,
    ) -> Self {
        Self {
            user,
            permissions,
            tenant,
            repo,
        }
    }
}

/// Borrowed canonical namespace: validate without allocating or normalizing a
/// potentially conflicting spelling. Organization and personal names share it.
#[derive(Clone, Copy, Debug)]
pub struct Namespace<'a>(&'a str);

impl<'a> Namespace<'a> {
    pub fn parse(value: &'a str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return None;
        }
        Some(Self(value))
    }
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_names_round_trip_in_canonical_order() {
        let parsed = Scopes::parse("logs:read runs:read  runs:read platform:admin").unwrap();
        assert_eq!(
            parsed,
            Scopes::RUNS_READ
                .union(Scopes::LOGS_READ)
                .union(Scopes::PLATFORM_ADMIN)
        );
        assert_eq!(parsed.to_names(), "runs:read logs:read platform:admin");
        assert_eq!(Scopes::parse(&parsed.to_names()), Ok(parsed));
        assert_eq!(Scopes::parse(&Scopes::ALL.to_names()), Ok(Scopes::ALL));
        assert_eq!(Scopes::ALL.names().count(), 10);
        assert_eq!(Scopes::parse(""), Ok(Scopes::NONE));
        assert_eq!(
            Scopes::CLI_DEFAULT.to_names(),
            "runs:read runs:write logs:read artifacts:read cache:read"
        );
    }

    #[test]
    fn unknown_names_and_undefined_bits_are_refused() {
        assert_eq!(Scopes::parse("runs:read admin"), Err(UnknownScope));
        assert_eq!(Scopes::parse("RUNS:READ"), Err(UnknownScope));
        assert_eq!(Scopes::parse("runs:read,logs:read"), Err(UnknownScope));
        assert_eq!(Scopes::from_bits(0x3FF), Some(Scopes::ALL));
        assert_eq!(Scopes::from_bits(0x400), None);
        assert_eq!(Scopes::from_bits(u32::MAX), None);
    }

    #[test]
    fn each_scope_has_one_permission_ceiling() {
        for scope in [
            Scopes::RUNS_READ,
            Scopes::LOGS_READ,
            Scopes::ARTIFACTS_READ,
            Scopes::CACHE_READ,
            Scopes::SECRETS_METADATA,
        ] {
            assert_eq!(scope.ceiling(), Permissions::READ, "{scope:?}");
        }
        assert_eq!(Scopes::RUNS_WRITE.ceiling(), Permissions::RUN);
        assert_eq!(Scopes::CACHE_WRITE.ceiling(), Permissions::RUN);
        assert_eq!(Scopes::SECRETS_WRITE.ceiling(), Permissions::WRITE_SECRETS);
        assert_eq!(Scopes::TENANT_ADMIN.ceiling(), Permissions::TENANT_ADMIN);
        assert_eq!(
            Scopes::PLATFORM_ADMIN.ceiling(),
            Permissions::PLATFORM_ADMIN
        );
        assert_eq!(Scopes::NONE.ceiling(), Permissions::NONE);
        assert_eq!(Scopes::ALL.ceiling(), Permissions::ALL);
        assert_eq!(
            Scopes::CLI_DEFAULT.ceiling(),
            Permissions::READ.union(Permissions::RUN)
        );
    }

    #[test]
    fn existing_credentials_keep_exactly_their_authority() {
        for bits in 0..=Permissions::ALL.bits() {
            let permissions = Permissions::from_bits(bits).unwrap();
            let scopes = Scopes::from_permissions(permissions);
            assert_eq!(scopes.ceiling(), permissions, "{bits}");
        }
        let read = Scopes::from_permissions(Permissions::READ);
        assert!(read.contains(Scopes::LOGS_READ.union(Scopes::SECRETS_METADATA)));
        assert!(!read.contains(Scopes::RUNS_WRITE));
        assert_eq!(Scopes::from_permissions(Permissions::ALL), Scopes::ALL);
    }

    #[test]
    fn audience_codes_are_stable() {
        assert_eq!(Audience::Api.code(), 1);
        assert_eq!(Audience::from_code(1), Some(Audience::Api));
        assert_eq!(Audience::from_code(2), Some(Audience::Mcp));
        assert_eq!(Audience::from_code(0), None);
    }
}
