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
