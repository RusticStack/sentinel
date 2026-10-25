use std::path::PathBuf;

use sentinel_core::TenantId;
use sentinel_pipeline::schema::Cache;
use sentinel_protocol::cache::Class;

pub use crate::CACHE_DIR as ROOT_DIR;

use crate::{
    lease::Lease,
    manifest::{Compat, key_stem},
    outcome::Outcome,
    publish::SkipReason,
    scope::{Platform, Scope},
};

/// Fixed, never random: tenant-less jobs share one scope path and never collide with a real tenant.
pub const UNKNOWN_TENANT: TenantId = match TenantId::from_bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]) {
    Ok(tenant) => tenant,
    Err(_) => panic!("constant is a valid v4 uuid"),
};

pub const MAX_KEY_BYTES: usize = 1024;

pub const PRIVATE_DIR: &str = ".sentinel-cache";

pub fn declared_compat(decl: &Cache, key: &str, platform: Platform) -> Compat {
    match decl.class {
        Class::Downloads => Compat::Downloads {
            tool: decl.name.clone(),
        },
        Class::Dependencies => Compat::Dependencies {
            lock: *blake3::hash(key.as_bytes()).as_bytes(),
            installer: "pipeline".to_owned(),
            flags: String::new(),
            abi: platform.component(),
        },
        Class::Compiler => Compat::Compiler {
            flags: String::new(),
        },
    }
}

pub fn entry_key(class: Class, key: &str) -> &str {
    match class {
        Class::Downloads | Class::Compiler => key_stem(key),
        Class::Dependencies => key,
    }
}

pub struct Attached {
    pub name: String,
    pub scope: Scope,
    pub key: String,
    pub compat: Compat,
    pub generation: Option<String>,
    pub outcome: Outcome,
    pub targets: Vec<Target>,
    pub lease: Option<Lease>,
    pub stats: Stats,
}

pub const COSTLY_HIT_NS: u64 = 5_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Costly {
    CopiedAll,
    Slow,
}

impl Costly {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CopiedAll => "copied_all",
            Self::Slow => "slow",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Committed {
    Sealed {
        staged_bytes: u64,
        reused_bytes: u64,
    },
    Skipped(SkipReason),
    Failed,
}

impl Attached {
    pub fn costly_hit(&self) -> Option<Costly> {
        if !self.outcome.is_hit() {
            return None;
        }
        if self.stats.reflink && self.stats.bytes > 0 && self.stats.copied_bytes == self.stats.bytes
        {
            return Some(Costly::CopiedAll);
        }
        let waited = self
            .stats
            .lock_wait_ns
            .unwrap_or(0)
            .saturating_add(self.stats.clone_ns.unwrap_or(0));
        if waited > COSTLY_HIT_NS {
            return Some(Costly::Slow);
        }
        None
    }
}

pub struct Target {
    pub declared: String,
    /// Publication reopens this anchor and resolves `dir` beneath it without following symlinks,
    /// since everything below the anchor is content the job could rewrite.
    pub root: PathBuf,
    pub dir: PathBuf,
    pub container: String,
    pub mount: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub lookup_ns: Option<u64>,
    pub lock_wait_ns: Option<u64>,
    pub clone_ns: Option<u64>,
    pub first_touch_ns: Option<u64>,
    pub files: u64,
    pub bytes: u64,
    pub copied_bytes: u64,
    pub reflink: bool,
    pub remote_ns: Option<u64>,
    pub remote_bytes: u64,
    pub remote_from: Option<u64>,
    pub commit_ns: Option<u64>,
    pub committed: Option<Committed>,
}

#[cfg(test)]
mod tests {
    use sentinel_core::RepoId;
    use sentinel_protocol::{cache::Trust, negotiate::Arch};

    use super::*;
    use crate::{
        manifest::Manifest,
        outcome::Hit,
        scope::{Os, Platform},
    };

    fn attached(outcome: Outcome) -> Attached {
        let scope = Scope::new(
            TenantId::new(),
            RepoId::new(),
            Class::Dependencies,
            Trust::Protected,
            Platform {
                os: Os::Linux,
                arch: Arch::X86_64,
            },
            [7; 32],
            "deps",
        )
        .unwrap();
        Attached {
            name: "deps".into(),
            scope,
            key: "k".into(),
            compat: Compat::Downloads { tool: "t".into() },
            generation: None,
            outcome,
            targets: Vec::new(),
            lease: None,
            stats: Stats::default(),
        }
    }

    fn hit() -> Outcome {
        let scope = Scope::new(
            TenantId::new(),
            RepoId::new(),
            Class::Dependencies,
            Trust::Protected,
            Platform {
                os: Os::Linux,
                arch: Arch::X86_64,
            },
            [7; 32],
            "deps",
        )
        .unwrap();
        Outcome::Hit(Box::new(Hit {
            manifest: Manifest::writing(&scope, "k", Compat::Downloads { tool: "t".into() }),
            bytes: 0,
        }))
    }

    #[test]
    fn the_costly_hit_rule_flags_only_implausible_hits() {
        let mut miss = attached(Outcome::Miss(crate::Miss::Absent));
        miss.stats.reflink = true;
        miss.stats.bytes = 100;
        miss.stats.copied_bytes = 100;
        assert_eq!(miss.costly_hit(), None);

        let mut full_copy = attached(hit());
        full_copy.stats.reflink = true;
        full_copy.stats.bytes = 100;
        full_copy.stats.copied_bytes = 100;
        assert_eq!(full_copy.costly_hit(), Some(Costly::CopiedAll));

        full_copy.stats.copied_bytes = 99;
        assert_eq!(full_copy.costly_hit(), None);
        let mut copied = attached(hit());
        copied.stats.bytes = 100;
        copied.stats.copied_bytes = 100;
        assert_eq!(copied.costly_hit(), None);
        let mut empty = attached(hit());
        empty.stats.reflink = true;
        assert_eq!(empty.costly_hit(), None);

        let mut slow = attached(hit());
        slow.stats.lock_wait_ns = Some(COSTLY_HIT_NS - 1);
        slow.stats.clone_ns = Some(1);
        assert_eq!(slow.costly_hit(), None);
        slow.stats.clone_ns = Some(2);
        assert_eq!(slow.costly_hit(), Some(Costly::Slow));
        slow.stats.reflink = true;
        slow.stats.bytes = 4;
        slow.stats.copied_bytes = 4;
        assert_eq!(slow.costly_hit(), Some(Costly::CopiedAll));
    }

    #[test]
    fn costly_reasons_have_stable_names() {
        assert_eq!(Costly::CopiedAll.as_str(), "copied_all");
        assert_eq!(Costly::Slow.as_str(), "slow");
    }
}
