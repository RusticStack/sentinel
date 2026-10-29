use std::path::PathBuf;

use sentinel_core::TenantId;
use sentinel_pipeline::schema::Cache;
use sentinel_protocol::cache::Class;

pub use crate::CACHE_DIR as ROOT_DIR;

use crate::{
    cost::CostBook,
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
    /// What the restore paid before the job could start: waiting for the entry plus the clone.
    pub fn restore_ns(&self) -> u64 {
        self.stats
            .lock_wait_ns
            .unwrap_or(0)
            .saturating_add(self.stats.clone_ns.unwrap_or(0))
    }

    fn copied_all(&self) -> bool {
        self.stats.reflink && self.stats.bytes > 0 && self.stats.copied_bytes == self.stats.bytes
    }

    /// The fixed default rule, for a class with no measured rebuild cost.
    pub fn costly_hit(&self) -> Option<Costly> {
        self.costly_against(None)
    }

    /// The measured rule: a hit is costly when its restore took longer than the class's measured rebuild.
    /// A class whose rebuild estimate has not settled falls back to [`Attached::costly_hit`].
    pub fn costly_hit_with(&self, book: &CostBook) -> Option<Costly> {
        self.costly_against(book.rebuild(self.scope.class).map(|e| e.ns))
    }

    fn costly_against(&self, rebuild_ns: Option<u64>) -> Option<Costly> {
        if !self.outcome.is_hit() {
            return None;
        }
        let restore = self.restore_ns();
        match rebuild_ns {
            Some(rebuild) if restore > rebuild => Some(if self.copied_all() {
                Costly::CopiedAll
            } else {
                Costly::Slow
            }),
            Some(_) => None,
            None if self.copied_all() => Some(Costly::CopiedAll),
            None if restore > COSTLY_HIT_NS => Some(Costly::Slow),
            None => None,
        }
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

    fn settled(class: Class, rebuild_ns: u64) -> CostBook {
        let book = CostBook::new();
        for _ in 0..crate::cost::MIN_SAMPLES {
            book.record_rebuild(class, rebuild_ns);
        }
        book
    }

    #[test]
    fn a_measured_rebuild_decides_instead_of_the_fixed_default() {
        let mut hit_ = attached(hit());
        hit_.stats.clone_ns = Some(2_000);
        hit_.stats.lock_wait_ns = Some(500);

        // Restore (2.5 us) beats a 10 us rebuild: not costly, and a slow restore by the default's standard
        // is still fine when the rebuild it saves is slower.
        assert_eq!(
            hit_.costly_hit_with(&settled(Class::Dependencies, 10_000)),
            None
        );
        let mut slow_but_worth_it = attached(hit());
        slow_but_worth_it.stats.clone_ns = Some(COSTLY_HIT_NS + 1);
        assert_eq!(slow_but_worth_it.costly_hit(), Some(Costly::Slow));
        assert_eq!(
            slow_but_worth_it.costly_hit_with(&settled(Class::Dependencies, COSTLY_HIT_NS * 4)),
            None
        );
        // The same restore against a cheaper rebuild is costly, far below the fixed 5 s bound.
        assert_eq!(hit_.costly_hit(), None);
        assert_eq!(
            hit_.costly_hit_with(&settled(Class::Dependencies, 2_499)),
            Some(Costly::Slow)
        );
        assert_eq!(
            hit_.costly_hit_with(&settled(Class::Dependencies, 2_500)),
            None
        );

        // Copying every byte is only costly when it actually costs more than the rebuild.
        let mut copied = attached(hit());
        copied.stats.reflink = true;
        copied.stats.bytes = 100;
        copied.stats.copied_bytes = 100;
        copied.stats.clone_ns = Some(1_000);
        assert_eq!(copied.costly_hit(), Some(Costly::CopiedAll));
        assert_eq!(
            copied.costly_hit_with(&settled(Class::Dependencies, 5_000)),
            None
        );
        assert_eq!(
            copied.costly_hit_with(&settled(Class::Dependencies, 999)),
            Some(Costly::CopiedAll)
        );
    }

    #[test]
    fn without_a_settled_rebuild_for_its_class_the_default_applies() {
        let mut slow = attached(hit());
        slow.stats.clone_ns = Some(COSTLY_HIT_NS + 1);
        slow.stats.reflink = true;
        slow.stats.bytes = 4;
        slow.stats.copied_bytes = 4;

        let empty = CostBook::new();
        assert_eq!(slow.costly_hit_with(&empty), slow.costly_hit());
        // Another class's rebuild cost is not this class's.
        let other = settled(Class::Compiler, u64::MAX);
        assert_eq!(slow.costly_hit_with(&other), Some(Costly::CopiedAll));
        // Too few samples to trust.
        let thin = CostBook::new();
        thin.record_rebuild(Class::Dependencies, u64::MAX);
        assert_eq!(slow.costly_hit_with(&thin), Some(Costly::CopiedAll));
        // A miss is never a hit, measured or not.
        let miss = attached(Outcome::Miss(crate::Miss::Absent));
        assert_eq!(miss.costly_hit_with(&settled(Class::Dependencies, 1)), None);
    }

    #[test]
    fn only_a_hit_with_a_measured_restore_feeds_the_book() {
        let book = CostBook::new();
        let mut miss = attached(Outcome::Miss(crate::Miss::Absent));
        miss.stats.clone_ns = Some(900);
        let mut unmeasured = attached(hit());
        unmeasured.stats.lookup_ns = Some(5);
        let mut measured = attached(hit());
        measured.stats.lock_wait_ns = Some(100);
        measured.stats.clone_ns = Some(900);
        for _ in 0..crate::cost::MIN_SAMPLES {
            book.observe(&miss);
            book.observe(&unmeasured);
        }
        assert_eq!(book.restore(Class::Dependencies), None);
        for _ in 0..crate::cost::MIN_SAMPLES {
            book.observe(&measured);
        }
        assert_eq!(book.restore(Class::Dependencies).map(|e| e.ns), Some(1_000));
    }

    #[test]
    fn costly_reasons_have_stable_names() {
        assert_eq!(Costly::CopiedAll.as_str(), "copied_all");
        assert_eq!(Costly::Slow.as_str(), "slow");
    }
}
