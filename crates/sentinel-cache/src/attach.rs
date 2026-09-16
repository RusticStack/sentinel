//! The carrier between restore (K02) and publish (K03): what one declared
//! `cache:` entry became for one attempt. Preparation fills one per
//! declaration; finalization reads them to publish the job's writes.
//! Both directions share the derivations here — a write must record
//! exactly what reads ask for, or the two never meet.

use std::path::PathBuf;

use sentinel_core::TenantId;
use sentinel_pipeline::schema::Cache;
use sentinel_protocol::cache::Class;

use crate::{
    lease::Lease,
    manifest::{Compat, key_stem},
    outcome::Outcome,
    publish::SkipReason,
    scope::{Platform, Scope},
};

/// The tenant a scope records when the job context carries none — a
/// protocol <6 peer cannot name one. A fixed, valid v4 UUID: never
/// random, so two tenant-less jobs still share a scope path, and a
/// manifest recorded here can never collide with a real tenant's claim.
pub const UNKNOWN_TENANT: TenantId = match TenantId::from_bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]) {
    Ok(tenant) => tenant,
    Err(_) => panic!("constant is a valid v4 uuid"),
};

/// The worker's cache store is `<data_dir>/cache` — restore reads it,
/// publish (K03) writes it, and the reflink probe runs against it so the
/// `Capabilities::REFLINK` bit and the clone backend agree.
pub const ROOT_DIR: &str = "cache";

/// The rendered key's byte cap — the same bound `manifest` enforces on
/// decode (`MAX_KEY_BYTES` there), so a key that cannot serve is refused
/// at render rather than at the manifest boundary.
pub const MAX_KEY_BYTES: usize = 1024;

/// Absolute declared paths are materialized under this directory inside
/// the workspace and bound into the container. A relative declaration
/// that names it is refused: the private area is the cache machinery's,
/// not a job's.
pub const PRIVATE_DIR: &str = ".sentinel-cache";

/// The `Compat` a bare `cache:` declaration carries (docs/cache.md).
/// Recipes (K07) pin real tool/installer values; for a bare declaration
/// the name is the tool identity, the rendered key is the exact
/// materialization input and the compiler namespaces modes internally —
/// the pins record the shape without information a caller could vary.
/// Restore and publish both derive through this function.
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
        // K06: a bare `class: compiler` declaration's namespace is the key
        // stem alone — `entry_key` already gives each stem its own entry
        // directory (and `current` pointer) and `compatible` re-verifies
        // the stem inside it, so recording `key_stem(key)` here would only
        // ever duplicate the check the manifest just ran. `flags` stays
        // empty as the reserved channel a recipe fills with a rendered
        // namespace token when it wants a pin tighter than the stem.
        Class::Compiler => Compat::Compiler {
            flags: String::new(),
        },
    }
}

/// The key an entry directory answers to: the stem for `downloads` and
/// `compiler` (the classes that serve across compatible key tails), the
/// full rendered key for `dependencies` (exact match only). Restore and
/// publish must derive the same entry or they never meet.
pub fn entry_key(class: Class, key: &str) -> &str {
    match class {
        Class::Downloads | Class::Compiler => key_stem(key),
        Class::Dependencies => key,
    }
}

/// One declared cache, resolved for a job.
pub struct Attached {
    /// The pipeline's cache name.
    pub name: String,
    /// The scope the entry lives under — every boundary dimension
    /// resolved for this run.
    pub scope: Scope,
    /// The rendered user key (`hash_files` evaluated against the pinned
    /// checkout, so it is evaluated only after it lands).
    pub key: String,
    /// The class's compatibility inputs for this request — what a
    /// published manifest records.
    pub compat: Compat,
    /// The generation the private view was cloned from; `None` on a miss.
    /// Publish reads it for incremental reuse.
    pub generation: Option<String>,
    /// What the lookup answered — hit, or the explainable miss reason.
    pub outcome: Outcome,
    /// One resolved declared path per `cache.paths` entry, in
    /// declaration order: `targets[i]` materializes the generation's
    /// `payload/<i>/` tree and publish reads it back.
    pub targets: Vec<Target>,
    /// The pin on the entry for the attempt's run: keeps the source
    /// generation (and this writer's staging) away from GC, and lets an
    /// incremental publish still read the generation it cloned from.
    /// Released with the `Attached`.
    pub lease: Option<Lease>,
    /// Restore- and commit-path measurements for the availability
    /// summaries (K08); `None` where a phase never ran — a miss never
    /// clones, and an unworthy verdict never commits.
    pub stats: Stats,
}

/// The wall-time bound on a nominal hit's wait-plus-clone (K08), part of
/// the costly-hit rule `docs/cache.md` states. A healthy restore — a
/// per-file `FICLONE` pass, or a warm copy of a dependency payload at
/// even 100 MiB/s — is nowhere near it; five seconds is deliberately
/// generous so only a restore that plausibly cost more than rebuilding
/// the dependency is flagged, and flagged is all it ever is: a diagnostic,
/// never a verdict.
pub const COSTLY_HIT_NS: u64 = 5_000_000_000;

/// Which costly-hit clause a nominal hit tripped (docs/cache.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Costly {
    /// The root is `Backend::Reflink` yet every payload byte was copied:
    /// the filesystem refused each file, so the "hit" paid a full copy.
    CopiedAll,
    /// `lock_wait_ns + clone_ns` exceeded [`COSTLY_HIT_NS`].
    Slow,
}

impl Costly {
    /// The stable lowercase spelling for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CopiedAll => "copied_all",
            Self::Slow => "slow",
        }
    }
}

/// What a commit did with the job's writable views (K03), recorded for
/// the summary's per-entry record (K08).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Committed {
    /// A new generation was sealed: `staged_bytes` of payload, of which
    /// `reused_bytes` were hardlinked out of the source generation — the
    /// rest, `staged_bytes - reused_bytes`, is what the job's view
    /// rewrote.
    Sealed {
        staged_bytes: u64,
        reused_bytes: u64,
    },
    /// The commit answered a stable skip reason; nothing was staged.
    Skipped(SkipReason),
    /// The commit errored; the bounded detail went to the cache note.
    Failed,
}

impl Attached {
    /// The K08 costly-hit rule evaluated on a finished restore: `Some`
    /// when a nominal hit paid rebuild-scale cost — a reflink root that
    /// ended up copying every payload byte, or a wait-plus-clone past
    /// [`COSTLY_HIT_NS`]. `None` on a miss and on a plausible hit.
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

/// One declared path resolved for the job.
pub struct Target {
    /// The declared path exactly as written.
    pub declared: String,
    /// The host directory holding the job's writable view. Relative
    /// declared paths materialize inside the workspace (the existing
    /// mount carries them); absolute ones get a private directory plus
    /// a bind mount.
    pub dir: PathBuf,
    /// The path the container sees for `dir`: `/workspace/...` for
    /// workspace-relative declarations, the declared absolute path for
    /// mounts.
    pub container: String,
    /// True when `dir` reaches the container through a bind mount —
    /// absolute declared paths only.
    pub mount: bool,
}

/// Restore- and commit-path measurements. Durations are `Option` per the
/// reporting convention: a phase that never ran is absent, never zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Manifest read plus compatibility check.
    pub lookup_ns: Option<u64>,
    /// Lease-acquisition wait.
    pub lock_wait_ns: Option<u64>,
    /// Payload materialization (clone or copy).
    pub clone_ns: Option<u64>,
    /// The bounded first-read sample after a hit's clone materialized —
    /// one ≤4 KiB read of the largest listed file per target. Cold-extent
    /// cost the clone's wall time hides (the K02 probe showed it is
    /// real); absent when no regular file was listed to sample.
    pub first_touch_ns: Option<u64>,
    /// Files and payload bytes materialized.
    pub files: u64,
    pub bytes: u64,
    /// Bytes actually copied — reflinked files don't count.
    pub copied_bytes: u64,
    /// The backend the clone used.
    pub reflink: bool,
    /// The commit's wall time; `None` while no publish ran — an unworthy
    /// verdict or a finalization that never reached it.
    pub commit_ns: Option<u64>,
    /// What the commit settled into.
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

    /// The smallest `Attached` the rule reads: an outcome plus the stats
    /// fields the clauses inspect; the rest is carrier shape.
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

    /// The K08 rule (docs/cache.md): a nominal hit that paid a full copy
    /// on a reflink root, or waited and cloned past the bound, is flagged
    /// — a miss never is, and neither is a plausible restore.
    #[test]
    fn the_costly_hit_rule_flags_only_implausible_hits() {
        // A miss with damning-looking stats is still just a miss.
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

        // A partial copy on a reflink root is the documented fallback,
        // not a flag; on a copy root a full copy is simply the backend.
        full_copy.stats.copied_bytes = 99;
        assert_eq!(full_copy.costly_hit(), None);
        let mut copied = attached(hit());
        copied.stats.bytes = 100;
        copied.stats.copied_bytes = 100;
        assert_eq!(copied.costly_hit(), None);
        // An empty payload cannot have paid a copy.
        let mut empty = attached(hit());
        empty.stats.reflink = true;
        assert_eq!(empty.costly_hit(), None);

        // Wait plus clone strictly over the bound trips `Slow`; at the
        // bound it does not, and the first clause still wins when both do.
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
