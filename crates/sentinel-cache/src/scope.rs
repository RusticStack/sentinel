//! The `cache/<scope>/<entry>/` half of the worker-local layout
//! (docs/cache.md). Rendering is pure and total: a `Scope` can only be
//! built from components that already pass validation, so a rendered path
//! is always six single safe directory names — never a traversal, never a
//! separator, never an empty segment.

use std::path::{Path, PathBuf};

use sentinel_core::{RepoId, TenantId};
use sentinel_pipeline::schema::valid_id;
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};
use serde::{Deserialize, Serialize};

/// The kernel half of the `os-arch` platform component. Linux is the only
/// executor today; the enum exists so a second OS can never reuse a scope
/// directory silently — it would render a different component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Os {
    Linux = 0,
}

impl Os {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
        }
    }
}

/// The `os-arch` scope component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
}

impl Platform {
    /// `linux-x86_64` — one directory name, always safe.
    pub fn component(self) -> String {
        let mut s = String::with_capacity(12);
        s.push_str(self.os.as_str());
        s.push('-');
        s.push_str(self.arch.as_str());
        s
    }
}

/// Why a scope cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeError {
    /// The cache name is not `valid_id`-shaped — the same rule the schema
    /// enforces, so a compiled pipeline can never produce this.
    BadName,
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadName => f.write_str("cache name is not [a-z0-9][a-z0-9_-]*"),
        }
    }
}
impl std::error::Error for ScopeError {}

/// Every dimension that decides where an entry lives. The path leads with
/// the repository — repo IDs are globally unique, so two tenants can never
/// produce the same scope directory — and the manifest still records the
/// tenant, so a directory moved under another tenant's tree can never
/// serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub class: Class,
    pub trust: Trust,
    pub platform: Platform,
    /// BLAKE3 digest of the toolchain descriptor (image digest, tool
    /// versions — whatever pins "the toolchain"). The path shows the
    /// first 8 bytes as 16 lowercase hex characters.
    pub toolchain: [u8; 32],
    /// The pipeline's cache name.
    pub name: String,
}

impl Scope {
    /// The name must already satisfy the schema's `valid_id` rule; this
    /// re-checks rather than trusts, so metadata built by hand gets the
    /// same answer the parser would have given.
    pub fn new(
        tenant: TenantId,
        repo: RepoId,
        class: Class,
        trust: Trust,
        platform: Platform,
        toolchain: [u8; 32],
        name: &str,
    ) -> Result<Scope, ScopeError> {
        if !valid_id(name) {
            return Err(ScopeError::BadName);
        }
        Ok(Scope {
            tenant,
            repo,
            class,
            trust,
            platform,
            toolchain,
            name: name.to_owned(),
        })
    }

    /// BLAKE3 of a toolchain descriptor, as `Scope::toolchain` wants it.
    pub fn toolchain_digest(descriptor: &[u8]) -> [u8; 32] {
        *blake3::hash(descriptor).as_bytes()
    }

    /// The scope directory relative to the cache root:
    /// `<repo>/<class>/<trust>/<os>-<arch>/<toolchain16>/<name>`.
    pub fn rel_path(&self) -> PathBuf {
        let mut p = PathBuf::from(self.repo.to_string());
        p.push(self.class.as_str());
        p.push(self.trust.as_str());
        p.push(self.platform.component());
        p.push(toolchain16(&self.toolchain));
        p.push(&self.name);
        p
    }

    /// `<root>/<scope>`; the root is the worker's `data_dir/cache`.
    pub fn dir(&self, cache_root: &Path) -> PathBuf {
        cache_root.join(self.rel_path())
    }

    /// `<root>/<scope>/<entry>` for a rendered key.
    pub fn entry_dir(&self, cache_root: &Path, key: &str) -> PathBuf {
        self.dir(cache_root).join(entry_name(key))
    }
}

/// The scope's toolchain component: the first 8 bytes of the descriptor
/// digest as 16 lowercase hex characters.
pub fn toolchain16(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &digest[..8] {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0x0F) as u32, 16).expect("nibble"));
    }
    s
}

/// The entry directory for a rendered key: a readable slug plus 8 bytes of
/// the key's digest, so different keys can never share a directory — a
/// slug collision (or, at 64 bits, an adversarial digest collision) only
/// produces a `WrongKey` miss at manifest check time, never wrong content.
pub fn entry_name(key: &str) -> String {
    let mut slug = String::with_capacity(48);
    for b in key.bytes() {
        if slug.len() == 48 {
            break;
        }
        slug.push(match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => b as char,
            b'A'..=b'Z' => b.to_ascii_lowercase() as char,
            _ => '-',
        });
    }
    let slug = slug.trim_matches(|c| c == '-' || c == '_');
    let mut name = String::with_capacity(65);
    if slug.is_empty() {
        name.push('x');
    } else {
        name.push_str(slug);
    }
    name.push('-');
    name.push_str(&toolchain16(blake3::hash(key.as_bytes()).as_bytes()));
    name
}

/// A generation directory: `gen-<unix_ms>-<rand>` — creation order in the
/// name, an 8-hex random suffix so two generations sealed in the same
/// millisecond never collide.
pub fn gen_name(unix_ms: i64, rand: u32) -> String {
    format!("gen-{unix_ms}-{rand:08x}")
}

/// The manifest file inside a generation directory.
pub const MANIFEST_NAME: &str = "manifest";
/// The file listing inside a generation directory (K02's materialization
/// input): manifest carries only its count, bytes and digest so lookups
/// never pay for it.
pub const FILES_NAME: &str = "files";
/// The entry's pointer to the live generation: a small file naming the
/// `gen-*` directory, swapped atomically at publication (K03).
pub const CURRENT_NAME: &str = "current";
/// Per-entry staging area for generations still being written.
pub const WRITING_NAME: &str = "writing";
/// Per-entry lease markers (K03).
pub const LEASE_NAME: &str = "lease";

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(
        tenant: TenantId,
        repo: RepoId,
        class: Class,
        trust: Trust,
        platform: Platform,
        toolchain: u8,
        name: &str,
    ) -> Scope {
        Scope::new(tenant, repo, class, trust, platform, [toolchain; 32], name).unwrap()
    }

    fn base() -> Scope {
        scope(
            TenantId::new(),
            RepoId::new(),
            Class::Dependencies,
            Trust::Protected,
            Platform {
                os: Os::Linux,
                arch: Arch::X86_64,
            },
            7,
            "deps",
        )
    }

    #[test]
    fn every_boundary_dimension_isolates_the_scope() {
        let a = base();
        assert_eq!(a.rel_path(), a.rel_path(), "same inputs, same path");
        let isolated = |f: &dyn Fn(&mut Scope)| {
            let mut other = a.clone();
            f(&mut other);
            other.rel_path()
        };
        // A different repo is a different tenant's content: repo IDs are
        // globally unique, and it is the leading component — so the two
        // tenants can never produce the same scope directory.
        assert_ne!(a.rel_path(), isolated(&|s| s.repo = RepoId::new()), "repo");
        // The tenant is not a path component (the repo leads); it is still
        // recorded in every manifest boundary, so a directory moved under
        // another tenant's tree can never serve — see manifest tests.
        assert_eq!(
            a.rel_path(),
            isolated(&|s| s.tenant = TenantId::new()),
            "tenant only lives in the manifest"
        );
        assert_ne!(
            a.rel_path(),
            isolated(&|s| s.class = Class::Compiler),
            "class"
        );
        assert_ne!(
            a.rel_path(),
            isolated(&|s| s.trust = Trust::PullRequest),
            "trust"
        );
        assert_ne!(
            a.rel_path(),
            isolated(&|s| s.platform.arch = Arch::Aarch64),
            "platform"
        );
        assert_ne!(
            a.rel_path(),
            isolated(&|s| s.toolchain[0] ^= 1),
            "toolchain"
        );
        assert_ne!(
            a.rel_path(),
            isolated(&|s| s.name = "other".to_string()),
            "name"
        );
    }

    #[test]
    fn scope_components_are_single_safe_names() {
        let s = base();
        let rel = s.rel_path();
        let parts: Vec<_> = rel.iter().collect();
        assert_eq!(parts.len(), 6);
        for part in &parts {
            let text = part.to_str().expect("utf8 names");
            assert!(!text.is_empty());
            assert!(
                text.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{text}"
            );
        }
        assert_eq!(parts[1], "dependencies");
        assert_eq!(parts[2], "protected");
        assert_eq!(parts[3], "linux-x86_64");
        assert_eq!(parts[4].to_str().unwrap().len(), 16);
        assert_eq!(parts[5], "deps");
    }

    #[test]
    fn names_must_be_schema_valid() {
        let t = TenantId::new();
        let r = RepoId::new();
        let p = Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        };
        for bad in ["", "Upper", "a/b", "-x", "..", "a b", &"a".repeat(65)] {
            assert_eq!(
                Scope::new(t, r, Class::Downloads, Trust::Protected, p, [0; 32], bad),
                Err(ScopeError::BadName),
                "{bad}"
            );
        }
        assert!(
            Scope::new(
                t,
                r,
                Class::Downloads,
                Trust::Protected,
                p,
                [0; 32],
                "ok-name_1"
            )
            .is_ok()
        );
    }

    #[test]
    fn entries_differ_per_key_and_stay_safe() {
        let s = base();
        let a = entry_name("cargo-9f8e7d6c");
        let b = entry_name("cargo-00000000");
        assert_ne!(a, b, "different keys, different entries");
        for name in [
            a,
            b,
            entry_name(""),
            entry_name("!!!"),
            entry_name("a/b\\c d"),
        ] {
            assert!(!name.is_empty());
            assert!(name.len() <= 65);
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
                "{name}"
            );
        }
        // Same key, same entry, deterministic across calls.
        assert_eq!(entry_name("cargo-9f8e7d6c"), entry_name("cargo-9f8e7d6c"));
        // Slug collisions are still distinct entries via the digest tail.
        assert_ne!(entry_name("a/b"), entry_name("a\\b"));
        let root = Path::new("/cache");
        let dir = s.entry_dir(root, "cargo-9f8e7d6c");
        assert_eq!(dir.parent().unwrap(), s.dir(root));
    }

    #[test]
    fn generation_names_order_and_differ() {
        assert_eq!(gen_name(1_700_000_000_000, 1), "gen-1700000000000-00000001");
        assert_ne!(gen_name(1, 1), gen_name(1, 2));
        // Unix-millisecond stamps are the same width for the foreseeable
        // future, so directory listings sort oldest-first.
        assert!(gen_name(1_700_000_000_000, 9) < gen_name(1_700_000_000_001, 0));
    }
}
