//! The `manifest` file inside a generation directory: what the generation
//! was sealed under and what it can still serve. The file is
//! `sentinel.cache` magic, a format byte, a reserved zero byte, then a
//! postcard body — 16 bytes of head, `MAX_MANIFEST_BYTES` at most, never
//! read unbounded.
//!
//! The sibling `files` blob carries the per-file listing. It is separate
//! because lookups read manifests and materialization reads listings; a
//! 200k-file listing must never inflate the lookup path. The manifest pins
//! the blob's digest, so the anchor here is enough to trust it.

use std::path::Path;

use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_pipeline::schema::{valid_id, valid_relative_path};
use sentinel_protocol::cache::{Class, Trust};
use serde::{Deserialize, Serialize};

use crate::{
    outcome::{Hit, Miss, Outcome},
    scope::{Platform, Scope},
};

/// Manifest format this build reads and writes.
pub const FORMAT: u8 = 1;
/// The `files` blob format.
pub const FILES_FORMAT: u8 = 1;
const MAGIC: &[u8; 14] = b"sentinel.cache";
const FILES_MAGIC: &[u8; 14] = b"sentinel.files";
/// Magic + version + one reserved byte, kept zero.
pub const HEAD_BYTES: usize = 16;
/// Manifests are lookup-path reads: small and tightly capped. 64 KiB is
/// far above any well-formed manifest (hundreds of bytes).
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
/// The `files` listing is only read to materialize; still strictly capped.
pub const MAX_FILES_BLOB_BYTES: u64 = 64 << 20;
/// Entries one `files` blob may name.
pub const MAX_FILE_ENTRIES: u32 = 1 << 20;
/// Bounds on the free-text fields: cache keys render under a template cap
/// and class inputs are short tokens; both get headroom, neither is
/// unbounded.
const MAX_KEY_BYTES: usize = 1024;
const MAX_FIELD_BYTES: usize = 256;

/// The boundary a generation was sealed under — every scope dimension,
/// recorded so the manifest alone decides what it may serve. A directory
/// moved under a different scope is caught here, not by its path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    /// Raw `TenantId` bytes; validated back to a v4 UUID on decode.
    pub tenant: [u8; 16],
    /// Raw `RepoId` bytes.
    pub repo: [u8; 16],
    pub class: Class,
    pub trust: Trust,
    pub platform: Platform,
    /// The full toolchain descriptor digest; the scope path shows only
    /// its first 8 bytes.
    pub toolchain: [u8; 32],
    /// The cache name — the scope's last component.
    pub name: String,
}

impl Boundary {
    pub fn of(scope: &Scope) -> Boundary {
        Boundary {
            tenant: *scope.tenant.as_bytes(),
            repo: *scope.repo.as_bytes(),
            class: scope.class,
            trust: scope.trust,
            platform: scope.platform,
            toolchain: scope.toolchain,
            name: scope.name.clone(),
        }
    }
}

/// What a request needs to match, beyond the boundary and the key. The
/// variant is the class's own rule; `read` rejects a manifest whose
/// variant disagrees with `boundary.class`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compat {
    /// `downloads`: tool-addressed blobs. `tool` pins the installing
    /// tool's protocol (`cargo`, `npm`, …); reuse is allowed across
    /// compatible lockfile edits because the tool validates content.
    Downloads { tool: String },
    /// `dependencies`: an exact materialization. Every recorded input
    /// must match — the whole point of the class.
    Dependencies {
        /// BLAKE3 of the lockfile/manifest set the install consumed.
        lock: [u8; 32],
        /// The installer identity and its flag string (`cargo`,
        /// `pip --no-deps`, …).
        installer: String,
        flags: String,
        /// ABI tag the materialization was built for.
        abi: String,
    },
    /// `compiler`: a stable toolchain namespace. The compiler owns
    /// input-level invalidation inside it; the store pins the flags
    /// namespace the entries were written under.
    Compiler { flags: String },
}

/// One file inside a generation, relative to its directory — what K02
/// clones and verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// `/`-separated relative path, `valid_relative_path`-shaped.
    pub path: String,
    pub size: u64,
    /// BLAKE3 of the file's content.
    pub digest: [u8; 32],
    /// Permission bits worth keeping (the exec bit on tools).
    pub mode: u32,
}

/// The `files` blob body: the generation's listing, sorted by path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesBlob {
    pub entries: Vec<FileEntry>,
}

/// A sealed generation's metadata. `sealed_ms == 0` means the write never
/// completed; an unsealed generation is always a miss.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub boundary: Boundary,
    /// The rendered key this generation was written under.
    pub key: String,
    /// The class's compatibility inputs as recorded at seal.
    pub compat: Compat,
    /// Unix milliseconds when sealed; 0 while unsealed.
    pub sealed_ms: u64,
    /// Total payload bytes the `files` blob listed at seal time.
    pub bytes: u64,
    /// Entry count of the `files` blob.
    pub files: u32,
    /// BLAKE3 of the `files` blob — the anchor K02 verifies before
    /// materializing.
    pub files_digest: [u8; 32],
}

/// What a lookup asks for: the scope to serve, the rendered key, and the
/// class's compatibility inputs.
pub struct Request<'a> {
    pub scope: &'a Scope,
    pub key: &'a str,
    pub compat: &'a Compat,
}

/// The part of a key that is stable across content edits: everything
/// before the last `-` — `cargo-9f8e…` and `npm-41aa…` differ in their
/// volatile hash tail, and `downloads`/`compiler` namespaces serve by
/// stem. A key with no `-` is its own stem, so the rule degrades to an
/// exact match.
pub(crate) fn key_stem(key: &str) -> &str {
    key.rsplit_once('-').map_or(key, |(stem, _)| stem)
}

impl Manifest {
    /// The unsealed manifest for a generation still being written; K02
    /// fills `bytes`/`files`/`files_digest` from the blob it produced and
    /// calls `seal` last.
    pub fn writing(scope: &Scope, key: &str, compat: Compat) -> Manifest {
        Manifest {
            boundary: Boundary::of(scope),
            key: key.to_owned(),
            compat,
            sealed_ms: 0,
            bytes: 0,
            files: 0,
            files_digest: [0; 32],
        }
    }

    /// Stamp the seal time; a sealed manifest may serve.
    pub fn seal(&mut self, now: UnixMillis) {
        self.sealed_ms = u64::try_from(now.0).unwrap_or(0);
    }

    pub const fn sealed(&self) -> bool {
        self.sealed_ms != 0
    }

    /// `head + postcard(manifest)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES + 64);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT);
        out.push(0);
        out.extend_from_slice(&postcard::to_allocvec(self).expect("manifest encodes"));
        out
    }

    /// Bytes → manifest. Every failure is a typed `Miss`: nothing here
    /// panics and nothing guesses.
    pub fn decode(bytes: &[u8]) -> Result<Manifest, Miss> {
        if bytes.len() < HEAD_BYTES || &bytes[..MAGIC.len()] != MAGIC {
            return Err(Miss::Corrupt);
        }
        if bytes[MAGIC.len()] != FORMAT {
            return Err(Miss::UnsupportedVersion);
        }
        if bytes[MAGIC.len() + 1] != 0 {
            return Err(Miss::Corrupt);
        }
        let manifest: Manifest =
            postcard::from_bytes(&bytes[HEAD_BYTES..]).map_err(|_| Miss::Corrupt)?;
        manifest.validate().map(|_| manifest)
    }

    /// Semantic checks after decode: a manifest that parses but is wrong
    /// is `Invalid`, distinct from bytes that would not parse.
    fn validate(&self) -> Result<(), Miss> {
        let bad = || Miss::Invalid;
        if TenantId::from_bytes(self.boundary.tenant).is_err()
            || RepoId::from_bytes(self.boundary.repo).is_err()
            || !valid_id(&self.boundary.name)
            || self.key.is_empty()
            || self.key.len() > MAX_KEY_BYTES
            || self.files > MAX_FILE_ENTRIES
        {
            return Err(bad());
        }
        let class = self.boundary.class;
        let ok = match &self.compat {
            Compat::Downloads { tool } => {
                class == Class::Downloads && !tool.is_empty() && tool.len() <= MAX_FIELD_BYTES
            }
            Compat::Dependencies {
                installer,
                flags,
                abi,
                ..
            } => {
                class == Class::Dependencies
                    && !installer.is_empty()
                    && installer.len() <= MAX_FIELD_BYTES
                    && flags.len() <= MAX_FIELD_BYTES
                    && abi.len() <= MAX_FIELD_BYTES
            }
            Compat::Compiler { flags } => {
                class == Class::Compiler && flags.len() <= MAX_FIELD_BYTES
            }
        };
        if ok { Ok(()) } else { Err(bad()) }
    }

    /// Whether this manifest may serve `want`. First mismatch wins and is
    /// the reason, so an explanation names the outermost broken boundary.
    /// Returns the recorded payload bytes on a hit.
    pub fn compatible(&self, want: &Request<'_>) -> Result<u64, Miss> {
        let b = &self.boundary;
        let s = want.scope;
        if b.class != s.class {
            return Err(Miss::WrongClass);
        }
        if b.tenant != *s.tenant.as_bytes() {
            return Err(Miss::WrongTenant);
        }
        if b.repo != *s.repo.as_bytes() {
            return Err(Miss::WrongRepo);
        }
        if b.trust != s.trust {
            return Err(Miss::WrongTrust);
        }
        if b.platform != s.platform {
            return Err(Miss::WrongPlatform);
        }
        if b.toolchain != s.toolchain {
            return Err(Miss::WrongToolchain);
        }
        if b.name != s.name {
            return Err(Miss::WrongName);
        }
        match (&self.compat, want.compat) {
            (Compat::Downloads { tool }, Compat::Downloads { tool: want_tool }) => {
                // The namespace, not the volatile tail: `cargo-<h1>` may
                // serve `cargo-<h2>` because the tool validates content.
                if key_stem(&self.key) != key_stem(want.key) {
                    return Err(Miss::WrongKey);
                }
                if tool != want_tool {
                    return Err(Miss::Incompatible);
                }
            }
            (
                Compat::Dependencies {
                    lock,
                    installer,
                    flags,
                    abi,
                },
                Compat::Dependencies {
                    lock: want_lock,
                    installer: want_installer,
                    flags: want_flags,
                    abi: want_abi,
                },
            ) => {
                // Exact materialization: the key and every recorded input.
                if self.key != want.key {
                    return Err(Miss::WrongKey);
                }
                if lock != want_lock
                    || installer != want_installer
                    || flags != want_flags
                    || abi != want_abi
                {
                    return Err(Miss::Incompatible);
                }
            }
            (Compat::Compiler { flags }, Compat::Compiler { flags: want_flags }) => {
                // The compiler invalidates per input inside the namespace;
                // the store pins stem and flags only.
                if key_stem(&self.key) != key_stem(want.key) {
                    return Err(Miss::WrongKey);
                }
                if flags != want_flags {
                    return Err(Miss::Incompatible);
                }
            }
            // A `compat` variant from another class is nonsense input;
            // `read` already rejects such manifests as `Invalid`.
            _ => return Err(Miss::Incompatible),
        }
        Ok(self.bytes)
    }
}

/// Read and verify the manifest in a generation directory. Bounded: at
/// most `MAX_MANIFEST_BYTES + 1` bytes are ever read, and every failure
/// mode is a `Miss` — a cache must degrade a build to a rebuild, never
/// break it.
pub fn read(generation_dir: &Path) -> Outcome {
    use std::io::Read;
    let file = match std::fs::File::open(generation_dir.join(crate::scope::MANIFEST_NAME)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Miss(Miss::Absent),
        Err(_) => return Outcome::Miss(Miss::Corrupt),
    };
    let mut buf = Vec::new();
    match file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut buf) {
        Ok(_) if buf.len() as u64 > MAX_MANIFEST_BYTES => Outcome::Miss(Miss::Corrupt),
        Ok(_) => match Manifest::decode(&buf) {
            Ok(manifest) if !manifest.sealed() => Outcome::Miss(Miss::Unsealed),
            Ok(manifest) => Outcome::Hit(Box::new(Hit {
                bytes: manifest.bytes,
                manifest,
            })),
            Err(miss) => Outcome::Miss(miss),
        },
        Err(_) => Outcome::Miss(Miss::Corrupt),
    }
}

/// Read the manifest, then apply the request's boundary and class rule —
/// the full lookup. The `current` pointer and generation choice are K03's;
/// this answers "may this generation dir serve this request".
pub fn lookup(generation_dir: &Path, want: &Request<'_>) -> Outcome {
    match read(generation_dir) {
        Outcome::Hit(hit) => match hit.manifest.compatible(want) {
            Ok(bytes) => Outcome::Hit(Box::new(Hit {
                manifest: hit.manifest,
                bytes,
            })),
            Err(miss) => Outcome::Miss(miss),
        },
        miss => miss,
    }
}

impl FilesBlob {
    /// `head + postcard(blob)`; the entries are stored in the order given —
    /// writers sort by path so reads and the manifest digest are stable.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES + 64);
        out.extend_from_slice(FILES_MAGIC);
        out.push(FILES_FORMAT);
        out.push(0);
        out.extend_from_slice(&postcard::to_allocvec(self).expect("files blob encodes"));
        out
    }

    /// BLAKE3 of the encoded blob — the `files_digest` a manifest records.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<FilesBlob, Miss> {
        if bytes.len() < HEAD_BYTES || &bytes[..FILES_MAGIC.len()] != FILES_MAGIC {
            return Err(Miss::Corrupt);
        }
        if bytes[FILES_MAGIC.len()] != FILES_FORMAT {
            return Err(Miss::UnsupportedVersion);
        }
        if bytes[FILES_MAGIC.len() + 1] != 0 {
            return Err(Miss::Corrupt);
        }
        let blob: FilesBlob =
            postcard::from_bytes(&bytes[HEAD_BYTES..]).map_err(|_| Miss::Corrupt)?;
        if blob.entries.len() as u32 > MAX_FILE_ENTRIES {
            return Err(Miss::Invalid);
        }
        for e in &blob.entries {
            if !valid_relative_path(&e.path) {
                // A listing entry that escapes the generation must never
                // reach materialization.
                return Err(Miss::Invalid);
            }
        }
        Ok(blob)
    }
}

/// Read the `files` listing in a generation directory — bounded like
/// `read`, and a `Miss` on the same terms.
pub fn read_files(generation_dir: &Path) -> Result<FilesBlob, Miss> {
    use std::io::Read;
    let file = match std::fs::File::open(generation_dir.join(crate::scope::FILES_NAME)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Miss::Absent),
        Err(_) => return Err(Miss::Corrupt),
    };
    let mut buf = Vec::new();
    match file.take(MAX_FILES_BLOB_BYTES + 1).read_to_end(&mut buf) {
        Ok(_) if buf.len() as u64 > MAX_FILES_BLOB_BYTES => Err(Miss::Corrupt),
        Ok(_) => FilesBlob::decode(&buf),
        Err(_) => Err(Miss::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use sentinel_protocol::negotiate::Arch;

    use super::*;
    use crate::scope::{Os, entry_name};

    fn scope() -> Scope {
        Scope::new(
            TenantId::new(),
            RepoId::new(),
            Class::Dependencies,
            Trust::Protected,
            Platform {
                os: Os::Linux,
                arch: Arch::X86_64,
            },
            Scope::toolchain_digest(b"rust 1.85 linux"),
            "deps",
        )
        .unwrap()
    }

    fn deps_compat() -> Compat {
        Compat::Dependencies {
            lock: *blake3::hash(b"Cargo.lock").as_bytes(),
            installer: "cargo".to_string(),
            flags: "--locked".to_string(),
            abi: "glibc-2.39".to_string(),
        }
    }

    /// A sealed, valid manifest for `scope()` under key `deps-<hash>`.
    fn manifest(scope: &Scope, key: &str, compat: Compat) -> Manifest {
        let mut m = Manifest::writing(scope, key, compat);
        m.bytes = 1234;
        m.files = 3;
        m.files_digest = *blake3::hash(b"files").as_bytes();
        m.seal(UnixMillis(1_700_000_000_000));
        m
    }

    fn request<'a>(scope: &'a Scope, key: &'a str, compat: &'a Compat) -> Request<'a> {
        Request { scope, key, compat }
    }

    #[test]
    fn manifest_round_trips() {
        let s = scope();
        let m = manifest(&s, "deps-aa00", deps_compat());
        let bytes = m.encode();
        assert_eq!(&bytes[..14], b"sentinel.cache");
        assert_eq!(bytes[14], FORMAT);
        assert_eq!(bytes[15], 0);
        assert_eq!(Manifest::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn every_truncation_is_corrupt() {
        let m = manifest(&scope(), "deps-aa00", deps_compat());
        let bytes = m.encode();
        for len in 0..bytes.len() {
            assert!(
                matches!(Manifest::decode(&bytes[..len]), Err(Miss::Corrupt)),
                "prefix len {len}"
            );
        }
    }

    #[test]
    fn head_corruption_is_typed() {
        let m = manifest(&scope(), "deps-aa00", deps_compat());
        let good = m.encode();
        // Magic, version and the reserved byte each have their own answer.
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(Manifest::decode(&bad), Err(Miss::Corrupt));
        let mut bad = good.clone();
        bad[14] = FORMAT + 1;
        assert_eq!(Manifest::decode(&bad), Err(Miss::UnsupportedVersion));
        bad[14] = 0;
        assert_eq!(Manifest::decode(&bad), Err(Miss::UnsupportedVersion));
        let mut bad = good;
        bad[15] = 1;
        assert_eq!(Manifest::decode(&bad), Err(Miss::Corrupt));
    }

    #[test]
    fn a_semantically_wrong_manifest_is_invalid_not_corrupt() {
        let s = scope();
        let m = manifest(&s, "deps-aa00", deps_compat());
        let mut bytes = m.encode();
        // First body byte is the tenant's first byte; byte 6 of a UUID
        // carries the version nibble — anything but 4 is `Invalid`.
        bytes[HEAD_BYTES + 6] ^= 0x40;
        assert_eq!(Manifest::decode(&bytes), Err(Miss::Invalid));
        // A `compat` payload from another class cannot be validated away.
        let wrong = Manifest {
            compat: Compat::Downloads {
                tool: "cargo".to_string(),
            },
            ..m
        };
        assert_eq!(Manifest::decode(&wrong.encode()), Err(Miss::Invalid));
        // An unbounded key is invalid, not merely wrong.
        let mut long = manifest(&s, "deps-aa00", deps_compat());
        long.key = "k".repeat(MAX_KEY_BYTES + 1);
        assert_eq!(Manifest::decode(&long.encode()), Err(Miss::Invalid));
    }

    #[test]
    fn unsealed_generations_are_a_miss() {
        let s = scope();
        let mut m = manifest(&s, "deps-aa00", deps_compat());
        m.sealed_ms = 0;
        let dir = tempfile::tempdir().unwrap();
        let generation = dir.path().join(crate::scope::gen_name(1, 1));
        std::fs::create_dir(&generation).unwrap();
        std::fs::write(generation.join(crate::scope::MANIFEST_NAME), m.encode()).unwrap();
        assert_eq!(read(&generation), Outcome::Miss(Miss::Unsealed));
        let c = deps_compat();
        assert_eq!(
            lookup(&generation, &request(&s, "deps-aa00", &c)),
            Outcome::Miss(Miss::Unsealed)
        );
    }

    #[test]
    fn read_is_bounded_and_never_fails_a_build() {
        let dir = tempfile::tempdir().unwrap();
        let generation = dir.path().join("generation-1-00000001");
        std::fs::create_dir(&generation).unwrap();
        // Nothing at all.
        assert_eq!(read(&generation), Outcome::Miss(Miss::Absent));
        // An oversize manifest is corrupt — and the read never allocates
        // past the cap.
        std::fs::write(
            generation.join(crate::scope::MANIFEST_NAME),
            vec![b'x'; (MAX_MANIFEST_BYTES + 8) as usize],
        )
        .unwrap();
        assert_eq!(read(&generation), Outcome::Miss(Miss::Corrupt));
        // A short garbage file likewise.
        std::fs::write(generation.join(crate::scope::MANIFEST_NAME), b"junk").unwrap();
        assert_eq!(read(&generation), Outcome::Miss(Miss::Corrupt));
        // And a well-formed manifest hits.
        let s = scope();
        let m = manifest(&s, "deps-aa00", deps_compat());
        std::fs::write(generation.join(crate::scope::MANIFEST_NAME), m.encode()).unwrap();
        match read(&generation) {
            Outcome::Hit(h) => {
                assert_eq!(h.manifest, m);
                assert_eq!(h.bytes, 1234);
            }
            other => panic!("expected hit, got {other:?}"),
        }
    }

    #[test]
    fn every_boundary_mismatch_is_named() {
        let s = scope();
        let m = manifest(&s, "deps-aa00", deps_compat());
        let want = deps_compat();
        assert_eq!(m.compatible(&request(&s, "deps-aa00", &want)), Ok(1234));

        let mut s2 = s.clone();
        s2.class = Class::Compiler;
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongClass)
        );
        let mut s2 = s.clone();
        s2.tenant = TenantId::new();
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongTenant)
        );
        let mut s2 = s.clone();
        s2.repo = RepoId::new();
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongRepo)
        );
        let mut s2 = s.clone();
        s2.trust = Trust::PullRequest;
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongTrust)
        );
        let mut s2 = s.clone();
        s2.platform.arch = Arch::Aarch64;
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongPlatform)
        );
        let mut s2 = s.clone();
        s2.toolchain = Scope::toolchain_digest(b"rust 1.86");
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongToolchain)
        );
        let mut s2 = s.clone();
        s2.name = "other".to_string();
        assert_eq!(
            m.compatible(&request(&s2, "deps-aa00", &want)),
            Err(Miss::WrongName)
        );
        assert_eq!(
            m.compatible(&request(&s, "deps-bb11", &want)),
            Err(Miss::WrongKey)
        );
        // Any class input differing is `Incompatible`, not `WrongKey`.
        for field in 0..4 {
            let mut w = deps_compat();
            if let Compat::Dependencies {
                lock,
                installer,
                flags,
                abi,
            } = &mut w
            {
                match field {
                    0 => lock[0] ^= 1,
                    1 => *installer = "bazel".to_string(),
                    2 => *flags = "--offline".to_string(),
                    _ => *abi = "musl".to_string(),
                }
            }
            assert_eq!(
                m.compatible(&request(&s, "deps-aa00", &w)),
                Err(Miss::Incompatible),
                "field {field}"
            );
        }
    }

    #[test]
    fn downloads_reuse_within_the_key_stem() {
        let mut s = scope();
        s.class = Class::Downloads;
        let m = manifest(
            &s,
            "cargo-aa00",
            Compat::Downloads {
                tool: "cargo".to_string(),
            },
        );
        let want = Compat::Downloads {
            tool: "cargo".to_string(),
        };
        // Same stem, different volatile tail: a compatible lockfile edit.
        assert_eq!(m.compatible(&request(&s, "cargo-bb11", &want)), Ok(1234));
        // A different stem is a different namespace.
        assert_eq!(
            m.compatible(&request(&s, "npm-bb11", &want)),
            Err(Miss::WrongKey)
        );
        // A different tool under the same stem is incompatible.
        let pip = Compat::Downloads {
            tool: "pip".to_string(),
        };
        assert_eq!(
            m.compatible(&request(&s, "cargo-bb11", &pip)),
            Err(Miss::Incompatible)
        );
    }

    #[test]
    fn compiler_entries_share_a_flags_namespace() {
        let mut s = scope();
        s.class = Class::Compiler;
        let m = manifest(
            &s,
            "obj-aa00",
            Compat::Compiler {
                flags: "-O2".to_string(),
            },
        );
        let want = Compat::Compiler {
            flags: "-O2".to_string(),
        };
        // The compiler invalidates inputs itself; the store only pins the
        // namespace.
        assert_eq!(m.compatible(&request(&s, "obj-bb11", &want)), Ok(1234));
        let debug = Compat::Compiler {
            flags: "-O0".to_string(),
        };
        assert_eq!(
            m.compatible(&request(&s, "obj-bb11", &debug)),
            Err(Miss::Incompatible)
        );
    }

    #[test]
    fn lookup_combines_read_and_compatibility() {
        let s = scope();
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join(entry_name("deps-aa00"));
        let generation = entry.join(crate::scope::gen_name(1_700_000_000_000, 1));
        std::fs::create_dir_all(&generation).unwrap();
        let m = manifest(&s, "deps-aa00", deps_compat());
        std::fs::write(generation.join(crate::scope::MANIFEST_NAME), m.encode()).unwrap();
        let want = deps_compat();
        match lookup(&generation, &request(&s, "deps-aa00", &want)) {
            Outcome::Hit(h) => assert_eq!(h.bytes, 1234),
            other => panic!("expected hit, got {other:?}"),
        }
        // The same directory under a pull-request request misses.
        let mut pr = s.clone();
        pr.trust = Trust::PullRequest;
        assert_eq!(
            lookup(&generation, &request(&pr, "deps-aa00", &want)),
            Outcome::Miss(Miss::WrongTrust)
        );
    }

    #[test]
    fn files_blob_round_trips_and_validates() {
        let blob = FilesBlob {
            entries: vec![
                FileEntry {
                    path: "lib/a.o".to_string(),
                    size: 10,
                    digest: *blake3::hash(b"a").as_bytes(),
                    mode: 0o644,
                },
                FileEntry {
                    path: "bin/tool".to_string(),
                    size: 20,
                    digest: *blake3::hash(b"b").as_bytes(),
                    mode: 0o755,
                },
            ],
        };
        let bytes = blob.encode();
        assert_eq!(&bytes[..14], b"sentinel.files");
        assert_eq!(FilesBlob::decode(&bytes).unwrap(), blob);
        assert_eq!(blob.digest(), *blake3::hash(&bytes).as_bytes());
        for len in 0..bytes.len() {
            assert!(
                matches!(FilesBlob::decode(&bytes[..len]), Err(Miss::Corrupt)),
                "prefix len {len}"
            );
        }
        // A path that escapes the generation must never reach K02.
        let mut bad = blob.clone();
        bad.entries[0].path = "../outside".to_string();
        assert_eq!(FilesBlob::decode(&bad.encode()), Err(Miss::Invalid));
        let mut bad = blob.clone();
        bad.entries[0].path = "/abs".to_string();
        assert_eq!(FilesBlob::decode(&bad.encode()), Err(Miss::Invalid));
        // And the bounded reader applies the same answers on disk.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_files(dir.path()), Err(Miss::Absent));
        std::fs::write(dir.path().join(crate::scope::FILES_NAME), &bytes).unwrap();
        assert_eq!(read_files(dir.path()).unwrap(), blob);
        std::fs::write(
            dir.path().join(crate::scope::FILES_NAME),
            vec![0u8; (MAX_FILES_BLOB_BYTES + 4) as usize],
        )
        .unwrap();
        assert_eq!(read_files(dir.path()), Err(Miss::Corrupt));
    }
}
