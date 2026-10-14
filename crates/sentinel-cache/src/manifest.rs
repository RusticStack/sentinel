//! The `files` listing is a separate blob so lookups never pay for a large listing.

use std::path::Path;

use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_pipeline::schema::{valid_id, valid_relative_path};
use sentinel_protocol::cache::{Class, Trust};
use serde::{Deserialize, Serialize};

use crate::{
    outcome::{Hit, Miss, Outcome},
    scope::{Platform, Scope},
};

pub const FORMAT: u8 = 1;
pub const FILES_FORMAT: u8 = 1;
const MAGIC: &[u8; 14] = b"sentinel.cache";
const FILES_MAGIC: &[u8; 14] = b"sentinel.files";
pub const HEAD_BYTES: usize = 16;
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
pub const MAX_FILES_BLOB_BYTES: u64 = 64 << 20;
pub const MAX_FILE_ENTRIES: u32 = 1 << 20;
const MAX_KEY_BYTES: usize = 1024;
const MAX_FIELD_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub tenant: [u8; 16],
    pub repo: [u8; 16],
    pub class: Class,
    pub trust: Trust,
    pub platform: Platform,
    pub toolchain: [u8; 32],
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compat {
    /// Tool-addressed blobs; `tool` pins the installing tool's protocol.
    Downloads { tool: String },
    Dependencies {
        lock: [u8; 32],
        installer: String,
        flags: String,
        abi: String,
    },
    /// A stable toolchain namespace; the store pins the flags entries were written under.
    Compiler { flags: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub digest: [u8; 32],
    pub mode: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesBlob {
    pub entries: Vec<FileEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub boundary: Boundary,
    pub key: String,
    pub compat: Compat,
    pub sealed_ms: u64,
    pub bytes: u64,
    pub files: u32,
    pub files_digest: [u8; 32],
}

pub struct Request<'a> {
    pub scope: &'a Scope,
    pub key: &'a str,
    pub compat: &'a Compat,
}

/// Everything before the last `-`: the volatile hash tail is ignored, and a key without `-` matches exactly.
pub(crate) fn key_stem(key: &str) -> &str {
    key.rsplit_once('-').map_or(key, |(stem, _)| stem)
}

impl Manifest {
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

    pub fn seal(&mut self, now: UnixMillis) {
        self.sealed_ms = u64::try_from(now.0).unwrap_or(0);
    }

    pub const fn sealed(&self) -> bool {
        self.sealed_ms != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES + 64);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT);
        out.push(0);
        out.extend_from_slice(&postcard::to_allocvec(self).expect("manifest encodes"));
        out
    }

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
                if key_stem(&self.key) != key_stem(want.key) {
                    return Err(Miss::WrongKey);
                }
                if flags != want_flags {
                    return Err(Miss::Incompatible);
                }
            }
            _ => return Err(Miss::Incompatible),
        }
        Ok(self.bytes)
    }
}

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
    /// Writers sort by path: the manifest pins the digest of this encoding, so it must be stable.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES + 64);
        out.extend_from_slice(FILES_MAGIC);
        out.push(FILES_FORMAT);
        out.push(0);
        out.extend_from_slice(&postcard::to_allocvec(self).expect("files blob encodes"));
        out
    }

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
                // Escaping paths must never reach materialization.
                return Err(Miss::Invalid);
            }
        }
        Ok(blob)
    }
}

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
        bytes[HEAD_BYTES + 6] ^= 0x40;
        assert_eq!(Manifest::decode(&bytes), Err(Miss::Invalid));
        let wrong = Manifest {
            compat: Compat::Downloads {
                tool: "cargo".to_string(),
            },
            ..m
        };
        assert_eq!(Manifest::decode(&wrong.encode()), Err(Miss::Invalid));
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
        assert_eq!(read(&generation), Outcome::Miss(Miss::Absent));
        std::fs::write(
            generation.join(crate::scope::MANIFEST_NAME),
            vec![b'x'; (MAX_MANIFEST_BYTES + 8) as usize],
        )
        .unwrap();
        assert_eq!(read(&generation), Outcome::Miss(Miss::Corrupt));
        std::fs::write(generation.join(crate::scope::MANIFEST_NAME), b"junk").unwrap();
        assert_eq!(read(&generation), Outcome::Miss(Miss::Corrupt));
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
        assert_eq!(m.compatible(&request(&s, "cargo-bb11", &want)), Ok(1234));
        assert_eq!(
            m.compatible(&request(&s, "npm-bb11", &want)),
            Err(Miss::WrongKey)
        );
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
        let mut bad = blob.clone();
        bad.entries[0].path = "../outside".to_string();
        assert_eq!(FilesBlob::decode(&bad.encode()), Err(Miss::Invalid));
        let mut bad = blob.clone();
        bad.entries[0].path = "/abs".to_string();
        assert_eq!(FilesBlob::decode(&bad.encode()), Err(Miss::Invalid));
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
