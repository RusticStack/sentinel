//! The disk the endpoint serves from: cache archives and artifacts on the worker's own NVMe, each
//! sealed under the sandbox's boundary and verified before it is served.
//!
//! The layout follows the cache store's rule — a directory moved anywhere else can never serve —
//! without joining that store's generation vocabulary, because an Actions cache entry is one opaque
//! archive rather than a tree of files:
//!
//! ```text
//! cache/<repo>/<trust>/<platform>/<key16>/<version16>/gen-<unix_ms>-<rand>/{archive,manifest}
//! cache/<repo>/<trust>/<platform>/<key16>/<version16>/current
//! cache/writing/<upload>.part
//! artifacts/<repo>/<trust>/<run>/<slug>-<rand>/{blob,manifest}
//! artifacts/writing/<upload>/…
//! ```
//!
//! `key16`/`version16` are the first 8 bytes of the client's key and version digests: two keys can
//! never share a directory, and a slug collision is a `wrong_key` miss, never wrong bytes.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub use sentinel_cache::{Os, Platform};

use crate::{Error, Result, Scope};

const CACHE_MAGIC: &[u8; 8] = b"sntlcach";
const ARTIFACT_MAGIC: &[u8; 8] = b"sntlartf";
const FORMAT: u8 = 1;
/// The most a manifest may occupy: read whole or refused, never partially trusted.
const MAX_MANIFEST: usize = 8 << 10;
/// The client's key and version bounds: a cache key is 512 bytes and a version digest a 64-byte hex.
pub const MAX_KEY_BYTES: usize = 512;
pub const MAX_VERSION_BYTES: usize = 128;
/// The most blocks one artifact body may be uploaded in: the pinned client stages 16 MiB chunks, so even
/// a 4 GiB artifact is 256 of them.
const MAX_BLOCKS: usize = 4096;
/// One archive, one artifact. A body beyond these is refused before it is written.
pub const MAX_ARCHIVE_BYTES: u64 = 10 << 30;
pub const MAX_ARTIFACT_BYTES: u64 = 4 << 30;

/// What one read found: the sealed archive, or the reason it cannot be served.
pub enum Lookup {
    Hit(Archive),
    Miss(&'static str),
}

pub struct Archive {
    pub path: PathBuf,
    pub bytes: u64,
    pub digest: [u8; 32],
}

/// One sealed artifact, as a listing or a download names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRow {
    pub name: String,
    pub bytes: u64,
    pub digest: [u8; 32],
    pub run: u64,
    pub job: u64,
    pub id: u64,
    pub sealed_ms: i64,
}

/// The boundary a generation was sealed under, recorded in every manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Boundary {
    tenant: [u8; 16],
    repo: [u8; 16],
    trust: u8,
    platform: Platform,
}

impl Boundary {
    fn of(scope: &Scope) -> Boundary {
        Boundary {
            tenant: *scope.tenant.as_bytes(),
            repo: *scope.repo.as_bytes(),
            trust: scope.trust.to_u8(),
            platform: scope.platform,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CacheManifest {
    boundary: Boundary,
    key: String,
    version: String,
    bytes: u64,
    digest: [u8; 32],
    sealed_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct ArtifactManifest {
    boundary: Boundary,
    run: u64,
    job: u64,
    name: String,
    bytes: u64,
    digest: [u8; 32],
    /// The id this entry answers as, minted at finalize so a later `download-artifact` can name it.
    id: u64,
    sealed_ms: i64,
}

struct Upload {
    scope: Scope,
    key: String,
    version: String,
    file: File,
    path: PathBuf,
    bytes: u64,
}

struct Opening {
    scope: Scope,
    run: u64,
    job: u64,
    name: String,
    dir: PathBuf,
    /// The staged blocks in arrival order, with the id the client gave each.
    blocks: Vec<(String, PathBuf)>,
    blob: PathBuf,
}

#[derive(Default)]
struct Uploads {
    next: u64,
    cache: HashMap<u64, Upload>,
    artifacts: HashMap<u64, Opening>,
}

pub struct Store {
    cache: PathBuf,
    artifacts: PathBuf,
    uploads: Mutex<Uploads>,
}

impl Store {
    /// A store rooted at `root`: `cache` below it for archives, `artifacts` below it for what
    /// `upload-artifact` produced.
    pub fn new(root: &Path) -> Store {
        let store = Store {
            cache: root.join("cache"),
            artifacts: root.join("artifacts"),
            uploads: Mutex::new(Uploads::default()),
        };
        let _ = fs::create_dir_all(store.cache.join("writing"));
        let _ = fs::create_dir_all(store.artifacts.join("writing"));
        store
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache
    }

    pub fn artifact_root(&self) -> &Path {
        &self.artifacts
    }

    /// The entry directory of one key under one boundary.
    pub fn entry_dir(&self, scope: &Scope, key: &str, version: &str) -> PathBuf {
        self.cache
            .join(scope.repo.to_string())
            .join(scope.trust.as_str())
            .join(scope.platform.component())
            .join(hex8(key))
            .join(hex8(version))
    }

    /// Reads the live generation of one entry and checks every boundary it records.
    pub fn lookup(&self, scope: &Scope, key: &str, version: &str) -> Lookup {
        let dir = self.entry_dir(scope, key, version);
        let Some(generation) = current(&dir) else {
            return Lookup::Miss("absent");
        };
        let Some(manifest) = read_cache_manifest(&dir.join(&generation).join("manifest")) else {
            return Lookup::Miss("corrupt");
        };
        if manifest.boundary.tenant != *scope.tenant.as_bytes() {
            return Lookup::Miss("wrong_tenant");
        }
        if manifest.boundary.repo != *scope.repo.as_bytes() {
            return Lookup::Miss("wrong_repo");
        }
        if manifest.boundary.trust != scope.trust.to_u8() {
            return Lookup::Miss("wrong_trust");
        }
        if manifest.boundary.platform != scope.platform {
            return Lookup::Miss("wrong_platform");
        }
        if manifest.key != key {
            return Lookup::Miss("wrong_key");
        }
        if manifest.version != version {
            return Lookup::Miss("wrong_version");
        }
        let path = dir.join(&generation).join("archive");
        match fs::metadata(&path) {
            Ok(meta) if meta.len() == manifest.bytes => Lookup::Hit(Archive {
                path,
                bytes: manifest.bytes,
                digest: manifest.digest,
            }),
            _ => Lookup::Miss("corrupt"),
        }
    }

    /// Serves the generation an archive location names, if it is this sandbox's to serve: the URL is a
    /// capability, and the manifest's boundary is what admits it. The parts are the location's own
    /// components, re-validated as path-shaped hex before any of them reaches the filesystem.
    pub fn archive_at(&self, scope: &Scope, parts: [&str; 6]) -> Option<Archive> {
        let [repo, trust, platform, key16, version16, generation] = parts;
        if repo != scope.repo.to_string()
            || trust != scope.trust.as_str()
            || platform != scope.platform.component()
            || !name16(key16)
            || !name16(version16)
            || !generation_name(generation)
        {
            return None;
        }
        let dir = self
            .cache
            .join(repo)
            .join(trust)
            .join(platform)
            .join(key16)
            .join(version16);
        let manifest = read_cache_manifest(&dir.join(generation).join("manifest"))?;
        if manifest.boundary != Boundary::of(scope) {
            return None;
        }
        let path = dir.join(generation).join("archive");
        let meta = fs::metadata(&path).ok()?;
        (meta.len() == manifest.bytes).then_some(Archive {
            path,
            bytes: manifest.bytes,
            digest: manifest.digest,
        })
    }

    /// The archive location one generation is served from: its boundary and identity, never a pointer
    /// a later save could move.
    pub fn archive_name(
        &self,
        scope: &Scope,
        key: &str,
        version: &str,
        generation: &str,
    ) -> String {
        format!(
            "/_apis/artifactcache/archive/{}/{}/{}/{}/{}/{}",
            scope.repo,
            scope.trust.as_str(),
            scope.platform.component(),
            hex8(key),
            hex8(version),
            generation
        )
    }

    /// Opens an upload for one key. A reserve while an upload of the same key is open is its own
    /// upload: the client reserves once and uploads once.
    pub fn reserve(&self, scope: &Scope, key: &str, version: &str) -> Result<u64> {
        if key.len() > MAX_KEY_BYTES || version.len() > MAX_VERSION_BYTES {
            return Err(Error::Store("cache key"));
        }
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let id = next_id(&mut uploads);
        let path = self.cache.join("writing").join(format!("{id}.part"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        uploads.cache.insert(
            id,
            Upload {
                scope: *scope,
                key: key.to_owned(),
                version: version.to_owned(),
                file,
                path,
                bytes: 0,
            },
        );
        Ok(id)
    }

    /// Appends `bytes` at `offset`. The pinned client uploads chunks in parallel, so a chunk is written
    /// where its `Content-Range` says rather than at the end of what arrived before it.
    pub fn chunk(&self, id: u64, offset: u64, bytes: &[u8], scope: &Scope) -> Result<()> {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let upload = uploads
            .cache
            .get_mut(&id)
            .filter(|upload| upload.scope == *scope)
            .ok_or(Error::Store("unknown upload"))?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= MAX_ARCHIVE_BYTES)
            .ok_or(Error::Store("archive bound"))?;
        upload.file.write_all_at(bytes, offset)?;
        upload.bytes = upload.bytes.max(end);
        Ok(())
    }

    /// Seals one upload: the body must be exactly `size` bytes, and it becomes the entry's live
    /// generation only once its manifest is written.
    pub fn commit(&self, id: u64, size: u64, scope: &Scope) -> Result<()> {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let upload = uploads
            .cache
            .remove(&id)
            .filter(|upload| upload.scope == *scope)
            .ok_or(Error::Store("unknown upload"))?;
        let sealed = (|| {
            if upload.bytes != size || size > MAX_ARCHIVE_BYTES {
                return Err(Error::Store("upload size"));
            }
            let digest = digest_file(&upload.path)?;
            let dir = self.entry_dir(&upload.scope, &upload.key, &upload.version);
            fs::create_dir_all(&dir)?;
            let generation = generation_name_now();
            let target = dir.join(&generation);
            fs::create_dir_all(&target)?;
            fs::rename(&upload.path, target.join("archive"))?;
            write_manifest(
                &target.join("manifest"),
                CACHE_MAGIC,
                &CacheManifest {
                    boundary: Boundary::of(&upload.scope),
                    key: upload.key.clone(),
                    version: upload.version.clone(),
                    bytes: size,
                    digest,
                    sealed_ms: now_ms(),
                },
            )?;
            // The pointer is the commit: a reader that saw the generation before this stands either way.
            let previous = current(&dir);
            write_pointer(&dir.join("current"), &generation)?;
            if let Some(previous) = previous.filter(|p| *p != generation) {
                let _ = fs::remove_dir_all(dir.join(previous));
            }
            Ok(())
        })();
        if sealed.is_err() {
            let _ = fs::remove_file(&upload.path);
        }
        sealed
    }

    /// Drops an upload the client abandoned (its request ended before the commit).
    pub fn abandon(&self, id: u64) {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(upload) = uploads.cache.remove(&id) {
            let _ = fs::remove_file(upload.path);
        }
        if let Some(opening) = uploads.artifacts.remove(&id) {
            let _ = fs::remove_dir_all(opening.dir);
        }
    }

    /// The entry names a diagnostics listing can report for one client key.
    pub fn keys(&self, scope: &Scope) -> Vec<(String, String, u64, i64)> {
        let dir = self
            .cache
            .join(scope.repo.to_string())
            .join(scope.trust.as_str())
            .join(scope.platform.component());
        let mut out = Vec::new();
        for key in read_dir(&dir) {
            for version in read_dir(&key) {
                let Some(generation) = current(&version) else {
                    continue;
                };
                let Some(manifest) =
                    read_cache_manifest(&version.join(&generation).join("manifest"))
                else {
                    continue;
                };
                if manifest.boundary == Boundary::of(scope) {
                    out.push((
                        manifest.key,
                        manifest.version,
                        manifest.bytes,
                        manifest.sealed_ms,
                    ));
                }
            }
        }
        out
    }

    /// Opens an artifact upload. `run` and `job` are the GitHub run and job the delivery named, and the
    /// boundary is the sandbox's, so two repositories' run ids never collide on disk.
    pub fn artifact_begin(&self, scope: &Scope, run: u64, job: u64, name: &str) -> Result<u64> {
        if name.is_empty() || name.len() > 256 || name.contains('/') || name.contains('\0') {
            return Err(Error::Store("artifact name"));
        }
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let id = next_id(&mut uploads);
        let dir = self.artifacts.join("writing").join(id.to_string());
        fs::create_dir_all(&dir)?;
        uploads.artifacts.insert(
            id,
            Opening {
                scope: *scope,
                run,
                job,
                name: name.to_owned(),
                blob: dir.join("blob"),
                blocks: Vec::new(),
                dir,
            },
        );
        Ok(id)
    }

    /// Stages one block of the artifact's body. Blocks are kept in the order the commit lists them; an
    /// upload that is only ever staged as one body (`x-ms-blob-type`) arrives here as a single block.
    pub fn artifact_block(
        &self,
        id: u64,
        blockid: &str,
        bytes: &[u8],
        scope: &Scope,
    ) -> Result<usize> {
        if blockid.len() > 64
            || !blockid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        {
            return Err(Error::Store("block id"));
        }
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let opening = uploads
            .artifacts
            .get_mut(&id)
            .filter(|opening| opening.scope == *scope)
            .ok_or(Error::Store("unknown artifact"))?;
        if opening.blocks.iter().any(|(named, _)| named == blockid) {
            return Err(Error::Store("block id twice"));
        }
        let index = opening.blocks.len();
        let path = opening.dir.join(format!("block-{index}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(bytes)?;
        opening.blocks.push((blockid.to_owned(), path));
        Ok(index)
    }

    /// The staged blocks a committed block list names, in its order. An id the upload never staged is
    /// `None` rather than a guess, and a bound keeps one list from naming a block a thousand times.
    pub fn block_order(&self, id: u64, scope: &Scope, list: &[u8]) -> Option<Vec<usize>> {
        let uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let opening = uploads
            .artifacts
            .get(&id)
            .filter(|opening| opening.scope == *scope)?;
        let text = std::str::from_utf8(list).ok()?;
        let mut order = Vec::new();
        for entry in text.split("<Latest>").skip(1) {
            let (named, _) = entry.split_once("</Latest>")?;
            let index = opening
                .blocks
                .iter()
                .position(|(blockid, _)| blockid == named.trim())?;
            order.push(index);
            if order.len() > MAX_BLOCKS {
                return None;
            }
        }
        (!order.is_empty()).then_some(order)
    }

    /// The upload a finalized artifact names, by the run it belongs to and the name it was opened
    /// under: the client never has to echo an id this endpoint minted.
    pub fn upload_of(&self, scope: &Scope, run: u64, name: &str) -> Option<u64> {
        let uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        uploads
            .artifacts
            .iter()
            .find(|(_, opening)| {
                opening.scope == *scope && opening.run == run && opening.name == name
            })
            .map(|(id, _)| *id)
    }

    /// Assembles the staged blocks in the order the block list names and checks the whole body against
    /// the artifact bound.
    pub fn artifact_blocks(&self, id: u64, order: &[usize], scope: &Scope) -> Result<u64> {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let opening = uploads
            .artifacts
            .get_mut(&id)
            .filter(|opening| opening.scope == *scope)
            .ok_or(Error::Store("unknown artifact"))?;
        let mut blob = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&opening.blob)?;
        let mut total = 0u64;
        for index in order {
            let path = opening
                .blocks
                .get(*index)
                .map(|(_, path)| path)
                .ok_or(Error::Store("block list"))?;
            let bytes = fs::read(path)?;
            total = total
                .checked_add(bytes.len() as u64)
                .filter(|total| *total <= MAX_ARTIFACT_BYTES)
                .ok_or(Error::Store("artifact bound"))?;
            blob.write_all(&bytes)?;
        }
        blob.sync_all()?;
        Ok(total)
    }

    /// Seals an artifact: the body becomes the entry's blob only once its manifest is written, and the
    /// entry answers with the id the client is told.
    pub fn artifact_finalize(&self, id: u64, size: u64, scope: &Scope) -> Result<ArtifactRow> {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        let opening = uploads
            .artifacts
            .remove(&id)
            .filter(|opening| opening.scope == *scope)
            .ok_or(Error::Store("unknown artifact"))?;
        let sealed = (|| {
            let meta = fs::metadata(&opening.blob).map_err(|_| Error::Store("no body"))?;
            if meta.len() != size || size > MAX_ARTIFACT_BYTES {
                return Err(Error::Store("artifact size"));
            }
            let digest = digest_file(&opening.blob)?;
            let row_id = artifact_id(&opening.scope, opening.run, &opening.name);
            let dir = artifact_dir(&self.artifacts, &opening.scope, opening.run, &opening.name);
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            fs::create_dir_all(&dir)?;
            fs::rename(&opening.blob, dir.join("blob"))?;
            let sealed_ms = now_ms();
            write_manifest(
                &dir.join("manifest"),
                ARTIFACT_MAGIC,
                &ArtifactManifest {
                    boundary: Boundary::of(&opening.scope),
                    run: opening.run,
                    job: opening.job,
                    name: opening.name.clone(),
                    bytes: size,
                    digest,
                    id: row_id,
                    sealed_ms,
                },
            )?;
            Ok(ArtifactRow {
                name: opening.name,
                bytes: size,
                digest,
                run: opening.run,
                job: opening.job,
                id: row_id,
                sealed_ms,
            })
        })();
        let _ = fs::remove_dir_all(&opening.dir);
        sealed
    }

    /// The blob one artifact download names, if the boundary admits it.
    pub fn artifact_blob(
        &self,
        scope: &Scope,
        run: u64,
        slug: &str,
    ) -> Option<(PathBuf, ArtifactRow)> {
        let (name, dir) = find_artifact(&self.artifacts, scope, run, slug)?;
        let manifest = read_artifact_manifest(&dir.join("manifest"))?;
        if manifest.boundary != Boundary::of(scope) || manifest.name != name || manifest.run != run
        {
            return None;
        }
        let path = dir.join("blob");
        let meta = fs::metadata(&path).ok()?;
        (meta.len() == manifest.bytes).then_some((
            path,
            ArtifactRow {
                name: manifest.name,
                bytes: manifest.bytes,
                digest: manifest.digest,
                run: manifest.run,
                job: manifest.job,
                id: manifest.id,
                sealed_ms: manifest.sealed_ms,
            },
        ))
    }

    /// What this run has produced in this sandbox's boundary: the listing `download-artifact` and its
    /// `ListArtifacts` call read.
    pub fn artifacts(&self, scope: &Scope, run: u64) -> Vec<ArtifactRow> {
        let mut out = Vec::new();
        let dir = self
            .artifacts
            .join(scope.repo.to_string())
            .join(scope.trust.as_str())
            .join(run.to_string());
        for entry in read_dir_paths(&dir) {
            let Some(manifest) = read_artifact_manifest(&entry.join("manifest")) else {
                continue;
            };
            if manifest.boundary != Boundary::of(scope) || manifest.run != run {
                continue;
            }
            out.push(ArtifactRow {
                name: manifest.name,
                bytes: manifest.bytes,
                digest: manifest.digest,
                run: manifest.run,
                job: manifest.job,
                id: manifest.id,
                sealed_ms: manifest.sealed_ms,
            });
        }
        out.sort_by_key(|row| (row.job, row.name.clone()));
        out
    }
}

fn artifact_id(scope: &Scope, run: u64, name: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(scope.repo.as_bytes());
    hasher.update(&run.to_be_bytes());
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(bytes) & i64::MAX as u64
}

fn artifact_dir(root: &Path, scope: &Scope, run: u64, name: &str) -> PathBuf {
    root.join(scope.repo.to_string())
        .join(scope.trust.as_str())
        .join(run.to_string())
        .join(slug(name))
}

/// The slug an artifact entry is named by: its name reduced to path-safe characters plus a digest, so
/// two names differing only in what the reduction drops never share a directory.
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(32);
    for byte in name.bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.');
        out.push(if keep { char::from(byte) } else { '_' });
        if out.len() == 40 {
            break;
        }
    }
    out.push('-');
    out.push_str(&hex8(name));
    out
}

fn find_artifact(root: &Path, scope: &Scope, run: u64, slug: &str) -> Option<(String, PathBuf)> {
    let dir = root
        .join(scope.repo.to_string())
        .join(scope.trust.as_str())
        .join(run.to_string())
        .join(slug);
    let manifest = read_artifact_manifest(&dir.join("manifest"))?;
    Some((manifest.name, dir))
}

fn next_id(uploads: &mut Uploads) -> u64 {
    uploads.next += 1;
    uploads.next
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hex8(value: &str) -> String {
    let digest = blake3::hash(value.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest.as_bytes()[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A generation's name: creation order first, so a reader can never confuse two seals.
fn generation_name_now() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("gen-{}-{:08x}", now_ms(), nanos)
}

fn generation_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("gen-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let millis = parts.next().unwrap_or("");
    let rand = parts.next().unwrap_or("");
    parts.next().is_none()
        && !millis.is_empty()
        && millis.len() <= 18
        && millis.bytes().all(|b| b.is_ascii_digit())
        && rand.len() == 8
        && rand.bytes().all(|b| b.is_ascii_hexdigit())
}

fn name16(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn current(dir: &Path) -> Option<String> {
    let mut bytes = Vec::with_capacity(32);
    File::open(dir.join("current"))
        .ok()?
        .take(64)
        .read_to_end(&mut bytes)
        .ok()?;
    let name = String::from_utf8(bytes).ok()?;
    let name = name.trim();
    generation_name(name).then(|| name.to_owned())
}

fn write_pointer(path: &Path, generation: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    file.write_all(generation.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_manifest<T: Serialize>(path: &Path, magic: &[u8; 8], value: &T) -> Result<()> {
    let body = postcard::to_allocvec(value).map_err(|_| Error::Store("manifest encode"))?;
    let mut out = Vec::with_capacity(body.len() + 10);
    out.extend_from_slice(magic);
    out.push(FORMAT);
    out.push(0);
    out.extend_from_slice(&body);
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    file.write_all(&out)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_manifest<T: for<'de> Deserialize<'de>>(path: &Path, magic: &[u8; 8]) -> Option<T> {
    let mut bytes = Vec::with_capacity(256);
    File::open(path)
        .ok()?
        .take(MAX_MANIFEST as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_MANIFEST || bytes.len() < 10 || &bytes[..8] != magic || bytes[8] != FORMAT
    {
        return None;
    }
    postcard::from_bytes(&bytes[10..]).ok()
}

fn read_cache_manifest(path: &Path) -> Option<CacheManifest> {
    read_manifest(path, CACHE_MAGIC)
}

fn read_artifact_manifest(path: &Path) -> Option<ArtifactManifest> {
    read_manifest(path, ARTIFACT_MAGIC)
}

fn digest_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 << 10];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn read_dir(dir: &Path) -> Vec<PathBuf> {
    read_dir_paths(dir)
}

fn read_dir_paths(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{RepoId, TenantId};
    use sentinel_protocol::{cache::Trust, negotiate::Arch};

    fn scope(trust: Trust) -> Scope {
        Scope::new(TenantId::new(), RepoId::new(), trust, Arch::X86_64)
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        (dir, store)
    }

    fn seal(store: &Store, scope: &Scope, key: &str, version: &str, body: &[u8]) {
        let id = store.reserve(scope, key, version).unwrap();
        store.chunk(id, 0, body, scope).unwrap();
        store.commit(id, body.len() as u64, scope).unwrap();
    }

    #[test]
    fn a_sealed_archive_serves_once_and_only_under_its_own_boundary() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        seal(&store, &protected, "cargo-main", "v1", b"archive bytes");
        let Lookup::Hit(archive) = store.lookup(&protected, "cargo-main", "v1") else {
            panic!("a sealed entry did not serve");
        };
        assert_eq!(fs::read(&archive.path).unwrap(), b"archive bytes");
        assert_eq!(archive.bytes, 13);
        assert_eq!(archive.digest, *blake3::hash(b"archive bytes").as_bytes());

        // Every other trust is a different scope and cannot see it.
        let pull = scope(Trust::PullRequest);
        let other = Scope {
            trust: Trust::PullRequest,
            ..protected
        };
        assert!(matches!(
            store.lookup(&other, "cargo-main", "v1"),
            Lookup::Miss("absent")
        ));
        // The same key under the same trust but a moved directory is a typed miss.
        assert!(matches!(
            store.lookup(&pull, "cargo-main", "v1"),
            Lookup::Miss("absent")
        ));
        assert!(matches!(
            store.lookup(&protected, "cargo-main", "v2"),
            Lookup::Miss("absent")
        ));
    }

    #[test]
    fn a_manifest_moved_under_another_boundary_is_a_typed_miss() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        seal(&store, &protected, "k", "v", b"one");
        let from = store.entry_dir(&protected, "k", "v");
        let pull = Scope {
            trust: Trust::PullRequest,
            ..protected
        };
        let to = store.entry_dir(&pull, "k", "v");
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::rename(&from, &to).unwrap();
        assert!(matches!(
            store.lookup(&protected, "k", "v"),
            Lookup::Miss("absent")
        ));
        assert!(matches!(
            store.lookup(&pull, "k", "v"),
            Lookup::Miss("wrong_trust")
        ));
    }

    #[test]
    fn chunks_arrive_out_of_order_and_the_commit_checks_the_whole_size() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        let id = store.reserve(&protected, "k", "v").unwrap();
        store.chunk(id, 4, b"EFGH", &protected).unwrap();
        store.chunk(id, 0, b"ABCD", &protected).unwrap();
        assert!(
            store.commit(id, 9, &protected).is_err(),
            "a short body is refused"
        );
        let id = store.reserve(&protected, "k", "v").unwrap();
        store.chunk(id, 4, b"EFGH", &protected).unwrap();
        store.chunk(id, 0, b"ABCD", &protected).unwrap();
        store.commit(id, 8, &protected).unwrap();
        let Lookup::Hit(archive) = store.lookup(&protected, "k", "v") else {
            panic!("the commit did not seal");
        };
        assert_eq!(fs::read(&archive.path).unwrap(), b"ABCDEFGH");
    }

    #[test]
    fn an_archive_location_names_one_generation_and_is_admitted_by_the_manifest() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        seal(&store, &protected, "k", "v", b"bytes");
        let generation = current(&store.entry_dir(&protected, "k", "v")).unwrap();
        let location = store.archive_name(&protected, "k", "v", &generation);
        let parts: Vec<&str> = location.rsplitn(7, '/').collect();
        let [
            generation_from,
            version16,
            key16,
            platform,
            trust,
            repo,
            _prefix,
        ] = [
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6],
        ];
        let archive = store
            .archive_at(
                &protected,
                [repo, trust, platform, key16, version16, generation_from],
            )
            .expect("its own location is served");
        assert_eq!(archive.bytes, 5);
        // The same location under another trust is not this sandbox's to serve.
        let pull = Scope {
            trust: Trust::PullRequest,
            ..protected
        };
        assert!(
            store
                .archive_at(
                    &pull,
                    [repo, trust, platform, key16, version16, generation_from]
                )
                .is_none()
        );
        // A location naming a traversal or another repository is refused before the filesystem.
        assert!(
            store
                .archive_at(
                    &protected,
                    [repo, "..", platform, key16, version16, generation_from]
                )
                .is_none()
        );
    }

    #[test]
    fn an_artifact_is_sealed_against_its_run_and_readable_only_inside_its_boundary() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        let id = store.artifact_begin(&protected, 42, 7, "logs").unwrap();
        store
            .artifact_block(id, "0", b"PK\x03\x04", &protected)
            .unwrap();
        let total = store.artifact_blocks(id, &[0], &protected).unwrap();
        let row = store.artifact_finalize(id, total, &protected).unwrap();
        assert_eq!(row.name, "logs");
        assert_eq!(row.run, 42);
        assert_eq!(row.job, 7);
        assert_eq!(store.artifacts(&protected, 42), vec![row.clone()]);
        assert!(store.artifacts(&protected, 43).is_empty());
        let slug = slug("logs");
        let (path, served) = store.artifact_blob(&protected, 42, &slug).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"PK\x03\x04");
        assert_eq!(served.id, row.id);
        let pull = Scope {
            trust: Trust::PullRequest,
            ..protected
        };
        assert!(store.artifact_blob(&pull, 42, &slug).is_none());
    }

    #[test]
    fn two_artifact_names_that_reduce_to_one_slug_still_have_their_own_entries() {
        let (_dir, store) = store();
        let protected = scope(Trust::Protected);
        for name in ["a b", "a?b", "a*b"] {
            let id = store.artifact_begin(&protected, 1, 2, name).unwrap();
            store
                .artifact_block(id, "0", name.as_bytes(), &protected)
                .unwrap();
            let total = store.artifact_blocks(id, &[0], &protected).unwrap();
            store.artifact_finalize(id, total, &protected).unwrap();
        }
        let rows = store.artifacts(&protected, 1);
        assert_eq!(rows.len(), 3, "{rows:?}");
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"a b") && names.contains(&"a?b") && names.contains(&"a*b"));
    }
}
