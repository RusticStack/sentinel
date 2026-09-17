//! K02 — the read path: resolve an entry's `current` generation, verify
//! its manifest against the request, pin it with a lease and clone it
//! into the job's private view. Every failure is an `Outcome::Miss`.
//!
//! The flow per declared `cache:` entry (docs/cache.md):
//!
//! 1. The key is already rendered (the caller evaluated `hash_files`
//!    against the fresh checkout); the scope and compat inputs are
//!    derived through `attach`'s shared functions so publish (K03)
//!    derives the same entry.
//! 2. `entry/current` names the live generation — a bounded read whose
//!    content is the `gen-*` directory name.
//! 3. `manifest::lookup` answers hit or the explainable miss.
//! 4. On a hit the entry is pinned (`Lease::acquire`, so GC can never
//!    take the generation mid-clone), the `files` blob's digest is
//!    verified against the manifest — the trust anchor for the whole
//!    payload — and each `payload/<i>` is cloned to its target.
//! 5. On a miss the declared paths still exist as empty writable
//!    directories: a job always sees writable cache paths.
//!
//! Nothing here fails an attempt: a filesystem or lease error is an
//! explainable `Miss`, and target resolution never follows a symlink —
//! a link inside the workspace is the checkout's data, not a path.

use std::{
    collections::HashMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Instant,
};

use sentinel_pipeline::schema::{Cache, valid_cache_path, valid_relative_path};

use crate::{
    attach::{self, Attached, Stats, Target, entry_key},
    clone::{self, Backend},
    lease::{self, Lease},
    manifest::{self, FileEntry, FilesBlob, Request},
    outcome::{Miss, Outcome},
    publish::MAX_WALK_DEPTH,
    scope::{self, Scope},
};

/// `current` is one `gen-<unix_ms>-<rand>` name: 4 + digits + 1 + 8 hex
/// fits in 32 bytes; 128 is generous headroom, never unbounded.
const MAX_CURRENT_BYTES: u64 = 128;

/// The first-read sample size (K08): one small read of a representative
/// file per target — enough to fault a cold extent, never enough to
/// matter.
const FIRST_TOUCH_BYTES: usize = 4 * 1024;

fn ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

/// The environment every restore in one attempt shares — built once by
/// the caller, never re-derived per declaration.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The worker's cache root: `<data_dir>/cache`.
    pub cache_root: &'a Path,
    /// The attempt's workspace on the host.
    pub workspace: &'a Path,
    /// The path the container sees for `workspace` (`/workspace`) —
    /// the `container` half of every relative target, and the prefix an
    /// absolute declaration may never shadow.
    pub workspace_mount: &'a str,
    /// The clone backend `clone::detect` reported for `cache_root`.
    pub backend: Backend,
}

/// Restore one declared `cache:` entry for an attempt. `key` is the
/// rendered template — `None` when it would not render (a `hash_files`
/// failure or a resolution miss is a miss, not a build failure). `owner`
/// names the lease holder for diagnostics (the attempt id). Never fails:
/// the worst answer is an `Attached` whose `outcome` explains the miss
/// and whose targets are empty writable directories.
pub fn restore(
    env: &Context<'_>,
    decl: &Cache,
    key: Option<String>,
    scope: Scope,
    owner: &str,
) -> Attached {
    let key = key.unwrap_or_default();
    let compat = attach::declared_compat(decl, &key, scope.platform);
    let mut attached = Attached {
        name: decl.name.clone(),
        scope,
        key,
        compat,
        generation: None,
        outcome: Outcome::Miss(Miss::Absent),
        targets: Vec::with_capacity(decl.paths.len()),
        lease: None,
        stats: Stats::default(),
    };

    // Targets first: whatever the lookup answers, the job needs its
    // writable paths, and an unusable one decides the entry on its own —
    // a store read for a path that cannot serve is wasted work.
    let mut usable = !attached.key.is_empty();
    for (index, declared) in decl.paths.iter().enumerate() {
        let (target, miss) = target(env, &decl.name, index, declared);
        attached.targets.push(target);
        usable &= miss.is_none();
    }
    if !usable {
        attached.outcome = Outcome::Miss(Miss::Invalid);
        return attached;
    }

    let entry_dir = attached
        .scope
        .entry_dir(env.cache_root, entry_key(decl.class, &attached.key));
    let started = Instant::now();
    let found = {
        let want = Request {
            scope: &attached.scope,
            key: &attached.key,
            compat: &attached.compat,
        };
        current(&entry_dir).map(|(name, dir)| (name, dir.clone(), manifest::lookup(&dir, &want)))
    };
    attached.stats.lookup_ns = Some(ns(started));
    let (name, gen_dir, hit) = match found {
        Ok((name, dir, Outcome::Hit(hit))) => (name, dir, hit),
        Ok((_, _, Outcome::Miss(miss))) | Err(miss) => {
            attached.outcome = Outcome::Miss(miss);
            return attached;
        }
    };

    // A hit pins the entry for the attempt's run: the generation — and
    // later this writer's staging — stays unreachable to GC while the
    // job reads and rewrites its view.
    let started = Instant::now();
    let lease = match Lease::acquire(&entry_dir, owner, lease::DEFAULT_TTL) {
        Ok(lease) => lease,
        Err(_) => {
            // The wait was measured either way; the lease is the part
            // that never happened.
            attached.stats.lock_wait_ns = Some(ns(started));
            attached.outcome = Outcome::Miss(Miss::Unavailable);
            return attached;
        }
    };
    attached.stats.lock_wait_ns = Some(ns(started));

    let started = Instant::now();
    attached.stats.reflink = env.backend == Backend::Reflink;
    match materialize(
        &gen_dir,
        &hit.manifest,
        &attached.targets,
        env.backend,
        &mut attached.stats,
    ) {
        Ok(blob) => {
            attached.stats.clone_ns = Some(ns(started));
            // K08: the first-touch sample is timed separately — cold-extent
            // read cost is not the clone's wall time.
            attached.stats.first_touch_ns = first_touch(&blob, &attached.targets);
            attached.generation = Some(name);
            attached.lease = Some(lease);
            attached.outcome = Outcome::Hit(hit);
        }
        // The dropped `lease` releases the pin; the entry answers the miss.
        Err(miss) => attached.outcome = Outcome::Miss(miss),
    }
    attached
}

/// `entry/current` → the generation's `(name, dir)`. Absent is the common
/// miss; an unreadable file is `Unavailable`, a malformed one `Corrupt` —
/// and a name that is not `gen-*`-shaped can never name a directory here.
fn current(entry: &Path) -> Result<(String, PathBuf), Miss> {
    let file = fs::File::open(entry.join(scope::CURRENT_NAME)).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Miss::Absent,
        _ => Miss::Unavailable,
    })?;
    let mut raw = Vec::new();
    file.take(MAX_CURRENT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Miss::Unavailable)?;
    if raw.len() as u64 > MAX_CURRENT_BYTES {
        return Err(Miss::Corrupt);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| Miss::Corrupt)?;
    let name = text.strip_suffix('\n').unwrap_or(text);
    if !gen_name_shape(name) {
        return Err(Miss::Corrupt);
    }
    Ok((name.to_owned(), entry.join(name)))
}

/// Exactly what `scope::gen_name` writes: `gen-<unix_ms>-<8 hex>`.
fn gen_name_shape(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("gen-") else {
        return false;
    };
    let Some((ms, rand)) = rest.rsplit_once('-') else {
        return false;
    };
    !ms.is_empty()
        && ms.bytes().all(|b| b.is_ascii_digit())
        && rand.len() == 8
        && rand.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The `files` listing: bounded read, BLAKE3 digest verified against the
/// manifest — the anchor that lets materialization skip per-file hashing
/// — then decode. A manifest without its listing, an oversize one or a
/// digest mismatch is a `Corrupt` generation.
fn files_blob(gen_dir: &Path, manifest: &manifest::Manifest) -> Result<FilesBlob, Miss> {
    let file = fs::File::open(gen_dir.join(scope::FILES_NAME)).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Miss::Corrupt,
        _ => Miss::Unavailable,
    })?;
    let mut raw = Vec::new();
    file.take(manifest::MAX_FILES_BLOB_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Miss::Unavailable)?;
    if raw.len() as u64 > manifest::MAX_FILES_BLOB_BYTES
        || blake3::hash(&raw).as_bytes() != &manifest.files_digest
    {
        return Err(Miss::Corrupt);
    }
    FilesBlob::decode(&raw)
}

/// `payload/<i>/<rel>` → `(i, rel)` — the listing's own shape, which
/// materialization validated before this is ever asked.
fn payload_parts(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("payload/")?;
    let (index, rel) = rest.split_once('/')?;
    if rel.is_empty() {
        return None;
    }
    Some((index.parse().ok()?, rel))
}

/// Walk a generation's `payload/<i>` tree and require it to be exactly
/// the sealed listing for that index: every non-directory entry a listed
/// regular file at its listed size, and all of them present. A planted
/// file, a symlink where a file was listed or a missing listed file is a
/// generation that drifted from what its manifest pinned — `Corrupt`,
/// never served. Bounded like the writer's own walk: deeper than
/// [`MAX_WALK_DEPTH`] cannot be sealed content.
fn check_payload_tree(src: &Path, listed: &HashMap<&str, &FileEntry>) -> Result<(), Miss> {
    // `(dir, rel)` — `rel` is the listing's suffix form: `sub/dir/file`.
    let mut stack = vec![(src.to_path_buf(), String::new(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth >= MAX_WALK_DEPTH {
            return Err(Miss::Corrupt);
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Miss::Corrupt),
            Err(_) => return Err(Miss::Unavailable),
        };
        for child in entries {
            let child = child.map_err(|_| Miss::Unavailable)?;
            let meta = child.metadata().map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => Miss::Corrupt,
                _ => Miss::Unavailable,
            })?;
            let Some(name) = child.file_name().to_str().map(str::to_owned) else {
                // An unencodable name can never be listed — planted.
                return Err(Miss::Corrupt);
            };
            let rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if meta.is_dir() {
                stack.push((child.path(), rel, depth + 1));
            } else if meta.is_file() {
                match listed.get(rel.as_str()) {
                    Some(entry) if entry.size == meta.len() => seen += 1,
                    _ => return Err(Miss::Corrupt),
                }
            } else {
                // A symlink or special file can never be listed — planted.
                return Err(Miss::Corrupt);
            }
        }
    }
    if seen != listed.len() {
        // A listed file the tree does not hold — the other hole.
        return Err(Miss::Corrupt);
    }
    Ok(())
}

/// Clone every `payload/<i>` to its target. The listing is re-validated
/// here — `decode` already checked each path is relative, and a clone
/// input is checked twice rather than trusted once — and the tree must
/// match it exactly: the listing is the payload's whole authority, so a
/// planted or missing file is `Corrupt`, never served (K09). Payload
/// bytes are not re-hashed: that would defeat the reflink path
/// (docs/cache.md). `Ok` carries the verified listing so the caller can
/// run the bounded first-touch sample after it has stamped `clone_ns` —
/// the sample's cost must not land inside the clone's wall time (K08).
fn materialize(
    gen_dir: &Path,
    manifest: &manifest::Manifest,
    targets: &[Target],
    backend: Backend,
    stats: &mut Stats,
) -> Result<FilesBlob, Miss> {
    let blob = files_blob(gen_dir, manifest)?;
    // Per-index `rel → entry` maps: what the payload trees must hold.
    let mut listed: Vec<HashMap<&str, &FileEntry>> =
        targets.iter().map(|_| HashMap::new()).collect();
    for entry in &blob.entries {
        let ok = valid_relative_path(&entry.path)
            && payload_parts(&entry.path).is_some_and(|(i, rel)| {
                i < targets.len() && listed[i].insert(rel, entry).is_none()
            });
        if !ok {
            // The verified listing names a file outside the payload
            // layout — or the same payload path twice: the generation
            // cannot serve.
            return Err(Miss::Invalid);
        }
    }
    for (index, target) in targets.iter().enumerate() {
        let src = gen_dir.join("payload").join(index.to_string());
        match fs::symlink_metadata(&src) {
            Ok(meta) if meta.is_dir() => {
                check_payload_tree(&src, &listed[index])?;
                let cloned =
                    clone::tree(&src, &target.dir, backend).map_err(|e| match e.kind() {
                        // A payload the listing names but the tree does
                        // not hold is a broken generation, not a hiccup.
                        io::ErrorKind::NotFound => Miss::Corrupt,
                        _ => Miss::Unavailable,
                    })?;
                stats.files += cloned.files;
                stats.bytes += cloned.bytes;
                stats.copied_bytes += cloned.copied_bytes;
            }
            Ok(_) => return Err(Miss::Corrupt),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // No payload for this declared path: honest only when the
                // listing agrees there was nothing to carry.
                if !listed[index].is_empty() {
                    return Err(Miss::Corrupt);
                }
            }
            Err(_) => return Err(Miss::Unavailable),
        }
    }
    Ok(blob)
}

/// One bounded first-read sample per target after a hit's clone
/// materialized: open the largest listed file and read its first
/// [`FIRST_TOUCH_BYTES`]. A clone's cost is per file, but the first real
/// read is what faults a cold extent — the K02 probe showed that cost is
/// real, so it is measured separately rather than folded into `clone_ns`.
/// `None` when the listing held no file to sample; a file that will not
/// open is simply not measured, never a miss.
fn first_touch(blob: &FilesBlob, targets: &[Target]) -> Option<u64> {
    if blob.entries.is_empty() {
        return None;
    }
    // The largest listed file per target, in one pass over the listing.
    let mut largest: Vec<Option<(u64, &str)>> = vec![None; targets.len()];
    for entry in &blob.entries {
        let Some((index, rel)) = payload_parts(&entry.path) else {
            continue;
        };
        let Some(slot) = largest.get_mut(index) else {
            continue;
        };
        match slot {
            Some((size, _)) if *size >= entry.size => {}
            _ => *slot = Some((entry.size, rel)),
        }
    }
    let started = Instant::now();
    let mut sampled = false;
    for (target, pick) in targets.iter().zip(&largest) {
        let Some((_, rel)) = pick else {
            continue;
        };
        let Ok(mut file) = fs::File::open(target.dir.join(rel)) else {
            continue;
        };
        // One read; a short read still faulted the extent, which is the
        // cost being measured.
        sampled |= file.read(&mut [0u8; FIRST_TOUCH_BYTES]).is_ok();
    }
    if sampled { Some(ns(started)) } else { None }
}

/// Resolve one declared path to its `Target`, creating the writable
/// directory. The `Miss` in the pair explains a refusal: the declared
/// path was unusable (`Invalid`) or the workspace refused it
/// (`Unavailable`). The `Target` is always produced so `targets[i]` keeps
/// index alignment with `payload/<i>`.
fn target(env: &Context<'_>, name: &str, index: usize, declared: &str) -> (Target, Option<Miss>) {
    // Re-check the schema's rule rather than trust it: a path that is not
    // a normalised relative or `/`-absolute path is refused, not guessed.
    if !valid_cache_path(declared) {
        return (
            Target {
                declared: declared.to_owned(),
                dir: env.workspace.to_path_buf(),
                container: declared.to_owned(),
                mount: false,
            },
            Some(Miss::Invalid),
        );
    }
    let (dir, container, mount, rel) = match declared.strip_prefix('/') {
        Some(rest) => {
            // Absolute inside the container: the job writes outside the
            // workspace, so a private view is bound in. One naming the
            // workspace mount itself would shadow the checkout — refused.
            let mount_rel = env.workspace_mount.trim_start_matches('/');
            let under_mount = rest == mount_rel || rest.starts_with(&format!("{mount_rel}/"));
            let rel = Path::new(attach::PRIVATE_DIR)
                .join(name)
                .join(index.to_string());
            (
                env.workspace.join(&rel),
                declared.to_owned(),
                true,
                (rel, under_mount),
            )
        }
        None => {
            // Relative: inside the workspace, which already reaches the
            // container at `workspace_mount` — no bind needed. The
            // private directory's name is the machinery's, not a job's.
            let reserved = declared.split('/').next() == Some(attach::PRIVATE_DIR);
            (
                env.workspace.join(declared),
                format!("{}/{declared}", env.workspace_mount),
                false,
                (PathBuf::from(declared), reserved),
            )
        }
    };
    let (rel, refused) = rel;
    let target = Target {
        declared: declared.to_owned(),
        dir,
        container,
        mount,
    };
    if refused {
        return (target, Some(Miss::Invalid));
    }
    let miss = create_under(env.workspace, &rel).err();
    (target, miss)
}

/// Create `root/rel` as a real directory, never resolving through
/// symlinks: an existing component above the last that is a symlink (or
/// anything but a directory) makes the path unusable — `Invalid` — while
/// a symlink *at* the path is replaced with the real directory it hides.
/// Missing components are created 0755-by-umask.
fn create_under(root: &Path, rel: &Path) -> Result<(), Miss> {
    let mut cur = root.to_path_buf();
    let components: Vec<_> = rel.iter().collect();
    for (i, comp) in components.iter().enumerate() {
        cur.push(comp);
        let last = i + 1 == components.len();
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) if meta.file_type().is_symlink() => {
                if !last {
                    // Resolving through it would write wherever the
                    // checkout's link points — refused, never followed.
                    return Err(Miss::Invalid);
                }
                fs::remove_file(&cur).map_err(|_| Miss::Unavailable)?;
                fs::create_dir(&cur).map_err(|_| Miss::Unavailable)?;
            }
            Ok(_) => {
                if !last {
                    return Err(Miss::Invalid);
                }
                fs::remove_file(&cur).map_err(|_| Miss::Unavailable)?;
                fs::create_dir(&cur).map_err(|_| Miss::Unavailable)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|_| Miss::Unavailable)?;
            }
            Err(_) => return Err(Miss::Unavailable),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sentinel_core::{RepoId, TenantId, UnixMillis};
    use sentinel_pipeline::expr::Template;
    use sentinel_protocol::{
        cache::{Class, Trust},
        negotiate::Arch,
    };

    use super::*;
    use crate::{
        attach,
        manifest::{Compat, FileEntry, Manifest},
        outcome::Hit,
        scope::{Os, Platform},
    };

    const KEY: &str = "deps-aa00bb11";
    const MOUNT: &str = "/workspace";

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
            Scope::toolchain_digest(b"img@sha256:11"),
            "deps",
        )
        .unwrap()
    }

    fn decl(paths: &[&str]) -> Cache {
        Cache {
            name: "deps".into(),
            class: Class::Dependencies,
            key: Template::parse(KEY).unwrap(),
            paths: paths.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// What `seal` writes: `entry_of`/`entry_key` decide which entry dir
    /// the generation sits under; `recorded`/`recorded_key` are what the
    /// manifest claims — kept separate so a test can emulate a directory
    /// found under the wrong scope, exactly the case the boundary fields
    /// exist to catch.
    struct Seal<'a> {
        entry_of: &'a Scope,
        entry_key: &'a str,
        recorded: &'a Scope,
        recorded_key: &'a str,
        compat: &'a Compat,
        sealed: bool,
        payloads: &'a [&'a [(&'a str, &'a [u8])]],
    }

    impl<'a> Seal<'a> {
        /// The honest case: the generation sits where its manifest's own
        /// scope and key put it, sealed, carrying `payloads`.
        fn at(
            recorded: &'a Scope,
            key: &'a str,
            compat: &'a Compat,
            payloads: &'a [&'a [(&'a str, &'a [u8])]],
        ) -> Seal<'a> {
            Seal {
                entry_of: recorded,
                entry_key: key,
                recorded,
                recorded_key: key,
                compat,
                sealed: true,
                payloads,
            }
        }
    }

    /// Write a generation and the `current` pointer for it; returns the
    /// entry dir and the generation dir.
    fn seal(cache_root: &Path, s: &Seal<'_>) -> (PathBuf, PathBuf) {
        let entry_dir = s
            .entry_of
            .entry_dir(cache_root, attach::entry_key(s.entry_of.class, s.entry_key));
        let name = scope::gen_name(1_700_000_000_000, 0x00ab_cdef);
        let gdir = entry_dir.join(&name);
        fs::create_dir_all(&gdir).unwrap();
        let mut entries = Vec::new();
        let mut total = 0u64;
        for (i, files) in s.payloads.iter().enumerate() {
            for (rel, body) in *files {
                let path = gdir.join("payload").join(i.to_string()).join(rel);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, body).unwrap();
                entries.push(FileEntry {
                    path: format!("payload/{i}/{rel}"),
                    size: body.len() as u64,
                    digest: *blake3::hash(body).as_bytes(),
                    mode: 0o644,
                });
                total += body.len() as u64;
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let blob = FilesBlob { entries };
        fs::write(gdir.join(scope::FILES_NAME), blob.encode()).unwrap();
        let mut manifest = Manifest::writing(s.recorded, s.recorded_key, s.compat.clone());
        manifest.bytes = total;
        manifest.files = s.payloads.iter().map(|p| p.len() as u32).sum();
        manifest.files_digest = blob.digest();
        if s.sealed {
            manifest.seal(UnixMillis(1_700_000_000_001));
        }
        fs::write(gdir.join(scope::MANIFEST_NAME), manifest.encode()).unwrap();
        fs::write(entry_dir.join(scope::CURRENT_NAME), format!("{name}\n")).unwrap();
        (entry_dir, gdir)
    }

    fn env<'a>(root: &'a Path, ws: &'a Path) -> Context<'a> {
        Context {
            cache_root: root,
            workspace: ws,
            workspace_mount: MOUNT,
            backend: Backend::Copy,
        }
    }

    fn restore_one(root: &Path, ws: &Path, decl: &Cache, want: Scope) -> Attached {
        restore(
            &env(root, ws),
            decl,
            Some(KEY.to_owned()),
            want,
            "attempt-1",
        )
    }

    fn hit(attached: &Attached) -> &Hit {
        match &attached.outcome {
            Outcome::Hit(hit) => hit,
            other => panic!("expected a hit, got {other:?}"),
        }
    }

    fn miss(attached: &Attached) -> Miss {
        match attached.outcome {
            Outcome::Miss(miss) => miss,
            _ => panic!("expected a miss, got {:?}", attached.outcome),
        }
    }

    #[test]
    fn a_hit_clones_every_payload_into_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["vendor", "cache/locked"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        seal(
            &root,
            &Seal::at(
                &s,
                KEY,
                &compat,
                &[&[("a/lib", b"lib"), ("b", b"bb")], &[("only", b"o")]],
            ),
        );
        let a = restore_one(&root, &ws, &d, s.clone());
        assert_eq!(hit(&a).manifest.key, KEY);
        assert_eq!(a.generation.as_deref().map(|g| &g[..4]), Some("gen-"));
        assert!(a.lease.is_some(), "the pin is held for the attempt");
        assert_eq!(fs::read(ws.join("vendor/a/lib")).unwrap(), b"lib");
        assert_eq!(fs::read(ws.join("vendor/b")).unwrap(), b"bb");
        assert_eq!(fs::read(ws.join("cache/locked/only")).unwrap(), b"o");
        // A job's writes stay private: the payload keeps its bytes.
        fs::write(ws.join("vendor/b"), b"job wrote").unwrap();
        let entry = s.entry_dir(&root, attach::entry_key(Class::Dependencies, KEY));
        let gen_dir = entry.join(a.generation.as_ref().unwrap());
        assert_eq!(fs::read(gen_dir.join("payload/0/b")).unwrap(), b"bb");
        // Measured, all four phases — the clone ran, and the first-touch
        // sample read the largest listed file's first bytes per target.
        assert!(a.stats.lookup_ns.is_some());
        assert!(a.stats.lock_wait_ns.is_some());
        assert!(a.stats.clone_ns.is_some());
        assert!(a.stats.first_touch_ns.is_some());
        assert_eq!(a.stats.files, 3);
        assert_eq!(a.stats.bytes, 6);
        assert_eq!(a.stats.copied_bytes, 6);
        assert!(!a.stats.reflink);
        // The lease outlives the call: the marker file is on disk.
        let lease_file = a.lease.as_ref().unwrap().path().to_path_buf();
        assert!(lease_file.exists());
    }

    #[test]
    fn an_absent_entry_is_a_miss_but_the_targets_are_writable() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let d = decl(&["vendor"]);
        let a = restore_one(&root, &ws, &d, scope());
        assert_eq!(miss(&a), Miss::Absent);
        assert!(a.generation.is_none() && a.lease.is_none());
        // The job's contract: writable cache paths exist regardless.
        fs::write(a.targets[0].dir.join("fresh"), b"x").unwrap();
        assert!(a.targets[0].dir.is_dir());
        assert!(a.stats.lookup_ns.is_some(), "the lookup ran and failed");
        assert!(a.stats.clone_ns.is_none(), "a miss never clones");
        assert!(
            a.stats.first_touch_ns.is_none(),
            "nothing materialized to touch"
        );
    }

    #[test]
    fn a_hit_without_listed_files_measures_no_first_touch() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        // A declared path the generation never carried: the hit is real
        // but the listing is empty, so there is nothing to sample.
        let d = decl(&["vendor"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        seal(&root, &Seal::at(&s, KEY, &compat, &[&[]]));
        let a = restore_one(&root, &ws, &d, s);
        assert!(a.outcome.is_hit());
        assert_eq!(a.stats.files, 0);
        assert!(a.stats.clone_ns.is_some());
        assert!(a.stats.first_touch_ns.is_none());
    }

    #[test]
    fn unsealed_corrupt_and_overlong_states_are_explainable_misses() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["v"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        // Unsealed: the manifest exists but `sealed_ms` is 0.
        let (entry, _) = seal(
            &root,
            &Seal {
                sealed: false,
                ..Seal::at(&s, KEY, &compat, &[&[("x", b"x")]])
            },
        );
        let a = restore_one(&root, &ws, &d, s.clone());
        assert_eq!(miss(&a), Miss::Unsealed);
        // A `current` that cannot name a generation is corrupt.
        fs::write(entry.join(scope::CURRENT_NAME), b"not-a-generation\n").unwrap();
        let a = restore_one(&root, &ws, &d, s.clone());
        assert_eq!(miss(&a), Miss::Corrupt);
        fs::write(entry.join(scope::CURRENT_NAME), vec![b'g'; 200]).unwrap();
        let a = restore_one(&root, &ws, &d, s.clone());
        assert_eq!(miss(&a), Miss::Corrupt);
    }

    #[test]
    fn a_files_blob_that_lies_about_its_digest_is_corrupt() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["v"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        let (_, gdir) = seal(&root, &Seal::at(&s, KEY, &compat, &[&[("x", b"x")]]));
        // Rewrite the listing: the manifest's digest no longer matches.
        fs::write(gdir.join(scope::FILES_NAME), FilesBlob::default().encode()).unwrap();
        let a = restore_one(&root, &ws, &d, s);
        assert_eq!(miss(&a), Miss::Corrupt);
        assert!(a.lease.is_none(), "the pin is dropped with the miss");
    }

    #[test]
    fn a_listing_that_escapes_its_payload_is_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["v"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        let (_, gdir) = seal(&root, &Seal::at(&s, KEY, &compat, &[&[("x", b"x")]]));
        // Forge a listing that names a file outside `payload/<i>` — the
        // digest is recomputed so only the shape is wrong.
        let blob = FilesBlob {
            entries: vec![FileEntry {
                path: "payload/9/elsewhere".into(),
                size: 1,
                digest: *blake3::hash(b"x").as_bytes(),
                mode: 0o644,
            }],
        };
        fs::write(gdir.join(scope::FILES_NAME), blob.encode()).unwrap();
        let mut m = Manifest::writing(&s, KEY, compat);
        m.bytes = 1;
        m.files = 1;
        m.files_digest = blob.digest();
        m.seal(UnixMillis(1_700_000_000_001));
        fs::write(gdir.join(scope::MANIFEST_NAME), m.encode()).unwrap();
        let a = restore_one(&root, &ws, &d, s);
        assert_eq!(miss(&a), Miss::Invalid);
    }

    #[test]
    fn a_lease_that_cannot_be_acquired_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["v"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        let (entry, _) = seal(&root, &Seal::at(&s, KEY, &compat, &[&[("x", b"x")]]));
        // A file where the lease directory must be: acquisition fails.
        fs::write(entry.join(scope::LEASE_NAME), b"not a dir").unwrap();
        let a = restore_one(&root, &ws, &d, s);
        assert_eq!(miss(&a), Miss::Unavailable);
        assert!(a.stats.lookup_ns.is_some() && a.stats.lock_wait_ns.is_some());
        assert!(a.stats.clone_ns.is_none());
    }

    #[test]
    fn wrong_boundaries_are_named_not_confused() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["v"]);
        // The manifest was sealed for another trust class; the entry dir
        // is the requester's — the moved-directory case the boundary is for.
        let mut pr = s.clone();
        pr.trust = Trust::PullRequest;
        let compat = attach::declared_compat(&d, KEY, s.platform);
        seal(
            &root,
            &Seal {
                entry_of: &pr,
                ..Seal::at(&s, KEY, &compat, &[&[("x", b"x")]])
            },
        );
        let a = restore_one(&root, &ws, &d, pr);
        assert_eq!(miss(&a), Miss::WrongTrust);
        // Same for the toolchain dimension.
        let mut other_tool = s.clone();
        other_tool.toolchain = Scope::toolchain_digest(b"img@sha256:22");
        seal(
            &root,
            &Seal {
                entry_of: &other_tool,
                ..Seal::at(&s, KEY, &compat, &[&[("x", b"x")]])
            },
        );
        let a = restore_one(&root, &ws, &d, other_tool);
        assert_eq!(miss(&a), Miss::WrongToolchain);
        // And an exact-class key that differs — the entry dir is the
        // request's, the recorded key is not.
        seal(
            &root,
            &Seal {
                recorded_key: "deps-ff00",
                ..Seal::at(&s, KEY, &compat, &[&[("x", b"x")]])
            },
        );
        let a = restore_one(&root, &ws, &d, s);
        assert_eq!(miss(&a), Miss::WrongKey);
    }

    #[test]
    fn absolute_paths_become_private_dirs_and_mounts() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["/opt/ccache"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        seal(&root, &Seal::at(&s, KEY, &compat, &[&[("bin", b"b")]]));
        let a = restore_one(&root, &ws, &d, s);
        hit(&a);
        let t = &a.targets[0];
        assert!(t.mount);
        assert_eq!(t.container, "/opt/ccache");
        // The host view is the machinery's private directory, never a
        // path the job's own files could occupy.
        assert!(t.dir.starts_with(ws.join(attach::PRIVATE_DIR)));
        assert_eq!(fs::read(t.dir.join("bin")).unwrap(), b"b");
    }

    #[test]
    fn unusable_paths_are_refused_without_touching_the_store() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        // `..`, a shadowing of the workspace mount, and the private dir's
        // name as a relative path are all refused with `Invalid`.
        for paths in [
            &["../up"][..],
            &["/workspace/evil"][..],
            &[".sentinel-cache/x"][..],
        ] {
            let d = decl(paths);
            let a = restore_one(&root, &ws, &d, s.clone());
            assert_eq!(miss(&a), Miss::Invalid, "{paths:?}");
            // Refused before any store read: no lookup time was measured.
            assert!(a.stats.lookup_ns.is_none(), "{paths:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_parent_is_refused_not_followed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        // The checkout's symlink must not decide where a cache lands.
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, ws.join("link")).unwrap();
        let a = restore_one(&root, &ws, &decl(&["link/sub"]), scope());
        assert_eq!(miss(&a), Miss::Invalid);
        // A symlink AT the path is replaced with the real directory.
        symlink(&outside, ws.join("leaf")).unwrap();
        let a = restore_one(&root, &ws, &decl(&["leaf"]), scope());
        assert_eq!(miss(&a), Miss::Absent);
        assert!(a.targets[0].dir.is_dir());
        assert!(
            !fs::symlink_metadata(&a.targets[0].dir)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn an_unrenderable_key_is_an_explainable_miss() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let d = decl(&["v"]);
        let a = restore(&env(&root, &ws), &d, None, scope(), "attempt-1");
        assert_eq!(miss(&a), Miss::Invalid);
        assert!(a.targets[0].dir.is_dir());
    }
}
