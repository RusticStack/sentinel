//! The read path: resolve an entry's `current` generation, verify
//! its manifest against the request, pin it with a lease and clone it
//! into the job's private view. Every failure is an `Outcome::Miss`.
//!
//! Per declared `cache:` entry (docs/cache.md): the caller has rendered the
//! key against the fresh checkout; `entry/current` names the live
//! generation, which is pinned and the pointer re-read under the pin;
//! `manifest::lookup` answers hit or miss; on a hit the `files` blob's digest
//! (the trust anchor for the payload) and every `payload/<i>` tree are
//! verified before any is cloned. On a miss the declared paths still exist
//! as empty writable directories.
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

/// `current` is one `gen-<unix_ms>-<rand>` name, under 32 bytes.
const MAX_CURRENT_BYTES: u64 = 128;

/// The first-read sample size: enough to fault a cold extent.
const FIRST_TOUCH_BYTES: usize = 4 * 1024;

fn ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

/// The environment every restore in one attempt shares.
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
    restore_remote(env, decl, key, scope, owner, None)
}

/// [`restore`] with remote hydration ([`crate::remote`]) available for a
/// local miss; a local hit never consults `remote`. When a transfer ran and
/// did not serve, the miss is the transfer's own: `unavailable` if it failed
/// or ran out of budget, else the reason the received bundle failed the
/// local lookup.
pub fn restore_remote(
    env: &Context<'_>,
    decl: &Cache,
    key: Option<String>,
    scope: Scope,
    owner: &str,
    remote: Option<crate::remote::Policy<'_>>,
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

    // Targets first: the job needs its writable paths whatever the lookup
    // answers, and an unusable one decides the entry without a store read.
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
    // An entry with no `current` takes no pin. Otherwise the pin comes
    // before the pointer is trusted and the pointer is re-read under it, so
    // GC cannot reclaim the generation between read and clone; a sweep that
    // raced the first read is an ordinary miss, never `corrupt`.
    let started = Instant::now();
    let probe = current(&entry_dir);
    let mut lookup_ns = ns(started);
    let lease = match probe {
        Ok(_) => {
            let waited = Instant::now();
            let pinned = Lease::acquire(&entry_dir, owner, lease::DEFAULT_TTL);
            attached.stats.lock_wait_ns = Some(ns(waited));
            match pinned {
                Ok(lease) => Some(lease),
                Err(_) => {
                    attached.stats.lookup_ns = Some(lookup_ns);
                    attached.outcome = Outcome::Miss(Miss::Unavailable);
                    return attached;
                }
            }
        }
        Err(_) => None,
    };
    let started = Instant::now();
    let found = match probe {
        Err(miss) => Err(miss),
        Ok(_) => {
            let want = Request {
                scope: &attached.scope,
                key: &attached.key,
                compat: &attached.compat,
            };
            current(&entry_dir)
                .map(|(name, dir)| (name, dir.clone(), manifest::lookup(&dir, &want)))
        }
    };
    lookup_ns += ns(started);
    attached.stats.lookup_ns = Some(lookup_ns);
    let (name, gen_dir, hit, lease) = match (found, lease) {
        (Ok((name, dir, Outcome::Hit(hit))), Some(lease)) => (name, dir, hit, lease),
        // A hit is only ever read under a pin; without one it cannot serve.
        (Ok((_, _, Outcome::Hit(_))), None) => {
            attached.outcome = Outcome::Miss(Miss::Unavailable);
            return attached;
        }
        (Ok((_, _, Outcome::Miss(miss))), _) | (Err(miss), _) => {
            attached.outcome = Outcome::Miss(miss);
            // Any local miss may hydrate: a bad local generation says
            // nothing about what the controller holds.
            if let Some(policy) = remote {
                match crate::remote::hydrate(env, &mut attached, owner, policy) {
                    crate::remote::Hydro::Served(hydrated) => {
                        attached.outcome = Outcome::Hit(Box::new(hydrated.hit));
                        attached.generation = Some(hydrated.generation);
                        attached.lease = Some(hydrated.lease);
                    }
                    crate::remote::Hydro::Nothing => {}
                    crate::remote::Hydro::Refused(miss) => attached.outcome = Outcome::Miss(miss),
                }
            }
            return attached;
        }
    };

    // The pin stays for the attempt's run so GC cannot take the generation
    // (or later this writer's staging) while the job uses its view.
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
            // Timed apart from `clone_ns`: cold-extent reads are not clone cost.
            attached.stats.first_touch_ns = first_touch(&blob, &attached.targets);
            // Reclamation evicts least recently used.
            crate::gc::touch(&entry_dir);
            attached.generation = Some(name);
            attached.lease = Some(lease);
            attached.outcome = Outcome::Hit(hit);
        }
        // Dropping `lease` releases the pin. A generation gone although
        // pinned was reclaimed before the pin landed: transient, not tampering.
        Err(miss) => {
            let miss = if miss == Miss::Corrupt && !gen_dir.is_dir() {
                Miss::Unavailable
            } else {
                miss
            };
            attached.outcome = Outcome::Miss(miss);
        }
    }
    attached
}

/// `entry/current` → the generation's `(name, dir)`. Absent is the common
/// miss; an unreadable file is `Unavailable`, a malformed one `Corrupt`.
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

/// The `files` listing: bounded read, BLAKE3 digest checked against the
/// manifest (the anchor that lets materialization skip per-file hashing),
/// then decode. A missing, oversize or mismatching listing is `Corrupt`.
pub(crate) fn files_blob(gen_dir: &Path, manifest: &manifest::Manifest) -> Result<FilesBlob, Miss> {
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

/// `payload/<i>/<rel>` → `(i, rel)`.
fn payload_parts(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("payload/")?;
    let (index, rel) = rest.split_once('/')?;
    if rel.is_empty() {
        return None;
    }
    Some((index.parse().ok()?, rel))
}

/// Require a generation's `payload/<i>` tree to be exactly the sealed
/// listing for that index: every non-directory entry a listed regular file
/// at its listed size, all present. A planted file, a symlink or a missing
/// file is `Corrupt`. Deeper than [`MAX_WALK_DEPTH`] cannot be sealed
/// content.
fn check_payload_tree(src: &Path, listed: &HashMap<&str, &FileEntry>) -> Result<(), Miss> {
    // `(dir, rel)` — `rel` is the listing's suffix form: `sub/dir/file`.
    let mut stack = vec![(src.to_path_buf(), String::new(), 0usize)];
    let mut seen = 0usize;
    // Scratch buffer: the listing key is built in place per file.
    let mut key = String::new();
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
            let file_name = child.file_name();
            let Some(name) = file_name.to_str() else {
                // An unencodable name can never be listed — planted.
                return Err(Miss::Corrupt);
            };
            key.clear();
            if !rel.is_empty() {
                key.push_str(&rel);
                key.push('/');
            }
            key.push_str(name);
            if meta.is_dir() {
                stack.push((child.path(), key.clone(), depth + 1));
            } else if meta.is_file() {
                match listed.get(key.as_str()) {
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
/// (paths relative, shaped `payload/<i>/<rel>`) and the tree must match it
/// exactly, so a planted or missing file is `Corrupt`. Payload bytes are not
/// re-hashed: that would defeat the reflink path (docs/cache.md). `Ok`
/// carries the verified listing so the caller can take the first-touch
/// sample after stamping `clone_ns`.
///
/// Shared with the remote path so a hydrated generation faces the same
/// checks as a local one.
pub(crate) fn materialize(
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
            // A file outside the payload layout, or listed twice.
            return Err(Miss::Invalid);
        }
    }
    // Check every tree before cloning any: a generation broken at index 1
    // must not leave index 0's bytes in the job's view under a miss.
    let mut sources = Vec::with_capacity(targets.len());
    for (index, listed) in listed.iter().enumerate() {
        let src = gen_dir.join("payload").join(index.to_string());
        match fs::symlink_metadata(&src) {
            Ok(meta) if meta.is_dir() => {
                check_payload_tree(&src, listed)?;
                sources.push(Some(src));
            }
            Ok(_) => return Err(Miss::Corrupt),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Honest only when the listing carries nothing for it.
                if !listed.is_empty() {
                    return Err(Miss::Corrupt);
                }
                sources.push(None);
            }
            Err(_) => return Err(Miss::Unavailable),
        }
    }
    for (src, target) in sources.iter().zip(targets) {
        let Some(src) = src else {
            continue;
        };
        match clone::tree(src, &target.dir, backend) {
            Ok(cloned) => {
                stats.files += cloned.files;
                stats.bytes += cloned.bytes;
                stats.copied_bytes += cloned.copied_bytes;
            }
            Err(e) => {
                // Restore the miss contract: no partial materialization an
                // installer could mistake for a finished one.
                for target in targets {
                    let _ = clone::empty(&target.dir);
                }
                return Err(match e.kind() {
                    // Listed but absent: a broken generation, not a hiccup.
                    io::ErrorKind::NotFound => Miss::Corrupt,
                    _ => Miss::Unavailable,
                });
            }
        }
    }
    Ok(blob)
}

/// Read the first [`FIRST_TOUCH_BYTES`] of the largest listed file per
/// target after a hit's clone. The first real read faults a cold extent, so
/// it is measured apart from `clone_ns`. `None` when nothing was sampled; a
/// file that will not open is not measured, never a miss.
pub(crate) fn first_touch(blob: &FilesBlob, targets: &[Target]) -> Option<u64> {
    if blob.entries.is_empty() {
        return None;
    }
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
        // A short read still faulted the extent.
        sampled |= file.read(&mut [0u8; FIRST_TOUCH_BYTES]).is_ok();
    }
    if sampled { Some(ns(started)) } else { None }
}

/// Resolve one declared path to its `Target`, creating the writable
/// directory. The `Miss` explains a refusal (`Invalid`: unusable path;
/// `Unavailable`: the workspace refused it). The `Target` is always
/// produced so `targets[i]` stays aligned with `payload/<i>`.
fn target(env: &Context<'_>, name: &str, index: usize, declared: &str) -> (Target, Option<Miss>) {
    // The schema's rule is re-checked, not trusted. An absolute path
    // reaches the container as a bind-mount spec where `:` and `,` are
    // separators: it would only fail `podman create`, and so the attempt.
    let unmountable = declared.starts_with('/') && declared.contains([':', ',']);
    if !valid_cache_path(declared) || unmountable {
        return (
            Target {
                declared: declared.to_owned(),
                root: env.workspace.to_path_buf(),
                dir: env.workspace.to_path_buf(),
                container: declared.to_owned(),
                mount: false,
            },
            Some(Miss::Invalid),
        );
    }
    let (dir, container, mount, rel) = match declared.strip_prefix('/') {
        Some(rest) => {
            // Absolute inside the container: bound in as a private view.
            // One naming the workspace mount would shadow the checkout.
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
            // Relative: already reachable at `workspace_mount`, no bind
            // needed. The private directory's name is reserved.
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
        root: env.workspace.to_path_buf(),
        dir,
        container,
        mount,
    };
    if refused {
        return (
            Target {
                mount: false,
                ..target
            },
            Some(Miss::Invalid),
        );
    }
    match create_under(env.workspace, &rel) {
        Ok(()) => (target, None),
        // Never bound: a mount of a missing host path would fail the start.
        Err(miss) => (
            Target {
                mount: false,
                ..target
            },
            Some(miss),
        ),
    }
}

/// Create `root/rel` as a real directory without resolving symlinks: a
/// non-directory component above the last makes the path `Invalid`, while a
/// symlink *at* the path is replaced with a real directory. Components are
/// created with the default umask mode.
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
                    // Following it would write wherever the checkout's link points.
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

    /// `entry_of`/`entry_key` pick the entry dir the generation sits under;
    /// `recorded`/`recorded_key` are what its manifest claims, so a test can
    /// emulate a generation found under the wrong scope.
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
        /// A sealed generation where its manifest's scope and key put it.
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

    /// Returns the entry dir and the generation dir.
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
        // A real hit with an empty listing: nothing to sample.
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
        // Sealed for another trust class but found under the requester's entry dir.
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
        // A recorded key that differs from the request's.
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
        // The host view is the private directory.
        assert!(t.dir.starts_with(ws.join(attach::PRIVATE_DIR)));
        assert_eq!(fs::read(t.dir.join("bin")).unwrap(), b"b");
    }

    #[test]
    fn unusable_paths_are_refused_without_touching_the_store() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        // `..`, shadowing the workspace mount and the private dir's name.
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

    /// A generation broken at a later index leaves every target empty and
    /// releases the pin.
    #[test]
    fn a_failed_materialization_leaves_empty_targets() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        let d = decl(&["one", "two"]);
        let compat = attach::declared_compat(&d, KEY, s.platform);
        let (_, gdir) = seal(
            &root,
            &Seal::at(
                &s,
                KEY,
                &compat,
                &[&[("lib.so", &[1u8; 4096])], &[("x", b"x")]],
            ),
        );
        // A listed file of payload/1 is gone.
        fs::remove_file(gdir.join("payload/1/x")).unwrap();
        let a = restore_one(&root, &ws, &d, s);
        assert_eq!(miss(&a), Miss::Corrupt);
        assert!(a.lease.is_none(), "the pin is dropped with the miss");
        for target in &a.targets {
            assert!(target.dir.is_dir(), "the target is still writable");
            assert_eq!(
                fs::read_dir(&target.dir).unwrap().count(),
                0,
                "no partial payload in {}",
                target.declared
            );
        }
    }

    /// A path the bind-mount spec cannot carry is `invalid` and never a mount.
    #[test]
    fn an_unmountable_absolute_path_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        for path in ["/opt/a:b", "/opt/a,b"] {
            let a = restore_one(&root, &ws, &decl(&[path]), scope());
            assert_eq!(miss(&a), Miss::Invalid, "{path}");
            assert!(!a.targets[0].mount, "{path} is never bound in");
        }
        // A refused path under the workspace mount is not a mount either.
        let a = restore_one(&root, &ws, &decl(&["/workspace/evil"]), scope());
        assert_eq!(miss(&a), Miss::Invalid);
        assert!(!a.targets[0].mount);
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
