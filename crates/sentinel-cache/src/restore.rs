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

const MAX_CURRENT_BYTES: u64 = 128;

const FIRST_TOUCH_BYTES: usize = 4 * 1024;

fn ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub cache_root: &'a Path,
    pub workspace: &'a Path,
    pub workspace_mount: &'a str,
    pub backend: Backend,
}

pub fn restore(
    env: &Context<'_>,
    decl: &Cache,
    key: Option<String>,
    scope: Scope,
    owner: &str,
) -> Attached {
    restore_remote(env, decl, key, scope, owner, None)
}

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
    // Pin before trusting `current`, and re-read it under the pin: GC cannot reclaim the
    // generation between the read and the clone.
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
        (Ok((_, _, Outcome::Hit(_))), None) => {
            attached.outcome = Outcome::Miss(Miss::Unavailable);
            return attached;
        }
        (Ok((_, _, Outcome::Miss(miss))), _) | (Err(miss), _) => {
            attached.outcome = Outcome::Miss(miss);
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
            attached.stats.first_touch_ns = first_touch(&blob, &attached.targets);
            crate::gc::touch(&entry_dir);
            attached.generation = Some(name);
            attached.lease = Some(lease);
            attached.outcome = Outcome::Hit(hit);
        }
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

fn payload_parts(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("payload/")?;
    let (index, rel) = rest.split_once('/')?;
    if rel.is_empty() {
        return None;
    }
    Some((index.parse().ok()?, rel))
}

fn check_payload_tree(src: &Path, listed: &HashMap<&str, &FileEntry>) -> Result<(), Miss> {
    let mut stack = vec![(src.to_path_buf(), String::new(), 0usize)];
    let mut seen = 0usize;
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
                return Err(Miss::Corrupt);
            }
        }
    }
    if seen != listed.len() {
        return Err(Miss::Corrupt);
    }
    Ok(())
}

pub(crate) fn materialize(
    gen_dir: &Path,
    manifest: &manifest::Manifest,
    targets: &[Target],
    backend: Backend,
    stats: &mut Stats,
) -> Result<FilesBlob, Miss> {
    let blob = files_blob(gen_dir, manifest)?;
    let mut listed: Vec<HashMap<&str, &FileEntry>> =
        targets.iter().map(|_| HashMap::new()).collect();
    for entry in &blob.entries {
        let ok = valid_relative_path(&entry.path)
            && payload_parts(&entry.path).is_some_and(|(i, rel)| {
                i < targets.len() && listed[i].insert(rel, entry).is_none()
            });
        if !ok {
            return Err(Miss::Invalid);
        }
    }
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
                for target in targets {
                    let _ = clone::empty(&target.dir);
                }
                return Err(match e.kind() {
                    io::ErrorKind::NotFound => Miss::Corrupt,
                    _ => Miss::Unavailable,
                });
            }
        }
    }
    Ok(blob)
}

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
        sampled |= file.read(&mut [0u8; FIRST_TOUCH_BYTES]).is_ok();
    }
    if sampled { Some(ns(started)) } else { None }
}

fn target(env: &Context<'_>, name: &str, index: usize, declared: &str) -> (Target, Option<Miss>) {
    // `:` and `,` separate fields of a bind-mount spec, so such a path would fail `podman create`.
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
        Err(miss) => (
            Target {
                mount: false,
                ..target
            },
            Some(miss),
        ),
    }
}

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
        let (entry, _) = seal(
            &root,
            &Seal {
                sealed: false,
                ..Seal::at(&s, KEY, &compat, &[&[("x", b"x")]])
            },
        );
        let a = restore_one(&root, &ws, &d, s.clone());
        assert_eq!(miss(&a), Miss::Unsealed);
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
        assert!(t.dir.starts_with(ws.join(attach::PRIVATE_DIR)));
        assert_eq!(fs::read(t.dir.join("bin")).unwrap(), b"b");
    }

    #[test]
    fn unusable_paths_are_refused_without_touching_the_store() {
        let temp = tempfile::tempdir().unwrap();
        let (root, ws) = (temp.path().join("cache"), temp.path().join("ws"));
        fs::create_dir(&ws).unwrap();
        let s = scope();
        for paths in [
            &["../up"][..],
            &["/workspace/evil"][..],
            &[".sentinel-cache/x"][..],
        ] {
            let d = decl(paths);
            let a = restore_one(&root, &ws, &d, s.clone());
            assert_eq!(miss(&a), Miss::Invalid, "{paths:?}");
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
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, ws.join("link")).unwrap();
        let a = restore_one(&root, &ws, &decl(&["link/sub"]), scope());
        assert_eq!(miss(&a), Miss::Invalid);
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
