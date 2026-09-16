//! Compiler-state persistence (K06): a `class: compiler` entry is a
//! stable toolchain namespace — the tool inside owns per-input
//! invalidation while Sentinel pins where the state lives and always
//! hands the job a writable view.
//!
//! What this file proves end to end through the real restore/publish
//! paths:
//!
//! - a generation sealed under `cc-normal-<h1>` serves `cc-normal-<h2>` —
//!   a small source or lockfile edit changes the volatile tail, not the
//!   key stem that names the entry directory;
//! - `cc-normal`/`cc-race`/`cc-coverage`/`cc-experiment` are disjoint
//!   namespaces — different stems, different entry directories, never a
//!   cross-mode serve;
//! - the `os-arch` scope component isolates architectures — another arch
//!   answers `absent`, a moved manifest answers `wrong_platform`;
//! - a manifest recorded under another class is `wrong_class`, and
//!   corrupt, tampered or half-written generations are typed misses,
//!   never panics;
//! - tool-owned invalidation: a hit restores the namespace wholesale and
//!   a compiler stand-in (the Rust mirror of `fixtures/compiler/fakecc.sh`)
//!   rebuilds only the inputs that changed — a cache hit is bytes on
//!   disk, never a cached verdict.
//!
//! `Attached`/`Outcome` carry no step or verdict surface at all: a hit is
//! a manifest plus materialized files, and the worker-side proof that the
//! step runner never consults cache state lives in `attempt.rs`.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sentinel_cache::{
    attach::{self, Attached, entry_key},
    clone::Backend,
    manifest::{Compat, FileEntry, FilesBlob, Manifest},
    outcome::{Hit, Miss, Outcome},
    publish::{self, Published},
    restore::{self, Context},
    scope::{self, Os, Platform, Scope},
};
use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_pipeline::{expr::Template, schema::Cache};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};

/// The build modes a pipeline namespaces by stem convention —
/// `cc-<mode>-<hash>`: instrumented and uninstrumented outputs live in
/// different entry directories and can never serve each other.
const MODES: [&str; 4] = ["normal", "race", "coverage", "experiment"];

/// One compiler scope: tenant and repo are fresh per call, so tests that
/// share a store build their scope once and reuse it.
fn cscope(arch: Arch) -> Scope {
    Scope::new(
        TenantId::new(),
        RepoId::new(),
        Class::Compiler,
        Trust::Protected,
        Platform {
            os: Os::Linux,
            arch,
        },
        Scope::toolchain_digest(b"cc 15.0 linux"),
        "cc",
    )
    .unwrap()
}

/// The same scope rooted at another class — for manifests recorded under
/// a class the request is not.
fn scope_as(scope: &Scope, class: Class) -> Scope {
    let mut other = scope.clone();
    other.class = class;
    other
}

/// A bare `class: compiler` declaration; `key` is a literal template —
/// `restore` takes the already-rendered key, so the template is never
/// evaluated here.
fn decl(paths: &[&str]) -> Cache {
    Cache {
        name: "cc".into(),
        class: Class::Compiler,
        key: Template::parse("cc-normal-literal").unwrap(),
        paths: paths.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// The `Compat` a bare compiler declaration derives (K06): `flags` stays
/// empty — the key stem is the whole namespace.
fn compat(d: &Cache, key: &str, platform: Platform) -> Compat {
    let compat = attach::declared_compat(d, key, platform);
    assert_eq!(
        compat,
        Compat::Compiler {
            flags: String::new()
        }
    );
    compat
}

/// What a sealed generation looks like on disk — `entry_of`/`entry_key`
/// decide which entry directory the generation sits under;
/// `recorded`/`recorded_key` are what the manifest claims. Keeping them
/// separate lets a test place a manifest where it does not belong —
/// exactly the case the boundary fields exist to catch.
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
        .entry_dir(cache_root, entry_key(s.entry_of.class, s.entry_key));
    let name = scope::gen_name(1_700_000_000_000, 0x00ab_cdef);
    let gdir = entry_dir.join(&name);
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
        workspace_mount: "/workspace",
        backend: Backend::Copy,
    }
}

/// Restore one declaration under an already-rendered key — `cc-<mode>-<h>`
/// in these tests, where the tail is the `hash_files` half a small edit
/// moves.
fn restore_key(root: &Path, ws: &Path, decl: &Cache, scope: Scope, key: &str) -> Attached {
    restore::restore(
        &env(root, ws),
        decl,
        Some(key.to_owned()),
        scope,
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

fn workspace(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    dir.to_path_buf()
}

fn commit(root: &Path, a: &Attached, ms: i64) -> Published {
    publish::commit(
        root,
        a,
        a.scope.trust,
        UnixMillis(ms),
        Instant::now() + Duration::from_secs(60),
        &|| false,
    )
    .unwrap()
}

/// The Rust mirror of `fixtures/compiler/fakecc.sh` — same algorithm, a
/// different content digest (the store has blake3 to hand; the script
/// uses `sha256sum` because busybox does): each input's artifact name
/// carries the digest of the bytes it was built from, so an artifact is
/// reused exactly when its input is unchanged. Sentinel never inspects
/// this — the tool owns staleness inside the served namespace.
fn fakecc(cache_dir: &Path, inputs: &[(&str, &[u8])]) -> (Vec<String>, Vec<String>) {
    let mut built = Vec::new();
    let mut reused = Vec::new();
    for (name, bytes) in inputs {
        let out = cache_dir.join(format!("{name}.{}.o", blake3::hash(bytes).to_hex()));
        if out.exists() {
            reused.push((*name).to_owned());
        } else {
            fs::write(&out, bytes).unwrap();
            built.push((*name).to_owned());
        }
    }
    (built, reused)
}

/// (a) A small source or lockfile edit moves the volatile tail; the stem
/// still names the entry, so the sealed generation serves.
#[test]
fn a_new_tail_inside_the_stem_is_a_hit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);
    let c = compat(&d, "cc-normal-aaaa1111", s.platform);
    seal(
        &root,
        &Seal::at(
            &s,
            "cc-normal-aaaa1111",
            &c,
            &[&[("obj/a.o", b"alpha-object"), ("obj/b.o", b"beta-object")]],
        ),
    );

    // The next attempt renders `cc-normal-<h2>`: same namespace, new tail.
    let ws = workspace(&temp.path().join("ws"));
    let a = restore_key(&root, &ws, &d, s, "cc-normal-bbbb2222");
    assert_eq!(hit(&a).manifest.key, "cc-normal-aaaa1111");
    assert_eq!(
        fs::read(ws.join("ccache/obj/a.o")).unwrap(),
        b"alpha-object",
        "the sealed payload materializes into the writable view"
    );
    assert_eq!(a.stats.files, 2);
}

/// (b) Every mode is its own stem: four entry directories, four `current`
/// pointers, and a manifest found under another mode's entry is a
/// `wrong_key` miss — never a cross-mode serve.
#[test]
fn build_modes_are_disjoint_namespaces() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);

    for mode in MODES {
        let key = format!("cc-{mode}-aaaa1111");
        let c = compat(&d, &key, s.platform);
        let body = format!("{mode}-objects").into_bytes();
        seal(
            &root,
            &Seal::at(&s, &key, &c, &[&[("obj/out.o", body.as_slice())]]),
        );
    }

    for (i, mode) in MODES.iter().enumerate() {
        // A request under each mode's stem with a moved tail hits only
        // its own namespace.
        let ws = workspace(&temp.path().join(format!("ws-{mode}")));
        let a = restore_key(&root, &ws, &d, s.clone(), &format!("cc-{mode}-ffff9999"));
        assert_eq!(
            hit(&a).manifest.key,
            format!("cc-{mode}-aaaa1111"),
            "{mode} serves its own stem"
        );
        assert_eq!(
            fs::read(ws.join("ccache/obj/out.o")).unwrap(),
            format!("{mode}-objects").into_bytes(),
            "{mode} payload, not another mode's"
        );
        // Every other mode's entry directory is a different path.
        for other in MODES.iter().skip(i + 1) {
            assert_ne!(
                s.entry_dir(&root, entry_key(Class::Compiler, &format!("cc-{mode}-x"))),
                s.entry_dir(&root, entry_key(Class::Compiler, &format!("cc-{other}-x"))),
                "{mode} vs {other} must be different entries"
            );
        }
    }

    // A generation under a mode's entry whose manifest claims another
    // stem — the moved-directory case — is `wrong_key`, not a serve.
    let key = "cc-race-aaaa1111";
    let c = compat(&d, key, s.platform);
    seal(
        &root,
        &Seal {
            recorded_key: "cc-normal-cccc3333",
            ..Seal::at(&s, key, &c, &[&[("x", b"x")]])
        },
    );
    let ws = workspace(&temp.path().join("ws-moved"));
    let a = restore_key(&root, &ws, &d, s, "cc-race-dddd4444");
    assert_eq!(miss(&a), Miss::WrongKey);
}

/// (c) The `os-arch` scope component is the architecture boundary: the
/// same key under another arch is a different directory (`absent`), and
/// a manifest moved across answers `wrong_platform`.
#[test]
fn the_architecture_boundary_is_the_scope_path() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let x86 = cscope(Arch::X86_64);
    let arm = cscope(Arch::Aarch64);
    // Same store, same name, same everything but the arch — and a
    // manifest that records x86 to model a directory moved across.
    let mut arm_with_x86_ids = arm.clone();
    arm_with_x86_ids.tenant = x86.tenant;
    arm_with_x86_ids.repo = x86.repo;
    let d = decl(&["ccache"]);
    let key = "cc-normal-aaaa1111";
    let c = compat(&d, key, x86.platform);
    seal(&root, &Seal::at(&x86, key, &c, &[&[("o", b"obj")]]));
    assert_ne!(
        x86.entry_dir(&root, entry_key(Class::Compiler, key)),
        arm_with_x86_ids.entry_dir(&root, entry_key(Class::Compiler, key)),
        "the scope path itself separates the architectures"
    );

    // Nothing under the aarch64 scope path: a clean `absent`, never a
    // cross-arch serve.
    let ws = workspace(&temp.path().join("ws-arm"));
    let a = restore_key(&root, &ws, &d, arm_with_x86_ids.clone(), key);
    assert_eq!(miss(&a), Miss::Absent);

    // An x86 manifest placed under the aarch64 entry answers
    // `wrong_platform` — the recorded boundary catches the move.
    seal(
        &root,
        &Seal {
            entry_of: &arm_with_x86_ids,
            ..Seal::at(&x86, key, &c, &[&[("o", b"obj")]])
        },
    );
    let a = restore_key(&root, &ws, &d, arm_with_x86_ids, key);
    assert_eq!(miss(&a), Miss::WrongPlatform);
}

/// (d) A manifest recorded under another class never serves a compiler
/// request — and a compiler manifest never serves a dependencies one.
/// Class is checked before any key or compat input.
#[test]
fn a_manifest_of_another_class_never_serves() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);
    let key = "cc-normal-aaaa1111";

    // A dependencies manifest sitting in the compiler entry directory.
    let deps_scope = scope_as(&s, Class::Dependencies);
    let deps_compat = Compat::Dependencies {
        lock: *blake3::hash(b"lock").as_bytes(),
        installer: "cargo".into(),
        flags: "--locked".into(),
        abi: "test".into(),
    };
    seal(
        &root,
        &Seal {
            entry_of: &s,
            entry_key: key,
            recorded: &deps_scope,
            recorded_key: key,
            compat: &deps_compat,
            sealed: true,
            payloads: &[&[("o", b"obj")]],
        },
    );
    let ws = workspace(&temp.path().join("ws"));
    let a = restore_key(&root, &ws, &d, s.clone(), key);
    assert_eq!(miss(&a), Miss::WrongClass);

    // And the symmetric direction: a compiler manifest under an entry a
    // `dependencies` request resolves. The deps class serves the full
    // rendered key, so the entry is keyed by `deps-exact`, not a stem.
    let deps_decl = Cache {
        name: "cc".into(),
        class: Class::Dependencies,
        key: Template::parse("deps-exact").unwrap(),
        paths: vec!["v".into()],
    };
    let compiler_compat = compat(&d, key, s.platform);
    seal(
        &root,
        &Seal {
            entry_of: &deps_scope,
            entry_key: "deps-exact",
            recorded: &s,
            recorded_key: key,
            compat: &compiler_compat,
            sealed: true,
            payloads: &[&[("o", b"obj")]],
        },
    );
    let a = restore_key(&root, &ws, &deps_decl, deps_scope, "deps-exact");
    assert_eq!(miss(&a), Miss::WrongClass);
}

/// (e) Half-written, corrupt or tampered state is always a typed miss:
/// the job rebuilds, nothing panics.
#[test]
fn tampered_or_incomplete_state_is_a_typed_miss() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);
    let key = "cc-normal-aaaa1111";
    let c = compat(&d, key, s.platform);
    let (entry, gdir) = seal(&root, &Seal::at(&s, key, &c, &[&[("o", b"obj")]]));
    let ws = workspace(&temp.path().join("ws"));

    // A `current` naming a generation that is not on disk.
    fs::write(entry.join(scope::CURRENT_NAME), b"gen-999-00000000\n").unwrap();
    assert_eq!(
        miss(&restore_key(&root, &ws, &d, s.clone(), key)),
        Miss::Absent
    );
    // A `current` that is not a generation name at all.
    fs::write(entry.join(scope::CURRENT_NAME), b"garbage\n").unwrap();
    assert_eq!(
        miss(&restore_key(&root, &ws, &d, s.clone(), key)),
        Miss::Corrupt
    );
    fs::write(entry.join(scope::CURRENT_NAME), vec![b'g'; 200]).unwrap();
    assert_eq!(
        miss(&restore_key(&root, &ws, &d, s.clone(), key)),
        Miss::Corrupt
    );

    // A truncated manifest.
    fs::write(
        entry.join(scope::CURRENT_NAME),
        format!("{}\n", gdir.file_name().unwrap().to_str().unwrap()),
    )
    .unwrap();
    let manifest = fs::read(gdir.join(scope::MANIFEST_NAME)).unwrap();
    fs::write(gdir.join(scope::MANIFEST_NAME), &manifest[..8]).unwrap();
    assert_eq!(
        miss(&restore_key(&root, &ws, &d, s.clone(), key)),
        Miss::Corrupt
    );

    // A manifest whose magic was tampered with.
    let mut flipped = manifest;
    flipped[0] = b'X';
    fs::write(gdir.join(scope::MANIFEST_NAME), flipped).unwrap();
    assert_eq!(
        miss(&restore_key(&root, &ws, &d, s.clone(), key)),
        Miss::Corrupt
    );

    // A `files` blob rewritten after sealing: the digest the manifest
    // pins no longer matches. A second generation under the same stem —
    // the next publisher's tail — is what `current` resolves to.
    let (_, gdir2) = seal(
        &root,
        &Seal {
            entry_key: "cc-normal-bbbb2222",
            recorded_key: "cc-normal-bbbb2222",
            ..Seal::at(&s, key, &c, &[&[("o", b"obj")]])
        },
    );
    fs::write(gdir2.join(scope::FILES_NAME), FilesBlob::default().encode()).unwrap();
    let a = restore_key(&root, &ws, &d, s.clone(), "cc-normal-bbbb2222");
    assert_eq!(miss(&a), Miss::Corrupt);

    // A generation that was never sealed.
    seal(
        &root,
        &Seal {
            entry_key: "cc-normal-cccc3333",
            recorded_key: "cc-normal-cccc3333",
            sealed: false,
            ..Seal::at(&s, key, &c, &[&[("o", b"obj")]])
        },
    );
    let a = restore_key(&root, &ws, &d, s, "cc-normal-cccc3333");
    assert_eq!(miss(&a), Miss::Unsealed);
}

/// The K06 mechanism end to end: cold miss, warm hit after a small edit,
/// the tool rebuilding only the changed input, and a second publication
/// the next attempt still serves. `current` keeps naming the newest
/// generation inside one stem — the tool's per-input keys are what make
/// the accumulated payload correct.
#[test]
fn the_tool_invalidates_inputs_inside_a_served_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);
    let entry = s.entry_dir(&root, entry_key(Class::Compiler, "cc-normal-x"));

    // Attempt 1 — nothing under the stem: a miss, then the tool fills
    // its private view with one artifact per input.
    let ws1 = workspace(&temp.path().join("ws1"));
    let a1 = restore_key(&root, &ws1, &d, s.clone(), "cc-normal-aaaa1111");
    assert_eq!(miss(&a1), Miss::Absent);
    let (built, reused) = fakecc(
        &a1.targets[0].dir,
        &[("a.c", b"alpha"), ("b.c", b"beta"), ("c.c", b"gamma")],
    );
    assert_eq!(built, ["a.c", "b.c", "c.c"]);
    assert!(reused.is_empty());
    let out = commit(&root, &a1, 1_000);
    assert!(matches!(out, Published::Sealed { files: 3, .. }), "{out:?}");

    // Attempt 2 — a small edit: `b.c` changed, so `hash_files` moved the
    // tail. Same stem, so the namespace serves and the tool decides the
    // rest: only `b.c` is rebuilt.
    let ws2 = workspace(&temp.path().join("ws2"));
    let a2 = restore_key(&root, &ws2, &d, s.clone(), "cc-normal-bbbb2222");
    assert_eq!(hit(&a2).manifest.key, "cc-normal-aaaa1111");
    let (built, reused) = fakecc(
        &a2.targets[0].dir,
        &[("a.c", b"alpha"), ("b.c", b"beta-v2"), ("c.c", b"gamma")],
    );
    assert_eq!(reused, ["a.c", "c.c"], "unchanged inputs are not rebuilt");
    assert_eq!(built, ["b.c"], "the edited input is rebuilt");
    let out = commit(&root, &a2, 2_000);
    // The accumulated view now carries the stale `b.c` artifact too —
    // the store keeps what the tool wrote; the tool's keys keep it
    // correct. Only the new artifact is new bytes.
    assert!(matches!(out, Published::Sealed { files: 4, .. }), "{out:?}");

    // Attempt 3 — another tail, still the same stem: the newest
    // generation serves and the whole accumulated state is writable.
    let ws3 = workspace(&temp.path().join("ws3"));
    let a3 = restore_key(&root, &ws3, &d, s, "cc-normal-dddd4444");
    assert_eq!(hit(&a3).manifest.key, "cc-normal-bbbb2222");
    let view = &a3.targets[0].dir;
    assert_eq!(fs::read_dir(view).unwrap().count(), 4);
    let (built, reused) = fakecc(
        view,
        &[("a.c", b"alpha"), ("b.c", b"beta-v2"), ("c.c", b"gamma")],
    );
    assert_eq!(reused, ["a.c", "b.c", "c.c"]);
    assert!(built.is_empty());
    // Nothing changed: the identical listing is an `unchanged` skip, not
    // a new generation.
    assert_eq!(
        commit(&root, &a3, 3_000),
        Published::Skipped(publish::SkipReason::Unchanged)
    );
    // `current` still names the second generation — one pointer, one
    // namespace.
    let current = fs::read_to_string(entry.join(scope::CURRENT_NAME)).unwrap();
    assert!(current.starts_with("gen-2000-"), "{current}");
}

/// The serving half of the "never a cached outcome" contract: two
/// attempts with different rendered keys but the same stem share one
/// namespace and one `current` — whoever publishes last is what the next
/// attempt sees, and the tool inside reconciles inputs. There is no
/// path by which a hit could skip work: the outcome type itself carries
/// only a manifest and a byte count.
#[test]
fn a_hit_is_bytes_on_disk_not_a_verdict() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let s = cscope(Arch::X86_64);
    let d = decl(&["ccache"]);
    let c = compat(&d, "cc-normal-aaaa1111", s.platform);
    seal(
        &root,
        &Seal::at(&s, "cc-normal-aaaa1111", &c, &[&[("o", b"obj")]]),
    );

    let ws = workspace(&temp.path().join("ws"));
    let a = restore_key(&root, &ws, &d, s, "cc-normal-eeee5555");
    let h = hit(&a);
    // The whole answer: the verified manifest and its byte total. The
    // `Hit` type has no field that could carry a step result — bytes are
    // the only thing a cache hit can deliver.
    assert_eq!(h.bytes, 3);
    assert_eq!(fs::read(a.targets[0].dir.join("o")).unwrap(), b"obj");
}
