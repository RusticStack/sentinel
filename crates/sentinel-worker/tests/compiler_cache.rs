//! K06 compiler-state persistence against a real container: a
//! `class: compiler` entry mounted writable inside the environment keeps
//! serving across small source edits, and the tool inside the namespace —
//! `fixtures/compiler/fakecc.sh`, a content-keyed compiler stand-in —
//! rebuilds only the inputs that changed. A cache hit restores bytes for
//! the steps to consume; the tool still runs and still decides staleness
//! per input, which is exactly why a hit is never a cached verdict.
//!
//! Gated like the Podman suite: `SENTINEL_PODMAN_TESTS=1` as a rootless
//! Podman account; otherwise it reports the skip, never a false pass.

#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use sentinel_cache::{
    Miss, Os, Outcome, Platform, Scope,
    attach::UNKNOWN_TENANT,
    clone,
    publish::{self, Published},
    restore::{self, Context},
};
use sentinel_core::{AttemptId, RepoId, UnixMillis, WorkerId};
use sentinel_pipeline::{expr::Template, run::StepCommand, schema::Cache};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};
use sentinel_worker::podman::{self, Container, Limits, Mount};

const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
/// The checked-in fixture the container runs — the job's "compiler".
const FAKECC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/compiler/fakecc.sh"
);

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

/// A bare `class: compiler` declaration with an absolute cache path, so
/// the restored view reaches the container through a bind mount — the
/// writability this test exists to prove.
fn decl() -> Cache {
    Cache {
        name: "cc".into(),
        class: Class::Compiler,
        key: Template::parse("cc-normal-literal").unwrap(),
        paths: vec!["/cc-cache".into()],
    }
}

fn scope(repo: RepoId) -> Scope {
    Scope::new(
        UNKNOWN_TENANT,
        repo,
        Class::Compiler,
        Trust::Protected,
        Platform {
            os: Os::Linux,
            arch: if cfg!(target_arch = "aarch64") {
                Arch::Aarch64
            } else {
                Arch::X86_64
            },
        },
        Scope::toolchain_digest(IMAGE.as_bytes()),
        "cc",
    )
    .unwrap()
}

fn env<'a>(root: &'a Path, ws: &'a Path) -> Context<'a> {
    Context {
        cache_root: root,
        workspace: ws,
        workspace_mount: podman::WORKSPACE_MOUNT,
        backend: clone::detect(root),
    }
}

fn mounts_of(a: &sentinel_cache::attach::Attached) -> Vec<Mount> {
    a.targets
        .iter()
        .filter(|t| t.mount)
        .map(|t| Mount {
            host: t.dir.clone(),
            container: t.container.clone(),
            read_only: false,
        })
        .collect()
}

fn sh(script: &str) -> StepCommand {
    StepCommand {
        argv: vec!["/bin/sh".into(), "-e".into(), "-c".into(), script.into()],
        env: Vec::new(),
        secrets: Vec::new(),
        secret_files: Vec::new(),
        workdir: None,
        timeout_secs: 120,
    }
}

/// One attempt's worth of workspace: the fixture plus its "sources".
fn workspace(dir: &Path, b_source: &[u8]) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::copy(FAKECC, dir.join("fakecc.sh")).unwrap();
    fs::write(dir.join("src/a.c"), b"int a(void) { return 1; }\n").unwrap();
    fs::write(dir.join("src/b.c"), b_source).unwrap();
}

fn publish(root: &Path, a: &sentinel_cache::attach::Attached) -> Published {
    publish::commit(
        root,
        a,
        Trust::Protected,
        UnixMillis::now(),
        Instant::now() + publish::CACHE_PUBLISH_TIMEOUT,
        &|| false,
    )
    .unwrap()
}

#[test]
fn a_compiler_namespace_persists_across_attempts_and_the_tool_decides_staleness() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let authfile = sentinel_worker::images::prepare_anonymous_authfile(tmp.path()).unwrap();
    podman::pull(
        IMAGE,
        &authfile,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let root = tmp.path().join("cache");
    let repo = RepoId::new();
    let d = decl();
    let limits = Limits {
        cpu_millis: 1_000,
        memory_bytes: 256 << 20,
        pids: podman::DEFAULT_PIDS_LIMIT,
    };
    let run_fakecc = sh("sh /workspace/fakecc.sh /cc-cache src/a.c src/b.c");

    // Attempt 1 — a cold namespace: restore misses, the tool fills its
    // writable mounted view inside the container, publish seals it.
    let ws1 = tmp.path().join("ws1");
    workspace(&ws1, b"int b(void) { return 1; }\n");
    let a1 = restore::restore(
        &env(&root, &ws1),
        &d,
        Some("cc-normal-aaaa1111".into()),
        scope(repo),
        "attempt-1",
    );
    assert_eq!(a1.outcome, Outcome::Miss(Miss::Absent));
    let mounts = mounts_of(&a1);
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].container, "/cc-cache");
    let c1 = Container::start(
        WorkerId::new(),
        AttemptId::new(),
        IMAGE,
        limits,
        &ws1,
        &mounts,
    )
    .unwrap();
    let exit = c1.exec(&run_fakecc, &[]).unwrap();
    assert_eq!(exit.code, Some(0), "{}", exit.stderr_excerpt());
    let out = String::from_utf8_lossy(&exit.stdout);
    assert!(
        out.contains("built a.c") && out.contains("built b.c"),
        "{out}"
    );
    // The mount was genuinely writable inside the environment: the two
    // artifacts the container wrote are visible in the host view.
    assert_eq!(fs::read_dir(&a1.targets[0].dir).unwrap().count(), 2);
    let sealed = publish(&root, &a1);
    assert!(
        matches!(sealed, Published::Sealed { files: 2, .. }),
        "{sealed:?}"
    );
    c1.destroy().unwrap();
    drop(a1);

    // Attempt 2 — a small source edit moves the rendered key's tail; the
    // stem is the same, so the namespace serves. The tool then runs and
    // rebuilds only the edited input — the hit restored state, not a
    // verdict, and the work still happened.
    let ws2 = tmp.path().join("ws2");
    workspace(&ws2, b"int b(void) { return 2; }\n");
    let a2 = restore::restore(
        &env(&root, &ws2),
        &d,
        Some("cc-normal-bbbb2222".into()),
        scope(repo),
        "attempt-2",
    );
    assert!(a2.outcome.is_hit(), "{:?}", a2.outcome);
    assert_eq!(fs::read_dir(&a2.targets[0].dir).unwrap().count(), 2);
    let c2 = Container::start(
        WorkerId::new(),
        AttemptId::new(),
        IMAGE,
        limits,
        &ws2,
        &mounts_of(&a2),
    )
    .unwrap();
    let exit = c2.exec(&run_fakecc, &[]).unwrap();
    assert_eq!(exit.code, Some(0), "{}", exit.stderr_excerpt());
    let out = String::from_utf8_lossy(&exit.stdout);
    assert!(out.contains("reused a.c"), "{out}");
    assert!(out.contains("built b.c"), "{out}");
    let sealed = publish(&root, &a2);
    // a.c's artifact, both b.c artifacts (the stale one accumulates —
    // the tool's content keys keep it correct): three files sealed.
    assert!(
        matches!(sealed, Published::Sealed { files: 3, .. }),
        "{sealed:?}"
    );
    c2.destroy().unwrap();
    drop(a2);

    // Attempt 3 — another tail, still the same stem: the newest
    // generation serves the accumulated state.
    let ws3 = tmp.path().join("ws3");
    workspace(&ws3, b"int b(void) { return 2; }\n");
    let a3 = restore::restore(
        &env(&root, &ws3),
        &d,
        Some("cc-normal-cccc3333".into()),
        scope(repo),
        "attempt-3",
    );
    assert!(a3.outcome.is_hit(), "{:?}", a3.outcome);
    assert_eq!(fs::read_dir(&a3.targets[0].dir).unwrap().count(), 3);
    // The `gen-*` name of the generation this attempt cloned from — the
    // source the next publish would reuse.
    assert!(
        a3.generation
            .as_deref()
            .is_some_and(|g| g.starts_with("gen-"))
    );
}
