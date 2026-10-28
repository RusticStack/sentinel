#![cfg(target_os = "linux")]

#[path = "support/shim_dir.rs"]
mod shim_dir;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, FailureClass, Fence, JobId, RepoId, RunId, WorkerId};
use sentinel_link::session::{EventContext, JobContext};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::summary::AttemptSummary;
use sentinel_worker::{
    artifacts::NoSink,
    attempt::{self, Job, NoOutput, Report, Verdict},
    images::Images,
    workspace::WORKSPACES_DIR,
};

const DIGEST: &str = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct Rec {
    events: Mutex<Vec<Event>>,
    summary: Mutex<Option<AttemptSummary>>,
}

impl Report for Rec {
    fn event(&self, _: AttemptId, _: Fence, event: Event) {
        self.events.lock().unwrap().push(event);
    }
    fn finish(&self, _: AttemptId, _: Fence, event: Event, summary: Vec<u8>) {
        self.events.lock().unwrap().push(event);
        *self.summary.lock().unwrap() = Some(AttemptSummary::decode(&summary).unwrap());
    }
}

fn uncanceled() -> attempt::Cancel {
    Default::default()
}

#[derive(Default)]
struct Seen {
    image: String,
    present_at_start: bool,
    appeared_during: bool,
}

#[test]
fn the_pull_overlaps_the_checkout() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("greeting.txt"), "hello\n").unwrap();
    // 200 files keep the checkout busy long enough for the pull to start first.
    for i in 0..200 {
        fs::write(repo.join(format!("file-{i:03}.txt")), "x\n").unwrap();
    }
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);

    let root = temp.path().join("worker");
    let attempt = AttemptId::new();
    let workspace = root.join(WORKSPACES_DIR).join(attempt.to_string());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let images = Images::with_download({
        let (seen, workspace) = (Arc::clone(&seen), workspace.clone());
        move |image, _, _, _, _| {
            {
                let mut seen = seen.lock().unwrap();
                seen.image = image.to_owned();
                seen.present_at_start = workspace.join("greeting.txt").exists();
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            while !workspace.join("greeting.txt").exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            seen.lock().unwrap().appeared_during = workspace.join("greeting.txt").exists();
            Ok(false)
        }
    });

    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  main:\n    image: example.test/image:1@{DIGEST}\n    resources: {{ cpu: 1, memory: 128MiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    let spec = RunSpec::new(
        PinnedSource::new(repo.to_str().unwrap(), &sha, Some("main")).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap();
    let mut job = Job {
        worker: WorkerId::new(),
        attempt,
        fence: Fence(1),
        job_index: 0,
        digest: DIGEST.to_owned(),
        spec,
        context: JobContext {
            source: None,
            source_valid_until: None,
            run: RunId::new(),
            repo: RepoId::new(),
            repo_name: "app".into(),
            job: JobId::new(),
            job_name: "main".into(),
            sha: sha.clone(),
            event: EventContext {
                name: "push".into(),
                ref_name: "main".into(),
                base_ref: None,
                pr_number: None,
                key: "k".into(),
            },
            cancelled: false,
            needs: Vec::new(),
            tenant: None,
            trust: sentinel_protocol::cache::Trust::Protected,
        },
        images: images.clone(),
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        caches: Vec::new(),
        cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
        mirrors: None,
        prepare_hold: Duration::ZERO,
        network: sentinel_worker::podman::Network::None,
        runtime: Default::default(),
    };
    let rec = Rec {
        events: Mutex::new(Vec::new()),
        summary: Mutex::new(None),
    };
    let (verdict, summary) = attempt::run(
        &root,
        &mut job,
        &rec,
        Arc::new(NoOutput),
        &NoSink,
        &uncanceled(),
    );
    let seen = seen.lock().unwrap();

    assert_eq!(seen.image, format!("example.test/image@{DIGEST}"));
    assert!(
        !seen.present_at_start,
        "the pull began before the checkout finished"
    );
    assert!(
        seen.appeared_during,
        "the checkout finished while the pull was in flight"
    );
    assert!(summary.checkout_ns.is_some());
    assert!(summary.image_pull_ns.is_some());
    // image_present stays false even though production still runs its scoped auth pull.
    assert_eq!(summary.image_present, Some(false));
    assert!(images.holds(DIGEST));
    match verdict {
        Verdict::Failed(FailureClass::Preparation, _) => {}
        other => panic!("expected a preparation failure, got {other:?}"),
    }
    assert!(matches!(
        rec.events.lock().unwrap().as_slice(),
        [
            Event::PreparationStarted,
            Event::Failed(FailureClass::Preparation)
        ]
    ));
    assert!(rec.summary.lock().unwrap().is_some());
}

#[test]
fn an_unpinned_reference_is_still_refused() {
    let images = Images::with_download(|_, _, _, _, _| Ok(false));
    match images.pull(
        "example.test/image:latest",
        Duration::from_secs(1),
        &uncanceled(),
    ) {
        Err(sentinel_worker::Error::Preparation(ref what)) => {
            assert_eq!(what, "image is not pinned by digest")
        }
        other => panic!("unpinned reference got {other:?}"),
    }
    assert_eq!(images.in_flight(), 0);
    assert!(images.held().is_empty());
}

// Only shell builtins: the pull command runs with an empty PATH.
const PODMAN: &str = r#"#!/bin/sh
dir="${0%/*}"
last=
for a in "$@"; do last="$a"; done
key="${last##*@}"
case "$1" in
  image)
    echo "exists $key" >> "$dir/calls"
    if [ -e "$dir/corrupt-$key" ] && [ ! -e "$dir/repaired-$key" ]; then
      echo "Error: layer not known" >&2
      exit 125
    fi
    if [ -e "$dir/present-$key" ]; then exit 0; fi
    exit 1 ;;
  pull)
    echo "pull $key" >> "$dir/calls"
    : > "$dir/present-$key"
    : > "$dir/repaired-$key"
    exit 0 ;;
  *) exit 1 ;;
esac
"#;

fn podman_shim() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = shim_dir::create("images");
        let path = dir.join("podman");
        fs::write(&path, PODMAN).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let joined = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // SAFETY: set once, before any test in this binary spawns podman
        // (every test that does calls `podman_shim()` first, and `OnceLock` serializes it).
        unsafe {
            std::env::set_var("PATH", joined);
        }
        dir
    })
}

fn pulls_of(dir: &Path, digest: &str) -> usize {
    fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == format!("pull {digest}"))
        .count()
}

fn digest_of(n: u8) -> String {
    format!("sha256:{n:02x}{}", "ab".repeat(31))
}

fn reference(digest: &str) -> String {
    format!("example.test/image@{digest}")
}

#[test]
fn a_resident_digest_skips_the_pull_and_a_missing_one_pulls() {
    let dir = podman_shim();
    let (present, missing) = (digest_of(1), digest_of(2));
    fs::write(dir.join(format!("present-{present}")), "").unwrap();
    let images = Images::new(PathBuf::from("unused-auth.json"));

    // Anonymous pull into the shared store: a resident digest never asks the registry.
    assert!(
        images
            .pull(&reference(&present), Duration::from_secs(10), &uncanceled())
            .unwrap(),
        "a resident digest reports present"
    );
    assert_eq!(pulls_of(dir, &present), 0, "the resident digest was pulled");
    assert!(images.holds(&present));

    assert!(
        !images
            .pull(&reference(&missing), Duration::from_secs(10), &uncanceled())
            .unwrap(),
        "a missing digest reports not present"
    );
    assert_eq!(pulls_of(dir, &missing), 1);
    // The pull landed it; a second pull now takes the fast path.
    assert!(
        images
            .pull(&reference(&missing), Duration::from_secs(10), &uncanceled())
            .unwrap()
    );
    assert_eq!(
        pulls_of(dir, &missing),
        1,
        "the second pull skipped the registry"
    );
}

#[test]
fn an_image_podman_cannot_confirm_is_pulled_again() {
    let dir = podman_shim();
    let corrupt = digest_of(3);
    fs::write(dir.join(format!("present-{corrupt}")), "").unwrap();
    fs::write(dir.join(format!("corrupt-{corrupt}")), "").unwrap();
    let images = Images::new(PathBuf::from("unused-auth.json"));
    // `podman image exists` fails for a damaged image, so it is not trusted as resident.
    assert!(
        !images
            .pull(&reference(&corrupt), Duration::from_secs(10), &uncanceled())
            .unwrap()
    );
    assert_eq!(pulls_of(dir, &corrupt), 1);
}

#[test]
fn a_credentialed_pull_contacts_the_registry_even_for_a_resident_digest() {
    let dir = podman_shim();
    let resident = digest_of(4);
    fs::write(dir.join(format!("present-{resident}")), "").unwrap();
    let images = Images::new(PathBuf::from("unused-auth.json"));
    let present = images
        .pull_for_tenant(
            &reference(&resident),
            [7; 16],
            [9; 32],
            Path::new("tenant-auth.json"),
            &sentinel_worker::podman::Store::Shared,
            Duration::from_secs(10),
            &uncanceled(),
        )
        .unwrap();
    assert!(
        present,
        "the image was resident before the authorizing pull"
    );
    assert_eq!(
        pulls_of(dir, &resident),
        1,
        "authorization needs the registry"
    );
}
