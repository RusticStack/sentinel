//! K05: preparation overlaps the image pull with the checkout, pulls are
//! single-flight per `name@sha256:…` across attempts, and helpers keep the
//! worker's registry authorization. The slot mechanics live behind a stub
//! download so nothing here needs a registry; `images`'s own tests cover
//! the follower/cancel paths, and `podman`'s cover the environment.

#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
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

/// Sentinel value for a `Job`'s cancel flag.
fn uncanceled() -> attempt::Cancel {
    Default::default()
}

/// What the stub download saw: the reference it was handed, whether the
/// checkout's file was already there when the pull began, and whether it
/// appeared while the pull was in flight.
#[derive(Default)]
struct Seen {
    image: String,
    present_at_start: bool,
    appeared_during: bool,
}

/// A real local checkout and a stubbed pull run in one `prepare`: the
/// pull must begin while the checkout is still working — a serial
/// implementation would only see the checkout's file already present.
#[test]
fn the_pull_overlaps_the_checkout() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("greeting.txt"), "hello\n").unwrap();
    // Enough files that the checkout's four Git invocations cannot plausibly
    // finish before the pull thread's first look at the workspace.
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
            // Stay in flight until the checkout's file lands.
            let deadline = Instant::now() + Duration::from_secs(15);
            while !workspace.join("greeting.txt").exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            seen.lock().unwrap().appeared_during = workspace.join("greeting.txt").exists();
            // The stub stands in for a download: `false` is `podman
            // pull`'s "the store did not already hold it" answer.
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
        mirrors: None,
        prepare_hold: Duration::ZERO,
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

    // The stub pulled the exact `name@sha256:…` reference — the spec's tag
    // is dropped in favor of the run's pin — and it ran while the checkout
    // was still working: the file was absent at pull start and appeared
    // during it. A serial `prepare` could satisfy neither.
    assert_eq!(seen.image, format!("example.test/image@{DIGEST}"));
    assert!(
        !seen.present_at_start,
        "the pull began before the checkout finished"
    );
    assert!(
        seen.appeared_during,
        "the checkout finished while the pull was in flight"
    );
    // Both phases still carry their own measured wall time, and the image
    // the run pinned joins the worker's held record.
    assert!(summary.checkout_ns.is_some());
    assert!(summary.image_pull_ns.is_some());
    // The image was absent before the stub's pull, so `image_present` is
    // false even though production still runs its scoped auth pull.
    assert_eq!(summary.image_present, Some(false));
    assert!(images.holds(DIGEST));
    // There is no podman image behind the stub, so the container start —
    // or the helper spawn — is what preparation reports.
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

/// A tag-only reference is refused before any pull machinery runs, on the
/// shared path just as on the direct one.
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
