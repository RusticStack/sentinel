//! K05 bounded image prefetch with real rootless Podman. Runs only with
//! `SENTINEL_PODMAN_TESTS=1` as an account with rootless Podman (see
//! docs/development.md); otherwise it reports that it was skipped, never a
//! false pass. It needs the registry: the images are pulled from Docker
//! Hub by digest. It removes only the images below, which no other suite
//! uses, so it can run beside them against the same store.
//!
//! `prefetch_saves_the_attempt_pull` (ignored) measures an attempt's pull
//! of a 123 MB image cold and after a prefetch.

#![cfg(target_os = "linux")]

use std::{
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use sentinel_worker::{
    images::Images,
    podman,
    prefetch::{Bounds, PodmanProbe, Prefetcher},
};

/// 25 KB: a prefetch that lands in well under a second.
const SMALL: &str = "docker.io/library/hello-world@sha256:5e23090353324d887c48ad5e5c56d294eab81588df9605b07d1afe895f9cc8f8";
/// `python:3.12-slim`, 123 MB: a pull long enough to be caught mid-way.
const LARGE: &str = "docker.io/library/python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9";

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

fn digest(image: &str) -> &str {
    image.split_once('@').unwrap().1
}

fn exists(image: &str) -> bool {
    Command::new("podman")
        .args(["image", "exists", image])
        .status()
        .unwrap()
        .success()
}

/// Remove `image`, retrying briefly: other suites share the store and may
/// hold its lock for a moment.
fn remove(image: &str) {
    for _ in 0..5 {
        let _ = Command::new("podman")
            .args(["rmi", "--force", image])
            .output();
        if !exists(image) {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("{image} could not be removed");
}

fn eventually(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn uncanceled() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// A hint lands the image through the real store: the prefetch pulls it,
/// records it held (what the profile then reports warm) and charges its
/// real size to the byte window; the attempt that then needs it finds it
/// without a download. The disk reserve was measured on podman's own
/// graph root.
#[test]
fn a_hinted_image_is_prefetched_and_the_attempt_finds_it_held() {
    if !enabled() {
        return;
    }
    remove(SMALL);
    let images = Images::new();
    let prefetcher = Prefetcher::new(images.clone(), Bounds::default(), PodmanProbe::new());
    prefetcher.hint(&[SMALL.to_owned()]);
    eventually("the prefetch", Duration::from_secs(180), || {
        prefetcher.stats().completed + prefetcher.stats().failed == 1
    });
    assert!(images.holds(digest(SMALL)));
    assert!(exists(SMALL));
    let stats = prefetcher.stats();
    assert_eq!((stats.started, stats.completed, stats.failed), (1, 1, 0));
    assert_eq!(stats.skipped_disk, 0, "the graph root had room");
    assert!(stats.window_used > 0, "the pulled size was charged");
    assert_eq!(
        Some(stats.window_used),
        podman::image_bytes(SMALL),
        "charged exactly what the store holds"
    );
    // The attempt's own pull: the store already has it.
    let present = images
        .pull(SMALL, podman::IMAGE_PULL_TIMEOUT, &uncanceled())
        .unwrap();
    assert!(present, "no download for the attempt");
    prefetcher.stop();
}

/// A hint that drops a reference kills its running `podman pull`: the pull
/// ends early, nothing is recorded held, and the store holds no image.
#[test]
fn a_stale_prefetch_kills_the_real_pull() {
    if !enabled() {
        return;
    }
    remove(LARGE);
    let images = Images::new();
    let prefetcher = Prefetcher::new(images.clone(), Bounds::default(), PodmanProbe::new());
    let started = Instant::now();
    prefetcher.hint(&[LARGE.to_owned()]);
    eventually("the pull under way", Duration::from_secs(30), || {
        prefetcher.running() == 1 && images.in_flight() == 1
    });
    thread::sleep(Duration::from_millis(300));
    prefetcher.hint(&[]);
    eventually("the kill", Duration::from_secs(30), || {
        prefetcher.stats().canceled == 1
    });
    eprintln!(
        "stale pull killed after {} ms",
        started.elapsed().as_millis()
    );
    assert_eq!(prefetcher.running(), 0);
    assert_eq!(images.in_flight(), 0);
    assert!(!images.holds(digest(LARGE)));
    assert!(!exists(LARGE), "a killed pull left no image");
    let ps = Command::new("pgrep")
        .args(["-f", &format!("podman pull -q -- {LARGE}")])
        .output()
        .unwrap();
    assert!(!ps.status.success(), "the pull process is gone");
    prefetcher.stop();
}

/// Measurement: the attempt-side pull of `LARGE` cold, then with the image
/// prefetched while the "job" was still queued. Three rounds.
#[test]
#[ignore = "measurement; needs the registry"]
fn prefetch_saves_the_attempt_pull() {
    if !enabled() {
        return;
    }
    for round in 0..3 {
        remove(LARGE);
        let images = Images::new();
        let started = Instant::now();
        let present = images
            .pull(LARGE, podman::IMAGE_PULL_TIMEOUT, &uncanceled())
            .unwrap();
        let cold = started.elapsed();
        assert!(!present);

        remove(LARGE);
        let images = Images::new();
        let prefetcher = Prefetcher::new(images.clone(), Bounds::default(), PodmanProbe::new());
        let hinted = Instant::now();
        prefetcher.hint(&[LARGE.to_owned()]);
        eventually("the prefetch", Duration::from_secs(600), || {
            images.holds(digest(LARGE))
        });
        let prefetch = hinted.elapsed();
        let started = Instant::now();
        let present = images
            .pull(LARGE, podman::IMAGE_PULL_TIMEOUT, &uncanceled())
            .unwrap();
        let warm = started.elapsed();
        assert!(present);
        eprintln!(
            "round {round}: attempt pull cold {} ms; prefetch {} ms in the background, then the attempt's pull {} ms",
            cold.as_millis(),
            prefetch.as_millis(),
            warm.as_millis()
        );
        prefetcher.stop();
    }
    remove(LARGE);
}
