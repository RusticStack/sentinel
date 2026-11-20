//! The whole path with a real client: containers/image — the library Podman pulls with — resolves a
//! registry through the `registries.conf` the worker writes, and the pull lands on the cache.
//!
//! Gated on `SENTINEL_CONTAINERS_IMAGE_TESTS=1` because it needs a working `docker` and its skopeo
//! image; on a host without them the case reports its skip instead of passing silently. The upstream is
//! the loopback registry double from `support/`, so every request it answers is counted: the second copy
//! of the same digest must reach it zero times.
//!
//! `SENTINEL_SKOPEO_IMAGE` names the client image (default `quay.io/skopeo/stable:latest`).

use std::{path::Path, process::Command};

#[path = "support/upstream.rs"]
mod upstream;
use upstream::{Upstream, image};

use sentinel_registry::{PullThrough, Scope, Settings};

fn skip(why: &str) -> bool {
    eprintln!("skipped: {why}");
    true
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn copy(skopeo: &str, conf: &Path, reference: &str) -> std::result::Result<(), String> {
    let dir = conf.parent().expect("the configuration's directory");
    let output = Command::new("docker")
        .args(["run", "--rm", "--network", "host"])
        .arg("-e")
        .arg("CONTAINERS_REGISTRIES_CONF=/conf/registries.conf")
        .arg("-v")
        .arg(format!("{}:/conf:ro", dir.display()))
        .arg(skopeo)
        .args(["copy", "--retry-times", "0"])
        .arg(format!("docker://{reference}"))
        .arg("dir:/out")
        .output()
        .map_err(|error| format!("docker run: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "skopeo copy {reference} failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(600)
            .collect::<String>()
    ))
}

#[test]
fn a_real_containers_image_pull_lands_on_the_cache_and_the_second_one_fetches_nothing() {
    if std::env::var_os("SENTINEL_CONTAINERS_IMAGE_TESTS").is_none() {
        assert!(skip(
            "set SENTINEL_CONTAINERS_IMAGE_TESTS=1 on a host with docker to run this against skopeo"
        ));
        return;
    }
    if !docker_available() {
        assert!(skip("docker is not usable by this account"));
        return;
    }
    let skopeo = std::env::var("SENTINEL_SKOPEO_IMAGE")
        .unwrap_or_else(|_| "quay.io/skopeo/stable:latest".to_owned());

    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = PullThrough::open(Settings::new(
        dir.path().join("registry"),
        64 << 20,
        vec![upstream.registry()],
    ))
    .unwrap();
    cache.start().unwrap();
    let conf = cache.mirror_conf(Scope::Anonymous).unwrap();
    let built = image(&upstream, "1.0", 21, 256 << 10);
    let reference = format!("{}/library/app@{}", upstream.host(), built.digest);

    let cold = std::time::Instant::now();
    copy(&skopeo, &conf, &reference).expect("the first pull");
    let cold = cold.elapsed();
    let after_first = upstream.requests();
    assert!(
        after_first >= 3,
        "a cold pull asked the upstream for the manifest and its blobs: {:?}",
        upstream.paths()
    );
    assert!(
        cache.used_bytes() >= built.manifest.len() as u64,
        "the cache stored what the pull fetched"
    );

    let warm = std::time::Instant::now();
    copy(&skopeo, &conf, &reference).expect("the second pull");
    eprintln!(
        "cold pull {} ms over {after_first} upstream requests, warm pull {} ms over 0",
        cold.as_millis(),
        warm.elapsed().as_millis()
    );
    assert_eq!(
        upstream.requests(),
        after_first,
        "a warm pull reached the upstream: {:?}",
        upstream.paths()
    );

    // A tag goes through the same path and is answered from disk inside its window.
    let tagged = format!("{}/library/app:1.0", upstream.host());
    copy(&skopeo, &conf, &tagged).expect("the tagged pull");
    let after_tag = upstream.requests();
    copy(&skopeo, &conf, &tagged).expect("the second tagged pull");
    assert_eq!(
        upstream.requests(),
        after_tag,
        "a fresh tag record answered from disk: {:?}",
        upstream.paths()
    );

    // The credentialled path: the registry refuses anything but the tenant's own header, the cache
    // relays the refusal, and the pull carries the header through to it.
    let scoped = Scope::Tenant {
        tenant: [0x33; 16],
        trust: sentinel_protocol::cache::Trust::Protected,
    };
    let scoped_conf = cache.mirror_conf(scoped).unwrap();
    upstream.require(Some("Basic dGVzdDp0ZXN0"));
    let denied = copy(&skopeo, &scoped_conf, &reference);
    assert!(
        denied.is_err(),
        "a private pull without its credential succeeded"
    );
    let mut files = String::new();
    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                files.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    assert!(
        !files.contains("dGVzdDp0ZXN0"),
        "the credential was written into the cache"
    );
}
