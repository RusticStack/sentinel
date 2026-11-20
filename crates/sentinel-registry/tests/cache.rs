//! Real requests against a real upstream registry double: the cache listens on a loopback port, the
//! upstream is a second loopback listener serving real bytes, and every case counts what reached the
//! upstream. Nothing here calls an internal function where a pull would: the path taken is the one
//! containers/image takes — `/v2/` check, manifests, blobs — with the same headers.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

#[path = "support/upstream.rs"]
mod upstream;
use upstream::{Upstream, hex, image, sha256};

use sentinel_protocol::cache::Trust;
use sentinel_registry::{PullThrough, Scope, Settings};

const TENANT: [u8; 16] = [0x5a; 16];

// ---------------------------------------------------------------- the client

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// True only when the body arrived whole: a declared length was met, or the chunked stream ended.
    complete: bool,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn get(addr: SocketAddr, path: &str) -> Reply {
    request(addr, "GET", path, &[])
}

fn request(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)]) -> Reply {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nhost: cache\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a response head");
    let text = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = raw[split + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    if chunked {
        let (body, complete) = unchunk(&body);
        return Reply {
            status,
            headers,
            body,
            complete,
        };
    }
    let declared: Option<usize> = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok());
    let complete = match declared {
        Some(declared) => body.len() == declared,
        None => true,
    };
    Reply {
        status,
        headers,
        body,
        complete,
    }
}

fn unchunk(mut raw: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(end) = raw.windows(2).position(|window| window == b"\r\n") else {
            return (body, false);
        };
        let Ok(size) = usize::from_str_radix(String::from_utf8_lossy(&raw[..end]).trim(), 16)
        else {
            return (body, false);
        };
        raw = &raw[end + 2..];
        if size == 0 {
            return (body, raw.starts_with(b"\r\n"));
        }
        if raw.len() < size + 2 {
            return (body, false);
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

// ---------------------------------------------------------------- the cache under test

struct Cache {
    cache: PullThrough,
    addr: SocketAddr,
    dir: std::path::PathBuf,
}

impl Cache {
    fn start(dir: &Path, budget: u64, upstream: &Upstream) -> Cache {
        let cache =
            PullThrough::open(Settings::new(dir, budget, vec![upstream.registry()])).unwrap();
        let addr = cache.start().unwrap();
        Cache {
            cache,
            addr,
            dir: dir.to_path_buf(),
        }
    }

    /// The mirror location for a scope, read back from the configuration a pull would be given: this is
    /// where containers/image sends the request, so the tests go there too.
    fn mirror(&self, scope: Scope) -> String {
        let path = self.cache.mirror_conf(scope).unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let line = text
            .lines()
            .skip_while(|line| *line != "[[registry.mirror]]")
            .skip(1)
            .find(|line| line.starts_with("location = \""))
            .expect("a mirror location");
        line.trim_start_matches("location = \"")
            .trim_end_matches('"')
            .to_owned()
    }

    /// The request path containers/image builds from a mirror location: the location's path becomes the
    /// first components of the repository, and its address stays out of the path.
    fn path(&self, scope: Scope, rest: &str) -> String {
        let mirror = self.mirror(scope);
        let path = mirror.split_once('/').map(|(_, path)| path).unwrap_or("");
        format!("/v2/{path}/{rest}")
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Everything the cache wrote, as one string, to prove no credential was kept.
    fn files(&self) -> String {
        let mut all = String::new();
        collect(&self.dir, &mut all);
        all
    }
}

fn collect(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
}

fn pull(cache: &Cache, scope: Scope, repo: &str, reference: &str) -> Reply {
    get(
        cache.addr(),
        &cache.path(scope, &format!("{repo}/manifests/{reference}")),
    )
}

fn pull_blob(cache: &Cache, scope: Scope, repo: &str, digest: &str) -> Reply {
    get(
        cache.addr(),
        &cache.path(scope, &format!("{repo}/blobs/{digest}")),
    )
}

// ---------------------------------------------------------------- the cases

#[test]
fn a_first_pull_populates_and_a_second_pull_of_the_same_digest_fetches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let image = image(&upstream, "1.0", 1, 4096);

    let first = pull(&cache, Scope::Anonymous, "library/app", &image.digest);
    assert_eq!(first.status, 200, "{first:?}");
    assert_eq!(first.body, image.manifest);
    assert!(first.complete);
    for (digest, bytes) in &image.blobs {
        let reply = pull_blob(&cache, Scope::Anonymous, "library/app", digest);
        assert_eq!(reply.status, 200, "{reply:?}");
        assert_eq!(&reply.body, bytes);
        assert!(reply.complete);
    }
    let after_first = upstream.requests();
    assert_eq!(
        after_first,
        3,
        "one manifest and two blobs: {:?}",
        upstream.paths()
    );

    let second = pull(&cache, Scope::Anonymous, "library/app", &image.digest);
    assert_eq!(second.body, image.manifest);
    for (digest, bytes) in &image.blobs {
        let reply = pull_blob(&cache, Scope::Anonymous, "library/app", digest);
        assert_eq!(&reply.body, bytes);
    }
    assert_eq!(
        upstream.requests(),
        after_first,
        "the second pull of the same digest reached the upstream: {:?}",
        upstream.paths()
    );

    // A tag inside its revalidation window is answered from disk as well.
    let tagged = pull(&cache, Scope::Anonymous, "library/app", "1.0");
    assert_eq!(tagged.body, image.manifest);
    assert_eq!(
        upstream.requests(),
        after_first + 1,
        "the tag itself was fetched once"
    );
    let tagged_again = pull(&cache, Scope::Anonymous, "library/app", "1.0");
    assert_eq!(tagged_again.body, image.manifest);
    assert_eq!(
        upstream.requests(),
        after_first + 1,
        "a fresh tag record answers from disk"
    );
    assert_eq!(
        tagged.header("docker-content-digest"),
        Some(image.digest.as_str())
    );
}

#[test]
fn a_mutable_tag_is_revalidated_after_its_ttl_while_a_digest_never_is() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let mut settings = Settings::new(dir.path(), 64 << 20, vec![upstream.registry()]);
    settings.tag_ttl = Duration::from_millis(150);
    let cache = PullThrough::open(settings).unwrap();
    let addr = cache.start().unwrap();
    let cache = Cache {
        cache,
        addr,
        dir: dir.path().to_path_buf(),
    };
    let first = image(&upstream, "latest", 2, 256);

    assert_eq!(
        pull(&cache, Scope::Anonymous, "library/app", "latest").body,
        first.manifest
    );
    let after_first = upstream.requests();
    assert_eq!(
        pull(&cache, Scope::Anonymous, "library/app", "latest").body,
        first.manifest
    );
    assert_eq!(
        upstream.requests(),
        after_first,
        "inside the window the tag is not revalidated"
    );

    // The tag moves to another image while the record is still inside its window.
    let second = image(&upstream, "latest", 3, 256);
    std::thread::sleep(Duration::from_millis(250));
    let revalidated = pull(&cache, Scope::Anonymous, "library/app", "latest");
    assert_eq!(
        upstream.requests(),
        after_first + 1,
        "the stale tag was revalidated"
    );
    assert_eq!(
        revalidated.body, second.manifest,
        "the revalidation serves what the tag names now"
    );
    assert_eq!(
        revalidated.header("docker-content-digest"),
        Some(second.digest.as_str())
    );

    // The manifest the tag used to name is still cached by digest, and a digest is never revalidated.
    let by_digest = pull(&cache, Scope::Anonymous, "library/app", &first.digest);
    assert_eq!(by_digest.body, first.manifest);
    let after_digest = upstream.requests();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        pull(&cache, Scope::Anonymous, "library/app", &first.digest).body,
        first.manifest
    );
    assert_eq!(
        upstream.requests(),
        after_digest,
        "an immutable digest is never revalidated"
    );
}

#[test]
fn a_corrupted_blob_is_never_served_and_the_next_pull_fetches_it_again() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let image = image(&upstream, "1.0", 4, 8192);

    let (digest, bytes) = &image.blobs[1];
    let good = pull_blob(&cache, Scope::Anonymous, "library/app", digest);
    assert_eq!(&good.body, bytes);

    // Flip one byte of the stored copy in place: the length still matches, so only the digest can tell.
    let stored = find_blob(dir.path(), digest).expect("the stored blob");
    let mut corrupted = bytes.clone();
    corrupted[100] ^= 0xff;
    std::fs::write(&stored, &corrupted).unwrap();

    let served = pull_blob(&cache, Scope::Anonymous, "library/app", digest);
    assert!(
        served.status != 200 || !served.complete,
        "a corrupted blob was served as a complete response: {served:?}"
    );
    assert!(!stored.exists(), "the corrupted copy was left in place");

    let healed = pull_blob(&cache, Scope::Anonymous, "library/app", digest);
    assert_eq!(healed.status, 200);
    assert_eq!(&healed.body, bytes, "the next pull fetched the blob again");
    assert!(healed.complete);
}

#[test]
fn a_partial_blob_from_the_upstream_is_refused_and_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let bytes = vec![9u8; 4096];
    let digest = format!("sha256:{}", hex(&sha256(&bytes)));
    // The upstream stores a body that does not hash to the digest it answers for.
    upstream
        .state
        .blobs
        .lock()
        .unwrap()
        .insert(digest.clone(), vec![8u8; 4096]);

    let reply = pull_blob(&cache, Scope::Anonymous, "library/app", &digest);
    assert_ne!(reply.status, 200, "{reply:?}");
    assert_ne!(
        reply.body,
        vec![8u8; 4096],
        "the mismatched body was served"
    );
    assert!(
        find_blob(dir.path(), &digest).is_none(),
        "a body that does not match its digest was stored"
    );
}

#[test]
fn the_size_bound_refuses_a_pull_it_cannot_evict_for() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    // Two 40 MiB layers cannot both live in a 64 MiB cache, and both were served just now, so neither is
    // evictable: the second pull is refused rather than filling the disk.
    let first = image(&upstream, "1.0", 5, 40 << 20);
    let second = image(&upstream, "2.0", 6, 40 << 20);
    assert_eq!(
        pull_blob(&cache, Scope::Anonymous, "library/app", &first.blobs[1].0).status,
        200
    );
    let refused = pull_blob(&cache, Scope::Anonymous, "library/app", &second.blobs[1].0);
    assert_eq!(refused.status, 507, "{refused:?}");
    assert!(
        cache.cache.used_bytes() <= cache.cache.budget_bytes(),
        "{} of {}",
        cache.cache.used_bytes(),
        cache.cache.budget_bytes()
    );
    // The copy the first pull made is still intact and still served.
    let still_there = pull_blob(&cache, Scope::Anonymous, "library/app", &first.blobs[1].0);
    assert_eq!(still_there.body, first.blobs[1].1);
}

#[test]
fn the_size_bound_evicts_the_least_recently_served_layer_first() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let mut settings = Settings::new(dir.path(), 64 << 20, vec![upstream.registry()]);
    // A three-layer rotation cannot fit, so nothing may be pinned by the keep window here.
    settings.keep_window = Duration::from_secs(0);
    let cache = PullThrough::open(settings).unwrap();
    let addr = cache.start().unwrap();
    let cache = Cache {
        cache,
        addr,
        dir: dir.path().to_path_buf(),
    };
    let a = image(&upstream, "a", 10, 24 << 20);
    let b = image(&upstream, "b", 11, 24 << 20);
    let c = image(&upstream, "c", 12, 24 << 20);

    for image in [&a, &b] {
        let reply = pull_blob(&cache, Scope::Anonymous, "library/app", &image.blobs[1].0);
        assert_eq!(reply.status, 200, "{reply:?}");
    }
    // Serve `a` again: it is now the more recently used of the two.
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        pull_blob(&cache, Scope::Anonymous, "library/app", &a.blobs[1].0).body,
        a.blobs[1].1
    );
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        pull_blob(&cache, Scope::Anonymous, "library/app", &c.blobs[1].0).status,
        200
    );
    assert!(
        find_blob(dir.path(), &a.blobs[1].0).is_some(),
        "the layer served least recently was not the one evicted"
    );
    assert!(
        find_blob(dir.path(), &b.blobs[1].0).is_none(),
        "the least recently served layer survived the eviction"
    );
    assert!(find_blob(dir.path(), &c.blobs[1].0).is_some());
    assert!(cache.cache.used_bytes() <= cache.cache.budget_bytes());
}

#[test]
fn a_fork_pull_request_scope_never_reaches_a_protected_scope() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let protected = Scope::Tenant {
        tenant: TENANT,
        trust: Trust::Protected,
    };
    let fork = Scope::Tenant {
        tenant: TENANT,
        trust: Trust::PullRequest,
    };
    assert_ne!(cache.mirror(protected), cache.mirror(fork));

    let trusted_image = image(&upstream, "1.0", 13, 2048);
    let first = pull(&cache, fork, "library/app", &trusted_image.digest);
    assert_eq!(first.status, 200);
    assert_eq!(
        pull_blob(&cache, fork, "library/app", &trusted_image.blobs[1].0).status,
        200
    );
    let fork_blob = find_blob(dir.path(), &trusted_image.blobs[1].0).expect("the fork's own copy");
    assert!(
        fork_blob
            .to_string_lossy()
            .contains(&mirror_token(&cache.mirror(fork)))
    );

    // The protected scope is a different directory: it takes its own copy from the upstream.
    let before = upstream.requests();
    let trusted = pull(&cache, protected, "library/app", &trusted_image.digest);
    assert_eq!(trusted.body, trusted_image.manifest);
    assert_eq!(
        upstream.requests(),
        before + 1,
        "the protected scope fetched its own manifest"
    );

    // Whatever the fork scope ends up holding cannot change what the protected scope serves.
    let mut corrupted = trusted_image.blobs[1].1.clone();
    corrupted[0] ^= 0xff;
    std::fs::write(&fork_blob, &corrupted).unwrap();
    let trusted_blob = pull_blob(&cache, protected, "library/app", &trusted_image.blobs[1].0);
    assert_eq!(trusted_blob.body, trusted_image.blobs[1].1);
    assert!(trusted_blob.complete);

    // A tag poisoned through the fork's scope is not what the protected scope reads.
    let poisoned = image(&upstream, "latest", 14, 512);
    assert_eq!(
        pull(&cache, fork, "library/app", "latest").body,
        poisoned.manifest
    );
    let other = image(&upstream, "latest", 15, 512);
    assert_eq!(
        pull(&cache, protected, "library/app", "latest").body,
        other.manifest,
        "the protected scope read a tag the fork scope had already resolved"
    );

    // A token this worker never minted is not a scope at all.
    let stranger = format!("/v2/{}/library/app/manifests/latest", "ab".repeat(16));
    assert_eq!(get(cache.addr(), &stranger).status, 404);
    let _ = cache.files();
}

#[test]
fn a_private_registry_needs_the_pulls_own_credential_and_the_cache_keeps_none() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let secret = format!("Basic {}", hex(b"tenant:passw0rd"));
    upstream.require(Some(&secret));
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let scope = Scope::Tenant {
        tenant: TENANT,
        trust: Trust::Protected,
    };
    let image = image(&upstream, "1.0", 16, 1024);

    let denied = pull(&cache, scope, "library/app", &image.digest);
    assert_eq!(denied.status, 401, "{denied:?}");
    assert_eq!(
        denied.header("www-authenticate"),
        Some("Basic realm=\"test\""),
        "the upstream's challenge is relayed so the client authenticates itself"
    );
    assert!(
        find_blob(dir.path(), &image.blobs[0].0).is_none(),
        "a refused pull stored something"
    );

    let allowed = request(
        cache.addr(),
        "GET",
        &cache.path(scope, &format!("library/app/manifests/{}", image.digest)),
        &[("authorization", &secret)],
    );
    assert_eq!(allowed.status, 200, "{allowed:?}");
    assert_eq!(allowed.body, image.manifest);
    let after_allowed = upstream.requests();

    // The credential was used for that request and is nowhere on disk.
    let stored = cache.files();
    assert!(
        !stored.contains("passw0rd"),
        "the credential was written into the cache"
    );
    assert!(!stored.contains(&secret));

    // The tenant's own scope answers the repeat from disk, with no credential and no upstream request.
    let repeat = pull(&cache, scope, "library/app", &image.digest);
    assert_eq!(repeat.status, 200);
    assert_eq!(repeat.body, image.manifest);
    assert_eq!(upstream.requests(), after_allowed);
}

#[test]
fn a_range_read_names_one_slice_of_a_verified_blob() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let image = image(&upstream, "1.0", 17, 4096);
    let (digest, bytes) = &image.blobs[1];
    assert_eq!(
        pull_blob(&cache, Scope::Anonymous, "library/app", digest).status,
        200
    );

    let ranged = request(
        cache.addr(),
        "GET",
        &cache.path(Scope::Anonymous, &format!("library/app/blobs/{digest}")),
        &[("range", "bytes=10-19")],
    );
    assert_eq!(ranged.status, 206, "{ranged:?}");
    assert_eq!(ranged.body, bytes[10..=19].to_vec());
    assert_eq!(
        ranged.header("content-range"),
        Some(format!("bytes 10-19/{}", bytes.len()).as_str())
    );
    let unsatisfiable = request(
        cache.addr(),
        "GET",
        &cache.path(Scope::Anonymous, &format!("library/app/blobs/{digest}")),
        &[("range", &format!("bytes={}-", bytes.len()))],
    );
    assert_eq!(unsatisfiable.status, 416);
}

#[test]
fn head_answers_the_length_of_what_a_get_would_send() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let image = image(&upstream, "1.0", 18, 2048);
    let manifest_head = request(
        cache.addr(),
        "HEAD",
        &cache.path(
            Scope::Anonymous,
            &format!("library/app/manifests/{}", image.digest),
        ),
        &[],
    );
    assert_eq!(manifest_head.status, 200);
    assert!(manifest_head.body.is_empty());
    assert_eq!(
        manifest_head.header("content-length"),
        Some(image.manifest.len().to_string().as_str())
    );
    let blob_head = request(
        cache.addr(),
        "HEAD",
        &cache.path(
            Scope::Anonymous,
            &format!("library/app/blobs/{}", image.blobs[1].0),
        ),
        &[],
    );
    assert_eq!(blob_head.status, 200);
    assert!(blob_head.body.is_empty());
    assert_eq!(blob_head.header("content-length"), Some("2048"));
}

#[test]
fn the_endpoint_answers_only_the_surfaces_it_implements_and_forwards_none_of_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let cache = Cache::start(dir.path(), 64 << 20, &upstream);
    let mirror = cache.mirror(Scope::Anonymous);

    assert_eq!(get(cache.addr(), "/v2/").status, 200);
    assert_eq!(get(cache.addr(), "/v2").status, 200);

    let before = upstream.requests();
    for path in [
        format!("/v2/{mirror}/library/app/tags/list"),
        format!("/v2/{mirror}/library/app/blobs/uploads"),
        format!("/v2/{mirror}/library/app/manifests/tag:odd"),
        format!("/v2/{}/library/app/manifests/1.0", "ab".repeat(16)),
        format!("/v2/{mirror}/../etc/manifests/1.0"),
        "/v2".to_owned() + &"/x".repeat(4000),
    ] {
        let reply = get(cache.addr(), &path);
        assert!(
            (400..500).contains(&reply.status),
            "{path} answered {}",
            reply.status
        );
    }
    // A registry the worker does not cache is refused even with a valid scope token.
    let uncached = format!(
        "/v2/{}/ghcr.io/library/app/manifests/1.0",
        mirror_token(&mirror)
    );
    assert_eq!(get(cache.addr(), &uncached).status, 404);
    assert_eq!(
        upstream.requests(),
        before,
        "a refused request reached the upstream: {:?}",
        upstream.paths()
    );
}

// ---------------------------------------------------------------- helpers over the layout

/// The token is the first component of what a mirror location contributes to a repository name.
fn mirror_token(mirror: &str) -> String {
    mirror
        .split_once('/')
        .and_then(|(_, path)| path.split('/').next())
        .expect("a mirror location carries a token")
        .to_owned()
}

/// The file the cache stored for a digest, wherever it put it.
fn find_blob(root: &Path, digest: &str) -> Option<std::path::PathBuf> {
    let hex = digest.strip_prefix("sha256:")?;
    let mut found = None;
    search(&root.join("blobs"), &hex[2..], &mut found);
    found
}

fn search(dir: &Path, name: &str, found: &mut Option<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            search(&path, name, found);
        } else if path.file_name().and_then(|file| file.to_str()) == Some(name) {
            *found = Some(path);
        }
    }
}
