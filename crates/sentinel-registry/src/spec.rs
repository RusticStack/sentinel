//! What the endpoint understands, decided before anything is looked up or fetched.
//!
//! The read half of the OCI distribution API is: `/v2/` for the API check, a manifest by tag or by
//! digest, a blob by digest, `GET` and `HEAD` on each. This module turns a request path into one of
//! those or a refusal. Nothing else is parsed into a shape that could reach an upstream: a push, a
//! catalog listing, a tag listing or an upload is answered here and never forwarded.

const MAX_PATH_BYTES: usize = 2048;
const MAX_SEGMENTS: usize = 40;
const MAX_REPO_BYTES: usize = 255;
const MAX_TAG_BYTES: usize = 128;

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[(byte >> 4) as usize]));
        text.push(char::from(HEX[(byte & 0xf) as usize]));
    }
    text
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Digest(pub(crate) [u8; 32]);

impl Digest {
    pub(crate) fn parse(text: &str) -> Option<Digest> {
        let hex = text.strip_prefix("sha256:")?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Digest(bytes))
    }

    pub(crate) fn hex(self) -> String {
        hex_bytes(&self.0)
    }

    /// The digest of `bytes`, the reference the upstream and the client both compute.
    pub(crate) fn of(bytes: &[u8]) -> Digest {
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(bytes);
        Digest::of_finished(&hasher)
    }

    pub(crate) fn of_finished(hasher: &ring::digest::Context) -> Digest {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hasher.clone().finish().as_ref());
        Digest(digest)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reference<'a> {
    Tag(&'a str),
    Digest(Digest),
}

impl Reference<'_> {
    pub(crate) fn text(self) -> String {
        match self {
            Reference::Tag(tag) => tag.to_owned(),
            Reference::Digest(digest) => digest.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route<'a> {
    /// `/v2/`: the API check a client makes before it resolves anything.
    Ping,
    Manifest {
        token: &'a str,
        host: &'a str,
        repo: &'a str,
        reference: Reference<'a>,
    },
    Blob {
        token: &'a str,
        host: &'a str,
        repo: &'a str,
        digest: Digest,
    },
    /// A shape this endpoint does not implement, answered with `why` and `status` instead of forwarded.
    Refused { why: &'static str, status: u16 },
}

fn refused(why: &'static str) -> Route<'static> {
    Route::Refused { why, status: 404 }
}

fn unsupported(why: &'static str) -> Route<'static> {
    Route::Refused { why, status: 405 }
}

pub(crate) fn route(path: &str) -> Route<'_> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.len() > MAX_PATH_BYTES {
        return refused("the request path is too long");
    }
    let Some(rest) = path.strip_prefix('/') else {
        return refused("a request path starts with /");
    };
    if rest == "v2" || rest == "v2/" {
        return Route::Ping;
    }
    let Some(rest) = rest.strip_prefix("v2/") else {
        return refused("only the /v2 distribution API is served");
    };
    if rest.bytes().any(|b| !b.is_ascii_graphic()) {
        return refused("the request path carries a byte a reference cannot hold");
    }
    let mut segments = [""; MAX_SEGMENTS];
    let mut count = 0usize;
    for segment in rest.split('/') {
        if count == MAX_SEGMENTS {
            return refused("the request path has too many components");
        }
        if segment.is_empty() {
            return refused("the request path has an empty component");
        }
        segments[count] = segment;
        count += 1;
    }
    if count < 4 {
        return refused(
            "a request names <scope>/<registry>/<repository>/<manifests|blobs>/<reference>",
        );
    }
    let (token, host) = (segments[0], segments[1]);
    if token.len() > 64 || !token.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return refused("the scope component is not a scope");
    }
    if !valid_segment(host) {
        return refused("the registry component is not a registry the cache can name");
    }
    let (kind, last) = (segments[count - 2], segments[count - 1]);
    // The repository is every component between the registry host and the verb, taken as one slice of
    // the request path: no copy, and nothing a joined string could differ from.
    let start = segments[2].as_ptr() as usize - path.as_ptr() as usize;
    let tail = segments[count - 3];
    let end = tail.as_ptr() as usize - path.as_ptr() as usize + tail.len();
    let repo = &path[start..end];
    if !valid_repo(repo) {
        return refused("the repository name is not a valid reference path");
    }
    match kind {
        "manifests" => {
            let reference = match Digest::parse(last) {
                Some(digest) => Reference::Digest(digest),
                None if valid_tag(last) => Reference::Tag(last),
                None => {
                    return refused("the manifest reference is neither a tag nor a sha256 digest");
                }
            };
            Route::Manifest {
                token,
                host,
                repo,
                reference,
            }
        }
        "blobs" => match Digest::parse(last) {
            Some(digest) => Route::Blob {
                token,
                host,
                repo,
                digest,
            },
            None if last == "uploads" => unsupported("the cache does not accept pushes"),
            None => refused("a blob is named by a sha256 digest"),
        },
        "uploads" => unsupported("the cache does not accept pushes"),
        _ => refused("only manifests and blobs are served"),
    }
}

/// A registry as the mirror path spells it: a host name, and `_` where a port's colon would be.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 253
        && segment.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
        && !segment.starts_with('.')
        && !segment.starts_with('-')
        && !segment.starts_with('_')
}

fn valid_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TAG_BYTES {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn valid_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > MAX_REPO_BYTES {
        return false;
    }
    repo.split('/').all(|part| {
        let bytes = part.as_bytes();
        if bytes.is_empty() || part == "." || part == ".." {
            return false;
        }
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return false;
        }
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            return false;
        }
        bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn repo_of(path: &str) -> Option<String> {
        match route(path) {
            Route::Manifest { repo, .. } | Route::Blob { repo, .. } => Some(repo.to_owned()),
            _ => None,
        }
    }

    #[test]
    fn the_api_check_and_the_three_read_surfaces_are_routed() {
        for path in ["/v2", "/v2/", "/v2/?x=1"] {
            assert_eq!(route(path), Route::Ping, "{path}");
        }
        let path = format!("/v2/{TOKEN}/docker.io/library/busybox/manifests/1.36");
        assert!(matches!(
            route(&path),
            Route::Manifest {
                reference: Reference::Tag("1.36"),
                ..
            }
        ));
        let digest = format!("sha256:{}", "a".repeat(64));
        let path = format!("/v2/{TOKEN}/ghcr.io/acme/app/manifests/{digest}");
        assert!(matches!(
            route(&path),
            Route::Manifest {
                reference: Reference::Digest(_),
                host: "ghcr.io",
                ..
            }
        ));
        let path = format!("/v2/{TOKEN}/ghcr.io/acme/app/blobs/{digest}");
        assert!(matches!(route(&path), Route::Blob { digest: d, .. } if d.hex() == "a".repeat(64)));
        assert_eq!(
            repo_of(&format!(
                "/v2/{TOKEN}/docker.io/library/busybox/manifests/1.36"
            ))
            .as_deref(),
            Some("library/busybox")
        );
        assert_eq!(
            repo_of(&format!("/v2/{TOKEN}/ghcr.io/a/b/c/manifests/latest")).as_deref(),
            Some("a/b/c")
        );
        let path = format!("/v2/{TOKEN}/docker.io/a/b/c/manifests/latest");
        let Route::Manifest { host, repo, .. } = route(&path) else {
            panic!("routed to {:?}", route(&path));
        };
        assert_eq!((host, repo), ("docker.io", "a/b/c"));
    }

    #[test]
    fn everything_else_is_refused_rather_than_forwarded() {
        let digest = format!("sha256:{}", "a".repeat(64));
        for path in [
            "/".to_owned(),
            "/v3/".to_owned(),
            format!("/v2/{TOKEN}/docker.io/library/busybox/tags/list"),
            format!("/v2/{TOKEN}/docker.io/library/busybox/blobs/uploads/"),
            format!("/v2/{TOKEN}/docker.io/library/busybox/blobs/uploads/uuid"),
            format!("/v2/{TOKEN}/docker.io/library/busybox/_catalog"),
            format!("/v2/{TOKEN}/docker.io/Library/busybox/manifests/1.36"),
            format!("/v2/{TOKEN}/docker.io/library/busybox/manifests/tag:with:colons"),
            format!(
                "/v2/{TOKEN}/docker.io/library/busybox/blobs/sha256:{}",
                "a".repeat(63)
            ),
            format!(
                "/v2/{TOKEN}/docker.io/library/busybox/manifests/sha256:{}",
                "A".repeat(64)
            ),
            format!("/v2/../docker.io/library/busybox/blobs/{digest}"),
            format!("/v2/{TOKEN}/docker.io/../../etc/blobs/{digest}"),
            "/v2/".to_owned() + &"a".repeat(3000),
        ] {
            assert!(
                matches!(route(&path), Route::Refused { .. }),
                "{path} routed to {:?}",
                route(&path)
            );
        }
        assert!(matches!(
            route(&format!(
                "/v2/{TOKEN}/docker.io/library/busybox/blobs/uploads"
            )),
            Route::Refused { status: 405, .. }
        ));
        assert!(matches!(
            route(&format!("/v2/{TOKEN}/docker.io/library/busybox/uploads/u1")),
            Route::Refused { status: 405, .. }
        ));
    }

    #[test]
    fn a_digest_is_only_sha256_with_sixty_four_lower_case_hex() {
        assert!(Digest::parse(&format!("sha256:{}", "f".repeat(64))).is_some());
        for text in [
            format!("sha256:{}", "F".repeat(64)),
            format!("sha512:{}", "f".repeat(64)),
            format!("sha256:{}", "f".repeat(63)),
            "sha256:".to_owned(),
        ] {
            assert!(Digest::parse(&text).is_none(), "{text}");
        }
        assert_eq!(
            Digest::parse(&format!("sha256:{}", "f".repeat(64)))
                .unwrap()
                .hex(),
            "f".repeat(64)
        );
    }

    #[test]
    fn a_repository_never_escapes_its_prefix() {
        for repo in ["library/busybox", "a", "a/b-c_d.e", "x1/y2"] {
            assert!(valid_repo(repo), "{repo}");
        }
        for repo in [
            "", "/a", "a/", "a//b", "../a", "a/../b", "A", "a b", "-a", "a-", "a/./b",
        ] {
            assert!(!valid_repo(repo), "{repo}");
        }
    }
}
