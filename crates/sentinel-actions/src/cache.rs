//! The Actions cache service, as `@actions/cache` 4.0.0 calls it: a lookup over the client's key list,
//! a reserve, chunked uploads addressed by `Content-Range`, a commit, and a download of the archive the
//! lookup named.
//!
//! The client's `key` and `version` are the only things it tells the endpoint about itself, and neither
//! picks a scope: they name an entry *inside* the boundary the listener serves. That is why a fork's
//! job cannot reach a trusted entry even when it names the exact key the trusted job wrote — the trust
//! dimension is not part of the conversation, it is the listener.

use std::io;

use crate::{
    CACHE_HOST, SCHEMA, Scope,
    http::{Request, Response},
    store::{Lookup, MAX_KEY_BYTES, Store},
};

/// The path every cache call is under: `@actions/cache` builds `${ACTIONS_CACHE_URL}_apis/artifactcache/…`.
pub const PREFIX: &str = "/_apis/artifactcache/";

/// The most keys one lookup may name: the pinned client sends its primary key and its restore keys.
const MAX_KEYS: usize = 16;

pub fn serve<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Response {
    let method = request.method.clone();
    let Some(rest) = request.path.strip_prefix(PREFIX).map(str::to_owned) else {
        return refuse(request, "not_implemented");
    };
    let route = rest.as_str();
    match (method.as_str(), route) {
        ("GET", "cache") => lookup(request, scope, store),
        ("GET", "caches") => list(request, scope, store),
        ("POST", "caches") => reserve(request, scope, store),
        ("PATCH", rest) if rest.starts_with("caches/") => chunk(request, scope, store, rest),
        ("POST", rest) if rest.starts_with("caches/") => commit(request, scope, store, rest),
        ("GET", rest) if rest.starts_with("archive/") => archive(request, scope, store, rest),
        // A method the service does not answer is refused rather than passed anywhere: `cache` is a
        // lookup, and a `POST` to it is a client this endpoint does not serve.
        (_, route) if is_route(route) => Response::json(
            405,
            &refusal_body("method_not_implemented", Some(&request.path)),
        ),
        _ => refuse(request, "not_implemented"),
    }
}

/// Whether a path is one of the service's, so a wrong method is `405` rather than `404`.
fn is_route(rest: &str) -> bool {
    rest == "cache"
        || rest == "caches"
        || rest.starts_with("caches/")
        || rest.starts_with("archive/")
}

pub fn refuse<S: io::Read + io::Write>(request: &mut Request<'_, S>, why: &str) -> Response {
    let _ = request.body.discard();
    Response::json(404, &refusal_body(why, Some(&request.path)))
}

pub fn refusal_body(why: &str, path: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "schema": SCHEMA,
        "refusal": why,
        "forwarded": false,
    });
    if let Some(path) = path {
        body["path"] = serde_json::Value::String(path.to_owned());
    }
    body
}

/// `GET cache?keys=a,b&version=v`: the first of the client's keys this boundary holds, or `204`.
fn lookup<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Response {
    let (Some(keys), Some(version)) = (request.param("keys"), request.param("version")) else {
        return Response::json(400, &refusal_body("missing_key_or_version", None));
    };
    if keys.len() > MAX_KEYS * MAX_KEY_BYTES || version.len() > super::store::MAX_VERSION_BYTES {
        return Response::json(400, &refusal_body("bounds", None));
    }
    let keys: Vec<&str> = keys
        .split(',')
        .filter(|key| !key.is_empty())
        .take(MAX_KEYS)
        .collect();
    let _ = request.body.discard();
    for key in keys {
        if let Lookup::Hit(archive) = store.lookup(scope, key, &version) {
            let location = store.archive_name(scope, key, &version, &generation_of(&archive.path));
            return Response::json(
                200,
                &serde_json::json!({
                    "cacheKey": key,
                    "archiveLocation": format!("https://{CACHE_HOST}{location}"),
                }),
            );
        }
    }
    Response::new(204)
}

/// The generation an archive path names, taken from its directory: the location is built from what was
/// actually read, never from a pointer a later save could move.
fn generation_of(path: &std::path::Path) -> String {
    path.parent()
        .and_then(|dir| dir.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `GET caches?key=…`: the diagnostics listing the pinned client reads when a lookup misses in debug
/// mode. It answers this boundary's entries for the key prefix only.
fn list<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Response {
    let key = request.param("key").unwrap_or_default();
    let _ = request.body.discard();
    let entries: Vec<serde_json::Value> = store
        .keys(scope)
        .into_iter()
        .filter(|(entry, _, _, _)| entry == &key || entry.starts_with(&format!("{key}-")))
        .map(|(key, version, bytes, sealed_ms)| {
            serde_json::json!({
                "cacheKey": key,
                "cacheVersion": version,
                "scope": format!("refs/{}", scope.trust.as_str()),
                "creationTime": sealed_ms,
                "size": bytes,
            })
        })
        .collect();
    let total = entries.len();
    Response::json(
        200,
        &serde_json::json!({ "totalCount": total, "artifactCaches": entries }),
    )
}

/// `POST caches {key, version, cacheSize?}`: opens an upload and answers its id.
fn reserve<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Response {
    let body = match request.body.read_all(crate::http::MAX_JSON_BODY) {
        Ok(body) => body,
        Err(_) => return Response::json(413, &refusal_body("body", None)),
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Response::json(400, &refusal_body("json", None));
    };
    let (Some(key), Some(version)) = (
        value.get("key").and_then(|v| v.as_str()),
        value.get("version").and_then(|v| v.as_str()),
    ) else {
        return Response::json(400, &refusal_body("missing_key_or_version", None));
    };
    match store.reserve(scope, key, version) {
        Ok(id) => Response::json(200, &serde_json::json!({ "cacheId": id })),
        Err(_) => Response::json(400, &refusal_body("key", None)),
    }
}

/// `PATCH caches/{id}` with `Content-Range: bytes <start>-<end>/*`: writes the chunk where its range
/// says, because the pinned client uploads several at once.
fn chunk<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
    rest: &str,
) -> Response {
    let Some(id) = rest.strip_prefix("caches/").and_then(parse_id) else {
        return Response::json(404, &refusal_body("unknown_upload", Some(&request.path)));
    };
    let Some(offset) = request.header("content-range").and_then(range_start) else {
        let _ = request.body.discard();
        return Response::json(411, &refusal_body("missing_content_range", None));
    };
    let mut at = offset;
    let streamed = request.body.stream(|bytes| {
        store
            .chunk(id, at, bytes, scope)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        at += bytes.len() as u64;
        Ok(())
    });
    match streamed {
        Ok(_) => Response::new(204),
        Err(_) => Response::json(413, &refusal_body("chunk", None)),
    }
}

/// `POST caches/{id} {size}`: seals the upload, and only then does the entry serve.
fn commit<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
    rest: &str,
) -> Response {
    let Some(id) = rest.strip_prefix("caches/").and_then(parse_id) else {
        return Response::json(404, &refusal_body("unknown_upload", Some(&request.path)));
    };
    let body = match request.body.read_all(crate::http::MAX_JSON_BODY) {
        Ok(body) => body,
        Err(_) => return Response::json(413, &refusal_body("body", None)),
    };
    let size = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("size").and_then(|v| v.as_u64()));
    let Some(size) = size else {
        return Response::json(400, &refusal_body("missing_size", None));
    };
    match store.commit(id, size, scope) {
        Ok(()) => Response::new(204),
        Err(_) => Response::json(409, &refusal_body("commit", None)),
    }
}

/// `GET archive/<repo>/<trust>/<platform>/<key16>/<version16>/<gen>`: the bytes the lookup named, if the
/// manifest admits this sandbox.
fn archive<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
    rest: &str,
) -> Response {
    let _ = request.body.discard();
    let Some(named) = rest.strip_prefix("archive/") else {
        return Response::json(404, &refusal_body("not_implemented", Some(&request.path)));
    };
    let parts: Vec<&str> = named.split('/').collect();
    let [repo, trust, platform, key16, version16, generation] = parts[..] else {
        return Response::json(404, &refusal_body("unknown_archive", Some(&request.path)));
    };
    match store.archive_at(scope, [repo, trust, platform, key16, version16, generation]) {
        Some(archive) => Response::file(200, archive.path, archive.bytes)
            .header("Content-Type", "application/octet-stream"),
        None => Response::json(404, &refusal_body("unknown_archive", Some(&request.path))),
    }
}

fn parse_id(text: &str) -> Option<u64> {
    text.split('/').next().and_then(|id| id.parse::<u64>().ok())
}

/// The start offset of `bytes <start>-<end>/*`; a range this endpoint cannot place is none.
pub fn range_start(value: &str) -> Option<u64> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (start, end) = rest.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.split('/').next()?.trim().parse::<u64>().ok()?;
    (end >= start).then_some(start)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{Scope, store::Store};
    use sentinel_core::{RepoId, TenantId};
    use sentinel_protocol::{cache::Trust, negotiate::Arch};

    fn scope(trust: Trust) -> Scope {
        Scope::new(TenantId::new(), RepoId::new(), trust, Arch::X86_64)
    }

    fn body_of(response: &Response) -> serde_json::Value {
        match &response.body {
            crate::http::Payload::Bytes(bytes) => {
                serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null)
            }
            _ => serde_json::Value::Null,
        }
    }

    fn one(store: &Store, scope: &Scope, raw: &[u8]) -> (u16, serde_json::Value) {
        let mut conn = crate::http::Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let mut request = Request::parse(&mut conn, &head).unwrap();
        let response = serve(&mut request, scope, store);
        let value = body_of(&response);
        (response.status, value)
    }

    /// The pinned client's whole save path, in its own wire shape: reserve, two concurrent chunks, then
    /// a commit; then the lookup that must name the sealed generation and the download that serves it.
    #[test]
    fn the_clients_save_and_restore_round_trip_through_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let protected = scope(Trust::Protected);

        let reserve = "{\"key\":\"cargo-main\",\"version\":\"abc\",\"cacheSize\":8}";
        let raw = format!(
            "POST /_apis/artifactcache/caches HTTP/1.1\r\nContent-Length: {}\r\n\r\n{reserve}",
            reserve.len()
        );
        let (status, reserved) = one(&store, &protected, raw.as_bytes());
        assert_eq!(status, 200);
        let id = reserved["cacheId"].as_u64().unwrap();

        let patch = |start: u64, end: u64, chunk: &str| {
            format!(
                "PATCH /_apis/artifactcache/caches/{id} HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {start}-{end}/*\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
                chunk.len()
            )
        };
        assert_eq!(
            one(&store, &protected, patch(4, 7, "EFGH").as_bytes()).0,
            204
        );
        assert_eq!(
            one(&store, &protected, patch(0, 3, "ABCD").as_bytes()).0,
            204
        );
        let commit = format!(
            "POST /_apis/artifactcache/caches/{id} HTTP/1.1\r\nContent-Length: 10\r\n\r\n{{\"size\":8}}"
        );
        assert_eq!(one(&store, &protected, commit.as_bytes()).0, 204);

        let lookup = b"GET /_apis/artifactcache/cache?keys=cargo-main%2Cfallback&version=abc HTTP/1.1\r\n\r\n";
        let (status, body) = one(&store, &protected, lookup);
        assert_eq!(status, 200);
        assert_eq!(body["cacheKey"], "cargo-main");
        let location = body["archiveLocation"].as_str().unwrap();
        assert!(
            location.starts_with(&format!(
                "https://{CACHE_HOST}/_apis/artifactcache/archive/"
            )),
            "{location}"
        );
        let path = location
            .strip_prefix(&format!("https://{CACHE_HOST}"))
            .unwrap();
        let raw = format!("GET {path} HTTP/1.1\r\n\r\n");
        let mut conn = crate::http::Conn::new(Cursor::new(raw.into_bytes()));
        let head = conn.head().unwrap().unwrap();
        let mut request = Request::parse(&mut conn, &head).unwrap();
        let response = serve(&mut request, &protected, &store);
        assert_eq!(response.status, 200);
        match response.body {
            crate::http::Payload::File { path, len } => {
                assert_eq!(len, 8);
                assert_eq!(std::fs::read(path).unwrap(), b"ABCDEFGH");
            }
            _ => panic!("the archive was not served as a file"),
        }
    }

    #[test]
    fn a_miss_is_204_and_another_trusts_entry_is_invisible_even_at_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let protected = scope(Trust::Protected);
        let pull = Scope {
            trust: Trust::PullRequest,
            ..protected
        };
        let id = store.reserve(&protected, "key", "v").unwrap();
        store.chunk(id, 0, b"trusted", &protected).unwrap();
        store.commit(id, 7, &protected).unwrap();
        let lookup = b"GET /_apis/artifactcache/cache?keys=key&version=v HTTP/1.1\r\n\r\n";
        assert_eq!(one(&store, &protected, lookup).0, 200);
        assert_eq!(one(&store, &pull, lookup).0, 204);
    }

    #[test]
    fn an_unimplemented_call_is_refused_and_never_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let protected = scope(Trust::Protected);
        for raw in [
            &b"GET /_apis/artifactcache/twunks HTTP/1.1\r\n\r\n"[..],
            b"POST /twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            b"CONNECT artifactcache.actions.githubusercontent.com:443 HTTP/1.1\r\n\r\n",
        ] {
            let (status, body) = one(&store, &protected, raw);
            assert_eq!(status, 404, "{}", String::from_utf8_lossy(raw));
            assert_eq!(body["refusal"], "not_implemented");
            assert_eq!(body["forwarded"], false);
            assert_eq!(body["schema"], "sentinel.actions/1");
        }
        // A method the service does know on a path it does know is `405`, not a refusal of the path.
        let (status, body) = one(
            &store,
            &protected,
            b"POST /_apis/artifactcache/cache HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            (status, body["refusal"].as_str()),
            (405, Some("method_not_implemented"))
        );
    }

    #[test]
    fn a_content_range_is_read_as_the_client_spells_it() {
        assert_eq!(range_start("bytes 0-199/*"), Some(0));
        assert_eq!(range_start("bytes 200-399/*"), Some(200));
        assert_eq!(range_start("bytes 0-7/8"), Some(0));
        assert_eq!(range_start("chunks 0-1/*"), None);
        assert_eq!(range_start("bytes 9-2/*"), None);
    }
}
