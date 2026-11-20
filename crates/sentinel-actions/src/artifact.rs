//! The Actions artifact service, as `@actions/artifact` 2.0.1 calls it: four Twirp methods over JSON
//! and an Azure block-blob upload the service hands the client a signed URL for.
//!
//! The client's own idea of which run it belongs to is a string out of its token, and this endpoint
//! never uses it: the run and job an artifact is filed under are the lease's, carried to the sandbox
//! with its boundary. A job that names another run's backend id still writes into its own run — proven
//! in `a_client_that_names_another_run_writes_its_own` — and the signed URL it receives can only reach
//! a blob inside the boundary the listener serves.

use std::io;

use crate::{
    RESULTS_HOST, SCHEMA, Scope,
    http::{Payload, Request, Response},
    store::{ArtifactRow, Store},
};

/// The Twirp prefix the client builds from `ACTIONS_RESULTS_URL`: `/twirp/<service>/<method>`.
pub const TWIRP: &str = "/twirp/github.actions.results.api.v1.ArtifactService/";

/// Where the signed upload and download URLs point: the same results host the client already trusts.
pub const BLOB: &str = "/blob/";

pub fn serve<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Option<Response> {
    if let Some(method) = request.path.strip_prefix(TWIRP).map(str::to_owned) {
        let path = request.path.clone();
        return Some(rpc(request, scope, store, &method, &path));
    }
    if request.path.starts_with(BLOB) {
        return Some(blob(request, scope, store));
    }
    None
}

fn rpc<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
    method: &str,
    path: &str,
) -> Response {
    if request.method != "POST" {
        let _ = request.body.discard();
        return Response::json(
            405,
            &crate::cache::refusal_body("method_not_implemented", Some(path)),
        );
    }
    let body = match request.body.read_all(crate::http::MAX_JSON_BODY) {
        Ok(body) => body,
        Err(_) => return Response::json(413, &crate::cache::refusal_body("body", None)),
    };
    let value =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    match method {
        "CreateArtifact" => create(&value, scope, store),
        "FinalizeArtifact" => finalize(&value, scope, store),
        "ListArtifacts" => list(&value, scope, store),
        "GetSignedArtifactURL" => signed(&value, scope, store),
        _ => Response::json(
            404,
            &crate::cache::refusal_body("not_implemented", Some(path)),
        ),
    }
}

/// `CreateArtifact`: opens the upload and answers the URL the client's block uploader will speak to.
fn create(value: &serde_json::Value, scope: &Scope, store: &Store) -> Response {
    let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
        return Response::json(400, &crate::cache::refusal_body("missing_name", None));
    };
    match store.artifact_begin(scope, scope.run, scope.job, name) {
        Ok(id) => Response::json(
            200,
            &serde_json::json!({
                "ok": true,
                "signed_upload_url": format!("https://{RESULTS_HOST}{BLOB}{id}"),
            }),
        ),
        Err(_) => Response::json(400, &crate::cache::refusal_body("name", None)),
    }
}

/// `FinalizeArtifact`: seals the upload at the size the client states and answers the artifact's id.
fn finalize(value: &serde_json::Value, scope: &Scope, store: &Store) -> Response {
    let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
        return Response::json(400, &crate::cache::refusal_body("missing_name", None));
    };
    let size = value
        .get("size")
        .and_then(|v| match v {
            serde_json::Value::String(text) => text.parse::<u64>().ok(),
            serde_json::Value::Number(number) => number.as_u64(),
            _ => None,
        })
        .unwrap_or(0);
    let Some(id) = store.upload_of(scope, scope.run, name) else {
        return Response::json(404, &crate::cache::refusal_body("unknown_artifact", None));
    };
    match store.artifact_finalize(id, size, scope) {
        Ok(row) => Response::json(
            200,
            &serde_json::json!({ "ok": true, "artifact_id": row.id.to_string() }),
        ),
        Err(_) => Response::json(409, &crate::cache::refusal_body("finalize", None)),
    }
}

/// `ListArtifacts`: what this run has produced in this boundary, in job then name order, filtered by
/// the name or id the client asked for.
fn list(value: &serde_json::Value, scope: &Scope, store: &Store) -> Response {
    let name_filter = value.get("name_filter").and_then(|v| v.as_str());
    let id_filter = value
        .get("id_filter")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<u64>().ok());
    let mut rows: Vec<ArtifactRow> = store.artifacts(scope, scope.run);
    if let Some(name) = name_filter {
        rows.retain(|row| row.name == name);
    }
    if let Some(id) = id_filter {
        rows.retain(|row| row.id == id);
    }
    let artifacts: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "workflow_run_backend_id": scope.run.to_string(),
                "workflow_job_run_backend_id": scope.job.to_string(),
                "database_id": row.id.to_string(),
                "name": row.name,
                "size": row.bytes.to_string(),
                "created_at": row.sealed_ms,
            })
        })
        .collect();
    Response::json(200, &serde_json::json!({ "artifacts": artifacts }))
}

/// `GetSignedArtifactURL`: the URL a `download-artifact` step fetches the zip from.
fn signed(value: &serde_json::Value, scope: &Scope, store: &Store) -> Response {
    let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
        return Response::json(400, &crate::cache::refusal_body("missing_name", None));
    };
    if store
        .artifact_blob(scope, scope.run, &crate::store::slug(name))
        .is_none()
    {
        return Response::json(404, &crate::cache::refusal_body("unknown_artifact", None));
    }
    Response::json(
        200,
        &serde_json::json!({
            "signed_url": format!("https://{RESULTS_HOST}{BLOB}art/{}/{}/{}/{}",
                scope.repo, scope.trust.as_str(), scope.run, crate::store::slug(name)),
        }),
    )
}

/// The blob side: the client's block uploader (`comp=block`, `comp=blocklist`), a single-shot put, and
/// the download a `download-artifact` step performs.
fn blob<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
) -> Response {
    let path = request.path.clone();
    let rest = path[BLOB.len()..].to_owned();
    if let Some(download) = rest.strip_prefix("art/").map(str::to_owned) {
        return download_result(request, scope, store, &download);
    }
    let Some(id) = rest.split('/').next().and_then(|id| id.parse::<u64>().ok()) else {
        let _ = request.body.discard();
        return Response::json(
            404,
            &crate::cache::refusal_body("unknown_artifact", Some(&path)),
        );
    };
    let comp = request.param("comp");
    match (request.method.as_str(), comp.as_deref()) {
        ("PUT", Some("block")) => {
            let Some(blockid) = request.param("blockid") else {
                let _ = request.body.discard();
                return Response::json(400, &crate::cache::refusal_body("missing_blockid", None));
            };
            let staged = request.body.stream(|bytes| {
                store
                    .artifact_block(id, &blockid, bytes, scope)
                    .map(|_| ())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
            });
            match staged {
                Ok(_) => block_created(),
                Err(_) => Response::json(413, &crate::cache::refusal_body("block", None)),
            }
        }
        ("PUT", Some("blocklist")) => {
            let body = match request.body.read_all(crate::http::MAX_JSON_BODY) {
                Ok(body) => body,
                Err(_) => return Response::json(413, &crate::cache::refusal_body("body", None)),
            };
            let order = match store.block_order(id, scope, &body) {
                Some(order) => order,
                None => return Response::json(400, &crate::cache::refusal_body("blocklist", None)),
            };
            match store.artifact_blocks(id, &order, scope) {
                Ok(_) => block_created(),
                Err(_) => Response::json(413, &crate::cache::refusal_body("body", None)),
            }
        }
        // A body uploaded in one request (`x-ms-blob-type: BlockBlob`): one block, then committed.
        ("PUT", None) => {
            let staged = request.body.stream(|bytes| {
                store
                    .artifact_block(id, "single", bytes, scope)
                    .map(|_| ())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
            });
            match staged.and_then(|_| {
                store
                    .artifact_blocks(id, &[0], scope)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
            }) {
                Ok(_) => block_created(),
                Err(_) => Response::json(413, &crate::cache::refusal_body("body", None)),
            }
        }
        ("GET", _) => download_result(request, scope, store, &rest),
        ("HEAD", _) => {
            let _ = request.body.discard();
            Response::new(200).header("x-ms-blob-type", "BlockBlob")
        }
        (method, _) => {
            let _ = (method, request.body.discard());
            Response::json(
                405,
                &crate::cache::refusal_body("method_not_implemented", Some(&path)),
            )
        }
    }
}

fn download_result<S: io::Read + io::Write>(
    request: &mut Request<'_, S>,
    scope: &Scope,
    store: &Store,
    named: &str,
) -> Response {
    let _ = request.body.discard();
    let parts: Vec<&str> = named.split('/').collect();
    let [repo, trust, run, slug] = parts[..] else {
        return Response::json(
            404,
            &crate::cache::refusal_body("unknown_artifact", Some(&request.path)),
        );
    };
    let Ok(run) = run.parse::<u64>() else {
        return Response::json(
            404,
            &crate::cache::refusal_body("unknown_artifact", Some(&request.path)),
        );
    };
    if repo != scope.repo.to_string() || trust != scope.trust.as_str() {
        return Response::json(
            404,
            &crate::cache::refusal_body("unknown_artifact", Some(&request.path)),
        );
    }
    match store.artifact_blob(scope, run, slug) {
        Some((path, row)) => Response::file(200, path, row.bytes)
            .header("Content-Type", "application/zip")
            .header("x-ms-blob-type", "BlockBlob"),
        None => Response::json(
            404,
            &crate::cache::refusal_body("unknown_artifact", Some(&request.path)),
        ),
    }
}

/// What the Azure block uploader reads as a successful stage or commit: `201` with the headers its
/// deserializer requires, and no body.
fn block_created() -> Response {
    Response::new(201)
        .header("ETag", "\"0x8D0000000000000\"")
        .header("x-ms-request-server-encrypted", "true")
        .header("x-ms-version", "2021-12-02")
        .header("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT")
}

/// The refusal a path outside both services gets, with `SCHEMA` naming the contract.
pub fn refusal(path: &str) -> Response {
    let mut body = serde_json::json!({
        "schema": SCHEMA,
        "refusal": "not_implemented",
        "forwarded": false,
        "path": path,
    });
    body["path"] = serde_json::Value::String(path.to_owned());
    Response::json(404, &body)
}

pub fn is_payload(response: &Response) -> bool {
    matches!(response.body, Payload::File { .. })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::store::Store;
    use sentinel_core::{RepoId, TenantId};
    use sentinel_protocol::{cache::Trust, negotiate::Arch};

    fn scope(trust: Trust) -> Scope {
        Scope::with_job(TenantId::new(), RepoId::new(), trust, Arch::X86_64, 11, 22)
    }

    fn call(store: &Store, scope: &Scope, raw: &[u8]) -> (u16, Vec<u8>) {
        let mut conn = crate::http::Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let mut request = Request::parse(&mut conn, &head).unwrap();
        let response = crate::endpoint::dispatch(&mut request, Some(scope), store);
        let body = match &response.body {
            crate::http::Payload::Bytes(bytes) => bytes.clone(),
            crate::http::Payload::File { path, .. } => std::fs::read(path).unwrap(),
        };
        (response.status, body)
    }

    fn json(store: &Store, scope: &Scope, method: &str, body: &str) -> (u16, serde_json::Value) {
        let (status, bytes) = call(
            store,
            scope,
            format!(
                "POST {TWIRP}{method} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn put(store: &Store, scope: &Scope, path: &str, extra: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut raw = format!(
            "PUT {path} HTTP/1.1\r\nContent-Length: {}\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        call(store, scope, &raw)
    }

    /// The pinned client's upload in its own shape: `CreateArtifact`, stage blocks, commit the block
    /// list, `FinalizeArtifact`; then the download's `ListArtifacts` → `GetSignedArtifactURL` → `GET`.
    #[test]
    fn the_artifact_services_upload_and_download_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let pull = scope(Trust::PullRequest);

        let (status, created) = json(
            &store,
            &pull,
            "CreateArtifact",
            "{\"workflow_run_backend_id\":\"1\",\"workflow_job_run_backend_id\":\"2\",\"name\":\"logs\",\"version\":4}",
        );
        assert_eq!(status, 200);
        assert_eq!(created["ok"], true);
        let url = created["signed_upload_url"].as_str().unwrap();
        let path = url
            .strip_prefix(&format!("https://{RESULTS_HOST}"))
            .unwrap();
        assert!(path.starts_with(BLOB), "{path}");

        for (index, block) in ["PK\x03\x04", "payload"].iter().enumerate() {
            let (status, _) = put(
                &store,
                &pull,
                &format!("{path}?comp=block&blockid=block-{index}&timeout=30"),
                "x-ms-blob-type: BlockBlob\r\n",
                block.as_bytes(),
            );
            assert_eq!(status, 201);
        }
        let list = "<BlockList><Latest>block-0</Latest><Latest>block-1</Latest></BlockList>";
        let (status, _) = put(
            &store,
            &pull,
            &format!("{path}?comp=blocklist&timeout=30"),
            "Content-Type: application/xml\r\n",
            list.as_bytes(),
        );
        assert_eq!(status, 201);

        let (status, finalized) = json(
            &store,
            &pull,
            "FinalizeArtifact",
            "{\"workflow_run_backend_id\":\"1\",\"name\":\"logs\",\"size\":\"11\",\"hash\":{\"value\":\"sha256:00\"}}",
        );
        assert_eq!(status, 200);
        assert_eq!(finalized["ok"], true);
        let id = finalized["artifact_id"].as_str().unwrap().to_owned();

        let (status, listed) = json(
            &store,
            &pull,
            "ListArtifacts",
            "{\"workflow_run_backend_id\":\"1\",\"workflow_job_run_backend_id\":\"22\",\"name_filter\":\"logs\"}",
        );
        assert_eq!(status, 200);
        let artifacts = listed["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0]["name"], "logs");
        assert_eq!(artifacts[0]["database_id"], id.as_str());
        assert_eq!(artifacts[0]["workflow_job_run_backend_id"], "22");

        let (status, signed) = json(&store, &pull, "GetSignedArtifactURL", "{\"name\":\"logs\"}");
        assert_eq!(status, 200);
        let url = signed["signed_url"].as_str().unwrap();
        let path = url
            .strip_prefix(&format!("https://{RESULTS_HOST}"))
            .unwrap();
        let (status, body) = call(
            &store,
            &pull,
            format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes(),
        );
        assert_eq!(status, 200);
        assert_eq!(body, b"PK\x03\x04payload");
    }

    /// The client's own backend ids are not authority: a job that names another run still writes into
    /// the run its lease is bound to.
    #[test]
    fn a_client_that_names_another_run_writes_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let pull = scope(Trust::PullRequest);
        let (status, created) = json(
            &store,
            &pull,
            "CreateArtifact",
            "{\"workflow_run_backend_id\":\"9999\",\"workflow_job_run_backend_id\":\"8888\",\"name\":\"theirs\"}",
        );
        assert_eq!(status, 200);
        let url = created["signed_upload_url"].as_str().unwrap();
        let path = url
            .strip_prefix(&format!("https://{RESULTS_HOST}"))
            .unwrap();
        let (status, _) = put(&store, &pull, path, "", b"body");
        assert_eq!(status, 201);
        let (status, _) = json(
            &store,
            &pull,
            "FinalizeArtifact",
            "{\"name\":\"theirs\",\"size\":\"4\"}",
        );
        assert_eq!(status, 200);
        // The artifact is filed under this lease's run, not the one the client named.
        assert_eq!(store.artifacts(&pull, pull.run).len(), 1);
        assert!(store.artifacts(&pull, 9999).is_empty());
    }

    /// Two boundaries: the same artifact name in one run never appears in the other, and a signed URL
    /// cannot be moved to another boundary's entry.
    #[test]
    fn an_artifact_is_invisible_to_another_trust_and_another_run() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let pull = scope(Trust::PullRequest);
        let id = store
            .artifact_begin(&pull, pull.run, pull.job, "dist")
            .unwrap();
        store.artifact_block(id, "0", b"zip", &pull).unwrap();
        let total = store.artifact_blocks(id, &[0], &pull).unwrap();
        store.artifact_finalize(id, total, &pull).unwrap();

        let protected = Scope {
            trust: Trust::Protected,
            ..pull
        };
        assert!(store.artifacts(&protected, protected.run).is_empty());
        let other_run = Scope { run: 99, ..pull };
        assert!(store.artifacts(&other_run, other_run.run).is_empty());
        let slug = crate::store::slug("dist");
        assert!(
            store
                .artifact_blob(&protected, protected.run, &slug)
                .is_none()
        );
        assert!(store.artifact_blob(&pull, pull.run, &slug).is_some());
    }

    /// A method outside the four Twirp calls is refused, and so is a body that names a block the upload
    /// never staged.
    #[test]
    fn the_artifact_service_refuses_what_it_does_not_implement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let pull = scope(Trust::PullRequest);
        let (status, body) = json(&store, &pull, "GetArtifact", "{\"name\":\"x\"}");
        assert_eq!(status, 404);
        assert_eq!(body["refusal"], "not_implemented");
        assert_eq!(body["forwarded"], false);
        let (status, _) = call(&store, &pull, b"GET /twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts HTTP/1.1\r\n\r\n");
        assert_eq!(status, 405);
        let id = store
            .artifact_begin(&pull, pull.run, pull.job, "x")
            .unwrap();
        store.artifact_block(id, "seen", b"body", &pull).unwrap();
        assert!(
            store
                .block_order(id, &pull, b"<BlockList><Latest>unseen</Latest></BlockList>")
                .is_none()
        );
        assert_eq!(
            store.block_order(id, &pull, b"<BlockList><Latest>seen</Latest></BlockList>"),
            Some(vec![0])
        );
    }
}
