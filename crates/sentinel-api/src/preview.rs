//! One artifact entry's bytes for the run page's browser: text up to 1 MiB and images up to 8 MiB, never a document.
//!
//! The page needs an entry's first bytes to show a log, a report or a screenshot, and it must be able to do so without
//! turning a job's output into a page in the controller's origin. So every preview is served as an attachment with
//! `X-Content-Type-Options: nosniff` and a sandboxing `Content-Security-Policy`, its type comes from a table of known
//! extensions rather than from the bytes, and the length is computed from the manifest before the first byte: a text
//! entry longer than [`TEXT_MAX`] streams exactly [`TEXT_MAX`] bytes and says so in `x-sentinel-truncated`, and an
//! image past [`IMAGE_MAX`] is refused instead of half-served. Nothing is buffered here — the entry streams from the
//! object store as the archive route streams it, holding one transfer slot — and the authorization is the archive
//! route's: the caller must read the run's repository, another tenant's or repository's run is the same `not_found`.

use std::io::Read;

use sentinel_core::{
    ArtifactId, RunId, UnixMillis,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::error::ErrorCode;
use sentinel_store::{Error as StoreError, artifacts, auth as authz, lookup};

use crate::{
    State, auth,
    http::Request,
    routes::{Held, Reply, Route, err, header, id, slot, store_error},
};

/// The most text one preview carries; a longer entry is cut here and flagged.
pub(crate) const TEXT_MAX: u64 = 1 << 20;
/// The largest image served whole; an image preview needs every byte to render, so a bigger one downloads instead.
pub(crate) const IMAGE_MAX: u64 = 8 << 20;

/// What a preview of one entry is, decided from its path and length alone.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    Image,
}

/// Extensions read as text. Anything else is a download: a type the browser would guess from bytes is exactly what
/// `nosniff` exists to prevent.
const TEXT: &[&str] = &[
    "txt",
    "log",
    "md",
    "markdown",
    "json",
    "jsonl",
    "ndjson",
    "yaml",
    "yml",
    "toml",
    "xml",
    "csv",
    "tsv",
    "html",
    "htm",
    "css",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "rs",
    "go",
    "py",
    "rb",
    "sh",
    "bash",
    "c",
    "h",
    "cc",
    "cpp",
    "hpp",
    "java",
    "kt",
    "php",
    "sql",
    "diff",
    "patch",
    "ini",
    "cfg",
    "conf",
    "properties",
    "lock",
    "sum",
    "proto",
    "graphql",
    "tf",
    "ex",
    "gradle",
    "mod",
    "env",
];

/// Extensions previewed as images, with the type each is served as. SVG is safe here only because the response is an
/// attachment and carries a sandbox policy: nothing it holds runs as this origin's document.
const IMAGES: &[(&str, &str)] = &[
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("avif", "image/avif"),
    ("svg", "image/svg+xml"),
];

/// The extension of a path's last segment, if it has one. Borrowed, never allocated: a listing classifies every entry.
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    name.rsplit_once('.').map(|(_, ext)| ext)
}

/// How one entry previews, or `None` when it downloads instead. `len` is the entry's stored length.
pub(crate) fn kind(path: &str, len: u64) -> Option<Kind> {
    let ext = extension(path)?;
    if let Some((_, _)) = IMAGES
        .iter()
        .find(|(name, _)| ext.eq_ignore_ascii_case(name))
    {
        return (len <= IMAGE_MAX).then_some(Kind::Image);
    }
    TEXT.iter()
        .any(|name| ext.eq_ignore_ascii_case(name))
        .then_some(Kind::Text)
}

/// The label the artifact detail carries beside each entry, so the page knows what to offer before it asks.
pub(crate) fn label(path: &str, len: u64) -> Option<&'static str> {
    match kind(path, len)? {
        Kind::Text => Some("text"),
        Kind::Image => Some("image"),
    }
}

impl Kind {
    fn content_type(self, path: &str) -> &'static str {
        match self {
            Kind::Text => "text/plain; charset=utf-8",
            Kind::Image => {
                let ext = extension(path).unwrap_or_default();
                IMAGES
                    .iter()
                    .find(|(name, _)| ext.eq_ignore_ascii_case(name))
                    .map_or("application/octet-stream", |(_, kind)| kind)
            }
        }
    }
}

/// A query parameter's value, percent-decoded. A name given twice is refused rather than resolved to one of them.
fn decoded(query: &str, name: &str) -> Result<Option<String>, sentinel_protocol::error::ApiError> {
    let mut found = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == name {
            if found.is_some() {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!("{name} given twice"),
                ));
            }
            found = Some(value.into_owned());
        }
    }
    Ok(found)
}

/// The download's file name: the path's last segment, cut to what a header value may hold and stripped of anything
/// that is not a plain file-name character.
fn file_name(path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or(path);
    let mut name = String::with_capacity(last.len().min(96));
    for c in last.chars().take(96) {
        name.push(match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        });
    }
    if name.is_empty() {
        name.push_str("entry");
    }
    name
}

/// `GET /api/v1/runs/{run}/artifacts/{arf}/preview?path=` — one entry's bytes, bounded and served as an attachment.
pub(crate) fn entry(state: &State, request: &Request, run: &str, art: &str, query: &str) -> Route {
    let who = crate::routes::identify(state, request, false)?;
    auth::require_scope(&who, Scopes::ARTIFACTS_READ)?;
    let Some(path) = decoded(query, "path")? else {
        return Err(err(
            ErrorCode::InvalidRequest,
            "path query parameter required",
        ));
    };
    let (run, art): (RunId, ArtifactId) = (id(run, "run")?, id(art, "artifact")?);
    let (tenant, entry) = state
        .store
        .read(|c| {
            let repo = lookup::run_repo(c, run)?;
            let (tenant, _) = authz::require_repo_slug(c, who.principal, repo, Permissions::READ)?;
            let row = artifacts::get(c, tenant, run, art)?;
            // Retention is re-checked here and not only by the sweep, as the archive route does: an artifact past its
            // deadline is gone to the client from the moment it is due, whatever the maintenance pass has reached.
            if row.pinned_ms.is_none() && row.retain_until_ms <= UnixMillis::now() {
                return Err(StoreError::NotFound);
            }
            let Some(version) = row.manifest_version else {
                return Err(StoreError::NotFound);
            };
            // A row's producer names its manifest: a job's `{job}/{name}`, a run-level artifact's
            // `run/{run}/{name}` or a runner-mode one's GitHub coordinates.
            let manifest = state.objects.manifest(
                c,
                tenant,
                sentinel_store::objects::Kind::Artifact,
                &row.manifest()?,
                Some(version),
            )?;
            manifest
                .entries
                .into_iter()
                .find(|e| e.path == path)
                .map(|e| (tenant, e))
                .ok_or(StoreError::NotFound)
        })
        .map_err(store_error)?;
    let Some(kind) = kind(&entry.path, entry.len) else {
        return Err(err(
            ErrorCode::InvalidRequest,
            "this entry has no preview; download it instead",
        ));
    };
    let body_len = match kind {
        Kind::Text => entry.len.min(TEXT_MAX),
        Kind::Image => entry.len,
    };
    let mut reader = state
        .objects
        .open_entry(tenant, entry.digest, entry.len)
        .map_err(store_error)?;
    let mut headers = vec![
        header("content-type", kind.content_type(&entry.path)),
        header(
            "content-disposition",
            &format!("attachment; filename=\"{}\"", file_name(&entry.path)),
        ),
        header("x-content-type-options", "nosniff"),
        header("content-security-policy", "default-src 'none'; sandbox"),
    ];
    if kind == Kind::Text {
        headers.push(header(
            "x-sentinel-truncated",
            if entry.len > TEXT_MAX {
                "true"
            } else {
                "false"
            },
        ));
    }
    let slot = slot(state)?;
    // The first byte is read here, so an unreadable entry is a response rather than a truncated body.
    let mut first = [0u8; 1];
    if body_len > 0 {
        let got = reader
            .read(&mut first)
            .map_err(|_| err(ErrorCode::Internal, "controller fault"))?;
        if got == 0 {
            return Err(err(ErrorCode::Internal, "controller fault"));
        }
    }
    Ok(Reply::Stream(
        200,
        Box::new(Held {
            inner: Head {
                first: first[0],
                taken: body_len > 0,
                rest: reader.take(body_len.saturating_sub(1)),
            },
            _slot: slot,
        }),
        body_len,
        headers,
    ))
}

/// The one byte read to prove the entry opens, then the rest of the bounded body.
struct Head<R> {
    first: u8,
    taken: bool,
    rest: std::io::Take<R>,
}

impl<R: Read> Read for Head<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.taken && !buf.is_empty() {
            self.taken = false;
            buf[0] = self.first;
            return Ok(1);
        }
        self.rest.read(buf)
    }
}
