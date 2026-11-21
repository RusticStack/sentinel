use std::{
    collections::HashSet,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use sentinel_protocol::limits::{
    MAX_ARTIFACT_BYTES, MAX_ARTIFACT_ENTRIES, MAX_ARTIFACT_PATH_BYTES,
};
use serde_json::{Map, Value, json};

use super::{List, segment, tenant, text};
use crate::client::{self, Client, Error, Exit, Output};

pub(super) fn list(client: &Client, output: Output, run: &str) -> Result<(), Error> {
    let run = segment("run", run)?;
    let mut view = client.get(&format!("/api/v1/runs/{run}/artifacts"))?;
    let mut list = List::new(output);
    for artifact in view["artifacts"].as_array().into_iter().flatten() {
        list.item(artifact.clone(), || {
            format!(
                "{} {:<24} {:<9} {:>6} entries {:>12} bytes  {}\n",
                text(artifact, "id"),
                text(artifact, "name"),
                text(artifact, "state"),
                artifact["entries"].as_u64().unwrap_or(0),
                artifact["bytes"].as_u64().unwrap_or(0),
                text(artifact, "job_name"),
            )
        });
    }
    let mut extra = Map::new();
    if let Some(tenant) = view.get_mut("tenant") {
        extra.insert("tenant".to_owned(), tenant.take());
    }
    list.finish("artifacts", extra);
    Ok(())
}

pub(super) fn show(
    client: &Client,
    output: Output,
    run: &str,
    artifact: &str,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    let artifact = segment("artifact", artifact)?;
    let view = client.get(&format!("/api/v1/runs/{run}/artifacts/{artifact}"))?;
    client::emit(output, &view, || {
        let mut out = format!(
            "{} {} {} ({} entries, {} bytes)\n",
            text(&view, "id"),
            text(&view, "name"),
            text(&view, "state"),
            view["entries"].as_u64().unwrap_or(0),
            view["bytes"].as_u64().unwrap_or(0),
        );
        for entry in view["manifest"]["entries"].as_array().into_iter().flatten() {
            out.push_str(&format!(
                "  {:>12} {} {}\n",
                entry["len"].as_u64().unwrap_or(0),
                text(entry, "digest"),
                text(entry, "path"),
            ));
        }
        out
    });
    Ok(())
}

pub(super) fn download(
    client: &Client,
    output: Output,
    run: &str,
    artifact: &str,
    entry_path: &str,
    out: &Path,
    tenant_flag: Option<String>,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    let artifact = segment("artifact", artifact)?;
    let view = client.get(&format!("/api/v1/runs/{run}/artifacts/{artifact}"))?;
    let slug = owner_slug(client, &view, tenant_flag)?;
    let (digest, len) = manifest_entry(&view, artifact, entry_path)?;
    write_entry(client, &slug, &digest, len, out)?;
    let result = json!({
        "artifact": artifact,
        "path": entry_path,
        "out": out.display().to_string(),
        "digest": digest,
        "len": len,
    });
    client::emit(output, &result, || {
        format!(
            "{entry_path}: {len} bytes, digest {digest} -> {}\n",
            out.display()
        )
    });
    Ok(())
}

/// Every entry of one artifact, written under `dir` at its manifest path: each object is verified on its own, so a
/// failure part way keeps the entries already written and names the one that stopped.
pub(super) fn download_all(
    client: &Client,
    output: Output,
    run: &str,
    artifact: &str,
    dir: &Path,
    tenant_flag: Option<String>,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    let artifact = segment("artifact", artifact)?;
    let view = client.get(&format!("/api/v1/runs/{run}/artifacts/{artifact}"))?;
    let slug = owner_slug(client, &view, tenant_flag)?;
    let entries = view["manifest"]["entries"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if entries.is_empty() {
        return Err(Error::new(
            Exit::NotFound,
            format!(
                "artifact {artifact} has no manifest to download (its state is {})",
                text(&view, "state")
            ),
        ));
    }
    fs::create_dir_all(dir)
        .map_err(|e| Error::usage(format!("cannot create {}: {e}", dir.display())))?;
    let mut list = List::new(output);
    for entry in entries {
        let path = text(entry, "path");
        let digest = segment("digest", text(entry, "digest"))?.to_owned();
        let len = entry["len"]
            .as_u64()
            .ok_or_else(|| Error::remote("the manifest entry has no length"))?;
        let dest = entry_destination(dir, path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::usage(format!("cannot create {}: {e}", parent.display())))?;
        }
        write_entry(client, &slug, &digest, len, &dest)?;
        let item = json!({
            "path": path,
            "out": dest.display().to_string(),
            "digest": digest,
            "len": len,
        });
        list.item(item, || {
            format!(
                "{path}: {len} bytes, digest {digest} -> {}\n",
                dest.display()
            )
        });
    }
    let mut extra = Map::with_capacity(2);
    extra.insert("artifact".to_owned(), Value::String(artifact.to_owned()));
    extra.insert("out".to_owned(), Value::String(dir.display().to_string()));
    list.finish("entries", extra);
    Ok(())
}

/// A short-lived download URL for one entry or the whole archive; minting is a write of nothing, so it is idempotent.
pub(super) fn link(
    client: &Client,
    output: Output,
    run: &str,
    artifact: &str,
    entry: Option<&str>,
    format: Option<&str>,
    expires: u64,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    let artifact = segment("artifact", artifact)?;
    match format {
        None | Some("tar" | "zip") => {}
        Some(other) => {
            return Err(Error::usage(format!(
                "--format is tar or zip, not {other:?}"
            )));
        }
    }
    if entry.is_some() && format.is_some() {
        return Err(Error::usage(
            "--entry names one file and takes no --format; omit --entry for a whole archive",
        ));
    }
    if !(1..=3600).contains(&expires) {
        return Err(Error::usage("--expires is 1 to 3600 seconds"));
    }
    let mut body =
        Map::with_capacity(1 + usize::from(entry.is_some()) + usize::from(format.is_some()));
    if let Some(entry) = entry {
        body.insert("entry".to_owned(), Value::String(entry.to_owned()));
    }
    if let Some(format) = format {
        body.insert("format".to_owned(), Value::String(format.to_owned()));
    }
    body.insert("expires_secs".to_owned(), Value::from(expires));
    let view = client.post(
        &format!("/api/v1/runs/{run}/artifacts/{artifact}/link"),
        &Value::Object(body),
        None,
    )?;
    client::emit(output, &view, || {
        format!(
            "{}\nexpires in {expires}s: anyone holding this URL can download until then\n",
            text(&view, "url")
        )
    });
    Ok(())
}

/// Records one artifact from local files: each regular file under `source` becomes a manifest entry at
/// its relative path, its bytes go through an upload session of the run's own tenant unless that tenant
/// already holds them, and the manifest is attached once every object is committed.
pub(super) fn upload(
    client: &Client,
    output: Output,
    run: &str,
    name: &str,
    source: &Path,
    options: UploadOptions,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    artifact_name(name)?;
    let mode = parse_mode(options.mode.as_deref())?;
    if options.class.as_ref().is_some_and(String::is_empty) {
        return Err(Error::usage(
            "--class names an artifact class; it is not empty",
        ));
    }
    if options.retain == Some(0) {
        return Err(Error::usage("--retain is at least 1 second"));
    }
    let files = files_under(source)?;
    if files.is_empty() {
        return Err(Error::usage(format!(
            "{} holds no regular file to upload",
            source.display()
        )));
    }
    if files.len() > MAX_ARTIFACT_ENTRIES {
        return Err(Error::usage(format!(
            "{} holds {} regular files; an artifact holds at most {MAX_ARTIFACT_ENTRIES} entries",
            source.display(),
            files.len()
        )));
    }
    // The run's own tenant owns its objects, so a session opened for another tenant would leave a
    // manifest naming bytes that tenant's store does not hold: the listing settles the tenant before a
    // byte moves, and it names the artifacts the run already holds so a duplicate name never uploads
    // bytes it would have to discard.
    let listing = client.get(&format!("/api/v1/runs/{run}/artifacts"))?;
    let slug = run_tenant(client, &listing, options.tenant, run)?;
    if listing["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|artifact| artifact["name"] == name)
    {
        return Err(Error::new(
            Exit::Conflict,
            format!(
                "run {run} already holds an artifact named {name:?}; choose another name, or read it \
                 with: artifact list {run}"
            ),
        ));
    }
    let mut buf = vec![0u8; CHUNK];
    let mut entries = Vec::with_capacity(files.len());
    let mut held = HashSet::new();
    let mut total = 0u64;
    let (mut uploaded, mut kept) = (0usize, 0usize);
    for (file, path) in files {
        let (digest, len) = digest_of(&file, &mut buf)?;
        total = total.saturating_add(len);
        if total > MAX_ARTIFACT_BYTES {
            return Err(Error::usage(format!(
                "{} holds more than the {MAX_ARTIFACT_BYTES}-byte artifact limit",
                source.display()
            )));
        }
        // Identical content is one object: a digest already sent (or already stored) is not sent again.
        if held.insert(digest.clone()) {
            if stored(client, &slug, &digest) {
                kept += 1;
            } else {
                put_blob(client, &slug, &file, &digest, len, &mut buf)?;
                uploaded += 1;
            }
        }
        entries.push(json!({
            "path": path,
            "digest": digest,
            "len": len,
            "mode": mode,
        }));
    }
    let mut body = Map::with_capacity(4);
    body.insert("name".to_owned(), Value::String(name.to_owned()));
    body.insert("entries".to_owned(), Value::Array(entries));
    if let Some(class) = options.class {
        body.insert("class".to_owned(), Value::String(class));
    }
    if let Some(secs) = options.retain {
        body.insert("retain_secs".to_owned(), Value::from(secs));
    }
    let view = client.post(
        &format!("/api/v1/runs/{run}/artifacts"),
        &Value::Object(body),
        None,
    )?;
    client::emit(output, &view, || {
        format!(
            "{} {} {} ({} entries, {} bytes; {uploaded} uploaded, {kept} already held)\n",
            text(&view, "id"),
            text(&view, "name"),
            text(&view, "state"),
            view["entries"].as_u64().unwrap_or(0),
            view["bytes"].as_u64().unwrap_or(0),
        )
    });
    Ok(())
}

/// What an upload records besides the files themselves: the tenant whose store the objects go to, and the
/// class, retention and file mode the manifest and the row carry.
#[derive(Debug, Default)]
pub(super) struct UploadOptions {
    pub tenant: Option<String>,
    pub class: Option<String>,
    pub retain: Option<u64>,
    pub mode: Option<String>,
}

/// The store's name rule, checked locally so a name the controller would refuse never moves bytes.
fn artifact_name(name: &str) -> Result<(), Error> {
    const NAME_MAX: usize = 128;
    if name.is_empty() || name.len() > NAME_MAX || name.bytes().any(|b| b < 32 || b == 127) {
        return Err(Error::usage(format!(
            "an artifact name is 1 to {NAME_MAX} printable ASCII bytes, not {name:?}"
        )));
    }
    Ok(())
}

/// `--mode` is octal like `chmod`; the leading zero is optional and the setuid, setgid and sticky bits are
/// masked off, as the store masks them.
fn parse_mode(mode: Option<&str>) -> Result<u32, Error> {
    let Some(text) = mode else {
        return Ok(0o644);
    };
    u32::from_str_radix(text.trim_start_matches("0o"), 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .map(|mode| mode & 0o777)
        .ok_or_else(|| Error::usage(format!("--mode is octal up to 0777, not {text:?}")))
}

/// The tenant whose store holds the run's objects, as the server states it. `--tenant` may repeat it and
/// never change it.
fn run_tenant(
    client: &Client,
    listing: &Value,
    tenant_flag: Option<String>,
    run: &str,
) -> Result<String, Error> {
    let owner = match listing["tenant"].as_str() {
        Some(owner) => segment("tenant", owner)?.to_owned(),
        None => tenant(client, None)?,
    };
    match tenant_flag {
        Some(flag) => {
            let flag = tenant(client, Some(flag))?;
            if flag != owner {
                return Err(Error::usage(format!(
                    "run {run} belongs to tenant {owner} and its objects are that tenant's; --tenant is {owner}"
                )));
            }
            Ok(flag)
        }
        None => Ok(owner),
    }
}

/// Every regular file under `source` as (where to read it, the path the manifest names it), sorted by that
/// path so one tree always produces one manifest. A single file is one entry named by its file name; a
/// symbolic link or any other non-regular entry is skipped rather than followed.
fn files_under(source: &Path) -> Result<Vec<(PathBuf, String)>, Error> {
    let kind = fs::symlink_metadata(source).map_err(|e| local(source, e))?;
    if kind.is_file() {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::usage(format!(
                    "{} has no UTF-8 file name to name the entry by",
                    source.display()
                ))
            })?;
        entry_path(name)?;
        return Ok(vec![(source.to_path_buf(), name.to_owned())]);
    }
    if !kind.is_dir() {
        return Err(Error::usage(format!(
            "{} is neither a regular file nor a directory",
            source.display()
        )));
    }
    let mut files = Vec::new();
    walk(source, "", &mut files)?;
    files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    Ok(files)
}

fn walk(dir: &Path, prefix: &str, files: &mut Vec<(PathBuf, String)>) -> Result<(), Error> {
    for entry in fs::read_dir(dir).map_err(|e| local(dir, e))? {
        let entry = entry.map_err(|e| local(dir, e))?;
        let file = entry.path();
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            Error::usage(format!(
                "{} has no UTF-8 file name; a manifest names its entries in UTF-8",
                file.display()
            ))
        })?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type().map_err(|e| local(&file, e))?;
        if kind.is_dir() {
            walk(&file, &path, files)?;
        } else if kind.is_file() {
            entry_path(&path)?;
            files.push((file, path));
        }
    }
    Ok(())
}

/// A path the manifest accepts: bounded, and every segment a plain name, so nothing the local tree states
/// could name a path the store would refuse after the bytes were already sent.
fn entry_path(path: &str) -> Result<(), Error> {
    let plain = path.split('/').all(|part| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', ':', '\0'])
    });
    if !plain || path.len() > MAX_ARTIFACT_PATH_BYTES {
        return Err(Error::usage(format!(
            "the entry path {path:?} is not a plain relative path of at most \
             {MAX_ARTIFACT_PATH_BYTES} bytes"
        )));
    }
    Ok(())
}

fn local(path: &Path, error: std::io::Error) -> Error {
    let what = match error.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        _ => error.to_string(),
    };
    Error::usage(format!("cannot read {}: {what}", path.display()))
}

/// The digest and length of one file, read once through a bounded buffer.
fn digest_of(path: &Path, buf: &mut [u8]) -> Result<(String, u64), Error> {
    let mut file = fs::File::open(path).map_err(|e| local(path, e))?;
    let mut hasher = blake3::Hasher::new();
    let mut len = 0u64;
    loop {
        let n = file.read(buf).map_err(|e| local(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), len))
}

/// Whether the tenant's store already holds these bytes: an object read of one byte answers 206 when it
/// does and 404 when it does not. Any other answer (a credential without `artifacts:read`, a server that
/// ignores the range) says nothing, so the bytes go up and the commit verifies them anyway.
fn stored(client: &Client, slug: &str, digest: &str) -> bool {
    let object = format!("/api/v1/tenants/{slug}/objects/{digest}");
    match client.download(&object, Some((0, 1))) {
        Ok(mut download) => {
            let mut one = [0u8; 1];
            let _ = download.body.read(&mut one);
            matches!(download.status, 200 | 206)
        }
        Err(_) => false,
    }
}

/// One object through its own upload session: the length and digest are declared, the file goes up in
/// bounded chunks, and the commit is the server's own digest check. A failure aborts the session, so its
/// reservation against the tenant's quota comes back at once instead of at the session's expiry.
fn put_blob(
    client: &Client,
    slug: &str,
    path: &Path,
    digest: &str,
    len: u64,
    buf: &mut [u8],
) -> Result<(), Error> {
    let begin = client.post(
        &format!("/api/v1/tenants/{slug}/uploads"),
        &json!({ "len": len, "digest": digest }),
        None,
    )?;
    let upload = segment("upload", text(&begin, "upload"))?;
    if let Err(error) = stream(client, upload, path, len, buf) {
        let _ = client.delete(&format!("/api/v1/uploads/{upload}"));
        return Err(error);
    }
    let commit = client.post(
        &format!("/api/v1/uploads/{upload}/commit"),
        &json!({}),
        None,
    )?;
    let sealed = segment("digest", text(&commit, "digest"))?;
    if sealed != digest {
        return Err(Error::remote(format!(
            "the controller stored {sealed} where the file hashes to {digest}"
        )));
    }
    Ok(())
}

fn stream(
    client: &Client,
    upload: &str,
    path: &Path,
    len: u64,
    buf: &mut [u8],
) -> Result<(), Error> {
    let mut file = fs::File::open(path).map_err(|e| local(path, e))?;
    let mut offset = 0u64;
    loop {
        let n = file.read(buf).map_err(|e| local(path, e))?;
        if n == 0 {
            break;
        }
        client.put_bytes(
            &format!("/api/v1/uploads/{upload}?offset={offset}"),
            &buf[..n],
            "application/octet-stream",
            &[],
            &format!("upload-{upload}-{offset}"),
        )?;
        offset += n as u64;
    }
    if offset != len {
        return Err(Error::usage(format!(
            "{} changed while it was read: {offset} bytes of the {len} its digest covers",
            path.display()
        )));
    }
    Ok(())
}

/// The slug the artifact row belongs to, so entry bytes come from the owning tenant's objects.
fn owner_slug(client: &Client, view: &Value, tenant_flag: Option<String>) -> Result<String, Error> {
    match (tenant_flag, view["tenant"].as_str()) {
        (Some(flag), _) => tenant(client, Some(flag)),
        (None, Some(owner)) => Ok(segment("tenant", owner)?.to_owned()),
        (None, None) => tenant(client, None),
    }
}

/// The digest and length the manifest gives one entry, or `not_found` when it holds no such path.
fn manifest_entry(view: &Value, artifact: &str, entry_path: &str) -> Result<(String, u64), Error> {
    let entry = view["manifest"]["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["path"] == entry_path)
        .ok_or_else(|| {
            Error::new(
                Exit::NotFound,
                format!("artifact {artifact} has no entry {entry_path:?}"),
            )
        })?;
    let digest = segment("digest", text(entry, "digest"))?.to_owned();
    let len = entry["len"]
        .as_u64()
        .ok_or_else(|| Error::remote("the manifest entry has no length"))?;
    Ok((digest, len))
}

/// An entry path joins under the directory only as plain names: the manifest is the server's, and a path that could
/// leave the destination is refused rather than normalized.
fn entry_destination(dir: &Path, path: &str) -> Result<PathBuf, Error> {
    let mut dest = dir.to_path_buf();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':']) {
            return Err(Error::remote(format!(
                "the manifest entry {path:?} is not a plain relative path"
            )));
        }
        dest.push(part);
    }
    Ok(dest)
}

/// One entry's bytes into `out`: a partial file beside it resumes and verifies, and only matching bytes are renamed.
fn write_entry(
    client: &Client,
    slug: &str,
    digest: &str,
    len: u64,
    out: &Path,
) -> Result<(), Error> {
    let object = format!("/api/v1/tenants/{slug}/objects/{digest}");
    let part = partial_path(out, digest);
    match fetch(client, &object, &part, len, digest) {
        Ok(()) => fs::rename(&part, out).map_err(|e| {
            let _ = fs::remove_file(&part);
            Error::usage(format!("cannot write {}: {e}", out.display()))
        }),
        Err(Failure::Interrupted(error)) => Err(error),
        Err(Failure::Failed(error)) => {
            let _ = fs::remove_file(&part);
            Err(error)
        }
    }
}

const STALLED_ATTEMPTS: u32 = 3;
const RESUME_PAUSE: Duration = Duration::from_millis(200);
const BUFFER: usize = 64 << 10;
/// One upload chunk, read into this buffer and sent as-is; the controller accepts at most 8 MiB per chunk.
const CHUNK: usize = 1 << 20;

/// Beside the destination so the final rename never crosses a filesystem; keyed by digest so only the same content resumes.
fn partial_path(out: &Path, digest: &str) -> PathBuf {
    let mut name = out.as_os_str().to_owned();
    name.push(".");
    name.push(&digest[..digest.len().min(16)]);
    name.push(".sentinel-part");
    PathBuf::from(name)
}

enum Failure {
    Interrupted(Error),
    Failed(Error),
}

struct Part {
    file: fs::File,
    hasher: blake3::Hasher,
    count: u64,
}

impl Part {
    fn restart(&mut self) -> std::io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.hasher.reset();
        self.count = 0;
        Ok(())
    }
}

fn fetch(
    client: &Client,
    object: &str,
    part: &Path,
    len: u64,
    digest: &str,
) -> Result<(), Failure> {
    let local = |e: std::io::Error| {
        Failure::Failed(Error::usage(format!(
            "cannot write {}: {e}",
            part.display()
        )))
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(part)
        .map_err(local)?;
    let mut part_file = Part {
        file,
        hasher: blake3::Hasher::new(),
        count: 0,
    };
    let mut buf = vec![0u8; BUFFER];
    let mut resumed = resume(&mut part_file, len, &mut buf).map_err(local)?;
    loop {
        let mut stalls = 0;
        while part_file.count < len {
            let before = part_file.count;
            match transfer(client, object, len, &mut part_file, &mut buf) {
                Ok(()) => {}
                Err(Failure::Interrupted(error)) => {
                    stalls = if part_file.count > before {
                        0
                    } else {
                        stalls + 1
                    };
                    if stalls >= STALLED_ATTEMPTS {
                        return Err(Failure::Interrupted(Error::new(
                            Exit::Busy,
                            format!(
                                "{}; {} of {len} bytes are kept in {}: run the same command again to resume",
                                error.message,
                                part_file.count,
                                part.display()
                            ),
                        )));
                    }
                    std::thread::sleep(RESUME_PAUSE);
                }
                Err(failed) => return Err(failed),
            }
        }
        if part_file.hasher.finalize().to_hex().as_str() == digest {
            return part_file.file.sync_all().map_err(local);
        }
        // Bytes an earlier run left may belong to other content: fetch everything once more.
        if !resumed {
            return Err(Failure::Failed(Error::remote(
                "the downloaded bytes do not match the manifest digest",
            )));
        }
        resumed = false;
        part_file.restart().map_err(local)?;
    }
}

fn resume(part: &mut Part, len: u64, buf: &mut [u8]) -> std::io::Result<bool> {
    let existing = part.file.metadata()?.len();
    if existing > len {
        part.restart()?;
        return Ok(false);
    }
    loop {
        let n = part.file.read(buf)?;
        if n == 0 {
            break;
        }
        part.hasher.update(&buf[..n]);
        part.count += n as u64;
    }
    if part.count != existing {
        part.restart()?;
    }
    Ok(part.count > 0)
}

fn transfer(
    client: &Client,
    object: &str,
    len: u64,
    part: &mut Part,
    buf: &mut [u8],
) -> Result<(), Failure> {
    let local = |e: std::io::Error| {
        Failure::Failed(Error::usage(format!("cannot write the partial file: {e}")))
    };
    let range = (part.count > 0).then_some((part.count, len));
    let download = client
        .download(object, range)
        .map_err(|error| match error.exit {
            Exit::Busy => Failure::Interrupted(error),
            _ => Failure::Failed(error),
        })?;
    let expected = match (range, download.status) {
        (Some((start, end)), 206) => {
            if download.start != Some(start) {
                return Err(Failure::Failed(Error::remote(format!(
                    "the server answered a range that does not start at byte {start}"
                ))));
            }
            end - start
        }
        // A server that ignores `Range` sends everything: start over.
        (_, 200) => {
            if range.is_some() {
                part.restart().map_err(local)?;
            }
            len
        }
        (_, status) => {
            return Err(Failure::Failed(Error::remote(format!(
                "the server answered HTTP {status} to a download"
            ))));
        }
    };
    if download.len.is_some_and(|d| d != expected) {
        return Err(Failure::Failed(Error::remote(format!(
            "the server declared {} bytes where {expected} were expected",
            download.len.unwrap_or(0)
        ))));
    }
    let mut body = download.body;
    loop {
        let n = match body.read(buf) {
            Ok(n) => n,
            Err(e) => {
                return Err(Failure::Interrupted(Error::new(
                    Exit::Busy,
                    format!("download interrupted: {e}"),
                )));
            }
        };
        if n == 0 {
            break;
        }
        if part.count + n as u64 > len {
            return Err(Failure::Failed(Error::remote(format!(
                "the download ran past the entry's {len} bytes"
            ))));
        }
        part.file.write_all(&buf[..n]).map_err(local)?;
        part.hasher.update(&buf[..n]);
        part.count += n as u64;
    }
    if part.count < len {
        return Err(Failure::Interrupted(Error::new(
            Exit::Busy,
            format!("the download ended at {} of {len} bytes", part.count),
        )));
    }
    Ok(())
}

pub(super) fn cache(client: &Client, output: Output, attempt: &str) -> Result<(), Error> {
    let attempt = segment("attempt", attempt)?;
    let view = client.get(&format!("/api/v1/attempts/{attempt}/summary"))?;
    client::emit(output, &view, || {
        if view["present"] != true {
            return format!("{attempt}: no summary yet (the attempt has not finished)\n");
        }
        let caches = view["caches"].as_array().map_or(&[][..], Vec::as_slice);
        if caches.is_empty() {
            return format!("{attempt}: no caches declared\n");
        }
        let mut out = String::new();
        for record in caches {
            out.push_str(&format!(
                "{:<20} {:<24} {:>8} files {:>12} bytes  publish {}{}\n",
                text(record, "name"),
                text(record, "outcome"),
                record["files"].as_u64().unwrap_or(0),
                record["bytes"].as_u64().unwrap_or(0),
                record["publish"].as_str().unwrap_or("-"),
                if record["costly_hit"] == true {
                    "  (costly hit)"
                } else {
                    ""
                },
            ));
        }
        out
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_walks_into_regular_files_only_sorted_by_their_manifest_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("b/inner")).unwrap();
        for (name, body) in [("z.txt", "z"), ("b/inner/x.bin", "x"), ("a.txt", "a")] {
            fs::write(root.join(name), body).unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("link.txt")).unwrap();
        let files = files_under(root).unwrap();
        let paths: Vec<&str> = files.iter().map(|(_, path)| path.as_str()).collect();
        assert_eq!(paths, ["a.txt", "b/inner/x.bin", "z.txt"]);
        let single = files_under(&root.join("z.txt")).unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].1, "z.txt");
        assert_eq!(
            files_under(&root.join("absent")).unwrap_err().exit,
            Exit::Usage
        );
    }

    #[test]
    fn mode_is_octal_and_names_and_entry_paths_are_checked_before_any_byte_moves() {
        assert_eq!(parse_mode(None).unwrap(), 0o644);
        for (text, mask) in [
            ("644", 0o644),
            ("0644", 0o644),
            ("0o644", 0o644),
            ("755", 0o755),
            ("4755", 0o755),
            ("7777", 0o777),
        ] {
            assert_eq!(parse_mode(Some(text)).unwrap(), mask, "{text:?}");
        }
        for bad in ["rw-r--r--", "644a", "", "10000"] {
            assert_eq!(
                parse_mode(Some(bad)).unwrap_err().exit,
                Exit::Usage,
                "{bad:?}"
            );
        }
        assert!(artifact_name("release").is_ok());
        for bad in ["", "a\nb"] {
            assert_eq!(artifact_name(bad).unwrap_err().exit, Exit::Usage, "{bad:?}");
        }
        assert_eq!(
            artifact_name(&"a".repeat(129)).unwrap_err().exit,
            Exit::Usage
        );
        assert!(entry_path("out/report.txt").is_ok());
        for bad in ["", "/etc/passwd", "out//x", "out/../x", "out\\x", "c:x"] {
            assert_eq!(entry_path(bad).unwrap_err().exit, Exit::Usage, "{bad:?}");
        }
        assert_eq!(entry_path(&"a/".repeat(600)).unwrap_err().exit, Exit::Usage);
    }

    #[test]
    fn entry_paths_join_under_the_directory_only_as_plain_names() {
        let dir = Path::new("/tmp/tree");
        assert_eq!(
            entry_destination(dir, "out/report.txt").unwrap(),
            dir.join("out").join("report.txt")
        );
        assert_eq!(
            entry_destination(dir, "a/b/c.bin").unwrap(),
            dir.join("a/b/c.bin")
        );
        for bad in [
            "../escape.bin",
            "out/../../escape.bin",
            "/etc/passwd",
            "out//x",
            "out/./x",
            "out\\x",
            "c:x",
            "",
        ] {
            let error = entry_destination(dir, bad).unwrap_err();
            assert_eq!(error.exit, Exit::Remote, "{bad:?}");
        }
    }
}
