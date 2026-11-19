use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
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
