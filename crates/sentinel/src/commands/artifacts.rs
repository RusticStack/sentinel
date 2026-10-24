use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Map, json};

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
    let slug = match (tenant_flag, view["tenant"].as_str()) {
        (Some(flag), _) => tenant(client, Some(flag))?,
        (None, Some(owner)) => segment("tenant", owner)?.to_owned(),
        (None, None) => tenant(client, None)?,
    };
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
    let object = format!("/api/v1/tenants/{slug}/objects/{digest}");
    let part = partial_path(out, &digest);
    match fetch(client, &object, &part, len, &digest) {
        Ok(()) => fs::rename(&part, out).map_err(|e| {
            let _ = fs::remove_file(&part);
            Error::usage(format!("cannot write {}: {e}", out.display()))
        })?,
        Err(Failure::Interrupted(error)) => return Err(error),
        Err(Failure::Failed(error)) => {
            let _ = fs::remove_file(&part);
            return Err(error);
        }
    }
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
