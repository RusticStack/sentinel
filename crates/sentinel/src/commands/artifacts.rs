//! `artifact list|show|download` and `cache show`.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
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

/// Stream one manifest entry to `out` through a sibling temporary file,
/// hashing (BLAKE3, the object store's digest) and counting as it goes;
/// the file replaces `out` only when the declared length, the byte count
/// and the digest all match the manifest. A mismatch leaves `out` as it
/// was and exits 1.
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
    // The answer names the run's tenant; `--tenant` or the profile context
    // only matter for a server that does not.
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
    let (_, declared, mut body) =
        client.download(&format!("/api/v1/tenants/{slug}/objects/{digest}"), None)?;
    if declared.is_some_and(|d| d != len) {
        return Err(Error::remote(format!(
            "the server declared {} bytes for an entry of {len}",
            declared.unwrap_or(0)
        )));
    }
    let part = partial_path(out);
    let written = copy_verified(&mut body, &part, len, &digest);
    match written {
        Ok(()) => fs::rename(&part, out).map_err(|e| {
            let _ = fs::remove_file(&part);
            Error::usage(format!("cannot write {}: {e}", out.display()))
        })?,
        Err(error) => {
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

/// `<out>.sentinel-part` beside the destination, so the final rename never
/// crosses a filesystem.
fn partial_path(out: &Path) -> PathBuf {
    let mut name = out.as_os_str().to_owned();
    name.push(".sentinel-part");
    PathBuf::from(name)
}

fn copy_verified(body: &mut dyn Read, part: &Path, len: u64, digest: &str) -> Result<(), Error> {
    let local = |e: std::io::Error| Error::usage(format!("cannot write {}: {e}", part.display()));
    let mut file = fs::File::create(part).map_err(local)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut count = 0u64;
    loop {
        let n = body
            .read(&mut buf)
            .map_err(|e| Error::new(Exit::Busy, format!("download interrupted: {e}")))?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > len {
            return Err(Error::remote(format!(
                "the download ran past the entry's {len} bytes"
            )));
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(local)?;
    }
    if count != len {
        return Err(Error::remote(format!(
            "the download ended at {count} of {len} bytes"
        )));
    }
    if hasher.finalize().to_hex().as_str() != digest {
        return Err(Error::remote(
            "the downloaded bytes do not match the manifest digest",
        ));
    }
    file.sync_all().map_err(local)
}

/// An attempt's cache records (K08) from its terminal summary.
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
