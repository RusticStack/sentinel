use std::{io::Read, path::Path, time::Duration};

use sentinel_core::AttemptId;
use sentinel_link::session::{ArtifactCode, Offered};
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_protocol::limits::{
    MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_ENTRIES, MAX_ARTIFACT_OFFER_ENTRIES,
};

pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Sink: Send + Sync {
    fn capable(&self) -> bool;
    /// Whether the peer may be offered digests before bodies; a sink that cannot still sends every body.
    fn digests(&self) -> bool {
        false
    }
    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode>;
    fn offer(&self, _attempt: AttemptId, _name: &str, _entries: &[Offered], _last: bool) -> bool {
        false
    }
    /// The entries of the closed offer the tenant already holds; `None` when the artifact was refused or the
    /// answer never came.
    fn held(&self, _attempt: AttemptId, _name: &str) -> Option<Vec<u32>> {
        Some(Vec::new())
    }
    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool;
    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool;
    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode;
    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode;
    fn settle(&self, attempt: AttemptId, name: &str) -> ArtifactCode;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Published,
    Absent,
    Failed,
    /// The controller refused the publication at the tenant's hard storage threshold, after evicting its caches;
    /// the artifact's row records used, limit and the largest classes.
    QuotaExceeded,
}

pub struct NoSink;
impl Sink for NoSink {
    fn capable(&self) -> bool {
        false
    }
    fn begin(&self, _: AttemptId, _: &str) -> Option<ArtifactCode> {
        Some(ArtifactCode::Store)
    }
    fn file(&self, _: AttemptId, _: &str, _: u64, _: u32) -> bool {
        false
    }
    fn data(&self, _: AttemptId, _: u32, _: &[u8]) -> bool {
        false
    }
    fn end(&self, _: AttemptId, _: &str) -> ArtifactCode {
        ArtifactCode::Store
    }
    fn absent(&self, _: AttemptId, _: &str, _: u8) -> ArtifactCode {
        ArtifactCode::Store
    }
    fn settle(&self, _: AttemptId, _: &str) -> ArtifactCode {
        ArtifactCode::Store
    }
}

pub fn due(decl: &Artifact, passed: bool) -> bool {
    match decl.when {
        ArtifactWhen::Success => passed,
        ArtifactWhen::Failure => !passed,
        ArtifactWhen::Always => true,
    }
}

/// Has exactly `len` bytes and proves the file did not grow: one byte of lookahead, as the send pass does.
fn hash_file(file: &mut std::fs::File, len: u64, buf: &mut [u8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut left = len;
    while left > 0 {
        let take = left.min(buf.len() as u64) as usize;
        let read = match file.read(&mut buf[..take]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => n,
        };
        hasher.update(&buf[..read]);
        left -= read as u64;
    }
    let mut extra = [0u8; 1];
    loop {
        match file.read(&mut extra) {
            Ok(0) => return Ok(*hasher.finalize().as_bytes()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(_) | Err(_) => return Err(std::io::ErrorKind::InvalidData.into()),
        }
    }
}

pub fn capture(workspace: &Path, decl: &Artifact, sink: &dyn Sink, attempt: AttemptId) -> Outcome {
    use sentinel_pipeline::expr::HashFilesError;
    use std::os::unix::fs::MetadataExt;

    if !sink.capable() {
        return Outcome::Failed;
    }
    let patterns: Vec<&str> = decl.paths.iter().map(String::as_str).collect();
    let resolved = match sentinel_pipeline::hash_files::resolve_paths(
        workspace,
        &patterns,
        MAX_ARTIFACT_ENTRIES,
    ) {
        Ok(resolved) => resolved,
        Err(HashFilesError::NoMatch) => {
            return match sink.absent(attempt, &decl.name, 0) {
                ArtifactCode::Absent => Outcome::Absent,
                _ => Outcome::Failed,
            };
        }
        Err(_) => {
            let _ = sink.absent(attempt, &decl.name, 1);
            return Outcome::Failed;
        }
    };
    if let Some(code) = sink.begin(attempt, &decl.name) {
        return refused(code);
    }
    let mut buf = vec![0u8; MAX_ARTIFACT_CHUNK_BYTES];
    let offered = if sink.digests() {
        let mut offered: Vec<Offered> = Vec::with_capacity(resolved.paths.len());
        for path in &resolved.paths {
            // Pin under the resolved root first: a rename after resolve must not smuggle in a symlink.
            let (pinned, meta) = match resolved.pin(path) {
                Ok(pair) => pair,
                Err(_) => {
                    let _ = sink.absent(attempt, &decl.name, 1);
                    return Outcome::Failed;
                }
            };
            if !meta.is_file() {
                let _ = sink.absent(attempt, &decl.name, 1);
                return Outcome::Failed;
            }
            let len = meta.len();
            let digest = match resolved.readable(&pinned).and_then(|mut file| {
                hash_file(&mut file, len, &mut buf)
                    .map_err(|_| HashFilesError::Io("artifact file read failed".into()))
            }) {
                Ok(digest) => digest,
                Err(_) => {
                    let _ = sink.absent(attempt, &decl.name, 1);
                    return Outcome::Failed;
                }
            };
            offered.push(Offered {
                path: path.clone(),
                digest,
                len,
                mode: meta.mode() & 0o777,
            });
        }
        // One batch is always sent, so an artifact with no entries still closes its offer and gets its answer.
        let batches = offered.len().div_ceil(MAX_ARTIFACT_OFFER_ENTRIES).max(1);
        for batch in 0..batches {
            let from = batch * MAX_ARTIFACT_OFFER_ENTRIES;
            let to = (from + MAX_ARTIFACT_OFFER_ENTRIES).min(offered.len());
            if !sink.offer(
                attempt,
                &decl.name,
                &offered[from..to],
                batch + 1 == batches,
            ) {
                sink.settle(attempt, &decl.name);
                return Outcome::Failed;
            }
        }
        Some(offered)
    } else {
        None
    };
    // The answer arrives once, for the whole offer, and holds indexes in path order.
    let mut held = match (&offered, sink.digests()) {
        (Some(_), true) => match sink.held(attempt, &decl.name) {
            Some(mut held) => {
                held.sort_unstable();
                held.dedup();
                held
            }
            None => {
                sink.settle(attempt, &decl.name);
                return Outcome::Failed;
            }
        },
        _ => Vec::new(),
    };
    held.retain(|index| (*index as usize) < resolved.paths.len());
    for (index, path) in resolved.paths.iter().enumerate() {
        if held.binary_search(&(index as u32)).is_ok() {
            continue;
        }
        let (pinned, meta) = match resolved.pin(path) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = sink.absent(attempt, &decl.name, 1);
                return Outcome::Failed;
            }
        };
        if !meta.is_file() {
            let _ = sink.absent(attempt, &decl.name, 1);
            return Outcome::Failed;
        }
        let len = meta.len();
        let mode = meta.mode() & 0o777;
        if !sink.file(attempt, path, len, mode) {
            sink.settle(attempt, &decl.name);
            return Outcome::Failed;
        }
        let mut file = match resolved.readable(&pinned) {
            Ok(file) => file,
            Err(_) => {
                let _ = sink.absent(attempt, &decl.name, 1);
                return Outcome::Failed;
            }
        };
        let mut left = len;
        let mut seq = 0u32;
        let mut io_failed = false;
        while left > 0 {
            let take = left.min(buf.len() as u64) as usize;
            let read = match file.read(&mut buf[..take]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => {
                    io_failed = true;
                    break;
                }
                Ok(n) => n,
            };
            if !sink.data(attempt, seq, &buf[..read]) {
                sink.settle(attempt, &decl.name);
                return Outcome::Failed;
            }
            seq += 1;
            left -= read as u64;
        }
        if io_failed {
            let _ = sink.absent(attempt, &decl.name, 1);
            return Outcome::Failed;
        }
        // One byte of lookahead: a file that grew mid-stream must not pass the length check.
        loop {
            let mut extra = [0u8; 1];
            match file.read(&mut extra) {
                Ok(0) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => {
                    let _ = sink.absent(attempt, &decl.name, 1);
                    return Outcome::Failed;
                }
            }
        }
    }
    match sink.end(attempt, &decl.name) {
        ArtifactCode::Stored => Outcome::Published,
        code => refused(code),
    }
}

fn refused(code: ArtifactCode) -> Outcome {
    match code {
        ArtifactCode::QuotaExceeded => Outcome::QuotaExceeded,
        _ => Outcome::Failed,
    }
}
