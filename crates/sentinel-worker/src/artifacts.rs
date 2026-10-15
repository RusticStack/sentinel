use std::{path::Path, time::Duration};

use sentinel_core::AttemptId;
use sentinel_link::session::ArtifactCode;
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_protocol::limits::{MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_ENTRIES};

pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Sink: Send + Sync {
    fn capable(&self) -> bool;
    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode>;
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

pub fn capture(workspace: &Path, decl: &Artifact, sink: &dyn Sink, attempt: AttemptId) -> Outcome {
    use sentinel_pipeline::expr::HashFilesError;
    use std::io::Read;
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
    if let Some(_code) = sink.begin(attempt, &decl.name) {
        return Outcome::Failed;
    }
    let mut buf = vec![0u8; MAX_ARTIFACT_CHUNK_BYTES];
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
        _ => Outcome::Failed,
    }
}
