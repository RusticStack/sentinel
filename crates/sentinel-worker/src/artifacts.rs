//! Artifact capture (D03): resolve a job's declared artifacts against the
//! live workspace and publish them over the link before finalization tears
//! anything down.
//!
//! Matching is the `hash_files` confined walk — one pinned root descriptor,
//! `openat2` with `BENEATH | NO_SYMLINKS | NO_XDEV`, bounded depth, visit,
//! count and byte limits — so a path pattern can never read outside the
//! workspace or follow a planted symlink. Files stream to the controller in
//! bounded chunks; the object store hashes and verifies them on arrival, so
//! the worker never buffers an artifact.
//!
//! Every capture ends in one terminal verdict from the controller: stored,
//! recorded absent or failed, or refused. Nothing is retried here — a run's
//! artifacts are an output of its attempt, not a queue.

use std::{path::Path, time::Duration};

use sentinel_core::AttemptId;
use sentinel_link::session::ArtifactCode;
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_protocol::limits::{MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_ENTRIES};

/// How long a publication waits for the controller's answer before the
/// capture is called failed. The session's own liveness is much shorter —
/// a detached link answers `Store` at once — so this only bounds a live
/// but unresponsive controller.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// What the executor provides for artifact publication: the wire to the
/// controller. All calls are ordered per attempt; `begin`/`end`/`absent`
/// block, bounded by [`REPLY_TIMEOUT`], for the controller's answer.
pub trait Sink: Send + Sync {
    /// Whether the current session can carry artifacts at all (protocol 4).
    fn capable(&self) -> bool;
    /// Send `ArtifactBegin` and await the answer: `None` grants the stream,
    /// `Some(code)` closed it with a terminal verdict.
    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode>;
    /// Declare the next file; `len` bytes of `data` follow it, `seq` from 0.
    /// `false` means the stream already failed — [`Sink::settle`] has the code.
    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool;
    /// One ordered chunk of the open file. `false` means the stream already
    /// failed — [`Sink::settle`] has the code.
    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool;
    /// Send `ArtifactEnd` and await the terminal verdict.
    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode;
    /// Send `ArtifactAbsent` (`reason` 0 = no paths matched, 1 = capture
    /// failed), abandoning any in-flight stream of the same name, and await
    /// the verdict.
    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode;
    /// Await the verdict of a publication whose send already failed: the
    /// controller's answer if one arrived, `Store` otherwise.
    fn settle(&self, attempt: AttemptId, name: &str) -> ArtifactCode;
}

/// How one declared artifact ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Files were published and committed controller-side.
    Published,
    /// The declaration matched no files.
    Absent,
    /// Resolution, workspace IO or the verdict failed the capture.
    Failed,
}

/// A sink for attempts without a link: every capture fails and nothing
/// blocks. Tests and the non-Linux stub use it.
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

/// Whether `decl` captures under the step verdict: success artifacts after
/// a pass, failure artifacts after any failure, `always` either way —
/// including a canceled run, whose workspace still exists at capture time.
pub fn due(decl: &Artifact, passed: bool) -> bool {
    match decl.when {
        ArtifactWhen::Success => passed,
        ArtifactWhen::Failure => !passed,
        ArtifactWhen::Always => true,
    }
}

/// Resolve `decl.paths` inside `workspace` and publish the matched files.
/// Any mid-flight failure is settled through the sink so the controller's
/// verdict — not the local guess — decides the outcome.
pub fn capture(workspace: &Path, decl: &Artifact, sink: &dyn Sink, attempt: AttemptId) -> Outcome {
    use sentinel_pipeline::expr::HashFilesError;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    if !sink.capable() {
        // The session cannot carry artifacts at all; nothing is recorded.
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
                // The record could not be delivered; nothing is published
                // and nothing claims otherwise.
                _ => Outcome::Failed,
            };
        }
        // A pattern, traversal or limit failure is a capture failure.
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
        // Pin beneath the resolved root first: the descriptor classifies
        // the entry, so a rename between resolve and read cannot smuggle
        // a symlink into the artifact.
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
        let mode = meta.mode() & 0o7777;
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
                    // Shrank beneath us, or the read failed: either way the
                    // declared length can no longer be proven.
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
        // One byte of lookahead: a file that grew mid-stream cannot stand
        // in for what the length check declared.
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
