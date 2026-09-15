//! D03 worker-side capture: policy selection, confined resolution and the
//! streamed publication protocol, against a scripted `Sink` that records
//! every call and answers on cue.

#![cfg(target_os = "linux")]

use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex};

use sentinel_core::AttemptId;
use sentinel_link::session::ArtifactCode;
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_worker::artifacts::{self, Outcome, Sink};

#[derive(Debug)]
enum Call {
    Begin(String),
    File { path: String, len: u64, mode: u32 },
    Data { seq: u32, bytes: Vec<u8> },
    End(String),
    Absent { name: String, reason: u8 },
    Settle(String),
}

/// A scripted wire: records calls, answers `begin` with `grant`, `end` and
/// `absent` with `verdict`, and fails `data` after `data_fail_at` sends.
struct Scripted {
    grant: Option<ArtifactCode>,
    verdict: ArtifactCode,
    capable: bool,
    data_fail_at: Option<u32>,
    calls: Mutex<Vec<Call>>,
}

impl Scripted {
    fn stored() -> Scripted {
        Scripted {
            grant: None,
            verdict: ArtifactCode::Stored,
            capable: true,
            data_fail_at: None,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

impl Sink for Scripted {
    fn capable(&self) -> bool {
        self.capable
    }
    fn begin(&self, _a: AttemptId, name: &str) -> Option<ArtifactCode> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Begin(name.to_owned()));
        self.grant
    }
    fn file(&self, _a: AttemptId, path: &str, len: u64, mode: u32) -> bool {
        self.calls.lock().unwrap().push(Call::File {
            path: path.to_owned(),
            len,
            mode,
        });
        true
    }
    fn data(&self, _a: AttemptId, seq: u32, bytes: &[u8]) -> bool {
        if self.data_fail_at == Some(seq) {
            return false;
        }
        self.calls.lock().unwrap().push(Call::Data {
            seq,
            bytes: bytes.to_vec(),
        });
        true
    }
    fn end(&self, _a: AttemptId, name: &str) -> ArtifactCode {
        self.calls.lock().unwrap().push(Call::End(name.to_owned()));
        self.verdict
    }
    fn absent(&self, _a: AttemptId, name: &str, reason: u8) -> ArtifactCode {
        self.calls.lock().unwrap().push(Call::Absent {
            name: name.to_owned(),
            reason,
        });
        match reason {
            0 => ArtifactCode::Absent,
            _ => ArtifactCode::CaptureFailed,
        }
    }
    fn settle(&self, _a: AttemptId, name: &str) -> ArtifactCode {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Settle(name.to_owned()));
        self.verdict
    }
}

fn decl(name: &str, paths: &[&str], when: ArtifactWhen, required: bool) -> Artifact {
    Artifact {
        name: name.to_owned(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        when,
        retain_secs: 3600,
        required,
    }
}

fn attempt_id() -> AttemptId {
    AttemptId::new()
}

#[test]
fn capture_policy_selects_on_the_step_verdict() {
    let art = |when| decl("a", &["x"], when, false);
    assert!(artifacts::due(&art(ArtifactWhen::Success), true));
    assert!(!artifacts::due(&art(ArtifactWhen::Success), false));
    assert!(!artifacts::due(&art(ArtifactWhen::Failure), true));
    assert!(artifacts::due(&art(ArtifactWhen::Failure), false));
    assert!(artifacts::due(&art(ArtifactWhen::Always), true));
    assert!(artifacts::due(&art(ArtifactWhen::Always), false));
}

#[test]
fn capture_streams_sorted_files_in_bounded_order() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    // Bigger than one 48 KiB frame, so seq ordering is exercised.
    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(out.join("b.bin"), &big).unwrap();
    fs::write(out.join("a.txt"), "report\n").unwrap();
    fs::write(out.join("empty"), []).unwrap();
    fs::set_permissions(out.join("a.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    // Outside the pattern: never touched.
    fs::write(dir.path().join("secret.txt"), "no\n").unwrap();

    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("dist", &["out/**"], ArtifactWhen::Success, true),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Published);

    let calls = sink.calls();
    assert!(matches!(&calls[0], Call::Begin(n) if n == "dist"));
    assert!(matches!(calls.last(), Some(Call::End(n)) if n == "dist"));
    // Sorted relative paths; the zero-length file declares no data.
    let files: Vec<(&str, u64, u32)> = calls
        .iter()
        .filter_map(|c| match c {
            Call::File { path, len, mode } => Some((path.as_str(), *len, *mode)),
            _ => None,
        })
        .collect();
    assert_eq!(
        files.iter().map(|(p, l, _)| (*p, *l)).collect::<Vec<_>>(),
        vec![("out/a.txt", 7), ("out/b.bin", 150_000), ("out/empty", 0)]
    );
    // The explicitly-set mode survives; the others follow the umask.
    assert_eq!(files[0].2, 0o640);
    // Chunks are seq-ordered per file and reassemble to the content.
    let mut next_seq = None;
    let mut collecting = false;
    let (mut assembled, mut a_txt) = (Vec::new(), Vec::new());
    for c in &calls {
        match c {
            Call::File { path, .. } => {
                next_seq = Some(0);
                collecting = path == "out/b.bin";
            }
            Call::Data { seq, bytes } => {
                assert_eq!(Some(*seq), next_seq);
                next_seq = next_seq.map(|s| s + 1);
                if collecting {
                    assembled.extend_from_slice(bytes);
                } else {
                    a_txt.extend_from_slice(bytes);
                }
            }
            _ => {}
        }
    }
    assert_eq!(a_txt, b"report\n");
    assert_eq!(assembled, big);
}

#[test]
fn no_match_records_absent_and_refusals_fail() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("x"), "1\n").unwrap();
    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("cov", &["coverage/**"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Absent);
    let calls = sink.calls();
    assert_eq!(calls.len(), 1);
    assert!(matches!(&calls[0], Call::Absent { name, reason: 0 } if name == "cov"));

    // A begin the controller refuses is a failed capture, not a stream.
    let sink = Scripted {
        grant: Some(ArtifactCode::NotDeclared),
        ..Scripted::stored()
    };
    let outcome = artifacts::capture(
        dir.path(),
        &decl("x", &["x"], ArtifactWhen::Success, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
    assert!(matches!(sink.calls().as_slice(), [Call::Begin(_)]));

    // A verdict other than Stored closes the capture as failed.
    let sink = Scripted {
        verdict: ArtifactCode::TooLarge,
        ..Scripted::stored()
    };
    let outcome = artifacts::capture(
        dir.path(),
        &decl("x", &["x"], ArtifactWhen::Success, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
}

#[test]
fn escapes_and_unreadable_entries_fail_the_capture() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("keep.txt"), "k\n").unwrap();
    // A symlink out of the workspace: confined resolution must refuse it.
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join("escape")).unwrap();

    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("evil", &["escape"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
    assert!(
        matches!(
            sink.calls().as_slice(),
            [Call::Absent { name, reason: 1 }] if name == "evil"
        ),
        "{:?}",
        sink.calls()
    );

    // A traversal pattern never leaves the patterns' grammar.
    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("up", &["../etc/passwd"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);

    // The same escape mixed into a glob enumeration fails the capture too.
    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("all", &["*"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
}

#[test]
fn a_failed_frame_settles_instead_of_streaming_on() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), vec![7u8; 3]).unwrap();
    let sink = Scripted {
        data_fail_at: Some(0),
        ..Scripted::stored()
    };
    let outcome = artifacts::capture(
        dir.path(),
        &decl("a", &["a"], ArtifactWhen::Success, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
    let calls = sink.calls();
    // begin, file, settle — the failed data send is not recorded and no
    // further frame goes out.
    assert!(matches!(&calls[0], Call::Begin(_)));
    assert!(matches!(&calls[1], Call::File { .. }));
    assert!(matches!(&calls[2], Call::Settle(n) if n == "a"));
    assert_eq!(calls.len(), 3);
}

#[test]
fn incapable_sink_fails_without_walking() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), "x").unwrap();
    let sink = Scripted {
        capable: false,
        ..Scripted::stored()
    };
    let outcome = artifacts::capture(
        dir.path(),
        &decl("a", &["a"], ArtifactWhen::Success, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);
    assert!(sink.calls().is_empty());
    assert_eq!(
        artifacts::capture(
            dir.path(),
            &decl("a", &["a"], ArtifactWhen::Success, false),
            &artifacts::NoSink,
            attempt_id(),
        ),
        Outcome::Failed
    );
}

#[test]
fn required_artifacts_gate_the_verdict_optional_ones_do_not() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("present.txt"), "p\n").unwrap();
    let declarations = [
        decl("must", &["missing/**"], ArtifactWhen::Always, true),
        decl("maybe", &["also-missing/**"], ArtifactWhen::Always, false),
        decl("opt", &["present.txt"], ArtifactWhen::Always, false),
    ];
    let sink = Scripted::stored();
    let failure = sentinel_worker::attempt::capture_artifacts(
        attempt_id(),
        dir.path(),
        &declarations,
        true,
        &sink,
    );
    assert!(
        failure.as_ref().is_some_and(|m| m.contains("must")),
        "{failure:?}"
    );

    // Everything optional: the same outcomes leave the verdict alone.
    let optional = [
        decl("a", &["missing/**"], ArtifactWhen::Always, false),
        decl("b", &["present.txt"], ArtifactWhen::Always, false),
    ];
    let sink = Scripted::stored();
    assert_eq!(
        sentinel_worker::attempt::capture_artifacts(
            attempt_id(),
            dir.path(),
            &optional,
            true,
            &sink,
        ),
        None
    );

    // `when` filters before any capture runs: a success-only artifact does
    // not touch the workspace on a failed attempt.
    let gated = [decl("s", &["present.txt"], ArtifactWhen::Success, true)];
    let sink = Scripted::stored();
    assert_eq!(
        sentinel_worker::attempt::capture_artifacts(attempt_id(), dir.path(), &gated, false, &sink,),
        None
    );
    assert!(sink.calls().is_empty());
}
