#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, mpsc},
};

use sentinel_core::AttemptId;
use sentinel_link::session::{ArtifactCode, Offered};
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_worker::artifacts::{self, Outcome, Sink};

#[derive(Debug)]
enum Call {
    Begin(String),
    Offer {
        entries: Vec<(String, [u8; 32], u64)>,
        last: bool,
    },
    Held,
    File {
        path: String,
        len: u64,
        mode: u32,
    },
    Data {
        seq: u32,
        bytes: Vec<u8>,
    },
    End(String),
    Absent {
        name: String,
        reason: u8,
    },
    Settle(String),
}

struct Scripted {
    grant: Option<ArtifactCode>,
    verdict: ArtifactCode,
    capable: bool,
    data_fail_at: Option<u32>,
    /// `None` keeps the bodies-only path every protocol below 12 uses.
    digest_first: Option<Vec<u32>>,
    offer_refused: bool,
    held_missing: bool,
    calls: Mutex<Vec<Call>>,
}

impl Scripted {
    fn stored() -> Scripted {
        Scripted {
            grant: None,
            verdict: ArtifactCode::Stored,
            capable: true,
            data_fail_at: None,
            digest_first: None,
            offer_refused: false,
            held_missing: false,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn digests(held: Vec<u32>) -> Scripted {
        Scripted {
            digest_first: Some(held),
            ..Scripted::stored()
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
    fn digests(&self) -> bool {
        self.digest_first.is_some()
    }
    fn offer(&self, _a: AttemptId, _name: &str, entries: &[Offered], last: bool) -> bool {
        self.calls.lock().unwrap().push(Call::Offer {
            entries: entries
                .iter()
                .map(|e| (e.path.clone(), e.digest, e.len))
                .collect(),
            last,
        });
        !self.offer_refused
    }
    fn held(&self, _a: AttemptId, _name: &str) -> Option<Vec<u32>> {
        self.calls.lock().unwrap().push(Call::Held);
        if self.held_missing {
            return None;
        }
        self.digest_first.clone()
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
        class: None,
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

/// A publication held inside the link, so the test decides when it may finish.
struct Gated {
    reached: mpsc::Sender<()>,
    go: Mutex<mpsc::Receiver<()>>,
}

impl Sink for Gated {
    fn capable(&self) -> bool {
        true
    }
    fn begin(&self, _a: AttemptId, _name: &str) -> Option<ArtifactCode> {
        self.reached.send(()).unwrap();
        self.go.lock().unwrap().recv().unwrap();
        None
    }
    fn file(&self, _a: AttemptId, _path: &str, _len: u64, _mode: u32) -> bool {
        true
    }
    fn data(&self, _a: AttemptId, _seq: u32, _bytes: &[u8]) -> bool {
        true
    }
    fn end(&self, _a: AttemptId, _name: &str) -> ArtifactCode {
        ArtifactCode::Stored
    }
    fn absent(&self, _a: AttemptId, _name: &str, _reason: u8) -> ArtifactCode {
        ArtifactCode::Store
    }
    fn settle(&self, _a: AttemptId, _name: &str) -> ArtifactCode {
        ArtifactCode::Store
    }
}

fn step(id: &str) -> sentinel_pipeline::schema::Step {
    sentinel_pipeline::schema::Step {
        id: id.to_owned(),
        run: "true".to_owned(),
        condition: None,
        shell: sentinel_pipeline::schema::Shell::Sh,
        env: Vec::new(),
        secrets: Vec::new(),
        secret_files: Vec::new(),
        workdir: None,
        timeout_secs: None,
        outputs: Vec::new(),
    }
}

#[test]
fn a_step_trigger_never_publishes_at_finalization() {
    let art = decl("dist", &["out/**"], ArtifactWhen::Step(0), true);
    assert!(!artifacts::due(&art, true));
    assert!(!artifacts::due(&art, false));
    assert_eq!(art.when.step(), Some(0));
    assert_eq!(ArtifactWhen::Always.step(), None);
}

/// The step's end starts the upload and returns: the steps after it run while the link is still taking the file.
#[test]
fn a_step_publication_returns_before_the_upload_finishes_and_is_joined_at_finalization() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("out")).unwrap();
    fs::write(dir.path().join("out/a.txt"), "alpha").unwrap();
    let (reached, reached_rx) = mpsc::channel();
    let (go, go_rx) = mpsc::channel();
    let sink: Arc<dyn Sink> = Arc::new(Gated {
        reached,
        go: Mutex::new(go_rx),
    });
    let declared = [decl("dist", &["out/**"], ArtifactWhen::Step(0), true)];
    let mut publications = artifacts::StepPublications::default();
    publications.publish(0, &declared[0], dir.path(), &sink, attempt_id());

    // The publication is inside the link and this thread is free: that is the overlap with later steps.
    reached_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the publication never started");
    go.send(()).unwrap();

    assert_eq!(publications.settle(&declared, &[step("build")], true), None);
}

#[test]
fn a_required_step_artifact_is_reported_when_its_step_never_completed() {
    let declared = [decl("dist", &["out/**"], ArtifactWhen::Step(1), true)];
    let steps = [step("build"), step("package")];
    let mut publications = artifacts::StepPublications::default();
    let failure = publications
        .settle(&declared, &steps, true)
        .expect("a required artifact whose step never ran");
    assert!(
        failure.contains("step `package` did not complete"),
        "{failure}"
    );
    assert_eq!(
        publications.settle(&declared, &steps, false),
        None,
        "a job already failing on a step is not failed again for its artifact"
    );
}

#[test]
fn a_failed_step_publication_of_a_required_artifact_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("present.txt"), "p\n").unwrap();
    let scripted = Arc::new(Scripted {
        verdict: ArtifactCode::CaptureFailed,
        ..Scripted::stored()
    });
    let sink: Arc<dyn Sink> = scripted.clone();
    let declared = [decl("dist", &["present.txt"], ArtifactWhen::Step(0), true)];
    let mut publications = artifacts::StepPublications::default();
    publications.publish(0, &declared[0], dir.path(), &sink, attempt_id());
    let failure = publications
        .settle(&declared, &[step("build")], true)
        .expect("a required artifact that did not publish");
    assert!(failure.contains("required artifact `dist`"), "{failure}");
}

#[test]
fn capture_streams_sorted_files_in_bounded_order() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(out.join("b.bin"), &big).unwrap();
    fs::write(out.join("a.txt"), "report\n").unwrap();
    fs::write(out.join("empty"), []).unwrap();
    fs::set_permissions(out.join("a.txt"), fs::Permissions::from_mode(0o640)).unwrap();
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
    assert_eq!(files[0].2, 0o640);
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

    let sink = Scripted::stored();
    let outcome = artifacts::capture(
        dir.path(),
        &decl("up", &["../etc/passwd"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Failed);

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

    let gated = [decl("s", &["present.txt"], ArtifactWhen::Success, true)];
    let sink = Scripted::stored();
    assert_eq!(
        sentinel_worker::attempt::capture_artifacts(attempt_id(), dir.path(), &gated, false, &sink,),
        None
    );
    assert!(sink.calls().is_empty());
}

#[test]
fn capture_offers_every_file_by_content_and_sends_only_the_missing_bodies() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("out")).unwrap();
    fs::write(dir.path().join("out/a.txt"), "alpha").unwrap();
    fs::write(dir.path().join("out/m.txt"), "middle").unwrap();
    fs::write(dir.path().join("out/z.txt"), "zeta").unwrap();

    let sink = Scripted::digests(vec![1]);
    let outcome = artifacts::capture(
        dir.path(),
        &decl("dist", &["out/**"], ArtifactWhen::Always, false),
        &sink,
        attempt_id(),
    );
    assert_eq!(outcome, Outcome::Published);

    let calls = sink.calls();
    match &calls[1] {
        Call::Offer { entries, last } => {
            assert!(*last);
            assert_eq!(
                entries
                    .iter()
                    .map(|(path, digest, len)| { (path.as_str(), *digest, *len) })
                    .collect::<Vec<_>>(),
                [
                    ("out/a.txt", *blake3::hash(b"alpha").as_bytes(), 5),
                    ("out/m.txt", *blake3::hash(b"middle").as_bytes(), 6),
                    ("out/z.txt", *blake3::hash(b"zeta").as_bytes(), 4),
                ]
            );
        }
        other => panic!("the offer came second: {other:?}"),
    }
    assert!(matches!(calls[2], Call::Held));
    let paths: Vec<&str> = calls
        .iter()
        .filter_map(|call| match call {
            Call::File { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(paths, ["out/a.txt", "out/z.txt"]);
    // Everything else is the body path protocol 11 already used.
    assert!(matches!(calls.last(), Some(Call::End(name)) if name == "dist"));
}

#[test]
fn capture_fails_when_the_offer_or_its_answer_does_not_come() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), "a").unwrap();

    let refused = Scripted {
        offer_refused: true,
        ..Scripted::digests(Vec::new())
    };
    assert_eq!(
        artifacts::capture(
            dir.path(),
            &decl("dist", &["a.txt"], ArtifactWhen::Always, false),
            &refused,
            attempt_id(),
        ),
        Outcome::Failed
    );
    // A refused offer settles the artifact instead of leaving it in flight on the controller.
    assert!(matches!(refused.calls().last(), Some(Call::Settle(_))));

    let silent = Scripted {
        held_missing: true,
        ..Scripted::digests(Vec::new())
    };
    assert_eq!(
        artifacts::capture(
            dir.path(),
            &decl("dist", &["a.txt"], ArtifactWhen::Always, false),
            &silent,
            attempt_id(),
        ),
        Outcome::Failed
    );
    assert!(
        !silent
            .calls()
            .iter()
            .any(|call| matches!(call, Call::File { .. }))
    );
}
