//! A manual (unbound) remote is judged before Git connects, and every
//! refusal or failure is the same message: the worker's reach into its own
//! network is never an oracle for a client who names the remote.
#![cfg(unix)]

use std::time::Duration;

use sentinel_git::{Error, checkout};
use sentinel_pipeline::PinnedSource;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn refusal(remote: &str) -> String {
    let work = tempfile::tempdir().unwrap();
    let source = PinnedSource::new(remote, SHA, None).unwrap();
    match checkout(work.path(), &source, None, Duration::from_secs(20)) {
        Err(Error::Preparation(message)) => message,
        other => panic!("{remote}: expected a refusal, got {other:?}"),
    }
}

#[test]
fn internal_destinations_all_get_one_answer_and_leave_no_git_diagnostic() {
    let answers: Vec<String> = [
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1:9/repo.git",
        "https://localhost:9/repo.git",
        "https://metadata/computeMetadata/v1",
        // A public name that does not resolve is indistinguishable from a
        // refused one.
        "https://does-not-exist.invalid.example/repo.git",
    ]
    .into_iter()
    .map(refusal)
    .collect();
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    assert!(!answers[0].contains("fatal"), "{answers:?}");
}
