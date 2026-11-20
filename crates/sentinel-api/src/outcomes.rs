//! Reads a finished attempt's own test reports once, off the request path, and keeps one row per test.
//!
//! The controller does this here rather than on a request because the flaky list must not depend on anyone
//! opening a failure view: the attempt's queue row is written in its terminal transaction, and this pass
//! turns it into named outcomes and takes the row in the same transaction. What the pass reads is bounded
//! the same way the failure view's own report reading is: at most four files of 4 MiB and one 4 MiB log
//! page per attempt, at most [`sentinel_store::outcomes::MAX_QUEUE_BATCH`] attempts a round, and expiry of
//! the rows follows the log retention they were parsed beside.

use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, Weak},
    time::Duration,
};

use sentinel_core::UnixMillis;
use sentinel_protocol::diagnostics::{
    self as diag, MAX_PARSER_TEST_OUTCOMES, ReportFormat, StepReference, TestOutcome, TestStatus,
};
use sentinel_protocol::logs::Stream;
use sentinel_store::{
    Store, artifacts,
    logs::{LogStore, Page},
    objects::{Kind, Objects},
    outcomes,
};

use crate::evidence::detect_diagnostic_format;

/// How often an idle controller looks. Nothing is read when the queue is empty and nothing has expired.
pub(crate) const EVERY: Duration = Duration::from_secs(60);
/// Rounds one pass takes while it finds a full batch, so a burst catches up without holding the writer for
/// a whole backlog.
const ROUNDS: u32 = 8;
const EXPIRY_BATCH: u32 = 2_000;
const MAX_REPORT_ARTIFACTS: usize = 8;
/// Report files one attempt may contribute.
const MAX_REPORT_FILES: usize = 4;
/// A JUnit file longer than this parses as truncated, exactly as the failure view reads it.
const JUNIT_READ_BYTES: u64 = 4 << 20;
const LOG_PAGE_FRAMES: usize = 1_024;
const LOG_PAGE_BYTES: u64 = 4 << 20;

pub(crate) fn start(
    store: Weak<Store>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    every: Duration,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("sentinel-api-test-outcomes".into())
        .spawn(move || run(&store, &logs, &objects, every))?;
    Ok(())
}

fn run(store: &Weak<Store>, logs: &LogStore, objects: &Objects, every: Duration) {
    loop {
        std::thread::sleep(every);
        let Some(store) = store.upgrade() else {
            return;
        };
        if let Err(error) = pass(&store, logs, objects) {
            tracing::warn!(
                event = "test_outcomes_failed",
                %error,
                "the test-outcome pass failed; the queue keeps what it could not read"
            );
        }
    }
}

fn pass(store: &Store, logs: &LogStore, objects: &Objects) -> sentinel_store::Result<()> {
    for _ in 0..ROUNDS {
        let due = store.read(|c| outcomes::queued(c, outcomes::MAX_QUEUE_BATCH))?;
        if due.is_empty() {
            break;
        }
        let full = due.len() as u32 >= outcomes::MAX_QUEUE_BATCH;
        for (queued, sha) in due {
            let found = reports(store, logs, objects, &queued)?;
            let at_ms = queued.at_ms;
            store.writer().write(move |tx| {
                let rows: Vec<outcomes::Outcome<'_>> = found
                    .iter()
                    .map(|outcome| outcomes::Outcome {
                        identity: &outcome.identity,
                        suite: outcome.suite.as_deref(),
                        name: &outcome.name,
                        status: status(outcome.status),
                    })
                    .collect();
                outcomes::ingest(
                    tx,
                    &outcomes::Attempt {
                        tenant: queued.tenant,
                        repo: queued.repo,
                        attempt: queued.attempt,
                        sha: &sha,
                    },
                    at_ms,
                    &rows,
                )
            })?;
        }
        if !full {
            break;
        }
    }
    // A row lives exactly as long as the log the report was read beside, so a repository's history here is
    // the history its logs still cover.
    let before = UnixMillis::now()
        .0
        .saturating_sub(objects.deployment().log_retention_ms);
    for _ in 0..ROUNDS {
        let removed = store
            .writer()
            .write(move |tx| outcomes::expire(tx, before, EXPIRY_BATCH))?;
        if removed < EXPIRY_BATCH as usize {
            break;
        }
    }
    Ok(())
}

const fn status(status: TestStatus) -> outcomes::Status {
    match status {
        TestStatus::Passed => outcomes::Status::Passed,
        TestStatus::Failed => outcomes::Status::Failed,
        TestStatus::Skipped => outcomes::Status::Skipped,
    }
}

/// Every test the attempt's own reports name, one entry per identity. A file that does not parse contributes
/// nothing: the list is a record of what the reports stated, never a guess, and the attempt's queue row is
/// taken either way so a report that will never parse cannot hold the pass. A store that cannot be read is
/// the one thing that fails the attempt, so its queue row stays and the next pass tries again.
fn reports(
    store: &Store,
    logs: &LogStore,
    objects: &Objects,
    queued: &outcomes::Queued,
) -> sentinel_store::Result<Vec<TestOutcome>> {
    let mut merged: Vec<TestOutcome> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (bytes, format) in artifact_reports(store, objects, queued)? {
        let parsed = match format {
            ReportFormat::JunitXml => diag::parse_junit_xml(&bytes, None),
            _ => diag::parse_go_test_json(
                &bytes,
                StepReference {
                    index: 0,
                    key: None,
                },
            ),
        };
        merge(&mut merged, &mut seen, &parsed);
    }
    if let Some(bytes) = log_page(logs, queued)
        && detect_diagnostic_format(&bytes) == Some(ReportFormat::GoTestJson)
    {
        let step = StepReference {
            index: 0,
            key: None,
        };
        merge(
            &mut merged,
            &mut seen,
            &diag::parse_go_test_json(&bytes, step),
        );
    }
    Ok(merged)
}

/// One test per identity across every report of one attempt: a test that failed somewhere in the attempt
/// has failed, whatever another file said about it.
fn merge(
    merged: &mut Vec<TestOutcome>,
    seen: &mut HashMap<String, usize>,
    parsed: &diag::ParseResult,
) {
    for outcome in &parsed.outcomes {
        let Some(&at) = seen.get(&outcome.identity) else {
            if merged.len() == MAX_PARSER_TEST_OUTCOMES {
                continue;
            }
            seen.insert(outcome.identity.clone(), merged.len());
            merged.push(outcome.clone());
            continue;
        };
        let kept = &mut merged[at];
        if rank(outcome.status) > rank(kept.status) {
            kept.status = outcome.status;
        }
    }
}

const fn rank(status: TestStatus) -> u8 {
    match status {
        TestStatus::Failed => 2,
        TestStatus::Passed => 1,
        TestStatus::Skipped => 0,
    }
}

/// The attempt's captured report files, as bytes, bounded as the failure view bounds them: at most four
/// files, each read up to its own limit. The artifact bytes are the repository's own claim and are never
/// redacted, so they are read here only to be reduced to names and statuses.
fn artifact_reports(
    store: &Store,
    objects: &Objects,
    queued: &outcomes::Queued,
) -> sentinel_store::Result<Vec<(Vec<u8>, ReportFormat)>> {
    store.read(|c| {
        let mut out = Vec::new();
        let captured = artifacts::captured_for_attempt(
            c,
            queued.tenant,
            queued.attempt,
            MAX_REPORT_ARTIFACTS,
        )?;
        for (name, version) in captured {
            let manifest = match objects.manifest(
                c,
                queued.tenant,
                Kind::Artifact,
                &artifacts::manifest_name(queued.job, &name),
                Some(version),
            ) {
                Ok(manifest) => manifest,
                Err(sentinel_store::Error::NotFound) => continue,
                Err(error) => return Err(error),
            };
            for entry in &manifest.entries {
                let Some((limit, format)) = report_limit(&entry.path) else {
                    continue;
                };
                if out.len() == MAX_REPORT_FILES {
                    return Ok(out);
                }
                match objects.open_read(c, queued.tenant, entry.digest) {
                    Ok((reader, len)) => {
                        let mut bytes = Vec::with_capacity(len.min(limit) as usize);
                        if reader.take(limit).read_to_end(&mut bytes).is_ok() {
                            out.push((bytes, format));
                        }
                    }
                    Err(sentinel_store::Error::NotFound | sentinel_store::Error::Corrupt(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(out)
    })
}

/// The read limit of a report file whose name states one of the two formats the flaky list parses.
fn report_limit(path: &str) -> Option<(u64, ReportFormat)> {
    let name = path.rsplit('/').next()?;
    if name == "junit.xml"
        || name.ends_with(".junit.xml")
        || (name.starts_with("TEST-") && name.ends_with(".xml"))
    {
        Some((JUNIT_READ_BYTES, ReportFormat::JunitXml))
    } else if name == "go-test.json" || name.ends_with(".go-test.json") {
        Some((LOG_PAGE_BYTES, ReportFormat::GoTestJson))
    } else {
        None
    }
}

/// The first page of the attempt's own log: where a `go test -json` stream states its outcomes. One page,
/// read once, so an attempt whose log is longer than the bound is read to the bound and no further.
fn log_page(logs: &LogStore, queued: &outcomes::Queued) -> Option<Vec<u8>> {
    let tail = logs
        .tail_page(
            queued.run,
            queued.job,
            queued.attempt,
            0,
            Page {
                limit: LOG_PAGE_FRAMES,
                bytes: LOG_PAGE_BYTES,
                scan: LOG_PAGE_BYTES,
            },
            None,
        )
        .ok()?;
    let size = tail
        .frames
        .iter()
        .filter(|frame| frame.stream == Stream::Stdout)
        .map(|frame| frame.bytes.len())
        .sum();
    let mut bytes = Vec::with_capacity(size);
    for frame in &tail.frames {
        if frame.stream == Stream::Stdout {
            bytes.extend_from_slice(&frame.bytes);
        }
    }
    Some(bytes)
}
