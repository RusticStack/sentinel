//! Report files need `artifacts:read` because artifact bytes are not redacted.

use std::io::Read;

use sentinel_core::{
    AttemptId, JobId, RunId, TenantId,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::{
    cursor::{Cursor, Seq, StreamKind},
    diagnostics::{
        self as diag, CollectionSource, Diagnostic, DiagnosticReport, EvidenceFreshness,
        EvidenceReference, EvidenceStream, FramePosition, ParseResult, Producer, Provenance,
        ReportFormat, Severity, StepReference,
    },
    error::ErrorCode,
    logs::{Frame, Stream},
    summary::{AttemptSummary, StepOutcome},
};
use sentinel_store::{
    Connection, Error as StoreError, artifacts, auth as authz, dispatch, logs, lookup,
    objects::{Kind, Reader},
    status,
};
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Value, json};

use super::{
    ApiError, Request, Route, State, auth, err, id, identify, ok, query_param, store_error,
    stream_name,
};

const DEFAULT_BUDGET: usize = 8 << 10;
const MAX_BUDGET: usize = 64 << 10;
/// With no `budget` the whole body, not only its text, stays within the plan's 8 KiB failure view.
const DEFAULT_BODY_BYTES: usize = 8 << 10;
/// A capped diagnostic message keeps at least its first bytes, where Go, Cargo and JUnit put the assertion.
const KEPT_MESSAGE_BYTES: usize = 256;
const MAX_DIAGNOSTICS: usize = 20;
const SCAN_FRAMES: usize = 1_024;
const TAIL_FRAMES: usize = 128;
const PAGE_BYTES: u64 = 4 << 20;
/// Decode bound: the sparse index starts the read within one checkpoint, so only a damaged index reaches it.
const NEWEST_SCAN_BYTES: u64 = 16 << 20;
const MAX_REPORT_ARTIFACTS: usize = 8;
const MAX_REPORT_FILES: usize = 4;
const JUNIT_READ_BYTES: u64 = 4 << 20;

pub(super) fn attempt_failure(
    state: &State,
    request: &Request,
    attempt: &str,
    query: &str,
) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
    let explicit = query_param(query, "budget").is_some();
    let budget = match query_param(query, "budget") {
        None => DEFAULT_BUDGET,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|size| (1..=MAX_BUDGET).contains(size))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("budget must be 1..{MAX_BUDGET} bytes"),
                )
            })?,
    };
    let diagnostic_limit = match query_param(query, "limit") {
        None => MAX_DIAGNOSTICS,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|size| (1..=MAX_DIAGNOSTICS).contains(size))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("limit must be 1..{MAX_DIAGNOSTICS}"),
                )
            })?,
    };
    let collect_files = who.scopes.contains(Scopes::ARTIFACTS_READ);
    let (tenant, run, job, summary_bytes, attempt_status, files) = state
        .store
        .read(|c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            let tenant = authz::require_repo(c, who.principal, repo, Permissions::READ)?;
            let bytes = dispatch::attempt_summary(c, tenant, attempt)?;
            let status = status::attempt_job_status(c, tenant, attempt)?;
            let files = if collect_files {
                report_files(state, c, tenant, job, attempt)?
            } else {
                ReportFiles::default()
            };
            Ok((tenant, run, job, bytes, status, files))
        })
        .map_err(store_error)?;
    let summary = summary_bytes
        .as_deref()
        .map(AttemptSummary::decode)
        .transpose()
        .map_err(|_| err(ErrorCode::Internal, "stored summary unreadable"))?;
    let summary = summary.unwrap_or_default();
    // Job status describes only the attempt that still owns the job; older attempts must not inherit it.
    let current_attempt = attempt_status.current;
    let step = summary.steps.iter().find(|record| {
        matches!(
            record.outcome,
            StepOutcome::Failed { .. }
                | StepOutcome::Signaled { .. }
                | StepOutcome::OutOfMemory
                | StepOutcome::TimedOut
                | StepOutcome::Runtime
        )
    });

    let explicit_after = query_param(query, "after")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| err(ErrorCode::InvalidRequest, "malformed after"))
        })
        .transpose()?;
    let explicit_cursor = query_param(query, "cursor");
    let after = match (explicit_after, explicit_cursor) {
        (Some(_), Some(_)) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "after and cursor are exclusive",
            ));
        }
        (Some(after), None) => Some(after),
        (None, Some(text)) => Some(
            Cursor::parse(text, tenant)
                .ok()
                .filter(|cursor| {
                    cursor.kind == StreamKind::AttemptLog && cursor.stream == *attempt.as_bytes()
                })
                .ok_or_else(|| err(ErrorCode::InvalidCursor, "invalid cursor"))?
                .seq
                .0,
        ),
        (None, None) => None,
    };
    let page_after = after.unwrap_or(0);
    let failure_step = step.map(|record| record.index);
    let scan = failure_log_page(
        state,
        run,
        job,
        attempt,
        page_after,
        logs::Page {
            limit: SCAN_FRAMES,
            bytes: PAGE_BYTES,
            scan: PAGE_BYTES,
        },
        failure_step,
    )?;
    let scan_cut = scan.next_after.is_some();
    let newest = if scan_cut || (page_after > 0 && scan.frames.is_empty()) {
        newest_log_page(state, run, job, attempt, failure_step)?
    } else {
        None
    };
    let step_reference = step.map(|record| StepReference {
        index: record.index,
        key: Some(record.id.clone()),
    });
    let mut reports = Reports::default();
    log_reports(
        &mut reports,
        &scan.frames,
        0,
        LogScope {
            run,
            job,
            attempt,
            step_index: failure_step.or_else(|| scan.frames.last().map(|frame| frame.step)),
            step_reference: step_reference.clone(),
            complete: page_after == 0 && !scan_cut && scan.complete && scan.gaps.is_empty(),
        },
    );
    if after.is_none()
        && let (Some(from), Some(newest)) = (scan.next_after, newest.as_ref())
    {
        log_reports(
            &mut reports,
            &newest.frames,
            from,
            LogScope {
                run,
                job,
                attempt,
                step_index: failure_step.or_else(|| newest.frames.last().map(|frame| frame.step)),
                step_reference,
                complete: false,
            },
        );
    }
    let artifact_status = if collect_files {
        let (collected, skipped) = (files.files.len(), files.skipped);
        file_reports(&mut reports, files, run, job, attempt, &summary);
        json!({ "status": "collected", "files": collected, "skipped_files": skipped })
    } else {
        json!({ "status": "scope_required", "scope": "artifacts:read" })
    };

    let mut remaining = budget;
    let mut included = 0usize;
    let mut truncated = page_after > 0 || scan_cut;
    let mut omitted_diagnostics = reports.omitted.saturating_add(
        reports
            .items
            .iter()
            .map(|item| item.parse.omitted_diagnostics)
            .sum::<u64>(),
    );
    let mut kept: Vec<Vec<Option<Diagnostic>>> = reports
        .items
        .iter_mut()
        .map(|item| item.report.diagnostics.drain(..).map(Some).collect())
        .collect();
    let mut selected: Vec<Vec<bool>> = kept.iter().map(|items| vec![false; items.len()]).collect();
    for primary in [true, false] {
        for (items, chosen) in kept.iter_mut().zip(selected.iter_mut()) {
            for (slot, chosen) in items.iter_mut().zip(chosen.iter_mut()) {
                let Some(diagnostic) = slot.as_mut() else {
                    continue;
                };
                if matches!(diagnostic.severity, Severity::Error | Severity::Failure) != primary {
                    continue;
                }
                if included >= diagnostic_limit {
                    *slot = None;
                    omitted_diagnostics = omitted_diagnostics.saturating_add(1);
                    truncated = true;
                    continue;
                }
                if let std::borrow::Cow::Owned(text) = diag::display_text(&diagnostic.message) {
                    diagnostic.message = text;
                }
                truncated |= diagnostic_text_len(diagnostic) > remaining;
                if fit_diagnostic_text(diagnostic, &mut remaining) {
                    included += 1;
                    *chosen = true;
                } else {
                    *slot = None;
                    omitted_diagnostics = omitted_diagnostics.saturating_add(1);
                    truncated = true;
                }
            }
        }
    }
    let mut report_values = Vec::with_capacity(reports.items.len());
    for ((mut item, items), chosen) in reports.items.into_iter().zip(kept).zip(selected) {
        item.report.diagnostics = items
            .into_iter()
            .zip(chosen)
            .filter_map(|(slot, chosen)| slot.filter(|_| chosen))
            .collect();
        truncated |= !item.parse.complete
            || item.parse.omitted_diagnostics > 0
            || item.report.freshness == EvidenceFreshness::Incomplete;
        let mut value = json!({
            "report": item.report,
            "parse": {
                "complete": item.parse.complete,
                "malformed_records": item.parse.malformed_records,
                "omitted_diagnostics": item.parse.omitted_diagnostics,
                "bytes_scanned": item.parse.bytes_scanned,
            }
        });
        if let Some((first, last)) = item.window {
            value["window"] = json!({ "first_sequence": first, "last_sequence": last });
        }
        if let Some((artifact, path)) = item.artifact {
            value["artifact"] = json!({ "name": artifact, "path": path });
        }
        report_values.push(value);
    }

    let log_view = newest.as_ref().unwrap_or(&scan);
    let source = &log_view.frames;
    let shown_from = source.len().saturating_sub(TAIL_FRAMES);
    truncated |= shown_from > 0;
    let mut frames = Vec::with_capacity((source.len() - shown_from).min(16));
    let mut binary: Option<BinaryRun> = None;
    for frame in source[shown_from..].iter().rev() {
        if looks_binary(&frame.bytes) {
            match binary.as_mut() {
                Some(run) if run.step == frame.step && run.stream == frame.stream => {
                    run.first = frame.seq;
                    run.bytes += frame.bytes.len() as u64;
                }
                _ => {
                    if let Some(run) = binary.take() {
                        frames.push(run.json());
                    }
                    binary = Some(BinaryRun {
                        first: frame.seq,
                        last: frame.seq,
                        step: frame.step,
                        stream: frame.stream,
                        bytes: frame.bytes.len() as u64,
                    });
                }
            }
            continue;
        }
        if let Some(run) = binary.take() {
            frames.push(run.json());
        }
        if remaining == 0 {
            truncated = true;
            break;
        }
        let (text, cut) = bounded_log_suffix(&frame.bytes, remaining);
        if text.is_empty() {
            continue;
        }
        remaining = remaining.saturating_sub(text.len());
        truncated |= cut;
        frames.push(json!({
            "sequence": frame.seq,
            "step": frame.step,
            "stream": stream_name(frame.stream),
            "text": text,
        }));
    }
    if let Some(run) = binary.take() {
        frames.push(run.json());
    }
    frames.reverse();
    let next_cursor = scan.next_after.map(|sequence| Cursor {
        tenant,
        kind: StreamKind::AttemptLog,
        stream: *attempt.as_bytes(),
        seq: Seq(sequence),
    });
    let log_gaps_truncated = log_view.gaps.len() > sentinel_protocol::logs::MAX_GAPS;
    truncated |= log_gaps_truncated;
    let mut body = json!({
        "schema": "sentinel.failure/1",
        "attempt": attempt.to_string(),
        "run": run.to_string(),
        "job": job.to_string(),
        "authoritative": {
            "current_attempt": current_attempt,
            "job_state": attempt_status.state.map(|state| state.as_str()),
            "failure_class": attempt_status.failure_class.map(|class| class.as_str()),
        },
        "failed_step": step.map(|record| json!({
            "index": record.index,
            "id": record.id,
            "outcome": step_outcome_name(record.outcome),
            "exit_code": match record.outcome {
                StepOutcome::Failed { code } => Some(code),
                _ => None,
            },
            "signal": match record.outcome {
                StepOutcome::Signaled { signal } => Some(signal),
                _ => None,
            },
        })),
        "timings_ns": {
            "checkout": summary.checkout_ns,
            "image_pull": summary.image_pull_ns,
            "container_start": summary.container_start_ns,
            "steps": summary.steps_ns,
            "finalize": summary.finalize_ns,
        },
        "cache": summary.caches.iter().map(|cache| json!({
            "name": cache.name,
            "outcome": cache.outcome,
            "bytes": cache.bytes,
            "copied_bytes": cache.copied_bytes,
            "dirty_bytes": cache.dirty_bytes,
            "publish": cache.publish,
        })).collect::<Vec<_>>(),
        "reports": report_values,
        "artifact_reports": artifact_status,
        "tail": { "frames": frames },
        "budget_bytes": budget,
        "text_bytes": budget - remaining,
        "truncated": truncated,
        "omitted_diagnostics": omitted_diagnostics,
        "log_complete": log_view.complete && log_view.gaps.is_empty(),
        "log_gaps": log_view.gaps.iter().take(sentinel_protocol::logs::MAX_GAPS).collect::<Vec<_>>(),
        "log_gaps_truncated": log_gaps_truncated,
        "next_cursor": next_cursor.map(|cursor| cursor.to_string()),
    });
    cap_failure_json(
        &mut body,
        if explicit {
            MAX_BUDGET
        } else {
            DEFAULT_BODY_BYTES
        },
    );
    recount_failure_text(&mut body);
    ok(body)
}

fn failure_log_page(
    state: &State,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    after: u64,
    page: logs::Page,
    step: Option<u32>,
) -> Result<logs::Tail, ApiError> {
    state
        .logs
        .tail_page(run, job, attempt, after, page, step)
        .or_else(|error| match error {
            StoreError::NotFound => state.logs.tail_legacy_page(attempt, after, page, step),
            other => Err(other),
        })
        .or_else(|error| match error {
            StoreError::NotFound => Ok(logs::Tail {
                frames: Vec::new(),
                complete: false,
                gaps: Vec::new(),
                next_after: None,
                step_done: false,
            }),
            other => Err(other),
        })
        .map_err(store_error)
}

fn newest_log_page(
    state: &State,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    step: Option<u32>,
) -> Result<Option<logs::Tail>, ApiError> {
    match state.logs.newest_page(
        run,
        job,
        attempt,
        logs::Page {
            limit: SCAN_FRAMES,
            bytes: PAGE_BYTES,
            scan: NEWEST_SCAN_BYTES,
        },
        step,
    ) {
        Ok(tail) => Ok(Some(tail)),
        Err(StoreError::NotFound) => Ok(None),
        Err(other) => Err(store_error(other)),
    }
}

#[derive(Default)]
struct Reports {
    items: Vec<FailureReport>,
    omitted: u64,
}

struct FailureReport {
    report: DiagnosticReport,
    parse: ParseCounts,
    window: Option<(u64, u64)>,
    artifact: Option<(String, String)>,
}

struct ParseCounts {
    complete: bool,
    malformed_records: u64,
    omitted_diagnostics: u64,
    bytes_scanned: u64,
}

impl Reports {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        parsed: ParseResult,
        diagnostics: Vec<Diagnostic>,
        provenance: Provenance,
        fresh: EvidenceFreshness,
        window: Option<(u64, u64)>,
        artifact: Option<(String, String)>,
    ) {
        let mut parse = ParseCounts {
            complete: parsed.complete,
            malformed_records: parsed.malformed_records,
            omitted_diagnostics: parsed.omitted_diagnostics,
            bytes_scanned: parsed.bytes_scanned,
        };
        let mut valid = Vec::with_capacity(diagnostics.len());
        for diagnostic in diagnostics {
            if diagnostic.validate().is_ok() {
                valid.push(diagnostic);
            } else {
                parse.malformed_records = parse.malformed_records.saturating_add(1);
                parse.complete = false;
            }
        }
        let report = DiagnosticReport {
            schema_version: diag::REPORT_SCHEMA_VERSION,
            provenance,
            freshness: if parse.complete {
                fresh
            } else {
                EvidenceFreshness::Incomplete
            },
            diagnostics: valid,
        };
        match report.validate() {
            Ok(()) => self.items.push(FailureReport {
                report,
                parse,
                window,
                artifact,
            }),
            Err(_) => {
                self.omitted = self
                    .omitted
                    .saturating_add(report.diagnostics.len() as u64)
                    .saturating_add(1);
            }
        }
    }
}

struct LogScope {
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    step_index: Option<u32>,
    step_reference: Option<StepReference>,
    complete: bool,
}

struct LogInput {
    stream: Stream,
    bytes: Vec<u8>,
    chunks: Vec<Chunk>,
}

struct Chunk {
    start: usize,
    end: usize,
    seq: u64,
}

fn log_reports(out: &mut Reports, frames: &[Frame], after: u64, scope: LogScope) {
    let mut inputs = [Stream::Stdout, Stream::Stderr].map(|stream| LogInput {
        stream,
        bytes: Vec::new(),
        chunks: Vec::new(),
    });
    let Some(record_step) = scope.step_index else {
        return;
    };
    for frame in frames {
        if frame.seq <= after || frame.step != record_step {
            continue;
        }
        let Some(input) = inputs.iter_mut().find(|input| input.stream == frame.stream) else {
            continue;
        };
        let start = input.bytes.len();
        input.bytes.extend_from_slice(&frame.bytes);
        input.chunks.push(Chunk {
            start,
            end: input.bytes.len(),
            seq: frame.seq,
        });
    }
    for input in inputs {
        if input.bytes.is_empty() {
            continue;
        }
        let Some(format) = detect_diagnostic_format(&input.bytes) else {
            continue;
        };
        let mut step = scope.step_reference.clone().unwrap_or(StepReference {
            index: record_step,
            key: None,
        });
        step.index = record_step;
        let (mut parsed, producer) = match format {
            ReportFormat::GoTestJson => (
                diag::parse_go_test_json(&input.bytes, step.clone()),
                "go test",
            ),
            ReportFormat::RustCompilerJson => (
                diag::parse_rust_compiler_json(&input.bytes, step.clone()),
                "rustc",
            ),
            _ => continue,
        };
        let stream = match input.stream {
            Stream::Stdout => EvidenceStream::Stdout,
            Stream::Stderr => EvidenceStream::Stderr,
        };
        let diagnostics = parsed
            .diagnostics
            .drain(..)
            .map(|parsed| {
                let mut diagnostic = parsed.diagnostic;
                if let Some(range) = parsed.input_range.as_ref()
                    && let (Some(start), Some(end)) = (
                        frame_position(&input.chunks, range.start as usize),
                        frame_position(&input.chunks, range.end as usize),
                    )
                {
                    diagnostic.evidence.push(EvidenceReference {
                        step_index: record_step,
                        stream,
                        start,
                        end,
                    });
                }
                diagnostic
            })
            .collect();
        let window = input
            .chunks
            .first()
            .zip(input.chunks.last())
            .map(|(first, last)| (first.seq, last.seq));
        let provenance = Provenance {
            producer: Producer {
                name: producer.into(),
                version: None,
            },
            format,
            collected_from: match input.stream {
                Stream::Stdout => CollectionSource::Stdout,
                Stream::Stderr => CollectionSource::Stderr,
            },
            run_id: scope.run.to_string(),
            job_id: scope.job.to_string(),
            attempt_id: scope.attempt.to_string(),
            step: Some(step),
            input_sha256: sha256_hex(&input.bytes),
            parser_version: "1".into(),
        };
        let fresh = if scope.complete {
            EvidenceFreshness::Fresh
        } else {
            EvidenceFreshness::Incomplete
        };
        out.push(parsed, diagnostics, provenance, fresh, window, None);
    }
}

fn detect_diagnostic_format(input: &[u8]) -> Option<ReportFormat> {
    #[derive(Deserialize)]
    struct Probe<'a> {
        #[serde(rename = "Action")]
        action: Option<IgnoredAny>,
        #[serde(rename = "$message_type")]
        message_type: Option<IgnoredAny>,
        #[serde(borrow)]
        reason: Option<std::borrow::Cow<'a, str>>,
    }
    const MARKERS: [&[u8]; 3] = [b"\"Action\"", b"\"$message_type\"", b"\"reason\""];
    for line in input.split(|byte| *byte == b'\n') {
        if line.len() > diag::MAX_PARSER_RECORD_BYTES
            || line.iter().all(u8::is_ascii_whitespace)
            || !MARKERS.iter().any(|marker| {
                line.windows(marker.len())
                    .any(|candidate| candidate == *marker)
            })
        {
            continue;
        }
        let Ok(probe) = serde_json::from_slice::<Probe<'_>>(line) else {
            continue;
        };
        if probe.action.is_some() {
            return Some(ReportFormat::GoTestJson);
        }
        if probe.message_type.is_some()
            || probe.reason.as_deref().is_some_and(|reason| {
                matches!(
                    reason,
                    "compiler-message"
                        | "compiler-artifact"
                        | "build-script-executed"
                        | "build-finished"
                )
            })
        {
            return Some(ReportFormat::RustCompilerJson);
        }
    }
    None
}

fn frame_position(chunks: &[Chunk], offset: usize) -> Option<FramePosition> {
    let index = chunks.partition_point(|chunk| chunk.end < offset);
    let chunk = chunks.get(index).or_else(|| chunks.last())?;
    if offset < chunk.start || offset > chunk.end {
        return None;
    }
    Some(FramePosition {
        sequence: chunk.seq,
        payload_offset: u32::try_from(offset - chunk.start).ok()?,
    })
}

#[derive(Default)]
struct ReportFiles {
    files: Vec<ReportFile>,
    skipped: u64,
}

struct ReportFile {
    artifact: String,
    path: String,
    format: ReportFormat,
    reader: Reader,
    len: u64,
}

fn report_files(
    state: &State,
    c: &Connection,
    tenant: TenantId,
    job: JobId,
    attempt: AttemptId,
) -> sentinel_store::Result<ReportFiles> {
    let mut out = ReportFiles::default();
    for (name, version) in
        artifacts::captured_for_attempt(c, tenant, attempt, MAX_REPORT_ARTIFACTS)?
    {
        let manifest = match state.objects.manifest(
            c,
            tenant,
            Kind::Artifact,
            &artifacts::manifest_name(job, &name),
            Some(version),
        ) {
            Ok(manifest) => manifest,
            Err(StoreError::NotFound) => continue,
            Err(other) => return Err(other),
        };
        for entry in &manifest.entries {
            let Some(format) = report_file_format(&entry.path) else {
                continue;
            };
            if out.files.len() == MAX_REPORT_FILES {
                out.skipped += 1;
                continue;
            }
            match state.objects.open_read(c, tenant, entry.digest) {
                Ok((reader, len)) => out.files.push(ReportFile {
                    artifact: name.clone(),
                    path: entry.path.clone(),
                    format,
                    reader,
                    len,
                }),
                Err(StoreError::NotFound | StoreError::Corrupt(_)) => out.skipped += 1,
                Err(other) => return Err(other),
            }
        }
    }
    Ok(out)
}

fn report_file_format(path: &str) -> Option<ReportFormat> {
    let name = path.rsplit('/').next()?;
    if name == "junit.xml"
        || name.ends_with(".junit.xml")
        || (name.starts_with("TEST-") && name.ends_with(".xml"))
    {
        Some(ReportFormat::JunitXml)
    } else if name == "sentinel-diagnostics.json" || name.ends_with(".sentinel-diagnostics.json") {
        Some(ReportFormat::CustomJson)
    } else {
        None
    }
}

/// Report files are repository-authored claims, so they are advisory and never the verdict.
fn file_reports(
    out: &mut Reports,
    files: ReportFiles,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    summary: &AttemptSummary,
) {
    for file in files.files {
        let limit = match file.format {
            ReportFormat::JunitXml => JUNIT_READ_BYTES,
            _ => sentinel_protocol::limits::MAX_API_BODY_BYTES as u64 + 1,
        };
        let mut bytes = Vec::with_capacity(file.len.min(limit) as usize);
        let read = file.reader.take(limit).read_to_end(&mut bytes);
        let cut = file.len > bytes.len() as u64;
        let (producer, mut parsed) = match (read, file.format) {
            (Err(_), _) => (
                Producer {
                    name: "report file".into(),
                    version: None,
                },
                unreadable(file.format),
            ),
            (Ok(_), ReportFormat::JunitXml) => (
                Producer {
                    name: "junit".into(),
                    version: None,
                },
                diag::parse_junit_xml(&bytes, None),
            ),
            (Ok(_), _) => match diag::parse_custom_report(&bytes) {
                Ok(decoded) => decoded,
                Err(_) => (
                    Producer {
                        name: "custom report".into(),
                        version: None,
                    },
                    unreadable(ReportFormat::CustomJson),
                ),
            },
        };
        if cut {
            parsed.complete = false;
        }
        let mut diagnostics: Vec<Diagnostic> = parsed
            .diagnostics
            .drain(..)
            .map(|parsed| parsed.diagnostic)
            .collect();
        for diagnostic in &mut diagnostics {
            let known = |index: u32, key: Option<&String>| {
                summary
                    .steps
                    .iter()
                    .any(|record| record.index == index && key.is_none_or(|key| *key == record.id))
            };
            let mut unbound = false;
            if let Some(step) = &diagnostic.step
                && !known(step.index, step.key.as_ref())
            {
                diagnostic.step = None;
                unbound = true;
            }
            let before = diagnostic.evidence.len();
            diagnostic
                .evidence
                .retain(|reference| known(reference.step_index, None));
            if unbound || diagnostic.evidence.len() != before {
                parsed.malformed_records = parsed.malformed_records.saturating_add(1);
                parsed.complete = false;
            }
        }
        let format = parsed.format;
        let provenance = Provenance {
            producer,
            format,
            collected_from: match format {
                ReportFormat::JunitXml => CollectionSource::JunitUpload,
                _ => CollectionSource::CustomUpload,
            },
            run_id: run.to_string(),
            job_id: job.to_string(),
            attempt_id: attempt.to_string(),
            step: None,
            input_sha256: sha256_hex(&bytes),
            parser_version: "1".into(),
        };
        out.push(
            parsed,
            diagnostics,
            provenance,
            EvidenceFreshness::Advisory,
            None,
            Some((file.artifact, file.path)),
        );
    }
}

fn unreadable(format: ReportFormat) -> ParseResult {
    ParseResult {
        format,
        diagnostics: Vec::new(),
        complete: false,
        malformed_records: 1,
        omitted_diagnostics: 0,
        bytes_scanned: 0,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

fn fit_diagnostic_text(diagnostic: &mut Diagnostic, remaining: &mut usize) -> bool {
    if diagnostic.message.len() > *remaining {
        let mut end = *remaining;
        while !diagnostic.message.is_char_boundary(end) {
            end -= 1;
        }
        diagnostic.message.truncate(end);
        *remaining = 0;
        diagnostic.code = None;
        diagnostic.source = None;
        diagnostic.test = None;
        if let Some(step) = diagnostic.step.as_mut() {
            step.key = None;
        }
        return !diagnostic.message.is_empty();
    }
    *remaining -= diagnostic.message.len();
    if diagnostic
        .code
        .as_ref()
        .is_some_and(|text| text.len() > *remaining)
    {
        diagnostic.code = None;
    } else if let Some(code) = &diagnostic.code {
        *remaining -= code.len();
    }
    if diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.path.len() > *remaining)
    {
        diagnostic.source = None;
    } else if let Some(source) = &diagnostic.source {
        *remaining -= source.path.len();
    }
    let drop_test = if let Some(test) = &mut diagnostic.test {
        if test.name.len() > *remaining {
            true
        } else {
            *remaining -= test.name.len();
            if test
                .package
                .as_ref()
                .is_some_and(|text| text.len() > *remaining)
            {
                test.package = None;
            } else if let Some(package) = &test.package {
                *remaining -= package.len();
            }
            if test
                .class_name
                .as_ref()
                .is_some_and(|text| text.len() > *remaining)
            {
                test.class_name = None;
            } else if let Some(class_name) = &test.class_name {
                *remaining -= class_name.len();
            }
            false
        }
    } else {
        false
    };
    if drop_test {
        diagnostic.test = None;
    }
    let step_key_len = diagnostic
        .step
        .as_ref()
        .and_then(|step| step.key.as_ref())
        .map(String::len);
    if let Some(len) = step_key_len {
        if len > *remaining {
            if let Some(step) = diagnostic.step.as_mut() {
                step.key = None;
            }
        } else {
            *remaining -= len;
        }
    }
    true
}

fn diagnostic_text_len(diagnostic: &Diagnostic) -> usize {
    diagnostic.message.len()
        + diagnostic.code.as_ref().map_or(0, String::len)
        + diagnostic
            .source
            .as_ref()
            .map_or(0, |source| source.path.len())
        + diagnostic.test.as_ref().map_or(0, |test| {
            test.name.len()
                + test.package.as_ref().map_or(0, String::len)
                + test.class_name.as_ref().map_or(0, String::len)
        })
        + diagnostic
            .step
            .as_ref()
            .and_then(|step| step.key.as_ref())
            .map_or(0, String::len)
}

struct BinaryRun {
    first: u64,
    last: u64,
    step: u32,
    stream: Stream,
    bytes: u64,
}

impl BinaryRun {
    fn json(&self) -> Value {
        json!({
            "sequence": self.first,
            "end_sequence": self.last,
            "step": self.step,
            "stream": stream_name(self.stream),
            "binary": true,
            "bytes": self.bytes,
            "text": "",
        })
    }
}

fn looks_binary(bytes: &[u8]) -> bool {
    let controls = |text: &str| {
        text.bytes()
            .filter(|byte| *byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r' | 0x1b))
            .count()
    };
    let mut bad = 0usize;
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                bad += controls(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                bad += controls(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                let skip = error.error_len().unwrap_or(rest.len() - valid);
                bad += skip;
                rest = &rest[valid + skip..];
            }
        }
    }
    bad.saturating_mul(8) > bytes.len()
}

fn bounded_log_suffix(bytes: &[u8], budget: usize) -> (String, bool) {
    if budget == 0 {
        return (String::new(), !bytes.is_empty());
    }
    let decoded = String::from_utf8_lossy(bytes);
    let shown = diag::display_text(&decoded);
    let mut start = shown.len().saturating_sub(budget);
    while !shown.is_char_boundary(start) {
        start += 1;
    }
    (shown[start..].to_owned(), start > 0)
}

fn step_outcome_name(outcome: StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Passed => "passed",
        StepOutcome::Skipped => "skipped",
        StepOutcome::Failed { .. } => "failed",
        StepOutcome::Signaled { .. } => "signaled",
        StepOutcome::OutOfMemory => "out_of_memory",
        StepOutcome::TimedOut => "timed_out",
        StepOutcome::Runtime => "runtime",
        StepOutcome::NotRun => "not_run",
    }
}

fn json_len(value: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// Measured once per removed item and re-measured per round: serializing the body per item would be quadratic.
fn cap_failure_json(body: &mut Value, cap: usize) {
    let mut size = json_len(body);
    while size > cap {
        body["truncated"] = Value::Bool(true);
        let mut excess = size - cap;
        let mut removed = false;
        if let Some(frames) = body
            .pointer_mut("/tail/frames")
            .and_then(Value::as_array_mut)
        {
            // Oldest first: a frame the excess covers goes whole; a longer one keeps its newest bytes (one long line
            // can be the evidence); one whose text cannot cover the excess goes whole unless it is the last frame.
            let mut cut = 0;
            while excess > 0 && cut < frames.len() {
                let size = json_len(&frames[cut]) + 1;
                if size <= excess {
                    excess -= size;
                    cut += 1;
                    continue;
                }
                let text = frames[cut]
                    .get("text")
                    .and_then(Value::as_str)
                    .filter(|text| text.len() > excess)
                    .map(str::to_owned);
                if let Some(text) = text {
                    let mut start = excess;
                    while !text.is_char_boundary(start) {
                        start += 1;
                    }
                    frames[cut]["text"] = Value::String(text[start..].to_owned());
                    frames[cut]["cut"] = Value::Bool(true);
                    excess = excess.saturating_sub(start);
                    removed = true;
                    break;
                }
                if cut + 1 == frames.len() {
                    break;
                }
                excess = excess.saturating_sub(size);
                cut += 1;
            }
            if cut > 0 {
                frames.drain(..cut);
                removed = true;
            }
        }
        // Long messages shrink before any diagnostic goes: the test, its source and its evidence are the finding.
        if excess > 0
            && let Some(reports) = body.get_mut("reports").and_then(Value::as_array_mut)
        {
            'messages: for report in reports.iter_mut().rev() {
                let Some(items) = report
                    .get_mut("report")
                    .and_then(|report| report.get_mut("diagnostics"))
                    .and_then(Value::as_array_mut)
                else {
                    continue;
                };
                for item in items.iter_mut().rev() {
                    let Some(text) = item
                        .get("message")
                        .and_then(Value::as_str)
                        .filter(|text| text.len() > KEPT_MESSAGE_BYTES)
                        .map(str::to_owned)
                    else {
                        continue;
                    };
                    let mut keep = text.len().saturating_sub(excess).max(KEPT_MESSAGE_BYTES);
                    while !text.is_char_boundary(keep) {
                        keep -= 1;
                    }
                    excess = excess.saturating_sub(text.len() - keep);
                    item["message"] = Value::String(text[..keep].to_owned());
                    item["message_cut"] = Value::Bool(true);
                    removed = true;
                    if excess == 0 {
                        break 'messages;
                    }
                }
            }
        }
        let mut omitted = 0u64;
        if excess > 0
            && let Some(reports) = body.get_mut("reports").and_then(Value::as_array_mut)
        {
            'reports: for report in reports.iter_mut().rev() {
                let Some(items) = report
                    .get_mut("report")
                    .and_then(|report| report.get_mut("diagnostics"))
                    .and_then(Value::as_array_mut)
                else {
                    continue;
                };
                while let Some(item) = items.pop() {
                    excess = excess.saturating_sub(json_len(&item) + 1);
                    omitted += 1;
                    removed = true;
                    if excess == 0 {
                        break 'reports;
                    }
                }
            }
        }
        if omitted > 0 {
            body["omitted_diagnostics"] = body["omitted_diagnostics"]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(omitted)
                .into();
        }
        if !removed {
            break;
        }
        size = json_len(body);
    }
}

fn recount_failure_text(body: &mut Value) {
    let mut text_bytes = 0usize;
    if let Some(reports) = body.get("reports").and_then(Value::as_array) {
        for report in reports {
            let Some(diagnostics) = report
                .get("report")
                .and_then(|report| report.get("diagnostics"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for diagnostic in diagnostics {
                for text in [
                    diagnostic.get("message").and_then(Value::as_str),
                    diagnostic.get("code").and_then(Value::as_str),
                    diagnostic
                        .get("source")
                        .and_then(|source| source.get("path"))
                        .and_then(Value::as_str),
                    diagnostic
                        .get("test")
                        .and_then(|test| test.get("name"))
                        .and_then(Value::as_str),
                    diagnostic
                        .get("test")
                        .and_then(|test| test.get("package"))
                        .and_then(Value::as_str),
                    diagnostic
                        .get("test")
                        .and_then(|test| test.get("class_name"))
                        .and_then(Value::as_str),
                    diagnostic
                        .get("step")
                        .and_then(|step| step.get("key"))
                        .and_then(Value::as_str),
                ]
                .into_iter()
                .flatten()
                {
                    text_bytes = text_bytes.saturating_add(text.len());
                }
            }
        }
    }
    if let Some(frames) = body.pointer("/tail/frames").and_then(Value::as_array) {
        text_bytes = text_bytes.saturating_add(
            frames
                .iter()
                .filter_map(|frame| frame.get("text").and_then(Value::as_str))
                .map(str::len)
                .sum::<usize>(),
        );
    }
    body["text_bytes"] = Value::from(text_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_skips_oversized_lines_without_parsing_them() {
        let mut huge = b"{\"Action\":1,\"x\":[".to_vec();
        huge.extend(std::iter::repeat_n(b"0,".as_slice(), 2 << 20).flatten());
        huge.extend_from_slice(b"0]}\n");
        assert_eq!(detect_diagnostic_format(&huge), None);
        huge.extend_from_slice(b"{\"reason\":\"compiler-artifact\",\"x\":{}}\n");
        assert_eq!(
            detect_diagnostic_format(&huge),
            Some(ReportFormat::RustCompilerJson)
        );
        assert_eq!(
            detect_diagnostic_format(b"{\"reason\":\"unrelated\"}\n"),
            None
        );
    }

    #[test]
    fn binary_frames_are_told_from_coloured_text() {
        assert!(!looks_binary(b"\x1b[31mFAIL\x1b[0m api_test.go:42\r\n"));
        assert!(!looks_binary("résumé ✓\n".as_bytes()));
        let mut blob = vec![0xffu8; 1024];
        blob[0] = 0;
        assert!(looks_binary(&blob));
        assert!(looks_binary(b"\0\0\0\0text"));
    }

    #[test]
    fn capping_spends_the_tail_before_any_diagnostic() {
        let frame = |seq: u64| json!({"sequence": seq, "step": 0, "stream": "stdout", "text": "ordinary output line\n"});
        let mut body = json!({
            "reports": [{"report": {"diagnostics": [json!({"test": {"name": "TestCreate"}, "message": "wanted 201, got 500"})]}}],
            "tail": {"frames": (1..=73).map(frame).collect::<Vec<_>>()},
            "truncated": false,
            "omitted_diagnostics": 0,
        });
        let cap = json_len(&body) - 30;
        cap_failure_json(&mut body, cap);
        assert!(json_len(&body) <= cap);
        assert_eq!(
            body["reports"][0]["report"]["diagnostics"][0]["test"]["name"],
            "TestCreate"
        );
        assert_eq!(body["omitted_diagnostics"], 0);
        let frames = body["tail"]["frames"].as_array().unwrap();
        assert!(frames.len() < 73 && !frames.is_empty());
        assert_eq!(
            frames.last().unwrap()["sequence"],
            73,
            "the newest frame stays"
        );
    }

    #[test]
    fn capping_removes_items_by_measured_size_in_one_pass() {
        let frame =
            json!({"sequence": 1, "step": 0, "stream": "stdout", "text": "x".repeat(1_000)});
        let mut body = json!({
            "reports": [{"report": {"diagnostics": vec![json!({"message": "y".repeat(1_000)}); 70]}}],
            "tail": {"frames": vec![frame; 20]},
            "truncated": false,
            "omitted_diagnostics": 0,
        });
        cap_failure_json(&mut body, MAX_BUDGET);
        let size = json_len(&body);
        assert!(size <= MAX_BUDGET, "{size}");
        assert!(size > MAX_BUDGET - 1_100, "{size}");
        assert_eq!(body["truncated"], true);
        assert_eq!(body["tail"]["frames"].as_array().unwrap().len(), 0);
        // After the tail, long messages shrink, newest diagnostics first; none is dropped while one can shrink.
        assert_eq!(body["omitted_diagnostics"], 0);
        let diagnostics = body["reports"][0]["report"]["diagnostics"]
            .as_array()
            .unwrap();
        assert_eq!(diagnostics.len(), 70);
        let cut: Vec<&Value> = diagnostics
            .iter()
            .filter(|d| d["message_cut"] == true)
            .collect();
        assert!(!cut.is_empty());
        assert!(
            cut.iter()
                .all(|d| d["message"].as_str().unwrap().len() >= KEPT_MESSAGE_BYTES)
        );
        assert_eq!(diagnostics[0]["message"].as_str().unwrap().len(), 1_000);
    }

    #[test]
    fn capping_drops_diagnostics_only_once_their_messages_are_short() {
        let mut body = json!({
            "reports": [{"report": {"diagnostics": vec![json!({"message": "y".repeat(200)}); 400]}}],
            "tail": {"frames": []},
            "truncated": false,
            "omitted_diagnostics": 0,
        });
        cap_failure_json(&mut body, DEFAULT_BODY_BYTES);
        assert!(json_len(&body) <= DEFAULT_BODY_BYTES);
        let kept = body["reports"][0]["report"]["diagnostics"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(
            body["omitted_diagnostics"].as_u64().unwrap() as usize + kept,
            400
        );
        assert!(kept > 0 && kept < 400);
    }

    #[test]
    fn report_files_follow_the_documented_names() {
        assert_eq!(
            report_file_format("out/unit.junit.xml"),
            Some(ReportFormat::JunitXml)
        );
        assert_eq!(
            report_file_format("target/surefire-reports/TEST-pkg.AppTest.xml"),
            Some(ReportFormat::JunitXml)
        );
        assert_eq!(
            report_file_format("reports/lint.sentinel-diagnostics.json"),
            Some(ReportFormat::CustomJson)
        );
        assert_eq!(report_file_format("reports/coverage.xml"), None);
        assert_eq!(report_file_format("junit.xml.bak"), None);
    }
}
