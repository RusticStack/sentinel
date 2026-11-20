//! The controller's evidence derivation: what the stored log says about a failure.
//!
//! Two routes read this one path — the failure context a person reads (`GET /attempts/{id}/failure`)
//! and the evidence bundle an AI service reads (`GET /attempts/{id}/ai-context`, Y02) — so a
//! diagnostic means the same thing on both, and the second never reimplements the first's parsing.
//! Everything here works on frames the worker already redacted: nothing opens an artifact, and no
//! unredacted byte enters either answer.

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::{
    diagnostics::{
        self as diag, CollectionSource, Diagnostic, DiagnosticReport, EvidenceFreshness,
        EvidenceReference, EvidenceStream, FramePosition, ParseResult, Producer, Provenance,
        ReportFormat, StepReference,
    },
    logs::{Frame, Stream},
    summary::StepOutcome,
};
use serde::{Deserialize, de::IgnoredAny};
use serde_json::Value;

#[derive(Default)]
pub(crate) struct Reports {
    pub(crate) items: Vec<FailureReport>,
    pub(crate) omitted: u64,
}

pub(crate) struct FailureReport {
    pub(crate) report: DiagnosticReport,
    pub(crate) parse: ParseCounts,
    pub(crate) window: Option<(u64, u64)>,
    pub(crate) artifact: Option<(String, String)>,
}

pub(crate) struct ParseCounts {
    pub(crate) complete: bool,
    pub(crate) malformed_records: u64,
    pub(crate) omitted_diagnostics: u64,
    pub(crate) bytes_scanned: u64,
}

impl Reports {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
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

pub(crate) struct LogScope {
    pub(crate) run: RunId,
    pub(crate) job: JobId,
    pub(crate) attempt: AttemptId,
    pub(crate) step_index: Option<u32>,
    pub(crate) step_reference: Option<StepReference>,
    pub(crate) complete: bool,
}

pub(crate) struct LogInput {
    stream: Stream,
    bytes: Vec<u8>,
    chunks: Vec<Chunk>,
}

pub(crate) struct Chunk {
    start: usize,
    end: usize,
    seq: u64,
}

pub(crate) fn log_reports(out: &mut Reports, frames: &[Frame], after: u64, scope: LogScope) {
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

pub(crate) fn detect_diagnostic_format(input: &[u8]) -> Option<ReportFormat> {
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

pub(crate) fn frame_position(chunks: &[Chunk], offset: usize) -> Option<FramePosition> {
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

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
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

pub(crate) fn bounded_log_suffix(bytes: &[u8], budget: usize) -> (String, bool) {
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

pub(crate) fn step_outcome_name(outcome: StepOutcome) -> &'static str {
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

pub(crate) fn json_len(value: &Value) -> usize {
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
