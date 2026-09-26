//! Versioned diagnostic reports shared by report producers, the API, CLI and
//! MCP. Reports are evidence only: the fenced attempt transition and command
//! exit summary remain the authority for whether a job passed or failed.

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, str::FromStr};

mod parse;
pub use parse::{
    CustomInputError, MAX_PARSER_INPUT_BYTES, MAX_PARSER_RECORD_BYTES, ParseResult,
    ParsedDiagnostic, parse_custom_json, parse_custom_report, parse_go_test_json, parse_junit_xml,
    parse_rust_compiler_json,
};

pub const REPORT_SCHEMA_VERSION: u16 = 1;
pub const MAX_REPORT_DIAGNOSTICS: usize = 1_024;
pub const MAX_REPORT_EVIDENCE_PER_DIAGNOSTIC: usize = 8;
pub const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_DIAGNOSTIC_LABEL_BYTES: usize = 256;
pub const MAX_DIAGNOSTIC_PATH_BYTES: usize = 4 * 1024;
pub const MAX_EVIDENCE_FRAME_OFFSET: u32 = 1 << 20;

/// Custom report input, collected from a report file an attempt published
/// (see docs/diagnostics.md). Provenance, scope and evidence freshness are
/// supplied by the server after it binds this input to an authorized
/// attempt; a repository cannot claim that its own report is fresh or
/// complete. Input decoding is strict: this object and every nested object
/// reject unknown fields ([`strict`]). The shared nested types themselves
/// accept unknown fields so that v1 readers of server-authored reports stay
/// compatible with additive fields (docs/compatibility.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "strict::ReportInput")]
pub struct ReportInput {
    pub schema_version: u16,
    pub producer: Producer,
    pub diagnostics: Vec<Diagnostic>,
}

/// A report after the server has attached trusted collection metadata.
/// Server-authored: readers ignore fields they do not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub schema_version: u16,
    pub provenance: Provenance,
    pub freshness: EvidenceFreshness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    /// Stable producer name, for example `go test`, `rustc`, or a repository
    /// adapter name. It is display metadata and never selects control flow.
    pub name: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub producer: Producer,
    pub format: ReportFormat,
    pub collected_from: CollectionSource,
    /// Canonical typed IDs are strings here so the JSON schema remains
    /// transport friendly. The API validates them against the owning rows.
    pub run_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub step: Option<StepReference>,
    /// SHA-256 of the exact bounded input bytes, lowercase hexadecimal.
    pub input_sha256: String,
    /// Version of Sentinel's parser, distinct from the tool's version.
    pub parser_version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    GoTestJson,
    RustCompilerJson,
    JunitXml,
    SentinelJson,
    CustomJson,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionSource {
    Stdout,
    Stderr,
    JunitUpload,
    CustomUpload,
}

/// Describes the trust and completeness of evidence, never the command
/// result. `Fresh` is assigned only when the server binds evidence to the
/// current fenced attempt; clients cannot set this value in `ReportInput`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Fresh,
    Advisory,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub code: Option<String>,
    pub failure_class: Option<FailureClass>,
    pub source: Option<SourceReference>,
    pub test: Option<TestReference>,
    pub step: Option<StepReference>,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Failure,
    Warning,
    Info,
    Success,
}

/// Wire representation of the core failure classes. The exhaustive
/// conversion makes additions to the state-machine taxonomy a compile error
/// here until the diagnostic contract is deliberately updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    CommandFailed,
    CommandSignaled,
    OutOfMemory,
    ExecutionTimeout,
    QueueTimeout,
    Canceled,
    Preparation,
    LeaseExpired,
    WorkerLost,
    Reconciled,
    Publication,
    Runtime,
}

impl From<sentinel_core::FailureClass> for FailureClass {
    fn from(value: sentinel_core::FailureClass) -> Self {
        use sentinel_core::FailureClass as Core;
        match value {
            Core::CommandFailed => Self::CommandFailed,
            Core::CommandSignaled => Self::CommandSignaled,
            Core::OutOfMemory => Self::OutOfMemory,
            Core::ExecutionTimeout => Self::ExecutionTimeout,
            Core::QueueTimeout => Self::QueueTimeout,
            Core::Canceled => Self::Canceled,
            Core::Preparation => Self::Preparation,
            Core::LeaseExpired => Self::LeaseExpired,
            Core::WorkerLost => Self::WorkerLost,
            Core::Reconciled => Self::Reconciled,
            Core::Publication => Self::Publication,
            Core::Runtime => Self::Runtime,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReference {
    /// Repository-relative UTF-8 path using `/` separators.
    pub path: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestReference {
    pub name: String,
    pub package: Option<String>,
    pub class_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReference {
    /// Zero-based position in the compiled pipeline.
    pub index: u32,
    /// Compiled step key, when available. The API checks it against the run.
    pub key: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStream {
    Stdout,
    Stderr,
}

/// A half-open byte range in one step's log stream. Frame sequence and
/// payload offsets remain meaningful across log segmentation and paging.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub step_index: u32,
    pub stream: EvidenceStream,
    pub start: FramePosition,
    pub end: FramePosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FramePosition {
    pub sequence: u64,
    pub payload_offset: u32,
}

/// Strict decoding mirrors for [`ReportInput`]: identical shapes with
/// `deny_unknown_fields` on every object, converted field by field. Report
/// producers are untrusted, so an unknown field (for example a client trying
/// to assert `freshness`) is a decode error rather than silently ignored.
mod strict {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct ReportInput {
        schema_version: u16,
        producer: Producer,
        diagnostics: Vec<Diagnostic>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Producer {
        name: String,
        version: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Diagnostic {
        severity: super::Severity,
        message: String,
        code: Option<String>,
        failure_class: Option<super::FailureClass>,
        source: Option<SourceReference>,
        test: Option<TestReference>,
        step: Option<StepReference>,
        evidence: Vec<EvidenceReference>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SourceReference {
        path: String,
        line: Option<u32>,
        column: Option<u32>,
        end_line: Option<u32>,
        end_column: Option<u32>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestReference {
        name: String,
        package: Option<String>,
        class_name: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StepReference {
        index: u32,
        key: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceReference {
        step_index: u32,
        stream: super::EvidenceStream,
        start: FramePosition,
        end: FramePosition,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FramePosition {
        sequence: u64,
        payload_offset: u32,
    }

    impl From<ReportInput> for super::ReportInput {
        fn from(value: ReportInput) -> Self {
            Self {
                schema_version: value.schema_version,
                producer: super::Producer {
                    name: value.producer.name,
                    version: value.producer.version,
                },
                diagnostics: value.diagnostics.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl From<Diagnostic> for super::Diagnostic {
        fn from(value: Diagnostic) -> Self {
            Self {
                severity: value.severity,
                message: value.message,
                code: value.code,
                failure_class: value.failure_class,
                source: value.source.map(|source| super::SourceReference {
                    path: source.path,
                    line: source.line,
                    column: source.column,
                    end_line: source.end_line,
                    end_column: source.end_column,
                }),
                test: value.test.map(|test| super::TestReference {
                    name: test.name,
                    package: test.package,
                    class_name: test.class_name,
                }),
                step: value.step.map(|step| super::StepReference {
                    index: step.index,
                    key: step.key,
                }),
                evidence: value
                    .evidence
                    .into_iter()
                    .map(|reference| super::EvidenceReference {
                        step_index: reference.step_index,
                        stream: reference.stream,
                        start: reference.start.into(),
                        end: reference.end.into(),
                    })
                    .collect(),
            }
        }
    }

    impl From<FramePosition> for super::FramePosition {
        fn from(value: FramePosition) -> Self {
            Self {
                sequence: value.sequence,
                payload_offset: value.payload_offset,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedVersion,
    TooManyDiagnostics,
    TooMuchEvidence,
    EmptyMessage,
    MessageTooLong,
    InvalidLabel,
    InvalidPath,
    InvalidLocation,
    InvalidStep,
    InvalidEvidenceRange,
    InvalidProvenance,
}

impl ReportInput {
    /// Validate semantic bounds after a byte-bounded JSON decode.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedVersion);
        }
        validate_label(&self.producer.name)?;
        if let Some(version) = &self.producer.version {
            validate_label(version)?;
        }
        validate_diagnostics(&self.diagnostics)
    }
}

impl DiagnosticReport {
    /// Validate a server-produced report before storage or response.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedVersion);
        }
        sentinel_core::RunId::from_str(&self.provenance.run_id)
            .map_err(|_| ValidationError::InvalidProvenance)?;
        sentinel_core::JobId::from_str(&self.provenance.job_id)
            .map_err(|_| ValidationError::InvalidProvenance)?;
        sentinel_core::AttemptId::from_str(&self.provenance.attempt_id)
            .map_err(|_| ValidationError::InvalidProvenance)?;
        validate_label(&self.provenance.run_id)?;
        validate_label(&self.provenance.job_id)?;
        validate_label(&self.provenance.attempt_id)?;
        if self.provenance.input_sha256.len() != 64
            || !self
                .provenance
                .input_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::InvalidProvenance);
        }
        validate_label(&self.provenance.parser_version)?;
        validate_label(&self.provenance.producer.name)?;
        if let Some(version) = &self.provenance.producer.version {
            validate_label(version)?;
        }
        if let Some(step) = &self.provenance.step {
            validate_step(step)?;
        }
        validate_diagnostics(&self.diagnostics)
    }
}

fn validate_diagnostics(values: &[Diagnostic]) -> Result<(), ValidationError> {
    if values.len() > MAX_REPORT_DIAGNOSTICS {
        return Err(ValidationError::TooManyDiagnostics);
    }
    values.iter().try_for_each(Diagnostic::validate)
}

impl Diagnostic {
    /// Validate one diagnostic's bounds, so a collector can drop just the
    /// offending diagnostic and count it; [`DiagnosticReport::validate`]
    /// still refuses a whole report that contains one.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.message.is_empty() {
            return Err(ValidationError::EmptyMessage);
        }
        if self.message.len() > MAX_DIAGNOSTIC_MESSAGE_BYTES {
            return Err(ValidationError::MessageTooLong);
        }
        if let Some(code) = &self.code {
            validate_label(code)?;
        }
        if let Some(source) = &self.source {
            validate_path(&source.path)?;
            if source.line == Some(0)
                || source.column == Some(0)
                || source.end_line == Some(0)
                || source.end_column == Some(0)
                || matches!((source.line, source.end_line), (Some(start), Some(end)) if end < start)
            {
                return Err(ValidationError::InvalidLocation);
            }
        }
        if let Some(test) = &self.test {
            validate_label(&test.name)?;
            if let Some(package) = &test.package {
                validate_label(package)?;
            }
            if let Some(class_name) = &test.class_name {
                validate_label(class_name)?;
            }
        }
        if let Some(step) = &self.step {
            validate_step(step)?;
        }
        if self.evidence.len() > MAX_REPORT_EVIDENCE_PER_DIAGNOSTIC {
            return Err(ValidationError::TooMuchEvidence);
        }
        for reference in &self.evidence {
            if reference.step_index > 255
                || reference.start.sequence == 0
                || reference.end.sequence == 0
                || reference.start.payload_offset > MAX_EVIDENCE_FRAME_OFFSET
                || reference.end.payload_offset > MAX_EVIDENCE_FRAME_OFFSET
                || (reference.end.sequence, reference.end.payload_offset)
                    < (reference.start.sequence, reference.start.payload_offset)
            {
                return Err(ValidationError::InvalidEvidenceRange);
            }
        }
        Ok(())
    }
}

/// Display-safe diagnostic or excerpt text: every control character other
/// than newline and tab becomes U+FFFD, so a response carries no terminal
/// escape or NUL, and no character escapes to six JSON bytes. Borrowed when
/// nothing needed replacing.
pub fn display_text(text: &str) -> Cow<'_, str> {
    let unsafe_char = |ch: char| ch.is_control() && ch != '\n' && ch != '\t';
    let Some(first) = text.find(unsafe_char) else {
        return Cow::Borrowed(text);
    };
    let mut out = String::with_capacity(text.len() + 8);
    out.push_str(&text[..first]);
    for ch in text[first..].chars() {
        out.push(if unsafe_char(ch) { '\u{fffd}' } else { ch });
    }
    Cow::Owned(out)
}

fn validate_label(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_DIAGNOSTIC_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::InvalidLabel);
    }
    Ok(())
}

fn validate_step(step: &StepReference) -> Result<(), ValidationError> {
    if step.index > 255 {
        return Err(ValidationError::InvalidStep);
    }
    if let Some(key) = &step.key {
        validate_label(key)?;
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.len() > MAX_DIAGNOSTIC_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|b| b.is_ascii_control())
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ValidationError::InvalidPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ReportInput {
        ReportInput {
            schema_version: REPORT_SCHEMA_VERSION,
            producer: Producer {
                name: "rustc".into(),
                version: Some("1.97.0".into()),
            },
            diagnostics: vec![Diagnostic {
                severity: Severity::Error,
                message: "type mismatch".into(),
                code: Some("E0308".into()),
                failure_class: Some(FailureClass::CommandFailed),
                source: Some(SourceReference {
                    path: "src/lib.rs".into(),
                    line: Some(12),
                    column: Some(8),
                    end_line: None,
                    end_column: None,
                }),
                test: None,
                step: Some(StepReference {
                    index: 0,
                    key: Some("check".into()),
                }),
                evidence: vec![EvidenceReference {
                    step_index: 0,
                    stream: EvidenceStream::Stderr,
                    start: FramePosition {
                        sequence: 4,
                        payload_offset: 15,
                    },
                    end: FramePosition {
                        sequence: 5,
                        payload_offset: 22,
                    },
                }],
            }],
        }
    }

    #[test]
    fn custom_report_round_trips_versioned_source_test_and_evidence_refs() {
        let value = input();
        value.validate().unwrap();
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: ReportInput = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert!(
            String::from_utf8(encoded)
                .unwrap()
                .contains("schema_version")
        );
    }

    #[test]
    fn input_cannot_assert_server_provenance_or_freshness() {
        let encoded = br#"{"schema_version":1,"producer":{"name":"repo","version":null},"freshness":"fresh","diagnostics":[]}"#;
        assert!(serde_json::from_slice::<ReportInput>(encoded).is_err());
    }

    #[test]
    fn server_report_requires_canonical_ids_and_a_lowercase_sha256() {
        let input = input();
        let report = DiagnosticReport {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance {
                producer: input.producer,
                format: ReportFormat::CustomJson,
                collected_from: CollectionSource::CustomUpload,
                run_id: sentinel_core::RunId::new().to_string(),
                job_id: sentinel_core::JobId::new().to_string(),
                attempt_id: sentinel_core::AttemptId::new().to_string(),
                step: None,
                input_sha256: "a".repeat(64),
                parser_version: "1".into(),
            },
            freshness: EvidenceFreshness::Advisory,
            diagnostics: input.diagnostics,
        };
        report.validate().unwrap();

        let mut invalid = report;
        invalid.provenance.run_id = "run_not-an-id".into();
        assert_eq!(invalid.validate(), Err(ValidationError::InvalidProvenance));
    }

    #[test]
    fn rejects_unsupported_versions_unbounded_counts_and_unsafe_paths() {
        let mut report = input();
        report.schema_version += 1;
        assert_eq!(report.validate(), Err(ValidationError::UnsupportedVersion));

        let mut report = input();
        let diagnostic = report.diagnostics[0].clone();
        report
            .diagnostics
            .resize(MAX_REPORT_DIAGNOSTICS + 1, diagnostic);
        assert_eq!(report.validate(), Err(ValidationError::TooManyDiagnostics));

        let mut report = input();
        report.diagnostics[0].source.as_mut().unwrap().path = "../../secret.rs".into();
        assert_eq!(report.validate(), Err(ValidationError::InvalidPath));

        let mut report = input();
        report.diagnostics[0].source.as_mut().unwrap().path = "./src/lib.rs".into();
        assert_eq!(report.validate(), Err(ValidationError::InvalidPath));
    }

    #[test]
    fn input_rejects_unknown_fields_at_every_depth() {
        let mut value = serde_json::to_value(input()).unwrap();
        value["diagnostics"][0]["source"]["trusted"] = true.into();
        assert!(serde_json::from_value::<ReportInput>(value).is_err());
        let mut value = serde_json::to_value(input()).unwrap();
        value["diagnostics"][0]["evidence"][0]["start"]["verified"] = true.into();
        assert!(serde_json::from_value::<ReportInput>(value).is_err());
        let mut value = serde_json::to_value(input()).unwrap();
        value["producer"]["signature"] = "x".into();
        assert!(serde_json::from_value::<ReportInput>(value).is_err());
    }

    #[test]
    fn server_reports_ignore_additive_fields_from_newer_v1_servers() {
        let input = input();
        let report = DiagnosticReport {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance {
                producer: input.producer,
                format: ReportFormat::GoTestJson,
                collected_from: CollectionSource::Stdout,
                run_id: sentinel_core::RunId::new().to_string(),
                job_id: sentinel_core::JobId::new().to_string(),
                attempt_id: sentinel_core::AttemptId::new().to_string(),
                step: None,
                input_sha256: "b".repeat(64),
                parser_version: "1".into(),
            },
            freshness: EvidenceFreshness::Fresh,
            diagnostics: input.diagnostics,
        };
        let mut value = serde_json::to_value(&report).unwrap();
        value["added_later"] = 1.into();
        value["provenance"]["collector"] = "x".into();
        value["provenance"]["producer"]["build"] = "y".into();
        value["diagnostics"][0]["hint"] = "z".into();
        value["diagnostics"][0]["source"]["snippet"] = "w".into();
        value["diagnostics"][0]["test"] = serde_json::json!({
            "name": "TestA", "package": null, "class_name": null, "duration_ns": 5
        });
        value["diagnostics"][0]["evidence"][0]["end"]["line"] = 3.into();
        let decoded: DiagnosticReport = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.provenance, report.provenance);
        assert_eq!(decoded.diagnostics[0].source, report.diagnostics[0].source);
    }

    #[test]
    fn display_text_replaces_controls_but_keeps_lines_and_tabs() {
        assert!(matches!(display_text("plain\ttext\n"), Cow::Borrowed(_)));
        let shown = display_text("\u{1b}[31mred\u{1b}[0m\0\r\nnext\u{7f}\u{85}");
        assert_eq!(
            shown,
            "\u{fffd}[31mred\u{fffd}[0m\u{fffd}\u{fffd}\nnext\u{fffd}\u{fffd}"
        );
        // Every replacement costs three JSON bytes, never six.
        let json = serde_json::to_string(&shown).unwrap();
        assert!(!json.contains("\\u00"));
    }

    #[test]
    fn core_failure_classes_have_a_stable_wire_mapping() {
        let wire: FailureClass = sentinel_core::FailureClass::OutOfMemory.into();
        assert_eq!(serde_json::to_string(&wire).unwrap(), "\"out_of_memory\"");
    }
}
