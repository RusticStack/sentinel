//! Bounded parsers for common test/compiler reports. Parsers return evidence
//! only and never influence a fenced attempt transition.

use super::{
    Diagnostic, EvidenceReference, FailureClass, MAX_DIAGNOSTIC_LABEL_BYTES,
    MAX_DIAGNOSTIC_MESSAGE_BYTES, MAX_REPORT_DIAGNOSTICS, ReportFormat, ReportInput, Severity,
    SourceReference, StepReference, TestReference,
};
use quick_xml::{
    XmlVersion,
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
    reader::Reader,
};
use serde::Deserialize;
use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    ops::Range,
};

/// Existing attempt logs are capped at 256 MiB. Parsers stop at that same
/// bound even when called with a larger slice.
pub const MAX_PARSER_INPUT_BYTES: usize = 256 << 20;
const MAX_RECORD_BYTES: usize = 64 << 10;
const MAX_PARSER_RECORDS: usize = 2_000_000;
const MAX_TEST_OUTPUT_BYTES: usize = 4 << 10;

/// One parser result is bounded by input bytes, record count and diagnostic
/// count. A false complete means some input was malformed, over a limit, or
/// omitted; it never means that the command passed or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseResult {
    pub format: ReportFormat,
    pub diagnostics: Vec<ParsedDiagnostic>,
    pub complete: bool,
    pub malformed_records: u64,
    pub omitted_diagnostics: u64,
    pub bytes_scanned: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDiagnostic {
    pub diagnostic: Diagnostic,
    /// Half-open byte range in the exact parser input. For Go and rustc this
    /// can be mapped back to a step's stdout/stderr frames. For uploaded XML
    /// it identifies the testcase in the uploaded report.
    pub input_range: Option<Range<u64>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomInputError {
    TooLarge,
    InvalidJson,
    InvalidContract,
}

impl ParseResult {
    fn new(format: ReportFormat, input_len: usize) -> Self {
        Self {
            format,
            diagnostics: Vec::new(),
            complete: input_len <= MAX_PARSER_INPUT_BYTES,
            malformed_records: 0,
            omitted_diagnostics: 0,
            bytes_scanned: 0,
        }
    }

    fn push(&mut self, diagnostic: Diagnostic, range: Range<u64>) {
        if self.diagnostics.len() == MAX_REPORT_DIAGNOSTICS {
            self.omitted_diagnostics = self.omitted_diagnostics.saturating_add(1);
            self.complete = false;
            return;
        }
        self.diagnostics.push(ParsedDiagnostic {
            diagnostic,
            input_range: Some(range),
        });
    }

    fn malformed(&mut self) {
        self.malformed_records = self.malformed_records.saturating_add(1);
        self.complete = false;
    }
}

/// Parse Go test JSON output. Output is retained only as a fixed-size tail
/// per active test; successful tests release their retained bytes immediately.
pub fn parse_go_test_json(input: &[u8], step: StepReference) -> ParseResult {
    let mut result = ParseResult::new(ReportFormat::GoTestJson, input.len());
    let mut lines = JsonLines::new(input);
    let mut output_by_test: HashMap<u64, TestOutput> = HashMap::new();
    let mut failed_packages: HashMap<u64, String> = HashMap::new();

    for line in lines.by_ref() {
        if line.oversized {
            result.malformed();
            continue;
        }
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: GoEvent<'_> = match serde_json::from_slice(line.bytes) {
            Ok(event) => event,
            Err(_) => {
                result.malformed();
                continue;
            }
        };
        let action = event.action.as_deref().unwrap_or_default();
        let package = event.package.as_deref().unwrap_or_default();
        let test = event.test.as_deref().unwrap_or_default();
        if package.len() > MAX_DIAGNOSTIC_LABEL_BYTES
            || test.len() > MAX_DIAGNOSTIC_LABEL_BYTES
            || package.chars().any(char::is_control)
            || test.chars().any(char::is_control)
        {
            result.malformed();
            continue;
        }
        let key = test_key(package, test);
        match action {
            "output" => {
                let Some(output) = event.output.as_deref() else {
                    continue;
                };
                if let Some(existing) = output_by_test.get_mut(&key) {
                    if existing.package != package || existing.test != test {
                        // A hash collision must never combine one test's
                        // output with another test's diagnostic.
                        result.malformed();
                    } else {
                        existing.push(output.as_bytes(), line.start, line.end);
                    }
                } else if output_by_test.len() < MAX_REPORT_DIAGNOSTICS {
                    let mut captured = TestOutput::new(package, test, line.start);
                    captured.push(output.as_bytes(), line.start, line.end);
                    output_by_test.insert(key, captured);
                } else {
                    result.complete = false;
                }
            }
            "fail" => {
                if test.is_empty()
                    && let Some(failed_package) = failed_packages.get(&test_key(package, ""))
                {
                    if failed_package == package {
                        continue;
                    }
                    result.malformed();
                }
                let output = match output_by_test.remove(&key) {
                    Some(captured) if captured.package == package && captured.test == test => {
                        Some(captured)
                    }
                    Some(_) => {
                        result.malformed();
                        None
                    }
                    None => None,
                };
                let message = output
                    .as_ref()
                    .map(TestOutput::text)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| {
                        if test.is_empty() {
                            format!("go test reported a package failure in {package}")
                        } else {
                            format!("go test reported a failure in {package}: {test}")
                        }
                    });
                let code = if message.contains("WARNING: DATA RACE") {
                    Some("go_race")
                } else if message.contains("panic:") || message.contains("fatal error:") {
                    Some("go_panic")
                } else {
                    None
                };
                let source = source_from_output(&message);
                let start = output
                    .as_ref()
                    .map_or(line.start as u64, |captured| captured.start);
                if !test.is_empty() {
                    let package_key = test_key(package, "");
                    match failed_packages.get(&package_key) {
                        Some(existing) if existing != package => result.malformed(),
                        Some(_) => {}
                        None if failed_packages.len() < MAX_REPORT_DIAGNOSTICS => {
                            failed_packages.insert(package_key, package.to_owned());
                        }
                        None => result.complete = false,
                    }
                }
                result.push(
                    Diagnostic {
                        severity: Severity::Failure,
                        message: bounded_message(&message),
                        code: code.map(str::to_owned),
                        failure_class: Some(FailureClass::CommandFailed),
                        source,
                        test: (!test.is_empty()).then(|| TestReference {
                            name: test.to_owned(),
                            package: (!package.is_empty()).then(|| package.to_owned()),
                            class_name: None,
                        }),
                        step: Some(step.clone()),
                        evidence: Vec::<EvidenceReference>::new(),
                    },
                    start..line.end as u64,
                );
            }
            "pass" | "skip" => {
                output_by_test.remove(&key);
            }
            _ => {}
        }
    }
    result.bytes_scanned = lines.cursor as u64;
    if lines.limited {
        result.complete = false;
    }
    result
}

/// Parse newline-delimited rustc compiler JSON. Records are scanned in place;
/// source snippets and rendered duplicates are ignored so retained errors
/// stay small.
pub fn parse_rust_compiler_json(input: &[u8], step: StepReference) -> ParseResult {
    let mut result = ParseResult::new(ReportFormat::RustCompilerJson, input.len());
    let mut lines = JsonLines::new(input);
    for line in lines.by_ref() {
        if line.oversized {
            result.malformed();
            continue;
        }
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record: RustEvent<'_> = match serde_json::from_slice(line.bytes) {
            Ok(record) => record,
            Err(_) => {
                result.malformed();
                continue;
            }
        };
        if record.message_type.as_deref() != Some("diagnostic") {
            continue;
        }
        let Some(message) = record.message.as_deref() else {
            result.malformed();
            continue;
        };
        if message.trim().is_empty() {
            result.malformed();
            continue;
        }
        let (severity, failure_class) = match record.level.as_deref() {
            Some("error") => (Severity::Error, Some(FailureClass::CommandFailed)),
            Some("failure") => (Severity::Failure, Some(FailureClass::CommandFailed)),
            Some("warning") => (Severity::Warning, None),
            Some("note" | "help") => continue,
            _ => {
                result.malformed();
                continue;
            }
        };
        let primary = record
            .spans
            .iter()
            .find(|span| span.is_primary)
            .or_else(|| record.spans.first());
        let source = primary.and_then(source_from_rust_span);
        let code = record
            .code
            .and_then(|code| code.code.map(|value| value.into_owned()));
        let code = match code {
            Some(code)
                if code.len() <= MAX_DIAGNOSTIC_LABEL_BYTES
                    && !code.chars().any(char::is_control) =>
            {
                Some(code)
            }
            Some(_) => {
                result.complete = false;
                None
            }
            None => None,
        };
        result.push(
            Diagnostic {
                severity,
                message: bounded_message(message),
                code,
                failure_class,
                source,
                test: None,
                step: Some(step.clone()),
                evidence: Vec::new(),
            },
            line.start as u64..line.end as u64,
        );
    }
    result.bytes_scanned = lines.cursor as u64;
    if lines.limited {
        result.complete = false;
    }
    result
}

/// Parse JUnit XML without building a document tree. DTDs are refused, tag
/// payloads are capped, and only one testcase plus one failure body is kept.
pub fn parse_junit_xml(input: &[u8], step: Option<StepReference>) -> ParseResult {
    let mut result = ParseResult::new(ReportFormat::JunitXml, input.len());
    let bounded = &input[..input.len().min(MAX_PARSER_INPUT_BYTES)];
    let mut reader = Reader::from_reader(bounded);
    reader.config_mut().check_end_names = true;
    let mut current: Option<JunitCase> = None;
    let mut active_failure = false;
    let mut position = 0u64;
    let mut events = 0usize;

    loop {
        if events == MAX_PARSER_RECORDS {
            result.complete = false;
            break;
        }
        let start = reader.buffer_position();
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(_) => {
                result.malformed();
                break;
            }
        };
        let end = reader.buffer_position();
        position = end;
        events += 1;
        match event {
            Event::Eof => break,
            Event::DocType(_) => {
                result.malformed();
                break;
            }
            Event::Start(tag) => junit_tag(
                &mut result,
                &tag,
                start,
                end,
                false,
                &mut current,
                &mut active_failure,
                step.as_ref(),
            ),
            Event::Empty(tag) => junit_tag(
                &mut result,
                &tag,
                start,
                end,
                true,
                &mut current,
                &mut active_failure,
                step.as_ref(),
            ),
            Event::End(tag) => match tag.name().as_ref() {
                "failure" | "error" => active_failure = false,
                "testcase" => {
                    if let Some(case) = current.take() {
                        push_junit_case(&mut result, case, end, step.as_ref());
                    } else {
                        result.malformed();
                    }
                }
                _ => {}
            },
            Event::Text(text) if active_failure => {
                if text.as_ref().len() > MAX_RECORD_BYTES {
                    result.malformed();
                    continue;
                }
                let decoded = text.xml_content(XmlVersion::Implicit1_0);
                if let Some(failure) = current.as_mut().and_then(|case| case.failure.as_mut())
                    && append_bounded(&mut failure.message, decoded.as_ref())
                {
                    result.complete = false;
                }
            }
            Event::CData(text) if active_failure => {
                if text.as_ref().len() > MAX_DIAGNOSTIC_MESSAGE_BYTES {
                    result.complete = false;
                    continue;
                }
                if let Some(failure) = current.as_mut().and_then(|case| case.failure.as_mut())
                    && append_bounded(&mut failure.message, text.as_ref())
                {
                    result.complete = false;
                }
            }
            Event::GeneralRef(reference) => {
                let value = if let Some(ch) = reference.resolve_char_ref().ok().flatten() {
                    Some(ch.to_string())
                } else {
                    resolve_predefined_entity(reference.as_ref()).map(str::to_owned)
                };
                if let Some(value) = value {
                    if active_failure
                        && let Some(failure) =
                            current.as_mut().and_then(|case| case.failure.as_mut())
                        && append_bounded(&mut failure.message, &value)
                    {
                        result.complete = false;
                    }
                } else {
                    result.malformed();
                }
            }
            Event::Text(text) if text.as_ref().len() > MAX_RECORD_BYTES => {
                result.malformed();
            }
            Event::CData(text) if text.as_ref().len() > MAX_RECORD_BYTES => {
                result.malformed();
            }
            _ => {}
        }
    }
    result.bytes_scanned = position.min(MAX_PARSER_INPUT_BYTES as u64);
    if current.is_some() {
        result.malformed();
    }
    if input.len() > MAX_PARSER_INPUT_BYTES {
        result.complete = false;
    }
    result
}

/// Decode and validate the custom diagnostics body. The 1 MiB protocol body
/// cap is checked before JSON deserialization allocates fields.
pub fn parse_custom_json(input: &[u8]) -> Result<ReportInput, CustomInputError> {
    if input.len() > crate::limits::MAX_API_BODY_BYTES {
        return Err(CustomInputError::TooLarge);
    }
    let report: ReportInput =
        serde_json::from_slice(input).map_err(|_| CustomInputError::InvalidJson)?;
    report
        .validate()
        .map_err(|_| CustomInputError::InvalidContract)?;
    Ok(report)
}

#[derive(Deserialize)]
struct GoEvent<'a> {
    #[serde(rename = "Action", borrow)]
    action: Option<Cow<'a, str>>,
    #[serde(rename = "Package", borrow)]
    package: Option<Cow<'a, str>>,
    #[serde(rename = "Test", borrow)]
    test: Option<Cow<'a, str>>,
    #[serde(rename = "Output", borrow)]
    output: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct RustEvent<'a> {
    #[serde(rename = "$message_type", borrow)]
    message_type: Option<Cow<'a, str>>,
    #[serde(borrow)]
    message: Option<Cow<'a, str>>,
    #[serde(borrow)]
    level: Option<Cow<'a, str>>,
    code: Option<RustCode<'a>>,
    #[serde(default, borrow)]
    spans: Vec<RustSpan<'a>>,
}

#[derive(Deserialize)]
struct RustCode<'a> {
    #[serde(borrow)]
    code: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct RustSpan<'a> {
    #[serde(borrow)]
    file_name: Option<Cow<'a, str>>,
    line_start: Option<u32>,
    line_end: Option<u32>,
    column_start: Option<u32>,
    column_end: Option<u32>,
    is_primary: bool,
}

struct JsonLine<'a> {
    bytes: &'a [u8],
    start: usize,
    end: usize,
    oversized: bool,
}

struct JsonLines<'a> {
    input: &'a [u8],
    cursor: usize,
    limit: usize,
    records: usize,
    limited: bool,
}

impl<'a> JsonLines<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            limit: input.len().min(MAX_PARSER_INPUT_BYTES),
            records: 0,
            limited: input.len() > MAX_PARSER_INPUT_BYTES,
        }
    }
}

impl<'a> Iterator for JsonLines<'a> {
    type Item = JsonLine<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.limit {
            return None;
        }
        if self.records == MAX_PARSER_RECORDS {
            self.limited = true;
            self.cursor = self.limit;
            return None;
        }
        let start = self.cursor;
        let remaining = &self.input[start..self.limit];
        let (len, newline) = match remaining.iter().position(|&byte| byte == b'\n') {
            Some(len) => (len, true),
            None => (remaining.len(), false),
        };
        let end = start + len;
        self.cursor = end + usize::from(newline);
        self.records += 1;
        Some(JsonLine {
            bytes: &self.input[start..end],
            start,
            end,
            oversized: len > MAX_RECORD_BYTES,
        })
    }
}

#[derive(Clone)]
struct TestOutput {
    package: String,
    test: String,
    start: u64,
    ring: [u8; MAX_TEST_OUTPUT_BYTES],
    ring_start: usize,
    ring_len: usize,
}

impl TestOutput {
    fn new(package: &str, test: &str, start: usize) -> Self {
        Self {
            package: package.to_owned(),
            test: test.to_owned(),
            start: start as u64,
            ring: [0; MAX_TEST_OUTPUT_BYTES],
            ring_start: 0,
            ring_len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8], _start: usize, _end: usize) {
        if bytes.len() >= MAX_TEST_OUTPUT_BYTES {
            self.ring
                .copy_from_slice(&bytes[bytes.len() - MAX_TEST_OUTPUT_BYTES..]);
            self.ring_start = 0;
            self.ring_len = MAX_TEST_OUTPUT_BYTES;
            return;
        }
        let overflow = (self.ring_len + bytes.len()).saturating_sub(MAX_TEST_OUTPUT_BYTES);
        self.ring_start = (self.ring_start + overflow) % MAX_TEST_OUTPUT_BYTES;
        self.ring_len -= overflow;
        let tail = (self.ring_start + self.ring_len) % MAX_TEST_OUTPUT_BYTES;
        let first = bytes.len().min(MAX_TEST_OUTPUT_BYTES - tail);
        self.ring[tail..tail + first].copy_from_slice(&bytes[..first]);
        self.ring[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.ring_len += bytes.len();
    }

    fn text(&self) -> String {
        let mut bytes = Vec::with_capacity(self.ring_len);
        let first = self.ring_len.min(MAX_TEST_OUTPUT_BYTES - self.ring_start);
        bytes.extend_from_slice(&self.ring[self.ring_start..self.ring_start + first]);
        bytes.extend_from_slice(&self.ring[..self.ring_len - first]);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn test_key(package: &str, test: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    package.hash(&mut hasher);
    test.hash(&mut hasher);
    hasher.finish()
}

fn source_from_output(text: &str) -> Option<SourceReference> {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        let mut parts = line.splitn(4, ':');
        let path = parts.next()?;
        let Some(line_number) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let column = match parts.next() {
            Some(value) => value.parse::<u32>().ok(),
            None => None,
        };
        let Some(path) = normalized_relative_path(path) else {
            continue;
        };
        return Some(SourceReference {
            path,
            line: Some(line_number),
            column,
            end_line: None,
            end_column: None,
        });
    }
    None
}

fn source_from_rust_span(span: &RustSpan<'_>) -> Option<SourceReference> {
    if span.line_start == Some(0)
        || span.line_end == Some(0)
        || span.column_start == Some(0)
        || span.column_end == Some(0)
        || matches!((span.line_start, span.line_end), (Some(start), Some(end)) if end < start)
    {
        return None;
    }
    let path = normalized_relative_path(span.file_name.as_deref()?)?;
    Some(SourceReference {
        path,
        line: span.line_start,
        column: span.column_start,
        end_line: span.line_end,
        end_column: span.column_end,
    })
}

fn normalized_relative_path(path: &str) -> Option<String> {
    let path = path
        .strip_prefix("/workspace/")
        .or_else(|| path.strip_prefix("workspace/"))
        .or_else(|| path.strip_prefix("./"))
        .unwrap_or(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        None
    } else {
        Some(path.to_owned())
    }
}

fn bounded_message(message: &str) -> String {
    let mut start = message.len().saturating_sub(MAX_DIAGNOSTIC_MESSAGE_BYTES);
    while !message.is_char_boundary(start) {
        start += 1;
    }
    message[start..].to_owned()
}

fn append_bounded(target: &mut String, value: &str) -> bool {
    let room = MAX_DIAGNOSTIC_MESSAGE_BYTES.saturating_sub(target.len());
    if value.len() <= room {
        target.push_str(value);
        return false;
    }
    let mut end = room;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&value[..end]);
    true
}

#[derive(Clone, Debug)]
struct JunitCase {
    name: String,
    class_name: Option<String>,
    start: u64,
    failure: Option<JunitFailure>,
    skipped: bool,
    omitted_failures: u64,
}

#[derive(Clone, Debug)]
struct JunitFailure {
    severity: Severity,
    message: String,
    code: Option<String>,
    end: u64,
}

fn junit_case(tag: &BytesStart<'_>, start: u64) -> Result<JunitCase, ()> {
    let mut name = None;
    let mut class_name = None;
    for attribute in tag.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| ())?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| ())?;
        if value.len() > MAX_DIAGNOSTIC_LABEL_BYTES || value.chars().any(char::is_control) {
            return Err(());
        }
        match attribute.key.as_ref() {
            "name" => name = Some(value.into_owned()),
            "classname" if !value.is_empty() => class_name = Some(value.into_owned()),
            _ => {}
        }
    }
    let name = name.filter(|name| !name.is_empty()).ok_or(())?;
    Ok(JunitCase {
        name,
        class_name,
        start,
        failure: None,
        skipped: false,
        omitted_failures: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn junit_tag(
    result: &mut ParseResult,
    tag: &BytesStart<'_>,
    start: u64,
    end: u64,
    empty: bool,
    current: &mut Option<JunitCase>,
    active_failure: &mut bool,
    step: Option<&StepReference>,
) {
    if tag.as_ref().len() > MAX_RECORD_BYTES {
        result.malformed();
        return;
    }
    let name = tag.name();
    match name.as_ref() {
        "testcase" => {
            if current.is_some() {
                result.malformed();
                return;
            }
            match junit_case(tag, start) {
                Ok(case) => *current = Some(case),
                Err(()) => result.malformed(),
            }
            if empty && let Some(case) = current.take() {
                push_junit_case(result, case, end, step);
            }
        }
        "failure" | "error" if current.is_some() => {
            let is_error = name.as_ref() == "error";
            match junit_failure_attrs(tag) {
                Ok((message, code)) => {
                    if let Some(case) = current {
                        if case.failure.is_none() {
                            case.failure = Some(JunitFailure {
                                severity: if is_error {
                                    Severity::Error
                                } else {
                                    Severity::Failure
                                },
                                message,
                                code,
                                end,
                            });
                        } else {
                            case.omitted_failures = case.omitted_failures.saturating_add(1);
                        }
                    }
                    *active_failure = !empty;
                }
                Err(()) => result.malformed(),
            }
        }
        "skipped" if current.is_some() => {
            if let Some(case) = current {
                case.skipped = true;
            }
        }
        _ => {}
    }
}

fn junit_failure_attrs(tag: &BytesStart<'_>) -> Result<(String, Option<String>), ()> {
    let mut message = String::new();
    let mut code = None;
    for attribute in tag.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| ())?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| ())?;
        match attribute.key.as_ref() {
            "message" => {
                if value.len() > MAX_DIAGNOSTIC_MESSAGE_BYTES {
                    return Err(());
                }
                message = value.into_owned();
            }
            "type" => {
                if value.len() > MAX_DIAGNOSTIC_LABEL_BYTES || value.chars().any(char::is_control) {
                    return Err(());
                }
                if !value.is_empty() {
                    code = Some(value.into_owned());
                }
            }
            _ => {}
        }
    }
    Ok((message, code))
}

fn push_junit_case(
    result: &mut ParseResult,
    case: JunitCase,
    end: u64,
    step: Option<&StepReference>,
) {
    if let Some(failure) = case.failure {
        let message = if failure.message.is_empty() {
            format!("test failed: {}", case.name)
        } else {
            failure.message
        };
        result.push(
            Diagnostic {
                severity: failure.severity,
                message: bounded_message(&message),
                code: failure.code,
                failure_class: Some(FailureClass::CommandFailed),
                source: None,
                test: Some(TestReference {
                    name: case.name,
                    package: None,
                    class_name: case.class_name,
                }),
                step: step.cloned(),
                evidence: Vec::new(),
            },
            case.start..end.max(failure.end),
        );
    } else if case.skipped {
        result.push(
            Diagnostic {
                severity: Severity::Info,
                message: format!("test skipped: {}", case.name),
                code: Some("junit_skipped".into()),
                failure_class: None,
                source: None,
                test: Some(TestReference {
                    name: case.name,
                    package: None,
                    class_name: case.class_name,
                }),
                step: step.cloned(),
                evidence: Vec::new(),
            },
            case.start..end,
        );
    }
    if case.omitted_failures > 0 {
        result.complete = false;
        result.omitted_diagnostics = result
            .omitted_diagnostics
            .saturating_add(case.omitted_failures);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step() -> StepReference {
        StepReference {
            index: 3,
            key: Some("test".into()),
        }
    }

    #[test]
    fn go_json_keeps_test_output_source_and_offsets_without_duplicate_package_fail() {
        let input = concat!(
            "{\"Action\":\"run\",\"Package\":\"example/pkg\",\"Test\":\"TestCreate\"}\n",
            "{\"Action\":\"output\",\"Package\":\"example/pkg\",\"Test\":\"TestCreate\",\"Output\":\"create_test.go:42: wanted 201\\n\"}\n",
            "{\"Action\":\"fail\",\"Package\":\"example/pkg\",\"Test\":\"TestCreate\"}\n",
            "{\"Action\":\"fail\",\"Package\":\"example/pkg\"}\n"
        );
        let parsed = parse_go_test_json(input.as_bytes(), step());
        assert!(parsed.complete);
        assert_eq!(parsed.diagnostics.len(), 1);
        let diagnostic = &parsed.diagnostics[0];
        assert_eq!(
            diagnostic.diagnostic.test.as_ref().unwrap().name,
            "TestCreate"
        );
        assert_eq!(
            diagnostic.diagnostic.source.as_ref().unwrap().line,
            Some(42)
        );
        assert_eq!(diagnostic.diagnostic.step.as_ref(), Some(&step()));
        assert_eq!(
            diagnostic.diagnostic.failure_class,
            Some(FailureClass::CommandFailed)
        );
        assert!(diagnostic.input_range.as_ref().unwrap().start > 0);
    }

    #[test]
    fn go_json_marks_malformed_and_oversized_records_incomplete() {
        let mut input = b"not-json\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_RECORD_BYTES + 1));
        input.push(b'\n');
        let parsed = parse_go_test_json(&input, step());
        assert!(!parsed.complete);
        assert_eq!(parsed.malformed_records, 2);
        assert!(parsed.diagnostics.is_empty());
    }

    #[test]
    fn go_json_classifies_race_and_panic_evidence_as_command_failures() {
        let input = concat!(
            "{\"Action\":\"output\",\"Package\":\"pkg\",\"Test\":\"TestRace\",\"Output\":\"WARNING: DATA RACE\\n\"}\n",
            "{\"Action\":\"fail\",\"Package\":\"pkg\",\"Test\":\"TestRace\"}\n",
            "{\"Action\":\"output\",\"Package\":\"pkg\",\"Test\":\"TestPanic\",\"Output\":\"panic: bad state\\n\"}\n",
            "{\"Action\":\"fail\",\"Package\":\"pkg\",\"Test\":\"TestPanic\"}\n"
        );
        let parsed = parse_go_test_json(input.as_bytes(), step());
        assert!(parsed.complete);
        assert_eq!(parsed.diagnostics.len(), 2);
        assert_eq!(
            parsed.diagnostics[0].diagnostic.code.as_deref(),
            Some("go_race")
        );
        assert_eq!(
            parsed.diagnostics[1].diagnostic.code.as_deref(),
            Some("go_panic")
        );
        assert!(
            parsed
                .diagnostics
                .iter()
                .all(|d| d.diagnostic.failure_class == Some(FailureClass::CommandFailed))
        );
    }

    #[test]
    fn rustc_json_uses_primary_span_and_ignores_artifact_messages() {
        let input = concat!(
            "{\"$message_type\":\"artifact\",\"artifact\":\"x\"}\n",
            "{\"$message_type\":\"diagnostic\",\"message\":\"mismatched types\",\"code\":{\"code\":\"E0308\"},\"level\":\"error\",\"spans\":[{\"file_name\":\"/workspace/src/main.rs\",\"line_start\":3,\"line_end\":3,\"column_start\":2,\"column_end\":4,\"is_primary\":true}]}\n"
        );
        let parsed = parse_rust_compiler_json(input.as_bytes(), step());
        assert!(parsed.complete);
        assert_eq!(parsed.diagnostics.len(), 1);
        let diagnostic = &parsed.diagnostics[0].diagnostic;
        assert_eq!(diagnostic.code.as_deref(), Some("E0308"));
        assert_eq!(diagnostic.source.as_ref().unwrap().path, "src/main.rs");
        assert_eq!(diagnostic.source.as_ref().unwrap().line, Some(3));
        assert_eq!(diagnostic.failure_class, Some(FailureClass::CommandFailed));
    }

    #[test]
    fn junit_reads_failures_and_skips_without_expanding_user_dtds() {
        let xml = br#"<testsuites><testsuite><testcase name="TestA" classname="pkg.A"><failure type="AssertionError" message="expected &lt;x&gt;">stack &amp; detail</failure></testcase><testcase name="TestB"><skipped/></testcase></testsuite></testsuites>"#;
        let parsed = parse_junit_xml(xml, Some(step()));
        assert!(parsed.complete);
        assert_eq!(parsed.diagnostics.len(), 2);
        assert_eq!(
            parsed.diagnostics[0].diagnostic.message,
            "expected <x>stack & detail"
        );
        assert_eq!(
            parsed.diagnostics[0]
                .diagnostic
                .test
                .as_ref()
                .unwrap()
                .class_name
                .as_deref(),
            Some("pkg.A")
        );
        assert_eq!(
            parsed.diagnostics[1].diagnostic.code.as_deref(),
            Some("junit_skipped")
        );

        let dtd = br#"<!DOCTYPE tests [<!ENTITY x "expanded">]><testsuite><testcase name="bad"><failure>&x;</failure></testcase></testsuite>"#;
        let rejected = parse_junit_xml(dtd, None);
        assert!(!rejected.complete);
        assert!(rejected.diagnostics.is_empty());

        let unresolved = br#"<testsuite><testcase name="bad"><failure>&custom;</failure></testcase></testsuite>"#;
        assert!(!parse_junit_xml(unresolved, None).complete);
    }

    #[test]
    fn custom_json_is_byte_bounded_strict_and_never_echoes_invalid_input() {
        let valid = br#"{"schema_version":1,"producer":{"name":"repo-adapter","version":null},"diagnostics":[]}"#;
        assert!(parse_custom_json(valid).is_ok());
        assert_eq!(
            parse_custom_json(b"not json"),
            Err(CustomInputError::InvalidJson)
        );
        assert_eq!(
            parse_custom_json(&vec![b' '; crate::limits::MAX_API_BODY_BYTES + 1]),
            Err(CustomInputError::TooLarge)
        );
        let freshness = br#"{"schema_version":1,"producer":{"name":"repo","version":null},"diagnostics":[],"freshness":"fresh"}"#;
        assert_eq!(
            parse_custom_json(freshness),
            Err(CustomInputError::InvalidJson)
        );
    }
}
