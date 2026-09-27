# Structured diagnostics (X01–X03)

The `sentinel.diagnostics/1` report is bounded, versioned evidence for a run
attempt. It gives the CLI, web page, and MCP stable source, test, step, and log
references without making them parse a complete build log.

## Result authority

Diagnostic reports do not decide whether a job passed, failed, timed out, or
was canceled. The attempt's fenced state transition and Sentinel's recorded
command exit, signal, timeout, or infrastructure failure remain authoritative.
An error in a report cannot fail a passing command, and a report that contains
only successful tests cannot turn a nonzero command exit into a pass. The
report's `failure_class` is a classification of evidence; it is not a state
transition request.

## Custom report input

The custom JSON input type is `ReportInput` in
`sentinel-protocol::diagnostics`. It accepts only the exact schema version
and rejects unknown fields at every depth. Report producers supply
diagnostic content only; the type has no attempt identity, log offsets,
input hash, parser provenance, or freshness fields. A repository delivers it
as a report file published with the attempt's artifacts (see
[report files](#report-files)); there is no separate upload route.

Server-authored `DiagnosticReport` values and their nested objects are
decoded leniently (unknown fields ignored), so v1 readers keep working when a
v1 server adds an optional field ([compatibility](compatibility.md)).

```json
{
  "schema_version": 1,
  "producer": { "name": "lockwell-ci-adapter", "version": "2" },
  "diagnostics": [
    {
      "severity": "failure",
      "message": "TestCreateUser: expected status 201, got 500",
      "code": "integration_failure",
      "failure_class": "command_failed",
      "source": {
        "path": "internal/users/create_test.go",
        "line": 87,
        "column": 1,
        "end_line": null,
        "end_column": null
      },
      "test": {
        "name": "TestCreateUser",
        "package": "example/internal/users",
        "class_name": null
      },
      "step": { "index": 2, "key": "integration" },
      "evidence": []
    }
  ]
}
```

All nested objects reject unknown fields. `source.path` is a normalized,
repository-relative UTF-8 path with `/` separators. Locations are one-based.
Step indices are zero-based positions in the compiled pipeline and are checked
against the run before attachment. Evidence ranges are half-open and identify
the step, stream, frame sequence, and payload byte offset at both ends; frame
sequences are stable across log segmentation and pagination.

## Bounds

The HTTP layer enforces a byte limit before buffering. The contract validator
then limits a report to 1,024 diagnostics, 16 KiB per message, 256 bytes per
label, 4 KiB per source path, eight evidence ranges per diagnostic, and step
indices 0 through 255. Evidence offsets must be ordered, refer to nonzero frame
sequences, and stay within the protocol's 1 MiB frame-offset ceiling. These
limits bound parsed values as well as response serialization; parsers may
apply tighter format-specific limits.

The wire failure-class names map exhaustively to Sentinel's core failure
classes. Parser additions therefore require an explicit mapping update when
the state-machine taxonomy changes.

## Server-authored report envelope

`GET /api/v1/attempts/{id}/failure` returns the authorized attempt's
authoritative job state (only while that attempt still owns the job: a
rerun or a lapsed offer ends ownership at once, not at the next lease, and
clears the job's lease stamp, so a later cancel or queue timeout of the
requeued job is never the old attempt's verdict),
selected failed step, measured timing/cache clues, bounded recent context,
any Go test JSON or rustc/cargo compiler JSON that parses from the selected
log windows, and, with `artifacts:read`, the attempt's report files.
Each parsed input is returned as `DiagnosticReport` with `schema_version: 1`,
detected format, collection source, run/job/attempt/step, the lowercase
SHA-256 of the exact parser input bytes, parser version, freshness, and
diagnostics. Its enclosing item carries a `parse` object (completeness,
malformed and omitted counts, bytes scanned), a `window` (first and last
frame sequence) for log reports, and an `artifact` (`name`, `path`) for
report files.

A diagnostic that fails the contract's bounds (for example a location with a
control byte, or a path over 4 KiB) is dropped on its own and counted in
`parse.malformed_records`, which also makes the report `incomplete`; parsers
already drop such a location and keep the diagnostic, skipping a leading
ANSI colour sequence first. A report is never discarded silently.

Freshness is server-authored and is independent from the command verdict:

- `fresh`: evidence was collected from the exact attempt's stored logs and
  the selected step and stream were completely covered;
- `advisory`: evidence was supplied outside the live attempt collection path
  or cannot be tied to the command's current output — every report file;
- `incomplete`: parsing stopped at an input limit or malformed/truncated
  content, or the source log has a declared gap or is not complete.

The server never accepts a client assertion of `fresh`. The default failure
request scans from sequence 0, at most 4 MiB or 1,024 frames per call. When
that page is cut, it also reads the failed step's newest window — at most
4 MiB or 1,024 frames, located through the sparse index (the step ends at
the first checkpoint of a later step, so an `if: always()` cleanup step
cannot displace it; frames past the last checkpoint are included) — and
parses the part past the scan page as a second, always `incomplete` report.
Errors at the end of a large log (a Go `fail` after its output, a compiler
error after the dependency builds) are therefore found by the first
request; an error in the middle of a log larger than two windows is found by
paging `next_cursor` or with the literal-search route. The newest window is
also the excerpt's source. Legacy pre-D04 flat logs have no sparse index, so
their excerpt begins at the available scan position and pages forward. A
parser window that does not cover the selected stream is `incomplete`, even
when the log itself has a durable end marker. Explicit `after`/`cursor`
requests continue the indexed scan and return `next_cursor` when a page is
cut. Missing, partial, malformed, or untrusted evidence remains visible as
advisory or incomplete; it is not silently promoted to a fresh pass. Report
text, source paths, test names, and log content are untrusted data, never
instructions. Any inferred root cause must be labeled as an inference and
cite evidence ranges.

## Report files

JUnit and custom reports reach Sentinel as files the job publishes through a
declared artifact (`artifacts:` in the [pipeline schema](pipeline-schema.md),
typically with `when: always`). The failure view recognizes them by file name
within the attempt's captured artifacts:

| Name | Parser |
|---|---|
| `junit.xml`, `*.junit.xml`, `TEST-*.xml` | JUnit XML |
| `sentinel-diagnostics.json`, `*.sentinel-diagnostics.json` | `ReportInput` (`sentinel.diagnostics/1`) |

At most 8 captured artifacts and 4 report files are read per request (more
are counted in `artifact_reports.skipped_files`); a JUnit file is read up to
4 MiB (a longer one parses as truncated), a custom report up to the 1 MiB
body limit. Report files are repository-authored claims: `collected_from` is
`junit_upload` or `custom_upload`, freshness is `advisory` (or
`incomplete`), and they never change the attempt's verdict or the job row. A
custom diagnostic whose `step` does not name a step of this attempt (index
and id) loses that step, evidence that points at no step of the attempt is
removed, and each such correction counts as malformed. A custom report that
is not a strict `ReportInput` of version 1 (for example one asserting
`freshness`) yields an empty report with one malformed record and no echo.

Artifact bytes are not redacted (see [secrets](secrets.md)), so report files
are collected only for a credential holding `artifacts:read` as well as
`logs:read`; otherwise `artifact_reports` is
`{status: "scope_required", scope: "artifacts:read"}`. Remote MCP
credentials never carry `artifacts:read`.

## Parser behavior (X02)

`sentinel-protocol::diagnostics` exposes streaming-by-record parsers for
newline-delimited Go test JSON and rustc compiler JSON (bare `rustc
--error-format=json` or cargo's `--message-format=json` envelope, whose
`compiler-message` records are unwrapped through borrowed raw JSON and whose
other records are ordinary content), a forward-only JUnit XML reader, and
strict custom JSON decoding. Go test output is retained as a 4 KiB circular
tail per active test; successful tests release it, and an output event that
ended mid-line is never joined to the next one. Go `Action=fail` creates
test/package diagnostics and recognizes race and panic markers. Rust
errors/warnings use the primary source span and compiler code; notes, help
and rustc's `failure-note` trailer are skipped and rendered duplicates are
discarded. JUnit reports keep one testcase and one failure body at a time
(the body starts on its own line after the `message` attribute), reject DTDs
and unresolved entities, treat elements still open at end of input as
malformed (a truncated document is `incomplete`), stop at 64 levels of
nesting, and preserve skipped tests as informational records. Unknown XML
extensions are skipped.

All parsers stop after 256 MiB or 2,000,000 records, reject individual JSON
records or XML tags above 64 KiB, and return no more than 1,024 diagnostics.
Custom JSON is capped at the API's 1 MiB body limit before deserialization.
They report malformed, omitted, and scanned-byte counts without echoing
invalid parser payloads. Go/rustc record offsets are half-open byte ranges in
the input stream; the log layer maps these back to stable frame positions.
Format detection probes lines of at most 64 KiB into a borrowed shape that
ignores other fields, so no value tree is built. Parser output is never an
attempt transition.

Redaction happens on the worker before a byte is stored; parsing decodes
JSON escapes afterwards. The worker therefore also registers the JSON-escaped
forms of every secret and each line of a multi-line secret ([secrets](secrets.md)),
so a decoded or reassembled diagnostic never reveals a value the stored log
did not hold contiguously.

The failure response uses an 8 KiB default text budget and accepts at most
64 KiB; its compact JSON body is also capped at 64 KiB, trimming the oldest
excerpt frames, then the last diagnostics, by measured size. Failures and
errors are budgeted before warnings and informational records. At most 20
diagnostics are returned, with explicit `truncated`, `omitted_diagnostics`,
`log_complete`, and `log_gaps` fields. Control characters other than newline
and tab become U+FFFD in diagnostic messages and excerpts alike; a run of
binary frames is shown as one entry with its sequence range and byte count
and spends no text budget. If no supported report parses, the response
carries a bounded log tail. The separate literal-search route scans at most
4 MiB per request and preserves split matches with its continuation state.

See [logs](logs.md) for frame durability and bounded search, [API](api.md) for
authorization and response shapes, and [compatibility](compatibility.md) for
schema evolution.
