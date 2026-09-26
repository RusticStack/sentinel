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
and rejects unknown fields. Report producers supply diagnostic content only;
the type has no attempt identity, log offsets, input hash, parser provenance,
or freshness fields. The parser is available to adapters, but Sentinel does
not yet expose a report-upload route.

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
authoritative job state (only when it remains the newest attempt), selected
failed step, measured timing/cache clues, bounded recent context, and any
Go test JSON or rustc compiler JSON that parses from the selected log window.
Each parsed log stream is returned as `DiagnosticReport` with
`schema_version: 1`, detected format, collection source, run/job/attempt/step,
the lowercase SHA-256 of the exact parser input bytes, parser version,
freshness, and diagnostics. Its enclosing `parse` object carries completeness,
malformed and omitted counts, and bytes scanned. JUnit XML and custom JSON
parsers are available to report adapters; Sentinel does not yet attach
uploaded JUnit/custom reports.

Freshness is server-authored and is independent from the command verdict:

- `fresh`: evidence was collected from the exact attempt's stored logs and
  the selected step and stream were completely covered;
- `advisory`: evidence was supplied outside the live attempt collection path
  or cannot be tied to the command's current output;
- `incomplete`: parsing stopped at an input limit or malformed/truncated
  content, or the source log has a declared gap or is not complete.

The server never accepts a client assertion of `fresh`. The default failure
request scans from sequence 0, at most 4 MiB or 1,024 frames per call, and
separately seeks the newest 128 frame positions for its fallback excerpt when
a sparse index is available. Legacy pre-D04 flat logs have no sparse tail
index, so their excerpt begins at the available scan position and pages
forward. A parser window that does not cover the selected stream is
`incomplete`, even when the log itself has a durable end marker.
Explicit `after`/`cursor` requests continue the indexed scan and return
`next_cursor` when a page is cut. Missing, partial, malformed, or untrusted
evidence remains visible as advisory or incomplete; it is not silently
promoted to a fresh pass. Report text, source paths, test names, and log
content are untrusted data, never instructions. Any inferred root cause must
be labeled as an inference and cite evidence ranges.

## Parser behavior (X02)

`sentinel-protocol::diagnostics` exposes streaming-by-record parsers for
newline-delimited Go test JSON and rustc compiler JSON, a forward-only JUnit
XML reader, and strict custom JSON decoding. Go test output is retained as a
4 KiB circular tail per active test; successful tests release it. Go
`Action=fail` creates test/package diagnostics and recognizes race and panic
markers. Rust errors/warnings use the primary source span and compiler code;
rendered duplicates are discarded. JUnit reports keep one testcase and one
failure body at a time, reject DTDs and unresolved entities, and preserve
skipped tests as informational records. Unknown XML extensions are skipped.

All parsers stop after 256 MiB or 2,000,000 records, reject individual JSON
records or XML tags above 64 KiB, and return no more than 1,024 diagnostics.
Custom JSON is capped at the API's 1 MiB body limit before deserialization.
They report malformed, omitted, and scanned-byte counts without echoing
invalid parser payloads. Go/rustc record offsets are half-open byte ranges in
the input stream; the log layer maps these back to stable frame positions.
Parser output is never an attempt transition.

The failure response uses an 8 KiB default text budget and accepts at most
64 KiB; its compact JSON body is also capped at 64 KiB. At most 20 diagnostics
are returned, with explicit `truncated`, `omitted_diagnostics`,
`log_complete`, and `log_gaps` fields. If no supported report parses, the
response carries a bounded log tail. The separate literal-search route scans
at most 4 MiB per request and preserves split matches with its continuation
state.

See [logs](logs.md) for frame durability and bounded search, [API](api.md) for
authorization and response shapes, and [compatibility](compatibility.md) for
schema evolution.
