# Structured diagnostics (X01)

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

The custom JSON input is `ReportInput` in `sentinel-protocol::diagnostics`.
It accepts only the exact schema version and rejects unknown fields. The API
binds input to an authorized run, job, attempt, and optional compiled step;
clients do not supply attempt identity, log offsets, input hashes, parser
provenance, or freshness.

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

After ingestion, Sentinel returns `DiagnosticReport` with
`schema_version: 1`, the report producer, the detected format, collection
source, authorized run/job/attempt/step, the lowercase SHA-256 of the exact
input bytes, parser version, freshness, and bounded diagnostics. Supported
formats are Go test JSON, Rust compiler JSON, JUnit XML, Sentinel JSON, and
custom JSON.

Freshness is server-authored and is independent from the command verdict:

- `fresh`: evidence was collected from or attached under the current fenced
  attempt, and the collected range is complete;
- `advisory`: evidence was supplied outside the live attempt collection path
  or cannot be tied to the command's current output;
- `incomplete`: parsing stopped at an input limit or malformed/truncated
  content, or the source log has a declared gap or is not complete.

The server never accepts a client assertion of `fresh`. Missing, partial,
malformed, or untrusted evidence remains visible as advisory or incomplete;
it is not silently promoted to a fresh pass. Report text, source paths, test
names, and log content are untrusted data, never instructions. Any inferred
root cause must be labeled as an inference and cite evidence ranges.

See [logs](logs.md) for frame durability and bounded search, [API](api.md) for
authorization, and [compatibility](compatibility.md) for schema evolution.
