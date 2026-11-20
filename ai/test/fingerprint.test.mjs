// The two keys an analysis is cached under: the evidence digest, which is the exact bundle, and the
// failure fingerprint, which survives a rerun. Anything volatile between two runs of the same
// failure has to be masked, or the fingerprint would never match.

import assert from "node:assert/strict";
import test from "node:test";

import { digest, fingerprint } from "../src/fingerprint.ts";

const bundle = (overrides = {}) =>
  JSON.stringify({
    schema: "sentinel.ai-context/1",
    attempt: "att_00000000-0000-4000-8000-000000000001",
    authoritative: { current_attempt: true, job_state: "failed", failure_class: "test_failure" },
    failed_step: { index: 1, id: "unit", outcome: "failed", exit_code: 1, duration_ns: 1_000_000 },
    diagnostics: [
      {
        id: "diag-1",
        severity: "error",
        message: "assertion failed: left != right (took 812ms, frame 0x5f3a91c)",
        test: { name: "adds two numbers", package: "math" },
      },
    ],
    log: { frames: [{ id: "log-7", sequence: 7, step: 1, text: "assertion failed: left != right" }] },
    ...overrides,
  });

test("the digest is the evidence byte for byte", () => {
  assert.equal(digest("a bundle"), digest("a bundle"));
  assert.notEqual(digest("a bundle"), digest("a bundle "));
  assert.match(digest("a bundle"), /^[0-9a-f]{64}$/);
});

test("a second attempt at the same failure has the same fingerprint", () => {
  const first = fingerprint(bundle());
  const rerun = fingerprint(
    bundle({
      attempt: "att_00000000-0000-4000-8000-000000000002",
      failed_step: {
        index: 1,
        id: "unit",
        outcome: "failed",
        exit_code: 1,
        duration_ns: 9_999_999,
      },
      diagnostics: [
        {
          id: "diag-1",
          severity: "error",
          // The duration, the frame and the run's ids change between runs and are masked.
          message: "assertion failed: left != right (took 921ms, frame 0xaa11bb2)",
          test: { name: "adds two numbers", package: "math" },
        },
      ],
      log: { frames: [{ id: "log-19", sequence: 19, step: 1, text: "assertion failed" }] },
    }),
  );
  assert.equal(first, rerun, "the same failure on a later run must reuse the analysis");
  assert.notEqual(digest(bundle()), digest(bundle({ attempt: "att_other" })), "the digest moved");
});

test("another failure is another fingerprint", () => {
  const base = fingerprint(bundle());
  assert.notEqual(
    base,
    fingerprint(
      bundle({
        diagnostics: [
          {
            id: "diag-1",
            severity: "error",
            message: "assertion failed: left != right",
            test: { name: "subtracts two numbers", package: "math" },
          },
        ],
      }),
    ),
    "a different test is a different failure",
  );
  assert.notEqual(
    base,
    fingerprint(
      bundle({
        authoritative: {
          current_attempt: true,
          job_state: "failed",
          failure_class: "build_failure",
        },
      }),
    ),
    "a different failure class is a different failure",
  );
  assert.notEqual(
    base,
    fingerprint(
      bundle({
        diagnostics: [
          {
            id: "diag-1",
            severity: "error",
            message: "cannot find crate `serde`",
            test: { name: "adds two numbers", package: "math" },
          },
        ],
      }),
    ),
    "a different error line is a different failure",
  );
  assert.notEqual(
    base,
    fingerprint(bundle({ failed_step: { index: 1, id: "lint", outcome: "failed", exit_code: 1 } })),
    "a different step is a different failure",
  );
});

test("a bundle that does not decode is keyed by its own bytes and never reused by signature", () => {
  const raw = "not json at all";
  assert.equal(fingerprint(raw), digest(raw));
  assert.equal(fingerprint("{}"), fingerprint("{}"), "an empty document is one signature");
  assert.notEqual(fingerprint("{}"), fingerprint(raw));
});

test("the same findings in a different order are the same failure", () => {
  const diagnostics = [
    { id: "diag-1", severity: "error", message: "first", test: { name: "a", package: "p" } },
    { id: "diag-2", severity: "error", message: "second", test: { name: "b", package: "p" } },
  ];
  assert.equal(
    fingerprint(bundle({ diagnostics })),
    fingerprint(bundle({ diagnostics: [...diagnostics].reverse() })),
  );
});
