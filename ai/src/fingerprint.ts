// The two keys a request is cached under, computed from the evidence bundle it will send.
//
// `digest` is the bundle's own bytes: one attempt asked about twice is the same question, and a
// bundle that changed — a new log frame, a shorter budget — is not. `fingerprint` is the failure's
// signature, which survives a new attempt: a rerun of the same failing step, test and error lines
// reuses the analysis the earlier run paid for, marked reused.
//
// Both are SHA-256 hex, because the controller stores them as fixed-width keys and never reads
// their structure.

import { createHash } from "node:crypto";

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

/** The exact evidence this request would send: one digest per bundle, byte for byte. */
export function digest(bundle: string): string {
  return sha256(bundle);
}

/**
 * The failure's signature: what failed, which test or code location, and the first line of what it
 * said — with the parts that change between runs masked, because a duration, a temporary path or a
 * frame count is not what makes two failures the same one.
 *
 * A bundle that does not decode yields the digest of its raw text: a request whose evidence cannot
 * be read is never served from a cached answer about other evidence.
 */
export function fingerprint(bundle: string): string {
  let document: unknown;
  try {
    document = JSON.parse(bundle);
  } catch {
    return sha256(bundle);
  }
  if (typeof document !== "object" || document === null) {
    return sha256(bundle);
  }
  const evidence = document as Bundle;
  const parts: string[] = [];
  parts.push(`class=${evidence.authoritative?.failure_class ?? ""}`);
  parts.push(`step=${normalize(evidence.failed_step?.id ?? "")}`);
  parts.push(`exit=${evidence.failed_step?.exit_code ?? ""}`);
  const diagnostics = (evidence.diagnostics ?? []).map((diagnostic) => {
    const identity = diagnostic.test
      ? `test:${diagnostic.test.package ?? ""}/${diagnostic.test.name ?? ""}`
      : diagnostic.code
        ? `code:${diagnostic.code}`
        : `at:${diagnostic.source?.path ?? ""}:${diagnostic.source?.line ?? ""}`;
    return `${identity} ${normalize(firstLine(diagnostic.message ?? ""))}`;
  });
  // Sorted, so a different order of the same findings is the same failure.
  parts.push(...[...new Set(diagnostics)].sort());
  return sha256(parts.join("\n"));
}

/** The bundle's fields this signature reads, as `sentinel.ai-context/1` serves them. */
interface Bundle {
  readonly authoritative?: {
    readonly failure_class?: string | null;
  };
  readonly failed_step?: {
    readonly id?: string;
    readonly exit_code?: number | null;
  } | null;
  readonly diagnostics?: readonly {
    readonly code?: string | null;
    readonly message?: string | null;
    readonly source?: { readonly path?: string; readonly line?: number | null } | null;
    readonly test?: {
      readonly name?: string | null;
      readonly package?: string | null;
    } | null;
  }[];
}

function firstLine(text: string): string {
  const end = text.indexOf("\n");
  return end === -1 ? text : text.slice(0, end);
}

/** Everything between a run's specifics: hex ids, numbers and runs of whitespace. */
function normalize(text: string): string {
  return text
    .replace(/[0-9a-f]{6,}/gi, "#")
    .replace(/\d+/g, "#")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}
