// `sentinel.ai-plan/1`: what a log-search question becomes before any log is read (Y07).
//
// The question never reaches a log directly. The model answers it with a plan of at most six reads
// of what the controller already serves — an indexed literal search across the repository's recent
// runs, or one attempt's failure context — and the controller executes that plan under the
// requester's own delegation. This module is the process's half of that contract: the same schema
// string and the same bounds as `crates/sentinel-protocol/src/plan.rs`, checked here so an
// out-of-bounds plan never reaches the controller at all.
//
// A plan this file refuses ends the request `unavailable` with the reason, which costs nothing: the
// reads it would have asked for never ran.

/** The document's version. `crates/sentinel-protocol/src/plan.rs` states the same one. */
export const PLAN_SCHEMA = "sentinel.ai-plan/1";
export const MAX_PLAN_BYTES = 4 << 10;
export const MAX_READS = 6;
export const MAX_NEEDLE = 256;
export const MAX_RUNS = 100;
export const MAX_MATCHES = 25;

/** A read of evidence the controller already serves. */
export type Read =
  | {
      readonly kind: "search";
      /** The literal to find, exactly as it appears in a log line. */
      readonly q: string;
      readonly runs: number;
      readonly limit: number;
    }
  | { readonly kind: "context"; readonly attempt: string };

export interface Plan {
  readonly schema: typeof PLAN_SCHEMA;
  readonly reads: Read[];
}

/** What the model is told to answer the first question with. */
export const PLAN_FORMAT = [
  `You may not read the logs yourself. Answer with one JSON object and nothing else: a plan of the`,
  `reads that would answer the question. Its schema is "${PLAN_SCHEMA}":`,
  '{"schema":"sentinel.ai-plan/1","reads":[{"kind":"search","q":"literal text","runs":20,"limit":10},',
  '{"kind":"context","attempt":"att_…"}]}.',
  `At most ${MAX_READS} reads. A "search" read finds one literal string, byte for byte, in the log`,
  `lines of the repository's newest "runs" runs (1–${MAX_RUNS}), returning at most "limit" lines`,
  `(1–${MAX_MATCHES}); it is not a regular expression, and a shorter literal that appears in the`,
  `error text finds more than a sentence from the question. A "context" read returns one attempt's`,
  "diagnostics and newest log lines, which is where a failure is explained; its attempt must be one",
  "the question or the search results name. Search first when you do not know which attempt to read.",
  `A literal is at most ${MAX_NEEDLE} bytes and must not be blank. Do not add fields the schema does`,
  "not have: a plan with one is refused and the question goes unanswered.",
].join(" ");

/** Why a plan is not executable. The message is a sentence a request's reason can carry. */
export interface Refusal {
  readonly reason: string;
}

/**
 * A model's plan decoded strictly: the schema this build states, no field it does not execute, every
 * bound the controller keeps. Prose around the object, a code fence, a missing field and an extra one
 * are all refusals.
 */
export function decode(text: string): Plan | Refusal {
  if (Buffer.byteLength(text, "utf8") > MAX_PLAN_BYTES) {
    return { reason: "plan: the plan is over its bound" };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { reason: "plan: the plan is not a JSON document" };
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { reason: "plan: the plan is not one object" };
  }
  const document = value as Record<string, unknown>;
  if (!only(document, ["schema", "reads"])) {
    return { reason: "plan: the plan has a field this build does not execute" };
  }
  if (document.schema !== PLAN_SCHEMA) {
    return { reason: "plan: the plan names another schema" };
  }
  if (!Array.isArray(document.reads) || document.reads.length === 0) {
    return { reason: "plan: the plan names no read" };
  }
  if (document.reads.length > MAX_READS) {
    return { reason: "plan: the plan names more reads than it may" };
  }
  const reads: Read[] = [];
  for (const read of document.reads) {
    if (typeof read !== "object" || read === null || Array.isArray(read)) {
      return { reason: "plan: a read is not one object" };
    }
    const item = read as Record<string, unknown>;
    if (item.kind === "search") {
      if (!only(item, ["kind", "q", "runs", "limit"])) {
        return { reason: "plan: a search names a field this build does not execute" };
      }
      const q = item.q;
      if (
        typeof q !== "string" ||
        q.trim().length === 0 ||
        Buffer.byteLength(q, "utf8") > MAX_NEEDLE
      ) {
        return { reason: "plan: a search's literal is blank or over its bound" };
      }
      const runs = count(item.runs, MAX_RUNS);
      if (runs === null) {
        return { reason: "plan: a search's run window is outside what it may name" };
      }
      const limit = count(item.limit, MAX_MATCHES);
      if (limit === null) {
        return { reason: "plan: a search's match count is outside what it may ask for" };
      }
      reads.push({ kind: "search", q, runs, limit });
    } else if (item.kind === "context") {
      if (!only(item, ["kind", "attempt"])) {
        return { reason: "plan: a context read names a field this build does not execute" };
      }
      if (typeof item.attempt !== "string" || !ATTEMPT.test(item.attempt)) {
        return { reason: "plan: a context read names no attempt" };
      }
      reads.push({ kind: "context", attempt: item.attempt });
    } else {
      return { reason: "plan: the plan names a read this build does not execute" };
    }
  }
  return { schema: PLAN_SCHEMA, reads };
}

/** Whether `value` decoded as a plan rather than a refusal. */
export function isPlan(value: Plan | Refusal): value is Plan {
  return "reads" in value;
}

/** The canonical document the controller receives: the schema, then each read in order. */
export function encode(plan: Plan): string {
  return JSON.stringify({
    schema: PLAN_SCHEMA,
    reads: plan.reads.map((read) =>
      read.kind === "search"
        ? { kind: read.kind, q: read.q, runs: read.runs, limit: read.limit }
        : { kind: read.kind, attempt: read.attempt },
    ),
  });
}

const ATTEMPT = /^att_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Whether `value` names only `allowed` keys: a plan this build would partly execute is not one. */
function only(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

/** A whole number in `1..=max`, or `null` for anything else. */
function count(value: unknown, max: number): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= max
    ? value
    : null;
}
