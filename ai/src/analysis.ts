// `sentinel.ai-analysis/1`: the one document a model's answer may be (Y05).
//
// The controller decodes this document itself before it stores an answer, so this module is the
// process's own half of one contract: the same schema string, the same bounds, the same shape. It
// exists for two reasons — a malformed answer is refused here, so a request ends `unavailable` with
// a reason rather than a controller refusing the settlement, and the prompt can state exactly what
// the answer has to look like instead of asking for prose and hoping.
//
// Every claim cites evidence from the bundle it was shown: an attempt and the bundle's own
// identifier for a log frame (`log-<sequence>`) or a diagnostic (`diag-<n>`). A citation that names
// something the controller did not serve resolves to nothing and is dropped before anyone sees the
// analysis, so guessing costs the answer its claim rather than making it look stronger.

/** The document's version. `crates/sentinel-protocol/src/analysis.rs` states the same one. */
export const ANALYSIS_SCHEMA = "sentinel.ai-analysis/1";
export const MAX_ANALYSIS_BYTES = 8 << 10;
export const MAX_CLAIMS = 8;
export const MAX_CLAIM_BYTES = 1_024;
export const MAX_SUMMARY_BYTES = 2_048;
export const MAX_CITATIONS = 8;
export const MAX_DIAGNOSTICS = 20;

export interface Citation {
  /** `att_…`: the attempt whose stored evidence the identifier names. */
  readonly attempt: string;
  /** `log-<sequence>` or `diag-<n>`, exactly as the bundle writes it. */
  readonly evidence: string;
}

export interface Claim {
  readonly text: string;
  readonly citations: Citation[];
}

export interface Analysis {
  readonly schema: typeof ANALYSIS_SCHEMA;
  readonly summary: string;
  readonly claims: Claim[];
}

/** What the model is told to answer with, appended to the prompt's own instructions. */
export const ANSWER_FORMAT = [
  `Answer with one JSON object and nothing else. Its schema is "${ANALYSIS_SCHEMA}":`,
  '{"schema":"sentinel.ai-analysis/1","summary":"…","claims":[{"text":"…",',
  '"citations":[{"attempt":"att_…","evidence":"log-<sequence>"}]}]}.',
  `At most ${MAX_CLAIMS} claims, each with one to ${MAX_CITATIONS} citations and at most`,
  `${MAX_CLAIM_BYTES} bytes of text; the summary is at most ${MAX_SUMMARY_BYTES} bytes.`,
  "Cite only identifiers that appear in the bundle: a log frame's \"id\" (log-<sequence>) or a",
  'diagnostic\'s "id" (diag-<n>), and the bundle\'s own "attempt". Do not invent an identifier,',
  "do not cite a frame the bundle does not contain, and do not add fields the schema does not have.",
  "A claim you cannot cite is a claim to leave out.",
].join(" ");

const ATTEMPT = /^att_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVIDENCE = /^(?:log-(?:0|[1-9][0-9]{0,19})|diag-(?:[1-9]|1[0-9]|20))$/;

/** Why an answer is not an analysis. The message is a sentence a request's reason can carry. */
export interface Refusal {
  readonly reason: string;
}

/**
 * A model's answer decoded strictly: one JSON object, the schema this build states, no field it does
 * not have, every bound the controller keeps. A code fence, prose around the object, a missing field
 * and an extra one are all refusals — the answer is stored whole or not at all.
 */
export function decode(text: string): Analysis | Refusal {
  if (Buffer.byteLength(text, "utf8") > MAX_ANALYSIS_BYTES) {
    return { reason: "schema: the answer is over the analysis bound" };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { reason: "schema: the answer is not a JSON document" };
  }
  return check(value);
}

/** The same check over an already-parsed document, which is what a reused analysis is. */
export function check(value: unknown): Analysis | Refusal {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { reason: "schema: the answer is not an object" };
  }
  const document = value as Record<string, unknown>;
  for (const key of Object.keys(document)) {
    if (key !== "schema" && key !== "summary" && key !== "claims") {
      return { reason: `schema: the answer has a field this version does not: ${key}` };
    }
  }
  if (document.schema !== ANALYSIS_SCHEMA) {
    return { reason: "schema: the answer names another schema" };
  }
  const summary = text(document.summary, MAX_SUMMARY_BYTES);
  if (summary === null) {
    return { reason: "schema: the answer's summary is missing, blank or too long" };
  }
  const claims = document.claims;
  if (!Array.isArray(claims) || claims.length === 0 || claims.length > MAX_CLAIMS) {
    return { reason: `schema: the answer has ${Array.isArray(claims) ? claims.length : "no"} claims` };
  }
  const checked: Claim[] = [];
  for (const claim of claims) {
    if (typeof claim !== "object" || claim === null || Array.isArray(claim)) {
      return { reason: "schema: a claim is not an object" };
    }
    const entry = claim as Record<string, unknown>;
    for (const key of Object.keys(entry)) {
      if (key !== "text" && key !== "citations") {
        return { reason: `schema: a claim has a field this version does not: ${key}` };
      }
    }
    const body = text(entry.text, MAX_CLAIM_BYTES);
    if (body === null) {
      return { reason: "schema: a claim's text is missing, blank or too long" };
    }
    const citations = entry.citations;
    if (!Array.isArray(citations) || citations.length === 0 || citations.length > MAX_CITATIONS) {
      return { reason: "schema: a claim cites no evidence, or more citations than the bound" };
    }
    const cited: Citation[] = [];
    for (const citation of citations) {
      if (typeof citation !== "object" || citation === null || Array.isArray(citation)) {
        return { reason: "schema: a citation is not an object" };
      }
      const reference = citation as Record<string, unknown>;
      for (const key of Object.keys(reference)) {
        if (key !== "attempt" && key !== "evidence") {
          return { reason: `schema: a citation has a field this version does not: ${key}` };
        }
      }
      if (typeof reference.attempt !== "string" || !ATTEMPT.test(reference.attempt)) {
        return { reason: "schema: a citation does not name an attempt" };
      }
      if (typeof reference.evidence !== "string" || !EVIDENCE.test(reference.evidence)) {
        return { reason: "schema: a citation does not name a log frame or a diagnostic" };
      }
      cited.push({ attempt: reference.attempt, evidence: reference.evidence });
    }
    checked.push({ text: body, citations: cited });
  }
  return { schema: ANALYSIS_SCHEMA, summary, claims: checked };
}

/** Whether a decoded value is an analysis rather than a refusal. */
export function isAnalysis(value: Analysis | Refusal): value is Analysis {
  return (value as Refusal).reason === undefined;
}

/** One text field within `limit` bytes and not blank. */
function text(value: unknown, limit: number): string | null {
  if (typeof value !== "string" || value.trim().length === 0) {
    return null;
  }
  return Buffer.byteLength(value, "utf8") > limit ? null : value;
}
