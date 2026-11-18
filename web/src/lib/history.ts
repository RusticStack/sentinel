// History views: the answers of the repository history routes (durations, compare, cross-run log search) and the
// small pure helpers the views share. Unmeasured values are absent, never zero, and the views show them as an em dash.
import { fmtNs } from "./format.ts";

export interface Percentiles { count: number; p50_ns: number; p95_ns: number }

/** The measured phases of an attempt, in the order they are shown; `sub` ones are parts of checkout. */
export const PHASES = [
  { key: "checkout", label: "Checkout", sub: false },
  { key: "checkout_fetch", label: "Checkout: fetch", sub: true },
  { key: "checkout_materialize", label: "Checkout: materialize", sub: true },
  { key: "image_pull", label: "Image pull", sub: false },
  { key: "container_start", label: "Container start", sub: false },
  { key: "steps", label: "Steps", sub: false },
  { key: "finalize", label: "Finalize", sub: false },
] as const;
export type PhaseKey = (typeof PHASES)[number]["key"];
/** The phases the percentile table shows beside the total; the two checkout parts are in the comparison only. */
export const TABLE_PHASES = PHASES.filter((p) => !p.sub);

export interface Sample {
  run: string;
  attempt: string;
  fence: number;
  created_ms: number;
  timings_ns: Partial<Record<PhaseKey, number>>;
  total_ns?: number;
}

export interface JobDurations {
  job: string;
  attempts: number;
  total: Percentiles | null;
  phases: Partial<Record<PhaseKey, Percentiles>>;
  samples?: Sample[];
}

export interface Durations {
  window: { requested: number; runs: number; oldest_ms: number | null; newest_ms: number | null };
  jobs: JobDurations[];
  truncated: boolean;
  unreadable: number;
}

export interface CompareSide {
  attempt: string;
  run: string;
  fence: number;
  created_ms: number;
  present: boolean;
  timings_ns?: Partial<Record<PhaseKey, number>>;
  total_ns?: number;
}

export interface Comparison {
  job: string;
  base: CompareSide;
  head: CompareSide;
  delta_ns: Partial<Record<PhaseKey | "total", number>>;
}

export interface Resume { run: string; attempt: string; after: number; carry: string | null; runs: number }

export interface LogHit { run: string; job: string; attempt: string; seq: number; step: number; stream: "stdout" | "stderr"; text: string }

export interface LogSearch {
  matches: LogHit[];
  attempts_scanned: number;
  scanned_bytes: number;
  expired_attempts: number;
  missing_logs: number;
  runs_in_window: number;
  next: Resume | null;
  complete: boolean;
}

/** The window sizes the views offer; the controller's ceilings are 500 runs for durations and 100 for log search. */
export const DURATION_WINDOWS = ["25", "50", "100", "250", "500"];
export const SEARCH_WINDOWS = ["5", "10", "20", "50", "100"];

const repoPath = (slug: string, repo: string) => `/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(repo)}`;

export function durationsPath(slug: string, repo: string, runs: string | undefined, job: string | undefined): string {
  const q = new URLSearchParams({ runs: runs || "100" });
  if (job) q.set("job", job);
  return `${repoPath(slug, repo)}/durations?${q}`;
}

export const comparePath = (slug: string, repo: string, base: string, head: string) =>
  `${repoPath(slug, repo)}/compare?${new URLSearchParams({ base, head })}`;

/** The first request of a search, or the continuation a previous answer's `next` asks for. */
export function searchPath(slug: string, repo: string, q: string, runs: string | undefined, resume?: Resume | null): string {
  const p = new URLSearchParams({ q });
  if (resume) {
    p.set("runs", String(resume.runs));
    p.set("run", resume.run);
    p.set("attempt", resume.attempt);
    p.set("after", String(resume.after));
    if (resume.carry) p.set("carry", resume.carry);
  } else if (runs) {
    p.set("runs", runs);
  }
  return `${repoPath(slug, repo)}/logs/search?${p}`;
}

/** The answer so far with a continuation's page added; the counters add up, the position is the last page's. */
export function addPage(sofar: LogSearch, page: LogSearch): LogSearch {
  return {
    matches: [...sofar.matches, ...page.matches],
    attempts_scanned: sofar.attempts_scanned + page.attempts_scanned,
    scanned_bytes: sofar.scanned_bytes + page.scanned_bytes,
    expired_attempts: sofar.expired_attempts + page.expired_attempts,
    missing_logs: sofar.missing_logs + page.missing_logs,
    runs_in_window: sofar.runs_in_window,
    next: page.next,
    complete: page.complete,
  };
}

/** A hit's text cut around its first occurrence of the term, for marking; the match is literal and case-sensitive. */
export function splitHit(text: string, term: string): [before: string, hit: string, after: string] {
  const at = term ? text.indexOf(term) : -1;
  return at < 0 ? [text, "", ""] : [text.slice(0, at), term, text.slice(at + term.length)];
}

/** A signed change for the comparison: the sign is in the text, so colour is never the only signal. */
export function fmtDelta(ns: number | null | undefined): string {
  if (ns === null || ns === undefined) return "—";
  if (ns === 0) return "no change";
  return `${ns > 0 ? "+" : "−"}${fmtNs(Math.abs(ns))}`;
}

/** The base's value as a share the head changed by, e.g. "+12%"; absent when the base was zero or unmeasured. */
export function fmtShare(base: number | null | undefined, delta: number | null | undefined): string {
  if (!base || delta === null || delta === undefined || delta === 0) return "";
  const share = Math.round((100 * delta) / base);
  return `${share >= 0 ? "+" : "−"}${Math.abs(share)}%`;
}

/** "12 runs (100 asked for)" and the span they cover. */
export function windowWords(w: Durations["window"]): string {
  if (!w.runs) return "No runs in this repository yet.";
  const runs = `${w.runs} ${w.runs === 1 ? "run" : "runs"}`;
  return w.runs < w.requested ? `The last ${runs} (up to ${w.requested} asked for).` : `The last ${runs}.`;
}

/** What a finished or paused search says about what it read. */
export function searchWords(s: Pick<LogSearch, "attempts_scanned" | "scanned_bytes" | "expired_attempts" | "missing_logs" | "complete" | "runs_in_window">, fmtBytes: (n: number) => string): string {
  const parts = [`Read ${s.attempts_scanned} ${s.attempts_scanned === 1 ? "log" : "logs"} (${fmtBytes(s.scanned_bytes)}) of the last ${s.runs_in_window} ${s.runs_in_window === 1 ? "run" : "runs"}.`];
  if (s.expired_attempts) parts.push(`${s.expired_attempts} ${s.expired_attempts === 1 ? "log was" : "logs were"} removed by retention and cannot be searched.`);
  if (s.missing_logs) parts.push(`${s.missing_logs} ${s.missing_logs === 1 ? "attempt has" : "attempts have"} no stored log.`);
  parts.push(s.complete ? "The search covered the whole window." : "More of the window is left to search.");
  return parts.join(" ");
}

/** The newest two samples as the default base and head of a comparison. */
export function defaultPair(samples: Sample[] | undefined): { base: string | null; head: string | null } {
  return { head: samples?.[0]?.attempt ?? null, base: samples?.[1]?.attempt ?? null };
}
