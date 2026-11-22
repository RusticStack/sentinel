// The evaluation of the analysis prompt (Y09): a set of seeded failures, each an evidence bundle
// with the identifiers of the line that actually failed, served through `serve` exactly as a queued
// request is, and scored on what the backlog row names — the share of analyses citing the actual
// error line, citation validity, canary leakage, and cost and latency p95 per analysis.
//
// A run is one record, keyed by provider, model, prompt version and the set's digest. The gate
// holds a record to the absolute requirements (every citation resolves, nothing leaks) and to the
// last committed record with the same key, so a prompt or model change that cites the failing line
// less often, or costs or takes more, is refused before it ships.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Effect } from "effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";

import type { Analysis } from "./analysis.ts";
import type { Config } from "./config.ts";
import { Controller, type ControllerShape, type RequestRow } from "./controller.ts";
import type { ProviderName } from "./policy.ts";
import { PROMPT_VERSION, serve } from "./service.ts";

export const RECORD_SCHEMA = "sentinel.ai-eval/1";

/** The fixtures a case may come from: the three pilots and the X08 100 MiB noisy log. */
export const SOURCES = ["cli", "ripgrep", "gson", "x08"] as const;
export type Source = (typeof SOURCES)[number];

/** One seeded failure. */
export interface Case {
  readonly id: string;
  readonly source: Source;
  /** What was broken on purpose, in a sentence. */
  readonly seeded: string;
  /** The `sentinel.ai-context/1` document the controller serves for the failed attempt. */
  readonly bundle: Bundle;
  /** The identifiers of the line with the actual error: citing any one of them is a hit. */
  readonly error_evidence: readonly string[];
  /** Values the seeded log held and the bundle must not: none may reach a prompt. */
  readonly canaries: readonly string[];
}

/** The bundle's fields the evaluation reads. */
export interface Bundle {
  readonly schema: string;
  readonly attempt: string;
  readonly diagnostics?: readonly { readonly id?: string }[];
  readonly log?: { readonly frames?: readonly { readonly id?: string }[] };
}

/** What serving one case produced. */
export interface Observation {
  readonly case: string;
  /** The stored analysis, or `null` when the request ended `unavailable`. */
  readonly analysis: Analysis | null;
  readonly reason: string | null;
  /** Every request body sent to the provider for this case. */
  readonly prompts: readonly string[];
  /** The provider-reported cost, `null` when it reported no usage or there was no call. */
  readonly cost_micros: number | null;
  readonly latency_ms: number;
}

export interface CaseScore {
  readonly case: string;
  readonly completed: boolean;
  readonly cites_error_line: boolean;
  readonly citations: number;
  readonly invalid_citations: number;
  readonly leaks: number;
  readonly cost_micros: number | null;
  readonly latency_ms: number;
}

export interface Scores {
  readonly cases: number;
  readonly completed: number;
  /** Analyses citing the actual error line, over all cases: an unavailable answer cites nothing. */
  readonly error_line_share: number;
  /** Citations that resolve in their bundle, over all citations; `null` with no citation. */
  readonly citation_validity: number | null;
  readonly canary_leaks: number;
  readonly cost_p95_micros: number | null;
  readonly latency_p95_ms: number | null;
}

export interface EvalRecord {
  readonly schema: typeof RECORD_SCHEMA;
  readonly recorded: string;
  readonly provider: string;
  readonly model: string;
  readonly prompt_version: string;
  readonly set: string;
  readonly scores: Scores;
  readonly per_case: readonly CaseScore[];
}

/** The set's identity: a record is only compared with one scored on the same cases. */
export function setDigest(cases: readonly Case[]): string {
  const hash = createHash("sha256");
  for (const one of [...cases].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    hash.update(JSON.stringify(one), "utf8").update("\n");
  }
  return hash.digest("hex");
}

/** The identifiers a citation of this bundle may name. */
export function evidenceIds(bundle: Bundle): Set<string> {
  const ids = new Set<string>();
  for (const frame of bundle.log?.frames ?? []) {
    if (typeof frame.id === "string") {
      ids.add(frame.id);
    }
  }
  for (const diagnostic of bundle.diagnostics ?? []) {
    if (typeof diagnostic.id === "string") {
      ids.add(diagnostic.id);
    }
  }
  return ids;
}

/**
 * Text no prompt may carry whatever the case registered: the token prefixes, key shapes and PEM
 * header the controller's pattern pass replaces (`sentinel_protocol::patterns`).
 */
const SECRET_SHAPES: readonly RegExp[] = [
  /gh[pousr]_[A-Za-z0-9]{36,}/g,
  /github_pat_[A-Za-z0-9_]{22,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
];

/** How many times a canary or a secret shape appears in `prompt`. */
export function leaks(prompt: string, canaries: readonly string[]): number {
  let found = 0;
  for (const canary of canaries) {
    if (canary.length === 0) {
      continue;
    }
    // A prompt is a JSON request body, so a canary with a quote or a newline travels escaped.
    const escaped = JSON.stringify(canary).slice(1, -1);
    for (const needle of escaped === canary ? [canary] : [canary, escaped]) {
      for (let at = prompt.indexOf(needle); at !== -1; at = prompt.indexOf(needle, at + needle.length)) {
        found += 1;
      }
    }
  }
  for (const shape of SECRET_SHAPES) {
    shape.lastIndex = 0;
    while (shape.exec(prompt) !== null) {
      found += 1;
    }
  }
  return found;
}

/** The nearest-rank 95th percentile; `null` for no samples. */
export function p95(samples: readonly number[]): number | null {
  if (samples.length === 0) {
    return null;
  }
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.ceil(sorted.length * 0.95) - 1] ?? null;
}

export function scoreCase(one: Case, observation: Observation): CaseScore {
  const known = evidenceIds(one.bundle);
  let citations = 0;
  let invalid = 0;
  let hit = false;
  for (const claim of observation.analysis?.claims ?? []) {
    for (const citation of claim.citations) {
      citations += 1;
      if (citation.attempt !== one.bundle.attempt || !known.has(citation.evidence)) {
        invalid += 1;
      } else if (one.error_evidence.includes(citation.evidence)) {
        hit = true;
      }
    }
  }
  let leaked = 0;
  for (const prompt of observation.prompts) {
    leaked += leaks(prompt, one.canaries);
  }
  return {
    case: one.id,
    completed: observation.analysis !== null,
    cites_error_line: hit,
    citations,
    invalid_citations: invalid,
    leaks: leaked,
    cost_micros: observation.cost_micros,
    latency_ms: observation.latency_ms,
  };
}

export function summarize(perCase: readonly CaseScore[]): Scores {
  let completed = 0;
  let hits = 0;
  let citations = 0;
  let invalid = 0;
  let leaked = 0;
  const costs: number[] = [];
  const latencies: number[] = [];
  for (const one of perCase) {
    citations += one.citations;
    invalid += one.invalid_citations;
    leaked += one.leaks;
    if (one.cites_error_line) {
      hits += 1;
    }
    // Cost and latency are per analysis: an unavailable request is not one.
    if (one.completed) {
      completed += 1;
      latencies.push(one.latency_ms);
      if (one.cost_micros !== null) {
        costs.push(one.cost_micros);
      }
    }
  }
  return {
    cases: perCase.length,
    completed,
    error_line_share: perCase.length === 0 ? 0 : hits / perCase.length,
    citation_validity: citations === 0 ? null : (citations - invalid) / citations,
    canary_leaks: leaked,
    cost_p95_micros: p95(costs),
    latency_p95_ms: p95(latencies),
  };
}

/** How far a record may move from its baseline before the gate refuses it. */
export interface Tolerance {
  /** The most `error_line_share` may fall, as a fraction of all cases. */
  readonly shareDrop: number;
  /** The most cost p95 may grow, as a ratio of the baseline's. */
  readonly costGrowth: number;
  /** The most latency p95 may grow, as a ratio of the baseline's. */
  readonly latencyGrowth: number;
}

/**
 * The share may not fall at all. Cost follows token counts, which a provider reports within a few
 * percent run to run; latency is a network round trip and gets the wider margin.
 */
export const TOLERANCE: Tolerance = { shareDrop: 0, costGrowth: 1.1, latencyGrowth: 1.5 };

/** The last record with `record`'s provider, model, prompt version and set, or `null`. */
export function baseline(history: readonly EvalRecord[], record: EvalRecord): EvalRecord | null {
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const past = history[index];
    if (
      past !== undefined &&
      past.provider === record.provider &&
      past.model === record.model &&
      past.prompt_version === record.prompt_version &&
      past.set === record.set
    ) {
      return past;
    }
  }
  return null;
}

/** Why `record` may not be committed; empty when it passes. */
export function gate(
  record: EvalRecord,
  past: EvalRecord | null,
  tolerance: Tolerance = TOLERANCE,
): string[] {
  const failures: string[] = [];
  const scores = record.scores;
  if (scores.cases === 0) {
    failures.push("the set is empty");
  }
  if (scores.citation_validity !== 1) {
    failures.push(
      scores.citation_validity === null
        ? "citation validity: no analysis cited anything"
        : `citation validity ${scores.citation_validity} is not 1`,
    );
  }
  if (scores.canary_leaks !== 0) {
    failures.push(`canary leakage: ${scores.canary_leaks} occurrence(s) reached a prompt`);
  }
  if (past === null) {
    return failures;
  }
  if (scores.error_line_share < past.scores.error_line_share - tolerance.shareDrop) {
    failures.push(
      `error-line share fell from ${past.scores.error_line_share} to ${scores.error_line_share}`,
    );
  }
  grew(failures, "cost p95", scores.cost_p95_micros, past.scores.cost_p95_micros, tolerance.costGrowth);
  grew(
    failures,
    "latency p95",
    scores.latency_p95_ms,
    past.scores.latency_p95_ms,
    tolerance.latencyGrowth,
  );
  return failures;
}

function grew(
  failures: string[],
  name: string,
  now: number | null,
  before: number | null,
  ratio: number,
): void {
  if (before === null) {
    return;
  }
  if (now === null) {
    failures.push(`${name} was ${before} and is now unmeasured`);
  } else if (now > before * ratio) {
    failures.push(`${name} grew from ${before} to ${now}, past ${ratio}x`);
  }
}

/**
 * Serves one case as a queued analysis request and returns what happened. The controller is in
 * memory — it hands out the case's bundle and always reserves, so nothing is answered from a cached
 * analysis — and the provider is whatever `HttpClient` the caller supplies: the recording fake in
 * the unit tests, the real one in `evaluate.ts`.
 */
export const observe = (
  config: Config,
  provider: ProviderName,
  one: Case,
): Effect.Effect<Observation, never, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const inner = yield* HttpClient.HttpClient;
    const prompts: string[] = [];
    const tapped = HttpClient.make((request) =>
      Effect.gen(function* () {
        const web = yield* HttpClientRequest.toWeb(request).pipe(Effect.orDie);
        if (web.method !== "GET" && web.method !== "HEAD") {
          prompts.push(yield* Effect.promise(() => web.text()));
        }
        return yield* inner.execute(request);
      }),
    );
    const evidence = JSON.stringify(one.bundle);
    const now = Date.now();
    const request: RequestRow = {
      id: "air_00000000-0000-4000-8000-000000000001",
      attempt: one.bundle.attempt,
      kind: "analysis",
      question: null,
      provider,
      data_policy: provider === "local" ? "local_only" : "provider_terms",
      state: "queued",
      outcome: null,
      origin: "member",
      reused: false,
      created_ms: now,
      deadline_ms: now + 600_000,
    };
    let analysis: Analysis | null = null;
    let reason: string | null = null;
    let cost: number | null = null;
    const controller: ControllerShape = {
      next: Effect.succeed(request),
      claim: () =>
        Effect.succeed({
          request,
          evidence: `/api/v1/attempts/${request.attempt}/ai-context`,
          token: {
            access: "evaluation",
            expires_ms: request.deadline_ms,
            scopes: ["runs:read", "logs:read"],
          },
        }),
      evidence: () => Effect.succeed(evidence),
      reserve: () => Effect.succeed({ state: "reserved", expires_ms: request.deadline_ms }),
      plan: () => Effect.succeed({ state: "refused", reason: "the evaluation runs no search" }),
      settle: (_id, _outcome, settled, why, usage) =>
        Effect.sync(() => {
          analysis = settled;
          reason = why;
          cost = usage?.cost_micros ?? null;
        }),
    };
    const started = performance.now();
    yield* serve(config).pipe(
      Effect.provideService(Controller, controller),
      Effect.provideService(HttpClient.HttpClient, tapped),
    );
    const latency = performance.now() - started;
    return {
      case: one.id,
      analysis,
      reason,
      prompts,
      cost_micros: cost,
      latency_ms: Math.round(latency * 1000) / 1000,
    };
  });

/** Serves every case in turn — one at a time, so one case's latency is not another's queueing. */
export const run = (
  config: Config,
  provider: ProviderName,
  cases: readonly Case[],
  recorded: string,
): Effect.Effect<EvalRecord, never, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const perCase: CaseScore[] = [];
    for (const one of cases) {
      perCase.push(scoreCase(one, yield* observe(config, provider, one)));
    }
    return {
      schema: RECORD_SCHEMA,
      recorded,
      provider,
      model: config.models[provider]?.id ?? "",
      prompt_version: PROMPT_VERSION,
      set: setDigest(cases),
      scores: summarize(perCase),
      per_case: perCase,
    };
  });

/** The committed set: every `*.json` under `directory`, in name order. */
export function loadCases(directory: string): Case[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(readFileSync(join(directory, name), "utf8")) as Case);
}

/** The committed records, one JSON document per line, oldest first. */
export function loadRecords(path: string): EvalRecord[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as EvalRecord);
}
