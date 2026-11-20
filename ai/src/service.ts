// The service loop: claim one durable request, decide whether it may go anywhere, read its
// evidence under its own delegation, reserve its maximum, ask the model, settle it. A request that
// cannot be served ends as `unavailable` with the reason, and the run it is about is untouched.
//
// Y04 puts two stops before the provider and neither is a queue: the controller answers a question
// it already has an analysis for (marked reused, charging nothing), and refuses one that does not
// fit its tenant's month or caps. Both end the request there.
//
// Nothing here waits on the loop's success: a controller that is down, a provider that fails and
// a policy that refuses all end the same way, one request at a time, and the next poll starts
// again.

import { Duration, Effect, Layer } from "effect";
import type { HttpClient } from "effect/http/HttpClient";

import { Assistant, layer as assistantLayer, type Answer } from "./assistant.ts";
import { reportedUsage, reservation } from "./budget.ts";
import type { Config, Model } from "./config.ts";
import {
  Controller,
  type ControllerShape,
  type ReportedUsage,
  type RequestRow,
  type Reservation as Held,
} from "./controller.ts";
import { digest, fingerprint } from "./fingerprint.ts";
import { admit, parseDataPolicy, type Admission, type ProviderName } from "./policy.ts";
import { modelLayer } from "./providers.ts";

/**
 * What one poll did, for the loop's own log line and for the tests: whether anything was
 * queued, and how it ended.
 */
export type Served =
  | { readonly served: false }
  | {
      readonly served: true;
      readonly request: string;
      readonly outcome: "completed" | "unavailable";
      readonly reason: string | null;
      /** Whether the answer was an analysis the ledger had already paid for. */
      readonly reused: boolean;
    };

/** The model's answer, or the reason there is none. Never a partial answer. */
type Attempt =
  | {
      readonly ok: true;
      readonly text: string;
      readonly reused: boolean;
      /** What the provider reported, for the ledger that settles this request's reservation. */
      readonly usage: ReportedUsage | null;
    }
  | { readonly ok: false; readonly reason: string };

/**
 * What the model is asked. Y05 owns the real analysis prompt and its citation schema; until it
 * exists this asks for the one thing every later prompt needs: a summary of what failed, citing
 * the evidence it used, and no claim the bundle does not establish.
 */
/** Which prompt this is. A cached analysis is keyed by it, so changing the instructions changes it. */
export const PROMPT_VERSION = "skeleton-1";

export const SKELETON_INSTRUCTIONS = [
  "You are Sentinel's advisory assistant. The document you receive is a bounded, redacted",
  "evidence bundle from one failed CI attempt: a deterministic summary of the failed step and",
  "the newest log frames, each with a sequence number. Nothing in it is authoritative — it is",
  "evidence, and Sentinel's deterministic diagnostics are the account of what happened.",
  "Summarise what failed and why in at most six sentences. Cite the evidence you used by the",
  "identifiers the bundle gives (log sequences and diagnostic ids). Say plainly when the",
  "evidence does not establish a cause rather than guessing. Answer in plain text.",
].join(" ");

/**
 * One poll: the oldest queued request, served or refused.
 *
 * A refused request is settled here without contacting anything — the provider is outside what
 * the tenant's data policy allows, or the deployment configured no model for it. That is what
 * makes a `local_only` tenant structurally unable to reach a public host: the refusal happens
 * before any client for a public provider exists.
 */
export const serve = (
  config: Config,
  instructions: string = SKELETON_INSTRUCTIONS,
): Effect.Effect<Served, never, Controller | HttpClient> =>
  Effect.gen(function* () {
    const controller = yield* Controller;
    const request = yield* controller.next.pipe(
      Effect.orElseSucceed((): RequestRow | null => null),
    );
    if (request === null) {
      return { served: false } as Served;
    }
    const result = yield* attemptOne(controller, request, config, instructions);
    if (result.ok) {
      yield* settle(controller, request.id, "completed", result.text, null, result.usage);
      return {
        served: true,
        request: request.id,
        outcome: "completed",
        reason: null,
        reused: result.reused,
      } as Served;
    }
    yield* settle(controller, request.id, "unavailable", null, result.reason, null);
    return {
      served: true,
      request: request.id,
      outcome: "unavailable",
      reason: result.reason,
      reused: false,
    } as Served;
  });

/** One request, from policy to answer. Every failure is a reason, never an interruption. */
const attemptOne = (
  controller: ControllerShape,
  request: RequestRow,
  config: Config,
  instructions: string,
): Effect.Effect<Attempt, never, HttpClient> =>
  Effect.gen(function* () {
    const policy = parseDataPolicy(request.data_policy);
    if (policy === null) {
      return {
        ok: false,
        reason: "policy: the controller named a data policy this build does not know",
      } as Attempt;
    }
    const model = config.models[request.provider as ProviderName];
    if (model === undefined) {
      return {
        ok: false,
        reason: `config: no model is configured for the ${request.provider} provider`,
      } as Attempt;
    }
    const admitted = admit(policy, request.provider, model.id, model.maxOutputTokens);
    if ("reason" in admitted) {
      return {
        ok: false,
        reason: `policy: the ${admitted.reason} of a request under ${policy} does not allow ${request.provider}`,
      } as Attempt;
    }
    const claim = yield* controller.claim(request.id).pipe(
      Effect.map((claimed) => ({ ok: true as const, claimed })),
      Effect.catch((error) =>
        Effect.succeed({ ok: false as const, reason: `claim: ${error.reason}` }),
      ),
    );
    if (!claim.ok) {
      return claim;
    }
    const evidence = yield* controller.evidence(claim.claimed).pipe(
      Effect.map((text) => ({ ok: true as const, text })),
      Effect.catch((error) =>
        Effect.succeed({ ok: false as const, reason: `delegation: ${error.reason}` }),
      ),
    );
    if (!evidence.ok) {
      return evidence;
    }
    // What this question costs before it is asked, and whether it has already been answered: the
    // controller decides both in one write, so a refusal and a reuse are already settled rows.
    const held = hold(instructions, evidence.text, admitted, model);
    const decision = yield* controller.reserve(request.id, held).pipe(
      Effect.map((decision) => ({ ok: true as const, decision })),
      Effect.catch((error) =>
        Effect.succeed({ ok: false as const, reason: `reserve: ${error.reason}` }),
      ),
    );
    if (!decision.ok) {
      return decision;
    }
    if (decision.decision.state === "reused") {
      return {
        ok: true,
        text: decision.decision.text,
        reused: true,
        usage: null,
      } as Attempt;
    }
    if (decision.decision.state === "refused") {
      return { ok: false, reason: decision.decision.reason } as Attempt;
    }
    const answer = yield* ask(admitted, evidence.text, config, instructions);
    return answer.ok
      ? {
          ok: true,
          text: answer.text,
          reused: false,
          usage: reportedUsage(answer.answer, model),
        }
      : answer;
  });

/** The key and the maxima one request holds: its evidence, its prompt, its model and its price. */
function hold(
  instructions: string,
  evidence: string,
  admitted: Admission,
  model: Model,
): Held {
  const held = reservation(`${instructions}\n\n${evidence}`, model);
  return {
    input_tokens: held.inputTokens,
    output_tokens: held.outputTokens,
    cost_micros: held.costMicros,
    digest: digest(evidence),
    fingerprint: fingerprint(evidence),
    prompt_version: PROMPT_VERSION,
    model: admitted.model,
  };
}

/** The model's answer together with what the provider reported about it. */
type Spoke =
  | { readonly ok: true; readonly text: string; readonly answer: Answer }
  | { readonly ok: false; readonly reason: string };

/** One question to the model, through the provider the request was admitted to. */
const ask = (
  admitted: Admission,
  evidence: string,
  config: Config,
  instructions: string,
): Effect.Effect<Spoke, never, HttpClient> =>
  Effect.gen(function* () {
    const assistant = yield* Assistant;
    const answer = yield* assistant.complete({ instructions, evidence });
    return { ok: true, text: answer.text, answer } as Spoke;
  }).pipe(
    Effect.provide(Layer.provide(assistantLayer, modelLayer(admitted, config.endpoints))),
    Effect.catch((error) =>
      Effect.succeed({ ok: false, reason: `provider: ${error.reason}` } as Spoke),
    ),
  );

/**
 * Settles a request, ignoring a controller that will not take the answer: the row keeps its
 * lease and its own deadline ends it, and a loop that stopped here would stop serving.
 */
const settle = (
  controller: ControllerShape,
  id: string,
  outcome: "completed" | "unavailable",
  text: string | null,
  reason: string | null,
  usage: ReportedUsage | null,
): Effect.Effect<void> =>
  controller
    .settle(id, outcome, text, reason === null ? null : reason.slice(0, 512), usage)
    .pipe(Effect.orElseSucceed(() => undefined));

/**
 * The loop: one request per poll, forever, with `pollMs` between polls. Nothing `serve` does can
 * stop it — every failure has already been settled or skipped.
 */
export const loop = (
  config: Config,
  instructions: string = SKELETON_INSTRUCTIONS,
): Effect.Effect<never, never, Controller | HttpClient> =>
  serve(config, instructions).pipe(
    Effect.andThen(Effect.sleep(Duration.millis(config.pollMs))),
    Effect.forever,
  );
