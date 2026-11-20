// What one request costs before it is made, and what it cost after: the maximum the controller
// holds against the tenant's month, and the usage the provider reported priced at the same rate.
//
// The estimate is deliberately a ceiling. A reservation that under-counts is a budget that can be
// overspent by the difference, so the prompt's bytes are divided by the lowest ratio a token can
// take in UTF-8 code and prose rather than by an average; a reservation that over-counts costs
// nothing, because the settlement replaces it with what the provider reported.

import type { Answer } from "./assistant.ts";

/** The three things one request reserves, in the units the ledger holds. */
export interface Metered {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly costMicros: number;
}

/** What the configuration states for one model: its output cap and what its tokens cost. */
export interface ModelLimits {
  /** The output cap the provider is asked for, and the most the request may be charged for. */
  readonly maxOutputTokens: number;
  /** Millionths of the deployment's currency, per million input tokens. */
  readonly inputMicrosPerMtok: number;
  /** Millionths of the deployment's currency, per million output tokens. */
  readonly outputMicrosPerMtok: number;
}

/** What the provider reported, priced. A count it did not report is `null`, never zero. */
export interface ReportedUsage {
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly cost_micros: number | null;
}

/**
 * The prompt's tokens, as a ceiling. Three ASCII bytes per token is below the ratio any modern
 * tokenizer achieves on English, JSON or source code, and a character outside ASCII counts as a
 * whole token — CJK and accented text is where a tokenizer's ratio is worst. The estimate errs
 * towards holding too much for the few seconds a call takes, which costs nothing: the settlement
 * replaces the hold with what the provider actually reported.
 */
export function estimateTokens(text: string): number {
  let weight = 0;
  for (let at = 0; at < text.length; at += 1) {
    weight += text.charCodeAt(at) < 0x80 ? 1 : 3;
  }
  return Math.ceil(weight / 3);
}

/** What one request at this prompt and these limits reserves. */
export function reservation(prompt: string, limits: ModelLimits): Metered {
  const inputTokens = estimateTokens(prompt);
  return {
    inputTokens,
    outputTokens: limits.maxOutputTokens,
    costMicros: price(inputTokens, limits.maxOutputTokens, limits),
  };
}

/** What the provider reported for one answer, priced at the model's rate. */
export function reportedUsage(answer: Answer, limits: ModelLimits): ReportedUsage {
  const input = answer.inputTokens;
  const output = answer.outputTokens;
  return {
    input_tokens: input,
    output_tokens: output,
    // A price from one reported half would be a guess, so an unreported count leaves the cost
    // unreported too, and the controller settles that at what the reservation held.
    cost_micros:
      input === null || output === null ? null : price(input, output, limits),
  };
}

/**
 * Tokens priced at `limits`, in millionths. Rounded up: a fraction of a micro is still a charge,
 * and rounding down would let every request in a month come out slightly free.
 */
function price(inputTokens: number, outputTokens: number, limits: ModelLimits): number {
  const micros =
    (inputTokens * limits.inputMicrosPerMtok + outputTokens * limits.outputMicrosPerMtok) /
    1_000_000;
  return Math.ceil(micros);
}
