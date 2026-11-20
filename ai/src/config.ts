// The process's configuration: where the controller is, the grant it presents there, the model
// each provider is asked for, and the local endpoint. Read once at startup and never echoed:
// every refusal names the variable that is missing or wrong, never its value.

import { Data, Redacted } from "effect";

import type { ModelLimits } from "./budget.ts";
import type { Endpoints } from "./providers.ts";
import { PROVIDERS, type ProviderName, staysLocal } from "./policy.ts";

/** Why the configuration cannot be used. The process does not start. */
export class ConfigError extends Data.TaggedError("ConfigError")<{
  readonly reason: string;
}> {}

/** One provider's model, what one request through it may spend, and what its tokens cost. */
export interface Model extends ModelLimits {
  readonly id: string;
}

/** Everything one `sentinel-ai` process needs. */
export interface Config {
  readonly controller: string;
  readonly grant: Redacted.Redacted<string>;
  /**
   * The model each provider is asked for, with the budget one request holds against it. A provider
   * with no model is never used, and a model with no budget is refused at startup rather than
   * reserving nothing: an unpriced request could spend a tenant's month without being counted.
   */
  readonly models: Partial<Record<ProviderName, Model>>;
  readonly endpoints: Endpoints;
  readonly pollMs: number;
}

/** Ollama's OpenAI-compatible path, on loopback: the local default, and local by construction. */
const DEFAULT_LOCAL_URL = "http://127.0.0.1:11434/v1";
const DEFAULT_POLL_MS = 2_000;

/** Reads the configuration from `env`, or refuses with the reason it cannot be used. */
export function load(env: Record<string, string | undefined>): Config | ConfigError {
  const controller = env.SENTINEL_AI_CONTROLLER;
  if (!controller) {
    return new ConfigError({ reason: "SENTINEL_AI_CONTROLLER is not set" });
  }
  if (!isHttp(controller)) {
    return new ConfigError({ reason: "SENTINEL_AI_CONTROLLER must be an http or https URL" });
  }
  const grant = env.SENTINEL_AI_TOKEN;
  if (!grant) {
    return new ConfigError({ reason: "SENTINEL_AI_TOKEN is not set" });
  }
  const local = env.SENTINEL_AI_LOCAL_URL ?? DEFAULT_LOCAL_URL;
  if (!staysLocal(local)) {
    return new ConfigError({
      reason: "SENTINEL_AI_LOCAL_URL must be an endpoint inside the operator's own network",
    });
  }
  const pollMs = readPoll(env.SENTINEL_AI_POLL_MS);
  if (pollMs instanceof ConfigError) {
    return pollMs;
  }
  const models = readModels(env);
  if (models instanceof ConfigError) {
    return models;
  }
  return {
    controller,
    grant: Redacted.make(grant),
    models,
    endpoints: {
      local: { url: local, key: env.SENTINEL_AI_LOCAL_KEY ?? null },
      openrouter: env.SENTINEL_AI_OPENROUTER_KEY ?? null,
      anthropic: env.SENTINEL_AI_ANTHROPIC_KEY ?? null,
      openai: env.SENTINEL_AI_OPENAI_KEY ?? null,
    },
    pollMs,
  };
}

/**
 * Each provider's model and the budget one request holds against it. The budget is
 * `<max output tokens>:<input micros per million tokens>:<output micros per million tokens>`, for
 * the deployment's own currency: Sentinel stores millionths and never guesses a price, so a model
 * without one is refused here, naming the variable and never its value.
 */
function readModels(
  env: Record<string, string | undefined>,
): Partial<Record<ProviderName, Model>> | ConfigError {
  const models: Partial<Record<ProviderName, Model>> = {};
  for (const provider of PROVIDERS) {
    const name = provider.toUpperCase();
    const id = env[`SENTINEL_AI_MODEL_${name}`];
    if (id === undefined) {
      continue;
    }
    const spec = env[`SENTINEL_AI_BUDGET_${name}`];
    if (spec === undefined) {
      return new ConfigError({ reason: `SENTINEL_AI_BUDGET_${name} is not set` });
    }
    const limits = parseLimits(spec);
    if (limits instanceof ConfigError) {
      return new ConfigError({ reason: `SENTINEL_AI_BUDGET_${name}: ${limits.reason}` });
    }
    models[provider] = { id, ...limits };
  }
  return models;
}

/** `max_output_tokens:input_micros_per_mtok:output_micros_per_mtok`, each a whole number. */
function parseLimits(spec: string): ModelLimits | ConfigError {
  const parts = spec.split(":");
  if (parts.length !== 3) {
    return new ConfigError({ reason: "must be <max tokens>:<input micros>:<output micros>" });
  }
  const values = parts.map((part) => (/^\d+$/.test(part) ? Number(part) : Number.NaN));
  const max = values[0] ?? Number.NaN;
  const input = values[1] ?? Number.NaN;
  const output = values[2] ?? Number.NaN;
  if (
    !Number.isSafeInteger(max) ||
    max <= 0 ||
    !Number.isSafeInteger(input) ||
    !Number.isSafeInteger(output)
  ) {
    return new ConfigError({
      reason: "must be three whole numbers, with the output cap above zero",
    });
  }
  return { maxOutputTokens: max, inputMicrosPerMtok: input, outputMicrosPerMtok: output };
}

function isHttp(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/** A poll interval of at least 100 ms, so a misconfiguration cannot turn into a spin. */
function readPoll(value: string | undefined): number | ConfigError {
  if (value === undefined) {
    return DEFAULT_POLL_MS;
  }
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 100
    ? parsed
    : new ConfigError({ reason: "SENTINEL_AI_POLL_MS must be a whole number of at least 100" });
}
