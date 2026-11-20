// The process's configuration: where the controller is, the grant it presents there, the model
// each provider is asked for, and the local endpoint. Read once at startup and never echoed:
// every refusal names the variable that is missing or wrong, never its value.

import { Data, Redacted } from "effect";

import type { Endpoints } from "./providers.ts";
import type { ProviderName } from "./policy.ts";
import { staysLocal } from "./policy.ts";

/** Why the configuration cannot be used. The process does not start. */
export class ConfigError extends Data.TaggedError("ConfigError")<{
  readonly reason: string;
}> {}

/** Everything one `sentinel-ai` process needs. */
export interface Config {
  readonly controller: string;
  readonly grant: Redacted.Redacted<string>;
  /** The model each provider is asked for. A provider with no model is refused, not guessed at. */
  readonly models: Partial<Record<ProviderName, string>>;
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
  return {
    controller,
    grant: Redacted.make(grant),
    models: {
      local: env.SENTINEL_AI_MODEL_LOCAL,
      openrouter: env.SENTINEL_AI_MODEL_OPENROUTER,
      anthropic: env.SENTINEL_AI_MODEL_ANTHROPIC,
      openai: env.SENTINEL_AI_MODEL_OPENAI,
    },
    endpoints: {
      local: { url: local, key: env.SENTINEL_AI_LOCAL_KEY ?? null },
      openrouter: env.SENTINEL_AI_OPENROUTER_KEY ?? null,
      anthropic: env.SENTINEL_AI_ANTHROPIC_KEY ?? null,
      openai: env.SENTINEL_AI_OPENAI_KEY ?? null,
    },
    pollMs,
  };
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
