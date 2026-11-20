// The four provider families, each reduced to the one thing the rest of the package sees: a
// `LanguageModel` layer, and therefore an `Assistant`, for one admitted request.
//
// Only the `local` provider has a configurable address, and it is refused unless it stays
// inside the operator's own network. The hosted providers are pinned to their own hosts, so a
// `local_only` tenant has nothing public to be sent to even by misconfiguration: the layer for
// a public provider is never built for one (`policy.admit` refuses first, and this file
// refuses again rather than trusting its caller).

import { AnthropicClient, AnthropicLanguageModel } from "@effect/ai-anthropic";
import { OpenAiClient, OpenAiLanguageModel } from "@effect/ai-openai";
import {
  OpenAiClient as CompatClient,
  OpenAiLanguageModel as CompatLanguageModel,
} from "@effect/ai-openai-compat";
import { OpenRouterClient, OpenRouterLanguageModel } from "@effect/ai-openrouter";
import { Data, Effect, Layer, Redacted } from "effect";
import type { HttpClient } from "effect/http/HttpClient";

import type { ModelLayer, ModelShape } from "./assistant.ts";
import { type Admission, staysLocal } from "./policy.ts";

/** Where each provider is, and the key it needs. A hosted key is absent when unconfigured. */
export interface Endpoints {
  /** The OpenAI-compatible endpoint (Ollama, vLLM, a LiteLLM gateway) Sentinel runs against. */
  readonly local: { readonly url: string; readonly key: string | null };
  readonly openrouter: string | null;
  readonly anthropic: string | null;
  readonly openai: string | null;
}

/** Why a provider layer could not be built. It ends the request as `unavailable`. */
export class ProviderError extends Data.TaggedError("ProviderError")<{
  readonly reason: string;
}> {}

/**
 * The model layer for one admitted request. Building it validates the configuration the
 * request actually needs — a missing key, or a `local` endpoint outside the operator's network
 * — so a misconfigured provider fails here, once, instead of mid-call.
 */
export function modelLayer(
  admission: Admission,
  endpoints: Endpoints,
): ModelLayer<ProviderError, HttpClient> {
  return Layer.unwrap(Effect.suspend(() => build(admission, endpoints)));
}

function build(
  admission: Admission,
  endpoints: Endpoints,
): Effect.Effect<Layer.Layer<ModelShape, never, HttpClient>, ProviderError> {
  const model = admission.model;
  switch (admission.provider) {
    case "local": {
      const { url, key } = endpoints.local;
      if (!staysLocal(url)) {
        return Effect.fail(
          new ProviderError({ reason: `the local endpoint ${url} is not inside the operator's network` }),
        );
      }
      const client = CompatClient.layer({
        apiUrl: url,
        apiKey: key === null ? undefined : Redacted.make(key),
      });
      return Effect.succeed(
        Layer.provide(CompatLanguageModel.layer({ model }), client),
      );
    }
    case "openrouter": {
      const key = endpoints.openrouter;
      if (key === null) {
        return Effect.fail(new ProviderError({ reason: "no OpenRouter key is configured" }));
      }
      // Always `provider.zdr: true`; `data_collection: deny` additionally under `zero_retention`.
      // Both are layer defaults, so no request path can leave them out.
      const client = OpenRouterClient.layer({ apiKey: Redacted.make(key) });
      const language = OpenRouterLanguageModel.layer({
        model,
        config: {
          provider: {
            zdr: true,
            data_collection: admission.denyCollection ? "deny" : null,
          },
        },
      });
      return Effect.succeed(Layer.provide(language, client));
    }
    case "anthropic": {
      const key = endpoints.anthropic;
      if (key === null) {
        return Effect.fail(new ProviderError({ reason: "no Anthropic key is configured" }));
      }
      const client = AnthropicClient.layer({ apiKey: Redacted.make(key) });
      return Effect.succeed(
        Layer.provide(AnthropicLanguageModel.layer({ model }), client),
      );
    }
    case "openai": {
      const key = endpoints.openai;
      if (key === null) {
        return Effect.fail(new ProviderError({ reason: "no OpenAI key is configured" }));
      }
      const client = OpenAiClient.layer({ apiKey: Redacted.make(key) });
      return Effect.succeed(
        Layer.provide(OpenAiLanguageModel.layer({ model }), client),
      );
    }
  }
}
