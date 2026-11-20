// A recording HTTP client: it answers every request from `respond` and keeps what was sent.
//
// The provider-policy tests use it as their fake provider, so "a `local_only` tenant never
// reaches a public host" is a statement about every request the process actually made — the
// fake is the only client in the context, and a request it never saw was never sent.

import { Effect } from "effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";

/**
 * `respond(call)` returns `{ status?, body }`. Every call is recorded as
 * `{ host, url, method, body, authorization }` before it is answered.
 */
export const recording = (respond) => {
  const calls = [];
  const client = HttpClient.make((request, url) =>
    Effect.gen(function* () {
      const web = yield* HttpClientRequest.toWeb(request);
      const body = web.method === "GET" || web.method === "HEAD" ? "" : yield* Effect.promise(() => web.text());
      const call = {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        url: url.toString(),
        method: web.method,
        body,
        authorization: web.headers.get("authorization") ?? "",
      };
      calls.push(call);
      const answer = respond(call);
      return HttpClientResponse.fromWeb(
        request,
        new Response(JSON.stringify(answer.body ?? {}), {
          status: answer.status ?? 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }),
  );
  return { client, calls };
};

/** An OpenAI-shaped chat completion, which both OpenRouter and an OpenAI-compatible endpoint speak. */
export const chatCompletion = (text) => ({
  id: "chatcmpl-fake",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "fake-model",
  choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
  system_fingerprint: null,
  usage: { prompt_tokens: 120, completion_tokens: 24, total_tokens: 144 },
});

/** An Anthropic-shaped message. */
export const anthropicMessage = (text) => ({
  id: "msg_fake",
  type: "message",
  role: "assistant",
  model: "fake-model",
  content: [{ type: "text", text }],
  stop_reason: "end_turn",
  usage: { input_tokens: 120, output_tokens: 24 },
});

/**
 * One provider's model with the budget a request holds against it, as the configuration states it:
 * an output cap and two rates per million tokens.
 */
export const model = (id, maxOutputTokens = 1_024) => ({
  id,
  maxOutputTokens,
  inputMicrosPerMtok: 150_000,
  outputMicrosPerMtok: 600_000,
});

/** The controller's decision before the provider is called: the maximum is held. */
export const reserved = (expires_ms = 1_700_000_900_000) => ({ state: "reserved", expires_ms });

/** The controller's decision when it already has the analysis. */
export const reused = (text, by = "evidence") => ({ state: "reused", by, text });

/** The controller's decision when the request does not fit. */
export const refused = (reason) => ({ state: "refused", reason });
