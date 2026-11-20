// Sentinel's `Assistant`: the one interface the rest of the package talks to a model through.
//
// `effect/ai` is tagged `@stability unstable`, so an upstream minor release may change any of
// it. This module is the only place that names its types: everywhere else, a model is an
// `Assistant` that answers one question about an evidence bundle. When the upstream shape
// moves, this file moves and nothing else does.

import { Context, Data, Effect, Layer } from "effect";
import { LanguageModel, Prompt } from "effect/ai";

/** One question about one bounded, redacted evidence bundle. */
export interface Question {
  /** Sentinel's instructions for this kind of request: what to look for, how to answer. */
  readonly instructions: string;
  /** The controller's evidence bundle (`sentinel.ai-context/1`), already redacted and bounded. */
  readonly evidence: string;
}

/** An answer, with the usage the provider reported. An unreported count is `null`, never zero. */
export interface Answer {
  readonly text: string;
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
}

/** Why no answer: the provider failed, refused, or answered with nothing usable. */
export class AssistantError extends Data.TaggedError("AssistantError")<{
  readonly reason: string;
}> {}

/** What an `Assistant` can do. */
export interface AssistantShape {
  readonly complete: (question: Question) => Effect.Effect<Answer, AssistantError>;
}

/** The tag every caller and layer names. */
export class Assistant extends Context.Service<Assistant, AssistantShape>()("sentinel-ai/Assistant") {}

/**
 * The `LanguageModel` tag, re-exported so a provider module that builds a model layer does not
 * import `effect/ai` itself. A layer of this shape is what `Assistant.layer` needs.
 */
export const Model = LanguageModel.LanguageModel;

/** The model contract itself, as the type a layer provides. */
export type ModelShape = LanguageModel.LanguageModel;

/** A provider's model layer: the thing `Assistant` puts an interface in front of. */
export type ModelLayer<Error, Requirements> = Layer.Layer<ModelShape, Error, Requirements>;

/**
 * An `Assistant` over whichever `LanguageModel` the context carries. A request with no usable
 * answer is an `AssistantError`, never a partial answer: an empty completion is a failure,
 * because nothing downstream may mistake it for an analysis.
 */
export const layer: Layer.Layer<Assistant, never, ModelShape> = Layer.effect(
  Assistant,
  Effect.map(LanguageModel.LanguageModel, (model) => ({
    complete: (question: Question) =>
      Effect.flatMap(
        model.generateText({
          prompt: Prompt.make([
            { role: "system", content: question.instructions },
            { role: "user", content: [{ type: "text", text: question.evidence }] },
          ]),
        }),
        (response) => {
          const text = response.text.trim();
          return text.length === 0
            ? Effect.fail(new AssistantError({ reason: "the provider answered with no text" }))
            : Effect.succeed({
                text,
                inputTokens: response.usage.inputTokens.total ?? null,
                outputTokens: response.usage.outputTokens.total ?? null,
              });
        },
      ).pipe(Effect.mapError(toAssistantError)),
  })),
);

/** An upstream failure becomes Sentinel's own, with the provider's message kept for the log. */
function toAssistantError(error: unknown): AssistantError {
  return error instanceof AssistantError
    ? error
    : new AssistantError({ reason: describe(error) });
}

function describe(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`.slice(0, 512);
  }
  return String(error).slice(0, 512);
}
