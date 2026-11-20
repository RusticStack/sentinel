// The controller's side of a request, as the AI process sees it: the durable rows it consumes,
// the evidence bundle it reads, and the settlement it writes back.
//
// Two credentials are used and never mixed. The service's own grant (`ai:context`) lists,
// claims and settles requests; a request's delegated token — minted by the controller at claim
// time, carrying the requester's read-only scopes and bound to that request — is the only thing
// that reads evidence. Neither is ever put in a log, an error or a prompt.

import { ByteSize, Context, Data, Effect, Layer, Redacted, Schema } from "effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";

import { isReadOnly } from "./policy.ts";

/** A durable request row, as the controller stores and returns it. */
export const RequestRow = Schema.Struct({
  id: Schema.String,
  attempt: Schema.String,
  provider: Schema.String,
  data_policy: Schema.String,
  state: Schema.String,
  outcome: Schema.NullOr(Schema.String),
  created_ms: Schema.Int,
  deadline_ms: Schema.Int,
});
export type RequestRow = typeof RequestRow.Type;

/** The request-scoped delegation: read-only scopes, ten minutes, bound to one request. */
export const Delegation = Schema.Struct({
  access: Schema.String,
  expires_ms: Schema.Int,
  scopes: Schema.Array(Schema.String),
});
export type Delegation = typeof Delegation.Type;

const Queued = Schema.Struct({ requests: Schema.Array(RequestRow) });
const Claim = Schema.Struct({
  request: RequestRow,
  evidence: Schema.String,
  token: Delegation,
});

/** What a claim hands back: the request, the bundle's path, and its delegation. */
export interface Claimed {
  readonly request: RequestRow;
  readonly evidence: string;
  readonly token: Delegation;
}

/** How a request ends. A request never ends any other way. */
export type Outcome = "completed" | "unavailable";

/** Why the controller could not be reached, refused, or did not answer as documented. */
export class ControllerError extends Data.TaggedError("ControllerError")<{
  readonly reason: string;
}> {}

/** What the service does to the controller. */
export interface ControllerShape {
  /** The oldest queued request, or `null` when there is none. */
  readonly next: Effect.Effect<RequestRow | null, ControllerError>;
  /** Claim `id`: lease it and mint its delegation. */
  readonly claim: (id: string) => Effect.Effect<Claimed, ControllerError>;
  /** The redacted evidence bundle, read under the request's own delegation. */
  readonly evidence: (claimed: Claimed) => Effect.Effect<string, ControllerError>;
  /** Settle `id`: the answer text, or the reason there is none. */
  readonly settle: (
    id: string,
    outcome: Outcome,
    text: string | null,
    reason: string | null,
  ) => Effect.Effect<void, ControllerError>;
}

/** The tag the service loop names. */
export class Controller extends Context.Service<Controller, ControllerShape>()(
  "sentinel-ai/Controller",
) {}

/** The evidence bundle's ceiling: the controller serves at most 64 KiB and we read no more. */
const MAX_BUNDLE_BYTES = 128 << 10;

const unreachable = (error: { readonly message: string } | string) =>
  new ControllerError({
    reason: `the controller is unreachable: ${typeof error === "string" ? error : error.message}`,
  });

/**
 * The HTTP client against `base`, authenticating with the service grant.
 *
 * A delegation is refused before it is used if it carries any scope outside the read-only set:
 * the controller caps it there, and a write-capable token in this process would be a write on a
 * person's behalf, so the second check is worth its one comparison.
 */
export const httpLayer = (base: string, grant: Redacted.Redacted<string>) =>
  Layer.effect(
    Controller,
    Effect.map(HttpClient.HttpClient, (client) => {
      const url = (path: string) => new URL(path, base).toString();
      const call = (request: HttpClientRequest.HttpClientRequest) =>
        client.execute(request).pipe(
          Effect.mapError(unreachable),
          Effect.flatMap((response) =>
            response.status < 400
              ? Effect.succeed(response)
              : Effect.fail(
                  new ControllerError({ reason: `the controller answered ${response.status}` }),
                ),
          ),
        );

      return {
        next: call(
          HttpClientRequest.get(url("/api/v1/ai/requests?limit=1")).pipe(
            HttpClientRequest.setHeader("authorization", `Bearer ${Redacted.value(grant)}`),
            HttpClientRequest.acceptJson,
          ),
        ).pipe(
          Effect.flatMap(HttpIncomingMessage.schemaBodyJson(Queued)),
          Effect.map((page) => page.requests[0] ?? null),
          Effect.mapError((error) =>
            error instanceof ControllerError ? error : unreachable("an undecodable request page"),
          ),
        ),
        claim: (id) =>
          call(
            HttpClientRequest.post(url(`/api/v1/ai/requests/${encodeURIComponent(id)}/claim`)).pipe(
              HttpClientRequest.setHeader("authorization", `Bearer ${Redacted.value(grant)}`),
              HttpClientRequest.acceptJson,
            ),
          ).pipe(
            Effect.flatMap(HttpIncomingMessage.schemaBodyJson(Claim)),
            Effect.map((claim) => ({
              request: claim.request,
              evidence: claim.evidence,
              token: claim.token,
            })),
            Effect.mapError((error) => annotate(error, "an undecodable claim")),
          ),
        evidence: (claimed) => {
          if (!isReadOnly(claimed.token.scopes)) {
            return Effect.fail(
              new ControllerError({
                reason: `the delegation carries more than read-only scopes: ${claimed.token.scopes.join(" ")}`,
              }),
            );
          }
          const request = HttpClientRequest.get(url(claimed.evidence)).pipe(
            HttpClientRequest.setHeader("authorization", `Bearer ${claimed.token.access}`),
            HttpClientRequest.acceptJson,
          );
          return call(request).pipe(
            Effect.flatMap((response) => response.text),
            Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.bytes(MAX_BUNDLE_BYTES)),
            Effect.mapError((error) => annotate(error, "an unreadable evidence bundle")),
          );
        },
        settle: (id, outcome, text, reason) =>
          Effect.flatMap(
            HttpClientRequest.bodyJson({ outcome, text, reason })(
              HttpClientRequest.post(url(`/api/v1/ai/requests/${encodeURIComponent(id)}/complete`)).pipe(
                HttpClientRequest.setHeader("authorization", `Bearer ${Redacted.value(grant)}`),
                HttpClientRequest.acceptJson,
              ),
            ),
            (request) => call(request),
          ).pipe(Effect.mapError((error) => annotate(error, "an unencodable settlement")), Effect.asVoid),
      } satisfies ControllerShape;
    }),
  );

/** Keeps a reported error and names what could not be read, without ever echoing the body. */
function annotate(error: unknown, what: string): ControllerError {
  if (error instanceof ControllerError) {
    return error;
  }
  if (error instanceof Error) {
    return unreachable(error);
  }
  return new ControllerError({ reason: `${what}: ${String(error).slice(0, 256)}` });
}
