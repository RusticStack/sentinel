// The `sentinel-ai` process: one loop that consumes durable requests from the controller.
//
// It is started by the deployment beside the controller (`docs/ai.md`), reads its configuration
// from the environment, and stops only when it is told to. A configuration it cannot use stops
// it before the first poll, with the reason and never a value.

import { Effect } from "effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";

import { ConfigError, load } from "./config.ts";
import { httpLayer } from "./controller.ts";
import { loop } from "./service.ts";

const config = load(process.env);
if (config instanceof ConfigError) {
  console.error(`sentinel-ai: ${config.reason}`);
  process.exit(1);
}

await Effect.runPromise(
  loop(config).pipe(
    Effect.provide(httpLayer(config.controller, config.grant)),
    Effect.provide(FetchHttpClient.layer),
  ),
);
