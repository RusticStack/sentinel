// Runs the evaluation set (Y09) against one configured provider and gates the result:
//
//   node src/evaluate.ts <provider> [--write]
//
// The provider, its model and its budget come from the same environment `sentinel-ai` reads. No
// controller is contacted: each case is served from memory through `serve`. The record is printed;
// with `--write` a record that passes the gate is appended to `eval/results.jsonl`, to be committed
// with the prompt or model change it measured. A record that fails the gate exits 1 and is not
// written.

import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Effect } from "effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";

import { ConfigError, load } from "./config.ts";
import { baseline, gate, loadCases, loadRecords, run } from "./evaluation.ts";
import { parseProvider } from "./policy.ts";

const CASES = fileURLToPath(new URL("../eval/cases", import.meta.url));
const RESULTS = fileURLToPath(new URL("../eval/results.jsonl", import.meta.url));

const provider = parseProvider(process.argv[2] ?? "");
if (provider === null) {
  console.error("usage: node src/evaluate.ts <local|openrouter|anthropic|openai> [--write]");
  process.exit(2);
}
// The controller's address and grant are required by `load` and never used here.
const config = load({
  SENTINEL_AI_CONTROLLER: "http://127.0.0.1:9",
  SENTINEL_AI_TOKEN: "evaluation",
  ...process.env,
});
if (config instanceof ConfigError) {
  console.error(`sentinel-ai evaluate: ${config.reason}`);
  process.exit(2);
}
if (config.models[provider] === undefined) {
  console.error(`sentinel-ai evaluate: no model is configured for ${provider}`);
  process.exit(2);
}

const record = await Effect.runPromise(
  run(config, provider, loadCases(CASES), new Date().toISOString()).pipe(
    Effect.provide(FetchHttpClient.layer),
  ),
);
console.log(JSON.stringify(record, null, 2));
const failures = gate(record, baseline(loadRecords(RESULTS), record));
if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`gate: ${failure}`);
  }
  process.exit(1);
}
if (process.argv.includes("--write")) {
  appendFileSync(RESULTS, `${JSON.stringify(record)}\n`);
}
