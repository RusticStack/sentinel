// Node module hooks that compile the TypeScript sources the unit tests import, for Node builds without type stripping
// (the verification hosts' distribution Node 22 has none).
import { readFile } from "node:fs/promises";
import { transform } from "esbuild";

export async function load(url, context, next) {
  if (url.startsWith("file:") && url.endsWith(".ts")) {
    const source = await readFile(new URL(url), "utf8");
    const { code } = await transform(source, { loader: "ts", format: "esm", target: "node22", sourcefile: url });
    return { format: "module", source: code, shortCircuit: true };
  }
  return next(url, context);
}
