// Bundles each candidate's run-filter validator for the browser (minified, tree-shaken) and reports its gzip size.
import { build } from "esbuild";
import { gzipSync } from "node:zlib";
const out = {};
for (const name of ["plain", "valibot", "zod-mini", "zod", "effect"]) {
  const r = await build({ entryPoints: [`${name}.ts`], bundle: true, minify: true, format: "esm", platform: "browser", target: "es2022", write: false, treeShaking: true });
  const code = r.outputFiles[0].contents;
  out[name] = { raw_bytes: code.length, gzip_bytes: gzipSync(code, { level: 9 }).length };
}
console.log(JSON.stringify(out));
