// U01: measure the log-view candidates in web/bench/candidates.js in a real
// browser and print one JSON line (appended to bench/u01-log-view.jsonl
// with --record). Needs Node 22+, `pnpm -C web install`, a Chromium-family
// browser, and Preact + htm unpacked somewhere (a comparison only; neither
// ships):
//
//   npm pack preact@10.29.8 htm@3.1.1 && tar xzf … (see docs/web-ui.md)
//   PREACT_DIR=… HTM_DIR=… node web/bench/log-view.mjs [--lines 200000] [--record]

import { writeFileSync, readFileSync, appendFileSync, mkdtempSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { tmpdir, cpus, totalmem, release, platform } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execSync } from "node:child_process";
import { build } from "esbuild";
import { launch } from "../test/cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, "..");
const repo = resolve(web, "..");
const arg = (name, fallback) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : fallback; };
const LINES = Number(arg("--lines", "200000"));
const REPEATS = Number(arg("--repeats", "3"));
const JUMPS = 300;
const preactDir = process.env.PREACT_DIR, htmDir = process.env.HTM_DIR;
if (!preactDir || !htmDir) { console.error("set PREACT_DIR and HTM_DIR to unpacked preact@10 and htm@3 packages"); process.exit(2); }
const files = {
  preact: join(preactDir, "dist/preact.min.umd.js"),
  hooks: join(preactDir, "hooks/dist/hooks.umd.js"),
  htm: join(htmDir, "dist/htm.umd.js"),
  vue: join(web, "node_modules/vue/dist/vue.global.prod.js"),
  viewer: join(web, "app/utils/logviewer.ts"),
  candidates: join(here, "candidates.js"),
  css: join(web, "app/assets/css/main.css"),
};
const url = (p) => pathToFileURL(p).href;
const gz = (...paths) => paths.reduce((n, p) => n + gzipSync(readFileSync(p), { level: 9 }).length, 0);

const dir = mkdtempSync(join(tmpdir(), "sentinel-u01-"));
// The shipped viewer, bundled as the interface bundles it (minified).
const viewerBundle = join(dir, "viewer.js");
await build({ entryPoints: [files.viewer], bundle: true, minify: true, format: "iife", globalName: "SentinelLog", outfile: viewerBundle, logLevel: "silent" });
// The viewer's own rules from the interface's stylesheet (the rest is
// Tailwind input, not CSS a page can load as is).
const css = readFileSync(files.css, "utf8");
const logCss = css.slice(css.indexOf("[hidden]"), css.indexOf("/* Job graph. */"));
function pageFor(name) {
  const libs = {
    naive: [],
    preact: [files.preact, files.hooks, files.htm],
    vue: [files.vue],
    sentinel: [viewerBundle],
  }[name];
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><style>body { font: 14px system-ui; margin: 16px; } ${logCss}</style></head>
<body><div id="status"></div><div id="alert" hidden></div><main id="main"><div id="root"></div></main>
${libs.map((p) => `<script src="${url(p)}"></script>`).join("\n")}
<script src="${url(files.candidates)}"></script>
<script>window.bench = candidates[${JSON.stringify(name)}](document.getElementById("root"));</script></body></html>`;
  const path = join(dir, `${name}.html`);
  writeFileSync(path, html);
  return url(path);
}

// What each stack costs to ship, gzipped: the libraries plus the viewer.
const stackBytes = {
  naive: 0,
  preact: gz(files.preact, files.hooks, files.htm),
  vue: gz(files.vue),
  sentinel: gz(viewerBundle),
};

const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };
const browser = await launch();
const version = (await browser.send("Browser.getVersion")).product;
const results = {};
for (const name of ["naive", "preact", "vue", "sentinel"]) {
  const runs = [];
  for (let r = 0; r < REPEATS; r++) {
    const page = await browser.newPage({ width: 1280, height: 900 });
    await page.goto(pageFor(name));
    await page.gc();
    const loadMs = await page.eval(`(async () => { const f = makeFrames(${LINES}); const t = performance.now(); await bench.load(f); return performance.now() - t; })()`);
    await page.gc();
    const after = await page.metrics();
    const elements = await page.eval("document.getElementsByTagName('*').length");
    const before = await page.metrics();
    const wall = await page.eval(`(async () => {
      const vp = bench.viewport; let seed = 7; const rand = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
      const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      const t = performance.now();
      for (let i = 0; i < ${JUMPS}; i++) { vp.scrollTop = rand() * (vp.scrollHeight - vp.clientHeight); vp.dispatchEvent(new Event("scroll")); await frame(); }
      return performance.now() - t; })()`);
    const end = await page.metrics();
    const work = (m) => m.ScriptDuration + m.LayoutDuration + m.RecalcStyleDuration;
    runs.push({
      load_ms: loadMs,
      heap_mib: after.JSHeapUsedSize / 2 ** 20,
      elements,
      jump_work_ms: ((work(end) - work(before)) * 1000) / JUMPS,
      jump_wall_ms: wall / JUMPS,
    });
    const errors = page.errors;
    if (errors.length) console.error(name, errors);
    await page.close();
  }
  results[name] = {
    stack_gzip_bytes: stackBytes[name],
    load_ms: +median(runs.map((x) => x.load_ms)).toFixed(0),
    heap_mib: +median(runs.map((x) => x.heap_mib)).toFixed(1),
    elements: median(runs.map((x) => x.elements)),
    jump_work_ms: +median(runs.map((x) => x.jump_work_ms)).toFixed(2),
    jump_wall_ms: +median(runs.map((x) => x.jump_wall_ms)).toFixed(1),
  };
  console.error(name, JSON.stringify(results[name]));
}
await browser.close();

let commit = null;
try { commit = execSync("git rev-parse --short HEAD", { cwd: repo }).toString().trim() + (execSync("git status --porcelain", { cwd: repo }).toString().trim() ? "+dirty" : ""); } catch (e) { /* no git */ }
const record = {
  record: "u01-log-view",
  date: new Date().toISOString().slice(0, 10),
  host: `${cpus()[0].model.trim()}, ${cpus().length} threads, ${Math.round(totalmem() / 2 ** 30)} GiB, ${platform()} ${release()}`,
  browser: version,
  code: commit,
  harness: `web/bench/log-view.mjs: ${LINES} lines of 127 characters in 32 KiB frames, ${REPEATS} fresh pages per candidate (medians), ${JUMPS} random scroll jumps each; work = script + layout + style time from Performance.getMetrics`,
  candidates: results,
};
console.log(JSON.stringify(record));
if (process.argv.includes("--record")) appendFileSync(join(repo, "bench/u01-log-view.jsonl"), JSON.stringify(record) + "\n");
