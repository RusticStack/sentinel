// Measures a running sentinel-web against the seeded controller of
// `crates/sentinel-api/tests/web_browser.rs` (`measure_the_web_interface`):
// shipped JavaScript per first view, server render time per view, resident
// memory, CPU for ten live log streams and log-view work per scroll jump.
// The views are addressed by path only, so the same harness measures the Nuxt
// interface (U08) and the TanStack Start one (U14).
import { readFileSync, appendFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { cpus, totalmem, release, platform, loadavg } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { launch } from "../test/cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const RECORD = process.env.SENTINEL_BENCH_RECORD || "";
const LABEL = process.env.SENTINEL_BENCH_HOST_LABEL || "unlabelled";
const RENDERS = Number(process.env.SENTINEL_BENCH_RENDERS || 40);
const STREAM_SECS = Number(process.env.SENTINEL_BENCH_STREAM_SECS || 30);
const JUMPS = 300;
const JUMP_REPEATS = 3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.error(...a);

// --- host and process probes (Linux /proc) ---
const CLK_TCK = 100;
function rssKiB(pid) {
  try { return Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, "utf8"))[1]); } catch { return null; }
}
function cpuTicks(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const f = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return Number(f[11]) + Number(f[12]); // utime + stime
  } catch { return null; }
}
function pressure() {
  try {
    const t = readFileSync("/proc/pressure/cpu", "utf8");
    return Number(/some avg10=([\d.]+)/.exec(t)[1]);
  } catch { return null; }
}
const load = () => ({ loadavg_1m: +loadavg()[0].toFixed(2), cpu_some_avg10: pressure() });

// The web interface may be more than one process (a front and the legacy one behind it).
const pids = (cfg.web_pids || [cfg.web_pid]).filter(Boolean);
const sumRss = () => pids.reduce((n, p) => n + (rssKiB(p) || 0), 0);
const sumTicks = () => pids.reduce((n, p) => n + (cpuTicks(p) || 0), 0);

// --- percentiles ---
function pct(xs, p) { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; }
const r2 = (x) => Math.round(x * 100) / 100;

// --- sign-in as three accounts (the controller allows 8 parked polls per user) ---
async function signIn(user) {
  const r = await fetch(cfg.base + "/api/v1/login", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", origin: cfg.base },
    body: JSON.stringify({ username: user, password: cfg.password }),
    redirect: "manual",
  });
  if (r.status !== 200) throw new Error(`sign-in of ${user}: HTTP ${r.status}`);
  const cookie = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  return { cookie, csrf: (await r.json()).csrf };
}
async function root(method, path, body) {
  const r = await fetch(cfg.base + path, { method, headers: { authorization: cfg.auth, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return r.status;
}

const VIEWS = {
  login: ["/login", "!!document.querySelector('#username')", false],
  runs: ["/t/acme", "document.querySelectorAll('main table tbody tr').length >= 3"],
  run: [`/runs/${cfg.diamond}`, "document.querySelectorAll('.dag .node').length === 4"],
  log: [`/runs/${cfg.diamond}/logs/${cfg.attempts.beta}`, "document.querySelectorAll('.log-row').length > 5"],
  queue: ["/t/acme/queue", "document.querySelectorAll('main table tbody tr').length >= 1"],
  workers: ["/t/acme/workers", "document.querySelectorAll('main table tbody tr').length >= 1"],
  sync: ["/t/acme/sync", "document.querySelectorAll('main table tbody tr').length >= 1"],
  admin: ["/t/acme/admin", "document.querySelectorAll('main table tbody tr').length >= 2"],
  platform: ["/platform/tenants", "document.querySelectorAll('main table tbody tr').length >= 2"],
  account: ["/account", "!!document.querySelector('#mfa-h')"],
  organizations: ["/organizations", "!!document.querySelector('#ns-h')"],
  settings: ["/t/acme/settings", "!!document.querySelector('#about-h')"],
};

const record = {
  record: "web-bench",
  date: new Date().toISOString().slice(0, 10),
  host_label: LABEL,
  host: { cpu: cpus()[0].model.trim(), threads: cpus().length, mem_gib: Math.round(totalmem() / 2 ** 30), os: `${platform()} ${release()}` },
  node: process.version,
  interface: cfg.interface || "unknown",
  code: null,
  harness: `web/bench/web-bench.mjs: ${RENDERS} server renders per view after 5 warm-ups (time to the whole body, signed in as root, one at a time); shipped JavaScript = same-origin scripts a cache-disabled first load of each view fetched until it was ready and the network idle 500 ms, each gzip -9 in the harness; RSS from /proc of the web process(es); stream CPU = utime+stime of the web process(es) over ${STREAM_SECS} s with ten /_stream/log streams (4 root, 3 dana, 3 rui) on the live attempt (a line every 150 ms); log jumps: ${JUMPS} random scroll jumps over the read bulk log, work = script + layout + style time from Performance.getMetrics, ${JUMP_REPEATS} fresh pages`,
  niceness: Number(process.env.SENTINEL_BENCH_NICE || 0),
  load_start: load(),
};
try { record.code = execSync("git rev-parse --short HEAD", { cwd: repo }).toString().trim() + (execSync("git status --porcelain -- web crates", { cwd: repo }).toString().trim() ? "+dirty" : ""); } catch {}

// --- idle RSS: the process has served nothing yet ---
await sleep(3000);
record.rss_idle_kib = sumRss();
const idleTicks0 = sumTicks();
await sleep(10000);
record.cpu_idle_ms_per_10s = ((sumTicks() - idleTicks0) * 1000) / CLK_TCK;
log("idle rss KiB", record.rss_idle_kib);

for (const user of ["dana", "rui"]) await root("PUT", `/api/v1/tenants/acme/repos/app/grants/${user}`, { access: ["read"] });
const sessions = { root: await signIn("root"), dana: await signIn("dana"), rui: await signIn("rui") };

// --- server render time per view ---
record.render = {};
for (const [name, [path, , signedIn = true]] of Object.entries(VIEWS)) {
  const headers = { accept: "text/html" };
  if (signedIn) headers.cookie = sessions.root.cookie;
  const once = async () => {
    const t = performance.now();
    const r = await fetch(cfg.web + path, { headers, redirect: "manual" });
    const body = await r.text();
    return { ms: performance.now() - t, status: r.status, bytes: body.length };
  };
  for (let i = 0; i < 5; i++) await once();
  const xs = [];
  let status = 0, bytes = 0;
  for (let i = 0; i < RENDERS; i++) { const o = await once(); xs.push(o.ms); status = o.status; bytes = o.bytes; }
  record.render[name] = { n: xs.length, status, html_bytes: bytes, p50_ms: r2(pct(xs, 50)), p95_ms: r2(pct(xs, 95)), min_ms: r2(Math.min(...xs)), max_ms: r2(Math.max(...xs)), rss_after_kib: sumRss() };
  log("render", name, JSON.stringify(record.render[name]));
}
record.rss_after_renders_kib = sumRss();

// --- shipped JavaScript per first view, in a real browser ---
const browser = await launch();
record.browser = (await browser.send("Browser.getVersion")).product;
const page = await browser.newPage({ width: 1280, height: 860 });
const scripts = new Map();
const inflight = new Set();
browser.on("Network.requestWillBeSent", (p, s) => { if (s === page.sessionId) inflight.add(p.requestId); });
browser.on("Network.loadingFinished", (p, s) => { if (s === page.sessionId) inflight.delete(p.requestId); });
browser.on("Network.loadingFailed", (p, s) => { if (s === page.sessionId) inflight.delete(p.requestId); });
browser.on("Network.responseReceived", (p, s) => {
  if (s !== page.sessionId || p.type !== "Script") return;
  const u = new URL(p.response.url);
  if (u.origin === new URL(cfg.web).origin) scripts.set(u.pathname + u.search, true);
});
await page.send("Network.setCacheDisabled", { cacheDisabled: true });
// Sign in through the form, as a person does; later loads carry the cookie.
await page.goto(cfg.web + "/login");
await page.waitFor("!!document.querySelector('#username')", 20000, "sign-in form");
await page.fill("#username", "root");
await page.fill("#password", cfg.password);
await page.key("Enter");
await page.waitFor("location.pathname !== '/login'", 20000, "signed in");

const gz = new Map();
async function gzipOf(path) {
  if (!gz.has(path)) {
    const r = await fetch(cfg.web + path, { headers: { cookie: sessions.root.cookie, "accept-encoding": "identity" } });
    const buf = Buffer.from(await r.arrayBuffer());
    gz.set(path, { raw: buf.length, gzip: gzipSync(buf, { level: 9 }).length });
  }
  return gz.get(path);
}
const INLINE = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
record.first_view_js = {};
for (const [name, [path, ready, signedIn = true]] of Object.entries(VIEWS)) {
  if (!signedIn) continue;
  scripts.clear();
  await page.send("Network.clearBrowserCache");
  await page.goto(cfg.web + path);
  await page.waitFor(ready, 30000, `${name} ready`);
  for (let quiet = 0, i = 0; quiet < 5 && i < 100; i++) { await sleep(100); quiet = inflight.size === 0 ? quiet + 1 : 0; }
  let raw = 0, gzip = 0;
  for (const p of scripts.keys()) { const s = await gzipOf(p); raw += s.raw; gzip += s.gzip; }
  const html = await (await fetch(cfg.web + path, { headers: { cookie: sessions.root.cookie, accept: "text/html" } })).text();
  const inline = [...html.matchAll(INLINE)].map((m) => m[1]).join("");
  record.first_view_js[name] = { files: scripts.size, raw_bytes: raw, gzip_bytes: gzip, inline_script_gzip_bytes: inline ? gzipSync(Buffer.from(inline), { level: 9 }).length : 0 };
  log("js", name, JSON.stringify(record.first_view_js[name]));
}
record.rss_after_views_kib = sumRss();

// --- log-view work per scroll jump over the read bulk log ---
const jumps = [];
for (let rep = 0; rep < JUMP_REPEATS; rep++) {
  const p = await browser.newPage({ width: 1280, height: 900 });
  await p.goto(cfg.web + "/login");
  await p.waitFor("!!document.querySelector('#username')", 20000, "sign-in form");
  await p.fill("#username", "root");
  await p.fill("#password", cfg.password);
  await p.key("Enter");
  await p.waitFor("location.pathname !== '/login'", 20000, "signed in");
  await p.goto(`${cfg.web}/runs/${cfg.bulk}/logs/${cfg.bulk_attempt}`);
  await p.waitFor("document.querySelectorAll('nav[aria-label=Steps] button').length === 2", 30000, "bulk log");
  await p.click("nav[aria-label=Steps] li:nth-child(2) button");
  await p.waitFor("document.querySelector('#log-view').textContent.includes('of the flood')", 30000, "first page");
  const STATE = "(() => { const v = document.querySelector('.log').logViewer; const s = v.sections[1]; return { lines: s.lines, dropped: s.dropped, done: s.done, loading: s.loading }; })()";
  const end = Date.now() + 240000;
  let state;
  for (;;) {
    await p.eval("document.querySelector('#log-view').focus()");
    await p.key("End");
    await sleep(50);
    state = await p.eval(STATE);
    if ((state.done && !state.loading) || Date.now() > end) break;
  }
  await p.gc();
  const before = await p.metrics();
  const wall = await p.eval(`(async () => {
    const vp = document.querySelector('#log-view'); let seed = 7; const rand = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
    const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const t = performance.now();
    for (let i = 0; i < ${JUMPS}; i++) { vp.scrollTop = rand() * (vp.scrollHeight - vp.clientHeight); vp.dispatchEvent(new Event("scroll")); await frame(); }
    return performance.now() - t; })()`);
  const after = await p.metrics();
  const work = (m) => m.ScriptDuration + m.LayoutDuration + m.RecalcStyleDuration;
  jumps.push({ lines: state.lines, dropped: state.dropped, rows: await p.eval("document.querySelectorAll('.log-row').length"), work_ms: ((work(after) - work(before)) * 1000) / JUMPS, wall_ms: wall / JUMPS });
  log("jump", JSON.stringify(jumps.at(-1)));
  await p.close();
}
const works = jumps.map((j) => j.work_ms);
record.log_jump = { lines: jumps[0].lines, rows: jumps[0].rows, repeats: jumps.length, work_ms_median: r2(pct(works, 50)), work_ms_min: r2(Math.min(...works)), work_ms_max: r2(Math.max(...works)), wall_ms_median: r2(pct(jumps.map((j) => j.wall_ms), 50)) };
const errors = page.errors.filter((e) => !e.startsWith("network:"));
record.script_errors = errors.length;
await browser.close();
record.rss_after_all_views_kib = sumRss();

// --- CPU for ten live log streams ---
async function stream(session, counter, signal) {
  const r = await fetch(`${cfg.web}/_stream/log/${cfg.live_attempt}`, { headers: { cookie: session.cookie, accept: "text/event-stream" }, signal });
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const text = dec.decode(value);
      counter.frames += (text.match(/^event: frames$/gm) || []).length;
      counter.busy += (text.match(/^data: busy$/gm) || []).length;
    }
  } catch { /* aborted */ }
}
const owners = ["root", "root", "root", "root", "dana", "dana", "dana", "rui", "rui", "rui"];
const ac = new AbortController();
const counter = { frames: 0, busy: 0 };
const open = owners.map((u) => stream(sessions[u], counter, ac.signal));
await sleep(3000); // connected and caught up
const framesAt = counter.frames;
const t0 = sumTicks();
const w0 = performance.now();
await sleep(STREAM_SECS * 1000);
const cpuMs = ((sumTicks() - t0) * 1000) / CLK_TCK;
const wallMs = performance.now() - w0;
record.streams = { streams: owners.length, secs: STREAM_SECS, cpu_ms: cpuMs, cpu_percent_of_one_core: r2((cpuMs / wallMs) * 100), frames_events: counter.frames - framesAt, busy_events: counter.busy, rss_during_kib: sumRss() };
ac.abort();
await Promise.allSettled(open);
log("streams", JSON.stringify(record.streams));
record.rss_end_kib = sumRss();
record.load_end = load();

const line = JSON.stringify(record);
console.log(line);
if (RECORD) appendFileSync(resolve(repo, RECORD), line + "\n");
process.exit(errors.length ? 1 : 0);
