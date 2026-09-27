// U06: the web interface in a real browser, against a seeded controller and
// the built Nuxt server in front of it (crates/sentinel-api/tests/
// web_browser.rs starts both and passes the config). Every check prints
// PASS/FAIL; measurements go to <out>/ui-metrics.json and screenshots to
// <out>/*.png. Exit status 1 when any check failed.
//
//   node web/test/ui.mjs <config.json>

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import net from "node:net";
import { launch } from "./cdp.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));

// The browser reaches the web interface through this relay (`cfg.base`
// → `cfg.web`), so the test can cut the network for real: every open
// connection — event streams included — is dropped and new ones refused
// until it comes back.
const relay = { sockets: new Set(), down: false };
const relayServer = net.createServer((client) => {
  if (relay.down) { client.destroy(); return; }
  const target = new URL(cfg.web);
  const up = net.connect(Number(target.port), target.hostname);
  const end = () => { client.destroy(); up.destroy(); relay.sockets.delete(client); relay.sockets.delete(up); };
  relay.sockets.add(client); relay.sockets.add(up);
  client.pipe(up); up.pipe(client);
  for (const s of [client, up]) { s.on("error", end); s.on("close", end); }
});
if (cfg.web !== cfg.base) await new Promise((resolve) => relayServer.listen(Number(new URL(cfg.base).port), "127.0.0.1", resolve));
function cut(ms) {
  relay.down = true;
  for (const s of relay.sockets) s.destroy();
  relay.sockets.clear();
  setTimeout(() => { relay.down = false; }, ms);
}
mkdirSync(cfg.out, { recursive: true });
const failures = [];
const metrics = { when: new Date().toISOString(), checks: {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let current = null;

function check(name, ok, detail) {
  metrics.checks[name] = !!ok;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail !== undefined ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  if (!ok) failures.push(name);
}

async function scenario(name, fn) {
  try { await fn(); } catch (e) {
    check(`${name} (no error)`, false, e.stack || e.message);
    if (current) await current.screenshot(join(cfg.out, `failed-${name.replace(/[^a-z0-9]+/gi, "-")}.png`)).catch(() => {});
  }
}

/// The API as root, from the test (not the page), through the same origin.
async function apiAs(auth, method, path, body) {
  const r = await fetch(cfg.base + path, {
    method, headers: { authorization: auth, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null };
}
const root = (method, path, body) => apiAs(cfg.auth, method, path, body);

const SIGNED_IN = `!!document.querySelector('[aria-label="Account menu"]')`;
async function signIn(page, user) {
  await page.goto(cfg.base + "/login");
  await page.waitFor("!!document.querySelector('#username')", 15000, "sign-in form");
  await page.fill("#username", user);
  await page.fill("#password", cfg.password);
  await page.key("Enter");
  await page.waitFor(SIGNED_IN, 15000, "signed in");
}

async function go(page, path, ready, timeout = 20000) {
  await page.goto(cfg.base + path);
  await page.waitFor(ready, timeout, `${path} ready`);
}

const clickText = (selector, text) => `(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().includes(${JSON.stringify(text)})); if (!el) return false; el.click(); return true; })()`;

// ------------------------------------------------------------ in-page ----

/// WCAG contrast of every element's own visible text against the colour
/// behind it (alpha-blended up the ancestors). SVG text, visually hidden
/// text and disabled controls (exempt in WCAG) are skipped. Colours are
/// normalised through a canvas, so `oklch()` values compare correctly.
const CONTRAST = `(() => {
  const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
  const parse = (c) => {
    ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = c; ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2], d[3] / 255];
  };
  const blend = (top, bottom) => { const a = top[3]; return [top[0]*a + bottom[0]*(1-a), top[1]*a + bottom[1]*(1-a), top[2]*a + bottom[2]*(1-a), 1]; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); }; return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2]); };
  const background = (el) => {
    const stack = [];
    for (let e = el; e; e = e.parentElement) { const bg = parse(getComputedStyle(e).backgroundColor); if (bg[3] > 0) stack.push(bg); if (bg[3] >= 1) break; }
    let c = parse(getComputedStyle(document.body).backgroundColor);
    if (c[3] === 0) c = parse(getComputedStyle(document.documentElement).backgroundColor);
    if (c[3] === 0) c = [255,255,255,1];
    for (let i = stack.length - 1; i >= 0; i--) c = blend(stack[i], c);
    return c;
  };
  const bad = []; let checked = 0;
  for (const el of document.body.querySelectorAll("*")) {
    if (el.closest("svg, .sr, .sr-only, [hidden], script, style, noscript, [aria-hidden=true]") || el.disabled || el.closest("[disabled], [data-disabled]")) continue;
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) continue;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || Number(st.opacity) === 0) continue;
    const bg = background(el);
    const fg = blend(parse(st.color), bg);
    const [a, b] = [lum(fg), lum(bg)];
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const size = parseFloat(st.fontSize), bold = Number(st.fontWeight) >= 700;
    const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5;
    checked++;
    if (ratio < need) bad.push({ text: el.textContent.trim().slice(0, 40), ratio: Math.round(ratio * 100) / 100, need, color: st.color, bg: "rgb(" + bg.slice(0,3).map(Math.round).join(",") + ")" });
  }
  return { checked, bad: bad.slice(0, 10), count: bad.length };
})()`;

const OVERFLOW = `(() => ({ scroll: document.documentElement.scrollWidth, width: window.innerWidth }))()`;

const FOCUS_RING = `(() => { const el = document.activeElement; if (!el || el === document.body) return null;
  const r = el.getBoundingClientRect();
  // The ring may be drawn by the element or by its ::before/::after.
  const drawn = (st) => (st.outlineStyle !== "none" && parseFloat(st.outlineWidth) > 0) || (st.boxShadow && st.boxShadow !== "none");
  const ring = [null, "::before", "::after"].some((pseudo) => drawn(getComputedStyle(el, pseudo)));
  return { tag: el.tagName, text: (el.getAttribute("aria-label") || el.textContent || el.value || "").trim().slice(0, 40),
    ring, visible: r.width > 0 && r.height > 0 }; })()`;

async function axAudit(page, label, signedOut) {
  const nodes = await page.axTree();
  const interactive = new Set(["button", "link", "textbox", "combobox", "checkbox", "searchbox", "listbox", "menuitem", "tab", "spinbutton"]);
  const unnamed = [];
  const roles = new Map();
  let h1 = 0;
  for (const n of nodes) {
    if (n.ignored) continue;
    const role = n.role && n.role.value;
    roles.set(role, (roles.get(role) || 0) + 1);
    const name = n.name && n.name.value ? String(n.name.value).trim() : "";
    if (interactive.has(role) && !name) unnamed.push(role);
    if (role === "heading" && (n.properties || []).some((p) => p.name === "level" && p.value.value === 1)) h1++;
  }
  check(`${label}: every control has an accessible name`, unnamed.length === 0, unnamed);
  check(`${label}: a main landmark${signedOut ? "" : " and navigation"}`, roles.get("main") === 1 && (signedOut || roles.get("navigation") >= 1),
    { main: roles.get("main"), navigation: roles.get("navigation") });
  check(`${label}: one level-one heading`, h1 === 1, h1);
}

// -------------------------------------------------------------- tests ----

const browser = await launch();
const page = await browser.newPage({ width: 1280, height: 860 });
current = page;

const PAGES = {
  runs: ["/t/acme", "document.querySelectorAll('main table tbody tr').length >= 3"],
  run: [`/runs/${cfg.diamond}`, "document.querySelectorAll('.dag .node').length === 4 && document.body.textContent.includes('expected 200, got 500')"],
  log: [`/runs/${cfg.diamond}/logs/${cfg.attempts.beta}`, "document.querySelectorAll('.log-row').length > 5"],
  queue: ["/t/acme/queue", "document.querySelectorAll('main table tbody tr').length >= 1"],
  workers: ["/t/acme/workers", "document.querySelectorAll('main table tbody tr').length >= 1"],
  sync: ["/t/acme/sync", "document.querySelectorAll('main table tbody tr').length >= 1"],
  admin: ["/t/acme/admin", "document.querySelectorAll('main table tbody tr').length >= 2"],
  platform: ["/platform/tenants", "document.querySelectorAll('main table tbody tr').length >= 2"],
};

await scenario("sign-in", async () => {
  const started = Date.now();
  await page.goto(cfg.base + "/t/acme");
  await page.waitFor("!!document.querySelector('#username')", 15000);
  metrics.sign_in_page_ms = Date.now() - started;
  check("a signed-out visit lands on sign-in, keeping where it was going", decodeURIComponent(await page.eval("location.search")).includes("next=/t/acme"));
  await axAudit(page, "sign-in page", true);
  await page.fill("#username", "root");
  await page.fill("#password", "wrong password");
  await page.key("Enter");
  await page.waitFor("!!document.querySelector('[role=alert]')", 8000, "refusal");
  check("a refused sign-in is announced", (await page.eval("document.querySelector('[role=alert]').textContent")).includes("refused"));
  await page.fill("#password", cfg.password);
  await page.key("Enter");
  await page.waitFor(`${SIGNED_IN} && location.pathname === '/t/acme'`, 15000, "signed in where it was going");
  check("sign-in continues to the page asked for", true);
});

await scenario("pages", async () => {
  for (const [name, [path, ready]] of Object.entries(PAGES)) {
    const started = Date.now();
    await go(page, path, ready);
    metrics[`view_${name}_ms`] = Date.now() - started;
    await axAudit(page, name);
    await page.screenshot(join(cfg.out, `${name}-1280.png`));
  }
  // A client-side navigation moves focus to the new view's heading.
  await go(page, "/t/acme", PAGES.runs[1]);
  await page.eval(clickText("nav a", "Queue"));
  await page.waitFor("location.pathname === '/t/acme/queue' && document.activeElement && document.activeElement.tagName === 'H1'", 10000, "focus on heading");
  check("navigation moves focus to the view's heading", true);
});

await scenario("hopping between live pages", async () => {
  // Each live page holds one stream; leaving it must give the controller's
  // parked wait back at once, or a person clicking through a few runs and
  // logs would run out of their share and see "busy".
  for (let i = 0; i < 4; i++) {
    await go(page, PAGES.run[0], "document.querySelectorAll('.dag .node').length === 4");
    await sleep(400);
    await go(page, `/runs/${cfg.diamond}/logs/${cfg.live_attempt}`, "document.querySelector('#log-view').textContent.includes('live line')");
    await sleep(400);
  }
  await go(page, PAGES.run[0], "document.querySelectorAll('.dag .node').length === 4");
  await sleep(3000);
  const text = await page.eval("document.body.textContent");
  check("after hopping between live pages the run page is live, not busy", text.includes("Live") && !text.includes("controller busy"));
});

await scenario("contrast", async () => {
  for (const dark of [false, true]) {
    await page.scheme(dark);
    for (const [name, [path, ready]] of Object.entries(PAGES)) {
      await go(page, path, ready);
      await sleep(300);
      const result = await page.eval(CONTRAST);
      check(`${name}, ${dark ? "dark" : "light"}: text contrast meets WCAG AA (${result.checked} elements)`, result.count === 0, result.bad);
    }
    await go(page, PAGES.run[0], PAGES.run[1]);
    await page.screenshot(join(cfg.out, `run-${dark ? "dark" : "light"}.png`));
  }
  await page.scheme(false);
});

await scenario("layouts", async () => {
  for (const width of [360, 768, 1280]) {
    await page.viewport(width, 800);
    for (const [name, [path, ready]] of Object.entries(PAGES)) {
      await go(page, path, ready);
      await sleep(200);
      const o = await page.eval(OVERFLOW);
      check(`${name} at ${width}px: no horizontal page scroll`, o.scroll <= o.width + 1, o);
      if (width === 360) await page.screenshot(join(cfg.out, `${name}-360.png`));
    }
  }
  await page.viewport(1280, 860);
});

await scenario("keyboard", async () => {
  await go(page, PAGES.run[0], PAGES.run[1]);
  await page.eval("(() => { document.activeElement && document.activeElement.blur(); document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute('tabindex'); })()");
  await page.key("Tab");
  check("the first tab stop is the skip link", (await page.eval("document.activeElement.textContent.trim()")) === "Skip to content");
  await page.key("Enter");
  check("the skip link moves focus to the content", (await page.eval("document.activeElement.id")) === "main");
  // Walk every tab stop from the top of the page.
  await page.eval("(() => { document.activeElement && document.activeElement.blur(); document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute('tabindex'); })()");
  const stops = [];
  for (let i = 0; i < 120; i++) {
    await page.key("Tab");
    const f = await page.eval(FOCUS_RING);
    if (!f) break;
    stops.push(f);
  }
  const labels = stops.map((s) => s.text);
  check("run page: cancel, rerun and log controls are keyboard reachable",
    labels.some((t) => t.startsWith("Cancel run")) && labels.some((t) => t.startsWith("Rerun")) && labels.some((t) => t.startsWith("Log of")), labels.slice(0, 40));
  const blind = stops.filter((s) => !s.ring || !s.visible);
  check("run page: every tab stop shows a focus indicator", blind.length === 0, blind.slice(0, 5));

  await go(page, PAGES.log[0], PAGES.log[1]);
  await page.eval("document.querySelector('#log-view').focus()");
  const lineH = await page.eval("document.querySelector('.log-row').getBoundingClientRect().height");
  await page.key("ArrowDown");
  await page.key("ArrowDown");
  check("log: arrow keys scroll by line", (await page.eval("document.querySelector('#log-view').scrollTop")) === 2 * lineH);
  await page.key("End");
  // End may reveal the step's status row and grow the list by a row: the
  // key keeps working until the view rests at the bottom.
  const atEnd = "(() => { const v = document.querySelector('#log-view'); return v.scrollTop + v.clientHeight >= v.scrollHeight - 1; })()";
  for (let i = 0; i < 5 && !(await page.eval(atEnd)); i++) { await sleep(100); await page.key("End"); }
  check("log: End reaches the end", await page.eval(atEnd));
  await page.key("Home");
  check("log: Home returns to the start", (await page.eval("document.querySelector('#log-view').scrollTop")) === 0);
  const toggle = "document.querySelector('nav[aria-label=Steps] button')";
  const before = await page.eval(`${toggle}.getAttribute('aria-expanded')`);
  await page.eval(`${toggle}.focus()`);
  await page.key("Enter");
  const after = await page.eval(`${toggle}.getAttribute('aria-expanded')`);
  check("log: a step folds and unfolds from the keyboard with aria-expanded", before !== after, { before, after });
});

await scenario("runs and filters", async () => {
  await go(page, "/t/acme", PAGES.runs[1]);
  // The filter form, as a person uses it: pick "Pull request", type, submit.
  await page.click("#f-kind");
  await page.waitFor("!!document.querySelector('[role=option]')", 5000, "filter options");
  await page.clickText("[role=option]", "Pull request");
  await page.fill("#f-value", "42");
  await page.key("Enter");
  const onlyRow = (text) => `(() => { const r = document.querySelectorAll('main table tbody tr'); return r.length === 1 && r[0].textContent.includes(${JSON.stringify(text)}); })()`;
  await page.waitFor(`location.search.includes('pr=42') && ${onlyRow("#42")}`, 10000, "pull request filter");
  check("filter by pull request", true);
  await go(page, "/t/acme?repo=app&sha=2222222", onlyRow("222222222222"));
  check("filter by commit prefix, deep-linked", true);

  await go(page, PAGES.run[0], PAGES.run[1]);
  const run = await page.eval(`(() => ({
    rows: document.querySelector('main table').querySelectorAll('tbody tr').length,
    failure: document.querySelector('[aria-label^="Failure of"]').textContent,
  }))()`);
  check("run: four jobs in the table", run.rows === 4, run.rows);
  check("run: the failed job's summary names the failing step and message", run.failure.includes("unit") && run.failure.includes("expected 200, got 500"), run.failure.slice(0, 200));
  await page.waitFor("document.body.textContent.includes('reflink')", 10000, "caches");
  check("run: cache outcomes with backend", true);
  await page.eval(clickText("[aria-label^='Failure of'] a", "evidence"));
  await page.waitFor("!!document.querySelector('.log-row.hl')", 15000, "evidence highlighted");
  check("evidence link opens the log at the line", (await page.eval("location.search")).includes("seq="));
});

await scenario("log search, gaps and deep links", async () => {
  await go(page, PAGES.log[0], PAGES.log[1]);
  const text = await page.eval("document.querySelector('#log-view').textContent");
  check("log: the stored gap is shown where it is", text.includes("was never stored"));
  const folds = await page.eval(`[...document.querySelectorAll('nav[aria-label=Steps] button')].map((x) => x.getAttribute('aria-expanded'))`);
  check("log: passed steps are folded, the failed one open", folds.join() === "false,true,false", folds);
  await page.fill("#log-q", "TestCheckout");
  await page.key("Enter");
  const hits = "ul[aria-label='Search results'] li:not(.more) button";
  await page.waitFor(`document.querySelectorAll("${hits}").length > 0`, 10000);
  await page.click(hits);
  await page.waitFor("!!document.querySelector('.log-row.hl')", 10000);
  const hl = await page.eval("document.querySelector('.log-row.hl').textContent");
  check("log: a search hit jumps to its line, marked", hl.includes("TestCheckout") && (await page.eval("!!document.querySelector('.log-row.hl mark')")), hl);
  const link = await page.eval("location.pathname + location.search");
  await go(page, link, "!!document.querySelector('.log-row.hl')");
  check("log: the deep link reopens at the same line", (await page.eval("document.querySelector('.log-row.hl').textContent")).includes("TestCheckout"), link);
});

await scenario("large log bounds", async () => {
  await page.gc();
  const baseHeap = (await page.metrics()).JSHeapUsedSize;
  await go(page, `/runs/${cfg.bulk}/logs/${cfg.bulk_attempt}`, "document.querySelectorAll('nav[aria-label=Steps] button').length === 2");
  const started = Date.now();
  await page.click("nav[aria-label=Steps] li:nth-child(2) button");
  await page.waitFor("document.querySelector('#log-view').textContent.includes('line         1 of the flood')", 15000, "first page");
  metrics.large_first_page_ms = Date.now() - started;
  let maxRows = 0, maxElements = 0, maxHeap = 0;
  const deadline = Date.now() + 240000;
  const STATE = `(() => { const v = document.querySelector('.log').logViewer; const sec = v.sections[1];
    return { rows: document.querySelectorAll('.log-row').length, elements: document.getElementsByTagName('*').length, lines: sec.lines, dropped: sec.dropped, done: sec.done, loading: sec.loading }; })()`;
  for (;;) {
    await page.eval("document.querySelector('#log-view').focus()");
    await page.key("End");
    await sleep(50);
    const s = await page.eval(STATE);
    maxRows = Math.max(maxRows, s.rows);
    maxElements = Math.max(maxElements, s.elements);
    if (s.done && !s.loading) { metrics.large_state = s; break; }
    if (Date.now() > deadline) { metrics.large_state = s; break; }
    if ((s.lines + s.dropped) % 50000 < 2000) maxHeap = Math.max(maxHeap, (await page.metrics()).JSHeapUsedSize);
  }
  metrics.large_all_pages_ms = Date.now() - started;
  await page.gc();
  const heap = (await page.metrics()).JSHeapUsedSize;
  maxHeap = Math.max(maxHeap, heap);
  metrics.large = { lines: cfg.bulk_lines, max_rows: maxRows, max_elements: maxElements, heap_bytes: heap, max_heap_bytes: maxHeap, base_heap_bytes: baseHeap };
  check("large log: read to the end", metrics.large_state.done, metrics.large_state);
  check("large log: at most 150 row elements whatever the length", maxRows <= 150, maxRows);
  check("large log: under 3,000 elements in the whole page", maxElements <= 3000, maxElements);
  check("large log: memory bound released the oldest lines and says so", metrics.large_state.dropped > 0 && metrics.large_state.lines <= 250000, metrics.large_state);
  check("large log: heap under 200 MiB", maxHeap < 200 * 2 ** 20, Math.round(maxHeap / 2 ** 20) + " MiB");
  await page.key("Home");
  await sleep(200);
  check("large log: the released lines are said at the top of the step",
    (await page.eval("document.querySelector('#log-view').textContent")).includes("released to bound memory"));
  await page.fill("#log-q", "needle-7f3a");
  await page.key("Enter");
  const hits = "ul[aria-label='Search results'] li:not(.more) button";
  await page.waitFor(`document.querySelectorAll("${hits}").length > 0`, 60000);
  await page.click(hits);
  await page.waitFor("!!document.querySelector('.log-row.hl')", 15000);
  check("large log: search finds the one line", (await page.eval("document.querySelector('.log-row.hl').textContent")).includes("needle-7f3a"));
  await page.screenshot(join(cfg.out, "large-log.png"));
});

const LIVE = `(() => { const v = document.querySelector('.log').logViewer; return v.sections[0].text.filter((t) => t.startsWith('live line ')).map((t) => Number(t.slice(10))); })()`;
const consecutive = (xs) => xs.every((x, i) => i === 0 || x === xs[i - 1] + 1);

await scenario("live log through a lost connection", async () => {
  await go(page, `/runs/${cfg.diamond}/logs/${cfg.live_attempt}`, "document.querySelector('#log-view').textContent.includes('live line')");
  await sleep(1500);
  const first = await page.eval(LIVE);
  check("live: new lines stream in while following", first.length >= 5 && consecutive(first), first.slice(-5));
  cut(4000);
  await page.waitFor("document.querySelector('.log p[role=status]').textContent.includes('Connection lost')", 10000, "reconnecting notice");
  check("live: a lost connection is said", true);
  await sleep(4000);
  const resumedAt = Date.now();
  await page.waitFor(`(${LIVE}).length > ${first.length + 20}`, 40000, "resumed");
  metrics.live_resume_ms = Date.now() - resumedAt;
  const resumed = await page.eval(LIVE);
  check("live: after reconnecting nothing is lost or repeated", consecutive(resumed), resumed.slice(-5));
});

await scenario("an open run page through a busy controller", async () => {
  // The same user's parked waits (on another, quiet run) take its whole
  // share of subscribers before the page opens: the web server's wait for
  // the page is refused as busy until they end.
  const { body: quiet } = await root("GET", `/api/v1/runs/${cfg.pr_run}/wait`);
  const spellEnds = Date.now() + 9000;
  const hold = async () => {
    while (Date.now() < spellEnds - 100) {
      await root("GET", `/api/v1/runs/${cfg.pr_run}/wait?since=${quiet.version}&timeout_ms=${Math.max(1, spellEnds - Date.now())}`);
    }
  };
  const held = Array.from({ length: cfg.subscribers_per_user }, hold);
  await sleep(300);
  await go(page, PAGES.run[0], "document.querySelectorAll('.dag .node').length === 4");
  await page.waitFor("document.body.textContent.includes('Updates paused: controller busy')", 20000, "busy notice");
  check("a busy controller is said, not treated as an error", !(await page.eval("!!document.querySelector('[role=alert]')")));
  await Promise.all(held);
  await page.waitFor("document.body.textContent.includes('Live') && !document.body.textContent.includes('controller busy')", 40000, "live again");
  const rerun = await root("POST", `/api/v1/jobs/${cfg.jobs.zeta}/rerun`, {});
  check("zeta is re-run under the page", rerun.status === 200, rerun);
  await page.waitFor("[...document.querySelector('main table').querySelectorAll('tbody tr')].some((r) => r.textContent.startsWith('zeta') && !r.textContent.includes('skipped'))", 20000, "update after the spell");
  check("after the busy spell the page shows changes live", true);
  const errors = page.errors.filter((e) => !e.startsWith("network:"));
  check("no script errors so far", errors.length === 0, errors);
});

await scenario("role changes during open sessions", async () => {
  await root("PUT", "/api/v1/tenants/acme/repos/app/grants/dana", { access: ["read", "run"] });
  const other = await browser.newPage({ width: 1280, height: 860 });
  current = other;
  await signIn(other, "dana");
  await go(other, `/runs/${cfg.diamond}`, "document.querySelectorAll('main table tbody tr').length === 4");
  check("dana (operator) sees no tenant admin link", !(await other.eval(`[...document.querySelectorAll('nav a')].some((a) => a.textContent.includes('Tenant admin'))`)));
  await root("PUT", "/api/v1/tenants/acme/members/dana", { role: "reader" });
  await other.eval(clickText("main table tbody tr button", "Cancel"));
  await other.waitFor("document.body.textContent.includes('no longer have access') || document.body.textContent.includes('not permitted')", 10000, "refusal toast");
  check("a lowered role's action is refused and said", true);
  const removedAt = Date.now();
  await root("DELETE", "/api/v1/tenants/acme/members/dana");
  await other.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('no longer have access'))", 10000, "removal shown");
  metrics.removal_noticed_ms = Date.now() - removedAt;
  check("removal is noticed by the open page within 5 s", metrics.removal_noticed_ms < 5000, metrics.removal_noticed_ms);
  await other.waitFor("!document.querySelector('[aria-label=\"Active tenant\"]')", 10000, "tenant list re-read");
  check("the tenant disappears from the navigation", true);
  await other.close();
  current = page;
});

await scenario("administration with step-up", async () => {
  await go(page, "/platform/tenants", PAGES.platform[1]);
  await page.eval(clickText("main table tbody tr:nth-child(2) button", "Suspend"));
  await page.waitFor(`!!document.querySelector('[role=dialog]')`, 8000, "confirmation");
  await page.eval(clickText("[role=dialog] button", "Suspend"));
  await page.waitFor("!!document.querySelector('#stepup-code')", 10000, "step-up dialog");
  check("a privileged change asks for a second factor", true);
  await page.fill("#stepup-code", cfg.password);
  await page.key("Enter");
  await page.waitFor("document.querySelector('main table tbody tr:nth-child(2)').textContent.includes('suspended')", 15000, "suspended");
  check("after step-up the tenant is suspended", true);
  await page.eval(clickText("main table tbody tr:nth-child(2) button", "Reactivate"));
  await page.waitFor("document.querySelector('main table tbody tr:nth-child(2)').textContent.includes('active')", 15000, "reactivated");
  const asked = `[...document.querySelectorAll('[role=dialog]')].some((d) => d.textContent.includes("Confirm it's you"))`;
  const again = await page.waitFor(`!${asked}`, 5000, "no second step-up").then(() => false, () => true);
  check("reactivated without asking again inside the window", !again);
  await go(page, "/t/acme/admin", PAGES.admin[1]);
  await page.click('[aria-label="Role of rui"]');
  await page.waitFor("!!document.querySelector('[role=option]')", 5000, "role options");
  await page.clickText("[role=option]", "Operator");
  await sleep(1000);
  const { body } = await root("GET", "/api/v1/tenants/acme/members");
  check("a member's role changes from the members table", body.members.find((m) => m.username === "rui").role === "operator");
});

const scriptErrors = page.errors.filter((e) => !e.startsWith("network:"));
check("no uncaught script errors", scriptErrors.length === 0, scriptErrors);
const hydration = page.console.filter((c) => c.includes("Hydration"));
check("server and browser render the same pages (no hydration mismatches)", hydration.length === 0, hydration.slice(0, 3));
await browser.close();
relayServer.close();
metrics.failures = failures;
writeFileSync(join(cfg.out, "ui-metrics.json"), JSON.stringify(metrics, null, 2));
console.log(`\n${failures.length ? "FAILED" : "PASSED"}: ${Object.keys(metrics.checks).length - failures.length}/${Object.keys(metrics.checks).length} checks; metrics in ${join(cfg.out, "ui-metrics.json")}`);
process.exit(failures.length ? 1 : 0);
