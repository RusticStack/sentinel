import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { launch } from "./cdp.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));

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

// SENTINEL_UI_ONLY="name;name" runs only those scenarios (after the sign-in they build on): a way to repeat one while
// working on it, never used by the gate.
const only = process.env.SENTINEL_UI_ONLY ? process.env.SENTINEL_UI_ONLY.split(";") : null;
async function scenario(name, fn) {
  if (only && !only.includes(name) && name !== "sign-in") return;
  try { await fn(); } catch (e) {
    check(`${name} (no error)`, false, e.stack || e.message);
    if (current) await current.screenshot(join(cfg.out, `failed-${name.replace(/[^a-z0-9]+/gi, "-")}.png`)).catch(() => {});
  }
}

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
  try {
    await page.waitFor(ready, timeout, `${path} ready`);
  } catch (error) {
    const shown = await page.eval("JSON.stringify({ at: location.pathname, rows: [...document.querySelectorAll('main table tbody tr')].map((r) => r.textContent.replace(/\\s+/g, ' ').slice(0, 60)), alerts: [...document.querySelectorAll('[role=alert]')].map((a) => a.textContent.trim().slice(0, 120)), text: document.body.innerText.replace(/\\s+/g, ' ').slice(0, 400) })").catch(() => "(page unreadable)");
    throw new Error(`${error.message}; the page showed ${shown}`);
  }
}

const clickText = (selector, text) => `(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().includes(${JSON.stringify(text)})); if (!el) return false; el.click(); return true; })()`;

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

// On an overflow it names the widest elements that stick out, so a failure points at the cause.
const OVERFLOW = `(() => { const width = window.innerWidth, scroll = document.documentElement.scrollWidth;
  const wide = scroll <= width + 1 ? [] : [...document.querySelectorAll('body *')].map((e) => ({ e, right: Math.round(e.getBoundingClientRect().right) }))
    .filter((x) => x.right > width + 1).sort((a, b) => b.right - a.right).slice(0, 5)
    .map(({ e, right }) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + '.' + String(e.className).split(' ').slice(0, 4).join('.') + ' right=' + right);
  return { scroll, width, wide }; })()`;

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
  storage: ["/t/acme/admin/storage", "document.querySelectorAll('main table tbody tr').length >= 1"],
  disk: ["/platform/storage", "document.body.textContent.includes('Metadata database')"],
  account: ["/account", "!!document.querySelector('#mfa-h') && !!document.querySelector('#password-h')"],
  service: ["/t/acme/admin/service-accounts", "!!document.querySelector('#sa-new-h')"],
  organizations: ["/organizations", "!!document.querySelector('#ns-h') && !!document.querySelector('#new-org-h')"],
  settings: ["/t/acme/settings", "!!document.querySelector('#about-h') && !!document.querySelector('#members-h')"],
  invitations: ["/t/acme/admin/invitations", "!!document.querySelector('#invite-h')"],
  workers: ["/platform/workers", "!!document.querySelector('#w-add-h') && !!document.querySelector('#w-pool')"],
  github: ["/setup/github", "document.querySelector('h1') && document.querySelector('h1').textContent === 'GitHub App' && document.querySelectorAll('main [role=status], main section').length >= 1"],
};

const PUBLIC_PAGES = {
  register: ["/register", "!!document.querySelector('#su-email')"],
  verify: ["/verify-email", "!!document.querySelector('#resend-email')"],
  forgot: ["/forgot-password", "document.querySelector('h1') && document.querySelector('h1').textContent.includes('Forgot')"],
  invitation: ["/invitations/accept", "document.querySelector('h1') && document.querySelector('h1').textContent.includes('invitation link')"],
};

function totp(key) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of key.replace(/[\s=]/g, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const secret = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const at = mac[19] & 15;
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1e6).padStart(6, "0");
}

await scenario("public pages", async () => {
  await go(page, "/setup", "location.pathname === '/login' && !!document.querySelector('#username')");
  check("the setup wizard is not reachable once setup is complete", true);
  for (const [name, [path, ready]] of Object.entries(PUBLIC_PAGES)) {
    await go(page, path, ready);
    await axAudit(page, `${name} page`, true);
    for (const dark of [false, true]) {
      await page.scheme(dark);
      await go(page, path, ready);
      await sleep(200);
      const result = await page.eval(CONTRAST);
      check(`${name}, ${dark ? "dark" : "light"}: text contrast meets WCAG AA (${result.checked} elements)`, result.count === 0, result.bad);
    }
    await page.scheme(false);
    await page.viewport(360, 800);
    await sleep(200);
    const o = await page.eval(OVERFLOW);
    check(`${name} at 360px: no horizontal page scroll`, o.scroll <= o.width + 1, o);
    await page.screenshot(join(cfg.out, `${name}-360.png`));
    await page.viewport(1280, 860);
  }

  await go(page, ...PUBLIC_PAGES.register);
  check("sign-up asks password managers for a new password",
    await page.eval("document.querySelector('#su-password').autocomplete === 'new-password' && document.querySelector('#su-again').autocomplete === 'new-password'"));
  await page.fill("#su-email", "newcomer@example.com");
  await page.fill("#su-password", "a long enough passphrase");
  await page.fill("#su-again", "a long enough passphrase");
  await page.key("Enter");
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('needs an invitation'))", 8000, "policy refusal");
  check("a refused sign-up says the instance needs an invitation", true);
  check("the password fields are emptied after sending", await page.eval("document.querySelector('#su-password').value === '' && document.querySelector('#su-again').value === ''"));

  await go(page, `/verify-email#token=${"ab".repeat(32)}`, "[...document.querySelectorAll('button')].some((b) => b.textContent.includes('Confirm my address'))");
  check("a verification link's secret is removed from the address bar", (await page.eval("location.hash")) === "");
  await page.clickText("button", "Confirm my address");
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('invalid or has expired')) && !!document.querySelector('#resend-email')", 8000, "invalid link");
  check("an unusable verification link is said, with a way to get a new one", true);
  await page.fill("#resend-email", "nobody-here@example.com");
  await page.key("Enter");
  await page.waitFor("[...document.querySelectorAll('[role=status]')].some((s) => s.textContent.includes('can be used here'))", 8000, "resend answer");
  check("asking for a new link answers the same whether or not the address exists", true);

  // Email-registered accounts have generated usernames: the administrator needs the lookup, and the address in lower case.
  await go(page, ...PUBLIC_PAGES.forgot);
  const recovery = await page.eval("document.querySelector('details pre code').textContent");
  check("forgot-password gives the administrator the lookup of a generated username by email, then the recovery",
    ["local_credentials", "users.email", "--data-dir", "--username"].every((part) => recovery.includes(part)), recovery);
  check("forgot-password says the address is stored in lower case", (await page.eval("document.querySelector('details').textContent")).includes("lower case"));
});

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
  await go(page, "/t/acme", PAGES.runs[1]);
  await page.eval(clickText("nav a", "Queue"));
  await page.waitFor("location.pathname === '/t/acme/queue' && document.activeElement && document.activeElement.tagName === 'H1'", 10000, "focus on heading");
  check("navigation moves focus to the view's heading", true);
});

await scenario("GitHub App setup page", async () => {
  await go(page, ...PAGES.github);
  const policy = await page.eval("fetch('/setup/github', { headers: { accept: 'text/html' } }).then((r) => r.headers.get('content-security-policy') || '')");
  check("the GitHub App page may post its manifest form to GitHub only", /form-action 'self' https:\/\/github\.com(;|$)/.test(policy), policy.slice(0, 300));
  const other = await page.eval("fetch('/t/acme', { headers: { accept: 'text/html' } }).then((r) => r.headers.get('content-security-policy') || '')");
  check("other pages keep form-action to this origin", /form-action 'self'(;|$)/.test(other));
  const text = await page.eval("document.querySelector('main').textContent");
  check("a controller GitHub cannot reach over HTTPS is said on the page", text.includes("GitHub cannot deliver events"), text.slice(0, 300));
});

await scenario("hopping between live pages", async () => {
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
  const atEnd = "(() => { const v = document.querySelector('#log-view'); return v.scrollTop + v.clientHeight >= v.scrollHeight - 1; })()";
  let rested = 0;
  for (let i = 0; i < 40 && rested < 3; i++) {
    if (await page.eval(atEnd)) rested++;
    else { rested = 0; await page.key("End"); }
    await sleep(100);
  }
  check("log: End reaches the end", rested >= 3,
    await page.eval("(() => { const v = document.querySelector('#log-view'); return { top: v.scrollTop, client: v.clientHeight, height: v.scrollHeight, rows: document.querySelectorAll('.log-row').length }; })()"));
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
  const { body: quiet } = await root("GET", `/api/v1/runs/${cfg.pr_run}/wait`);
  const spellEnds = Date.now() + 20000;
  const parkUrl = (timeout) => `/api/v1/runs/${cfg.pr_run}/wait?since=${quiet.version}&timeout_ms=${timeout}`;
  // A refused holder pauses briefly instead of spinning on the 429, and keeps asking until the spell ends.
  const hold = async () => {
    while (Date.now() < spellEnds - 100) {
      const answer = await root("GET", parkUrl(Math.max(1, spellEnds - Date.now())));
      if (answer.status === 429) await sleep(25);
    }
  };
  const held = Array.from({ length: cfg.subscribers_per_user }, hold);
  // Ready when the share is full: a further park by the same user is refused. That proves every holder is parked,
  // where a fixed pause only hoped so.
  const ready = Date.now() + 5000;
  for (;;) {
    const probe = await root("GET", parkUrl(1));
    if (probe.status === 429) break;
    if (Date.now() > ready) throw new Error(`the subscriber share never filled (last answer ${probe.status})`);
    await sleep(25);
  }
  // What the page's stream said and when, to show in the failure if the notice never comes.
  const watch = await page.send("Page.addScriptToEvaluateOnNewDocument", { source: `(() => { const Source = window.EventSource; window.__stream = [];
    window.EventSource = class extends Source { constructor(url, init) { super(url, init); const note = (what) => window.__stream.push([Math.round(performance.now()), what]);
      this.addEventListener("status", (e) => note("status " + e.data)); this.addEventListener("run", () => note("run")); this.addEventListener("error", () => note("error")); } }; })()` });
  const opened = Date.now();
  await go(page, PAGES.run[0], "document.querySelectorAll('.dag .node').length === 4");
  const noticeWait = Math.max(1000, spellEnds - Date.now() - 500);
  await page.waitFor("document.body.textContent.includes('Updates paused: controller busy')", noticeWait, "busy notice").catch(async (e) => {
    const shown = await page.eval("JSON.stringify({ stream: window.__stream, text: document.body.innerText.replace(/\s+/g, ' ').slice(0, 300) })").catch(() => "(page unreadable)");
    throw new Error(`${e.message}; the page loaded after ${Date.now() - opened} ms of a ${spellEnds - opened} ms spell and showed ${shown}`);
  });
  await page.send("Page.removeScriptToEvaluateOnNewDocument", { identifier: watch.identifier });
  const alerts = await page.eval("[...document.querySelectorAll('[role=alert]')].map((a) => a.textContent.trim().slice(0, 120)).filter((t) => t)");
  const empty = await page.eval("[...document.querySelectorAll('[role=alert]')].filter((a) => !a.textContent.trim()).map((a) => a.outerHTML.slice(0, 200))");
  if (empty.length) console.log("note: empty alert elements during the busy spell", JSON.stringify(empty));
  check("a busy controller is said, not treated as an error", alerts.length === 0, alerts);
  await Promise.all(held);
  const freed = Date.now();
  // The relay retries at the delay the controller states (1 s) and calls the page live once a retry is parked.
  await page.waitFor("document.body.textContent.includes('Live') && !document.body.textContent.includes('controller busy')", 12000, "live again");
  metrics.busy_recovery_ms = Date.now() - freed;
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
  await go(other, `/runs/${cfg.diamond}`, "document.querySelector('main table').querySelectorAll('tbody tr').length === 4");
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
  await other.waitFor("!document.querySelector('[aria-label=\"Active namespace\"]')", 10000, "tenant list re-read");
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

await scenario("storage policy", async () => {
  await go(page, ...PAGES.storage);
  await page.click('[aria-label="Storage policy of app"]');
  await page.waitFor("!!document.querySelector('#repo-app-logs')", 8000, "policy form");
  await page.fill("#repo-app-logs", "2");
  await page.key("Tab");
  await page.clickText("[role=dialog] button", "Save");
  await page.waitFor("!document.querySelector('[role=dialog]')", 8000, "saved");
  const { body } = await root("GET", "/api/v1/tenants/acme/storage");
  const app = body.repos.find((r) => r.name === "app");
  check("a repository's log retention is set from the storage page", app.policy.log_retention_ms === 2 * 86_400_000, app.policy);
  await go(page, ...PAGES.disk);
  check("the deployment's disk and stored bytes are shown", await page.eval("document.body.textContent.includes('Stored by tenants') && document.body.textContent.includes('Data filesystem')"));
});

await scenario("organizations and invitations", async () => {
  const { body: tenants } = await apiAs(cfg.auth, "GET", "/api/v1/tenants");
  check("the tenant list says each namespace's kind and membership source",
    (tenants.tenants || []).every((t) => ["personal", "organization"].includes(t.kind) && ["app", "github"].includes(t.membership)), tenants.tenants);

  await go(page, ...PAGES.organizations);
  await page.fill("#org-slug", "Bad Name");
  await page.key("Enter");
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('lowercase'))", 5000, "name refused in the page");
  check("an organization name of the wrong shape is refused before it is sent", true);
  await page.fill("#org-slug", "web-team");
  await page.key("Enter");
  await page.waitFor("location.pathname === '/t/web-team/settings' && !!document.querySelector('#about-h')", 10000, "new organization");
  check("a new organization opens on its settings, managed in Sentinel",
    await page.eval("document.querySelector('main').textContent.includes('Managed in Sentinel')"));
  check("an administrator sees the operator's domain rule, read-only",
    await page.eval("!!document.querySelector('#domains-h') && document.querySelector('main').textContent.includes('Read-only') && !document.querySelector('#domains-h').closest('section').querySelector('input')"));

  await page.click('[aria-label="Active namespace"]');
  await page.waitFor("!!document.querySelector('[role=option]')", 5000, "namespace options");
  check("the namespace switcher groups organizations apart", await page.eval("[...document.querySelectorAll('[role=listbox] *')].some((e) => e.textContent.trim() === 'Organizations')"));
  await page.key("Escape");

  await go(page, "/t/web-team/admin/invitations", "!!document.querySelector('#inv-email')");
  await page.fill("#inv-email", "invitee@example.com");
  await page.key("Enter");
  await page.waitFor("!!document.querySelector('[role=dialog] li') || [...document.querySelectorAll('main td')].some((t) => t.textContent.includes('invitee@example.com'))", 10000, "invitation made");
  if (await page.eval("!!document.querySelector('[role=dialog] li')")) {
    const link = await page.eval("document.querySelector('[role=dialog] li').textContent.trim()");
    check("without mail delivery the invitation link is shown once, pointing at the accept page", /\/invitations\/accept#token=sntl_[0-9a-f]{64}$/.test(link), link.replace(/[0-9a-f]{64}/, "…"));
    await page.click("[role=dialog] [role=checkbox]");
    await page.clickText("[role=dialog] button", "Done");
    await page.waitFor("!document.querySelector('[role=dialog]')", 8000, "link dialog closed");
    check("the link leaves the page once saved", !(await page.eval(`document.body.textContent.includes(${JSON.stringify(link)})`)));
  }
  await page.waitFor("[...document.querySelectorAll('main tr')].some((r) => r.textContent.includes('invitee@example.com') && r.textContent.includes('Pending'))", 8000, "pending invitation listed");
  check("the invitation is listed as pending, without its secret", !(await page.eval("/sntl_[0-9a-f]{64}/.test(document.querySelector('main').textContent)")));
  await page.click('[aria-label="Revoke the invitation for invitee@example.com"]');
  await page.waitFor("!!document.querySelector('[role=dialog]')", 5000, "revoke confirmation");
  await page.clickText("[role=dialog] button", "Revoke");
  await page.waitFor("[...document.querySelectorAll('main tr')].some((r) => r.textContent.includes('invitee@example.com') && r.textContent.includes('Revoked'))", 8000, "revoked");
  check("an invitation is revoked from the list", true);

  await go(page, `/invitations/accept#token=sntl_${"cd".repeat(32)}`, "[...document.querySelectorAll('button')].some((b) => b.textContent.includes('Accept invitation'))");
  check("an invitation link's secret is removed from the address bar", (await page.eval("location.hash")) === "");
  await page.clickText("button", "Accept invitation");
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('could not accept'))", 8000, "unusable invitation");
  check("an unusable invitation is said without naming an organization", !(await page.eval("document.querySelector('main').textContent.includes('acme')")));

  await page.eval(`(() => {
    document.cookie = "sentinel-return=%2Finvitations%2Faccept; Path=/; Max-Age=600; SameSite=Lax";
    sessionStorage.setItem("sentinel-invitation", JSON.stringify({ token: "sntl_${"cd".repeat(32)}", until: Date.now() + 600000 }));
    return true;
  })()`);
  await go(page, "/", "location.pathname.startsWith('/t/') || [...document.querySelectorAll('button')].some((b) => b.textContent.includes('Accept invitation'))");
  check("a GitHub sign-in started from an invitation comes back to the invitation, not the first tenant",
    await page.eval("location.pathname === '/invitations/accept' && [...document.querySelectorAll('button')].some((b) => b.textContent.includes('Accept invitation'))"),
    await page.eval("location.pathname"));
  check("the parked invitation secret leaves session storage once read", (await page.eval("sessionStorage.getItem('sentinel-invitation')")) === null);
  check("the return marker is cleared once it has served", !(await page.eval("document.cookie.includes('sentinel-return=')")));
  await go(page, "/", "location.pathname.startsWith('/t/')");
  check("without a pending return `/` opens a tenant again", true);

  await page.eval(`(() => { sessionStorage.setItem("sentinel-invitation", JSON.stringify({ token: "sntl_${"cd".repeat(32)}", until: Date.now() - 1 })); return true; })()`);
  await go(page, "/organizations", "!!document.querySelector('#org-slug')");
  check("an expired parked invitation secret is removed on the next load", (await page.eval("sessionStorage.getItem('sentinel-invitation')")) === null);
});

// A read that fails is refused in words, not drawn as an empty list. The page's fetch is replaced for the reads under
// test, and the section is reached by a link, so the route loader runs in the browser.
const STUB_READS = (pattern) => `(() => { window.__real ??= window.fetch; const failing = new RegExp(${JSON.stringify(pattern)});
  window.fetch = (input, init) => { const url = String(input && input.url ? input.url : input);
    return failing.test(url)
      ? Promise.resolve(new Response(JSON.stringify({ code: "internal", message: "stubbed failure" }), { status: 500, headers: { "content-type": "application/json" } }))
      : window.__real(input, init); };
  return true; })()`;
const UNSTUB_READS = `(() => { if (window.__real) window.fetch = window.__real; return true; })()`;
const RECORD_PUTS = `(() => { window.__real ??= window.fetch; window.__puts = [];
  window.fetch = (input, init) => { if (init && init.method === "PUT") window.__puts.push(String(input && input.url ? input.url : input)); return window.__real(input, init); };
  return true; })()`;
const members = async () => (await root("GET", "/api/v1/tenants/acme/members?limit=100")).body.members;
const serviceNamed = async (name) => (await members()).find((m) => m.kind === "service" && m.display_name === name);
const hasAlert = (text) => `[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes(${JSON.stringify(text)}))`;

await scenario("a failed read is said, not drawn as an empty list", async () => {
  await go(page, "/t/acme/admin/repos", "!!document.querySelector('#repos-h')");
  // Opening a source binding is a read: it announces nothing.
  await page.eval(clickText("main button", "Source binding"));
  await page.waitFor("!!document.querySelector('main button[aria-expanded=true]')", 8000, "source binding opened");
  check("a read action does not toast 'done'", await page.eval(`![...document.querySelectorAll('[aria-live]')].some((r) => r.textContent.includes('Source of'))`));

  await page.eval(STUB_READS("/tenants/acme/(members\\?|settings$)"));
  await page.eval(clickText("nav[aria-label=Sections] a", "Members"));
  await page.waitFor(hasAlert("Could not load the members"), 10000, "members failure");
  check("a failed members read is an alert with Try again, not an empty table",
    await page.eval(`!document.querySelector('main table') && [...document.querySelectorAll('[role=alert] button')].some((b) => b.textContent.trim() === 'Try again')`));
  await page.eval(UNSTUB_READS);
  await page.eval(clickText("[role=alert] button", "Try again"));
  await page.waitFor(`document.querySelectorAll('main table tbody tr').length >= 2 && !(${hasAlert("Could not load")})`, 10000, "members after Try again");
  check("Try again reads the members again", true);

  await page.eval(STUB_READS("/tenants/acme/(members\\?|settings$)"));
  await page.eval(clickText("nav[aria-label=Sections] a", "Invitations"));
  await page.waitFor(hasAlert("Could not load namespace settings"), 10000, "settings failure");
  check("with the settings unread the invitations section says so and offers no form",
    await page.eval("!document.querySelector('#inv-email') && !document.body.textContent.includes('No invitations yet')"));
  await page.eval(UNSTUB_READS);
  await page.eval(clickText("[role=alert] button", "Try again"));
  await page.waitFor("!!document.querySelector('#inv-email')", 10000, "invitation form after Try again");
  check("Try again brings the invitation form back", true);

  await go(page, "/platform/tenants", PAGES.platform[1]);
  await page.eval(STUB_READS("/api/v1/admin/(pools|policy)"));
  await page.eval(clickText("nav[aria-label=Sections] a", "Pools"));
  await page.waitFor(hasAlert("Could not load the worker pools"), 10000, "pools failure");
  await page.eval(clickText("nav[aria-label=Sections] a", "Policy"));
  await page.waitFor(hasAlert("Could not load the admission policy"), 10000, "policy failure");
  check("a failed policy read shows no form of defaults that saving would overwrite the policy with", await page.eval("!document.querySelector('#pol-reg')"));
  await page.eval(UNSTUB_READS);
  await page.eval(clickText("[role=alert] button", "Try again"));
  await page.waitFor("!!document.querySelector('#pol-reg')", 10000, "policy form after Try again");
  check("Try again reads the policy again", true);
});

await scenario("adding a member by user id", async () => {
  await go(page, "/t/acme/admin", PAGES.admin[1]);
  await page.eval(RECORD_PUTS);
  const puts = () => page.eval("window.__puts");

  await page.fill("#m-user", "pat");
  await page.key("Enter");
  await page.waitFor(hasAlert("user id"), 5000, "inline refusal");
  check("a name that is no member's is refused in the form, in words that say what to do",
    await page.eval(`${hasAlert("invite them by email")} && !document.body.textContent.includes('no longer have access')`));
  check("and nothing is sent", (await puts()).length === 0, await puts());

  await page.fill("#m-user", "rui");
  await page.key("Enter");
  await page.waitFor("window.__puts.length === 1", 8000, "role change sent");
  check("a member's username changes the role through the member's id", (await puts())[0].endsWith(`/members/${cfg.rui}`), await puts());
  await page.waitFor("[...document.querySelectorAll('main table tbody tr')].find((r) => r.textContent.includes('rui')).textContent.includes('Reader')", 8000, "role shown");
  check("the new role is saved", (await members()).find((m) => m.username === "rui").role === "reader");

  await page.fill("#m-user", ` ${cfg.dana} `);
  await page.key("Enter");
  await page.waitFor("[...document.querySelectorAll('main table tbody tr')].some((r) => r.textContent.includes('dana'))", 8000, "dana added");
  check("a user id typed with spaces around it is trimmed and adds the person", (await puts()).at(-1).endsWith(`/members/${cfg.dana}`), await puts());
  check("the person is a member", (await members()).some((m) => m.username === "dana"));
});

// Step-up decisions: each scenario signs in on its own page (its own browser context), so its session has no earlier
// confirmation. Every outcome is read from the controller's state, not from timing.
const COUNT_STEPUPS = `(() => { window.__steps = 0; const real = window.fetch;
  window.fetch = async (input, init) => { const response = await real(input, init); if (String(input && input.url ? input.url : input).endsWith("/api/v1/step-up")) window.__steps++; return response; };
  return true; })()`;
const ASKED = "!!document.querySelector('#stepup-code')";
const FIELD_READY = "!!document.activeElement && document.activeElement.id === 'stepup-code' && document.querySelector('#stepup-code').value === ''";

async function openServiceAccounts(p, user) {
  await signIn(p, user);
  await go(p, "/t/acme/admin/service-accounts", PAGES.service[1]);
}
async function createServiceAccount(p, name) {
  await p.fill("#sa-name", name);
  await p.key("Enter");
}
// Answers the step-up dialog with the password when one opens, then waits for the outcome.
async function answeringStepUp(p, outcome, what) {
  await p.waitFor(`${ASKED} || (${outcome})`, 10000, what);
  if (await p.eval(ASKED)) {
    await p.fill("#stepup-code", cfg.password);
    await p.key("Enter");
  }
  await p.waitFor(outcome, 10000, what);
}

await scenario("step-up decisions", async () => {
  const sp = await browser.newPage({ width: 1280, height: 860 });
  current = sp;
  await openServiceAccounts(sp, "root");

  await createServiceAccount(sp, "cancelled-bot");
  await sp.waitFor(ASKED, 10000, "step-up dialog");
  await sp.clickText("[role=dialog] button", "Cancel");
  await sp.waitFor("!document.querySelector('[role=dialog]')", 8000, "dialog closed by Cancel");
  check("Cancel drops the change: no service account is made and nothing is said",
    !(await serviceNamed("cancelled-bot")) && !(await sp.eval("document.body.textContent.includes('cancelled-bot')")));
  check("Cancel returns focus to where it was", await sp.eval("document.activeElement && document.activeElement.id === 'sa-name'"), await sp.eval("document.activeElement && document.activeElement.id"));

  await createServiceAccount(sp, "escaped-bot");
  await sp.waitFor(ASKED, 10000, "step-up dialog again");
  await sp.key("Escape");
  await sp.waitFor("!document.querySelector('[role=dialog]')", 8000, "dialog closed by Escape");
  check("Escape drops the change as Cancel does", !(await serviceNamed("escaped-bot")));

  await createServiceAccount(sp, "ci-bot");
  await sp.waitFor(ASKED, 10000, "step-up dialog a third time");
  await sp.fill("#stepup-code", "not the password");
  await sp.key("Enter");
  await sp.waitFor("[...document.querySelectorAll('[role=dialog] [role=alert]')].some((a) => a.textContent.includes('That password was not accepted'))", 8000, "wrong proof said");
  await sp.waitFor(FIELD_READY, 5000, "field emptied and focused");
  check("a wrong password is said, the dialog stays, the field is empty and focused", await sp.eval("!!document.querySelector('[role=dialog]')"));
  check("and the change still has not been made", !(await serviceNamed("ci-bot")));

  await sp.fill("#stepup-code", cfg.password);
  await sp.key("Enter");
  await sp.waitFor("!document.querySelector('[role=dialog]') && [...document.querySelectorAll('h3')].some((h) => h.textContent.includes('ci-bot'))", 10000, "service account made");
  check("the right password makes the change once", !!(await serviceNamed("ci-bot")));
  check("and says so", await sp.eval("document.body.textContent.includes('Create ci-bot: done')"));
  const traces = await sp.eval("[location.href, JSON.stringify(localStorage), JSON.stringify(sessionStorage), document.cookie].join(' ')");
  check("neither proof is left in the address, storage or cookies", !traces.includes(cfg.password) && !traces.includes("not the password"));
  await sp.close();
  current = page;
});

await scenario("step-up session end", async () => {
  const gone = await browser.newPage({ width: 1280, height: 860 });
  current = gone;
  await openServiceAccounts(gone, "ivy");
  await gone.eval(COUNT_STEPUPS);
  await createServiceAccount(gone, "ivy-bot");
  await gone.waitFor(ASKED, 10000, "step-up dialog");
  for (let n = 1; n <= 5; n++) {
    await gone.fill("#stepup-code", `wrong proof ${n}`);
    await gone.key("Enter");
    await gone.waitFor(`window.__steps === ${n} && ${FIELD_READY}`, 8000, `wrong proof ${n} answered`);
  }
  // The fifth wrong proof revokes the session as it is refused; the next request learns it, even with the right proof.
  check("five wrong proofs are each refused and said, the dialog still open", await gone.eval("!!document.querySelector('[role=dialog]')"));
  await gone.fill("#stepup-code", cfg.password);
  await gone.key("Enter");
  await gone.waitFor("location.pathname === '/login'", 10000, "sign-in after five wrong proofs");
  check("after five wrong proofs even the right one finds the session ended: the dialog is gone and the page is at sign-in", await gone.eval("!document.querySelector('[role=dialog]')"));
  check("the change was never made", !(await serviceNamed("ivy-bot")));
  check("the session is revoked on the controller", (await gone.eval("fetch('/api/v1/me', { headers: { accept: 'application/json' } }).then((r) => r.status)")) === 401);
  await gone.close();
  current = page;
});

await scenario("step-up second factor", async () => {
  const first = await browser.newPage({ width: 1280, height: 860 });
  current = first;
  await openServiceAccounts(first, "mia");
  await createServiceAccount(first, "mia-bot");
  await first.waitFor(ASKED, 10000, "step-up dialog");
  check("an account with an authenticator is offered its app and its recovery codes",
    (await first.eval("[...document.querySelectorAll('[role=dialog] input[type=radio]')].map((r) => r.value).join()")) === "totp,recovery"
    && (await first.eval("document.querySelector('label[for=stepup-code]').textContent.includes('Code from the app')")));
  const wrong = totp(cfg.mia.key) === "000000" ? "111111" : "000000";
  await first.fill("#stepup-code", wrong);
  await first.key("Enter");
  await first.waitFor(hasAlert("That code was not accepted"), 8000, "wrong code said");
  await first.waitFor(FIELD_READY, 5000, "field emptied and focused");
  check("a wrong authenticator code is said, and the field is emptied", true);
  await first.click("input[value=recovery]");
  await first.waitFor("document.querySelector('label[for=stepup-code]').textContent.includes('Recovery code')", 5000, "recovery field");
  await first.waitFor("![...document.querySelectorAll('[role=dialog] [role=alert]')].some((a) => a.textContent.trim())", 5000, "old message dropped");
  check("choosing a recovery code changes the field and drops the old message", true);
  await first.fill("#stepup-code", cfg.mia.recovery[0]);
  await first.key("Enter");
  await first.waitFor("!document.querySelector('[role=dialog]') && [...document.querySelectorAll('h3')].some((h) => h.textContent.includes('mia-bot'))", 10000, "made with a recovery code");
  check("a recovery code confirms the change", !!(await serviceNamed("mia-bot")));
  await first.close();

  const second = await browser.newPage({ width: 1280, height: 860 });
  current = second;
  await openServiceAccounts(second, "mia");
  await createServiceAccount(second, "mia-bot-2");
  await second.waitFor(ASKED, 10000, "step-up dialog in a second session");
  await second.click("input[value=recovery]");
  await second.waitFor("document.querySelector('label[for=stepup-code]').textContent.includes('Recovery code')", 5000, "recovery field");
  await second.fill("#stepup-code", cfg.mia.recovery[0]);
  await second.key("Enter");
  await second.waitFor(hasAlert("already used"), 8000, "spent code refused");
  check("a recovery code works once: the second use is refused and said", !(await serviceNamed("mia-bot-2")));
  await second.click("input[value=totp]");
  await second.waitFor("document.querySelector('label[for=stepup-code]').textContent.includes('Code from the app')", 5000, "app field");
  await second.fill("#stepup-code", totp(cfg.mia.key));
  await second.key("Enter");
  await second.waitFor("!document.querySelector('[role=dialog]') && [...document.querySelectorAll('h3')].some((h) => h.textContent.includes('mia-bot-2'))", 10000, "made with the app's code");
  check("the authenticator's code confirms the change", !!(await serviceNamed("mia-bot-2")));
  await second.close();
  current = page;
});

const inCard = (name, selector, text) => `(() => {
  const h = [...document.querySelectorAll('h3')].find((x) => x.textContent.includes(${JSON.stringify(name)}));
  const card = h && h.closest('.rounded-lg');
  const el = card && [...card.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim() === ${JSON.stringify(text)});
  if (!el) return false; el.click(); return true; })()`;

await scenario("service credential shown once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-dl-"));
  const sc = await browser.newPage({ width: 1280, height: 860 });
  current = sc;
  await sc.allowDownloads(dir);
  await openServiceAccounts(sc, "root");
  const account = await serviceNamed("ci-bot");
  const row = (name, text) => `[...document.querySelectorAll('main tr')].some((r) => r.textContent.includes(${JSON.stringify(name)}) && r.textContent.includes(${JSON.stringify(text)}))`;

  await sc.eval(inCard("ci-bot", "button", "Set access"));
  await answeringStepUp(sc, "document.body.textContent.includes('Access of ci-bot to app: done')", "access set");

  await sc.fill(`#sa-gname-${account.user}`, "agent-1");
  await sc.key("Enter");
  await answeringStepUp(sc, "!!document.querySelector('[role=dialog] li')", "credential shown");
  const secret = await sc.eval("document.querySelector('[role=dialog] li').textContent.trim()");
  check("a credential is shown in a dialog", secret.length > 20 && (await sc.eval("document.querySelectorAll('[role=dialog] li').length")) === 1);
  const done = "[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === 'Done')";
  check("Done stays disabled until the credential is saved", await sc.eval(`${done}.disabled`));
  await sc.key("Escape");
  await sc.key("Escape");
  // A browser may close the dialog on a repeated Escape; it reopens at once, so the credential is never left unshown.
  await sc.waitFor("!!document.querySelector('dialog[open] li')", 3000, "dialog open after Escape");
  check("Escape does not close it", true);
  for (const type of ["mousePressed", "mouseReleased"]) await sc.send("Input.dispatchMouseEvent", { type, x: 4, y: 4, button: "left", clickCount: 1 });
  check("a click outside does not close it", await sc.eval("!!document.querySelector('dialog[open] li')"));

  await sc.clickText("[role=dialog] button", "Download");
  const file = join(dir, "ci-bot.token");
  let saved = null;
  for (let i = 0; i < 200 && saved === null; i++) {
    if (existsSync(file) && !readdirSync(dir).some((f) => f.endsWith(".crdownload"))) saved = readFileSync(file, "utf8");
    else await sleep(50);
  }
  check("the download is named for the account and holds the secret and a newline", saved === `${secret}\n`, saved === null ? { files: readdirSync(dir), events: sc.downloads } : { name: "ci-bot.token", bytes: saved.length });

  await sc.click("[role=dialog] [role=checkbox]");
  await sc.clickText("[role=dialog] button", "Done");
  await sc.waitFor("!document.querySelector('[role=dialog]')", 8000, "dialog closed");
  const traces = await sc.eval(`(() => { const s = ${JSON.stringify(secret)};
    return [document.documentElement.outerHTML, location.href, JSON.stringify(localStorage), JSON.stringify(sessionStorage), document.cookie].some((t) => t.includes(s)); })()`);
  check("once saved the credential is in no part of the page, address, storage or cookies", !traces);

  await sc.eval(inCard("ci-bot", "button", "Show credentials"));
  await sc.waitFor(row("agent-1", "agent-1"), 8000, "credential listed");
  check("the list names the credential without its secret", !(await sc.eval(`document.querySelector('main').textContent.includes(${JSON.stringify(secret)})`)));
  const grants = async () => (await root("GET", `/api/v1/tenants/acme/service-accounts/${account.user}/grants`)).body.grants;
  await sc.click('[aria-label="Revoke agent-1"]');
  await sc.waitFor("!!document.querySelector('[role=dialog]')", 5000, "revoke confirmation");
  await sc.clickText("[role=dialog] button", "Keep");
  await sc.waitFor("!document.querySelector('[role=dialog]')", 5000, "confirmation closed");
  check("keeping the credential leaves it usable", (await grants()).find((g) => g.name === "agent-1").revoked === false);
  await sc.click('[aria-label="Revoke agent-1"]');
  await sc.waitFor("!!document.querySelector('[role=dialog]')", 5000, "revoke confirmation again");
  await sc.clickText("[role=dialog] button", "Revoke");
  await answeringStepUp(sc, `${row("agent-1", "revoked")} && !document.querySelector('[aria-label="Revoke agent-1"]')`, "revoked shown");
  check("revoking marks it revoked and takes the button away", true);
  check("the controller has it revoked", (await grants()).find((g) => g.name === "agent-1").revoked === true);
  await sc.close();
  current = page;
});

await scenario("worker enrollment page", async () => {
  const made = await root("POST", "/api/v1/admin/pools", { name: "fleet", kind: "shared" });
  check("a shared pool exists to enrol machines into", made.status === 201, made);

  // A fresh browser context has no step-up stamp, and every request, answer and console line it makes is recorded.
  const enr = await browser.newPage({ width: 1280, height: 860 });
  current = enr;
  const requests = [];
  const answers = [];
  browser.on("Network.requestWillBeSent", (p, s) => {
    if (s === enr.sessionId) requests.push({ method: p.request.method, url: p.request.url, headers: JSON.stringify(p.request.headers), post: p.request.postData ?? "" });
  });
  browser.on("Network.responseReceived", (p, s) => {
    if (s === enr.sessionId) answers.push({ url: p.response.url, status: p.response.status, cache: p.response.headers["cache-control"] ?? p.response.headers["Cache-Control"] ?? "" });
  });
  await signIn(enr, "root");

  const READY = "!!document.querySelector('#w-add-h') && !!document.querySelector('#w-pool')";
  await go(enr, "/platform/workers", READY);
  check("a platform administrator sees the Workers section", await enr.eval("[...document.querySelectorAll('nav[aria-label=Sections] a')].some((a) => a.textContent.trim() === 'Workers' && a.getAttribute('aria-current') === 'page')"));
  await axAudit(enr, "worker enrollment page");

  const pick = async (trigger, text) => {
    await enr.click(trigger);
    await enr.waitFor("!!document.querySelector('[role=option]')", 5000, "options");
    await enr.clickText("[role=option]", text);
    await enr.waitFor("!document.querySelector('[role=option]')", 5000, "options closed");
  };
  await pick("#w-pool", "fleet");
  check("the pool is chosen from the active pools", (await enr.eval("document.querySelector('#w-pool').textContent")).includes("fleet"));
  check("Tailcat is preselected when the controller offers it", (await enr.eval("document.querySelector('#w-transport').textContent")).includes("Tailcat"));

  // A bad ceiling is refused in the page, before anything is sent.
  const issues = () => requests.filter((r) => r.method === "POST" && r.url.endsWith("/api/v1/admin/worker-enrollments")).length;
  await enr.fill("#w-mem", "1.5");
  await enr.key("Enter");
  await enr.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('whole number of GiB'))", 5000, "ceiling refused");
  check("a fractional memory ceiling is refused in the page and nothing is sent", issues() === 0);
  await enr.fill("#w-cpu", "4");
  await enr.fill("#w-mem", "16");
  await enr.fill("#w-disk", "100");
  await enr.fill("#w-priority", "5");
  await enr.fill("#w-hours", "2");

  const secrets = [];
  const dialogValues = "[...document.querySelectorAll('[role=dialog] li [data-secret], [role=dialog] li')].filter((e, i, all) => !all.some((o) => o !== e && e.contains(o))).map((e) => e.textContent.trim())";
  async function saveAndClose(expected) {
    await enr.waitFor(`(${dialogValues}).length === ${expected}`, 15000, "the shown-once dialog");
    const values = await enr.eval(dialogValues);
    check(`the dialog lists exactly ${expected} value${expected === 1 ? "" : "s"}`, values.length === expected, values.length);
    check("Done stays disabled until the person says they saved it",
      await enr.eval(`[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === 'Done').disabled`));
    secrets.push(...values);
    await enr.click("[role=dialog] [role=checkbox]");
    await enr.clickText("[role=dialog] button", "Done");
    await enr.waitFor("!document.querySelector('[role=dialog]')", 8000, "dialog closed");
    return values;
  }

  const enrollmentCount = async () => (await root("GET", "/api/v1/admin/worker-enrollments")).body.enrollments.length;
  const issuedBefore = await enrollmentCount();
  await enr.key("Enter");
  await enr.waitFor("!!document.querySelector('#stepup-code')", 10000, "step-up dialog");
  check("issuing asks a fresh session for a second factor", true);
  check("nothing was issued before the second factor", (await enrollmentCount()) === issuedBefore, { issuedBefore });
  await enr.fill("#stepup-code", cfg.password);
  await enr.key("Enter");
  const [secret, address] = await saveAndClose(2);
  check("line one is an enrollment secret", /^sntl_[0-9a-f]{64}$/.test(secret), secret.replace(/[0-9a-f]{64}/, "…"));
  check("line two is the controller's Tailcat address", address === cfg.tailcat_address);
  const issuedPost = answers.find((a) => a.url.endsWith("/api/v1/admin/worker-enrollments") && a.status === 201);
  check("the issuing answer is not cacheable", issuedPost && issuedPost.cache.includes("no-store"), issuedPost);
  check("neither value is in the page once the dialog is closed",
    !(await enr.eval(`document.documentElement.outerHTML.includes(${JSON.stringify(secret.slice(5))}) || document.documentElement.outerHTML.includes(${JSON.stringify(address)})`)));

  await enr.waitFor("!!document.querySelector('#w-next-h')", 10000, "next steps");
  check("next steps appear for the new enrollment", true);
  const { body: listed } = await root("GET", "/api/v1/admin/worker-enrollments");
  const first = listed.enrollments[0];
  check("the enrollment is pending in the fleet pool with the approved ceilings",
    first.state === "pending" && first.transport === "tailcat" && first.host.cpu_millis === 4000 && first.host.memory_bytes === 16 * 2 ** 30 && first.host.disk_bytes === 100 * 2 ** 30 && first.host.priority === 5, first);

  // The script, checked by the page against the controller's digest and by this process against the bytes.
  await enr.clickText("button", "Download script");
  await enr.waitFor("document.querySelector('#w-script-status').textContent.includes('matches the controller digest')", 15000, "digest verified");
  check("the page recomputed the script's SHA-256 and it matches the controller's", true);
  const shown = await enr.eval("document.querySelector('#w-script-status code').textContent");
  const served = await fetch(`${cfg.base}/api/v1/admin/worker-enrollments/${first.id}/bootstrap.sh`, { headers: { authorization: cfg.auth } });
  const text = await served.text();
  check("the digest shown is the SHA-256 of the script the controller serves", createHash("sha256").update(text).digest("hex") === shown, shown);
  check("the script holds neither the secret nor the Tailcat address", !text.includes(secret.slice(5)) && !text.includes(address));
  const steps = await enr.eval("document.querySelector('#w-next-h').closest('section').textContent");
  check("the install command is given, with no secret in it", steps.includes("sudo sh sentinel-worker-bootstrap.sh install") && !steps.includes(secret.slice(5)));
  check("rollback and uninstall instructions are on the page", (await enr.eval("document.body.textContent")).includes("sentinel-worker-bootstrap.sh rollback") && (await enr.eval("document.body.textContent")).includes("sentinel-worker-bootstrap.sh uninstall"));
  check("this controller redeems over HTTPS, so no node-key form is offered", !(await enr.eval("!!document.querySelector('#w-identity')")));

  // A layout, contrast and keyboard pass over the page in the state a person works in.
  for (const dark of [false, true]) {
    await enr.scheme(dark);
    await sleep(300);
    const result = await enr.eval(CONTRAST);
    check(`worker enrollment page, ${dark ? "dark" : "light"}: text contrast meets WCAG AA (${result.checked} elements)`, result.count === 0, result.bad);
  }
  await enr.scheme(false);
  await enr.screenshot(join(cfg.out, "workers-1280.png"));
  await enr.viewport(360, 800);
  await sleep(300);
  const narrow = await enr.eval(OVERFLOW);
  check("worker enrollment page at 360px: no horizontal page scroll", narrow.scroll <= narrow.width + 1, narrow);
  await enr.screenshot(join(cfg.out, "workers-360.png"));
  await enr.viewport(1280, 860);
  await enr.eval("(() => { document.activeElement && document.activeElement.blur(); document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute('tabindex'); })()");
  const stops = [];
  for (let i = 0; i < 90; i++) {
    await enr.key("Tab");
    const f = await enr.eval(FOCUS_RING);
    if (!f) break;
    stops.push(f);
  }
  check("worker enrollment page: the form and the install steps are keyboard reachable",
    stops.some((s) => s.text.startsWith("Issue enrollment")) && stops.some((s) => s.text.startsWith("Download script")), stops.map((s) => s.text).slice(0, 40));
  const blind = stops.filter((s) => !s.ring || !s.visible);
  check("worker enrollment page: every tab stop shows a focus indicator", blind.length === 0, blind.slice(0, 5));

  // The machine redeems through the API URL; the page then says plainly that the script is no longer served.
  const redeemBody = (secretText, worker, print) => JSON.stringify({ secret: secretText, worker, name: "ui-1", fingerprint: print, arch: "x86_64", node_key: `nodekey:${"07".repeat(32)}` });
  const post = (body) => fetch(`${cfg.base}/api/v1/worker-enrollments/redeem`, { method: "POST", headers: { "content-type": "application/json" }, body });
  const worker = `wrk_${randomUUID()}`;
  const redeemed = await post(redeemBody(secret, worker, "11".repeat(32)));
  const redeemedBody = await redeemed.json();
  check("the machine redeems its enrollment at the API URL", redeemed.status === 200 && redeemedBody.worker === worker && redeemedBody.tailcat_address === cfg.tailcat_address, redeemedBody.message);
  const again = await post(redeemBody(secret, `wrk_${randomUUID()}`, "22".repeat(32)));
  check("a second machine presenting the same secret gets the uniform refusal", again.status === 403, again.status);
  await enr.clickText("button", "Download script");
  await enr.waitFor("[...document.querySelectorAll('#w-script-status [role=alert]')].some((a) => a.textContent.includes('no longer pending'))", 10000, "409 sentence");
  check("a spent enrollment's download is refused in plain words", true);
  check("a refused download offers no file", !(await enr.eval("document.querySelector('#w-script-status').textContent.includes('matches')")));

  // A direct-TLS enrollment withdrawn elsewhere while the page still lists it: the 404 is said, not hidden.
  const stepUpIfAsked = async () => {
    await sleep(400);
    if (await enr.eval("!!document.querySelector('#stepup-code')")) {
      await enr.fill("#stepup-code", cfg.password);
      await enr.key("Enter");
      await enr.waitFor("!document.querySelector('#stepup-code')", 10000, "step-up done");
    }
  };
  await pick("#w-transport", "Direct TLS");
  await enr.eval("document.querySelector('#w-hours').focus()");
  await enr.key("Enter");
  const [direct, directAddress] = await saveAndClose(1);
  check("a direct enrollment shows the secret alone", /^sntl_[0-9a-f]{64}$/.test(direct) && directAddress === undefined);
  await enr.waitFor("[...document.querySelectorAll('main table tbody tr')].some((r) => r.textContent.includes('pending') && r.textContent.includes('Direct TLS'))", 10000, "pending row");
  const { body: now } = await root("GET", "/api/v1/admin/worker-enrollments");
  const stale = now.enrollments.find((e) => e.state === "pending");
  const gone = await root("DELETE", `/api/v1/admin/worker-enrollments/${stale.id}`);
  check("the enrollment is withdrawn behind the page's back", gone.status === 204, gone);
  await enr.click('main table button[aria-label^="Withdraw"]');
  await enr.waitFor("!!document.querySelector('#w-list-error')", 10000, "404 sentence");
  const sentence = await enr.eval("document.querySelector('#w-list-error').textContent");
  check("withdrawing what is already gone says so plainly", sentence.includes("already used, withdrawn or gone"), sentence);

  // The rate limit: issuing again and again spends the burst; the next answer says how long to wait, and the wait counts down.
  let limited = false;
  for (let i = 0; i < 9 && !limited; i++) {
    await enr.eval("document.querySelector('#w-hours').focus()");
    await enr.key("Enter");
    await enr.waitFor("!!document.querySelector('#stepup-code') || !!document.querySelector('[role=dialog] li') || [...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('Too many requests'))", 15000, "an answer");
    await stepUpIfAsked();
    if (await enr.eval("!!document.querySelector('[role=dialog] li')")) await saveAndClose(1);
    else limited = await enr.eval("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('Too many requests'))");
  }
  check("issuing in a burst is told to wait in plain words", limited);
  const label = await enr.eval("[...document.querySelectorAll('form[aria-label=\"Issue a worker enrollment\"] button[type=submit]')].map((b) => b.textContent.trim() + '|' + b.disabled).join()");
  check("a rate-limited issue disables the button and counts down", /Try again in \d+ s\|true/.test(label), label);
  await enr.waitFor("[...document.querySelectorAll('form[aria-label=\"Issue a worker enrollment\"] button[type=submit]')].some((b) => b.textContent.trim() === 'Issue enrollment' && !b.disabled)", 20000, "countdown over");
  check("the wait ends and the button comes back", true);

  // The earlier enrollments are spent or withdrawn: issue one that stays pending for the withdraw check below.
  await enr.eval("document.querySelector('#w-hours').focus()");
  await enr.key("Enter");
  await stepUpIfAsked();
  await enr.waitFor("!!document.querySelector('[role=dialog] li')", 15000, "an enrollment issued after the wait");
  await saveAndClose(1);
  await enr.waitFor("[...document.querySelectorAll('main table tbody tr')].some((r) => r.textContent.includes('pending'))", 10000, "pending row");

  // A pending enrollment withdrawn from the page.
  const pending = async () => (await root("GET", "/api/v1/admin/worker-enrollments")).body.enrollments.filter((e) => e.state === "pending").length;
  const before = await pending();
  check("enrollments are pending to withdraw", before >= 1, before);
  await enr.click('main table button[aria-label^="Withdraw"]');
  for (let i = 0; i < 100 && (await pending()) === before; i++) await sleep(100);
  check("a pending enrollment is withdrawn from the page", (await pending()) === before - 1, { before, after: await pending() });

  // A worker's uninstall is requested from the page, behind a confirmation.
  await enr.waitFor("[...document.querySelectorAll('main table tbody tr')].some((r) => r.textContent.includes('ui-1'))", 10000, "worker listed");
  await enr.click('main table button[aria-label^="Request the uninstall of"]');
  await enr.waitFor("!!document.querySelector('[role=dialog]')", 5000, "confirmation");
  await enr.clickText("[role=dialog] button", "Request uninstall");
  await stepUpIfAsked();
  let hosts = (await root("GET", "/api/v1/admin/workers")).body.workers;
  for (let i = 0; i < 50 && hosts.some((h) => !h.uninstall_requested_ms); i++) {
    await sleep(100);
    hosts = (await root("GET", "/api/v1/admin/workers")).body.workers;
  }
  check("the uninstall is requested on the controller (or has already settled)", hosts.length === 0 || hosts.every((h) => h.uninstall_requested_ms), hosts);

  // The canary: no place the page, the browser or the web process could keep the values holds them.
  const needles = secrets.flatMap((s) => (s.startsWith("sntl_") ? [s.slice(5)] : [s]));
  const where = (name, text) => needles.filter((n) => text.includes(n)).map(() => name);
  const found = [];
  for (const r of requests) found.push(...where(`request ${r.method} ${r.url.slice(0, 80)}`, `${r.url}\n${r.headers}\n${r.post}`));
  const history = await enr.send("Page.getNavigationHistory");
  found.push(...where("navigation history", history.entries.map((e) => e.url).join("\n")));
  found.push(...where("location", await enr.eval("location.href")));
  found.push(...where("web storage", await enr.eval("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage), document.cookie])")));
  const cookies = await enr.send("Network.getAllCookies");
  found.push(...where("cookies", JSON.stringify(cookies.cookies)));
  found.push(...where("indexedDB and caches", await enr.eval("(async () => JSON.stringify([await (indexedDB.databases ? indexedDB.databases() : []), await caches.keys()]))()")));
  found.push(...where("console", enr.console.join("\n")));
  found.push(...where("script errors", enr.errors.join("\n")));
  found.push(...where("page text", await enr.eval("document.documentElement.outerHTML")));
  for (const path of ["/api/v1/admin/worker-enrollments", `/api/v1/admin/worker-enrollments/${first.id}`, "/api/v1/admin/workers", "/api/v1/admin/worker-bootstrap", "/api/v1/admin/audit?limit=100"]) {
    found.push(...where(`later answer ${path}`, JSON.stringify((await root("GET", path)).body)));
  }
  found.push(...where("the web process log", readFileSync(cfg.web_log, "utf8")));
  check("the secret and the Tailcat address appear in no URL, header, request body, history, storage, cookie, console line, error, later answer or web-process log",
    found.length === 0, found);
  check("the canary had something to look for", needles.length >= 3 && needles.every((n) => n.length >= 30), needles.length);
  const scriptErrors = enr.errors.filter((e) => !e.startsWith("network:"));
  check("the enrollment page raised no script errors", scriptErrors.length === 0, scriptErrors);
  await enr.close();
  current = page;
});

// Keep last: it changes rui's password, which ends every session of that account.
await scenario("account security", async () => {
  const acct = await browser.newPage({ width: 390, height: 844 });
  current = acct;
  await signIn(acct, "rui");
  await go(acct, ...PAGES.account);
  await acct.fill("#enroll-password", cfg.password);
  await acct.key("Enter");
  await acct.waitFor("!!document.querySelector('main svg[role=img] path') && !!document.querySelector('#totp-key')", 10000, "QR code and key");
  check("enrollment shows a QR code and the key", true);
  check("the one-time-code field asks for autofill", await acct.eval("document.querySelector('#totp-confirm').autocomplete === 'one-time-code'"));
  const key = await acct.eval("document.querySelector('#totp-key').textContent");
  const wrong = totp(key) === "000000" ? "111111" : "000000";
  await acct.fill("#totp-confirm", wrong);
  await acct.key("Enter");
  await acct.waitFor("[...document.querySelectorAll('main [role=alert]')].some((a) => a.textContent.includes('not accepted'))", 8000, "wrong code refused");
  check("a wrong confirmation code is refused and said, and the setup stays open", await acct.eval("!!document.querySelector('#totp-key')"));
  await acct.fill("#totp-confirm", totp(key));
  await acct.key("Enter");
  const codesShown = `[...document.querySelectorAll('[role=dialog] li')].length === 10`;
  await acct.waitFor(codesShown, 10000, "recovery codes");
  check("ten recovery codes are shown once, in a dialog", true);
  const first = await acct.eval("document.querySelector('[role=dialog] li').textContent.trim()");
  check("the dialog closes only after the codes are saved",
    await acct.eval(`[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === 'Done').disabled`));
  await acct.click("[role=dialog] [role=checkbox]");
  await acct.clickText("[role=dialog] button", "Done");
  await acct.waitFor("!document.querySelector('[role=dialog]')", 8000, "codes dialog closed");
  check("the codes leave the page once saved", !(await acct.eval(`document.body.textContent.includes(${JSON.stringify(first)})`)));
  await acct.waitFor("document.querySelector('main').textContent.includes('10 of 10 left')", 8000, "enrolled state");
  check("the page shows the authenticator on and the codes left", true);
  const overflow = await acct.eval(OVERFLOW);
  check("the account page fits a phone", overflow.scroll <= overflow.width, overflow);
  await acct.fill("#pw-current", "not the password");
  await acct.fill("#pw-new", "a fresh password for rui");
  await acct.fill("#pw-again", "a fresh password for rui");
  await acct.key("Enter");
  await acct.waitFor("[...document.querySelectorAll('main [role=alert]')].some((a) => a.textContent.includes('current password was not accepted'))", 8000, "wrong current password");
  check("a wrong current password is refused and said, and the session stays", await acct.eval("location.pathname === '/account'"));
  await acct.fill("#pw-current", cfg.password);
  await acct.fill("#pw-new", "a fresh password for rui");
  await acct.fill("#pw-again", "a fresh password for rui");
  // The controller ends the session as it answers, so a page request in flight at that moment is refused with 401 before
  // the answer is read. Hold the answer until such a request has been refused.
  const armed = await acct.eval(`(() => {
    const link = document.querySelector('a[href^="/t/"]');
    if (!link) return false;
    window.__real ??= window.fetch; window.__refused = false;
    window.fetch = async (input, init) => {
      const url = String(input && input.url ? input.url : input);
      const response = await window.__real(input, init);
      if (response.status === 401) window.__refused = true;
      if (url.endsWith("/api/v1/password") && init && init.method === "POST" && response.ok) {
        link.click();
        for (let i = 0; i < 200 && !window.__refused; i++) await new Promise((r) => setTimeout(r, 25));
      }
      return response;
    };
    return true; })()`);
  check("the password change is sent with a page request about to be refused", armed);
  await acct.key("Enter");
  await acct.waitFor("location.pathname === '/login' && document.body.textContent.includes('Password changed')", 15000, "signed out after the change");
  check("a password change signs out and says so", true);
  check("a request refused while the change was answered did not say the session ended",
    !acct.navigations.some((u) => u.includes("reason=expired")) && !(await acct.eval("document.body.textContent.includes('Your session ended')")), acct.navigations.slice(-4));
  await acct.close();
  current = page;
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
