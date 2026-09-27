// A minimal Chrome DevTools Protocol driver for the web interface's browser
// tests and benchmarks: Node's built-in WebSocket, no packages. Launches a
// Chromium-family browser (Edge, Chrome, Chromium) headless with a throwaway
// profile, and drives pages over one browser connection.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CANDIDATES = [
  process.env.SENTINEL_BROWSER,
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/microsoft-edge",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

export function findBrowser() {
  return CANDIDATES.find((p) => p && existsSync(p)) || null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launch({ browser = findBrowser(), headless = true } = {}) {
  if (!browser) throw new Error("no Chromium-family browser found; set SENTINEL_BROWSER");
  const profile = mkdtempSync(join(tmpdir(), "sentinel-cdp-"));
  const args = [
    headless ? "--headless=new" : null,
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "--no-first-run", "--no-default-browser-check", "--disable-extensions",
    "--disable-background-networking", "--disable-component-update", "--disable-sync",
    "--enable-precise-memory-info", "--js-flags=--expose-gc",
    "about:blank",
  ].filter(Boolean);
  const child = spawn(browser, args, { stdio: "ignore" });
  const portFile = join(profile, "DevToolsActivePort");
  for (let i = 0; i < 200 && !existsSync(portFile); i++) await sleep(50);
  let text = "";
  for (let i = 0; i < 100; i++) { text = existsSync(portFile) ? readFileSync(portFile, "utf8") : ""; if (text.includes("\n")) break; await sleep(50); }
  const [port, path] = text.trim().split("\n");
  if (!port) throw new Error("browser did not open a debugging port");
  const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (!p) return;
      if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`)); else p.resolve(msg.result);
    } else {
      for (const fn of listeners.get(msg.method) || []) fn(msg.params, msg.sessionId);
    }
  };
  const cdp = {
    send(method, params = {}, sessionId) {
      const msgId = ++id;
      ws.send(JSON.stringify({ id: msgId, method, params, sessionId }));
      return new Promise((resolve, reject) => pending.set(msgId, { resolve, reject, method }));
    },
    on(method, fn) { (listeners.get(method) || listeners.set(method, []).get(method)).push(fn); },
    async newPage({ width = 1280, height = 800 } = {}) {
      const { browserContextId } = await cdp.send("Target.createBrowserContext");
      const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank", browserContextId });
      const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
      const page = new Page(cdp, sessionId, targetId, browserContextId);
      await page.init(width, height);
      return page;
    },
    async close() {
      try { await cdp.send("Browser.close"); } catch (e) { /* gone */ }
      ws.close();
      await sleep(300);
      try { child.kill(); } catch (e) { /* gone */ }
      for (let i = 0; i < 10; i++) { try { rmSync(profile, { recursive: true, force: true }); break; } catch (e) { await sleep(200); } }
    },
  };
  return cdp;
}

export class Page {
  constructor(cdp, sessionId, targetId, contextId) {
    this.cdp = cdp; this.sessionId = sessionId; this.targetId = targetId; this.contextId = contextId;
    this.errors = [];
    this.console = [];
  }
  send(method, params) { return this.cdp.send(method, params, this.sessionId); }
  async init(width, height) {
    await this.send("Page.enable");
    await this.send("Runtime.enable");
    await this.send("Network.enable");
    await this.send("Performance.enable");
    await this.viewport(width, height);
    this.cdp.on("Runtime.exceptionThrown", (p, s) => { if (s === this.sessionId) this.errors.push(p.exceptionDetails.exception?.description || p.exceptionDetails.text); });
    this.cdp.on("Runtime.consoleAPICalled", (p, s) => { if (s === this.sessionId) this.console.push(`${p.type}: ${p.args.map((a) => a.value ?? a.description).join(" ")}`); });
    this.cdp.on("Log.entryAdded", (p, s) => { if (s === this.sessionId && p.entry.level === "error") this.errors.push(`${p.entry.source}: ${p.entry.text}`); });
    await this.send("Log.enable");
  }
  async viewport(width, height) {
    this.width = width; this.height = height;
    await this.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
  }
  async scheme(dark) {
    await this.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }] });
  }
  async goto(url) {
    await this.send("Page.navigate", { url });
    await this.waitFor("document.readyState === 'complete'", 15000);
  }
  /// Evaluate an expression (awaiting a promise) and return its value.
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}\n${expression}`);
    return r.result.value;
  }
  async waitFor(expression, timeout = 10000, what) {
    const end = Date.now() + timeout;
    let last;
    while (Date.now() < end) {
      try { last = await this.eval(expression); if (last) return last; } catch (e) { last = e.message; }
      await sleep(50);
    }
    throw new Error(`timed out waiting for ${what || expression} (last: ${JSON.stringify(last)})`);
  }
  async key(key, modifiers = 0) {
    const codes = { Tab: 9, Enter: 13, Escape: 27, End: 35, Home: 36, ArrowUp: 38, ArrowDown: 40, PageDown: 34, PageUp: 33, " ": 32 };
    const code = codes[key] || key.charCodeAt(0);
    const base = { key, code: key, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code, modifiers };
    await this.send("Input.dispatchKeyEvent", { type: "keyDown", ...base, text: key === "Enter" ? "\r" : key.length === 1 ? key : undefined });
    await this.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  }
  async type(text) { await this.send("Input.insertText", { text }); }
  /// Click an element's centre with the mouse, as a person would.
  async click(selector) {
    const box = await this.eval(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null; el.scrollIntoView({block: "center"}); const r = el.getBoundingClientRect(); return {x: r.x + r.width / 2, y: r.y + r.height / 2}; })()`);
    if (!box) throw new Error(`no element ${selector}`);
    for (const type of ["mousePressed", "mouseReleased"]) await this.send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: "left", clickCount: 1 });
  }
  /// Click, with the mouse, the first `selector` element whose text
  /// includes `text` (menus and listboxes act on pointer events).
  async clickText(selector, text) {
    const box = await this.eval(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().includes(${JSON.stringify(text)}));
      if (!el) return null; el.scrollIntoView({block: "center"}); const r = el.getBoundingClientRect(); return {x: r.x + r.width / 2, y: r.y + r.height / 2}; })()`);
    if (!box) throw new Error(`no ${selector} with ${text}`);
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) await this.send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: "left", clickCount: 1 });
  }
  async fill(selector, text) {
    await this.eval(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.focus(); el.value = ""; })()`);
    await this.type(text);
  }
  async screenshot(path) {
    const { data } = await this.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(path, Buffer.from(data, "base64"));
  }
  async metrics() {
    const { metrics } = await this.send("Performance.getMetrics");
    return Object.fromEntries(metrics.map((m) => [m.name, m.value]));
  }
  async gc() { await this.send("HeapProfiler.collectGarbage"); }
  async offline(off) {
    await this.send("Network.emulateNetworkConditions", { offline: off, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  }
  async latency(ms) {
    await this.send("Network.emulateNetworkConditions", { offline: false, latency: ms, downloadThroughput: -1, uploadThroughput: -1 });
  }
  async axTree() { return (await this.send("Accessibility.getFullAXTree")).nodes; }
  async close() { await this.cdp.send("Target.closeTarget", { targetId: this.targetId }); }
}
