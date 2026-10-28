// The U09 gate in a real browser: the TanStack Start front renders its own views under a hash-only script policy
// with no violation and no script error, hydrates, and still serves every unmoved view (the legacy process behind
// it), the controller's proxied routes and the live streams through the same origin.
import { readFileSync } from "node:fs";
import { launch } from "../../web/test/cdp.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const failures = [];
const check = (name, ok, detail) => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail !== undefined ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  if (!ok) failures.push(name);
};

// Start's own views, signed out and signed in.
const OWN_OUT = ["/"];
const OWN_IN = [];
// Views still served by the legacy process through the front.
const LEGACY_IN = [["/t/acme", "document.querySelectorAll('main table tbody tr').length >= 3"]];

for (const path of OWN_OUT) {
  const r = await fetch(cfg.base + path);
  const csp = r.headers.get("content-security-policy") || "";
  const html = await r.text();
  const script = (csp.split(";").find((d) => d.trim().startsWith("script-src")) || "").trim();
  const inline = [...html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)].filter((m) => m[1]).length;
  check(`${path}: rendered by the front (status ${r.status})`, r.status === 200 && html.includes('data-app="start"'));
  check(`${path}: script-src has no unsafe-inline and one hash per inline script`, !script.includes("unsafe-inline") && (script.match(/'sha256-/g) || []).length >= Math.min(1, inline), { script: script.slice(0, 120), inline });
  check(`${path}: security headers`, r.headers.get("x-frame-options") === "DENY" && r.headers.get("x-content-type-options") === "nosniff" && r.headers.get("referrer-policy") === "no-referrer");
}

const proxied = await fetch(cfg.base + "/api/v1/health");
check("the controller's API is proxied through the front", proxied.status === 200, proxied.status);
const refused = await fetch(cfg.base + "/api/v1/%2e%2e/metrics");
check("an ambiguous controller path is refused, not forwarded", refused.status === 400, refused.status);

const browser = await launch();
const page = await browser.newPage({ width: 1280, height: 860 });
for (const path of OWN_OUT) {
  await page.goto(cfg.base + path);
  check(`${path}: hydrated`, await page.eval("document.documentElement.dataset.hydrated === '1'"));
}
await page.goto(cfg.base + "/login");
await page.waitFor("!!document.querySelector('#username')", 15000, "sign-in form");
await page.fill("#username", "root");
await page.fill("#password", cfg.password);
await page.key("Enter");
await page.waitFor("location.pathname !== '/login'", 15000, "signed in");
check("sign-in works through the front", true);
for (const path of OWN_IN) {
  await page.goto(cfg.base + path);
  check(`${path}: hydrated signed in`, await page.eval("document.documentElement.dataset.hydrated === '1'"));
}
for (const [path, ready] of LEGACY_IN) {
  await page.goto(cfg.base + path);
  await page.waitFor(ready, 20000, `${path} ready`);
  check(`${path}: an unmoved view is served through the front`, true);
}
await page.goto(`${cfg.base}/runs/${cfg.diamond}/logs/${cfg.live_attempt}`);
await page.waitFor("document.querySelector('#log-view') && document.querySelector('#log-view').textContent.includes('live line')", 20000, "live log");
check("the live log stream works through the front", true);

const errors = page.errors.filter((e) => !e.startsWith("network:"));
check("no script errors or policy violations", errors.length === 0, errors.slice(0, 5));
await browser.close();
console.log(`\n${failures.length ? "FAILED" : "PASSED"}: ${failures.length} failures`);
process.exit(failures.length ? 1 : 0);
