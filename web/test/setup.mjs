// The first-run setup wizard in a real browser, against a controller with no administrator
// (`the_setup_wizard_in_a_real_browser` in web_browser.rs): every step, resuming after a refresh,
// the mail step without mail delivery, finishing, skipping the authenticator, and that no secret
// (the setup token, a password) is ever kept in the tab's storage.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { launch } from "./cdp.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const failures = [];
const check = (name, ok, detail) => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail !== undefined ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  if (!ok) failures.push(name);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASSWORD = "a long setup passphrase for ada";

const browser = await launch();
const page = await browser.newPage({ width: 1280, height: 900 });
const heading = () => page.eval("document.querySelector('main h1') && document.querySelector('main h1').textContent.trim()");
const waitHeading = (text) => page.waitFor(`document.querySelector('main h1') && document.querySelector('main h1').textContent.trim() === ${JSON.stringify(text)}`, 10000, `step ${text}`);
const next = async () => { await page.eval("document.querySelector('main form button[type=submit]').click()"); };
const stored = () => page.eval("(() => { try { return sessionStorage.getItem('sentinel-setup-draft') || ''; } catch (e) { return ''; } })()");
async function noSecretStored(where) {
  const s = await stored();
  check(`${where}: the stored draft holds no token or password`, !s.includes(cfg.token) && !s.includes(PASSWORD), s.slice(0, 200));
}

try {
  await page.goto(cfg.base + "/login");
  await page.waitFor("location.pathname === '/setup' && !!document.querySelector('#setup-token')", 15000, "wizard");
  check("while setup is open, sign-in leads to the wizard", true);
  check("the step list marks the current step", await page.eval("!!document.querySelector('nav[aria-label=\"Setup steps\"] [aria-current=step]')"));

  await page.fill("#setup-token", "0".repeat(10));
  await next();
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('64 characters'))", 5000, "token shape refused");
  check("a malformed token is refused in the page", true);
  await page.fill("#setup-token", cfg.token);
  await next();
  await waitHeading("Administrator");
  check("the administrator step opens with its heading focused", await page.eval("document.activeElement === document.querySelector('main h1')"));
  await page.fill("#admin-email", "ada@example.com");
  await page.fill("#admin-password", PASSWORD);
  await page.fill("#admin-again", PASSWORD);
  check("password fields ask password managers for a new password",
    await page.eval("document.querySelector('#admin-password').autocomplete === 'new-password' && document.querySelector('#admin-again').autocomplete === 'new-password'"));
  await next();
  await waitHeading("Who can join");
  await noSecretStored("after the administrator step");
  await next();
  await waitHeading("Instance");
  check("the address is pre-filled with the page's origin", (await page.eval("document.querySelector('#instance-url').value")) === cfg.base);
  await page.fill("#instance-name", "Acme CI");
  await next();
  await waitHeading("Email");
  await page.waitFor("!!document.querySelector('[aria-label=\"Environment lines for the controller\"]')", 10000, "mail not configured");
  check("without mail delivery the email step shows the controller's two environment lines",
    await page.eval("document.querySelector('[aria-label=\"Environment lines for the controller\"]').textContent.includes('SENTINEL_RESEND_API_KEY_FILE')"));
  await next();
  await waitHeading("Namespaces");
  await noSecretStored("at the namespaces step");

  // A refresh: back to the token step, which says it picks up, then the password, then this step.
  await page.goto(cfg.base + "/setup");
  await page.waitFor("!!document.querySelector('#setup-token') && document.body.textContent.includes('Picking up where you left off')", 10000, "resume notice");
  check("after a refresh the wizard picks up where it left off, asking for the token again", true);
  await page.fill("#setup-token", cfg.token);
  await next();
  await waitHeading("Administrator");
  check("then it asks for the password again", (await page.eval("document.querySelector('#admin-email').value")) === "ada@example.com" && (await page.eval("document.querySelector('#admin-password').value")) === "");
  await page.fill("#admin-password", PASSWORD);
  await page.fill("#admin-again", PASSWORD);
  await next();
  await waitHeading("Namespaces");
  check("and returns to the step the person was on", true);

  await page.fill("#ns-org", "acme");
  await next();
  await waitHeading("Review");
  const review = await page.eval("document.querySelector('main').textContent");
  check("the review shows the answers", review.includes("ada@example.com") && review.includes("Acme CI") && review.includes("acme"), review.slice(0, 300));
  await next();
  await waitHeading("Protect your account");
  check("after finishing, the wizard offers an authenticator", true);
  check("the draft is gone once setup completed", (await stored()) === "");
  await page.clickText("button", "Skip for now");
  await waitHeading("Sentinel is ready");
  check("skipping the authenticator leads to the next steps", true);
  await page.goto(cfg.base + "/setup");
  await page.waitFor("location.pathname !== '/setup'", 10000, "setup closed");
  check("once setup is complete, /setup leads away", true);
  const me = await page.eval("fetch('/api/v1/me', { headers: { accept: 'application/json' } }).then((r) => r.json())");
  check("the administrator is signed in", me && me.super_admin === true, me);
  await page.screenshot(join(cfg.out, "setup-done.png"));
} catch (e) {
  check("setup wizard (no error)", false, e.stack || e.message);
  await page.screenshot(join(cfg.out, "setup-failed.png")).catch(() => {});
}
const errors = page.errors.filter((e) => !e.startsWith("network:"));
check("no script errors or policy violations", errors.length === 0, errors.slice(0, 5));
check("no hydration mismatches", !page.console.some((c) => c.includes("Hydration")));
await browser.close();
console.log(`\n${failures.length ? "FAILED" : "PASSED"}: ${failures.length} failures`);
process.exit(failures.length ? 1 : 0);
