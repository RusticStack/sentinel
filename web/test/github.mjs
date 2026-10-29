// One-click GitHub App setup in a real browser (`the_github_app_setup_in_a_real_browser` in web_browser.rs), against a
// controller whose GitHub is `sentinel_github::fake`: step-up, the manifest posted to the fake's create page on another
// site (`cfg.github_web`, localhost, as github.com is another site than the controller), the confirm click, the return
// to /setup/github/created, a per-namespace install, the request-to-install path, and the refusals a browser can reach
// (another session's state, a replayed state). It also proves the premise that makes the return page need care: the
// session cookie is SameSite=Strict, so a cross-site navigation arrives signed out. Nothing secret may appear in any
// page, storage, cookie or response the browser saw (`cfg.canaries`).
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { launch } from "./cdp.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const WEB = cfg.web, GH = cfg.github_web;
const failures = [];
const check = (name, ok, detail) => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail !== undefined ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  if (!ok) failures.push(name);
};
const leaked = (text) => cfg.canaries.some((c) => text.includes(c));

const browser = await launch();
const page = await browser.newPage({ width: 1280, height: 900 });
page.captureBodies(WEB);
const SIGNED_IN = `!!document.querySelector('[aria-label="Account menu"]')`;
const alertText = (p) => p.eval("[...document.querySelectorAll('[role=alert]')].map((a) => a.textContent.trim()).join(' | ')");
const here = (p) => p.eval("location.href");

async function signIn(p) {
  await p.goto(WEB + "/login");
  await p.waitFor("!!document.querySelector('#username')", 15000, "sign-in form");
  await p.fill("#username", "root");
  await p.fill("#password", cfg.password);
  await p.key("Enter");
  await p.waitFor(SIGNED_IN, 15000, "signed in");
}

// What a page holds that a person or a script could read: its DOM, both storages, its cookies and its address.
async function noSecretInPage(p, where) {
  const text = await p.eval("JSON.stringify({ html: document.documentElement.outerHTML, local: Object.entries(localStorage), session: Object.entries(sessionStorage), cookie: document.cookie, href: location.href })");
  check(`${where}: no secret in the DOM, storage, cookies or address`, !leaked(text));
}

const allBodies = [];
let other = null;
try {
  await signIn(page);
  check("the administrator is signed in", true);

  // The premise: the session cookie is not sent on a navigation another site starts, so a return from GitHub arrives
  // signed out. The same navigation from this origin is signed in.
  await page.goto(GH + "/apps/none/installations/new");
  await page.eval(`location.href = ${JSON.stringify(WEB + "/api/v1/me")}`);
  await page.waitFor(`location.origin === ${JSON.stringify(WEB)}`, 10000, "the cross-site navigation");
  await page.waitFor("document.readyState === 'complete'", 10000);
  const cross = await page.eval("performance.getEntriesByType('navigation')[0].responseStatus");
  check("a navigation from another site carries no session (SameSite=Strict)", cross === 401, cross);
  await page.goto(WEB + "/");
  await page.waitFor(SIGNED_IN, 15000, "still signed in");
  check("and this browser is still signed in on this origin", true);

  // Create.
  await page.goto(WEB + "/setup/github");
  await page.waitFor("document.querySelector('h1') && document.querySelector('h1').textContent === 'GitHub App' && !!document.querySelector('#gh-org')", 15000, "the create form");
  const policy = await page.eval("fetch('/setup/github', { headers: { accept: 'text/html' } }).then((r) => r.headers.get('content-security-policy') || '')");
  check("the page may post its manifest to the GitHub origin, and only that", policy.includes(`form-action 'self' ${GH}`) && !policy.includes("https://github.com"), policy.slice(0, 300));
  check("a controller GitHub cannot reach says so", (await page.eval("document.body.textContent")).includes("GitHub cannot deliver events"));
  await page.fill("#gh-org", cfg.org);
  await page.screenshot(join(cfg.out, "github-1-form.png"));
  await page.clickText("button", "Create on GitHub");
  await page.waitFor("!!document.querySelector('#stepup-code')", 10000, "step-up dialog");
  check("creating the App asks for a second factor", true);
  await page.fill("#stepup-code", cfg.password);
  await page.key("Enter");

  // At the fake GitHub: another site.
  await page.waitFor(`location.origin === ${JSON.stringify(GH)} && !!document.querySelector('#create-app')`, 20000, "GitHub's create page");
  const at = new URL(await here(page));
  const state = at.searchParams.get("state") || "";
  check("the manifest was posted to the organization's page on the other site", at.pathname === `/organizations/${cfg.org}/settings/apps/new` && /^[0-9a-f]{64}$/.test(state), at.pathname);
  check("GitHub's page names the owner and the App", (await page.eval("document.querySelector('#owner').textContent")).includes(cfg.org) && (await page.eval("document.querySelector('#app-name').textContent")).length > 0);
  await page.screenshot(join(cfg.out, "github-2-github-create.png"));

  // Another session cannot spend this session's state, and failing to does not burn it.
  other = await browser.newPage({ width: 1280, height: 900 });
  other.captureBodies(WEB);
  await signIn(other);
  const stepped = await other.eval(`fetch('/api/v1/step-up', { method: 'POST', headers: { 'content-type': 'application/json', 'x-sentinel-csrf': localStorage.getItem('sentinel-csrf') || '' }, body: JSON.stringify({ method: 'password', code: ${JSON.stringify(cfg.password)} }) }).then((r) => r.status)`);
  check("the other session is stepped up, so only the state can refuse it", stepped === 200, stepped);
  await other.goto(`${WEB}/setup/github/created?code=bogus&state=${state}`);
  await other.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('started by another session'))", 10000, "the refusal");
  check("another session's state is refused in words", true, await alertText(other));
  allBodies.push(...(await other.capturedBodies()));
  await other.close();
  other = null;

  // Confirm on GitHub: the browser comes back from another site.
  const afterConfirm = page.navigations.length;
  await page.click("#create-app");
  await page.waitFor(`location.origin === ${JSON.stringify(new URL(WEB).origin)} && [...document.querySelectorAll('[role=status],[role=alert]')].some((a) => /is ready|could not be finished/.test(a.textContent))`, 20000, "the return page");
  const arrivals = page.navigations.slice(afterConfirm).filter((u) => u.startsWith(`${WEB}/setup/github/created?code=manifestcode`));
  const returned = arrivals[0] || "";
  check("the return from the other site never went through the sign-in page", !page.navigations.slice(afterConfirm).some((u) => u.startsWith(`${WEB}/login`)), page.navigations.slice(afterConfirm));
  check("the return page finished the setup", (await page.eval("document.body.textContent")).includes(`${cfg.app.name} is ready`), await alertText(page));
  check("the address bar no longer holds the code or the state", (await page.eval("location.search")) === "", await here(page));
  check("a cross-site arrival was answered once as a same-origin refresh", arrivals.length >= 2, arrivals.length);
  await noSecretInPage(page, "after the App is created");
  await page.screenshot(join(cfg.out, "github-3-created.png"));

  // The same address again: the state is spent.
  await page.goto(returned);
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('could not be finished'))", 10000, "the replay refusal");
  check("replaying the return address is refused in words", !(await page.eval("document.body.textContent")).includes("is ready"), await alertText(page));

  // Install on a namespace.
  await page.goto(WEB + "/setup/github");
  await page.waitFor("!!document.querySelector('#install-h') || document.body.textContent.includes('Install on acme')", 15000, "the install card");
  const body = await page.eval("document.body.textContent");
  check("the page shows the App, made by one-click setup, and a button per administered namespace", body.includes(cfg.app.name) && body.includes("one-click setup") && body.includes("Install on acme") && body.includes("Install on beta"));
  check("the create form is gone once the deployment has its App", !(await page.eval("!!document.querySelector('#gh-org')")));
  await page.clickText("button", "Install on acme");
  await page.waitFor(`location.origin === ${JSON.stringify(GH)} && !!document.querySelector('#install-app')`, 20000, "GitHub's install page");
  const install = new URL(await here(page));
  check("the install button followed the link to the other site (an http test origin)", install.pathname === `/apps/${cfg.app.slug}/installations/new` && /^[0-9a-f]{64}$/.test(install.searchParams.get("state") || ""), install.pathname);
  await page.screenshot(join(cfg.out, "github-4-github-install.png"));
  const afterInstall = page.navigations.length;
  await page.click("#install-app");
  await page.waitFor(`location.origin === ${JSON.stringify(new URL(WEB).origin)} && [...document.querySelectorAll('[role=status],[role=alert]')].some((a) => /Connected|could not be connected/.test(a.textContent))`, 20000, "the install return");
  check("the installation is connected to the namespace it was started from", (await page.eval("document.body.textContent")).includes(`Connected ${cfg.install_account} to acme`), await alertText(page));
  check("the address bar no longer holds the installation or the state", (await page.eval("location.search")) === "", await here(page));
  check("the install return never went through the sign-in page", !page.navigations.slice(afterInstall).some((u) => u.startsWith(`${WEB}/login`)), page.navigations.slice(afterInstall));
  await noSecretInPage(page, "after the installation");
  await page.screenshot(join(cfg.out, "github-5-installed.png"));

  // A member who cannot install asks for it: nothing is connected.
  await page.goto(WEB + "/setup/github");
  await page.waitFor("document.body.textContent.includes('Install on beta')", 15000, "the install card");
  await page.clickText("button", "Install on beta");
  await page.waitFor(`location.origin === ${JSON.stringify(GH)} && !!document.querySelector('#request-install')`, 20000, "GitHub's install page");
  await page.click("#request-install");
  await page.waitFor("[...document.querySelectorAll('[role=status],[role=alert]')].some((a) => /Installation requested|could not be connected/.test(a.textContent))", 20000, "the request return");
  check("a request to install is said to need an owner's approval", (await page.eval("document.body.textContent")).includes("Installation requested"), await alertText(page));

  await page.goto(WEB + "/t/acme/settings");
  await page.waitFor("document.body.textContent.includes('Installed for this namespace') || document.body.textContent.includes('Not installed')", 15000, "acme's settings");
  check("the namespace shows the App installed", (await page.eval("document.body.textContent")).includes("Installed for this namespace"));
  await page.goto(WEB + "/t/beta/settings");
  await page.waitFor("document.body.textContent.includes('Installed for this namespace') || document.body.textContent.includes('Not installed')", 15000, "beta's settings");
  check("the namespace that only requested it shows nothing installed", (await page.eval("document.body.textContent")).includes("Not installed"));
  await noSecretInPage(page, "at the end");

  allBodies.push(...(await page.capturedBodies()));
  writeFileSync(join(cfg.out, "github-bodies.txt"), allBodies.map((b) => `${b.status} ${b.url}\n${b.text}`).join("\n\n"));
  check("some responses were captured to scan", allBodies.length > 10, allBodies.length);
  check("no secret in any page, script or answer the browser received", !allBodies.some((b) => leaked(b.text)), allBodies.filter((b) => leaked(b.text)).map((b) => b.url));
} catch (e) {
  check("GitHub App setup (no error)", false, e.stack || e.message);
  console.log("navigations:", JSON.stringify(page.navigations.slice(-12)));
  console.log("the page showed:", await page.eval("JSON.stringify({ at: location.href.split('?')[0], forms: [...document.forms].map((f) => f.getAttribute('action')), text: document.body.innerText.replace(/\\s+/g, ' ').slice(0, 300) })").catch(() => "(unreadable)"));
  await page.screenshot(join(cfg.out, "github-failed.png")).catch(() => {});
}
const errors = [...page.errors, ...(other ? other.errors : [])].filter((e) => !e.startsWith("network:"));
check("no script errors or policy violations", errors.length === 0, errors.slice(0, 5));
check("no hydration mismatches", !page.console.some((c) => c.includes("Hydration")));
await browser.close();
console.log(`\n${failures.length ? "FAILED" : "PASSED"}: ${failures.length} failures`);
process.exit(failures.length ? 1 : 0);
