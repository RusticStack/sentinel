// The guided migration wizard in a real browser, against a seeded controller and a recorded GitHub
// fake (`the_migration_wizard_in_a_real_browser` in web_browser.rs). Three legs, one page:
//
// 1. runner mode, end to end — connect, pick, analyse, preview the exact diff, open the pull
//    request, the shadow and its parity, the switch and the rollback — after a repository whose only
//    job stays on GitHub's runners was refused at the pull request step;
// 2. the native path with the tenant's opt-in off: the required-check change is shown as a person's
//    own action, and the check after it reports that GitHub still states the old set;
// 3. the native path with the opt-in on: the same change is applied, read back equal, and rolled
//    back to the pre-switch document.
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
const text = () => "document.querySelector('main').innerText";
const at = (step) => `document.querySelector('#step-h') && document.querySelector('#step-h').textContent.trim() === ${JSON.stringify(step)}`;
const shows = (words) => `document.querySelector('main').innerText.includes(${JSON.stringify(words)})`;
const STEPS = "nav[aria-label=\"Migration steps\"] button";
/// The verdict cell the switch's read-back table states.
const verdict = (word) => `[...document.querySelectorAll('main table td')].some((c) => c.textContent.trim() === ${JSON.stringify(word)})`;

const browser = await launch();
const page = await browser.newPage({ width: 1280, height: 900 });
const measured = {};

/// The step's own Continue button, which is the only way forward: a step that has not been
/// answered does not offer one.
async function forward(heading) {
  await page.waitFor("[...document.querySelectorAll('button')].some((b) => b.textContent.includes('Continue') && !b.disabled)", 20000, "an answered step's Continue");
  await page.clickText("button", "Continue");
  await page.waitFor(at(heading), 10000, heading);
}
async function step(name) {
  await page.clickText(STEPS, name);
  await page.waitFor(at(name), 10000, name);
}

try {
  await page.goto(cfg.web + "/login");
  await page.waitFor("!!document.querySelector('#username')", 15000, "sign-in form");
  await page.fill("#username", "root");
  await page.fill("#password", cfg.password);
  await page.key("Enter");
  await page.waitFor("!!document.querySelector('[aria-label=\"Account menu\"]')", 15000, "signed in");

  await page.goto(cfg.web + "/t/" + cfg.slug);
  await page.waitFor("!!document.querySelector('nav[aria-label=Tenant]')", 15000, "tenant navigation");
  await page.clickText("nav[aria-label=Tenant] a", "Migration");
  await page.waitFor(`location.pathname === '/t/${cfg.slug}/migration' && ${at("Connect")}`, 20000, "the wizard");
  check("the tenant's navigation opens the wizard on its first step", true);
  check("the step list marks the step being worked on", await page.eval(`!!document.querySelector('nav[aria-label="Migration steps"] [aria-current=step]')`));
  check("connect reads the switch and the App's permissions from the controller",
    (await page.eval("document.querySelector('#connect-missing').textContent")) === "nothing");
  check("the required-check opt-in is off until a person turns it on", await page.eval("!document.querySelector('#connect-optin-box').checked"));

  await page.clickText("button", "Start the migration");
  await page.waitFor("document.querySelector('#connect-state') && document.querySelector('#connect-state').textContent.trim() === 'on'", 20000, "the migration is on");
  check("starting the migration is the controller's answer, not the page's", true);
  await page.clickText("button", "Continue");
  await page.waitFor(at("Repositories"), 10000, "repositories");
  check("the next step's heading takes focus", await page.waitFor("document.activeElement === document.querySelector('#step-h')", 5000, "focus").then(() => true, () => false));

  // --- one step the controller refuses: a repository whose only job stays on GitHub's runners has
  // nothing for a migration to commit, and the pull request route says so. ---
  await page.click("#repo-mac-only");
  await page.clickText("button", "Continue");
  await page.waitFor(at("Analysis"), 10000, "analysis");
  check("the native path is an option inside the same flow, beside runner mode",
    await page.eval("!!document.querySelector('#mode-runner') && !!document.querySelector('#mode-native')"));
  await page.clickText("button", "Analyse the workflows");
  await page.waitFor("!!document.querySelector('#analysis-findings')", 20000, "the analysis's findings");
  check("the analysis names the commit it read", (await page.eval("document.querySelector('#analysed-commit').textContent")) === cfg.commit);
  const macOnly = await page.eval(text());
  check("a job that stays on GitHub's runners is said with its reason", macOnly.includes("stays") && macOnly.includes("macOS"), macOnly.slice(-400));
  await forward("Preview");
  check("a workflow with nothing to move previews no diff", (await page.eval(text())).includes("No `runs-on:` line changes in this workflow."));
  await forward("Pull request");
  await page.clickText("button", "Open the pull request");
  await page.waitFor("[...document.querySelectorAll('[role=alert]')].some((a) => a.textContent.includes('no runs-on: line changes'))", 20000, "the refusal");
  const refused = await page.eval("[...document.querySelectorAll('[role=alert]')].map((a) => a.textContent).join(' ')");
  check("a refusal is the controller's own words", refused.includes("no workflow's runs-on changes at this commit"), refused);
  check("a refused step does not advance and claims nothing",
    await page.eval(`location.pathname === '/t/${cfg.slug}/migration' && ${at("Pull request")} && [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Continue to the shadow').disabled`));

  // --- leg 1: runner mode, end to end, on the repository this flow migrates. ---
  await step("Repositories");
  await page.click("#repo-widget");
  await page.clickText("button", "Continue");
  await page.waitFor(at("Analysis"), 10000, "analysis again");
  await page.clickText("button", "Analyse the workflows");
  await page.waitFor("!!document.querySelector('#analysis-findings')", 20000, "the analysis's findings");
  const analysis = await page.eval(text());
  check("the analysis says which jobs move and which stay", analysis.includes("moves") && analysis.includes("stays") && analysis.includes("ubuntu-latest"), analysis.slice(-500));
  await forward("Preview");
  const diff = await page.eval("document.querySelector('[aria-label=\"The runs-on: diff of .github/workflows/ci.yml\"]').textContent");
  check("the preview shows the exact runs-on: diff", /^-\s+runs-on: ubuntu-latest$/m.test(diff) && /^\+\s+runs-on: sentinel-/m.test(diff), diff);
  check("the preview names the job it keeps and why", (await page.eval(text())).includes("Stays on GitHub's runners: mac"));
  await forward("Pull request");
  await page.clickText("button", "Open the pull request");
  await page.waitFor(shows("Pull request #"), 20000, "the pull request");
  const opened = await page.eval(text());
  check("the pull request is opened against the default branch, and re-running updates it",
    /Pull request #\d+ \S+ → main, opened/.test(opened) && opened.includes("Update the pull request"), opened.slice(-400));
  await page.clickText("button", "Continue to the shadow");
  await page.waitFor(at("Shadow parity"), 10000, "shadow");
  await page.clickText("button", "Open the shadow pull request");
  await page.waitFor(shows("sentinel / build"), 20000, "the shadow copies");
  check("the shadow pull request adds a non-required copy of each migrating job", true);
  measured.elapsed = parseFloat(await page.eval("document.querySelector('#migration-elapsed').textContent"));
  check("the wizard measures the time from connect to the shadow step", measured.elapsed > 0 && measured.elapsed < 600, measured.elapsed);
  await page.clickText("button", "Read parity");
  await page.waitFor("[...document.querySelectorAll('main table tbody tr')].some((r) => r.textContent.includes('no_original'))", 20000, "parity");
  const parity = await page.eval(text());
  check("parity says what was compared and never claims a match it did not compare",
    parity.includes("no_original") && parity.includes("a pair is a match only when both sides were compared"), parity.slice(-500));
  await page.clickText("button", "Continue to the switch");
  await page.waitFor(at("Switch"), 10000, "switch");
  check("the switch step states the required-check change the preview stated", (await page.eval(text())).includes("No required check changes"));
  await page.clickText("button", "Switch this repository over");
  await page.waitFor(verdict("equal"), 20000, "the protection read back");
  const switched = await page.eval(text());
  check("the switch shows the protection read back and the verdict", switched.includes("equal"), switched.slice(-500));
  check("the merge gate is unchanged: both required checks are still required", switched.includes("build") && switched.includes("mac"));
  await page.clickText("button", "Continue to the rollback");
  await page.waitFor(at("Rollback"), 10000, "rollback");
  await page.clickText("button", "Roll this back");
  await page.waitFor(shows("What the rollback restores"), 20000, "the rollback");
  const rolled = await page.eval(text());
  check("the rollback restores the pre-switch workflows in one action", /What the rollback restores[\s\S]*\.github\/workflows\/ci\.yml[\s\S]*build/.test(rolled), rolled.slice(-400));
  await page.screenshot(join(cfg.out, "migration-runner.png"));

  // --- the native path, twice: the tenant's opt-in off, then on. ---
  async function nativeLeg(optIn) {
    await step("Connect");
    if ((await page.eval("document.querySelector('#connect-optin-box').checked")) !== optIn) await page.click("#connect-optin-box");
    await page.clickText("button", "Save the opt-in");
    await page.waitFor(`document.querySelector('#connect-optin').textContent === ${JSON.stringify(optIn ? "opted in" : "not opted in")}`, 10000, "the opt-in as saved");
    await page.clickText("button", "Continue");
    await page.waitFor(at("Repositories"), 10000, "repositories");
    await page.click("#repo-widget");
    await page.clickText("button", "Continue");
    await page.waitFor(at("Analysis"), 10000, "analysis");
    await page.click("#mode-native");
    await page.fill("#image-linux", cfg.image);
    await page.clickText("button", "Analyse the workflows");
    await page.waitFor("!!document.querySelector('#analysis-findings')", 20000, "the native analysis");
    await forward("Preview");
    await page.waitFor("!!document.querySelector('[aria-label^=\"The generated pipeline\"]')", 20000, "the generated pipeline");
    const native = await page.eval("document.querySelector('[aria-label^=\"The generated pipeline\"]').textContent");
    check(`native, opt-in ${optIn ? "on" : "off"}: the preview shows the generated pipeline`, native.includes("jobs:") && native.includes(cfg.image), native.slice(0, 200));
    await forward("Pull request");
    check("the native path opens no label pull request and says why",
      (await page.eval(text())).includes("The native path opens no label pull request"));
    await page.clickText("button", "Continue to the shadow");
    await page.waitFor(at("Shadow parity"), 10000, "shadow");
    await page.clickText("button", "Read the required-check change");
    await page.waitFor(shows("sentinel / build"), 20000, "the required-check change");
    const change = await page.eval(text());
    check(`native, opt-in ${optIn ? "on" : "off"}: the shadow step states the required-check change`, change.includes("replaced") && change.includes("build"), change.slice(-600));
    await page.clickText("button", "Continue to the switch");
    await page.waitFor(at("Switch"), 10000, "switch");
    if (optIn) {
      check("native, opt-in on: Sentinel's own change is offered", (await page.eval(text())).includes("Apply the change and disable the replaced jobs"));
      await page.clickText("button", "Apply the change and disable the replaced jobs");
      await page.waitFor(verdict("equal"), 20000, "the settings read back");
      const applied = await page.eval(text());
      check("native, opt-in on: the set read back is the set the change stated",
        applied.includes("sentinel / build") && applied.includes("equal"), applied.slice(-600));
      await page.clickText("button", "Continue to the rollback");
      await page.waitFor(at("Rollback"), 10000, "rollback");
      await page.clickText("button", "Roll this back");
      await page.waitFor(shows("What the rollback restores"), 20000, "the rollback");
      const back = await page.eval(text());
      check("native, opt-in on: the rollback puts the pre-switch required checks back and GitHub reads them back",
        back.includes("applied") && back.includes("GitHub reads it back exactly"), back.slice(-700));
      await page.screenshot(join(cfg.out, "migration-native.png"));
    } else {
      check("native, opt-in off: the change is shown as a person's own action",
        (await page.eval(text())).includes("This is a person's action, not Sentinel's"));
      await page.clickText("button", "Check the change I made");
      await page.waitFor(verdict("moved"), 20000, "the settings read back");
      const unchanged = await page.eval(text());
      check("native, opt-in off: the check reports the set GitHub still states, never a switch it did not see",
        unchanged.includes("moved") && unchanged.includes("not the set the change stated"), unchanged.slice(-600));
    }
  }
  await nativeLeg(false);
  await nativeLeg(true);
} catch (e) {
  check("the migration wizard (no error)", false, e.stack || e.message);
  await page.screenshot(join(cfg.out, "migration-failed.png")).catch(() => {});
}
const errors = page.errors.filter((e) => !e.startsWith("network:"));
check("no script errors or policy violations", errors.length === 0, errors.slice(0, 5));
check("no hydration mismatches", !page.console.some((c) => c.includes("Hydration")));
await browser.close();
if (measured.elapsed !== undefined) console.log(`MEASURED connect to the shadow step: ${measured.elapsed.toFixed(1)} s`);
console.log(`\n${failures.length ? "FAILED" : "PASSED"}: ${failures.length} failures`);
process.exit(failures.length ? 1 : 0);
