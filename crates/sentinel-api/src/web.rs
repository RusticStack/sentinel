//! The first thin page (W08): a single static document that talks to the
//! same API the CLI uses, with a session cookie. Runs of a repository, a
//! run's jobs, and an attempt's log with follow. No framework, no build
//! step, no request the CLI could not make.

pub const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: light dark; font: 14px/1.4 system-ui, sans-serif; }
  body { margin: 0; padding: 16px; max-width: 1100px; margin-inline: auto; }
  h1 { font-size: 18px; margin: 0 0 12px; }
  form, .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
  input, button { font: inherit; padding: 6px 8px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
  th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #8884; white-space: nowrap; }
  td.state { font-weight: 600; }
  .passed { color: #2a7; } .failed, .infra_failed, .timed_out { color: #d44; } .canceled { color: #a80; }
  .running, .preparing, .finalizing, .leased { color: #37c; }
  pre { background: #1113; padding: 8px; overflow: auto; max-height: 60vh; white-space: pre-wrap; }
  .stderr { color: #d66; }
  .muted { opacity: .7; }
  a { cursor: pointer; text-decoration: underline; }
</style>
</head>
<body>
<h1>Sentinel</h1>
<form id="login">
  <input id="username" placeholder="username" autocomplete="username" required>
  <input id="password" type="password" placeholder="password" autocomplete="current-password" required>
  <button>Sign in</button>
  <span id="who" class="muted"></span>
</form>
<div class="row">
  <input id="tenant" placeholder="tenant slug"> <input id="repo" placeholder="repository">
  <button id="load">Runs</button>
</div>
<table id="runs"><thead><tr><th>run</th><th>state</th><th>sha</th><th>created</th></tr></thead><tbody></tbody></table>
<div class="row"><span id="runtitle" class="muted"></span> <button id="cancelrun" hidden>Cancel run</button></div>
<table id="jobs"><thead><tr><th>job</th><th>state</th><th>class</th><th>attempt</th><th></th></tr></thead><tbody></tbody></table>
<div class="row"><span id="logtitle" class="muted"></span></div>
<pre id="log"></pre>
<script>
const $ = (id) => document.getElementById(id);
let csrf = null, following = null;
const api = async (method, path, body) => {
  const headers = { "accept": "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (csrf && method !== "GET") headers["x-sentinel-csrf"] = csrf;
  const r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(data && data.message ? `${data.code}: ${data.message}` : `${r.status}`);
  return data;
};
const cls = (s) => s.replace(/[^a-z_]/g, "");
$("login").onsubmit = async (e) => {
  e.preventDefault();
  try {
    const me = await api("POST", "/api/v1/login", { username: $("username").value, password: $("password").value });
    csrf = me.csrf; $("who").textContent = `signed in as ${me.user}`; $("password").value = "";
  } catch (err) { $("who").textContent = err.message; }
};
$("load").onclick = async () => {
  try {
    const runs = await api("GET", `/api/v1/tenants/${encodeURIComponent($("tenant").value)}/repos/${encodeURIComponent($("repo").value)}/runs`);
    const body = $("runs").querySelector("tbody"); body.innerHTML = "";
    for (const run of runs.runs) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><a>${run.id}</a></td><td class="state ${cls(run.state)}">${run.state}</td><td>${run.sha.slice(0,12)}</td><td>${new Date(run.created_ms).toLocaleString()}</td>`;
      tr.querySelector("a").onclick = () => showRun(run.id);
      body.appendChild(tr);
    }
  } catch (err) { $("runtitle").textContent = err.message; }
};
async function showRun(id) {
  try {
    const run = await api("GET", `/api/v1/runs/${id}`);
    $("runtitle").textContent = `${run.id} — ${run.state}`;
    $("cancelrun").hidden = run.state === "passed" || run.state === "failed" || run.state === "canceled" || run.state === "timed_out" || run.state === "infra_failed" || run.state === "skipped";
    $("cancelrun").onclick = async () => { await api("POST", `/api/v1/runs/${id}/cancel`, {}); showRun(id); };
    const body = $("jobs").querySelector("tbody"); body.innerHTML = "";
    for (const job of run.jobs) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${job.name}</td><td class="state ${cls(job.state)}">${job.state}</td><td>${job.failure_class || ""}</td><td>${job.attempt ? `<a>${job.attempt}</a>` : ""}</td><td>${job.terminal ? `<a class="rerun">rerun</a>` : `<a class="cancel">cancel</a>`}</td>`;
      const logLink = tr.querySelector("td:nth-child(4) a"); if (logLink) logLink.onclick = () => follow(job.attempt);
      const rerun = tr.querySelector("a.rerun"); if (rerun) rerun.onclick = async () => { await api("POST", `/api/v1/jobs/${job.id}/rerun`, {}); showRun(id); };
      const cancel = tr.querySelector("a.cancel"); if (cancel) cancel.onclick = async () => { await api("POST", `/api/v1/jobs/${job.id}/cancel`, {}); showRun(id); };
      body.appendChild(tr);
    }
  } catch (err) { $("runtitle").textContent = err.message; }
}
async function follow(attempt) {
  following = attempt; $("log").textContent = ""; $("logtitle").textContent = `${attempt} — following`;
  let after = 0;
  while (following === attempt) {
    let page;
    try { page = await api("GET", `/api/v1/attempts/${attempt}/logs?after=${after}&wait=1`); }
    catch (err) { $("logtitle").textContent = err.message; return; }
    for (const f of page.frames) {
      const span = document.createElement("span"); span.className = f.stream; span.textContent = f.text; $("log").appendChild(span); after = f.seq;
    }
    if (page.complete) { $("logtitle").textContent = `${attempt} — complete${page.gaps.length ? " (gaps: " + JSON.stringify(page.gaps) + ")" : ""}`; return; }
  }
}
</script>
</body>
</html>
"#;
