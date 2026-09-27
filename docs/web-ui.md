# Web interface (Part 12)

The human web interface is its own process, `sentinel-web`: a Nuxt 4 server (Vue 3, TypeScript, Nuxt UI) in [`web/`](../web). It renders every page on the server as the signed-in person, streams live run and log updates to the browser, and proxies the controller's own routes so the browser sees one origin. The controller remains the only authority: `sentinel-web` holds no credential, stores nothing and forwards each browser's own session cookie; every read and every action is authorized by the controller's API exactly as for the CLI and MCP ([API](api.md)).

Running a Node process beside the controller is a deliberate change of the original plan (which allowed build-time UI tooling only), decided by the project owner on 2026-09-27 for a richer, more maintainable interface; see [plan](../plan.md#new-human-ui). It is optional: the controller, CLI and MCP work without it.

## Architecture

```
browser ──https──▶ reverse proxy ──▶ sentinel-web (Node, :3000) ──▶ sentinel server api_listen (:7080)
                                     ├─ pages: server-rendered Vue, then hydrated
                                     ├─ /_stream/run/<id>, /_stream/log/<attempt>: server-sent events
                                     └─ /api/v1/**, /oauth/**, /auth/github/**, /.well-known/**, /device, /mcp: proxied unchanged
```

- **One origin.** `server/middleware/proxy.ts` passes the controller's routes through with their cookies, redirects and bodies (streamed), adding `X-Forwarded-For`; the controller counts unauthenticated budgets per client and trusts that header from loopback only ([configuration](configuration.md)). The controller's `public_url` is the origin browsers use — the web interface's — because sign-in checks `Origin` against it, and GitHub check links (`{public_url}/runs/<id>`) point at it.
- **Server rendering.** The first request for a page runs on the server with the browser's cookie (`useRequestFetch`): a signed-out visitor is sent to `/login?next=…` before anything is drawn, and a signed-in one receives the page with its data. The browser then hydrates and navigates client-side. The server and the first browser render are identical (the browser test asserts no hydration mismatch): times render as UTC clock time until mounted, and a page's render clock travels in its payload.
- **Live updates.** A page that shows something still changing opens one `EventSource` to `sentinel-web`, which holds the controller's long poll on the browser's behalf and pushes each change:
  - `/_stream/run/<run>`: `run` (the whole run document, on every version change), `status` (`live`, `busy`, `reconnecting`), `refused` (the controller's error — the session ended or access was removed; the page says so and the tenant list is re-read), `finished`.
  - `/_stream/log/<attempt>?step&after`: `frames` (a page of frames, with `id: step:seq`), `step_done`, `complete` (with the log's gaps), `status`, `refused`. The browser reconnects by itself with `Last-Event-ID`, and the server resumes after exactly that frame: a dropped connection never repeats or loses a line.
  - A controller that is busy (`rate_limited`) or unreachable is retried with capped exponential back-off and jitter, and the page shows "Updates paused" or "Reconnecting", never an error.
- **Controller side.** A parked long poll gives its handler permit back while it waits (waiting is not work), re-authorizes whenever the tenant's authorization epoch moves (a removed member's open page is refused within a quarter second), and ends as soon as its client hangs up, returning its slot. So live views are bounded by the subscriber budget (`sentinel_api::SUBSCRIBERS`, 32 parked at once, 8 per user), not by the 8 handler permits, and clicking between live pages never exhausts a person's share ([API](api.md#live-updates-and-long-polls)).

## Views

| Path | Shows | Controller routes |
|---|---|---|
| `/login` | password sign-in, and "Sign in with GitHub" when configured (`/api/v1/health` says) | `POST /login`, `/auth/github/start` |
| `/t/<tenant>` | a repository's runs, newest first, filtered by ref (a bare branch means `refs/heads/…`), pull request or commit prefix (7+ hex digits), keyset pages; the first page refreshes every 10 s | `GET /tenants/{slug}/repos`, `GET …/runs?ref|pr|sha&before` |
| `/runs/<id>` | the run's state and provenance, its job graph (levels by dependency depth, each node linked to its log), each job's phases (waiting, preparing, running, finalizing) as a scaled bar with the numbers, cancel and rerun, why each failed job failed (failed step, diagnostics with evidence links, output tail), cache outcomes with backend and sizes, artifacts with their files and downloads; live | `GET /runs/{id}`, `/pipeline`, `/artifacts`, `/attempts/{a}/failure`, `/summary`, the run stream |
| `/runs/<id>/logs/<attempt>` | the log viewer (below), the attempt's measured phases, step outcomes and durations | `/attempts/{a}/logs`, `/logs/search`, `/steps`, the log stream |
| `/t/<tenant>/queue` | waiting jobs, oldest first, with the scheduler's reason and missing quantities; refreshes every 5 s | `GET /queue` |
| `/t/<tenant>/workers` | pools the tenant may use; each worker's capacity, held attempts and reservations (totals — a shared worker's other tenants stay private), what is free on its host, labels, warm cache, transport; drain/undrain for platform administrators; refreshes every 5 s | `GET /workers`, `POST /workers/{id}/drain|undrain` |
| `/t/<tenant>/sync` | GitHub check publications waiting, the oldest one's age (marked past a minute), refusals in 24 h, last publication, deliveries not yet resolved into runs; refreshes every 10 s | `GET /tenants/{slug}/sync` |
| `/t/<tenant>/admin/{members,repos,secrets,audit}` | members and roles (add by sign-in name or id; the last administrator keeps the role), repositories (create; source binding metadata; member access), secret metadata (names, versions, state, bindings; delete with the version check — values are never shown or requested), run control audit | `/tenants/{slug}/members`, `/repos`, `/repos/{name}/source|grants`, `/secrets`, `/secret-bindings`, `/audit` |
| `/platform/{registrations,tenants,pools,policy,audit}` | pending registrations (approve, reject), every tenant with members, storage use and quota (set, reset), suspend and reactivate, create an organization; pools with owners, grants and workers (create, grant, revoke); admission policy; the authentication and administration audit | `/admin/*` |

Actions go through one helper (`useAct`): a toast for the outcome; on `forbidden` with `details.step_up` a "Confirm it's you" dialog (TOTP, a recovery code, or the password for an account without TOTP; `POST /step-up`), then one retry; on `not_found`/`forbidden` a re-read of the caller's tenants, so the navigation follows a role or membership change made while the page was open. Confirmations guard removals, suspensions and deletions.

## The log viewer

`app/utils/logviewer.ts` is plain DOM, deliberately outside Vue's reactivity: up to a quarter-million held lines, their typed per-line columns (sequence, stream, line number — no object per line), the memory bound and the stream state are ordinary data, never proxied.

- **Steps fold.** Each step is a section loaded on demand through `?step=` pages; passed, skipped and not-run steps start folded, failed and unfinished ones open. The step list and each section header toggle with `aria-expanded`.
- **Windowed rendering.** A fixed-height viewport over a spacer as tall as every row; only the rows in view plus 12 above and below exist, pooled and reused — a row that scrolls in only changes its text, link and class. Arrow keys, Page Up/Down, Home and End scroll; `End` follows.
- **Bounded memory.** At most 250,000 lines and 48 M characters are held; past that the oldest lines of the largest step are released in blocks of 25,000, the view stays on the lines being read, and the step's first row says how many were released, with "load earlier" to fetch them again. A line longer than 4,096 characters is shown cut, with the rest counted.
- **Nothing hidden.** A gap the store declared is a marker line where it falls ("frame N was never stored"); a completed log with gaps says so; ANSI colour codes are dropped.
- **Search** is the controller's indexed literal search (`/logs/search`, 4 MiB of log a request), continued until something is found; each hit jumps to its exact line, highlighted, with the term marked.
- **Deep links.** Every line number links to `…/logs/<attempt>?step=S&seq=N` (and `&q=` from a search); opening one loads a window around the frame and highlights the line.
- **Live.** A running attempt is followed through the log stream, step by step, and resumes exactly after a lost connection.

## Security

- The browser holds only the controller's `__Host-sentinel_session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`) and the session's CSRF secret, kept in `localStorage` (handed over by the login response or the GitHub finish page) and sent as `x-sentinel-csrf` on mutations; server-side rendering only reads.
- `sentinel-web` validates identifiers before they go into an upstream URL, forwards the caller's credentials unchanged and never logs them; it has no credential of its own, so it can do nothing the browser's session cannot.
- Pages carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; build assets are content-named and served `immutable`, gzip or brotli precompressed.
- The OAuth consent and device pages and GitHub sign-in stay the controller's own server-rendered pages, under their strict policy, reached through the proxy.

## Running it

Build once per release (Node 22+ and pnpm, at build time and run time):

```sh
pnpm -C web install --frozen-lockfile
pnpm -C web build            # writes web/.output (server + public assets)
```

Run it next to `sentinel server`, on loopback behind the reverse proxy:

```sh
NUXT_SENTINEL_API=http://127.0.0.1:7080 HOST=127.0.0.1 PORT=3000 node web/.output/server/index.mjs
```

| Setting | Meaning |
|---|---|
| `NUXT_SENTINEL_API` | the controller's `api_listen`, reached from this process (default `http://127.0.0.1:7080`) |
| `HOST`, `PORT` | where `sentinel-web` listens (default `0.0.0.0:3000`; bind loopback behind a proxy) |

The reverse proxy terminates TLS and sends everything for the public origin to `sentinel-web`; the controller's `public_url` is that origin ([configuration](configuration.md)). [`examples/sentinel-web.service`](../examples/sentinel-web.service) is a systemd unit.

**Resources**, measured on the development host (i7-13700KF, Windows 11, Node 24; release build, loopback): idle 61.5 MiB working set (29.7 MiB private); after rendering every view once 93.7 MiB; ten live log streams held for 30 s added 12 MiB and cost 1.2 s of CPU (about 4 % of one core). A first uncached visit to a run list downloads 356 KB compressed in 40 requests (1.3 MB decoded), DOM ready at 103 ms; later visits reuse the immutable assets.

## Stack choice (U01)

`web/bench/log-view.mjs` renders the same 200,000-line log (127-character lines in 32 KiB frames) four ways in a real browser, three fresh pages each, and records medians in [`bench/u01-log-view.jsonl`](../bench/u01-log-view.jsonl) (Edge 154, i7-13700KF, 2026-09-27):

| Candidate | Shipped JS (gzip) | Ingest + first paint | Elements | Work per scroll jump |
|---|---|---|---|---|
| One element per line (the old first page) | — | 2,118 ms | 200,012 | frames dropped (39.5 ms/jump wall) |
| Preact 10 + htm, windowed | 7.1 KB | 52 ms | 157 | 1.17 ms |
| Vue 3, windowed | 61.4 KB (whole runtime) | 43 ms | 155 | 0.98 ms |
| Shipped viewer (`logviewer.ts`), windowed | 6.7 KB | 56 ms | 181 | 1.11 ms |

Windowing is what matters: one element per line costs 200,000 elements and seconds per load. The three windowed renderings are within noise of each other and far under a frame's 16.7 ms, so the stack was chosen on what else it gives — Nuxt UI's accessible components, server rendering and typed code — and the viewer stays plain DOM for the reason above (bounded state outside reactivity), not for speed. The first measurement found the shipped viewer at 1.73 ms per jump; drawing each row with two nodes instead of three (the screen-reader "stderr:" prefix only on stderr rows) brought it to 1.11 ms.

## Verification (U06)

`crates/sentinel-api/tests/web.rs` (13 tests, loopback HTTP against a seeded controller) covers the routes behind the views: run filters and keyset pages, the caller's tenants, attempt steps, worker load and drain, sync lag, member and last-administrator rules, platform administration with step-up, repositories without credentials, the run control audit, `health`, a parked poll ending when its reader loses the tenant, a departed client's slot coming back, and parked polls leaving every handler for work.

`crates/sentinel-api/tests/web_browser.rs` (ignored by default; needs Node, `pnpm -C web build` and Edge, Chrome or Chromium) starts a seeded controller — two organizations, three members of different roles and a pending applicant, a worker with capacity and labels, a diamond run with a passed, a failed (with a stored gap), a running and a blocked job, pull-request and branch runs, a 64 MiB log, an unplaceable job, a lagging GitHub check — and the built `sentinel-web` in front of it behind a relay the test can cut, keeps writing the running job's log, and runs `web/test/ui.mjs` in headless Edge over the DevTools protocol:

```sh
pnpm -C web build
cargo test -p sentinel-api --test web_browser -- --ignored --nocapture the_web_interface
```

Its 114 checks (2026-09-27, all passing):

- **Structure and keyboard:** every control has an accessible name, one main landmark and navigation, one level-one heading per view; the first tab stop is "Skip to content" and it moves focus to the content; client-side navigation moves focus to the new heading; every tab stop on the run page shows a focus ring; cancel, rerun and log controls are reachable; the log viewer scrolls by line, page and end with the keyboard and steps fold from it.
- **Contrast:** every visible text element meets WCAG AA (4.5:1, 3:1 for large text) in both colour schemes on every view — the default light palette did not (sky and green text at about 2.7:1); light mode uses darker shades.
- **Layouts:** no horizontal page scroll at 360, 768 and 1280 px on every view.
- **Behaviour:** sign-in (refusal announced, continuing to the page asked for), run filters through the form and by deep link, the failed job's summary and evidence link, cache outcomes, the gap marker, folds, search jump and deep link, server rendering identical to the browser's.
- **Large log:** the 64 MiB, 524,289-line log read to its end in 5.6 s with at most 58 row elements and 392 elements in the page, the oldest lines released and said, heap at most 90 MiB; search finds the one line at the end.
- **Live and failures:** the running job's lines stream in; the relay cut is said ("Connection lost"), and after it the lines resume consecutive, nothing lost or repeated (2.1 s to resume); with the user's subscriber share held, the run page says "Updates paused", then turns live again and shows a change; hopping between live pages never exhausts the share.
- **Role changes during open sessions:** an operator lowered to reader has an action refused and said, and the navigation follows; removed from the tenant, their open run page says "You no longer have access" within 5 s (measured 18 ms) and the tenant leaves the navigation.
- **Administration:** suspending a tenant asks for a second factor, then suspends; reactivating inside the window does not ask again; a member's role changes from the members table.

The part's full suites (`cargo test-cli`, `lint-linux`, `test-linux`) and the base benchmarks are to run on the verification VPS, where every test now runs ([development](development.md#where-tests-run)); on 2026-09-27 the host was under another CI's load and the run was skipped, so they are pending ([TODO](../TODO.md#completion-log-and-handoff)).

## Known limits

- Live views are bounded by the controller's subscriber budget (32 parked at once, 8 per user); past it pages say "Updates paused" and retry. A deployment with many simultaneous viewers of live pages should expect that; raising the budget is a controller constant.
- Secret values, source credentials, hook secrets and invitations are managed from the CLI and host-local commands; the interface shows metadata only (invitations have no redemption route over HTTP yet).
- Keyboard and screen-reader behaviour is verified through the accessibility tree and keyboard events in a real browser, not with a screen reader in person.
