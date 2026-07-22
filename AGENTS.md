# AGENTS.md - Sentinel

Maintenance guide for operators and contributors. Sentinel is feature-complete; this file describes how the system works today, not a build plan.

## What it is

Sentinel monitors self-hosted GitHub Actions runners: status, host resources, and recent workflow runs. Access is limited to members of your GitHub org via OAuth.

Optional [Vigil SOC](https://vigilsoc.org/) integration surfaces security findings alongside CI metrics when `VIGIL_URL` is set.

Stack: Deno 2, Fresh 2.3 (SSR by default, islands where needed), Preact, Deno KV (sessions + capped metric history), WebSockets for live updates.

## Layout

```
sentinel/
├── routes/           # File-based routes, middleware, APIs
│   ├── _middleware.ts
│   ├── _app.tsx
│   ├── auth/         # OAuth login, callback, denied
│   ├── api/          # JSON + WebSocket
│   ├── runners/, runs/, security/
│   └── logout.tsx
├── islands/          # Client JS only (live panels, tour, logout confirm)
├── components/       # SSR UI primitives
├── lib/              # Auth, GitHub, system, Vigil, cache, realtime
├── assets/           # Tailwind theme + global CSS
├── static/           # Favicon, OG image, static files
├── deploy/           # systemd, Caddy, nginx templates
├── docs/             # DEPLOY.md, VIGIL.md
├── main.ts
├── utils.ts          # createDefine<State>()
└── vite.config.ts    # Dev server port 8000
```

## Tasks

```bash
deno task dev      # Vite HMR (http://localhost:8000)
deno task build    # Production build → _fresh/
deno task start    # deno serve on port 3000 (build first)
deno task check    # fmt --check, lint, type-check
deno task test     # Unit tests
```

Dev port comes from `vite.config.ts` (`server.port`, default 8000). `deno task start` always uses `--port=3000` (Deno tasks do not expand `${PORT:-3000}`). Under systemd, use `deno serve --port=${PORT}` so `PORT` from `EnvironmentFile` is honored. See `deploy/sentinel.service` and `docs/DEPLOY.md`.

## Environment

Copy `.env.example` to `.env` (never commit `.env` or `data/`):

```env
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_SECRET=...          # ≥32 random chars
# SESSION_DB_PATH=data/sessions.db
GH_ORG=...
GITHUB_PAT=...              # classic: admin:org + repo
APP_BASE_URL=https://...    # required off localhost
PORT=3000
RUNNER_COUNT=4

# Optional Vigil
VIGIL_URL=http://localhost:6987
VIGIL_USERNAME=...
VIGIL_PASSWORD=...
```

## Fresh conventions

- Define once: `createDefine<State>()` in `utils.ts`, import everywhere
- Routes: `define.handlers()` + `define.page()` (no `define.route()`)
- Middleware: `define.middleware()`; layouts: `define.layout()`
- Context: `ctx.req`, `ctx.state`, `ctx.render()`, `ctx.next()`, `ctx.redirect()`
- WebSockets: `ctx.upgrade()` in a GET handler (`routes/api/ws.ts`)
- Only `islands/` ship client JS; everything else is SSR HTML
- `trustProxy: true` in `main.ts` so `ctx.url` honors `X-Forwarded-*` behind TLS

## Auth flow

1. `_middleware.ts` reads the opaque session cookie, loads the Deno KV record (hashed key), enforces absolute (~12h) and idle (~2h) expiry
2. Valid session → re-check org membership via `GITHUB_PAT` (cached 5 min) → set `ctx.state.user`
3. Missing/invalid session → redirect to `/auth/login` (except `/auth/*`); `/api/*` returns JSON 401/403/503
4. Login: GitHub OAuth with `scope=read:org`, PKCE S256, sealed handshake cookie (SameSite=Lax)
5. Callback: exchange code, `GET /user`, confirm active org membership with PAT, create KV session, set opaque cookie (GitHub user token discarded)
6. Logout / confirmed non-member: delete KV record and clear cookie

Session records hold identity only (never the GitHub access token). Membership re-checks always use `GITHUB_PAT`.

## GitHub API + cache TTLs

| Call | Token | TTL |
|------|-------|-----|
| Org membership | `GITHUB_PAT` | 5 min |
| Org runners | `GITHUB_PAT` | 15 s |
| Org repos | `GITHUB_PAT` | 5 min |
| Workflow runs / jobs | `GITHUB_PAT` | 30 s |

Listing org runners needs `admin:org`. Cache lives in `lib/cache.ts`; callers in `lib/github.ts`.

## System metrics

Linux host via `Deno.Command`: `free -m`, `df -h /`, `/proc/loadavg`, `uptime -p`, `nproc`, `lscpu`, `systemctl show` for runner services. See `lib/system.ts`.

Host samples (load / memory % / disk %) are written to the same Deno KV file as sessions under `["metrics", "host"]`, capped to about 1 hour (~240 points). Growth stays tiny.

## Vigil (optional)

When `VIGIL_URL` is set, the Security nav appears. Sentinel logs in as a Vigil service user (`POST /api/auth/login`), caches the JWT, and reads:

| Endpoint | TTL |
|----------|-----|
| `GET /api/findings` | 30 s |
| `GET /api/cases` | 30 s |
| `GET /api/findings/{id}` | 60 s |
| `GET /api/agents/agents` | 15 s |

There is no `/api/agents/status`. File routes under `/security` always exist; UI and data gate on `VIGIL_URL`. Credentials and JWTs stay server-side.

Deploy notes and Ollama Cloud / Bifrost guidance: `docs/VIGIL.md`. Prefer upstream Vigil; Sentinel only needs the HTTP API.

Local Vigil `DEV_MODE=true` bypasses auth (dev only, never production).

## Deploy

Full checklist: `docs/DEPLOY.md`.

Templates (edit paths/domain before use):

- `deploy/sentinel.service`: systemd + `EnvironmentFile` + restart limits
- `deploy/Caddyfile`: reverse proxy + automatic HTTPS
- `deploy/nginx.conf.example`: TLS + WebSocket `/api/ws`

Typical update:

```bash
cd /opt/sentinel
git pull origin main
deno task build
sudo systemctl restart sentinel
```

## Security (keep these true)

- Never commit `.env`, secrets, or `data/`
- `SESSION_SECRET` seals the OAuth handshake cookie and HMACs opaque session IDs at rest
- Cookie holds only an opaque ID; authoritative session is Deno KV (`SESSION_DB_PATH`)
- Logout and membership denial delete the server record (immediate revocation)
- Absolute + idle TTLs enforced server-side; cookie `maxAge` matches absolute TTL
- Session ID rotated on login
- `APP_BASE_URL` pins OAuth `redirect_uri` and Secure-cookie decisions (do not trust Host / `X-Forwarded-*` alone)
- Session cookie: httpOnly, Secure on HTTPS, SameSite=Strict, `__Host-` on HTTPS
- Handshake cookie: httpOnly, Secure on HTTPS, SameSite=Lax, integrity-sealed (state + PKCE)
- Login scope `read:org` only; org APIs use `GITHUB_PAT` (`admin:org` + `repo`)
- Only `state=active` membership counts; pending invites denied
- Confirmed non-members lose the session; GitHub upstream errors return 503 without clearing it
- Vigil credentials and JWTs never reach the browser

## UI notes

- Auth-first: unauthenticated users see `/auth/login`, not a dashboard peek
- Light lemon / frosted glass theme in `assets/styles.css` (`@theme` tokens)
- No Live/Offline shell badges; quiet refresh on successful updates
- Product tour: Driver.js in `islands/ProductTour.tsx`; help at `/help`
- Prefer SSR; put interactivity only in islands

## CI

`.github/workflows/` runs `deno task check` and `deno task test` on self-hosted Linux runners (same runners Sentinel monitors when you self-host).
