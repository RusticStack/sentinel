# AGENTS.md - Sentinel

## Project

Sentinel is a dashboard for monitoring self-hosted GitHub Actions runners. It shows runner status, system resources, and recent workflow runs. Access is restricted to your GitHub org members through OAuth.

Optionally, Sentinel can integrate with [Vigil SOC](https://vigilsoc.org/), an open-source AI security operations platform, to surface security findings alongside CI metrics.

Built with Deno 2 and Fresh 2.3.

## Tech stack

- **Runtime:** Deno 2
- **Framework:** Fresh 2.3 (server-rendered by default, islands for interactivity)
- **UI:** Preact (bundled with Fresh)
- **Auth:** GitHub OAuth with signed JWT sessions
- **Real-time:** Fresh 2.3 WebSocket support
- **SOC integration:** Vigil (optional, via FastAPI backend)
- **Reverse proxy:** Caddy or nginx (your choice, with TLS)

## Prerequisites

- Deno 2 installed
- A GitHub OAuth App with:
  - Homepage URL set to your dashboard URL
  - Authorization callback URL set to `https://your-domain/auth/callback`
  - At login, request scopes `read:org` and `repo` on the authorize URL (`scope=`). Scopes are not configured as OAuth App form fields.
- A GitHub PAT (classic) with `admin:org` and `repo` for org-scoped runner/run queries (OAuth user tokens typically lack `admin:org`)
- (Optional) A running Vigil SOC instance if you want the security tab

## Development

```bash
deno task dev      # Vite dev server with HMR (default http://localhost:8000; set in vite.config.ts)
deno task build    # Production build (writes _fresh/)
deno task start    # Run production server via deno serve (build first)
deno task check    # Type-check
deno task test     # Run tests
```

Dev port is controlled by Vite (`vite.config.ts` `server.port`). Production port is controlled by `deno serve --port` in the `start` task (or `PORT` if you wire it there). Do not assume `PORT` alone changes the Vite dev server.

## Environment variables

Create a `.env` file (don't commit it):

```env
GITHUB_CLIENT_ID=your_oauth_app_client_id
GITHUB_CLIENT_SECRET=your_oauth_app_client_secret
SESSION_SECRET=random_32_char_string
GH_ORG=your_org_name
GITHUB_PAT=ghp_your_pat_with_admin_org_and_repo
PORT=3000
RUNNER_COUNT=4

# Optional: Vigil SOC integration
VIGIL_URL=http://localhost:6987
VIGIL_USERNAME=sentinel_service_user
VIGIL_PASSWORD=your_vigil_password
```

When `VIGIL_URL` is set, the security tab appears in the UI and Sentinel pulls findings, cases, and agent lists from the Vigil backend. Vigil's `/api/findings`, `/api/cases`, and `/api/agents/*` routes require an authenticated Vigil user JWT (not a shared API key). Use a dedicated Vigil service user and exchange credentials for a JWT via `POST /api/auth/login`.

## Project structure

```
sentinel/
├── routes/              # File-based routing
│   ├── _middleware.ts   # Auth: session check + org membership
│   ├── _app.tsx         # HTML shell, global layout
│   ├── index.tsx        # Dashboard home
│   ├── runners/         # Runner detail pages
│   ├── runs/            # Workflow runs page
│   ├── security/        # Vigil SOC integration (optional)
│   ├── auth/            # OAuth login + callback
│   ├── api/             # JSON API + WebSocket
│   └── logout.tsx       # Session cleanup
├── islands/             # Client-side hydrated components
├── components/          # Server-side reusable components
├── lib/                 # Business logic (github.ts, system.ts, auth.ts, vigil.ts, cache.ts)
├── static/              # Static assets (CSS, images)
├── deno.json            # Deno config, Fresh dependency, tasks
├── main.ts              # App entry point
└── vite.config.ts       # Vite config
```

## Conventions

### Fresh 2 patterns
- Create `define` once with `createDefine<State>()` (typically in `utils.ts`) and import it everywhere
- Use `define.middleware()` for middleware
- Use `define.handlers()` + `define.page()` for routes (there is no `define.route()`)
- Use `define.layout()` for layouts
- Context is unified: `ctx.req`, `ctx.state`, `ctx.render()`, `ctx.next()`, `ctx.redirect()`
- WebSockets: `ctx.upgrade()` in a GET handler, or `app.ws()` in `main.ts`
- Only files in `islands/` ship JavaScript to the browser
- Everything else is server-rendered HTML
- Behind a reverse proxy, construct the app with `trustProxy: true` so `ctx.url` honors `X-Forwarded-*`

### Auth flow
1. `_middleware.ts` runs on every request
2. Checks for the session cookie, verifies the JWT signature and expiry
3. If valid, checks org membership (cached for 5 min) and sets `ctx.state.user`
4. If missing or invalid, redirects to `/auth/login` (except for `/auth/*` routes)
5. `/auth/login` redirects to GitHub OAuth with `scope=read:org repo`
6. `/auth/callback` exchanges the code, verifies membership, creates the JWT, sets the cookie

### GitHub API usage
- Use the user's OAuth token for user-scoped queries (org membership via `GET /user/memberships/orgs/{org}`)
- Use `GITHUB_PAT` for org-scoped queries (runners, repos, runs). Listing org runners requires `admin:org`
- Cache all API responses with TTL to stay within rate limits
- See `plan.md` for cache TTLs per endpoint

### Vigil API usage
- Sentinel talks to the Vigil FastAPI backend (default port 6987)
- Authenticate with a Vigil service user (`POST /api/auth/login`), then call APIs with the JWT
- Pull findings (`GET /api/findings`), cases (`GET /api/cases`), and agents (`GET /api/agents/agents`)
- All Vigil API responses are cached with TTL (see `plan.md`)
- File-based `/security` routes always exist; show the security tab / return data only when `VIGIL_URL` is set

### System metrics
- Use `Deno.Command` for shell commands (not child_process, this is Deno)
- `free -m`, `df -h /`, `/proc/loadavg`, `uptime -p`, `nproc`, `lscpu`
- `systemctl show {service}` for per-runner service state

## Vigil SOC integration

[Vigil](https://github.com/Vigil-SOC/vigil) is an open-source AI SOC with 13 agents for security operations. Sentinel connects to its backend API and surfaces findings in a dedicated security tab.

### Authenticating to Vigil
Vigil protects findings/cases/agents with user JWT auth (`get_current_active_user`). There is no general-purpose `VIGIL_API_KEY` for read APIs.

1. Create a dedicated Vigil user for Sentinel (least privilege)
2. Set `VIGIL_URL`, `VIGIL_USERNAME`, and `VIGIL_PASSWORD` in Sentinel's `.env`
3. On startup / first request, `POST {VIGIL_URL}/api/auth/login` and cache the access token
4. Call Vigil APIs with `Authorization: Bearer <access_token>`
5. Refresh via Vigil's refresh flow when the access token expires

Local Vigil with `DEV_MODE=true` bypasses auth (dev only — never in production).

### Setting up Vigil with Ollama Cloud
Vigil uses Bifrost as its LLM gateway. Upstream `docker/bifrost/config.json` already includes an `ollama` provider wired to `env.OLLAMA_URL`. Point that at Ollama Cloud and supply an API key:

1. Fork `Vigil-SOC/vigil` only if you need patches beyond upstream (for example, open issues that still hardcode Anthropic in chat streaming — see Vigil #327 / #328)
2. Ensure Bifrost has an Ollama provider entry (upstream already does). For Ollama Cloud:

```json
{
  "providers": {
    "ollama": {
      "keys": [{
        "name": "ollama-cloud",
        "value": "env.OLLAMA_API_KEY",
        "models": ["*"],
        "weight": 1.0,
        "ollama_key_config": {
          "url": "https://ollama.com"
        }
      }]
    }
  }
}
```

3. Set env vars: `OLLAMA_ENABLED=true`, `OLLAMA_URL=https://ollama.com`, `DEFAULT_LLM_PROVIDER=ollama`, plus your Ollama Cloud API key for Bifrost
4. Prefer currently available Cloud models (check [Ollama Cloud docs](https://docs.ollama.com/cloud) for retirements). As of mid-2026, `gpt-oss:120b` / `gpt-oss:20b` are the durable picks; several older free-tier models (e.g. `gemma3:27b`, `glm-4.7`, `qwen3-coder:480b`) were retired 2026-07-15
5. Direct Cloud API is `https://ollama.com/api/chat` with `Authorization: Bearer $OLLAMA_API_KEY`

### Vigil fork maintenance
- Prefer tracking upstream. Bifrost already ships an Ollama provider section (issue #324's config gap is largely addressed in current `docker/bifrost/config.json`)
- Keep any remaining Bifrost / provider patches on a separate branch so rebasing stays clean
- Non-Anthropic chat may still need upstream fixes (#327 / #328) before Ollama Cloud works end-to-end in Vigil's UI agents

See `plan.md` for the full integration architecture and API endpoints.

## Deployment

### Server setup
- Install Deno 2 on the server
- Clone the repo and run `deno task build`
- Create a `.env` file with the variables listed above
- Set up a systemd service:

```ini
[Unit]
Description=Sentinel Dashboard
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/sentinel
EnvironmentFile=/path/to/sentinel/.env
ExecStart=/path/to/deno task start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- Put a reverse proxy in front with TLS. Enable Fresh `trustProxy: true` so redirects and absolute URLs see the public host. Caddy example:

```
your-domain.com {
    reverse_proxy 127.0.0.1:3000
}
```

### With Vigil SOC
- Deploy Vigil (upstream or a minimal fork) on the same server or a separate one
- Configure Bifrost for Ollama Cloud if desired (see above); verify chat works under your provider (#327)
- Set `VIGIL_URL` plus Vigil service-user credentials in Sentinel's `.env`
- The security tab appears in the UI when `VIGIL_URL` is set

### Deploy steps
```bash
cd /path/to/sentinel
git pull origin main
deno task build
sudo systemctl restart sentinel
```

## CI

The repo includes a GitHub Actions workflow:

```yaml
runs-on: [self-hosted, linux, arm64]
steps:
  - uses: actions/checkout@v4
  - uses: denoland/setup-deno@v2
  - run: deno task check
  - run: deno task test
```

If you're running Sentinel for your own self-hosted runners, this CI runs on those same runners.

## Security

- Never commit `.env` or secrets
- The JWT session secret (`SESSION_SECRET`) should be a long random string
- The OAuth client secret stays server-side, never sent to the browser
- All cookies are httpOnly, secure, sameSite=strict
- Org membership is checked on login and re-verified on each request (cached for 5 min)
- If a member leaves the org, their session stops working within 5 minutes
- `GITHUB_PAT` should have minimal scopes: `admin:org` and `repo`
- Vigil credentials (`VIGIL_USERNAME` / `VIGIL_PASSWORD`) and any obtained JWTs stay server-side and are never exposed to the browser
