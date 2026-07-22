# Plan - Sentinel

## What is this

A dashboard for monitoring self-hosted GitHub Actions runners. Built with Deno 2 and Fresh 2.3, server-rendered by default with islands for the interactive parts. Auth is handled through GitHub OAuth with org membership checks, so only your org members can get in.

Sentinel also has an optional integration with [Vigil SOC](https://vigilsoc.org/), an open-source AI security operations platform. When enabled, Sentinel acts as a unified interface that surfaces both your CI runner health and your security posture in one place.

## Why Fresh 2.3

- Pages render as plain HTML on the server. Islands only ship JS for the bits that actually need it (live metrics, auto-refresh). Most of the dashboard loads with zero client-side JavaScript.
- No client-side routing library, no SPA bundle. Fast first paint, small payload.
- Fresh 2.3 added first-class WebSocket support, which is useful for pushing runner status updates in real time instead of polling.
- File-based routing and middleware make the auth layer straightforward.
- Fresh 2.x uses Vite for the dev server and production asset build (`deno task build`). Pages still ship zero client JS by default; islands opt in to hydration.
- This is a small app. Fresh is designed for exactly this kind of thing.

## Auth: GitHub OAuth + org membership

### How it works
1. User hits the dashboard, middleware checks for a session cookie
2. No session -> redirect to `/auth/login` -> redirect to GitHub OAuth authorize URL
3. GitHub sends the user back to `/auth/callback` with a code
4. Server trades the code for an access token (server-side, client secret never hits the browser)
5. Server calls `GET /user` to get the GitHub username
6. Server calls `GET /user/memberships/orgs/{org}` to check if they belong to your org
   - 200 means they're a member
   - 404 means they're not, deny access
7. Create a signed JWT with the username and token, set it as an httpOnly cookie
8. Redirect to the dashboard

### Setting up the OAuth app
- Go to GitHub Settings -> Developer settings -> OAuth Apps -> New OAuth App
- Homepage URL: your dashboard URL
- Authorization callback URL: `https://your-domain/auth/callback`
- At login, request scopes on the authorize URL: `read:org` (membership) and `repo` (workflow runs). Scopes are not OAuth App form fields.
- Put the client ID and secret in your `.env`
- Also create a classic PAT with `admin:org` + `repo` and set `GITHUB_PAT` for org runner/run queries (listing org self-hosted runners requires `admin:org`)

### Sessions
- Signed JWT stored in an httpOnly, secure, sameSite=strict cookie
- JWT contains the username, the GitHub token, and an expiry timestamp
- Signed with a server-side secret you set via `SESSION_SECRET`
- Middleware verifies the JWT on every request and re-checks org membership (cached for 5 minutes so you don't hammer the GitHub API)

## Vigil SOC integration (optional)

[Vigil](https://github.com/Vigil-SOC/vigil) is an open-source AI SOC platform with 13 specialized agents for threat detection, investigation, and response. Sentinel can connect to a Vigil instance and surface security findings alongside CI runner health.

### What Vigil does
- 13 AI agents for triage, investigation, threat hunting, forensics, malware analysis, etc.
- Workflows defined as plain Markdown files (incident response, threat hunt, forensic analysis)
- 30+ integrations via MCP (Splunk, CrowdStrike, VirusTotal, Shodan, Jira, Slack, etc.)
- 7,200+ detection rules across Sigma, Splunk, Elastic, and KQL
- Built on Bifrost, an open LLM gateway that routes to Anthropic, OpenAI, or Ollama
- Apache 2.0 licensed, runs locally, data stays in your environment

### How Sentinel connects to Vigil
- Sentinel talks to the Vigil FastAPI backend (default port 6987)
- Vigil findings/cases/agents routes require an authenticated Vigil user JWT (`Depends(get_current_active_user)`). There is no shared `VIGIL_API_KEY` for these reads
- Sentinel logs in as a dedicated Vigil service user (`POST /api/auth/login`), caches the access token, and calls:
  - `GET /api/findings` — recent findings
  - `GET /api/cases` — cases
  - `GET /api/findings/{id}` — finding detail
  - `GET /api/agents/agents` — available agents (there is no `/api/agents/status`)
- Surfaces them in a dedicated "Security" tab when `VIGIL_URL` is configured (UI/nav gate; file routes still exist on disk)
- Links to the Vigil web UI (default `:6988`) for deep dives

### Swapping the AI backend to Ollama Cloud
Vigil uses [Bifrost](https://docs.getbifrost.ai/) as its LLM gateway. Upstream already ships an `ollama` provider in `docker/bifrost/config.json` wired to `env.OLLAMA_URL`. You can point that at Ollama Cloud instead of a local daemon.

To use Ollama Cloud:

1. Prefer upstream Vigil first. Fork only if you need patches beyond upstream (notably open issues #327 / #328 where chat endpoints still hardcode `ClaudeService`, which blocks non-Anthropic streaming even when Bifrost is correct)
2. Configure Bifrost for Ollama Cloud (API key + Cloud URL):

```json
{
  "providers": {
    "ollama": {
      "keys": [
        {
          "name": "ollama-cloud",
          "value": "env.OLLAMA_API_KEY",
          "models": ["*"],
          "weight": 1.0,
          "ollama_key_config": {
            "url": "https://ollama.com"
          }
        }
      ]
    }
  }
}
```

3. Set the env vars in Vigil's `.env`:
```
OLLAMA_ENABLED=true
OLLAMA_URL=https://ollama.com
OLLAMA_DEFAULT_MODEL=gpt-oss:120b
DEFAULT_LLM_PROVIDER=ollama
```
Plus provide the Ollama Cloud API key to Bifrost (`OLLAMA_API_KEY` / Bifrost key `value`).

4. Model notes (as of 2026-07-22):
   - Prefer `gpt-oss:120b` / `gpt-oss:20b` via Cloud API
   - Several older Cloud models were retired 2026-07-15 (`gemma3:27b`, `glm-4.7`, `qwen3-coder:480b`, and others) — check [Ollama Cloud docs](https://docs.ollama.com/cloud)
   - Local `ollama run …-cloud` offload uses `*-cloud` names; direct `https://ollama.com` API often uses the base name (e.g. `gpt-oss:120b`)

5. Direct Cloud API: `https://ollama.com/api/chat` with bearer token auth. Bifrost routes the same way when `ollama_key_config.url` is `https://ollama.com` and `value` holds the API key.

### Considerations
- Free / Cloud tiers have rate limits and rotating availability. Prefer official retirement notices over outdated community lists.
- For production, you may want local Ollama, paid Ollama Cloud, or Anthropic/OpenAI via Bifrost.
- Bifrost supports multiple providers simultaneously, so you can mix providers as fallback.
- Until Vigil #327 / #328 land, agent chat streaming may still require Anthropic even if Bifrost can reach Ollama.

### Vigil fork notes
- Prefer tracking upstream. Current upstream Bifrost config already includes `providers.ollama` with `env.OLLAMA_URL` (issue #324's missing-provider gap is largely addressed).
- Keep any remaining Bifrost / provider patches on a separate branch so rebasing stays clean.
- `env.example` already documents Ollama settings (`OLLAMA_ENABLED`, `OLLAMA_URL`, `DEFAULT_LLM_PROVIDER`).

## Architecture

```
sentinel/
├── routes/
│   ├── _middleware.ts          # Auth middleware: session check + org membership
│   ├── _app.tsx                # HTML shell, global layout
│   ├── index.tsx               # Dashboard home: system overview + runner cards
│   ├── runners/
│   │   └── index.tsx           # Per-runner detail page
│   ├── runs/
│   │   └── index.tsx           # Workflow runs table
│   ├── security/               # Vigil SOC integration (optional)
│   │   ├── index.tsx           # Security overview: findings, cases, agent activity
│   │   └── finding/[id].tsx    # Individual finding detail
│   ├── auth/
│   │   ├── login.tsx           # Redirects to GitHub OAuth
│   │   └── callback.tsx        # OAuth callback: exchange code, create session
│   ├── api/
│   │   ├── system.ts           # JSON: system metrics (CPU, RAM, disk)
│   │   ├── runners.ts          # JSON: GitHub runners + local service status
│   │   ├── runs.ts             # JSON: recent workflow runs + jobs
│   │   ├── vigil.ts            # JSON: Vigil findings + cases (if configured)
│   │   └── ws.ts               # WebSocket: real-time updates
│   └── logout.tsx              # Clear session, redirect to login
├── islands/
│   ├── SystemStats.tsx         # Auto-refreshing system metric cards
│   ├── RunnerGrid.tsx          # Runner cards with status
│   ├── RunsTable.tsx           # Runs table with auto-refresh
│   └── SecurityFeed.tsx        # Vigil findings feed (if enabled)
├── components/
│   ├── StatCard.tsx            # Reusable stat card
│   ├── RunnerCard.tsx          # Reusable runner card
│   ├── StatusBadge.tsx         # Status badge (online/offline/busy/success/failure)
│   ├── FindingCard.tsx         # Vigil finding card
│   └── Layout.tsx              # Page layout with nav
├── lib/
│   ├── github.ts               # GitHub API client (runners, runs, jobs, repos)
│   ├── system.ts               # System metrics via shell commands
│   ├── auth.ts                 # OAuth flow, JWT creation/verification, org check
│   ├── vigil.ts                # Vigil API client (JWT login, findings, cases, agents)
│   └── cache.ts                # In-memory cache with TTL
├── static/
│   └── styles.css              # Global styles (light translucent + lemon tokens)
├── deno.json                   # Deno config, Fresh dependency, tasks
├── main.ts                     # App entry point (consider trustProxy: true behind TLS proxy)
└── vite.config.ts              # Vite config for Fresh (dev server port lives here)
```

## Data sources

### GitHub API (server-side)
| Endpoint | Auth | What it's for | Cache TTL |
|----------|------|---------------|-----------|
| `GET /orgs/{org}/actions/runners` | `GITHUB_PAT` (`admin:org`) | Runner list and status | 15s |
| `GET /orgs/{org}/repos` | `GITHUB_PAT` | Repo list for fetching runs | 5min |
| `GET /repos/{org}/{repo}/actions/runs?per_page=5` | `GITHUB_PAT` (`repo` if private) | Recent runs per repo | 30s |
| `GET /repos/{org}/{repo}/actions/runs/{id}/jobs` | `GITHUB_PAT` | Jobs for a run (which runner) | 30s |
| `GET /user/memberships/orgs/{org}` | User OAuth token | Org membership check | 5min |

### Vigil API (optional, if VIGIL_URL is set; requires Vigil user JWT)
| Endpoint | What it's for | Cache TTL |
|----------|---------------|-----------|
| `POST /api/auth/login` | Obtain Vigil access JWT for the service user | n/a (token cache) |
| `GET /api/findings` | Recent security findings | 30s |
| `GET /api/cases` | Cases list | 30s |
| `GET /api/findings/{id}` | Finding detail | 60s |
| `GET /api/agents/agents` | Available agents list | 15s |

There is no Vigil `GET /api/agents/status` endpoint. Derive any "activity" UI from findings/cases/agent list data.

### System metrics (shell commands on the host)
| Source | Data |
|--------|------|
| `free -m` | Memory total/used/available |
| `df -h /` | Disk usage |
| `/proc/loadavg` | Load averages |
| `uptime -p` | Uptime string |
| `nproc` + `lscpu` | CPU cores and model |
| `systemctl show {svc}` | Per-runner service status, memory, PID |

### WebSocket (Fresh 2.3)
- Client connects to `/api/ws` on page load
- Implement with `define.handlers({ GET(ctx) { return ctx.upgrade({...}) } })` (or `app.ws()` in `main.ts`)
- Server pushes updates every 15 seconds: system metrics, runner status, and (if enabled) Vigil findings
- Client updates the DOM without a full page reload
- Falls back to HTTP polling if the WebSocket drops

## Pages

### `/` - Dashboard
- System overview: stat cards for CPU, RAM, disk, uptime with progress bars
- Runner grid: cards for each runner showing status, labels, service state, PID, memory
- Recent runs: table of the last 30 runs across all repos (repo, workflow, branch, commit, runner, duration, when)
- Security summary: latest Vigil findings (if integration is enabled)
- Everything auto-refreshes via WebSocket, with polling as fallback

### `/runners` - Runner details
- Per-runner view: current status, labels, service config
- Recent jobs that ran on each runner
- Resource usage over time (if we add history tracking later)

### `/runs` - Workflow runs
- Full table of recent runs across all repos
- Filter by repo, status, or runner
- Click a run to open it on GitHub

### `/security` - Vigil SOC (optional UI, when VIGIL_URL is set)
- Recent findings from Vigil with severity, status, and related agent context when available
- Active cases with MITRE ATT&CK mappings when present on the case/finding
- Agent list from Vigil (not a live "status" feed — Vigil has no `/api/agents/status`)
- Links to the Vigil web UI for full investigation

### `/auth/login` - Login
- "Sign in with GitHub" button
- Redirects to the GitHub OAuth authorize URL with `scope=read:org repo`

### `/auth/callback` - OAuth callback
- Exchanges the code for a token
- Verifies org membership
- Creates the session and redirects to `/`

## Deployment

### On your server
1. Install Deno 2: `curl -fsSL https://deno.land/install.sh | sh`
2. Clone the repo
3. Run `deno task build`
4. Create a `.env` file with the variables listed below
5. Set up a systemd service running `deno task start` (ensure the start task sets `--port` / `PORT` as intended)
6. Put a reverse proxy in front (Caddy, nginx, whatever you prefer) with TLS
7. Construct the Fresh app with `trustProxy: true` so `ctx.url` reflects `X-Forwarded-Proto` / `X-Forwarded-Host`

### With Vigil SOC (optional)
1. Deploy Vigil (prefer upstream; fork only for needed patches)
2. Configure Bifrost for Ollama Cloud if desired; confirm chat works for your provider (#327)
3. Create a Vigil service user for Sentinel
4. Set `VIGIL_URL`, `VIGIL_USERNAME`, and `VIGIL_PASSWORD` in Sentinel's `.env`
5. The security tab appears in the UI when `VIGIL_URL` is set

### CI
- The repo includes a GitHub Actions workflow that runs `deno task check` and `deno task test`
- If you're running this dashboard for your own self-hosted runners, the CI for this repo can run on those same runners

## Implementation phases

### Phase 1: Scaffold + auth
- Scaffold a Fresh project with `deno create @fresh/init`
- Set up the GitHub OAuth App and `GITHUB_PAT`
- Write the auth middleware in `_middleware.ts` using `define.middleware()`
- Implement login, callback, and logout routes with `define.handlers()` / `define.page()`
- Verify: you can log in with GitHub and only org members get through

### Phase 2: Data layer
- Write `lib/github.ts` (GitHub API client with caching; OAuth token for membership, PAT for org APIs)
- Write `lib/system.ts` (system metrics via shell)
- Write `lib/cache.ts` (TTL cache)
- Add API routes: `/api/system`, `/api/runners`, `/api/runs`

### Phase 3: Server-rendered UI
- `_app.tsx` with the HTML shell and dark theme
- `index.tsx` with the dashboard home (stats, runner grid, runs table)
- Build the reusable components: StatCard, RunnerCard, StatusBadge, Layout
- All server-rendered at this point, no islands yet

### Phase 4: Islands + real-time
- `islands/SystemStats.tsx` for auto-refreshing stat cards
- `islands/RunnerGrid.tsx` for live runner status
- `islands/RunsTable.tsx` for the auto-refreshing runs table
- WebSocket endpoint at `/api/ws` via `ctx.upgrade()` for real-time push

### Phase 5: Vigil SOC integration
- Write `lib/vigil.ts` (login + JWT-backed Vigil API client)
- Add `/security` UI gated on `VIGIL_URL` with findings, cases, and agent list
- Build `FindingCard` component
- Add security summary to the dashboard home
- WebSocket pushes Vigil findings alongside runner status

### Phase 6: Deploy
- Install Deno on the server
- Build and deploy
- Configure the reverse proxy + `trustProxy`
- If using Vigil: deploy Vigil, configure Bifrost/provider as needed, set Vigil env vars
- Test end to end

## Environment variables

| Variable | What it does |
|----------|-------------|
| `GITHUB_CLIENT_ID` | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | OAuth App client secret |
| `SESSION_SECRET` | Random string for JWT signing (32+ chars) |
| `GH_ORG` | GitHub org name |
| `GITHUB_PAT` | PAT with `admin:org` + `repo` for org runners/runs |
| `PORT` | Production server port (wire via `deno serve --port`; default often 8000 unless overridden) |
| `RUNNER_COUNT` | Number of runner instances (default: 4) |
| `VIGIL_URL` | URL of Vigil backend (optional, enables security tab) |
| `VIGIL_USERNAME` | Vigil service-user username (optional) |
| `VIGIL_PASSWORD` | Vigil service-user password (optional) |

## Tech stack

| Layer | Technology |
|-------|-----------|
| Runtime | Deno 2 |
| Framework | Fresh 2.3 |
| UI | Preact (built into Fresh) |
| Auth | GitHub OAuth + JWT sessions |
| Real-time | Fresh 2.3 WebSockets |
| SOC integration | Vigil (optional, via FastAPI backend) |
| LLM backend for Vigil | Ollama Cloud (free tier) or any Bifrost-supported provider |
| Reverse proxy | Caddy or nginx (your choice) |
| Deployment | Bare metal or VM |
