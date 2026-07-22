# Plan - Sentinel

## What is this

A dashboard for monitoring self-hosted GitHub Actions runners. Built with Deno 2 and Fresh 2.3, server-rendered by default with islands for the interactive parts. Auth is handled through GitHub OAuth with org membership checks, so only your org members can get in.

Sentinel also has an optional integration with [Vigil SOC](https://vigilsoc.org/), an open-source AI security operations platform. When enabled, Sentinel acts as a unified interface that surfaces both your CI runner health and your security posture in one place.

## Why Fresh 2.3

- Pages render as plain HTML on the server. Islands only ship JS for the bits that actually need it (live metrics, auto-refresh). Most of the dashboard loads with zero client-side JavaScript.
- No client-side routing library, no SPA bundle. Fast first paint, small payload.
- Fresh 2.3 added first-class WebSocket support, which is useful for pushing runner status updates in real time instead of polling.
- File-based routing and middleware make the auth layer straightforward.
- No node_modules, no build step during development. Deno handles it all natively.
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
- Scopes: `read:org` (membership check) and `repo` (reading workflow runs)
- Put the client ID and secret in your `.env`

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
- Pulls recent findings, active cases, and agent activity
- Surfaces them in a dedicated "Security" tab on the dashboard
- Links to the Vigil web UI for deep dives

### Swapping the AI backend to Ollama Cloud
Vigil uses [Bifrost](https://docs.getbifrost.ai/) as its LLM gateway. By default it routes to Anthropic Claude, but Bifrost supports Ollama as a provider. This means you can point Vigil at Ollama Cloud (which has a free tier) instead of paying for Claude API calls.

To do this, you fork Vigil and update the Bifrost config:

1. Fork `Vigil-SOC/vigil` to your org
2. Edit `docker/bifrost/config.json` and add an Ollama provider entry:

```json
{
  "providers": {
    "ollama": {
      "keys": [
        {
          "name": "ollama-cloud",
          "value": "your_ollama_api_key",
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

3. Set the env vars in your `.env`:
```
OLLAMA_ENABLED=true
OLLAMA_URL=https://ollama.com
OLLAMA_DEFAULT_MODEL=gpt-oss:120b-cloud
DEFAULT_LLM_PROVIDER=ollama
```

4. Ollama Cloud models that work on the free tier (confirmed by the community):
   - `gpt-oss:120b-cloud` - strong reasoning, good for investigation agents
   - `gpt-oss:20b-cloud` - lighter, faster, good for triage
   - `gemma3:27b-cloud` - solid all-rounder
   - `glm-4.7:cloud` - good for analysis tasks
   - `qwen3-coder:480b-cloud` - if available on free tier, excellent for code analysis

5. The Ollama Cloud API is at `https://ollama.com/api/chat` with bearer token auth. It speaks the same protocol as local Ollama, so Bifrost routes to it the same way.

### Considerations
- The free tier has rate limits and some models may be gated. Check [the unofficial tracker](https://github.com/OshriFatkiev/ollama-cloud-free-tier) for which models currently work on free.
- For production use, you may want to run a local Ollama instance with a smaller model on the same server, or upgrade to a paid Ollama Cloud plan.
- Bifrost supports multiple providers simultaneously, so you can mix Ollama Cloud (free) with a paid provider as fallback.

### Vigil fork notes
- The fork should track upstream closely. Vigil is actively developed (300+ commits).
- Keep your Bifrost config changes in a separate branch or overlay so rebasing on upstream is clean.
- The `env.example` in Vigil already has Ollama settings, but the Bifrost config file was missing the Ollama provider entry (known issue #324). Your fork fixes this.

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
│   ├── RunnerGrid.tsx          # Runner cards with live status
│   ├── RunsTable.tsx           # Runs table with auto-refresh
│   ├── SecurityFeed.tsx        # Vigil findings feed (if enabled)
│   └── LiveIndicator.tsx       # WebSocket-connected status dot
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
│   ├── vigil.ts                # Vigil API client (findings, cases, agents)
│   └── cache.ts                # In-memory cache with TTL
├── static/
│   └── styles.css              # Global styles (dark theme)
├── deno.json                   # Deno config, Fresh dependency, tasks
├── main.ts                     # App entry point
└── vite.config.ts              # Vite config for Fresh
```

## Data sources

### GitHub API (server-side, using a PAT or the user's OAuth token)
| Endpoint | What it's for | Cache TTL |
|----------|---------------|-----------|
| `GET /orgs/{org}/actions/runners` | Runner list and status | 15s |
| `GET /orgs/{org}/repos` | Repo list for fetching runs | 5min |
| `GET /repos/{org}/{repo}/actions/runs?per_page=5` | Recent runs per repo | 30s |
| `GET /repos/{org}/{repo}/actions/runs/{id}/jobs` | Jobs for a run (which runner) | 30s |
| `GET /user/memberships/orgs/{org}` | Org membership check | 5min |

### Vigil API (optional, if VIGIL_URL is set)
| Endpoint | What it's for | Cache TTL |
|----------|---------------|-----------|
| `GET /api/findings` | Recent security findings | 30s |
| `GET /api/cases` | Active cases | 30s |
| `GET /api/findings/{id}` | Finding detail | 60s |
| `GET /api/agents/status` | Agent activity status | 15s |

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

### `/security` - Vigil SOC (optional, only if VIGIL_URL is set)
- Recent findings from Vigil with severity, status, and agent that handled them
- Active cases with MITRE ATT&CK mappings
- Agent activity feed
- Links to the Vigil web UI for full investigation

### `/auth/login` - Login
- "Sign in with GitHub" button
- Redirects to the GitHub OAuth authorize URL

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
5. Set up a systemd service running `deno task start`
6. Put a reverse proxy in front (Caddy, nginx, whatever you prefer) with TLS

### With Vigil SOC (optional)
1. Fork Vigil-SOC/vigil to your org
2. Configure Bifrost to use Ollama Cloud (see the Vigil section above)
3. Deploy Vigil on the same server or a separate one
4. Set `VIGIL_URL` in Sentinel's `.env` pointing to the Vigil backend
5. The security tab appears automatically when `VIGIL_URL` is set

### CI
- The repo includes a GitHub Actions workflow that runs `deno task check` and `deno task test`
- If you're running this dashboard for your own self-hosted runners, the CI for this repo can run on those same runners

## Implementation phases

### Phase 1: Scaffold + auth
- Scaffold a Fresh project with `deno create`
- Set up the GitHub OAuth App
- Write the auth middleware in `_middleware.ts`
- Implement login, callback, and logout routes
- Verify: you can log in with GitHub and only org members get through

### Phase 2: Data layer
- Write `lib/github.ts` (GitHub API client with caching)
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
- WebSocket endpoint at `/api/ws` for real-time push

### Phase 5: Vigil SOC integration
- Write `lib/vigil.ts` (Vigil API client)
- Add `/security` route with findings, cases, and agent activity
- Build `FindingCard` component
- Add security summary to the dashboard home
- WebSocket pushes Vigil findings alongside runner status

### Phase 6: Deploy
- Install Deno on the server
- Build and deploy
- Configure the reverse proxy
- If using Vigil: deploy the fork, configure Bifrost with Ollama Cloud, set VIGIL_URL
- Test end to end

## Environment variables

| Variable | What it does |
|----------|-------------|
| `GITHUB_CLIENT_ID` | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | OAuth App client secret |
| `SESSION_SECRET` | Random string for JWT signing (32+ chars) |
| `GH_ORG` | GitHub org name |
| `PORT` | Server port (default: 3000) |
| `RUNNER_COUNT` | Number of runner instances (default: 4) |
| `VIGIL_URL` | URL of Vigil backend (optional, enables security tab) |
| `VIGIL_API_KEY` | API key for Vigil backend (optional) |

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
