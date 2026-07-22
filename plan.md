# Plan - Vigil

## What is this

A web dashboard for monitoring self-hosted GitHub Actions runners. Built with Deno 2 and Fresh 2.3, server-rendered by default with islands for the interactive parts. Auth is handled through GitHub OAuth with org membership checks, so only your org members can get in.

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

## Architecture

```
vigil/
├── routes/
│   ├── _middleware.ts          # Auth middleware: session check + org membership
│   ├── _app.tsx                # HTML shell, global layout
│   ├── index.tsx               # Dashboard home: system overview + runner cards
│   ├── runners/
│   │   └── index.tsx           # Per-runner detail page
│   ├── runs/
│   │   └── index.tsx           # Workflow runs table
│   ├── auth/
│   │   ├── login.tsx           # Redirects to GitHub OAuth
│   │   └── callback.tsx        # OAuth callback: exchange code, create session
│   ├── api/
│   │   ├── system.ts           # JSON: system metrics (CPU, RAM, disk)
│   │   ├── runners.ts          # JSON: GitHub runners + local service status
│   │   ├── runs.ts             # JSON: recent workflow runs + jobs
│   │   └── ws.ts               # WebSocket: real-time updates
│   └── logout.tsx              # Clear session, redirect to login
├── islands/
│   ├── SystemStats.tsx         # Auto-refreshing system metric cards
│   ├── RunnerGrid.tsx          # Runner cards with live status
│   ├── RunsTable.tsx           # Runs table with auto-refresh
│   └── LiveIndicator.tsx       # WebSocket-connected status dot
├── components/
│   ├── StatCard.tsx            # Reusable stat card
│   ├── RunnerCard.tsx          # Reusable runner card
│   ├── StatusBadge.tsx         # Status badge (online/offline/busy/success/failure)
│   └── Layout.tsx              # Page layout with nav
├── lib/
│   ├── github.ts               # GitHub API client (runners, runs, jobs, repos)
│   ├── system.ts               # System metrics via shell commands
│   ├── auth.ts                 # OAuth flow, JWT creation/verification, org check
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
- Server pushes updates every 15 seconds: system metrics and runner status
- Client updates the DOM without a full page reload
- Falls back to HTTP polling if the WebSocket drops

## Pages

### `/` - Dashboard
- System overview: stat cards for CPU, RAM, disk, uptime with progress bars
- Runner grid: cards for each runner showing status, labels, service state, PID, memory
- Recent runs: table of the last 30 runs across all repos (repo, workflow, branch, commit, runner, duration, when)
- Everything auto-refreshes via WebSocket, with polling as fallback

### `/runners` - Runner details
- Per-runner view: current status, labels, service config
- Recent jobs that ran on each runner
- Resource usage over time (if we add history tracking later)

### `/runs` - Workflow runs
- Full table of recent runs across all repos
- Filter by repo, status, or runner
- Click a run to open it on GitHub

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

### Phase 5: Deploy
- Install Deno on the server
- Build and deploy
- Configure the reverse proxy
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

## Tech stack

| Layer | Technology |
|-------|-----------|
| Runtime | Deno 2 |
| Framework | Fresh 2.3 |
| UI | Preact (built into Fresh) |
| Auth | GitHub OAuth + JWT sessions |
| Real-time | Fresh 2.3 WebSockets |
| Reverse proxy | Caddy or nginx (your choice) |
| Deployment | Bare metal or VM |
