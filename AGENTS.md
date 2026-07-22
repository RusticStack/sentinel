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
  - Callback URL set to `https://your-domain/auth/callback`
  - Scopes: `read:org`, `repo`
- (Optional) A running Vigil SOC instance if you want the security tab

## Development

```bash
deno task dev      # Dev server with HMR at http://localhost:8000
deno task build    # Production build
deno task start    # Run production server (build first)
deno task check    # Type-check
deno task test     # Run tests
```

## Environment variables

Create a `.env` file (don't commit it):

```env
GITHUB_CLIENT_ID=your_oauth_app_client_id
GITHUB_CLIENT_SECRET=your_oauth_app_client_secret
SESSION_SECRET=random_32_char_string
GH_ORG=your_org_name
PORT=3000
RUNNER_COUNT=4

# Optional: Vigil SOC integration
VIGIL_URL=http://localhost:6987
VIGIL_API_KEY=your_vigil_api_key
```

When `VIGIL_URL` is set, the security tab appears automatically and Sentinel pulls findings, cases, and agent activity from the Vigil backend.

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
- Use `define.middleware()` for middleware to get proper typings
- Use `define.route()` for route handlers
- Context is unified: `ctx.req`, `ctx.state`, `ctx.render()`, `ctx.next()`
- Only files in `islands/` ship JavaScript to the browser
- Everything else is server-rendered HTML

### Auth flow
1. `_middleware.ts` runs on every request
2. Checks for the session cookie, verifies the JWT signature and expiry
3. If valid, checks org membership (cached for 5 min) and sets `ctx.state.user`
4. If missing or invalid, redirects to `/auth/login` (except for `/auth/*` routes)
5. `/auth/login` redirects to GitHub OAuth
6. `/auth/callback` exchanges the code, verifies membership, creates the JWT, sets the cookie

### GitHub API usage
- Use the user's OAuth token for user-scoped queries (org membership)
- Use a stored PAT (env var) for org-scoped queries (runners, repos, runs) since the OAuth token may not have admin:org scope
- Cache all API responses with TTL to stay within rate limits
- See `plan.md` for cache TTLs per endpoint

### Vigil API usage
- Sentinel talks to the Vigil FastAPI backend (default port 6987)
- Pulls findings, cases, and agent activity status
- All Vigil API responses are cached with TTL (see `plan.md`)
- The security tab and related routes are only registered when `VIGIL_URL` is set

### System metrics
- Use `Deno.Command` for shell commands (not child_process, this is Deno)
- `free -m`, `df -h /`, `/proc/loadavg`, `uptime -p`, `nproc`, `lscpu`
- `systemctl show {service}` for per-runner service state

## Vigil SOC integration

[Vigil](https://github.com/Vigil-SOC/vigil) is an open-source AI SOC with 13 agents for security operations. Sentinel connects to its backend API and surfaces findings in a dedicated security tab.

### Setting up Vigil with Ollama Cloud
Vigil uses Bifrost as its LLM gateway. By default it routes to Anthropic Claude. To use Ollama Cloud's free tier instead:

1. Fork `Vigil-SOC/vigil` to your org
2. Add an Ollama provider to `docker/bifrost/config.json`:

```json
{
  "providers": {
    "ollama": {
      "keys": [{
        "name": "ollama-cloud",
        "value": "your_ollama_api_key",
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

3. Set env vars: `OLLAMA_ENABLED=true`, `OLLAMA_URL=https://ollama.com`, `DEFAULT_LLM_PROVIDER=ollama`
4. Pick a free-tier model: `gpt-oss:120b-cloud`, `gpt-oss:20b-cloud`, `gemma3:27b-cloud`, or `glm-4.7:cloud`
5. Check [the unofficial free-tier tracker](https://github.com/OshriFatkiev/ollama-cloud-free-tier) for which models currently work on free

### Vigil fork maintenance
- Keep the fork tracking upstream. Vigil is actively developed.
- Put Bifrost config changes in a separate branch so rebasing on upstream stays clean
- The upstream `env.example` already has Ollama settings, but the Bifrost config was missing the Ollama provider entry (issue #324). The fork fixes this.

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

- Put a reverse proxy in front with TLS. Caddy example:

```
your-domain.com {
    reverse_proxy 127.0.0.1:3000
}
```

### With Vigil SOC
- Deploy your Vigil fork on the same server or a separate one
- Configure Bifrost with Ollama Cloud (see above)
- Set `VIGIL_URL` in Sentinel's `.env` pointing to the Vigil backend
- The security tab appears automatically

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
- The PAT used for org-scoped API queries should have minimal scopes: `admin:org` and `repo`
- The Vigil API key (if used) is server-side only and never exposed to the browser
