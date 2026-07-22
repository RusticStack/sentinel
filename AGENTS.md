# AGENTS.md - Vigil

## Project

Vigil is a dashboard for monitoring self-hosted GitHub Actions runners. It shows runner status, system resources, and recent workflow runs. Access is restricted to your GitHub org members through OAuth.

Built with Deno 2 and Fresh 2.3.

## Tech stack

- **Runtime:** Deno 2
- **Framework:** Fresh 2.3 (server-rendered by default, islands for interactivity)
- **UI:** Preact (bundled with Fresh)
- **Auth:** GitHub OAuth with signed JWT sessions
- **Real-time:** Fresh 2.3 WebSocket support
- **Reverse proxy:** Caddy or nginx (your choice, with TLS)

## Prerequisites

- Deno 2 installed
- A GitHub OAuth App with:
  - Homepage URL set to your dashboard URL
  - Callback URL set to `https://your-domain/auth/callback`
  - Scopes: `read:org`, `repo`

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
```

## Project structure

```
vigil/
├── routes/              # File-based routing
│   ├── _middleware.ts   # Auth: session check + org membership
│   ├── _app.tsx         # HTML shell, global layout
│   ├── index.tsx        # Dashboard home
│   ├── runners/         # Runner detail pages
│   ├── runs/            # Workflow runs page
│   ├── auth/            # OAuth login + callback
│   ├── api/             # JSON API + WebSocket
│   └── logout.tsx       # Session cleanup
├── islands/             # Client-side hydrated components
├── components/          # Server-side reusable components
├── lib/                 # Business logic (github.ts, system.ts, auth.ts, cache.ts)
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

### System metrics
- Use `Deno.Command` for shell commands (not child_process, this is Deno)
- `free -m`, `df -h /`, `/proc/loadavg`, `uptime -p`, `nproc`, `lscpu`
- `systemctl show {service}` for per-runner service state

## Deployment

### Server setup
- Install Deno 2 on the server
- Clone the repo and run `deno task build`
- Create a `.env` file with the variables listed above
- Set up a systemd service:

```ini
[Unit]
Description=Vigil Dashboard
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/vigil
EnvironmentFile=/path/to/vigil/.env
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

### Deploy steps
```bash
cd /path/to/vigil
git pull origin main
deno task build
sudo systemctl restart vigil
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

If you're running Vigil for your own self-hosted runners, this CI runs on those same runners.

## Security

- Never commit `.env` or secrets
- The JWT session secret (`SESSION_SECRET`) should be a long random string
- The OAuth client secret stays server-side, never sent to the browser
- All cookies are httpOnly, secure, sameSite=strict
- Org membership is checked on login and re-verified on each request (cached for 5 min)
- If a member leaves the org, their session stops working within 5 minutes
- The PAT used for org-scoped API queries should have minimal scopes: `admin:org` and `repo`
