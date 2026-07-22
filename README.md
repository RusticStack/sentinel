# Sentinel

Dashboard for self-hosted GitHub Actions runners. It shows runner status, host resources, and recent workflow runs, with live updates over WebSocket (HTTP poll fallback). Access is gated by GitHub OAuth: only members of your org can sign in.

Optional [Vigil SOC](https://vigilsoc.org/) integration adds a Security tab for findings, cases, and agents when `VIGIL_URL` is set.

Built with [Deno 2](https://deno.land/) and [Fresh 2.3](https://fresh.deno.dev/).

## Requirements

- Deno 2
- Linux host with systemd (app service and runner `systemctl` metrics)
- Reverse proxy with TLS (Caddy or nginx)
- GitHub org with self-hosted runners
- GitHub OAuth App + classic PAT (see below)
- Optional: Vigil SOC instance for the Security tab

## Configure

1. Create a GitHub OAuth App (Settings → Developer settings → OAuth Apps):
   - Homepage URL: your dashboard URL
   - Authorization callback URL: `https://your-domain/auth/callback`
   - Login requests `read:org` only (set on the authorize URL; not an OAuth App form field)
2. Create a classic PAT with `admin:org` and `repo` for org runner and run APIs
3. Copy env and fill values:

```bash
cp .env.example .env
```

| Variable | Purpose |
|----------|---------|
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | OAuth App (secret stays on the server) |
| `SESSION_SECRET` | ≥32 chars; handshake seal + session-id HMAC |
| `SESSION_DB_PATH` | Deno KV path (default `data/sessions.db`; not committed). Also stores capped host metric history for sparklines. |
| `GH_ORG` | Org membership gate |
| `GITHUB_PAT` | Classic PAT: `admin:org` + `repo` |
| `APP_BASE_URL` | Public origin for OAuth `redirect_uri` and Secure cookies (**required** off localhost) |
| `PORT` | Production listen port for systemd (`deno serve --port=${PORT}`). Does not change Vite. `deno task start` uses 3000. |
| `RUNNER_COUNT` | Expected runner count (default `4`) |
| `VIGIL_URL` / `VIGIL_USERNAME` / `VIGIL_PASSWORD` | Optional Vigil; enables Security tab |

## Run (production)

```bash
deno task build
deno task start   # http://127.0.0.1:3000
```

Put a reverse proxy in front with TLS. Templates:

- [`deploy/sentinel.service`](deploy/sentinel.service) (systemd + `EnvironmentFile`)
- [`deploy/Caddyfile`](deploy/Caddyfile) or [`deploy/nginx.conf.example`](deploy/nginx.conf.example)

`main.ts` sets Fresh `trustProxy: true` so redirects and absolute URLs see the public host. Bind the app to localhost; do not expose port 3000 publicly.

Full checklist (security review + post-deploy E2E): [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Auth

Unauthenticated visitors are sent to `/auth/login`. After GitHub OAuth, Sentinel confirms **active** org membership and creates a server-side session in Deno KV. The browser cookie holds only an opaque ID (no GitHub token). Logout and membership denial delete the session immediately.

## Vigil (optional)

When `VIGIL_URL` is set, Sentinel logs in as a Vigil service user, caches the JWT server-side, and shows Security. There is no shared API key for findings/cases/agents. See [`docs/VIGIL.md`](docs/VIGIL.md).

## Development

```bash
deno task dev     # http://localhost:8000 (Vite; port in vite.config.ts)
deno task check
deno task test
```

Contributor and ops notes: [`AGENTS.md`](AGENTS.md).

## License

MIT
