# Sentinel

A dashboard for monitoring self-hosted GitHub Actions runners. Shows runner status, system resources, and recent workflow runs in real time. Access is gated by GitHub OAuth with org membership checks.

Optionally integrates with [Vigil SOC](https://vigilsoc.org/), an open-source AI security operations platform, to surface security findings alongside CI metrics.

Built with Deno 2 and [Fresh 2.3](https://fresh.deno.dev/). Server-rendered by default, with islands of interactivity only where needed.

## Features

- **Runner overview** - status, labels, service state, PID, memory usage per runner
- **System metrics** - CPU, RAM, disk, load average, uptime
- **Workflow runs** - recent runs across all your org repos, which runner executed them, duration, status
- **Real-time updates** - WebSocket push for live status changes (no polling)
- **GitHub OAuth** - only your org members can log in, no shared passwords or tokens
- **Vigil SOC integration** (optional) - security findings, active cases, and agent activity from a Vigil instance, shown in a dedicated security tab
- **Dark theme** - easy on the eyes

## Quick start

```bash
# Install Deno 2 first: https://deno.land/
git clone https://github.com/RusticStack/sentinel.git
cd sentinel
cp .env.example .env  # fill in your values
deno task dev
```

## Configuration

You need a GitHub OAuth App:

1. Go to GitHub Settings -> Developer settings -> OAuth Apps -> New OAuth App
2. Set the homepage URL to your dashboard URL
3. Set the authorization callback URL to `https://your-domain/auth/callback`
4. At login, request scopes `read:org` and `repo` on the authorize URL
5. Create a classic PAT with `admin:org` and `repo` for org runner/run API calls

Environment variables:

| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | OAuth App client secret |
| `SESSION_SECRET` | Random string for JWT signing (32+ chars) |
| `GH_ORG` | GitHub org name |
| `GITHUB_PAT` | PAT with `admin:org` + `repo` for org runners/runs |
| `PORT` | Production server port (wire via `deno serve --port`) |
| `RUNNER_COUNT` | Number of runner instances (default: 4) |
| `VIGIL_URL` | URL of Vigil backend (optional, enables security tab) |
| `VIGIL_USERNAME` | Vigil service-user username (optional) |
| `VIGIL_PASSWORD` | Vigil service-user password (optional) |

## Vigil SOC integration

Sentinel can connect to a [Vigil SOC](https://github.com/Vigil-SOC/vigil) instance and surface security findings alongside your CI runner health. When `VIGIL_URL` is set, a security tab appears in the UI. Vigil APIs require a Vigil user JWT — use a dedicated service user (`VIGIL_USERNAME` / `VIGIL_PASSWORD`), not a fictional shared API key.

Vigil uses Bifrost as its LLM gateway and supports Ollama as a provider. You can point it at [Ollama Cloud](https://ollama.com). See [AGENTS.md](AGENTS.md) for the full setup guide (including open Vigil issues that still affect non-Anthropic chat).

## Deployment

Check [AGENTS.md](AGENTS.md) and [plan.md](plan.md) for detailed setup, architecture, and deployment instructions.

## Requirements

- Deno 2
- A Linux server with systemd (for the runner service monitoring)
- A reverse proxy with TLS (Caddy or nginx)
- GitHub org with self-hosted runners registered
- (Optional) A Vigil SOC instance for the security integration

## License

MIT
