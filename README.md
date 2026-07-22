# Vigil

A dashboard for monitoring self-hosted GitHub Actions runners. Shows runner status, system resources, and recent workflow runs in real time. Access is gated by GitHub OAuth with org membership checks.

Built with Deno 2 and [Fresh 2.3](https://fresh.deno.dev/). Server-rendered by default, with islands of interactivity only where needed.

## Features

- **Runner overview** - status, labels, service state, PID, memory usage per runner
- **System metrics** - CPU, RAM, disk, load average, uptime
- **Workflow runs** - recent runs across all your org repos, which runner executed them, duration, status
- **Real-time updates** - WebSocket push for live status changes (no polling)
- **GitHub OAuth** - only your org members can log in, no shared passwords or tokens
- **Dark theme** - easy on the eyes

## Quick start

```bash
# Install Deno 2 first: https://deno.land/
git clone https://github.com/RusticStack/vigil.git
cd vigil
cp .env.example .env  # fill in your values
deno task dev
```

## Configuration

You need a GitHub OAuth App:

1. Go to GitHub Settings -> Developer settings -> OAuth Apps -> New OAuth App
2. Set the homepage URL to your dashboard URL
3. Set the callback URL to `https://your-domain/auth/callback`
4. Request scopes: `read:org` and `repo`

Environment variables:

| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | OAuth App client secret |
| `SESSION_SECRET` | Random string for JWT signing (32+ chars) |
| `GH_ORG` | GitHub org name |
| `PORT` | Server port (default: 3000) |
| `RUNNER_COUNT` | Number of runner instances (default: 4) |

## Deployment

Check [AGENTS.md](AGENTS.md) and [plan.md](plan.md) for detailed setup, architecture, and deployment instructions.

## Requirements

- Deno 2
- A Linux server with systemd (for the runner service monitoring)
- A reverse proxy with TLS (Caddy or nginx)
- GitHub org with self-hosted runners registered

## License

MIT
