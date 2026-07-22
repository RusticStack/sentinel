# Deploy Sentinel

Production deploy guide for a Linux host (systemd + reverse proxy + TLS). Artifacts live under [`deploy/`](../deploy/).

**Status:** configs and hardening docs are in-repo. Live VPS cutover and end-to-end HTTPS verification remain a manual ops step (see [Post-deploy E2E checklist](#post-deploy-e2e-checklist)).

## Ports

| Mode | How | Default URL |
|------|-----|-------------|
| Dev (`deno task dev`) | Vite `server.port` in `vite.config.ts` | `http://localhost:8000` |
| Prod (`deno task start`) | Hardcoded `--port=3000` in `deno.json` (Deno tasks do **not** expand `${PORT:-3000}`) | `http://127.0.0.1:3000` |
| Prod (systemd) | `deno serve --port=${PORT}` (systemd expands `PORT` from `EnvironmentFile`) | bind localhost; public HTTPS via Caddy/nginx |

`PORT` in `.env` / EnvironmentFile does **not** change the Vite dev server. Only the production listen port (systemd) uses it.

## Quick production path

1. Install [Deno 2](https://deno.land/) on the host.
2. Clone the repo; `cp .env.example /etc/sentinel/sentinel.env` and fill secrets (`chmod 600`).
3. Set `APP_BASE_URL=https://your-domain` (required off localhost).
4. `deno task build` then install [`deploy/sentinel.service`](../deploy/sentinel.service).
5. Put Caddy ([`deploy/Caddyfile`](../deploy/Caddyfile)) or nginx ([`deploy/nginx.conf.example`](../deploy/nginx.conf.example)) in front with TLS.
6. Point the GitHub OAuth App callback at `https://your-domain/auth/callback`.
7. Run the [post-deploy E2E checklist](#post-deploy-e2e-checklist).

## systemd

Template: [`deploy/sentinel.service`](../deploy/sentinel.service).

- `EnvironmentFile=` for secrets (never bake secrets into the unit).
- File permissions: `chmod 600`, owner `root:sentinel` (or root-only).
- `Restart=on-failure` + `StartLimitBurst` (recover without infinite crash loops).
- `ExecStart` calls `deno serve` directly with `--port=${PORT}` (systemd expansion). Prefer this over `deno task start` in production so `PORT` from the env file is honored.
- `ReadWritePaths=` must include the session DB directory (`SESSION_DB_PATH`, default `data/` under the app).

```bash
sudo cp deploy/sentinel.service /etc/systemd/system/sentinel.service
# edit paths / user / EnvironmentFile
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel
sudo systemctl status sentinel
```

## Reverse proxy

Fresh is constructed with `trustProxy: true` in `main.ts` so `ctx.url` honors `X-Forwarded-Proto` / `X-Forwarded-Host` behind TLS. Only enable this behind a proxy you control.

- **Caddy (recommended):** [`deploy/Caddyfile`](../deploy/Caddyfile) (automatic HTTPS; WebSockets work by default).
- **nginx:** [`deploy/nginx.conf.example`](../deploy/nginx.conf.example) (explicit `/api/ws` Upgrade headers).

Bind Sentinel to `127.0.0.1` (or a private interface). Do not expose port 3000 publicly.

## Environment checklist

| Variable | Required | Notes |
|----------|----------|-------|
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | yes | OAuth App; secret stays server-side |
| `SESSION_SECRET` | yes | ≥32 random chars |
| `SESSION_DB_PATH` | no | Default `data/sessions.db` (keep out of git; `.gitignore` has `data/`) |
| `GH_ORG` | yes | Org membership gate |
| `GITHUB_PAT` | yes | Classic PAT: `admin:org` + `repo` only |
| `APP_BASE_URL` | yes (prod) | Public `https://…` origin for OAuth `redirect_uri` + Secure cookies |
| `PORT` | yes (systemd) | Production listen port (e.g. `3000`) |
| `RUNNER_COUNT` | no | Default `4` |
| `VIGIL_URL` / `VIGIL_USERNAME` / `VIGIL_PASSWORD` | no | Enables security tab; creds never sent to the browser |

## Security review checklist (OWASP-oriented)

Use this before exposing a public URL. Code already implements the cookie/session model described in `AGENTS.md`; verify it still holds after changes.

### Cookies & sessions

- [ ] Session cookie: `HttpOnly`, `Secure` on HTTPS, `SameSite=Strict`, `__Host-` prefix on HTTPS
- [ ] OAuth handshake cookie: `HttpOnly`, `Secure` on HTTPS, `SameSite=Lax`, integrity-sealed (state + PKCE)
- [ ] Cookie holds only an opaque ID; authoritative session is in Deno KV
- [ ] Logout / membership denial deletes the server record (immediate revocation)
- [ ] Absolute (~12h) and idle (~2h) TTLs enforced server-side
- [ ] `APP_BASE_URL` pins OAuth `redirect_uri` and Secure-cookie decisions (do not trust `Host` / `X-Forwarded-*` alone)

### Secrets & tokens

- [ ] `.env` / EnvironmentFile not in git; `data/` not in git
- [ ] `SESSION_SECRET`, OAuth client secret, `GITHUB_PAT`, Vigil password never logged or returned in HTML/JSON API responses
- [ ] Login OAuth scope is `read:org` only; org runners/runs use `GITHUB_PAT`
- [ ] `GITHUB_PAT` scopes limited to `admin:org` + `repo`
- [ ] Vigil JWT / password used only in server-side `lib/vigil.ts`

### Edge / deploy

- [ ] TLS at reverse proxy; HTTP redirects to HTTPS
- [ ] HSTS enabled at the proxy (see Caddy/nginx examples)
- [ ] App not directly reachable on the public interface
- [ ] `trustProxy: true` only behind your proxy
- [ ] systemd unit uses a non-root user + `EnvironmentFile` with restrictive permissions

### Org gate

- [ ] Non-members redirected / denied; pending invites denied (`state=active` only)
- [ ] Membership re-check on requests (cached ~5 min); confirmed non-members lose session

## Post-deploy E2E checklist

**Deferred until a public HTTPS host is available.** Run on the runner host after DNS + TLS + systemd are live:

1. [ ] `curl -I https://your-domain` → 200/302 over valid TLS
2. [ ] Unauthenticated `/` → redirect to `/auth/login`
3. [ ] Org member: GitHub OAuth → dashboard (runners + system meters)
4. [ ] Non-member (or pending invite) → denied; session not usable
5. [ ] `/runners` and `/runs` render; filters work
6. [ ] WebSocket `/api/ws` connects (or poll fallback still updates)
7. [ ] Logout clears session; refresh requires login again
8. [ ] (Optional) With `VIGIL_URL` set: Security tab + findings; with it unset: tab hidden / empty setup
9. [ ] Confirm cookies: `__Host-sentinel_session` with `Secure; HttpOnly; SameSite=Strict`
10. [ ] `systemctl restart sentinel` recovers cleanly; proxy still healthy

## Deploy / update commands

```bash
cd /opt/sentinel
git pull origin main
deno task check
deno task test
deno task build
sudo systemctl restart sentinel
sudo systemctl status sentinel
```
