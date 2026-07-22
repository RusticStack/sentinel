# Vigil SOC deploy notes (optional)

Sentinel talks to Vigil over HTTP only (`findings` / `cases` / `agents` + login).
LLM provider choice is a **Vigil deploy** concern: Sentinel does not fork or patch Vigil for chat.

## Lean deploy for Sentinel integration

1. Run upstream [Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil) (Docker compose is fine).
2. Create a dedicated Vigil service user (least privilege).
3. In Sentinel `.env`:

```env
VIGIL_URL=http://127.0.0.1:6987
VIGIL_USERNAME=sentinel_service_user
VIGIL_PASSWORD=…
```

4. Confirm `POST /api/auth/login` returns `access_token` + `refresh_token`.
5. Sentinel caches the JWT server-side and reads:
   - `GET /api/findings` (30s TTL)
   - `GET /api/cases` (30s TTL)
   - `GET /api/findings/{id}` (60s TTL)
   - `GET /api/agents/agents` (15s TTL). There is **no** `/api/agents/status`

Unset `VIGIL_URL` → Security nav hidden; `/security` shows a setup empty state; CI dashboard unchanged.

## Other-org LLM profile (Ollama Cloud)

Prefer free Cloud models that remain available: **`gpt-oss:20b`** / **`gpt-oss:120b`** (check [Ollama Cloud docs](https://docs.ollama.com/cloud) for retirements).

Upstream Bifrost already ships `providers.ollama` in `docker/bifrost/config.json` (wired to `env.OLLAMA_URL`). Point that at Cloud:

```json
"ollama_key_config": { "url": "https://ollama.com" }
```

plus Bifrost key `value` for the Cloud API key, and Vigil env such as:

```env
OLLAMA_ENABLED=true
OLLAMA_URL=https://ollama.com
DEFAULT_LLM_PROVIDER=ollama
OLLAMA_DEFAULT_MODEL=gpt-oss:20b
```

## Fork vs upstream?

**Default: stay on upstream.** Sentinel does not need a Vigil fork.

Fork (or wait for upstream PRs) only if you need **Vigil UI agent chat** on Ollama without Anthropic:

| Issue | Topic | Status (checked 2026-07-22) |
|-------|--------|-----------------------------|
| [#324](https://github.com/Vigil-SOC/vigil/issues/324) | Bifrost `providers.ollama` | Still open as an issue, but **main already contains** an `ollama` provider block: treat as largely addressed in tree |
| [#327](https://github.com/Vigil-SOC/vigil/issues/327) / [#328](https://github.com/Vigil-SOC/vigil/issues/328) | Chat endpoints hardcode `ClaudeService` | Still open: blocks non-Anthropic **streaming/chat UI** |
| [#377](https://github.com/Vigil-SOC/vigil/pull/377) | Route service LLM calls via configured provider | Open (enrichment / service path; not a full #327/#328 fix by itself) |

**Recommendation:** use upstream for Sentinel’s API integration. If you must run Ollama-only agent chat in Vigil’s UI before #327/#328 land, maintain a minimal patch branch: do not fork for Sentinel alone.
