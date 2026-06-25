# Configuration

SIEMBox is configured with environment variables (a `.env` file next to your compose file). Copy [`.env.example`](https://github.com/cladkins/SIEMBOX/blob/main/.env.example) and edit it. Some settings (the AI builder key, threat-feed/reputation providers, retention) can also be managed in the UI under **Settings**.

## Core

| Variable | Default | Notes |
|----------|---------|-------|
| `NODE_ENV` | `production` | Runtime mode. |
| `PORT` | `8421` | Backend API port (inside the container). |
| `HOST` | `0.0.0.0` | Bind address. |
| `LOG_LEVEL` | `info` | Backend log verbosity. |
| `CORS_ORIGIN` | `*` | Allowed origin(s) for the API. |
| `VITE_API_URL` | `/api` | Where the frontend calls the API. |

## Database

| Variable | Default | Notes |
|----------|---------|-------|
| `DB_HOST` | `postgres` | Compose service name. |
| `DB_PORT` | `5432` | |
| `DB_NAME` | `siembox` | |
| `DB_USER` | `siembox` | |
| `DB_PASSWORD` | `changeme` | **Change this.** |

## Security & secrets

| Variable | Required | Notes |
|----------|----------|-------|
| `JWT_SECRET` | ✅ | Signs session tokens; use a long random string (32+ chars). Tokens are valid 24h. |
| `DEFAULT_ADMIN_PASSWORD` | ✅ | Initial password for the `admin` user. |
| `CREDENTIAL_ENCRYPTION_KEY` | ✅ | **64-char hex** key (AES-256-GCM) used to encrypt scanner credentials *and* the AI builder API key at rest. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. **If you lose/rotate this, stored encrypted credentials can't be decrypted.** |

## AI builder (optional)

The AI parser/detection builders are bring-your-own-key. Set a provider key here, **or** enter it in the UI (*Settings → AI Builder*), where it is stored encrypted with `CREDENTIAL_ENCRYPTION_KEY`.

| Variable | Notes |
|----------|-------|
| `ANTHROPIC_API_KEY` | For the Anthropic provider. |
| `OPENAI_API_KEY` | For the OpenAI provider. |
| *(Ollama)* | Local Ollama needs no key — set the base URL in *Settings → AI Builder*. |

See [Parsers → AI builder](Parsers#ai-builder) and [Detection Rules](Detection-Rules).

## Parser / detection catalog

| Variable | Default | Notes |
|----------|---------|-------|
| `SIEMBOX_CATALOG_REPO` | `cladkins/siembox-parsers` | GitHub repo backing the in-app catalog. |
| `SIEMBOX_CATALOG_REF` | `main` | Branch/tag/ref to read. |
| `GITHUB_TOKEN` | — | Optional, raises GitHub API rate limits for catalog browsing. |
| `SEED_BUNDLED_CONTENT` | *(unset = catalog-only)* | Set `true` to opt back into auto-importing bundled detection rules on startup (legacy). Defaults to catalog-only. |

## GeoIP enrichment

Offline country / foreign-geo enrichment (DB-IP IP-to-Country Lite, CC BY 4.0). No external calls. See [Threat Intel](Threat-Intel).

| Variable | Default | Notes |
|----------|---------|-------|
| `GEOIP_DB_PATH` | `/app/data/dbip-country-lite.mmdb` | MMDB path inside the container. |
| `GEOIP_HOME_COUNTRIES` | *(empty)* | Comma-separated ISO-2 home countries (e.g. `US,CA`). Logins from elsewhere get `geo_foreign=true`. Empty disables foreign-country detection. |

## Container scanning (optional)

Docker-host image discovery requires mounting the Docker socket into the backend; it is **commented out by default**. See the security note in [Vulnerability & Container Scanning](Vulnerability-and-Container-Scanning#docker-host-discovery) before enabling it (`:ro` does **not** make the Docker API read-only — socket access is root-equivalent on the host).

## In-UI settings

Some configuration lives in **Settings** rather than env vars:

- **AI Builder** — provider, model, base URL, API key.
- **Threat Feeds & Reputation** — enable/disable feeds, add AbuseIPDB/GreyNoise keys (admin-gated). See [Threat Intel](Threat-Intel).
- **Notifications** — Email / Slack / NTFY alert delivery.
- **Retention** — log retention window and automated cleanup.
