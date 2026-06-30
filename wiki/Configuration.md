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
| `CREDENTIAL_ENCRYPTION_KEY` | ✅ | **64-char hex** key (AES-256-GCM) used to encrypt scanner credentials, the AI builder API key, *and* per-user MFA secrets at rest. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. **If you lose/rotate this, stored encrypted credentials can't be decrypted.** |

### Two-factor authentication (MFA)

Per-account **TOTP** MFA for local users — **Settings → Security**. It's optional and opt-in: enabling it for one account doesn't affect anyone else's login, and accounts without it log in with just a password as before (recommended for admins). Enroll by scanning the key into an authenticator app (Google Authenticator, Authy, 1Password, …) and confirming a 6-digit code; you're then shown **one-time recovery codes** — save them. At login, MFA-enabled accounts are prompted for a code (or a recovery code). The TOTP secret is stored encrypted with `CREDENTIAL_ENCRYPTION_KEY`. To turn it off, use **Settings → Security → Disable MFA** with a current code; if you've lost both your authenticator and recovery codes, an admin can clear `mfa_enabled`/`mfa_secret` for the row in the `users` table.

## AI builder (optional)

The AI parser/detection builders are bring-your-own-key. Set a provider key here, **or** enter it in the UI (*Settings → AI Builder*), where it is stored encrypted with `CREDENTIAL_ENCRYPTION_KEY`.

| Variable | Notes |
|----------|-------|
| `ANTHROPIC_API_KEY` | For the Anthropic provider. |
| `OPENAI_API_KEY` | For the OpenAI provider. |
| *(Ollama)* | Local Ollama needs no key — set the base URL in *Settings → AI Builder*. |

See [Parsers → AI builder](Parsers#ai-builder) and [Detection Rules](Detection-Rules).

## AI Security Analyst (optional)

The **[AI Security Analyst](AI-Security-Analyst)** has its own model configuration under **Settings → AI Analyst** — provider (`ollama` / `openai` / `anthropic`), model, base URL, and (for cloud) API key (encrypted with `CREDENTIAL_ENCRYPTION_KEY`). Leave a field blank to **inherit** the AI builder config above, so the Analyst can reuse the same provider or point at a different — e.g. a local Ollama — model. The `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env vars apply here too.

## Parser / detection catalog

| Variable | Default | Notes |
|----------|---------|-------|
| `SIEMBOX_CATALOG_REPO` | `cladkins/siembox-parsers` | GitHub repo backing the in-app catalog. |
| `SIEMBOX_CATALOG_REF` | `main` | Branch/tag/ref to read. |
| `SIEMBOX_CATALOG_PARSERS_PATH` | `parsers` | Directory in the catalog repo for parsers. |
| `SIEMBOX_CATALOG_DETECTIONS_PATH` | `detections` | Directory in the catalog repo for detection rules. |
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

## Endpoints & YARA (optional)

Endpoint agents (see [SIEMBOX Endpoint](SIEMBOX-Endpoint)) are enrolled from the UI; the server delivers YARA rule packs to them.

| Variable | Default | Notes |
|----------|---------|-------|
| `EDR_YARA_FORGE_ENABLED` | *(off)* | Set `true` to import the open-source **YARA-Forge** pack daily and publish a new bundle when it changes. Admins can also pull on demand from *Endpoints*. |
| `EDR_YARA_KEEP_VERSIONS` | `10` | How many YARA bundle versions to retain server-side (older are pruned; agents always pull the newest). |

## In-UI settings

Some configuration lives in **Settings** rather than env vars:

- **AI Builder** — provider, model, base URL, API key.
- **AI Analyst** — the analyst's provider/model (inherits AI Builder if left blank). See [AI Security Analyst](AI-Security-Analyst).
- **Endpoints / YARA** — endpoint enrollment tokens and the server YARA bundle (incl. *Pull YARA-Forge now*). See [SIEMBOX Endpoint](SIEMBOX-Endpoint).
- **Threat Feeds & Reputation** — enable/disable feeds, add AbuseIPDB/AlienVault OTX keys (admin-gated). See [Threat Intel](Threat-Intel).
- **Notifications** — Email / Slack / NTFY alert delivery.
- **Retention** — log retention window and automated cleanup.
