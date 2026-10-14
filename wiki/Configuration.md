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

## Client addresses & reverse proxies

Rate limits, audit rows and shipper records use each client's address. The web UI's nginx reaches the backend over a unix socket on the `api-socket` volume (both compose files mount it), so browsers keep their real addresses. A direct caller on port 8421 (shipper, endpoint agent, script) is its TCP address: `X-Forwarded-For` and `X-Real-IP` from it are ignored unless it is listed in `TRUSTED_PROXIES`. See [DEPLOYMENT.md, "Client addresses and reverse proxies"](https://github.com/cladkins/SIEMBOX/blob/main/DEPLOYMENT.md#client-addresses-and-reverse-proxies) for every deployment mode, and check what the API sees at `GET /api/admin/client-address` (admin).

| Variable | Default | Notes |
|----------|---------|-------|
| `TRUSTED_PROXIES` | `frontend` | Comma-separated IPs, CIDRs or Compose service names whose `X-Forwarded-For` is believed (any hop). Names are looked up in Docker's DNS only, and an answer only counts when it is on the backend's own networks and Docker confirms it as a container there (so a LAN DNS server answering for the name doesn't count; on a macvlan or ipvlan network, list addresses instead). The value **replaces** the default, so keep `frontend` when adding a reverse proxy: `frontend,192.168.1.20`. `none` trusts only the socket. `*`, `true`, `/0` ranges, Express presets (`loopback`, …), hop counts and malformed entries are rejected (logged as errors); ranges wider than /24 (IPv4) or /64 (IPv6) log a warning. IPv6 entries never match IPv4 addresses. The Docker gateway is never trusted through a range. |
| `API_RATE_LIMIT_MAX` | `1000` | Requests per 15 minutes per client address across `/api`. A `429` is JSON with `Retry-After`. |
| `EDR_AGENT_RATE_MAX` | `30000` | Requests per 15 minutes per address on the EDR agent routes, which skip the general limit. |
| `SHIPPER_LOG_PUSH_MAX` | `6000` | Requests per 15 minutes per address on `POST /api/shippers/logs`, which skips the general limit. |
| `SIEMBOX_PROXY_SOCKET` | `/run/siembox/api.sock` | Where the backend listens for the frontend's nginx. Leave it unset, or set `off` to run without the socket: the bundled nginx only connects to `/run/siembox/api.sock`, so another path leaves the web UI on TCP (only a proxy of your own could use it). It only listens when the directory exists (the volume is mounted). |

POST `/api/auth/login` also allows at most **10 failed sign-ins per account per 15 minutes per address** (IPv6: per /64), and 100 per address across all accounts; past those, only accounts that already failed from that address are refused, so users who share an address don't lock each other out. Successful sign-ins don't count. Counters are in memory and reset when the backend restarts.

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
| `CREDENTIAL_ENCRYPTION_KEY` | ✅ | **64-char hex** key (AES-256-GCM) used to encrypt scanner credentials, the AI builder and Have I Been Pwned API keys, *and* per-user MFA secrets at rest. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. **If you lose/rotate this, stored encrypted credentials can't be decrypted.** |

### Two-factor authentication (MFA)

Per-account **TOTP** MFA for local users — **Settings → Account**. It's optional and opt-in: enabling it for one account doesn't affect anyone else's login, and accounts without it log in with just a password as before (recommended for admins). Enroll by scanning the key into an authenticator app (Google Authenticator, Authy, 1Password, …) and confirming a 6-digit code; you're then shown **one-time recovery codes** — save them. At login, MFA-enabled accounts are prompted for a code (or a recovery code). The TOTP secret is stored encrypted with `CREDENTIAL_ENCRYPTION_KEY`. To turn it off, use **Settings → Account → Disable MFA** with a current code; if you've lost both your authenticator and recovery codes, an admin can clear `mfa_enabled`/`mfa_secret` for the row in the `users` table.

## AI builder (optional)

The AI parser/detection builders are bring-your-own-key. Set a provider key here, **or** enter it in the UI (*Settings → AI Builder*), where it is stored encrypted with `CREDENTIAL_ENCRYPTION_KEY`.

| Variable | Notes |
|----------|-------|
| `ANTHROPIC_API_KEY` | For the Anthropic provider. |
| `OPENAI_API_KEY` | For the OpenAI provider. |
| *(Ollama)* | Local Ollama needs no key — set the base URL in *Settings → AI Builder*. |

A key entered in the UI is only sent to the provider and base URL it was saved for, in all three AI settings (AI Builder, AI Analyst, AI Triage). Changing the provider or base URL asks for the key again: enter the key for the new one, or remove the saved key to use the environment variable. A key set with `OPENAI_API_KEY` goes to whichever OpenAI base URL is set.

See [Parsers → AI builder](Parsers#ai-builder) and [Detection Rules](Detection-Rules).

## AI Security Analyst (optional)

The **[AI Security Analyst](AI-Security-Analyst)** has its own model configuration under **Settings → AI Analyst** — provider (`ollama` / `openai` / `anthropic`), model, base URL, and (for cloud) API key (encrypted with `CREDENTIAL_ENCRYPTION_KEY`). Leave a field blank to **inherit** the AI builder config above, so the Analyst can reuse the same provider or point at a different — e.g. a local Ollama — model. The `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env vars apply here too.

## AI Triage (optional)

[Automated triage](AI-Security-Analyst#automated-triage) runs the Analyst's read-only tool loop automatically on new alerts. It's **off by default**; enable it and set its options under **Settings → AI Triage**:

- **Enabled** — off until switched on.
- **Minimum severity** — only alerts at or above this severity are analyzed automatically (default: medium).
- **Daily cap** / **Max concurrent** — bound cost and load; a duplicate-alert dedupe window is also applied automatically.
- **Provider / Model / Base URL / API key** — a third independent model selection. Leave the provider blank to **inherit** the AI Analyst (chat) config above (which itself may inherit the AI builder config), or point triage at its own model.

Applying a manual "Analyze now" / "Re-run" from the UI bypasses the severity gate (but not the daily cap or concurrency limit) and works even while automatic triage is disabled.

## Digital Risk (optional)

Watches for your organization's exposure outside your network. Admins configure it under **Settings → Digital Risk** (or the optional *Digital Risk* step of the Getting Started checklist, which saves to the same place):

- **Owned domains** and **brand / lookalike domains** — bare hostnames such as `example.com` (no scheme, port, path, wildcard or IP), checked by domain monitoring on each domain's interval (daily by default; no API key needed). An owned domain is watched for DNS changes (NS, MX, TXT/SPF, DMARC, A/AAAA), registration changes and upcoming expiry (RDAP), new TLS certificates (Certificate Transparency, via crt.sh) and newly registered lookalikes; a brand domain only for lookalikes and the certificates issued for them. Each check's first run records a baseline silently, so only later changes raise findings and alerts (`source = domain-monitor`); an upcoming expiry, and certificates from a CA outside the domain's `expected_cas`, are reported straight away. Renewing a domain doesn't close its expiry warning: once the warning's date has passed, its detail says so rather than calling the domain expired, so resolve it once the renewal is confirmed (a registration that actually lapsed raises a separate *expired* finding). Which checks run for a domain, and its `expected_cas` (the unexpected-CA check is off while that list is empty), are set through the [API](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/API.md#exposure-monitoring-digital-risk). If domain monitoring is switched off (`exposure_domain_monitor_enabled`) or your version doesn't include it yet, the domain cards say so and domains are only saved.
- **Breach-monitored identities** — email addresses, or whole email domains, checked against [Have I Been Pwned](https://haveibeenpwned.com) (HIBP) in the background. Each breach becomes a finding and, the first time, an alert (`source = leaked-creds`). An **email domain** is only searchable once it's verified on your HIBP account, in the [HIBP dashboard](https://haveibeenpwned.com/Dashboard/Redirect/Domains). SIEMBox reads which of your domains are verified (HIBP's verified-domain list, refreshed at most every few hours, and only when an email domain is due) and skips the others: they read **Not verified**, with no error and no wasted HIBP call, until you verify them and click **Re-check HIBP verification**. Each subdomain is verified separately at HIBP. A verified domain larger than your HIBP plan covers is still searched, but HIBP then returns only its subscription-free breaches: SIEMBox marks it *may be limited*. On a plan without domain search (HIBP's High RPM plans) email domains are skipped and email addresses still checked.
- **HIBP API key** — bring your own ([get one](https://haveibeenpwned.com/API/Key)). It's stored encrypted with `CREDENTIAL_ENCRYPTION_KEY` and never shown again, so the field is always empty; *Remove key* is the only way to clear it, and saving fails with a clear message if `CREDENTIAL_ENCRYPTION_KEY` isn't set. *Test key* validates it (HIBP's public test key always fails that test by design). Under **Domain search**, the Have I Been Pwned card lists the domains verified on the key's account with their breached-address counts and whether the plan covers them, and offers **Monitor** for a verified domain you don't monitor yet; **Re-check** asks HIBP again (at most once a minute). Opening the page never calls HIBP.
- **Notifications and checks** — exposure notifications are off until you switch them on (minimum severity *medium*); *Run check now* runs the check immediately.
- **Password check** — an on-demand Pwned Passwords lookup using k-anonymity: only the first 5 characters of the password's SHA-1 hash leave the server, and nothing is stored or logged.

A status banner at the top of the page reports on the leaked-credential checks, what's wrong or that they're healthy: no key, provider disabled, checks paused by HIBP, `CREDENTIAL_ENCRYPTION_KEY` missing, a saved key the backend can't decrypt (`CREDENTIAL_ENCRYPTION_KEY` was removed or changed after the key was saved: put the original value back, which your other stored credentials need too, or save the HIBP key again), identities whose last check failed (HIBP unreachable, or a domain HIBP refused although it is listed as verified), email domains skipped because they aren't verified on your HIBP account or your plan has no domain search, or verified domains that may be larger than your plan covers. Each watched domain shows its own last check and error in its card; expand it to see what each check (DNS, RDAP, lookalikes, CT) reported on that run. A domain reads *OK* only when every check that applies to it ran cleanly: *Warnings* means a check ran with partial failures (e.g. DNS record types a filtering resolver didn't answer, which then aren't watched for changes), and *Partly monitored* means a check is switched off for the domain or can't monitor it (no RDAP service for its TLD). The checks run in the background; **Refresh** in the banner re-reads the page. The Getting Started step counts as done once something is actually checked (an enabled identity while breach checks can run, other than an email domain HIBP won't search for your key, or an enabled domain while domain monitoring is on), and shows the banner's warning when monitored identities can't be checked, failed their last check, or are skipped as not verified. Breach data is from Have I Been Pwned, licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): SIEMBox credits it on the Findings card, the verified-domain list, the alert lists (Alerts, SOC Triage, Dashboard → Recent Alerts) and the alert details whenever leaked-credential alerts are shown, and new alert descriptions and notifications end with the licence line. A credit a breach's provider asked HIBP for is shown as plain text in the finding. Everything on the page is also available through the API: [`/api/exposure`](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/API.md#exposure-monitoring-digital-risk).

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
- **AI Triage** — automatic per-alert analysis (off by default, severity-gated, inherits AI Analyst if left blank). See [Automated triage](AI-Security-Analyst#automated-triage).
- **Endpoints / YARA** — endpoint enrollment tokens and the server YARA bundle (incl. *Pull YARA-Forge now*). See [SIEMBOX Endpoint](SIEMBOX-Endpoint).
- **Threat Feeds & Reputation** — enable/disable feeds, add AbuseIPDB/AlienVault OTX keys (admin-gated). See [Threat Intel](Threat-Intel).
- **Notifications** — Email / Slack / NTFY alert delivery.
- **Retention** — log retention window and automated cleanup.
- **Digital Risk** — breach-monitored email addresses and domains, watched domains, the HIBP key, and the password check (admin). See [Digital Risk](#digital-risk-optional).
