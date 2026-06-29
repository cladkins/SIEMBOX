# FAQ

**What ports do I need?**
`8420` (web UI), `8421` (API + shipper ingest), and `514` UDP/TCP (syslog). See [Installation](Installation).

**What's the default login?**
User `admin`, password = the `DEFAULT_ADMIN_PASSWORD` you set in `.env`.

**I installed SIEMBox but there are no parsers or detection rules — is it broken?**
No — SIEMBox is **catalog-only by default**. A fresh install ships empty. Go to **Parsers → Browse Catalog** and **Detection Rules → Browse Catalog** and *Install all* (or pick what you need). To opt back into the legacy bundled rules, set `SEED_BUNDLED_CONTENT=true`.

**Do I need the log shipper?**
Only for collecting **files**, **Docker container logs**, or the **systemd journal** from a host. Devices that already emit **syslog** can send straight to `udp/tcp 514` with no shipper. See [Log Shippers](Log-Shippers).

**Does SIEMBox phone home / need internet?**
- **GeoIP** is fully **offline** (bundled DB-IP database) — no external calls.
- **Threat feeds** need outbound **HTTPS** to refresh the free blocklists; if egress is blocked they degrade gracefully.
- **Reputation** (AbuseIPDB/AlienVault OTX) and the **AI builder** are **bring-your-own-key** and only call out when you configure and use them.
- The **catalog** browser calls the GitHub API to list community parsers/rules.

**Which AI providers work with the builder?**
**Anthropic**, **OpenAI**, or local **Ollama**. Set it in *Settings → AI Builder* or via env (see [Configuration](Configuration#ai-builder-optional)).

**What's the AI Security Analyst, and how is it different from the AI builder?**
The **[AI Security Analyst](AI-Security-Analyst)** is a conversational, **read-only** assistant that answers questions about *your* alerts, vulnerabilities, assets, and threat intel and helps you prioritize — it can only observe (via read-only tools), never change anything. The **AI builder** instead *generates* parsers and detection rules. They can use the same model or different ones (*Settings → AI Analyst* vs *Settings → AI Builder*), including a local Ollama model. Available to admin/analyst/operator.

**What is SIEMBOX Endpoint, and how do I add an endpoint?**
**SIEMBOX Endpoint** lets you enroll lightweight **endpoint agents** that report inventory, detections, and vulnerabilities and run server-delivered YARA scans. Generate a one-time enrollment token under **Endpoints** (admin) and install the agent on the host; its findings show up in Alerts, Assets, and Vulnerability Management. See [SIEMBOX Endpoint](SIEMBOX-Endpoint).

**Where are my API keys stored?**
Encrypted at rest (AES-256-GCM) using `CREDENTIAL_ENCRYPTION_KEY`. This covers the AI builder key and scanner/reputation provider credentials.

**What happens if I lose or change `CREDENTIAL_ENCRYPTION_KEY`?**
Anything previously encrypted with the old key (stored provider keys/credentials) can no longer be decrypted — you'll need to re-enter them. Keep this key safe and stable.

**How do I detect logins from foreign countries?**
Set `GEOIP_HOME_COUNTRIES` to your home ISO-2 codes (e.g. `US,CA`). Logins from elsewhere get `geo_foreign=true`, which geo-aware rules can key on.

**How do I know which parser parsed a given log?**
The **Logs → Parsed Logs** table has a **Parser** column and a **Parser** filter. "Unknown" means that parser was deleted after the log was parsed.

**Do database migrations run on update?**
Yes — they run automatically on startup and are idempotent, so updating images is non-destructive to your data.

**Can I share or back up a parser/rule?**
Yes — export any parser or rule as portable JSON and import it elsewhere, or contribute it to the catalog. See [Parsers](Parsers) and [Detection Rules](Detection-Rules).
