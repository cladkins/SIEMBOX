# Architecture

## Components

| Component | Stack | Role |
|-----------|-------|------|
| **Frontend** | Vue 3 + Element Plus + Vite | Web UI (served on port **8420**). |
| **Backend** | Node.js + TypeScript + Express | REST API, syslog listener, parser/rules engines, scanners, the **EDR server** + YARA delivery, the **AI Security Analyst** tool loop, and jobs (port **8421**, syslog **514**). |
| **Database** | PostgreSQL (JSONB) | Raw + parsed logs, parsers, rules, alerts, assets, vulnerabilities, threat feeds/indicators, EDR agents + YARA bundles, analyst chat threads, settings. |
| **Log shipper** | Alpine container | *Optional* forwarder installed on other hosts (see [Log Shippers](Log-Shippers)). |
| **EDR endpoint agent** | Separate lightweight agent | *Optional* agent enrolled from the UI; reports inventory/detections/vulns and runs server-delivered YARA (see [Endpoints & EDR](Endpoints-and-EDR)). |

Everything is deployed with Docker Compose.

## Data flow

```
                         ┌──────────────────────── Backend (:8421) ────────────────────────┐
 syslog (udp/tcp 514) ─► │                                                                  │
 shipper (HTTP+API key)─►│  raw_logs ─► Parser engine ─────────────────────────────────►   │
                         │              (match by priority)                                 │
                         │                  │                                               │
                         │                  ▼                                               │
                         │   parse → map fields → apply derivations → normalize (canonical) │
                         │                  │                                               │
                         │                  ▼                                               │
                         │   GeoIP enrich ─► parsed_logs (parsed_data JSONB) ─► Rules engine │
                         │                                                          │        │
                         │                                                          ▼        │
                         │                                              conditions + aggregation
                         │                                                          │        │
                         │                                                          ▼        │
                         │                                                       alerts ─► notifications
                         └──────────────────────────────────────────────────────────────────┘
                                              ▲
                          Web UI (:8420) ─────┘   (search logs, manage parsers/rules, threat intel, scanning)
```

### The parse pipeline (single source of truth)

Every log runs through one DB-free pipeline (`runParser`): **match → map → derive → normalize**. The same pipeline powers the production engine *and* the parser self-tests / catalog CI, so "passes its self-tests" means "behaves identically once installed." See [Parsers](Parsers).

1. **Match** — the first enabled parser (by `priority`, lowest first) whose pattern matches wins.
2. **Map** — capture groups / JSON keys are mapped to fields via `field_mappings`.
3. **Derive** — declarative `derivations` fill additional fields (e.g. set `event=login_failure` when the message contains "failed").
4. **Normalize** — fields are mapped to a single **canonical schema** (aliases like `src_ip`/`client_ip` → `source_ip`), so detection rules match regardless of the source's original field names.

### Detection

The rules engine evaluates each parsed log against enabled rules: ANDed **conditions** plus optional **aggregation** (e.g. "5 failures from one IP in 5m"). Matches raise **alerts**, which can be delivered via Email / Slack / NTFY.

## Storage model

- **`raw_logs`** — the original line as received (kept for forensics; `message` defaults to it).
- **`parsed_logs`** — `parsed_data` (canonical fields, JSONB), `parser_id` (which parser matched — surfaced on the Logs view), `event_type`, `source_ip`, timestamps.
- **`parsers` / `rules`** — installed portable parsers and detection rules.
- **`alerts`, `assets`, `vulnerabilities`, `threat_feeds`, `threat_indicators`, `system_settings`** — feature data.
- **`edr_agents`, `edr_enrollment_tokens`, `edr_yara_bundle`** — EDR endpoints, one-time enrollment tokens, and versioned YARA bundles.
- **`chat_sessions`, `chat_messages`** — per-user AI Security Analyst threads.

## Ports recap

| Port | Purpose |
|------|---------|
| 8420 | Web UI |
| 8421 | REST API + shipper ingest |
| 514 (udp/tcp) | Syslog |
