# SIEMBox Roadmap

A living roadmap of where SIEMBox is headed. Ordering logic: **earn trust → remove
"can't start" blockers → become a real SIEM → scale only when demand is proven.**
Effort: **S** = days · **M** = 1–2 weeks · **L** = multi-week · **XL** = major.

> This is a public direction signal, not a commitment to dates or order. Feedback and
> contributions (especially parser/detection packs) are welcome.

## Recently shipped
- **v3 — AI Security Analyst**: conversational, read-only, model-agnostic (local Ollama or cloud).
- **SIEMBOX Endpoint** (renamed from EDR): agent enrollment, server-delivered YARA, Asset-360.
- **Threat Intel**: blocklist feeds + BYO-key reputation (AbuseIPDB / AlienVault OTX); offline GeoIP map.
- **`on_threat_feed` detection operator** — write a rule that fires when a source IP is on an enabled feed.
- Alerts keyword/IP search + filters; "Send test alert" email preview.

## Phase 1 — Trust & Reliability
Cheap, high-leverage foundation that makes SIEMBox safe to depend on.
- **Security hygiene** *(S)* — clear dependency alerts, `SECURITY.md` disclosure, automated dependency updates.
- **Backup / restore + safe upgrades** *(S–M)* — scheduled `pg_dump`, documented restore, idempotent startup migrations. *(Foundation for Hot/Cold below.)*
- **Endpoint alerts → notifications** *(S)* — endpoint-agent detections now email/Slack/ntfy like rule alerts.
- **Search index** *(S)* — `pg_trgm` GIN indexes so keyword/IP search stays fast as data grows.
- **Detection-engine + parser tests** *(M)* — guard against "rule silently never fires" regressions.

## Phase 2 — Onboarding & Content
The two biggest adoption unlocks.
- **Content Packs** *(M)* — curated, per-technology bundles (Auth, Reverse Proxy, Media, Documents, DNS,
  Network…) of parsers + detections, installable in one click. A pack references existing catalog content
  plus setup hints (which container, where the logs are).
- **Sigma import / convert** *(M–L)* — turn community Sigma rules into portable detections (huge content multiplier).
- **MFA (TOTP)** *(M)* — for local accounts; also unblocks the onboarding wizard.
- **Onboarding wizard** *(M)* — guided first run: secure account + MFA → log ingestion (+ shipper key) →
  install packs → API keys → notifications + test alert. *(Depends on MFA + Packs.)*

## Phase 3 — Operate like a SIEM
- **Reporting & exports** *(M)* — scheduled reports, CSV/PDF, prebuilt templates (alert summary, vuln posture).
- **Response, lite** *(M–L)* — per-rule actions (webhook / export-to-blocklist / run-script), incident/case
  grouping, ticketing webhook.
- **OIDC SSO** *(M–L)* — Google / Entra / Authentik / Authelia.

## Phase 4 — Scale & Data Lifecycle
- **Retention → Hot / Cold storage + Rehydrate** *(L)* — keep config/state always; **archive aged event
  windows** (`raw_logs` / `parsed_logs`) to compressed cold storage, prune them from the hot DB, and add a
  **Rehydrate page** to load a window back on demand for investigation, then evict it. Keeps the hot DB small
  and fast without a second storage engine. (Cold data is investigation-archive, not live-queryable — a future
  option is queryable cold via Parquet + DuckDB / object storage.)
- **Ingestion buffering** *(L)* — a small queue ahead of the database.
- **Pluggable store / HA** *(XL — gate on real demand)* — only if users actually hit Postgres limits; not
  built pre-emptively (it would erode the "simple to self-host" advantage).

## Dependencies
- **MFA** → Onboarding wizard (step 1).
- **Phase 1 backups** → Hot/Cold archival (Phase 4).
- **Content Packs** rely on catalog-repo content (`cladkins/siembox-catalog`).
- **Sigma import** accelerates everything content-related.
