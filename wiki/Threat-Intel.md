# Threat Intel

SIEMBox enriches the IPs in your logs with geography and reputation, and gives you a hub to investigate them.

## IP drill-down

The **Threat Intel** view (`/threat-intel`) lets you look up any IP and see, in one place:

- its **GeoIP country**,
- the **log events** it produced,
- the **alerts** it triggered,
- which **threat feeds** flag it and any **reputation verdicts** (see below).

It supports a country breakdown and deep links (`?ip=…`, `?country=…`) so you can pivot straight from a dashboard or alert into the context for an address.

## Dashboard country map

The dashboard shows an **offline choropleth** of alerts-by-country. The world map is bundled (`world-atlas` topojson) with **no CDN calls**, matching the offline-GeoIP design. Click a country to drill into the source IPs behind its alerts.

## GeoIP enrichment

Country / foreign-geo enrichment is **fully offline** (DB-IP IP-to-Country Lite, CC BY 4.0) — no external lookups. At parse time the actor IP gets `country`, `country_code`, and (if you set home countries) `geo_foreign`. Configure with `GEOIP_DB_PATH` and `GEOIP_HOME_COUNTRIES` — see [Configuration](Configuration#geoip-enrichment). This powers geo-aware detections such as foreign-login alerts.

## External threat feeds (free, no key)

SIEMBox seeds a set of **free, no-auth IP blocklists** and auto-refreshes them every few hours:

- **abuse.ch Feodo Tracker** (botnet C2)
- **Tor exit nodes**
- **blocklist.de**

These need only outbound HTTPS. If egress is blocked they degrade gracefully (the feed shows `last_status=error`) without breaking anything. When an IP in your logs appears on a feed, that's surfaced in its IP detail.

## Reputation providers (bring your own key)

On-demand reputation lookups from:

- **AbuseIPDB**
- **AlienVault OTX**

These are **bring-your-own-key**: add your keys in the admin **Threat Feeds & Reputation Providers** panel. Keys are **encrypted at rest** (AES-256-GCM, via `CREDENTIAL_ENCRYPTION_KEY`) and results are cached briefly. Verdicts appear in the IP detail alongside the feed hits.

## Managing feeds & providers

The **Threat Feeds & Reputation Providers** panel (admin-gated, under *Settings*) lets you enable/disable feeds, see each feed's last refresh status and indicator count, and add/remove reputation provider keys.

## Under the hood

The feeds and indicators live in the `threat_feeds` / `threat_indicators` tables (migration `015`, idempotent, applied on startup). Feed URLs are a fixed, seeded set restricted to known hosts (no user-supplied-URL SSRF surface), and all inputs are validated.
