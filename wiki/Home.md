# SIEMBox

A lightweight, self-hosted **Security Information and Event Management (SIEM)** system built with Node.js/TypeScript, Vue 3, and PostgreSQL. As of **v2 — the Parser Platform**, parsers and detection rules are *portable data*: shareable, installable from a community catalog, and generatable by AI.

> New here? Go to **[Installation](Installation)**, then **[Log Shippers](Log-Shippers)** to start getting logs in.

## What it does

SIEMBox ingests logs from your hosts and services, **parses** them into a single canonical schema, runs **detection rules** against them, raises **alerts**, and enriches everything with **GeoIP** and **threat intelligence**. It also scans your hosts and container images for **vulnerabilities**.

## Feature map

| Area | What you get | Wiki page |
|------|--------------|-----------|
| **Ingestion** | Syslog over UDP/TCP (port 514) + an optional universal **log shipper** for files, Docker logs, and journald | [Log Shippers](Log-Shippers) |
| **Parsers** | Declarative, portable parsers (pattern + field mappings + derivations + self-tests); install from an in-app **catalog** or generate with **AI** | [Parsers](Parsers) |
| **Detections** | Portable detection rules with conditions, aggregation/threshold logic, and alert templating; catalog + AI builder | [Detection Rules](Detection-Rules) |
| **Normalization** | One **canonical schema** so a rule written once fires across every log source | [Parsers](Parsers) |
| **Threat Intel** | IP drill-down (country, events, alerts), a dashboard **country choropleth**, free **blocklist feeds**, and BYO-key **reputation** (AbuseIPDB / AlienVault OTX) | [Threat Intel](Threat-Intel) |
| **Scanning** | Host vulnerability scanning (**Nuclei**) and container-image scanning (**Trivy**), with optional Docker-host image discovery and scheduled scans | [Vulnerability & Container Scanning](Vulnerability-and-Container-Scanning) |
| **Alerts & access** | Alert management, configurable retention, and role-based access (Admin / Analyst / Viewer) | [Configuration](Configuration) |

## Highlights

- **Catalog-only by default** — a fresh install ships empty; you install exactly the parsers and rules you want from the in-app catalog (*Browse Catalog → Install all*). No hidden hardcoded content.
- **AI builder (bring your own key)** — paste a log line to generate a parser, or describe a threat to generate a rule. A *generate → validate → auto-refine* loop runs against the **real engine**, so you never save an invalid artifact. Works with Anthropic, OpenAI, or local Ollama; keys are encrypted at rest.
- **Offline GeoIP** — country / foreign-geo enrichment with no external calls, powering geo-aware detections (e.g. foreign-login alerts) and the dashboard map.

## Architecture at a glance

```
log sources ──► (syslog 514 / shipper) ──► Backend (Node/TS, :8421)
                                              │  parse → normalize → derive → detect
                                              ▼
                                       PostgreSQL (JSONB)
                                              ▲
                       Web UI (Vue 3) :8420 ──┘
```

See **[Architecture](Architecture)** for the full data flow.

## Project links

- Repository: https://github.com/cladkins/SIEMBOX
- In-repo deep references: [API](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/API.md) · [Parsers](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/PARSERS.md) · [Rules](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/RULES.md) · [Security](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/SECURITY.md)
- License: MIT
