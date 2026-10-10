# Digital Risk Monitoring, Per-Area Settings & Onboarding

**Status:** design agreed; build in progress (see [Roadmap](#roadmap))
**Last updated:** 2026-10-10

This document covers three connected changes:

1. **Digital Risk / Exposure Monitoring.** Watch for the organization's **leaked credentials** and monitor its **domains** for lookalikes, new or mis-issued TLS certificates, registration changes, and DNS drift.
2. **A settings hub.** Every functional area of SIEMBox gets **its own settings page**, holding only the settings that belong to that area. This replaces the single monolithic Settings page.
3. **Onboarding.** Operators can enter Digital Risk inputs (domains, email domains, API keys) while onboarding, and those inputs land in exactly the same place the Digital Risk settings page reads from.

---

## Goals and non-goals

**Goals**
- Alert when accounts belonging to the org appear in a data breach, without ever storing a breached secret.
- Alert when someone registers a lookalike of the org's domain, gets a certificate issued for one of the org's domains or a lookalike, or changes the org's domain registration or DNS.
- Let operators configure everything during onboarding *and* afterwards in a dedicated Digital Risk settings page, both backed by one API.
- Give each functional area its own role-gated settings page.

**Non-goals (v1)**
- Commercial dark-web / stealer-log feeds. The source interface is pluggable, so these can come later.
- Querying domains or accounts the org doesn't own. Breach APIs prohibit this in their terms, and it would be abusive anyway.
- AI auto-triage of exposure alerts.

---

## Architecture

Exposure Monitoring is a **sibling subsystem** next to Threat Intel and Threat Feeds. It's a thin feature layer over infrastructure SIEMBox already has, so very little new plumbing is needed.

```
 Onboarding "Digital Risk" step ──┐
                                  ├──► /api/exposure/* ──► watched_domains, monitored_identities
 /settings/digital-risk ──────────┘          │                         │
                                             │          jobs (jobRegistry): leaked-creds, domain-monitor
                                             │                         │
                       system_settings ◄─────┘                         ▼
                       (exposure_* flags,                     exposure_findings ──► alerts
                        encrypted HIBP key)                   (deduped per        (source = leaked-creds |
                                                               fingerprint)         domain-monitor)
                                                                       │
                                                                       ▼
                                                       NotificationService.notifyExposure
                                                       (Slack / Email / NTFY, opt-in)
```

### What it reuses

| Need | Existing building block |
|---|---|
| Scheduling | `services/jobs/jobRegistry.ts`; job templates `jobs/threatFeeds.ts` (global cadence) and `jobs/scheduledScans.ts` (per-item cadence). Registered jobs show up on Admin → Background Jobs automatically. |
| Alerts | The EDR non-rule insert (`services/edr/edrService.ts`): `rule_id = NULL`, `source`, a stable `event_id`, and `ON CONFLICT (event_id) DO NOTHING`, using the partial unique index from migration 016. |
| Notifications | `NotificationService`. The new `notifyExposure` is cloned from `notifyVulnScan` and has its own enable and min-severity gate. |
| Secrets | `system_settings` + `CredentialEncryption` (AES-256-GCM), following the `threatintel/reputationService.ts` pattern. The key is never returned to the UI. |
| Outbound calls | `reputationService`'s SSRF-safe pattern: the host is a constant in a `URL` object, user-supplied values go only into the path via `encodeURIComponent`, and requests have an `AbortController` timeout. |
| Migrations | Idempotent numbered files (`023_shipper_containers.sql` style). |
| UI shell | The new settings hub (Part 3). |

---

## Part 1 — Leaked-credential monitoring

### Sources

| Source | Cost | What it provides | v1 |
|---|---|---|---|
| **HIBP Pwned Passwords** (k-anonymity range API) | Free, no key | Whether a given password appears in known breaches, and how often | ✅ Stateless, on-demand check |
| **HIBP v3 `breachedaccount`** | Paid API key | The breaches a specific email address appears in | ✅ Turns on once a key is added |
| **HIBP v3 `breacheddomain`** | Paid API key, plus the domain verified in the HIBP dashboard | Every breached alias on a domain the org owns | ✅ Turns on once a key is added and the domain is verified |
| Commercial stealer-log / credential feeds (SpyCloud, Hudson Rock, Flare, DeHashed, …) | Priced by quote | Infostealer-captured credentials | Later, as another source behind the same interface |

> **Decision:** Pwned Passwords is an **on-demand check only**. A password is never stored as something to keep watching, because re-checking it later would mean keeping its hash, and that breaks the privacy rule below. A useful follow-up is checking SIEMBox users' *own* passwords when they're set or changed.

### Data model (migration `034_exposure_monitoring.sql`)
- **`monitored_identities`**: `kind` (`email` | `email_domain`), `value`, `enabled`, `interval_minutes`, and last-check status. Unique on `(kind, value)`.
- **`watched_domains`**: used by Part 2. It's created in 034 so onboarding and the settings page can start collecting domains before the domain collectors ship.
- **`exposure_findings`**: `source`, `identity_id` or `domain_id`, `event_type`, `fingerprint`, `title`, `severity`, `detail` JSONB, `alert_id`, and `first_seen` / `last_seen` / `resolved_at`. Unique on `(source, fingerprint)`.
- **`system_settings` seeds**: `notify_exposure_enabled=false`, `notify_exposure_min_severity=medium`, `exposure_leaked_creds_enabled=true`, `exposure_hibp_enabled=false`. The HIBP key itself is stored encrypted as `exposure_hibp_key`.

### Job
A `leaked-creds` job is registered in the job registry. It ticks every 15 minutes, and each identity's own `interval_minutes` decides whether it's actually polled. The job is skipped, with the reason shown on the Admin dashboard, when the feature is off or no key is configured. Identities are checked one at a time, and the cycle stops on an HTTP 429 instead of hammering the API.

### How findings become alerts
`recordFinding()` upserts the finding by `(source, fingerprint)`. Only a **new** finding creates an alert (one alert, with a stable `event_id`) and calls `notifyExposure`, so re-polling never re-alerts.

| Condition | Severity |
|---|---|
| Stealer-log breach, or `Passwords` among the breached data classes | high |
| Breach flagged sensitive | high |
| Any other breach | medium |

### Privacy and terms-of-use guardrails (enforced in code)
1. Plaintext passwords, password hashes, and API keys are **never stored or logged**. `sanitizeDetail()` strips secret-like keys from every finding before it's written.
2. Pwned Passwords is called **only through k-anonymity**: just the first 5 characters of the SHA-1 hash leave the box, and response padding is on.
3. Only accounts and domains the org **owns** are monitored. HIBP domain search requires verified ownership.
4. HIBP is credited (its data is CC BY 4.0) wherever breach data is shown.
5. Requests send a descriptive User-Agent, honor 429 `retry-after`, and time out. Jobs are best-effort and never crash the process.
6. `POST /api/exposure/password-check` is stateless, never logged, and rate-limited per IP.

---

## Part 2 — Domain monitoring

Every collector compares its result against a stored baseline, and **only new changes raise an alert**.

| Collector | Data source | What it catches | Default severity |
|---|---|---|---|
| Certificate Transparency | crt.sh JSON (free) | A certificate for the org's own domain from an unexpected CA (mis-issuance); a certificate for a lookalike (a phishing site going up) | Unexpected CA: high · lookalike cert: medium |
| Lookalikes / typosquats | A built-in TypeScript permutation engine (omission, repetition, transposition, keyboard-adjacent replacement, homoglyph, hyphenation, bitsquat, TLD swap) plus DNS resolution. `dnstwist` is used too if it's installed. | A newly registered lookalike. An MX record on one usually means someone is getting ready to send phishing mail. | high (medium if the lookalike has no A/MX record) |
| RDAP / WHOIS | IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`), then the registry's RDAP server | Registrar, nameserver, status, or registrant changes (signs of a hijack); expiry approaching | Change: high/critical · expiry within 30 days: medium |
| DNS drift | Two independent resolvers; A/AAAA/MX/NS/TXT records | NS/MX changes; TXT changes (SPF/DKIM/DMARC tampering); A record changes | NS/MX: critical · TXT: high · A: medium |

> **Decision:** Lookalikes come from a **built-in TypeScript engine** rather than adding Python `dnstwist` to the backend image, which keeps the image lean. If `dnstwist` happens to be installed, it's used for broader coverage.

- **Data model (migration `035`)**: `domain_baselines(domain_id, collector, snapshot JSONB)`. Findings reuse `exposure_findings` with `source = 'domain-monitor'` and an `event_type` of `new_cert`, `unexpected_ca`, `lookalike_registered`, `rdap_change`, `dns_drift`, or `expiry_warning`.
- **Job**: `domain-monitor`. Each domain is polled on its own schedule, selected the same way `scheduledScans` picks due scans.
- **Network access**: the collectors need outbound access to crt.sh, data.iana.org, the registries' RDAP servers, and DNS. Without it, the feature degrades gracefully, and a banner in the UI tells "no key", "network access blocked", and "no findings" apart.

---

## Part 3 — Settings hub: one page per functional area

Today `Settings.vue` is a single ~2,000-line page of unrelated cards, and its route isn't role-gated (only the backend blocks writes). In its place:

- `/settings` becomes a **parent route** rendering `views/settings/SettingsLayout.vue`: a header, a secondary nav, and a nested `<router-view>`.
- Each area is a **child route** with its own component under `views/settings/`.
- One config array (`views/settings/areas.ts`) drives both the nav and the routes, so adding an area takes one entry and one component.
- Roles are enforced **in two places**: route `meta` (checked by the existing `beforeEach` guard) and the nav (items the user can't access are hidden).
- **Only the frontend is reorganized.** The backend `/api/settings/*` routes don't change.

| Area | Route | Contents | Backend | Access |
|---|---|---|---|---|
| My Account | `/settings/account` | MFA (TOTP), own password | `/auth/*` | any authenticated user |
| Data Retention | `/settings/retention` | Retention windows, manual cleanup, table stats | `/settings/retention*` | admin |
| Ingestion | `/settings/ingestion` | Syslog server configuration | `/settings/syslog*` | admin |
| AI | `/settings/ai` | AI Builder, AI Analyst (chat), AI Triage | `/settings/ai`, `/ai-chat`, `/ai-triage` | admin |
| Notifications | `/settings/notifications` | Channels (Slack/Email/NTFY) and event preferences | `/notifications/*` | admin |
| Detections | `/settings/detections` | IP whitelist (alert suppression) | `/settings/ip-whitelist*` | admin |
| Asset Discovery | `/settings/discovery` | Auto-discovery schedule, stale-asset threshold | `/settings/auto-discovery*` | admin |
| System | `/settings/system` | Version and runtime info, table sizes | `/settings`, `/admin` | admin |
| **Digital Risk** | `/settings/digital-risk` | See Part 4 | **`/api/exposure/*`** | admin |

Every area page has the same structure: a header (title, HelpTip, and an admin badge where it applies), then `el-card` sections, each with its own Save button and a success/error toast.

---

## Part 4 — The Digital Risk settings page (`/settings/digital-risk`)

1. **Owned domains.** Domains to watch for certificate mis-issuance, DNS drift, and RDAP changes.
2. **Breach-monitored identities.** Email domains and specific addresses to check against HIBP.
3. **Brand / lookalike domains.** Domains whose lookalikes and typosquats should be watched.
4. **Provider API keys.** The HIBP key, shown masked and stored encrypted; it's never displayed again after saving. If no encryption key is configured on the server, a warning appears and saving is disabled.
5. **Notifications.** Whether exposure alerts are sent, and the minimum severity for sending them.
6. **Password check.** An on-demand Pwned Passwords check (k-anonymity; nothing is stored).

A status banner at the top says which state the feature is in: *no API key*, *network access blocked*, *encryption key missing*, or *healthy*.

---

## Part 5 — Onboarding

**Today:** onboarding is a live checklist at `/getting-started` (`Onboarding.vue`). The only thing it collects directly is a new password; the other steps link out to other pages. "Done" is remembered by a `localStorage` flag in the browser.

**Change:** add an optional **Digital Risk** step that collects inputs right on the checklist: owned domains, email domains or addresses, brand domains, and an optional HIBP key. It submits to the **same `/api/exposure/*` endpoints** as the settings page, so there's one source of truth: anything entered during onboarding shows up on `/settings/digital-risk`, and vice versa. The step counts as done once at least one domain or identity is being watched. The existing step links are repointed to the specific `/settings/<area>` pages.

---

## Decisions (current defaults — any of these can be changed)

| # | Decision | Default |
|---|---|---|
| 1 | Where MFA and password settings live | A per-user **My Account** area (`/settings/account`), separate from admin-only system settings |
| 2 | Auto-discovery and IP whitelist settings | Main editors live in `/settings/discovery` and `/settings/detections`; links from the Assets and Rules pages can be added later |
| 3 | Onboarding model | Extend the existing checklist; keep `localStorage` dismissal in v1 (storing completion server-side is a follow-up) |
| 4 | Digital Risk onboarding step | Collects inputs directly, rather than just linking to settings |
| 5 | Other onboarding steps | No new ones in v1 beyond Digital Risk |
| 6 | HIBP | The paid-key integration is built and switches on when a key is added; nothing needs to be bought to ship |
| 7 | Pwned Passwords | On-demand only; passwords are never stored as watch items |
| 8 | Lookalike engine | Built-in TypeScript with default fuzzers; `dnstwist` used if present |
| 9 | Exposure notifications | Off until enabled; minimum severity medium |
| 10 | AI triage of exposure alerts | Off in v1 |
| 11 | Domain expiry warning | 30 days ahead |

---

## Roadmap

| PR | Scope | Depends on | Status |
|---|---|---|---|
| 1 | This design doc | — | In review |
| 2 | Settings hub (frontend reorganization, role-gated areas) | — | Building |
| 3 | Exposure backend foundation: migration 034, `/api/exposure`, encrypted HIBP key, leaked-credential job, Pwned Passwords check, `notifyExposure` | — | Building |
| 4 | Digital Risk settings page + onboarding Digital Risk step | 2, 3 | Next |
| 5 | Domain monitoring collectors + `domain-monitor` job (migration 035) | 3 | Planned |
| 6 | HIBP domain-search polish (verified-domain status, attribution) + storing onboarding completion server-side | 3, 4 | Planned |

---

## Risks

- **SSRF.** Domain and account lookups put user-supplied values into third-party URLs. They must use the constant-host pattern with strict validation; plain string concatenation is not allowed.
- **Privacy.** Persisting a breached password or hash would be a serious data-handling failure. This is prevented by design: Pwned Passwords is only called through k-anonymity, and `sanitizeDetail()` runs on every finding.
- **Terms of use.** Only org-owned domains and accounts may be queried. HIBP must be credited, its rate limits honored, and a descriptive User-Agent sent.
- **Unreliable external sources.** crt.sh returns 502s, and HIBP enforces per-minute limits. Every watch records its last status and error, and the UI shows when the feature is degraded.
- **Alert storms.** Deduplication depends entirely on stable fingerprints and `event_id`s.
- **Too many lookalikes.** The permutation engine is tuned conservatively; lookalikes with an MX record or high page similarity are escalated.
- **Installs without outbound network access** will produce no findings. This is why exposure notifications are off by default and the UI explains the cause.
- **Regressions from the settings reorganization.** Each card moves over with its behavior unchanged, and type-check and build must pass.

---

## References
- HIBP API v3 — https://haveibeenpwned.com/API/v3
- Pwned Passwords (k-anonymity) — https://haveibeenpwned.com/API/v3#PwnedPasswords
- crt.sh — https://crt.sh
- IANA RDAP bootstrap — https://data.iana.org/rdap/dns.json
- dnstwist — https://github.com/elceef/dnstwist
