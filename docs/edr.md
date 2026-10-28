# SIEMBOX Endpoint — server side

Server-side implementation of the SIEMBOX Endpoint API that the endpoint agent
([`cladkins/siembox-endpoint`](https://github.com/cladkins/siembox-endpoint)) talks to. The
wire contract is that repo's `docs/EDR_API.md`; this documents how it maps into
SIEMBox.

## Principle: reuse, don't reinvent

Only the agent **identity** is new. Everything the agent reports lands in the
**existing** tables so it shows up in the current UIs:

| Agent sends        | Stored in                                  |
|--------------------|--------------------------------------------|
| enroll / heartbeat | `edr_agents` (new)                         |
| inventory          | `assets` (`asset_type='endpoint'`, upserted by IP so it correlates with log/Nuclei data) |
| events (detection) | `alerts` (`source='edr'`, linked to the endpoint asset, deduped on the agent event id) |
| vulnerabilities    | `vulnerabilities` + `asset_vulnerabilities` (idempotent upsert) |
| packages           | `edr_agent_packages` + `edr_agent_package_snapshots` (migration 049; full snapshot per agent) |

New tables (migration `016_edr_agents.sql`): `edr_agents`, `edr_enrollment_tokens`.
`alerts` gains nullable `asset_id` / `source` / `event_id` columns (+ a partial
unique index on `event_id` for replay dedup).

## API (`/api/edr/*`, port 8421)

**Agent-facing** (per-agent key: `Authorization: Bearer <key>` + `X-Agent-ID`):
- `POST /agents/enroll` — exchange a one-time enrollment token for `{agent_id, agent_api_key, config}` (key returned once; only its sha256 is stored).
- `POST /agents/:id/heartbeat` → `{config_version, scan_requests}` (optional `update` progress report, see [Agent updates](#agent-updates); `capabilities` and `scan_requests`, see [Scans and scan history](#scans-and-scan-history))
- `GET  /agents/:id/config` → `AgentConfig` (includes `yara_rules_version`, `agent_update`, `scan_policy` (see [Scan policies](#scan-policies)) and `performance` (see [Machine performance](#machine-performance)))
- `GET  /agents/:id/yara` → curated YARA bundle as raw `text/plain` (empty body valid)
- `POST /inventory` · `POST /events` · `POST /vulnerabilities` → `202 Accepted`
- `POST /scans` → `200` `{scan_id, status, accepted}`: the agent reports a scan's start or end (see [Scans and scan history](#scans-and-scan-history))
- `POST /metrics` → `200` `{accepted, duplicate, rejected, processes, alerts_opened, alerts_recovered}`: per-minute performance samples and top-process snapshots (see [Machine performance](#machine-performance))
- `POST /packages` → `200` with `{accepted, unchanged, snapshot_required, package_count, stored, removed, skipped, truncated}` (installed software, see [Installed packages](#installed-packages))

**Console-facing** (JWT):
- Analyst, operator or admin: `GET /agents`, `GET /agents/:id`, `GET /agents/:id/vulnerabilities`, `GET /agents/:id/packages`, `GET /agents/:id/detections`
- Admin: `DELETE /agents/:id`
- Admin, agent updates: `GET /agent-updates`, `POST /agent-updates/check`, `PUT /agent-updates/settings`, `POST /agents/:id/update`, `DELETE /agents/:id/update`, `POST /agents/update-outdated` (see [Agent updates](#agent-updates) and `docs/reference/API.md`)
- Scans (analyst and up; history every role): `POST /agents/:id/scans`, `POST /agents/scans/bulk`, `POST /agents/:id/scans/:scanId/cancel`, `GET /agents/:id/scans`
- Performance (analyst and up): `GET /agents/:id/performance?range=1h|6h|24h|7d|30d|90d`, `GET /agents/:id/processes?range=&at=`; its settings and alert thresholds are part of the scan policy (write: operator and admin)
- Scan policies (read: analyst and up; write: operator and admin): `GET /scan-policies`, `POST /scan-policies`, `POST /scan-policies/preview`, `GET|PUT|DELETE /scan-policies/:policyId`, `POST /agents/scan-policy` (bulk assign), `GET|PUT /agents/:id/scan-policy` (see [Scan policies](#scan-policies))
- Admin: `POST /tokens` (generate, plaintext shown once), `GET /tokens`, `DELETE /tokens/:hash` (revoke)
- Admin: `GET /yara` (current bundle version/sha/size), `POST /yara/refresh` (pull YARA-Forge now)

The **Endpoints** UI (analyst, operator and admin; enrollment, tokens, YARA, updates and removal admin-only) lives under *Assets & Vulnerabilities → Endpoints*:
agent list with live status + open-vuln / recent-detection counts, a per-endpoint
drill-down (reusing the alert + vuln tables), and enrollment-token generation with
install instructions.

## Implementer decisions

- **Enrollment tokens:** single-use (`used_at` stamped atomically on enroll) with optional `expires_at`.
- **Auth:** sha256 hash of the agent key, constant-time compared; the `:id` path param must match the authenticated agent.
- **Vuln reconciliation:** idempotent upsert keyed by `(asset, CVE)`; `last_detected` refreshed each scan (no destructive replace). Ingest logs `received/unique/duplicate_id/skipped_no_id` so grype's per-package count reconciles with the host's unique-CVE count.
- **Scan timing:** the agent reports no forward schedule — it runs on the server-set cadence in `AgentConfig` (heartbeat 60s, config 5m, inventory 1h, **vuln scan daily**) and only reports `scan_started_at`/`scan_completed_at` after a scan. Those are stored on the agent row; the Endpoints UI shows the real last scan + duration and derives **next scan ≈ last completed + `vuln_scan_interval_seconds`**.
- **Detections:** `type='detection'` → alerts; `telemetry` events are ignored for now.
- **Offline:** an agent reads as offline when `last_seen` is older than 5 minutes.
- **Rate limiting:** the agent-key routes (heartbeat, config, YARA, inventory, events, vulnerabilities, packages, metrics) carrying `X-Agent-ID`, with the method each route answers, skip the general per-address limiter, so a fleet behind one NAT address isn't throttled; they have their own, higher per-address limit (`EDR_AGENT_RATE_MAX`, default 30000 per 15 minutes) in front of agent auth. Enrollment counts toward the general limit, with or without `X-Agent-ID`. The address is the agent's TCP address: an `X-Forwarded-For` it sends to port 8421 is ignored.

## Installed packages

The agent reports the full list of software installed on its host (not only
what grype finds vulnerable) to `POST /api/edr/packages`. Each report is a
**full snapshot**: it replaces the agent's previous list, so a package missing
from the newest report is removed. Rows belong to the agent (`ON DELETE
CASCADE`), so deregistering an endpoint drops its list; Application
Monitoring places them on the agent's asset as the `endpoint_sbom` evidence
source, matched by the signatures' `package` matcher (lower-cased name).

```json
{
  "agent_id": "<uuid>",
  "snapshot_hash": "sha256:…",
  "collected_at": "2026-10-26T12:00:00Z",
  "force": false,
  "packages": [{ "name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "type": "deb" }]
}
```

- `snapshot_hash` (optional, ≤128 chars of `[A-Za-z0-9:_+/=.-]`) is opaque to
  the server; without one it computes its own over the cleaned list. When it
  equals the stored hash nothing is written (`unchanged: true`) — only
  `reported_at` moves. `force: true` stores the list anyway.
- A body with `snapshot_hash` and no `packages` is a check: `unchanged: true`
  when the server has that snapshot, else `accepted: false,
  snapshot_required: true` (send the list).
- `type` is the ecosystem (`deb`, `rpm`, `apk`, `brew`, `app`, `pkg`, `msi`,
  `npm`, `pypi`, `go`, …): lower case, else stored as `''`. Names are clipped
  to 256 characters, versions to 128, control characters dropped; entries
  without a name are skipped, duplicate (type, name, version) collapse (dpkg
  lists multi-arch packages once per architecture). At most 50,000 packages a
  report (the rest are dropped, counted in `truncated`); the body limit is the
  API's 10 MB, and gzip request bodies are accepted.
- Stored in batched `UNNEST` upserts in one transaction under the agent's
  snapshot-row lock (two reports from one agent serialize): 10,000 packages
  take a fraction of a second, far inside the agent's 30 s timeout.
- Older servers answer `404`; the agent backs off and keeps the rest running.

## YARA rule packs (server-delivered)

The agent does on-disk YARA file detection. It ships an embedded baseline and pulls
a curated server bundle when the config's `yara_rules_version` increases. Wire
contract: `docs/SERVER_YARA_ADDON.md` in the agent repo.

- **Storage:** `edr_yara_bundle (version PK, rules, sha256, source, created_at)`
  — one row per version; the server always serves the **highest** version. Migration
  `017` seeds a small, valid, permissively-licensed starter bundle as version 1
  (EICAR + a couple of generic rules, `SIEMBox_`-prefixed so they can't collide with
  the agent's baseline identifiers).
- **Re-pull trigger (composite `config_version`):** the served `config_version` is
  `edr_agents.config_version + current yara version`. Publishing a higher bundle
  version therefore raises every agent's `config_version`, so the agent re-pulls
  config, sees the new `yara_rules_version`, and downloads `GET /agents/:id/yara`.
  No agent rows are mutated on publish — which keeps migration `017` idempotent
  (it re-runs every startup) and makes already-enrolled agents pick up v1 on their
  next heartbeat automatically.
- **Serving:** `GET /agents/:id/yara` returns only our rules as `text/plain`; the
  agent appends its baseline. Empty body is valid (no bundle published).
- **YARA-Forge refresh (opt-in):** `EDR_YARA_FORGE_ENABLED=true` runs a daily job
  that downloads the latest YARA-Forge **Extended** pack (a permissive superset of
  Core — using both would duplicate identifiers and break the agent's combined
  compile), extracts the `.yar` (dependency-free zip reader), and publishes a new
  bundle only when the content changed. Off by default since it pushes a large pack
  to every endpoint. `POST /yara/refresh` triggers it on demand regardless.
- **Retention:** each version is a full copy, so after every publish we keep only
  the newest `EDR_YARA_KEEP_VERSIONS` rows (default 10) — server-side only, since
  the agent always pulls the highest version. Pruning never reuses version numbers,
  so the agent's version comparison is unaffected.

## Agent updates

Admins can update endpoint agents from the Endpoints page. The server never
serves the binary: it names a target version and a fresh `request_id`, and the
agent downloads that release from `github.com/cladkins/siembox-endpoint` itself,
verifies it against the release's `SHA256SUMS`, and runs the native installer
for the way it was installed (deb, rpm, pkg, MSI, or a binary swap).

**Flow.** The `edr-agent-release` job checks the latest GitHub release at
startup and every 6 hours (*Check now* does it on demand; set `GITHUB_TOKEN` to
raise the GitHub rate limit). A release counts only if its tag is `vX.Y.Z` and
it has a `SHA256SUMS` asset. *Update* (per endpoint) or *Update all outdated*
stores the request on the agent (`update_request_id`, `update_target_version`,
state `pending`) and bumps its `config_version`; the agent sees
`agent_update: {version, request_id}` on its next config pull (within about a
minute), attempts each `request_id` at most once, and reports
`downloading` / `installing` / `succeeded` / `failed` in its heartbeat. The
request completes when the agent reports `succeeded` or its heartbeat
`agent_version` reaches or passes the target; a failure shows the agent's error as a
tooltip on the state tag, and *Update* issues a new request to retry.
*Cancel update* drops a request that has not started.

**Auto-update** is off by default. Turning it on (it asks for confirmation,
because it pushes every new release fleet-wide) immediately requests the latest
known version for all outdated endpoints, and does the same after each release
check. An endpoint with a request already outstanding for that version is not
asked again, including after a failure; use *Update* to retry.

**Rules.** Only plain `X.Y.Z` versions are targets and are compared numerically.
An agent on any other version (`dev`, `a8922f4-dirty`) is a development build:
manual *Update* is allowed, auto-update and *Update all outdated* skip it. A
downgrade or same-version update is never requested.

**Requirements.** Endpoints need HTTPS egress to `github.com` (and the release
asset CDN it redirects to) with system CA trust; the SIEMBox server needs
`api.github.com` for the release check. Agents older than this feature cannot
self-update: upgrade them by hand once. Updates are self-maintenance of the
agent; it still takes no remediation action on the host. See
[Troubleshooting](operations/TROUBLESHOOTING.md#endpoint-agent-issues) when an
update stays pending or fails.

## Scans and scan history

Each endpoint has a **Scan history** tab in its *Endpoints* drawer: every
vulnerability scan (grype), YARA file scan, package inventory and system
inventory the agent runs, scheduled or on demand, with who asked, when it ran,
how long it took, its status and a one-line result (findings new / no longer
reported, packages added / removed, YARA hits, inventory changed or not).
Stored in `edr_agent_scans` (migration `050_edr_agent_scans.sql`).

**On demand.** *Scan now* in the drawer (pick the types) or *Scan selected* on
the list (up to 200 endpoints, after a confirmation) creates a `pending`
request per endpoint and type; analysts, operators and admins can request and
cancel, every role can read the history. The agent's next heartbeat (about a
minute) carries the request in `scan_requests`; the agent reports `running`,
runs the scan at once without moving its schedule, then reports `succeeded` or
`failed` with a summary. A request for a scan already queued or running on that
endpoint returns the existing one. If the same scan is already running on its
schedule, the request runs right after it, never alongside. An offline
endpoint keeps the request (shown *queued — agent offline*) for 24 hours, then
it expires; a run not reported finished within 12 hours expires too. A pending
request can be cancelled. An on-demand YARA scan checks every file (the
scheduled passes after startup check only files changed since the previous
one), under the same CPU limits; an on-demand package inventory always sends
the full list.

**Scheduled runs** are reported by the agent too (trigger `schedule` or
`startup`, or `policy` for runs its scan policy issued, shown as *scan policy*
with the policy's name). YARA's minute-by-minute incremental passes are
recorded only when they find something; full passes always are.

**Summaries.** The server computes the vulnerability, package and inventory
counts from the report the scan sent (`scan_id` on `POST /vulnerabilities`,
`/packages`, `/inventory`). `resolved` for vulnerabilities counts open findings
of the previous report that the new one no longer holds; the server does not
close them. The agent's YARA summary is `hits`, `new_hits` and `full`; osquery
returns only matching files, so there is no files-scanned count.

**Older agents.** Agents before v0.0.20 neither report scans nor run requests;
the drawer says so (the agent reports the `adhoc_scans` capability in its
heartbeat) and requests sent to them expire. Retention: 90 days, and at most
the newest 200 rows per endpoint and scan type, pruned with stale requests by
the `edr-agent-release` job every 6 hours.

## Scan policies

*Endpoints → Scan policies* sets which scans endpoints run and when, instead of
each agent's built-in intervals. Stored in `edr_scan_policies`,
`edr_agents.scan_policy_id` / `scan_policy_overrides` and
`edr_agent_policy_runs` (migration `054_edr_scan_policies.sql`); logic in
`backend/src/services/edr/scanPolicies.ts`.

- **Policies.** A policy has one entry per scan type (vulnerability,
  YARA, package inventory, system inventory): on or off; a schedule, either a
  calendar one like Scheduled Scans' (hourly at a minute / every N hours,
  daily, weekly on chosen days, monthly, in a time zone) or a fixed interval
  (15 minutes to 30 days, counted from the endpoint's last run); and an
  optional **time window** ("only start between 22:00 and 06:00" in a time
  zone; it may wrap past midnight) — a scan that comes due outside it waits
  for it to open. The editor shows the next runs the server computes.
- **Default and named policies.** Exactly one policy is the default: every
  endpoint follows it unless assigned a named policy (select endpoints, then
  *Assign policy*, or pick one in the endpoint's *Scan policy* tab). The
  default can be edited but not deleted; deleting a named policy moves its
  endpoints back to the default. The default starts as what agents did on
  their own: system inventory hourly, packages every 6 hours, vulnerabilities
  and a full YARA pass daily.
- **Per-endpoint overrides.** In the drawer's *Scan policy* tab, *Override*
  replaces one scan type's entry for that endpoint only (*Clear* returns it to
  the policy). The tab shows each type's source (policy or override), its
  schedule, its next three runs, whether a due run waits for its window, and
  the last policy run.
- **Who.** Everyone on the Endpoints page (analysts and up) sees policies and
  each endpoint's effective schedule. Operators and admins create, edit,
  delete, assign and override, as they manage Scheduled Scans; every write is
  audited (`edr.scan_policy.*`). *Scan now* (analysts and up) still runs any
  scan at once, whatever the policy says.

**Delivery: the server schedules, the agent runs.** The server works out when
each endpoint's scans are due and issues them as scan requests in the
heartbeat response (`scan_requests`, trigger `policy`), the path *Scan now*
uses, so the agent needs no schedule logic. The config's `scan_policy`
(`{managed: true, policy, scans: {<type>: {enabled}}}`) tells the agent the
server schedules its scans: it stops its own intervals and startup scans.
YARA's per-minute check of changed files keeps running while the policy
enables YARA; full passes are the policy's. Changing a policy, assignment or
override raises the affected agents' `config_version`, so they re-pull the
config within a minute.

**When a scan is due.** Checked on every heartbeat, per endpoint and type
(`edr_agent_policy_runs`): an endpoint new to policies runs each enabled scan
once right away (its baseline), then on schedule; after a run, a calendar
entry is next due at its next occurrence, an interval entry an interval later.
Changing an entry recomputes its next due time (a calendar entry: its next
occurrence; an interval one: an interval after the last run). A due scan whose
previous policy run is still queued or running is skipped, not doubled up.

**Offline endpoints.** Nothing is queued while an endpoint is offline. When it
reconnects, each scan that came due meanwhile runs **once** (missed runs are
not replayed), subject to its window; the next one is computed from then.

**Older agents.** Agents before v0.0.22 do not report the `policy_scans`
capability: the server issues them no policy scans and they keep their own
intervals (system inventory hourly, vulnerabilities daily, packages every 6
hours, YARA changed files every minute plus a full pass at startup). The list
marks them *agent runs its own intervals*, and their *Scan policy* tab says so
and shows what applies once they are updated.

## Machine performance

Agents from v0.0.23 report the host's performance (capability `perf_metrics`):
*Endpoints* shows a small CPU / memory / fullest-disk indicator per endpoint
(dimmed when the newest sample is over 3 minutes old) and the drawer's
**Performance** tab charts it. Stored by migration
`055_edr_performance.sql`; logic in
`backend/src/services/edr/edrPerformance.ts` and `perfConfig.ts`.

**What the agent sends.** Every minute a sample: CPU % (all cores, since the
previous sample), memory used / total (used excludes reclaimable page cache:
`MemTotal - MemAvailable` on Linux), swap, load average 1/5/15 (not on
Windows), uptime, used / free bytes per local filesystem (network and pseudo
filesystems and read-only images such as snaps are skipped; at most 32), and
bytes/s in and out per interface (loopback and container veths skipped; at
most 16). Every 5 minutes the 10 busiest processes by CPU (averaged over the
5 minutes; % of one core, as top shows it) and by resident memory: pid, name,
user, never command lines. Batched to `POST /api/edr/metrics` every minute;
unsent data waits in a buffer of 3 hours (kept across an agent restart) so a
short outage leaves no gap. No external tools or dependencies on Linux
(`/proc`); macOS also runs `vm_stat`, `netstat -ibn` and `ps` once a minute;
Windows uses the Win32 APIs.

**Storage and retention.** Raw samples (`edr_perf_samples`, one row per
endpoint and minute, ~8 MB per endpoint per week) are kept
`EDR_PERF_RAW_DAYS` (7) days and drive the 1h / 6h / 24h charts (1-, 2- and
5-minute buckets). Each batch recomputes the hourly rollup
(`edr_perf_hourly`: averages and peaks per hour, weighted by sample count) of
the hours it added samples to, from that hour's raw rows, so a late or re-sent
batch lands correctly and nothing is counted twice. Rollups are kept
`EDR_PERF_HOURLY_DAYS` (90) days and drive the 7d / 30d / 90d charts (1-hour,
4-hour and 1-day buckets), so no chart reads more than ~1,500 rows. Process
snapshots are kept 7 days. The `edr-agent-release` job (every 6 hours) prunes
all three in batches. A sample dated more than 7 days back or 5 minutes ahead
is refused. With 50 endpoints and a full week of samples (504,000 rows) the
charts answer in 5–17 ms (median; 1h–24h raw, 7d rollups), and one agent's
per-minute ingest takes ~8 ms.

**Settings and thresholds (scan policy).** Each scan policy's *Performance*
tab (operators and admins) turns metrics and process sampling on or off for
its endpoints (sent in the agent config as `performance`) and sets three
alert thresholds, checked on the server as samples arrive:

| Metric | Default | Notes |
|--------|---------|-------|
| CPU    | above 95% for 10 minutes, medium | all cores |
| Memory | above 95% for 10 minutes, medium | |
| Disk   | above 90%, high | per mount point |

"For N minutes" means every sample of the last N minutes is above the
threshold, and those samples cover the span (at least 80% of a sample a
minute), so an agent that just started cannot alert on two samples; 0 means
the newest sample alone. An agent's own `"performance_metrics": false` (or
`"performance_processes": false`) in its `agent.json` turns it off whatever
the policy says.

**Alerts.** A breach raises an ordinary alert (source `edr-perf`, linked to
the endpoint's asset, through the notification channels like other alerts;
not sent to AI triage, as it is operational rather than a security finding),
for example *Disk / 93% full on web-01*. There is **one open alert per
endpoint, metric and mount** (`edr_perf_alert_state`): more breaching samples
change nothing. It **recovers** once the value has been at least 3 points
below the threshold for up to 5 minutes (the newest sample for a 0-minute
threshold): the slot is freed and the alert notes the recovery
(`matched_data.performance_state: recovered`, `recovered_at`,
`recovered_value`, a line in the description); its status is left for an
analyst to close. Only after a recovery can a new breach raise a new alert, so
a value hovering at the threshold cannot raise a storm. Turning a threshold
(or metrics) off releases its open alerts (`threshold_off`); a disk whose
mount is not reported for an hour releases its alert (`target_missing`).
Thresholds are evaluated only on fresh data (the newest sample at most 10
minutes old), not on an old batch replayed later. The Performance tab lists
an endpoint's open performance alerts; the list counts them.

**Older agents.** Agents before v0.0.23 send nothing; their Performance tab
says to update them.

## Known follow-ups

- Endpoint alerts are inserted directly, so they don't yet fire Email/Slack/NTFY notifications (rule-based alerts still do).
- Server-pushed Sigma `rules` in `AgentConfig` are empty; wire to `/api/rules` (endpoint/Sigma) later.
- The Endpoints page is open to analysts and operators (endpoints, detections, vulnerabilities, packages, scan history, Scan now / Scan selected; operators also edit and assign scan policies). Enrollment, tokens, YARA rules, agent updates and removal stay admin-only. Viewers don't see the page, although the scan-history API allows them.
- YARA bundle status (version/source/size) + a "Pull YARA-Forge now" button live on
  the **Endpoints** page; per-agent "which version does this agent have"
  isn't tracked yet (the agent stores it locally; the server only knows the served version).

## Verify with the real agent

```sh
# in the siembox-endpoint repo
go build -o /tmp/siembox-agent ./cmd/siembox-agent
mkdir -p /tmp/agentdir
cat > /tmp/agentdir/agent.json <<EOF
{"server_url":"http://<server>:8421","enrollment_token":"<TOKEN_FROM_UI>"}
EOF
/tmp/siembox-agent -dir /tmp/agentdir -v run
```
Generate a token under **Endpoints**, run the agent, and it should appear in
the list; inventory fills the endpoint asset, scans surface vulns on it, and
detections show in the **Alerts** UI and the endpoint drill-down. Its
performance indicator appears within two minutes and the *Performance* tab's
charts fill a point a minute (`siembox-agent metrics` prints one sample
without a server).

**YARA self-test** (needs no server rules — the agent's baseline matches it):
drop a file containing `SIEMBOX_YARA_SELFTEST` into a watched dir (`~/Downloads`
on macOS, `/tmp` on Linux). A `siembox-yara-file-match` detection should land at
`POST /api/edr/events` and show as an alert. To confirm the *server* bundle is
flowing, the seeded v1 also matches the EICAR test string, and
`curl -s http://localhost:8421/api/edr/yara -H "Authorization: Bearer <jwt>"`
shows the current `version`/`sha256`/`bytes`.
