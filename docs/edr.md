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
- `GET  /agents/:id/config` → `AgentConfig` (includes `yara_rules_version` and `agent_update`)
- `GET  /agents/:id/yara` → curated YARA bundle as raw `text/plain` (empty body valid)
- `POST /inventory` · `POST /events` · `POST /vulnerabilities` → `202 Accepted`
- `POST /scans` → `200` `{scan_id, status, accepted}`: the agent reports a scan's start or end (see [Scans and scan history](#scans-and-scan-history))
- `POST /packages` → `200` with `{accepted, unchanged, snapshot_required, package_count, stored, removed, skipped, truncated}` (installed software, see [Installed packages](#installed-packages))

**Console-facing** (JWT):
- Analyst, operator or admin: `GET /agents`, `GET /agents/:id`, `GET /agents/:id/vulnerabilities`, `GET /agents/:id/packages`, `GET /agents/:id/detections`
- Admin: `DELETE /agents/:id`
- Admin, agent updates: `GET /agent-updates`, `POST /agent-updates/check`, `PUT /agent-updates/settings`, `POST /agents/:id/update`, `DELETE /agents/:id/update`, `POST /agents/update-outdated` (see [Agent updates](#agent-updates) and `docs/reference/API.md`)
- Scans (analyst and up; history every role): `POST /agents/:id/scans`, `POST /agents/scans/bulk`, `POST /agents/:id/scans/:scanId/cancel`, `GET /agents/:id/scans`
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
- **Rate limiting:** the agent-key routes (heartbeat, config, YARA, inventory, events, vulnerabilities, packages) carrying `X-Agent-ID`, with the method each route answers, skip the general per-address limiter, so a fleet behind one NAT address isn't throttled; they have their own, higher per-address limit (`EDR_AGENT_RATE_MAX`, default 30000 per 15 minutes) in front of agent auth. Enrollment counts toward the general limit, with or without `X-Agent-ID`. The address is the agent's TCP address: an `X-Forwarded-For` it sends to port 8421 is ignored.

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
`startup`). YARA's minute-by-minute incremental passes are recorded only when
they find something; full passes always are.

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

## Known follow-ups

- Endpoint alerts are inserted directly, so they don't yet fire Email/Slack/NTFY notifications (rule-based alerts still do).
- Server-pushed Sigma `rules` in `AgentConfig` are empty; wire to `/api/rules` (endpoint/Sigma) later.
- The Endpoints page is open to analysts and operators (endpoints, detections, vulnerabilities, packages, scan history, Scan now / Scan selected). Enrollment, tokens, YARA rules, agent updates and removal stay admin-only. Viewers don't see the page, although the scan-history API allows them.
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
detections show in the **Alerts** UI and the endpoint drill-down.

**YARA self-test** (needs no server rules — the agent's baseline matches it):
drop a file containing `SIEMBOX_YARA_SELFTEST` into a watched dir (`~/Downloads`
on macOS, `/tmp` on Linux). A `siembox-yara-file-match` detection should land at
`POST /api/edr/events` and show as an alert. To confirm the *server* bundle is
flowing, the seeded v1 also matches the EICAR test string, and
`curl -s http://localhost:8421/api/edr/yara -H "Authorization: Bearer <jwt>"`
shows the current `version`/`sha256`/`bytes`.
