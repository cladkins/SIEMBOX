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

New tables (migration `016_edr_agents.sql`): `edr_agents`, `edr_enrollment_tokens`.
`alerts` gains nullable `asset_id` / `source` / `event_id` columns (+ a partial
unique index on `event_id` for replay dedup).

## API (`/api/edr/*`, port 8421)

**Agent-facing** (per-agent key: `Authorization: Bearer <key>` + `X-Agent-ID`):
- `POST /agents/enroll` — exchange a one-time enrollment token for `{agent_id, agent_api_key, config}` (key returned once; only its sha256 is stored).
- `POST /agents/:id/heartbeat` → `{config_version}` (optional `update` progress report, see [Agent updates](#agent-updates))
- `GET  /agents/:id/config` → `AgentConfig` (includes `yara_rules_version` and `agent_update`)
- `GET  /agents/:id/yara` → curated YARA bundle as raw `text/plain` (empty body valid)
- `POST /inventory` · `POST /events` · `POST /vulnerabilities` → `202 Accepted`

**Admin-facing** (JWT + admin role):
- `GET /agents`, `GET /agents/:id`, `GET /agents/:id/vulnerabilities`, `GET /agents/:id/detections`, `DELETE /agents/:id`
- Agent updates: `GET /agent-updates`, `POST /agent-updates/check`, `PUT /agent-updates/settings`, `POST /agents/:id/update`, `DELETE /agents/:id/update`, `POST /agents/update-outdated` (see [Agent updates](#agent-updates) and `docs/reference/API.md`)
- `POST /tokens` (generate, plaintext shown once), `GET /tokens`, `DELETE /tokens/:hash` (revoke)
- `GET /yara` (current bundle version/sha/size), `POST /yara/refresh` (pull YARA-Forge now)

The **Endpoints** UI (admin) lives under *Assets & Vulnerabilities → Endpoints*:
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
- **Rate limiting:** the agent-key routes (heartbeat, config, YARA, inventory, events, vulnerabilities) carrying `X-Agent-ID`, with the method each route answers, skip the general per-address limiter, so a fleet behind one NAT address isn't throttled; they have their own, higher per-address limit (`EDR_AGENT_RATE_MAX`, default 30000 per 15 minutes) in front of agent auth. Enrollment counts toward the general limit, with or without `X-Agent-ID`. The address is the agent's TCP address: an `X-Forwarded-For` it sends to port 8421 is ignored.

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

## Known follow-ups

- Endpoint alerts are inserted directly, so they don't yet fire Email/Slack/NTFY notifications (rule-based alerts still do).
- Server-pushed Sigma `rules` in `AgentConfig` are empty; wire to `/api/rules` (endpoint/Sigma) later.
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
