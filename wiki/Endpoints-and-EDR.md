# Endpoints & EDR

SIEMBox v3 adds **endpoint detection & response (EDR)**: lightweight agents you install on your hosts that report **inventory**, **detections**, and **vulnerabilities** back to SIEMBox, and run **YARA** scans using rule packs delivered by the server.

> **Two pieces.** This repo is the **server side** — the `/api/edr/*` API, the **Endpoints (EDR)** admin page, and YARA bundle delivery. The **agent** itself is a separate, lightweight component (a small Go binary) that you install on each endpoint and enroll from the UI.

## Where to find it

**Assets & Vulnerabilities → Endpoints (EDR)** (admin only). The page shows your endpoint fleet (hostname, OS, architecture, agent version, live status, open vulnerabilities, recent detections, last seen, last/next scan), enrollment-token management, and the current **YARA bundle** status.

## Enrolling an endpoint

1. **Generate a token.** On *Endpoints (EDR)*, create a one-time **enrollment token** (shown once — copy it).
2. **Install + enroll the agent** on the host, pointing it at your server (`https://<siembox-host>:8421`) with that token.
3. The agent calls `POST /api/edr/agents/enroll`; the server validates the token (single-use, optional expiry), then returns a unique **agent ID** and **API key** (the key is shown once and stored only as a hash server-side).
4. The agent **heartbeats** (~60s) and **pulls config** (~5m). Revoke a token anytime from the same page; revoked/expired tokens can't enroll.

## What the agent reports

Endpoint data flows into the **same** tables and views as the rest of SIEMBox, so there's one place to look:

| Agent sends | Lands in | Surfaced as |
|-------------|----------|-------------|
| **Inventory** (hostname, OS, version, arch, IP) | `assets` (`asset_type=endpoint`), keyed by IP | An **Asset** (correlates with log-/Nuclei-discovered hosts) |
| **Detections** | `alerts` (`source=edr`), deduped by event id | **Alerts**, linked to the endpoint asset |
| **Vulnerabilities** (local scan) | `asset_vulnerabilities` (idempotent by asset+CVE) | **Vulnerability Management** + the asset's vulns |

Because endpoints are assets, they also appear in **[Asset-360](Architecture)** — one asset view tying together its vulnerabilities, the alerts it raised, its agent, any matching log shipper, GeoIP, and open ports.

## Server-delivered YARA rule packs

The server stores **versioned YARA bundles** and serves the current one to agents. Agents combine the server bundle with their own baseline ruleset before scanning.

- **Baseline.** A small starter bundle (v1) ships seeded, so detection works out of the box.
- **Updates are automatic.** Publishing a new bundle bumps every agent's composite `config_version`; on the next heartbeat each agent notices the new `yara_rules_version` and pulls the rules. Existing agents are never mutated.
- **YARA-Forge (opt-in).** Set `EDR_YARA_FORGE_ENABLED=true` to have a daily job import the open-source **YARA-Forge** pack and publish a new bundle when it changes. Admins can also pull on demand with **"Pull YARA-Forge now"** on the Endpoints page (`POST /api/edr/yara/refresh`).
- **Retention.** Only the newest `EDR_YARA_KEEP_VERSIONS` bundles are kept (default 10); agents always pull the highest version.

See [Configuration → EDR](Configuration#edr--yara-optional) for the knobs.

## Verifying it works

- **YARA status card** on the Endpoints page shows the current bundle version, source, size, and timestamp.
- **Self-test:** drop a file containing the string `SIEMBOX_YARA_SELFTEST` into a watched directory on an enrolled host; the agent should detect it and raise an alert (`source=edr`) within a scan cycle.

## API

The full server-side API (enrollment, heartbeat, config, inventory/events/vulnerabilities ingest, YARA, admin endpoints) is documented in-repo: **[docs/edr.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/edr.md)**. Key route groups: `/api/edr/agents/*`, `/api/edr/tokens`, `/api/edr/yara`, `/api/edr/{inventory,events,vulnerabilities}`.

See also: [Architecture](Architecture) · [Vulnerability & Container Scanning](Vulnerability-and-Container-Scanning) · [Configuration](Configuration).
