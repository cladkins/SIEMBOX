# SIEMBox

A lightweight, self-hosted Security Information and Event Management (SIEM) system built with Node.js, TypeScript, and Vue.js. As of **v2 — the Parser Platform**, parsers and detections are portable data: shareable, installable from a community catalog, and generatable by AI.

## Features

- **Declarative parser platform**: Parsers are pure data — a match pattern, canonical field mappings, and declarative `derivations` — so you can onboard a new log source without touching engine code.
- **In-app community catalog**: Browse and install **27 parsers** and **48 detection rules** from a GitHub catalog directly in the UI (*Parsers → Browse Catalog*, *Detection Rules → Browse Catalog*) — every item validated and self-tested before install, with search, filters, and install/update status. Export or import any item as portable JSON.
- **AI builder (bring your own key)**: Paste a log line to generate a parser, or describe a threat to generate a detection rule. A *generate → validate → auto-refine* loop runs against the real engine (≤3 attempts), so you never get an invalid artifact. Works with **Anthropic, OpenAI, or local Ollama**; your key is encrypted at rest.
- **Canonical normalization**: Every parser normalizes to one canonical schema, so a detection rule written once fires against logs from any source.
- **GeoIP enrichment**: Offline country / foreign-geo enrichment (no external calls), powering geo-aware detections such as foreign-login alerts.
- **Catalog-only by default**: A fresh install starts empty — no hardcoded parsers or detections. You install exactly what you want from the in-app catalog (*Browse Catalog → Install all*), so the deployment carries only the content you chose.
- **Syslog ingestion**: Receive logs via UDP/TCP on port 514.
- **Log shipper**: Universal log forwarder for collecting logs (files, Docker containers, systemd journals) from any host.
- **Vulnerability scanning**: Built-in Nuclei scanning with per-host asset tracking and a vulnerability management view.
- **Container scanning**: Scan any image for OS/library CVEs with Trivy. Optionally enumerate the images already running on your Docker host and scan them in one click.
- **Threat Intel**: Investigate any IP — its GeoIP country, the log events it produced, and the alerts it triggered — with a country choropleth on the dashboard that drills into source IPs. Enriched with **external threat feeds** (free abuse.ch / Tor / blocklist.de blocklists) and optional **bring-your-own-key reputation** (AbuseIPDB, AlienVault OTX).
- **Ready-made parsers in the catalog**: Nginx, Traefik, Caddy, Authelia, Keycloak, Nextcloud, Pi-hole, Vaultwarden, UniFi, Home Assistant, Plex, Jellyfin, and more — one click to install from *Parsers → Browse Catalog*.
- **Alert management**: View, acknowledge, and manage security alerts.
- **Log retention**: Configurable retention policies with automated cleanup.
- **User management**: Role-based access control (Admin, Analyst, Viewer).
- **Dashboard**: Real-time visualization of logs, alerts, assets, and vulnerabilities.

## Quick Start

SIEMBox runs as two parts:

- **The main stack** — the server: web UI, API, syslog listener, and database. Deploy this once, on your SIEMBox host.
- **The log shipper** — an *optional* lightweight forwarder you install on **other** machines to push their logs to the main stack.

---

### Main stack

Two compose files live at the repo root:

| File | Use it for |
|------|-----------|
| `compose.prod.yaml` | **Recommended.** Runs pre-built images from GHCR. |
| `compose.yaml` | Builds the images locally from source (development). |

Once it's up, the **web UI is at `http://<your-server-ip>:8420`** and the API is on port **8421**.

#### Option 1: Pre-built images (recommended)

```bash
# Download the production compose file
curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/compose.prod.yaml

# Create a .env file with your secrets
cat > .env << EOF
DB_PASSWORD=your_secure_password
JWT_SECRET=your_jwt_secret_32_chars_min
DEFAULT_ADMIN_PASSWORD=your_admin_password
EOF

# Start SIEMBox
docker compose -f compose.prod.yaml up -d
```

Then open `http://<your-server-ip>:8420` and log in as `admin` with the password you set.

#### Option 2: Build from source

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
cp .env.example .env        # then edit .env
docker compose up -d --build
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

---

### Log shipper (optional)

The **log shipper** is a small container you install on any host whose logs you want in SIEMBox (a web server, a NAS, a Docker host…). It authenticates to the main stack with an API key and forwards log files, Docker container logs, and systemd journals over the network — it does **not** need the rest of the SIEMBox stack running locally.

Two compose files live in [`log-shipper/`](./log-shipper):

| File | Use it for |
|------|-----------|
| `log-shipper/compose.prod.yaml` | **Recommended — standalone.** Pre-built image; needs only this file + a `.env`. |
| `log-shipper/compose.yaml` | Builds the shipper image locally from source. |

```bash
# 1. In the SIEMBox UI: Log Shippers -> Add Shipper -> copy the API key.

# 2. On the host you want to collect logs from:
mkdir siembox-shipper && cd siembox-shipper
curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/log-shipper/compose.prod.yaml

# 3. Point it at your SIEMBox server (note the backend port, 8421):
cat > .env << EOF
SHIPPER_API_KEY=paste-your-api-key-here
SIEMBOX_API_URL=http://your-siembox-ip:8421/api
EOF

# 4. Edit compose.prod.yaml and uncomment the volume mounts for the logs
#    you want to ship (Docker socket, /var/log paths, etc.).

# 5. Start it
docker compose -f compose.prod.yaml up -d
```

The shipper should show as **online** in the UI within ~30 seconds. Full setup, log-source configuration, and troubleshooting are in the **[Log Shipper README](./log-shipper/README.md)**.

## Documentation

📚 **[GitHub Wiki](https://github.com/cladkins/SIEMBOX/wiki)** — friendly, navigable guides (Installation, Configuration, Parsers, Detections, Threat Intel, Scanning, API, FAQ). Pages are staged in [`wiki/`](./wiki); see [publishing](./docs/wiki-publishing.md).

📖 **[Complete Documentation Index](./docs/README.md)** — full in-repo reference documentation

### Quick Links

| I want to... | Go to... |
|-------------|----------|
| 🚀 Deploy SIEMBox | [Deployment Guide](./DEPLOYMENT.md) |
| 💻 Start developing | [Getting Started (Development)](./docs/guides/GETTING_STARTED_DEVELOPMENT.md) |
| 📤 Set up log forwarding | [Log Shipper Setup](./log-shipper/README.md) |
| 🔍 Search APIs | [API Reference](./API.md) |
| 🛡️ Secure my installation | [Security Hardening](./SECURITY.md) |
| 🐛 Fix an issue | [Troubleshooting Guide](./docs/operations/TROUBLESHOOTING.md) |

### Getting Started

**For Users:**
- **[Deployment Guide](./DEPLOYMENT.md)** - Installation, configuration, and setup
- **[Log Shipper Setup](./log-shipper/README.md)** - Universal log forwarder configuration
- **[Security Hardening](./SECURITY.md)** - Comprehensive security guide

**For Developers:**
- **[Getting Started (Development)](./docs/guides/GETTING_STARTED_DEVELOPMENT.md)** - Complete setup guide for developers
- **[Backend Development](./backend/README.md)** - Backend API development guide
- **[Frontend Development](./frontend/README.md)** - Frontend UI development guide
- **[Contributing Guide](./CONTRIBUTING.md)** - How to contribute to SIEMBox

### Log Shipper Documentation
- **[Log Shipper README](./log-shipper/README.md)** - Setup and configuration
- **[Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)** - Verify logs are flowing correctly
- **[Quick Reference](./log-shipper/QUICK-REFERENCE.md)** - Common commands and troubleshooting

### Reference Documentation
- **[API Reference](./API.md)** - Complete REST API documentation
- **[Community Parsers](./PARSERS.md)** - Pre-built parsers for common log sources
- **[Detection Rules](./RULES.md)** - Built-in and community detection rules
- **[Parser Platform Plan](./docs/parser-platform-plan.md)** - The v2 declarative engine + catalog design
- **[Canonical Schema](./docs/canonical-schema.md)** - The normalized field schema parsers map to
- **[Detection Normalization](./docs/detection-normalization.md)** - How rules match across log sources
- **[GeoIP Enrichment](./docs/geoip.md)** - Offline country / foreign-geo enrichment
- **[Parser Documentation](./docs/parsers/)** - Application-specific parser guides
- **[Architecture Documentation](./docs/architecture/)** - System design and specifications

### Operations & Troubleshooting
- **[Troubleshooting Guide](./docs/operations/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Log Shipper Diagnostics](./docs/operations/SHIPPER-DIAGNOSTICS.md)** - Debug log forwarding issues
- **[Operations Guides](./docs/operations/)** - Operational documentation and checklists

## Architecture

- **Frontend**: Vue.js 3 + Element Plus UI + Vite
- **Backend**: Node.js + TypeScript + Express
- **Database**: PostgreSQL with JSONB for flexible log storage
- **Log Shipper**: Alpine-based log forwarder (optional component)
- **Deployment**: Docker Compose

## Contributing

We welcome parser and rule contributions! See [PARSERS.md](./PARSERS.md) for guidelines on submitting parsers.

## License

MIT License - See LICENSE file for details

## Support

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions

## Roadmap

- [x] CEF (Common Event Format) parser
- [x] Declarative parser platform + portable parser/detection catalog (v2)
- [x] AI-assisted parser & detection authoring (v2)
- [x] Canonical normalization + GeoIP enrichment (v2)
- [x] Email / Slack / NTFY alert notifications
- [x] Threat intelligence (IP drill-down, country map, blocklist feeds, BYO-key reputation)
- [x] GeoIP dashboard map (alerts by country)
- [x] Container vulnerability scanning (Trivy) + scheduled scans
- [x] External threat-intelligence feeds (blocklists + BYO-key reputation)
- [ ] Additional parser types (LEEF)
- [ ] Advanced correlation rules
- [ ] Multi-tenancy support
