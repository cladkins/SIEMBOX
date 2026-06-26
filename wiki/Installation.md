# Installation

SIEMBox runs as two parts:

- **The main stack** — server: web UI, API, syslog listener, and database. Deploy this once on your SIEMBox host.
- **The log shipper** — an *optional* lightweight forwarder you install on **other** machines to push their logs to the main stack (see [Log Shippers](Log-Shippers)).

## Requirements

- A Linux host with **Docker** and the **Docker Compose** plugin.
- Inbound access to the ports below from the machines/log sources you want to reach it.

| Port | Protocol | Purpose |
|------|----------|---------|
| **8420** | TCP | Web UI |
| **8421** | TCP | REST API (and where shippers POST logs) |
| **514** | UDP + TCP | Syslog ingestion |

## Main stack

Two compose files live at the repo root:

| File | Use it for |
|------|-----------|
| `compose.prod.yaml` | **Recommended.** Runs pre-built images from GHCR. |
| `compose.yaml` | Builds the images locally from source (development). |

### Option 1 — Pre-built images (recommended)

```bash
# 1. Download the production compose file
curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/compose.prod.yaml

# 2. Create a .env with your secrets (see Configuration for the full list)
cat > .env << 'EOF'
DB_PASSWORD=your_secure_password
JWT_SECRET=your_jwt_secret_32_chars_min
DEFAULT_ADMIN_PASSWORD=your_admin_password
CREDENTIAL_ENCRYPTION_KEY=generate_a_64_char_hex_key
EOF

# 3. Start SIEMBox
docker compose -f compose.prod.yaml up -d
```

Generate the encryption key with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Option 2 — Build from source

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
cp .env.example .env     # then edit .env
docker compose up -d --build
```

## First login

1. Open `http://<your-server-ip>:8420`.
2. Log in as **`admin`** with the `DEFAULT_ADMIN_PASSWORD` you set.
3. SIEMBox starts **empty** (catalog-only). Go to **Parsers → Browse Catalog** and **Detection Rules → Browse Catalog** and install the content you want (or *Install all*). See [Parsers](Parsers) and [Detection Rules](Detection-Rules).
4. Point a log source at it: either configure devices to send **syslog** to `udp/tcp 514`, or install a **[Log Shipper](Log-Shippers)** on a host.

## Updating

```bash
docker compose -f compose.prod.yaml pull
docker compose -f compose.prod.yaml up -d
```

Database **migrations run automatically on startup** and are idempotent, so existing data is preserved across updates.

## Next steps

- **[Configuration](Configuration)** — every environment variable explained.
- **[Log Shippers](Log-Shippers)** — collect logs from other hosts.
- **[Troubleshooting](Troubleshooting)** — if the UI won't load or logs aren't arriving.
