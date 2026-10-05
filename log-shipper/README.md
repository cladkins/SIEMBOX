# SIEMBox Log Shipper

**Authenticated managed log forwarder** for SIEMBox. Deploy this lightweight container on any machine to forward logs from files, Docker containers, or systemd journals.

## 🔒 Security Notice

**ALL log shippers MUST authenticate with an API key.** This ensures:
- ✅ Centralized management and tracking
- ✅ Audit trail of which shippers are sending logs
- ✅ Ability to revoke access if compromised
- ✅ Visibility in the SIEMBox UI

The log shipper is **managed only** - there is no standalone/unauthenticated mode.

## 📚 Documentation

- **[Shipper Diagnostics](../docs/operations/SHIPPER-DIAGNOSTICS.md)** - Verify logs are flowing and debug forwarding
- **[Quick Reference](./QUICK-REFERENCE.md)** - Common commands and troubleshooting tips

## Features

- **Centralized Management**: Configure and manage shippers from the SIEMBox web UI
- **API Authentication**: All shippers authenticate with unique API keys
- **Auto-Registration**: Shippers automatically register and poll for configuration updates
- **File Tailing**: Monitor and forward any log file with glob pattern support
- **Docker Container Logs**: Forward logs from a specific container, or from all running containers at once
- **Systemd Journal**: Forward the host's systemd journal — the usual way to ship a Linux server's system logs
- **Multiple Sources**: Monitor multiple log sources simultaneously
- **Real-Time Updates**: Configuration changes apply automatically (polls every 30s)
- **Heartbeat Monitoring**: Track shipper health and last-seen status
- **Network Scanning**: Run nmap scans SIEMBox dispatches to it, out on the LAN where the SIEMBox backend's own nmap can't reach — see [Network Scanning](#network-scanning-lan-side-nmap)
- **Image**: Debian-slim based; bundles `journalctl` (for the systemd journal), the Docker CLI, and `nmap`
- **Custom Tags**: Tag logs by source for easy filtering in SIEMBox

## Quick Start

### Step 1: Create Shipper in SIEMBox UI

1. Navigate to **Log Shippers** in the SIEMBox web interface
2. Click **Add Shipper**
3. Enter a name (e.g., "Web Server") and optional description
4. **Copy the API key** - you'll need this for deployment

### Step 2: Deploy the Shipper Container

#### Option A: Using Pre-built Image (Recommended)

```bash
# Create a directory for the shipper
mkdir siembox-shipper && cd siembox-shipper

# Download the production compose file
curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/log-shipper/compose.prod.yaml

# Create .env file with your settings
cat > .env <<EOF
SHIPPER_API_KEY=paste-your-api-key-here
SIEMBOX_API_URL=http://your-siembox-ip:8421/api
EOF

# Start the shipper
docker compose -f compose.prod.yaml up -d
```

#### Option B: Build from Source

```bash
# Clone the repository
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX/log-shipper

# Create .env file with your settings
cat > .env <<EOF
SHIPPER_API_KEY=paste-your-api-key-here
SIEMBOX_API_URL=http://your-siembox-ip:8421/api
EOF

# Build and start
docker compose up -d --build
```

**IMPORTANT:** Update the `volumes` section in the compose file to match where your log files are located on the host machine.

### Step 3: Verify Shipper is Online

1. Return to the **Log Shippers** page in SIEMBox UI
2. Your shipper should show status: **online** within 30 seconds
3. Check the "Last Seen" timestamp confirms it's checking in

### Step 4: Add Log Sources

Now tell the shipper which log files to monitor:

1. Click **View** on your shipper
2. Click **Add Source** button
3. Configure the source:
   - **Type**: file
   - **File Path**: Full path to log file or wildcard pattern
     - Single file: `/var/log/nginx/access.log`
     - Wildcard: `/etc/app/stacks/npm/data/logs/*.log`
     - Multiple: `/var/log/app-*.log`
   - **Tag**: Friendly name (e.g., `nginx-access`)
   - **Facility**: local0 (or choose different for each source)
   - **Enabled**: ✓ (checked)
4. Click **Save**

**The shipper will automatically pick up the configuration within 30 seconds and start forwarding logs!**

### Shipping a Linux server's system logs

Forwarding a host's own system logs is the shipper's most common job. Two ways, depending on how the host logs:

- **Systemd journal (any modern Linux).** Mount the journal, then add a **Systemd Journal** source with the **unit left blank** to ship the entire journal:
  ```yaml
  volumes:
    - /var/log/journal:/var/log/journal:ro
  ```
  Add Source → Type **Systemd Journal**, Unit *(blank)*, Tag e.g. `system`. Set a unit such as `ssh.service` to ship just one service.
- **rsyslog text files.** Mount `/var/log`, then use the **"Add System Log Files"** button on the shipper — it creates File sources for `/var/log/syslog`, `/var/log/messages`, and `/var/log/auth.log` (paths that don't exist on the host are skipped):
  ```yaml
  volumes:
    - /var/log:/var/log:ro
  ```

### Wildcard Pattern Support

The log shipper supports glob patterns for file paths:
- `*.log` - All .log files in the directory
- `app-*.log` - All files starting with "app-" and ending in .log
- `/path/*/*.log` - All .log files in any subdirectory
- `/logs/app-[0-9].log` - Bracket expressions (app-0.log through app-9.log)

**Example:** `/etc/app/stacks/npm/data/logs/*.log` will tail all .log files in that directory.

**Note:** Wildcards are expanded when the shipper starts or configuration updates. New files created after startup won't be picked up until the next configuration poll or restart.

## Important Notes

- **Volume mounts** in compose.yml give the container access to directories
- **Log sources** in the UI tell the shipper which specific files to tail
- File paths in sources must match the paths INSIDE the container (same as host if you use matching mounts)
- You can add/edit/remove sources anytime through the UI without restarting the container
- **API key is required** - shippers without valid API keys will not be accepted

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHIPPER_API_KEY` | *required* | API key from SIEMBox UI |
| `SIEMBOX_API_URL` | `http://localhost:8421/api` | SIEMBox API endpoint |
| `CONFIG_POLL_INTERVAL` | `30` | How often to check for config updates (seconds) |
| `HEARTBEAT_INTERVAL` | `60` | How often to send heartbeat (seconds) |
| `CONTAINER_REPORT_INTERVAL` | `300` | How often to report the host's container images for vuln scanning (seconds; `0` disables) |
| `SCAN_POLL_INTERVAL` | `30` | How often to poll for dispatched nmap scan jobs (seconds; `0` disables scanning) |
| `SCAN_TIMEOUT` | `900` | Max wall-clock for a single dispatched nmap scan (seconds) |

### Source Types

#### File Sources
Monitor and forward log files in real-time.

**Configured in the SIEMBox UI:**
- Type: file
- File Path: `/var/log/nginx/access.log`
- Tag: `nginx-access`
- Facility: `local0`

#### Docker Container Sources
Forward logs from running Docker containers.

**Configured in the SIEMBox UI:**
- Type: docker
- Container Name: `nginx` — or leave **blank** (or `*` / `all`) to tail **every running container**, each tagged with its own name
- Tag: `nginx-container` (ignored in all-containers mode)
- Facility: `local1`

**Requirements:**
- Mount Docker socket: `-v /var/run/docker.sock:/var/run/docker.sock:ro`
- New/removed containers are picked up on the next config poll (~30s).

#### Systemd Journal Sources
Forward the host's systemd journal — the usual way to ship a Linux server's system logs.

**Configured in the SIEMBox UI:**
- Type: journal
- Unit filter: leave **blank** to ship the entire journal, or set a unit such as `ssh.service` to ship a single service
- Tag: `system`
- Facility: `local2`

**Requirements:**
- Mount the journal directory: `-v /var/log/journal:/var/log/journal:ro`
- Reads the journal with `journalctl`; only new entries are forwarded (existing history is not replayed).

## Network Scanning (LAN-side nmap)

SIEMBox can **dispatch nmap scans to this shipper** so they run from where the
shipper lives — out on your LAN — instead of from the SIEMBox backend. The
backend container normally sits on a Docker bridge network and can only see its
own bridge subnet, so its own nmap can't discover or scan real LAN hosts. A
shipper already runs on the network you want to scan, so it's the natural place
to run the scan from.

**How it works:** the shipper polls `GET /api/shippers/scan-jobs/<api_key>` every
`SCAN_POLL_INTERVAL` seconds. SIEMBox hands back any scans assigned to this
shipper, each with the **exact nmap flags and the validated target list the
server chose** — the shipper runs that command (`nmap … -oX -`) and POSTs the raw
XML back to `POST /api/shippers/scan-results`. The backend parses it through the
same code path as a backend-run scan, so results show up as assets and services
identically. This is on by default; set `SCAN_POLL_INTERVAL=0` to turn it off.

> **Security:** the shipper only ever runs flags and targets the server built
> and validated; it never accepts a scan command from anywhere else, and it
> passes every token to nmap as a separate argument (never a re-split string),
> so a target can't smuggle in extra nmap flags.

**Dispatching a scan to a shipper:** trigger an asset-discovery scan in SIEMBox
and select this shipper to run it. (Via the API, `POST /api/assets/scan` accepts
an `assignedShipperId`; omit it to run the scan on the backend as before.)

### Deployment for effective discovery

Where the shipper is on the network decides what it can find:

- **TCP connect and service scans** (`-sT`, `-sV`) work from a normal bridged
  container — outbound TCP is routed to the LAN by the host.
- **Ping sweeps and OS detection** (`-sn` ARP discovery, `-O`) need raw sockets
  and a direct link to the LAN segment. For these, run the shipper with **host
  networking** (recommended for a scanning shipper) or grant the raw-socket
  capabilities:

  ```yaml
  # compose: host networking — the shipper shares the host's LAN directly
  network_mode: host

  # …or keep bridge networking but allow raw-socket scans:
  cap_add:
    - NET_RAW
    - NET_ADMIN
  ```

A scan that the shipper can't run (nmap error, host unreachable, or a
`SCAN_TIMEOUT` of `900`s exceeded) is reported back and shown as **failed** in
SIEMBox rather than left hanging.

## Volume Mounts

The shipper needs access to log files and Docker socket depending on your sources:

```yaml
volumes:
  # For file sources
  - /var/log:/var/log:ro
  - /path/to/app/logs:/path/to/app/logs:ro

  # For Docker sources
  - /var/run/docker.sock:/var/run/docker.sock:ro

  # For systemd journal sources
  - /var/log/journal:/var/log/journal:ro
```

## Monitoring

In the SIEMBox UI, you can monitor:
- **Status**: Online/Offline/Pending
- **Last Seen**: When the shipper last checked in
- **Version**: Shipper version
- **Hostname**: Where the shipper is running
- **IP Address**: Shipper's IP
- **Sources**: Number and status of configured sources

### Logs

View shipper logs:
```bash
docker logs siembox-log-shipper

# Follow logs
docker logs -f siembox-log-shipper
```

### Health Check

The shipper includes a health check:
```bash
docker inspect siembox-log-shipper | jq '.[0].State.Health'
```

## Troubleshooting

For comprehensive troubleshooting, see:
- **[Shipper Diagnostics](../docs/operations/SHIPPER-DIAGNOSTICS.md)** - Verification procedures and forwarding diagnostics
- **[Quick Reference](./QUICK-REFERENCE.md)** - Quick troubleshooting commands

### Shipper shows as "Offline"

1. Check shipper logs for errors:
   ```bash
   docker logs siembox-log-shipper
   ```

2. Verify API key is correct:
   ```bash
   docker exec siembox-log-shipper env | grep SHIPPER_API_KEY
   ```

3. Check network connectivity to SIEMBox:
   ```bash
   docker exec siembox-log-shipper curl -v http://siembox-ip:8421/api/health
   ```

### Logs not appearing in SIEMBox

**Check shipper logs for "File not found" warnings:**
```bash
docker logs siembox-log-shipper | grep "File not found"
```

If you see warnings like:
```
[WARN] File not found: /var/log/nginx/access.log
```

This means the shipper can't access the file. **This is usually a volume mount issue.**

**Solution:**

1. **Verify the file exists on the HOST machine:**
   ```bash
   ls -la /var/log/nginx/access.log
   ```

2. **Add the volume mount to compose.yml:**
   ```yaml
   volumes:
     - /var/log/nginx:/var/log/nginx:ro
   ```

3. **Restart the shipper to apply volume changes:**
   ```bash
   docker compose down
   docker compose up -d
   ```

4. **Verify logs start flowing within 30 seconds**

**Other checks:**

1. Verify source is enabled in SIEMBox UI
2. Check file paths match EXACTLY (case-sensitive)
3. Ensure file has read permissions
4. Check syslog receiver is running in SIEMBox:
   ```bash
   docker logs siembox-backend | grep -i syslog
   ```

### How to Verify Logs Are Being Received

**Option 1: Check the Logs page in SIEMBox UI**
- Navigate to the "Logs" menu in the web interface
- Filter by the source tag you configured
- You should see logs appearing in real-time

**Option 2: Query the database directly**
```bash
# Check total log count
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) as total_logs FROM raw_logs;"

# View recent logs
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT timestamp, source_ip, LEFT(raw_message, 100) as message FROM raw_logs ORDER BY timestamp DESC LIMIT 10;"

# Check logs from a specific source IP
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM raw_logs WHERE source_ip = '192.168.1.100';"
```

**Option 3: Watch backend logs for incoming syslog messages**
```bash
# This will show when logs are being received
docker logs siembox-backend -f
```

### Configuration not updating

1. Check poll interval (default 30s)
2. Verify shipper is online in UI
3. Check for errors in shipper logs
4. Manually trigger config fetch:
   ```bash
   docker restart siembox-log-shipper
   ```

## Architecture

### Managed Flow

```
┌─────────────┐
│  SIEMBox UI │ (Configure shippers, sources, volumes)
└──────┬──────┘
       │
       ↓
┌─────────────┐
│ SIEMBox API │ (Authenticate & store configuration)
└──────┬──────┘
       ↑
       │ Register & Poll (every 30s) + API Key
       │
┌──────┴──────┐
│ Log Shipper │ (Auto-applies config)
└──────┬──────┘
       │
       ↓ Tail logs & forward
┌─────────────┐
│   Syslog    │ (SIEMBox:514)
└─────────────┘
```

## Container Image

The log shipper image is available on GitHub Container Registry:

```
ghcr.io/cladkins/siembox-log-shipper:latest
```

### Available Tags
- `latest` - Most recent build from main branch
- `1.0.0`, `1.0`, `1` - Semantic version tags from releases

### Building from Source

To build the shipper image locally:
```bash
docker build -t siembox-log-shipper:latest .
```

## License

MIT License - See main SIEMBox repository for details.
