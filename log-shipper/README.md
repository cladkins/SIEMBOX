# SIEMBox Log Shipper

Universal log forwarder for sending logs from any source to SIEMBox via syslog. Deploy this lightweight container on any machine to forward logs from files, Docker containers, or systemd journals.

## Features

- **Centralized Management**: Configure and manage shippers from the SIEMBox web UI
- **Auto-Registration**: Shippers automatically register and poll for configuration updates
- **File Tailing**: Monitor and forward any log file
- **Docker Container Logs**: Forward logs from specific Docker containers
- **Systemd Journal**: Forward systemd journal logs (host system logs)
- **Multiple Sources**: Monitor multiple log sources simultaneously
- **Real-Time Updates**: Configuration changes apply automatically (polls every 30s)
- **Heartbeat Monitoring**: Track shipper health and last-seen status
- **Lightweight**: Based on Alpine Linux (~15MB image)
- **Custom Tags**: Tag logs by source for easy filtering in SIEMBox

## Deployment Modes

### Managed Mode (Recommended)

In managed mode, the shipper is configured entirely from the SIEMBox web UI. This is the recommended approach for centralized management.

**Advantages:**
- Configure everything from one central UI
- No manual file editing required
- Real-time configuration updates
- Monitor shipper status and health
- Easy to manage multiple shippers

**Quick Start:**

### Step 1: Create Shipper in SIEMBox UI

1. Navigate to **Log Shippers** in the SIEMBox web interface
2. Click **Add Shipper**
3. Enter a name (e.g., "Web Server") and optional description
4. **Copy the API key** - you'll need this for deployment

### Step 2: Deploy the Shipper Container

Create a docker-compose.yml file on your target machine:

```yaml
services:
  siembox-log-shipper:
    image: siembox-log-shipper:managed
    container_name: siembox-log-shipper
    restart: unless-stopped
    network_mode: host
    environment:
      - SHIPPER_API_KEY=paste-your-api-key-here
      - SIEMBOX_API_URL=http://your-siembox-ip:3001/api
    volumes:
      # Mount directories containing log files you want to monitor
      - /var/log:/var/log:ro                                    # System logs
      - /path/to/app/logs:/path/to/app/logs:ro                 # Application logs
      # For Docker container logs (optional)
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

**IMPORTANT:** Update the volumes section to match where your log files are located on the host machine.

Deploy the shipper:
```bash
docker compose up -d
```

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
   - **File Path**: Full path to log file (e.g., `/var/log/nginx/access.log`)
   - **Tag**: Friendly name (e.g., `nginx-access`)
   - **Facility**: local0 (or choose different for each source)
   - **Enabled**: ✓ (checked)
4. Click **Save**

**The shipper will automatically pick up the configuration within 30 seconds and start forwarding logs!**

### Important Notes:

- **Volume mounts** in docker-compose.yml give the container access to directories
- **Log sources** in the UI tell the shipper which specific files to tail
- File paths in sources must match the paths INSIDE the container (same as host if you use matching mounts)
- You can add/edit/remove sources anytime through the UI without restarting the container

### Standalone Mode

In standalone mode, the shipper is configured using a local `.env` file. This is useful for simple deployments or when SIEMBox is not accessible during setup.

**Setup:**

1. **Copy Configuration Files**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` File**

   Set your SIEMBox server IP and configure sources:
   ```bash
   SIEM_HOST=192.168.1.100
   SIEM_PORT=514

   # Example: Monitor Nginx access logs
   SOURCE_1_TYPE=file
   SOURCE_1_FILE_PATH=/logs/nginx/access.log
   SOURCE_1_TAG=nginx-access
   SOURCE_1_FACILITY=local0
   SOURCE_1_ENABLED=true
   ```

3. **Deploy**
   ```bash
   docker compose up -d
   ```

## Configuration

### Environment Variables

#### Managed Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `SHIPPER_API_KEY` | *required* | API key from SIEMBox UI |
| `SIEMBOX_API_URL` | `http://localhost:3001/api` | SIEMBox API endpoint |
| `CONFIG_POLL_INTERVAL` | `30` | How often to check for config updates (seconds) |
| `HEARTBEAT_INTERVAL` | `60` | How often to send heartbeat (seconds) |

#### Standalone Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `SIEM_HOST` | `192.168.1.76` | SIEMBox server IP address |
| `SIEM_PORT` | `514` | Syslog port (UDP/TCP) |
| `SOURCE_N_TYPE` | - | Source type: `file`, `docker`, or `journal` |
| `SOURCE_N_FILE_PATH` | - | Path to log file (for file sources) |
| `SOURCE_N_CONTAINER_NAME` | - | Container name (for docker sources) |
| `SOURCE_N_JOURNAL_UNIT` | - | Systemd unit (for journal sources) |
| `SOURCE_N_TAG` | - | Log tag for identification |
| `SOURCE_N_FACILITY` | `local0` | Syslog facility |
| `SOURCE_N_ENABLED` | `true` | Enable/disable source |

### Source Types

#### File Sources
Monitor and forward log files in real-time.

**Example:**
```bash
SOURCE_1_TYPE=file
SOURCE_1_FILE_PATH=/var/log/nginx/access.log
SOURCE_1_TAG=nginx-access
SOURCE_1_FACILITY=local0
```

#### Docker Container Sources
Forward logs from running Docker containers.

**Example:**
```bash
SOURCE_2_TYPE=docker
SOURCE_2_CONTAINER_NAME=nginx
SOURCE_2_TAG=nginx-container
SOURCE_2_FACILITY=local1
```

**Requirements:**
- Mount Docker socket: `-v /var/run/docker.sock:/var/run/docker.sock:ro`

#### Systemd Journal Sources
Forward logs from systemd services.

**Example:**
```bash
SOURCE_3_TYPE=journal
SOURCE_3_JOURNAL_UNIT=nginx.service
SOURCE_3_TAG=nginx-systemd
SOURCE_3_FACILITY=local2
```

**Requirements:**
- Mount journal directory: `-v /var/log/journal:/var/log/journal:ro`

## Volume Mounts

The shipper needs access to log files and Docker socket depending on your sources:

```yaml
volumes:
  # For file sources
  - /var/log:/host-logs:ro
  - /path/to/app/logs:/app-logs:ro

  # For Docker sources
  - /var/run/docker.sock:/var/run/docker.sock:ro

  # For systemd journal sources
  - /var/log/journal:/var/log/journal:ro
```

In managed mode, volumes are configured in the SIEMBox UI and automatically applied.

## Monitoring

### Managed Mode

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

The managed shipper includes a health check:
```bash
docker inspect siembox-log-shipper | jq '.[0].State.Health'
```

## Troubleshooting

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
   docker exec siembox-log-shipper curl -v http://siembox-ip:3001/api/health
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

2. **Add the volume mount to docker-compose.yml:**
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

### Managed Mode Flow

```
┌─────────────┐
│  SIEMBox UI │ (Configure shippers, sources, volumes)
└──────┬──────┘
       │
       ↓
┌─────────────┐
│ SIEMBox API │ (Store configuration)
└──────┬──────┘
       ↑
       │ Register & Poll (every 30s)
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

### Components

- **shipper-managed.sh**: Managed shipper agent with auto-registration
- **shipper.sh**: Standalone shipper with local config
- **Dockerfile.managed**: Container image for managed mode
- **Dockerfile**: Container image for standalone mode

## Building

Build the managed shipper image:
```bash
docker build -f Dockerfile.managed -t siembox-log-shipper:managed .
```

Build the standalone shipper image:
```bash
docker build -f Dockerfile -t siembox-log-shipper:latest .
```

## License

MIT License - See main SIEMBox repository for details.
