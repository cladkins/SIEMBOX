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

**Setup:**

1. **Create a Shipper in SIEMBox UI**
   - Navigate to **Log Shippers** in the SIEMBox web interface
   - Click **Add Shipper**
   - Enter a name and description
   - Copy the generated API key

2. **Configure Sources and Volumes**
   - Click **View** on your shipper
   - Add log sources (files, Docker containers, systemd journals)
   - Add volume mounts for accessing log files
   - Sources and volumes are automatically synced to the shipper

3. **Deploy the Shipper**

   Create a `.env` file with your API key:
   ```bash
   SHIPPER_API_KEY=your-api-key-here
   SIEMBOX_API_URL=http://your-siembox-ip:3001/api
   ```

   Deploy using docker-compose:
   ```bash
   docker compose -f docker-compose.managed.yml up -d
   ```

   Or deploy manually:
   ```bash
   docker run -d \
     --name siembox-log-shipper \
     --network host \
     -v /var/log:/host-logs:ro \
     -v /var/run/docker.sock:/var/run/docker.sock:ro \
     -e SHIPPER_API_KEY=your-api-key-here \
     -e SIEMBOX_API_URL=http://your-siembox-ip:3001/api \
     siembox-log-shipper:managed
   ```

4. **Verify in SIEMBox UI**
   - The shipper should appear as "online" within 30 seconds
   - Check the "Last Seen" timestamp to confirm heartbeat
   - View configured sources and their status

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

1. Verify source is enabled in SIEMBox UI
2. Check file paths are correct and accessible
3. Verify volume mounts in docker-compose.yml
4. Check syslog receiver is running in SIEMBox:
   ```bash
   docker logs siembox-backend | grep -i syslog
   ```

### Configuration not updating

1. Check poll interval (default 30s)
2. Verify shipper is online in UI
3. Check for errors in shipper logs
4. Manually trigger config fetch:
   ```bash
   docker restart siembox-log-shipper
   ```

## Examples

See the [examples](./examples/) directory for common configurations:

- `examples/nginx.env` - Nginx access and error logs
- `examples/docker.env` - Docker container logs
- `examples/systemd.env` - System service logs
- `examples/multi-source.env` - Multiple sources combined

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
