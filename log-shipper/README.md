# SIEMBox Log Shipper

Universal log forwarder for sending logs from any source to SIEMBox via syslog. Deploy this lightweight container on any machine to forward logs from files, Docker containers, or the host system.

## Features

- **File Tailing**: Monitor and forward any log file
- **Docker Container Logs**: Forward logs from specific Docker containers
- **Systemd Journal**: Forward systemd journal logs (host system logs)
- **Multiple Sources**: Monitor multiple log sources simultaneously
- **Web-Based Config UI**: Easy-to-use interface for generating configurations
- **Easy Configuration**: Single `.env` file for all settings
- **Lightweight**: Based on Alpine Linux (~15MB image)
- **Flexible**: Supports UDP and TCP syslog
- **Custom Tags**: Tag logs by source for easy filtering in SIEMBox

## Quick Start

### Option 1: Use the Configuration UI (Recommended)

The easiest way to configure the log shipper is using the web-based UI:

```bash
cd log-shipper
docker-compose -f docker-compose.config-ui.yml up -d
```

Then open your browser to **http://localhost:3002** and:
1. Enter your SIEMBox connection details
2. Add your log sources using the form
3. Click "Generate Configuration"
4. Download the `.env` and `docker-compose.yml` files
5. Deploy using the generated files

![Config UI](https://via.placeholder.com/800x400?text=Config+UI+Screenshot)

### Option 2: Manual Configuration

### 1. Copy Configuration Files

```bash
cd log-shipper
cp .env.example .env
```

### 2. Edit `.env` File

Edit `.env` and set your SIEMBox server IP:

```bash
SIEM_HOST=192.168.1.76  # Your SIEMBox server IP
```

Then uncomment the log sources you want to forward. For example, for NPM logs:

```bash
FILE_1=/logs/proxy-host-1.log;npm-access;local0
FILE_2=/logs/error.log;npm-error;local0
```

### 3. Edit `docker-compose.yml`

Uncomment the volume mounts for your log sources. For NPM:

```yaml
volumes:
  - /etc/komodo/stacks/npm/data/logs:/logs:ro
```

### 4. Deploy

```bash
docker-compose up -d
```

### 5. Verify

```bash
# Check shipper logs
docker logs -f siembox-log-shipper

# Check SIEMBox UI
# Navigate to http://your-siembox-ip:3000
```

## Configuration

All configuration is done through two files:

### 1. `.env` File (Environment Variables)

Controls **what** logs to forward:

```bash
# Required
SIEM_HOST=192.168.1.76
SIEM_PORT=514

# File sources (format: /path;tag;facility)
FILE_1=/logs/app.log;myapp;local0
FILE_2=/logs/error.log;myapp-error;local0

# Docker sources (format: container;tag;facility)
DOCKER_1=nginx;nginx;local3

# Journal sources (format: unit;tag;facility)
JOURNAL_1=sshd;ssh;local4
```

### 2. `docker-compose.yml` (Volume Mounts)

Controls **where** logs come from:

```yaml
volumes:
  # Uncomment what you need:
  - /path/to/logs:/logs:ro                          # For file sources
  - /var/run/docker.sock:/var/run/docker.sock:ro    # For Docker sources
  - /var/log:/host-logs:ro                          # For host logs
```

## Common Use Cases

### Use Case 1: NPM Logs (Your Scenario)

**`.env` file:**
```bash
SIEM_HOST=192.168.1.76
SHIPPER_HOSTNAME=npm-server

FILE_1=/logs/proxy-host-1.log;npm-access;local0
FILE_2=/logs/proxy-host-2.log;npm-access;local0
FILE_3=/logs/error.log;npm-error;local0
```

**`docker-compose.yml` volumes:**
```yaml
volumes:
  - /etc/komodo/stacks/npm/data/logs:/logs:ro
```

### Use Case 2: Host System Logs

**`.env` file:**
```bash
SIEM_HOST=192.168.1.76
SHIPPER_HOSTNAME=web-server

FILE_1=/host-logs/auth.log;auth;local2
FILE_2=/host-logs/syslog;syslog;local2
JOURNAL_1=sshd;ssh;local4
```

**`docker-compose.yml` volumes:**
```yaml
volumes:
  - /var/log:/host-logs:ro
  - /var/run/docker.sock:/var/run/docker.sock:ro  # For journal
```

### Use Case 3: Docker Container Logs

**`.env` file:**
```bash
SIEM_HOST=192.168.1.76
SHIPPER_HOSTNAME=docker-host

DOCKER_1=nginx;nginx;local3
DOCKER_2=postgres;database;local3
DOCKER_3=redis;cache;local3
```

**`docker-compose.yml` volumes:**
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

### Use Case 4: Mixed Sources

**`.env` file:**
```bash
SIEM_HOST=192.168.1.76
SHIPPER_HOSTNAME=app-server

# Application files
FILE_1=/app-logs/application.log;myapp;local1
FILE_2=/app-logs/error.log;myapp-error;local1

# System logs
FILE_3=/host-logs/auth.log;auth;local2

# Container logs
DOCKER_1=nginx;nginx;local3
```

**`docker-compose.yml` volumes:**
```yaml
volumes:
  - /var/log/myapp:/app-logs:ro
  - /var/log:/host-logs:ro
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SIEM_HOST` | **Yes** | - | SIEMBox server IP or hostname |
| `SIEM_PORT` | No | `514` | SIEMBox syslog port |
| `SIEM_PROTOCOL` | No | `udp` | Protocol: `udp` or `tcp` |
| `SHIPPER_HOSTNAME` | No | `log-shipper` | Identifier in logs |

### Log Source Variables

**File Sources:** `FILE_1` through `FILE_10`
- Format: `/path/to/file;tag;facility`
- Example: `FILE_1=/logs/app.log;myapp;local0`

**Docker Sources:** `DOCKER_1` through `DOCKER_5`
- Format: `container_name;tag;facility`
- Example: `DOCKER_1=nginx;nginx;local3`
- Requires: `/var/run/docker.sock` mounted

**Journal Sources:** `JOURNAL_1` through `JOURNAL_3`
- Format: `unit_name;tag;facility`
- Example: `JOURNAL_1=sshd;ssh;local4`
- Requires: systemd journal access

### Syslog Facilities

| Facility | Use For |
|----------|---------|
| `local0` | Web server access logs, general application logs |
| `local1` | Application-specific logs |
| `local2` | System logs (auth, syslog, kernel) |
| `local3` | Container/service logs |
| `local4` | Security/authentication logs |
| `local5-7` | Reserved for custom use |

## Deployment Examples

### Deploy on NPM Server

```bash
# 1. Copy log-shipper directory to NPM server
scp -r log-shipper user@npm-server:/opt/

# 2. SSH to NPM server
ssh user@npm-server
cd /opt/log-shipper

# 3. Configure
cp .env.example .env
nano .env  # Set SIEM_HOST and uncomment NPM file sources

nano docker-compose.yml  # Uncomment NPM volume mount

# 4. Deploy
docker-compose up -d

# 5. Verify
docker logs -f siembox-log-shipper
```

### Deploy on Any Server

```bash
cd log-shipper
cp .env.example .env

# Edit configuration
nano .env                    # Configure log sources
nano docker-compose.yml      # Uncomment volume mounts

# Deploy
docker-compose up -d
```

## Monitoring

### View Shipper Logs

```bash
docker logs -f siembox-log-shipper
```

**Healthy output:**
```
[INFO] =========================================
[INFO] SIEMBox Log Shipper Starting
[INFO] =========================================
[INFO] SIEM Host: 192.168.1.76:514 (udp)
[INFO] Hostname: npm-server
[INFO]
[INFO] Successfully connected to SIEMBox at 192.168.1.76:514
[INFO]
[INFO] Tailing file: /logs/proxy-host-1.log (tag: npm-access)
[INFO] Tailing file: /logs/error.log (tag: npm-error)
[INFO]
[INFO] Log shipper running. Press Ctrl+C to stop.
```

### Verify in SIEMBox

1. Open SIEMBox UI: `http://192.168.1.76:3000`
2. Navigate to **Logs** page
3. Filter by:
   - **Tag** (e.g., `npm-access`, `nginx`, `auth`)
   - **Hostname** (your `SHIPPER_HOSTNAME` value)

## Troubleshooting

### No logs appearing in SIEMBox

**1. Check shipper is running:**
```bash
docker ps | grep log-shipper
```

**2. Check shipper logs for errors:**
```bash
docker logs siembox-log-shipper
```

**3. Test network connectivity:**
```bash
docker exec siembox-log-shipper nc -zv 192.168.1.76 514
```

**4. Verify SIEMBox is listening:**
```bash
# On SIEMBox server
netstat -uln | grep 514
```

### "File not found" errors

- Check file paths in `.env` match mounted paths in container
- Verify volume mounts in `docker-compose.yml` are correct
- Ensure files exist on host: `ls -la /path/to/logs`

### "Container not found" (Docker sources)

- Verify container names: `docker ps --format '{{.Names}}'`
- Ensure Docker socket is mounted: `/var/run/docker.sock`
- Check containers are running when shipper starts

### Permission denied

**For log files:**
```bash
chmod 644 /path/to/log/file
```

**For Docker socket:**
```bash
chmod 666 /var/run/docker.sock
# Or add user to docker group
```

## Management Commands

```bash
# Start shipper
docker-compose up -d

# Stop shipper
docker-compose down

# Restart after config changes
docker-compose restart

# View logs
docker logs -f siembox-log-shipper

# Rebuild after updates
docker-compose build
docker-compose up -d
```

## Advanced Configuration

### Using Config File Instead of Environment Variables

For complex setups, use `config.yml` instead:

1. Copy example: `cp config.yml.example config.yml`
2. Edit `config.yml` with your sources
3. In `docker-compose.yml`, uncomment:
   ```yaml
   volumes:
     - ./config.yml:/config/config.yml:ro
   ```

See `config.yml.example` for format.

### Custom Network Setup

By default, uses `host` network mode for simplicity. To use bridge network:

**In `docker-compose.yml`:**
```yaml
# Comment out:
# network_mode: host

# Uncomment at bottom:
networks:
  default:
    driver: bridge
```

## Performance

- **Image Size**: ~15MB
- **Memory Usage**: ~10-20MB per instance
- **CPU Usage**: Minimal, I/O bound
- **Scalability**: Can monitor dozens of log sources per shipper

## Security Best Practices

- ✅ Always mount logs as **read-only** (`:ro`)
- ✅ Use specific volume mounts, not entire filesystems
- ⚠️ Docker socket access gives container Docker API access
- ✅ Consider using bridge network instead of host for isolation
- ✅ Ensure firewall allows UDP/TCP 514 to SIEMBox

## Example Configurations

See the `examples/` directory for complete docker-compose examples:
- `examples/docker-compose.npm.yml` - NPM-specific setup
- `examples/docker-compose.host.yml` - Host system logs
- `examples/docker-compose.docker.yml` - Docker container logs

## Support

- **SIEMBox Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions

## License

MIT License - Same as SIEMBox
