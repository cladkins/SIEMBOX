# SIEMBox Log Shipper

Universal log forwarder for sending logs from any source to SIEMBox via syslog. Deploy this lightweight container on any machine to forward logs from files, Docker containers, or the host system.

## Features

- **File Tailing**: Monitor and forward any log file
- **Docker Container Logs**: Forward logs from specific Docker containers
- **Systemd Journal**: Forward systemd journal logs (host system logs)
- **Multiple Sources**: Monitor multiple log sources simultaneously
- **Flexible Configuration**: Configure via environment variables or YAML file
- **Lightweight**: Based on Alpine Linux (~15MB image)
- **Network Modes**: Supports both UDP and TCP syslog
- **Custom Tags**: Tag logs by source for easy filtering in SIEMBox

## Quick Start

### 1. Forward NPM Logs (Your Use Case)

On your NPM server:

```bash
cd log-shipper
docker-compose -f docker-compose.npm.yml up -d
```

This will forward all NPM logs from `/etc/komodo/stacks/npm/data/logs` to your SIEMBox at `192.168.1.76:514`.

### 2. Forward Host System Logs

```bash
docker-compose -f docker-compose.host.yml up -d
```

### 3. Forward Docker Container Logs

```bash
docker-compose -f docker-compose.docker.yml up -d
```

## Configuration Methods

You can configure the log shipper in two ways:

### Method 1: Environment Variables (Recommended for simple setups)

```yaml
environment:
  SIEM_HOST: 192.168.1.76
  SIEM_PORT: 514
  SIEM_PROTOCOL: udp
  SHIPPER_HOSTNAME: my-server

  # File sources: FILE_N=/path;tag;facility
  FILE_1: /logs/app.log;application;local0
  FILE_2: /logs/error.log;app-error;local0

  # Docker sources: DOCKER_N=container;tag;facility
  DOCKER_1: nginx;nginx;local3

  # Journal sources: JOURNAL_N=unit;tag;facility
  JOURNAL_1: sshd;ssh;local4
```

### Method 2: Config File (Recommended for complex setups)

Create `config.yml`:

```yaml
files:
  - path: /logs/npm/proxy-host-*.log
    tag: npm-access
    facility: local0

docker:
  - container: nginx
    tag: nginx
    facility: local3

journal:
  - unit: sshd
    tag: sshd
    facility: local4
```

Mount it:
```yaml
volumes:
  - ./config.yml:/config/config.yml:ro
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIEM_HOST` | `localhost` | SIEMBox server hostname or IP |
| `SIEM_PORT` | `514` | SIEMBox syslog port |
| `SIEM_PROTOCOL` | `udp` | Protocol: `udp` or `tcp` |
| `SHIPPER_HOSTNAME` | `hostname` | Hostname identifier in logs |
| `LOG_LEVEL` | `info` | Log verbosity |

### Dynamic Source Variables

**File Sources:**
- Format: `FILE_N=/path/to/file;tag;facility`
- Example: `FILE_1=/var/log/app.log;myapp;local0`

**Docker Container Sources:**
- Format: `DOCKER_N=container_name;tag;facility`
- Example: `DOCKER_1=nginx;nginx;local3`
- Requires: `/var/run/docker.sock` mounted

**Systemd Journal Sources:**
- Format: `JOURNAL_N=unit_name;tag;facility`
- Example: `JOURNAL_1=sshd;ssh;local4`
- Requires: systemd journal access

## Syslog Facilities

Use these facility codes to organize logs in SIEMBox:

- `local0` - General application logs
- `local1` - Application-specific logs
- `local2` - System logs
- `local3` - Container/service logs
- `local4` - Security/auth logs
- `local5` - Reserved
- `local6` - Reserved
- `local7` - Reserved

## Examples

### Example 1: NPM Logs

```yaml
services:
  log-shipper:
    image: siembox-log-shipper
    environment:
      SIEM_HOST: 192.168.1.76
      SIEM_PORT: 514
      FILE_1: /logs/proxy-host-1.log;npm-access;local0
      FILE_2: /logs/error.log;npm-error;local0
    volumes:
      - /etc/komodo/stacks/npm/data/logs:/logs:ro
    network_mode: host
```

### Example 2: Multiple Applications

```yaml
services:
  log-shipper:
    image: siembox-log-shipper
    environment:
      SIEM_HOST: 192.168.1.76
      FILE_1: /logs/nginx/access.log;nginx-access;local0
      FILE_2: /logs/nginx/error.log;nginx-error;local0
      FILE_3: /logs/app/app.log;myapp;local1
      DOCKER_1: postgres;database;local3
      DOCKER_2: redis;cache;local3
    volumes:
      - /var/log/nginx:/logs/nginx:ro
      - /var/log/myapp:/logs/app:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    network_mode: host
```

### Example 3: Host System Monitoring

```yaml
services:
  log-shipper:
    image: siembox-log-shipper
    environment:
      SIEM_HOST: 192.168.1.76
      FILE_1: /host-logs/auth.log;auth;local2
      FILE_2: /host-logs/syslog;syslog;local2
      JOURNAL_1: sshd;ssh;local4
      JOURNAL_2: docker;docker-daemon;local4
    volumes:
      - /var/log:/host-logs:ro
    network_mode: host
    pid: host
```

## Building

Build the Docker image:

```bash
cd log-shipper
docker build -t siembox-log-shipper .
```

Or build with docker-compose:

```bash
docker-compose build
```

## Deployment

### Deploy to NPM Server

1. Copy the `log-shipper` directory to your NPM server
2. Edit `docker-compose.npm.yml` and update `SIEM_HOST` if needed
3. Deploy:

```bash
cd log-shipper
docker-compose -f docker-compose.npm.yml up -d
```

### Deploy to Any Server

1. Copy the `log-shipper` directory
2. Create/edit your own docker-compose file or use one of the examples
3. Update environment variables for your sources
4. Deploy:

```bash
docker-compose up -d
```

## Monitoring

### View Shipper Logs

```bash
docker logs -f siembox-log-shipper
```

You should see output like:
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

1. Log into SIEMBox UI: http://192.168.1.76:3000
2. Navigate to **Logs** page
3. Look for logs with tags like `npm-access`, `npm-error`, etc.
4. Filter by hostname to see logs from specific shippers

## Troubleshooting

### Logs not appearing in SIEMBox

1. **Check shipper is running:**
   ```bash
   docker ps | grep log-shipper
   ```

2. **Check shipper logs:**
   ```bash
   docker logs siembox-log-shipper
   ```

3. **Test network connectivity:**
   ```bash
   docker exec siembox-log-shipper nc -zv 192.168.1.76 514
   ```

4. **Check SIEMBox is listening:**
   On SIEMBox server:
   ```bash
   netstat -uln | grep 514
   ```

### Permission Issues

If you see "Permission denied" errors:

1. **For file sources:** Ensure files are readable
   ```bash
   chmod 644 /path/to/log/file
   ```

2. **For Docker socket:** Ensure socket is accessible
   ```bash
   chmod 666 /var/run/docker.sock
   # Or add container to docker group
   ```

### Docker container not found

If monitoring Docker containers, ensure:
1. Container names are correct (use `docker ps` to verify)
2. Docker socket is mounted: `/var/run/docker.sock:/var/run/docker.sock:ro`
3. Containers are running when shipper starts

## Security Considerations

- **Read-only mounts**: Always mount log sources as read-only (`:ro`)
- **Docker socket**: Mounting Docker socket gives container access to Docker API - use with caution
- **Network isolation**: Consider using bridge network instead of host network for better isolation
- **Firewall**: Ensure firewall allows UDP/TCP 514 to SIEMBox server

## Performance

- **Lightweight**: ~15MB image size
- **Low CPU**: Minimal CPU usage, primarily I/O bound
- **Memory**: ~10-20MB RAM per shipper instance
- **Scalability**: Can monitor dozens of log sources per shipper

## License

MIT License - Same as SIEMBox

## Support

For issues or questions:
- SIEMBox Issues: https://github.com/cladkins/SIEMBOX/issues
- SIEMBox Discussions: https://github.com/cladkins/SIEMBOX/discussions
