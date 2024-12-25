# SIEMBox

Realtime security monitoring and threat detection for your infrastructure. Built with Docker.

![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/siembox)
![License](https://img.shields.io/github/license/yourusername/siembox)

## Quick Start

```bash
docker-compose up -d
```

Then open http://localhost:3000 in your browser.

## Installation

1. Get the compose file:
```bash
git clone https://github.com/yourusername/siembox.git
cd siembox
```

2. Initialize rules:
```bash
./init-rules.sh
```

3. Set required environment variables:
```bash
cp .env.example .env
```

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| DB_PASSWORD | Database password |
| JWT_SECRET | API security key |
| ENCRYPTION_KEY | Key for sensitive data |
| GITHUB_REPOSITORY | Your GitHub repository |

### Optional Environment Variables

| Variable | Description |
|----------|-------------|
| IPAPI_KEY | IP-API.com API key |
| CROWDSEC_API_KEY | CrowdSec API key |

## Features

- Syslog collection (TCP/UDP port 5514)
- Sigma-based threat detection
- IP intelligence and geolocation
- VPS security auditing
- Real-time monitoring dashboard

## Documentation

Detailed documentation is available in the `docs` directory:
- [System Architecture](docs/overview.txt)
- [API Reference](docs/api.txt)
- [Monitoring Setup](docs/monitoring.txt)
- [Backup Procedures](docs/backup.txt)
- [Performance Tuning](docs/performance.txt)
- [Security Features](docs/security.txt)

## Health Check

```bash
curl http://localhost:8080/health
```

## License

This project is licensed under the MIT License.
