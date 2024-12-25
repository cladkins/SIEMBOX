# SIEMBox

Realtime security monitoring and threat detection for your infrastructure. Built with Docker.

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cladkins/siembox/docker-build.yml?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/cladkins/siembox/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/cladkins/siembox/codeql-analysis.yml?style=flat-square&logo=github&label=CodeQL)](https://github.com/cladkins/siembox/security/code-scanning)
[![License](https://img.shields.io/github/license/cladkins/siembox?style=flat-square&logo=opensourceinitiative&logoColor=white)](https://github.com/cladkins/siembox/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/cladkins/siembox?style=flat-square&logo=github)](https://github.com/cladkins/siembox/releases)
[![Container Registry](https://img.shields.io/badge/Container%20Registry-ghcr.io-blue?style=flat-square&logo=docker&logoColor=white)](https://github.com/cladkins/siembox/pkgs/container/siembox)
[![Repo Size](https://img.shields.io/github/repo-size/cladkins/siembox?style=flat-square&logo=github)](https://github.com/cladkins/siembox)
[![Last Commit](https://img.shields.io/github/last-commit/cladkins/siembox?style=flat-square&logo=git)](https://github.com/cladkins/siembox/commits)
[![Open Issues](https://img.shields.io/github/issues/cladkins/siembox?style=flat-square&logo=github)](https://github.com/cladkins/siembox/issues)

## Quick Start

```bash
docker-compose up -d
```

Then open http://localhost:3000 in your browser.

## Installation

1. Get the compose file:
```bash
git clone https://github.com/cladkins/siembox.git
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
