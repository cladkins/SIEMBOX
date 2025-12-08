# SIEMBox

A lightweight, self-hosted Security Information and Event Management (SIEM) system built with Node.js, TypeScript, and Vue.js.

## Features

- **Zero-Configuration Setup**: Automatically seeds 19 parsers and 40+ detection rules on first startup
- **Syslog Ingestion**: Receive logs via UDP/TCP on port 514
- **Log Shipper**: Universal log forwarder for collecting logs from any source
- **Pre-Built Parsers**: Nginx, Traefik, Caddy, Authelia, Keycloak, Nextcloud, Pi-hole, Vaultwarden, UniFi, and more
- **Detection Rules**: Built-in rules for authentication failures, web attacks, DNS anomalies, and system events
- **Alert Management**: View, acknowledge, and manage security alerts
- **Log Retention**: Configurable retention policies with automated cleanup
- **User Management**: Role-based access control (Admin, Analyst, Viewer)
- **Dashboard**: Real-time visualization of logs and alerts

## Quick Start

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

```bash
# Clone and configure
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
git checkout develop

# Create .env file (see .env.example)
cp .env.example .env
nano .env

# Build and start
docker compose up -d

# That's it! SIEMBox automatically:
# - Runs database migrations
# - Imports 19 parsers (Nginx, Traefik, Caddy, Authelia, Vaultwarden, UniFi, etc.)
# - Seeds 40+ detection rules
# - Creates default admin user

# Access the UI
# Frontend: http://localhost:3000
# Default login: admin / changeme
```

## Documentation

📖 **[Documentation Map](./DOCUMENTATION-MAP.md)** - Complete overview of all documentation

### Getting Started
- **[Deployment Guide](./DEPLOYMENT.md)** - Installation, configuration, and setup
- **[Fresh Install Fix](./FRESH-INSTALL-FIX.md)** - ⚠️ **Having persistent errors?** Complete fresh start guide
- **[Deployment Fix Guide](./DEPLOYMENT-FIX-GUIDE.md)** - Troubleshooting deployment issues
- **[Log Shipper Setup](./log-shipper/README.md)** - Universal log forwarder configuration

### Log Shipper Documentation
- **[Log Shipper README](./log-shipper/README.md)** - Setup and configuration
- **[Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)** - How to verify logs are flowing
- **[Quick Reference](./log-shipper/QUICK-REFERENCE.md)** - Common commands and troubleshooting
- **[Deployment Verification](./log-shipper/DEPLOYMENT-VERIFICATION.md)** - Step-by-step deployment guide
- **[Technical Details](./log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md)** - Process management architecture

### Recent Updates
- **[Incident Resolution Summary](./INCIDENT-RESOLUTION-SUMMARY.md)** - Recent critical bug fix (2025-12-03)

### Reference Documentation
- **[API Reference](./API.md)** - Complete REST API documentation
- **[Community Parsers](./PARSERS.md)** - Pre-built parsers for common log sources
- **[Detection Rules](./RULES.md)** - Built-in and community detection rules

### Operations & Security
- **[Security Hardening](./SECURITY.md)** - Comprehensive security guide
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Common issues and solutions

### Development
- **[Contributing Guide](./CONTRIBUTING.md)** - How to contribute
- **[Backend API](./backend/README.md)** - Backend development documentation

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

- [ ] Additional parser types (CEF, LEEF)
- [ ] Threat intelligence integration
- [ ] Advanced correlation rules
- [ ] Email/webhook alert notifications
- [ ] Data export capabilities
- [ ] Multi-tenancy support
