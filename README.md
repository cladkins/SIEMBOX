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

# Create .env file (see .env.example)
cp .env.example .env
nano .env

# Deploy to your environment
# See DEPLOYMENT.md for full instructions

# Access the UI
# Frontend: http://your-server-ip:3000
# API: http://your-server-ip:3001
# Default login: admin / changeme
```

## Documentation

📖 **[Complete Documentation Index](./docs/README.md)** - Full documentation navigation

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
- **[Testing Strategies](./docs/reference/TESTING_STRATEGIES.md)** - PostgreSQL testing and mocking strategies
- **[Testing Quick Start](./docs/reference/TESTING_QUICK_START.md)** - Quick-start test templates
- **[Contributing Guide](./CONTRIBUTING.md)** - How to contribute to SIEMBox

### Log Shipper Documentation
- **[Log Shipper README](./log-shipper/README.md)** - Setup and configuration
- **[Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)** - Verify logs are flowing correctly
- **[Quick Reference](./log-shipper/QUICK-REFERENCE.md)** - Common commands and troubleshooting
- **[Deployment Verification](./log-shipper/DEPLOYMENT-VERIFICATION.md)** - Step-by-step deployment checklist

### Reference Documentation
- **[API Reference](./API.md)** - Complete REST API documentation
- **[Community Parsers](./PARSERS.md)** - Pre-built parsers for common log sources
- **[Detection Rules](./RULES.md)** - Built-in and community detection rules
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

- [ ] Additional parser types (CEF, LEEF)
- [ ] Threat intelligence integration
- [ ] Advanced correlation rules
- [ ] Email/webhook alert notifications
- [ ] Data export capabilities
- [ ] Multi-tenancy support
