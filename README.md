# SIEMBox

A lightweight, self-hosted Security Information and Event Management (SIEM) system built with Node.js, TypeScript, and Vue.js.

## Features

- **Syslog Ingestion**: Receive logs via UDP/TCP on port 514
- **Log Shipper**: Universal log forwarder for collecting logs from any source
- **Custom Parsers**: Build regex, grok, or JSON parsers to extract fields from logs
- **Detection Rules**: Create rules with conditions and thresholds to trigger alerts
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

# Access the UI
# Frontend: http://localhost:3000
# Default login: admin / changeme
```

## Documentation

- **[Deployment Guide](./DEPLOYMENT.md)** - Installation, configuration, and troubleshooting
- **[Log Shipper](./log-shipper/README.md)** - Universal log forwarder for any source
- **[Community Parsers](./PARSERS.md)** - Pre-built parsers for common log sources
- **Parser Builder** - Visual tool for creating custom parsers (in UI)
- **Rule Editor** - Create detection rules with conditions and aggregations (in UI)

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
