# SIEMBox Project

## Overview

SIEMBox is a lightweight, self-hosted Security Information and Event Management (SIEM) system built with Node.js, TypeScript, and Vue.js. It provides log ingestion, parsing, detection rules, alerting, and a web-based management interface.

## Vision

Create an accessible, self-hosted SIEM solution that:
- Is easy to deploy and maintain
- Provides real-time security monitoring
- Offers flexible log parsing and detection capabilities
- Scales from small homelab to medium enterprise deployments
- Remains free and open-source

## Current State

**Version:** Pre-v1.0 (Active Development)
**Branch:** `develop`

### What's Working

- ✅ Syslog ingestion (UDP/TCP port 514)
- ✅ Log parser engine (regex, grok, JSON)
- ✅ Detection rule engine with alerting
- ✅ 19 pre-built parsers (Nginx, Traefik, Authelia, Pi-hole, etc.)
- ✅ 40+ detection rules
- ✅ Web-based management UI (Vue.js 3)
- ✅ REST API with authentication
- ✅ Role-based access control (Admin, Analyst, Viewer, Operator)
- ✅ Asset discovery and scanning (NMAP integration)
- ✅ Log retention policies
- ✅ Log shipper for universal log collection
- ✅ Docker Compose deployment
- ✅ Comprehensive documentation

### Known Limitations

- Limited test coverage (only 8 test files)
- No horizontal scaling support
- Single-node architecture
- Limited real-time features (no WebSockets)
- Manual parser/rule management (no UI builder)
- Basic alert notifications (no email/webhook integrations)

## Tech Stack

**Backend:**
- Node.js 20 + TypeScript 5.3.3
- Express 4.18.2
- PostgreSQL 15 with JSONB
- Winston logging
- Jest testing

**Frontend:**
- Vue.js 3.4.5 + Composition API
- Element Plus UI components
- Vite build tool
- Pinia state management
- Vitest testing

**Infrastructure:**
- Docker + Docker Compose
- PostgreSQL for data storage
- Syslog server (UDP/TCP 514)

## Success Metrics

**v1.0 Release Goals:**
- Stable API with versioning
- 80%+ test coverage
- Production-ready database migrations
- Performance benchmarks documented
- Security audit completed
- Community parsers and rules repository

**Post-v1.0:**
- Active community contributions
- Plugin/extension system
- Horizontal scaling support
- Advanced correlation rules
- Threat intelligence integration

## Team & Roles

**Project Lead:** Chris Adkins
**Contributors:** Open-source community
**Current Status:** Active development, accepting contributions

## Related Documentation

- [README.md](../README.md) - Project overview
- [DEPLOYMENT.md](../DEPLOYMENT.md) - Installation guide
- [API.md](../API.md) - API reference
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [Backend README](../backend/README.md) - Backend development
- [Frontend README](../frontend/README.md) - Frontend development
- [Testing Guide](../docs/guides/TESTING_GUIDE.md) - Testing practices

## Repository

- **GitHub:** https://github.com/cladkins/SIEMBOX
- **Main Branch:** `main`
- **Development Branch:** `develop`
- **Issues:** https://github.com/cladkins/SIEMBOX/issues
- **Discussions:** https://github.com/cladkins/SIEMBOX/discussions
