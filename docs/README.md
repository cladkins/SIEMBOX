# SIEMBox Documentation

Welcome to the SIEMBox documentation. This directory contains comprehensive technical documentation, architecture specifications, operational guides, and project planning materials.

## 📁 Documentation Structure

### `/reference` - Technical Reference Documentation
Core technical documentation for SIEMBox features and capabilities.

- **[PARSERS.md](reference/PARSERS.md)** - Parser creation, community parsers, and log processing guide
- **[RULES.md](reference/RULES.md)** - Detection rule documentation and examples

### `/parsers` - Application-Specific Parser Documentation
Detailed documentation for parsers by application category.

- **[AUTHENTICATION-PARSERS.md](parsers/AUTHENTICATION-PARSERS.md)** - SSH, Authelia, Authentik parsers
- **[CRITICAL-APPLICATION-PARSERS.md](parsers/CRITICAL-APPLICATION-PARSERS.md)** - Vaultwarden, Nextcloud, Pi-hole parsers
- **[REVERSE-PROXY-PARSERS.md](parsers/REVERSE-PROXY-PARSERS.md)** - NGINX Proxy Manager, Traefik, Caddy parsers

### `/guides` - User Guides
User-facing guides for managing and using SIEMBox features.

- **[USER-MANAGEMENT.md](guides/USER-MANAGEMENT.md)** - User account and role management guide

### `/operations` - Operational Guides
Day-to-day operations, troubleshooting, and deployment procedures.

- **[TROUBLESHOOTING.md](operations/TROUBLESHOOTING.md)** - Common issues and solutions
- **[RULE-DEPLOYMENT-CHECKLIST.md](operations/RULE-DEPLOYMENT-CHECKLIST.md)** - Pre-deployment verification and rollout strategy

### `/architecture` - Architecture & Design Specifications
System architecture, design decisions, and implementation specifications.

- **[DOCUMENTATION-ARCHITECTURE.md](architecture/DOCUMENTATION-ARCHITECTURE.md)** - Documentation structure and organization
- **[HOMELAB-THREAT-MODEL.md](architecture/HOMELAB-THREAT-MODEL.md)** - Security threat model and attack scenarios
- **[PARSER-RULE-IMPLEMENTATION-SPEC.md](architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md)** - Parser and rule implementation design
- **[VAULTWARDEN-PARSER-IMPLEMENTATION.md](architecture/VAULTWARDEN-PARSER-IMPLEMENTATION.md)** - Vaultwarden parser design decisions

### `/archive` - Historical Documentation Archive
Archived documentation including resolved incidents, completed phases, and superseded guides. See [archive/README.md](archive/README.md) for complete archive index.

#### Resolved Incidents
- **[incidents/SIEMBOX-DB-001/](archive/incidents/SIEMBOX-DB-001/)** - Database migration incident (2025-12-03, resolved)

#### Completed Implementation Phases
- **[phase-implementation/](archive/phase-implementation/)** - Phase 3A, 3B, 3C implementation summaries (archived)

#### Superseded Documentation
- **[DEPLOYMENT-FIX-GUIDE.md](archive/DEPLOYMENT-FIX-GUIDE.md)** - Database initialization bug fix (resolved)
- **[FRESH-INSTALL-FIX.md](archive/FRESH-INSTALL-FIX.md)** - Volume persistence fix (resolved)
- **[DEPLOYMENT-GUIDE.md](archive/DEPLOYMENT-GUIDE.md)** - Old deployment guide (consolidated)

#### Historical Materials
- **[SESSION-HANDOFF.md](archive/SESSION-HANDOFF.md)** - Session continuity tracking
- **[DOCUMENTATION-MAP.md](archive/DOCUMENTATION-MAP.md)** - Previous documentation structure
- **[INCIDENT-RESOLUTION-SUMMARY.md](archive/INCIDENT-RESOLUTION-SUMMARY.md)** - Past incident resolutions
- **[PLAN.md](archive/PLAN.md)** - Original project planning document

---

## 🚀 Quick Start Guides

### For New Contributors
1. Start with [README.md](../README.md) in the root directory
2. Read [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines
3. Review [SECURITY.md](../SECURITY.md) for security practices
4. Explore [DEPLOYMENT.md](../DEPLOYMENT.md) for setup instructions

### For Parser Development
1. [reference/PARSERS.md](reference/PARSERS.md) - Parser creation guide
2. [parsers/](parsers/) - Application-specific parser examples
3. [architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md](architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md) - Implementation details

### For Rule Development
1. [reference/RULES.md](reference/RULES.md) - Detection rule documentation
2. [architecture/HOMELAB-THREAT-MODEL.md](architecture/HOMELAB-THREAT-MODEL.md) - Threat scenarios
3. [operations/RULE-DEPLOYMENT-CHECKLIST.md](operations/RULE-DEPLOYMENT-CHECKLIST.md) - Deployment guide

### For Operations/Deployment
1. [DEPLOYMENT.md](../DEPLOYMENT.md) - Installation and configuration
2. [operations/TROUBLESHOOTING.md](operations/TROUBLESHOOTING.md) - Issue resolution
3. [operations/RULE-DEPLOYMENT-CHECKLIST.md](operations/RULE-DEPLOYMENT-CHECKLIST.md) - Pre-deployment checklist
4. [guides/USER-MANAGEMENT.md](guides/USER-MANAGEMENT.md) - User account management

### For Architecture Review
1. [architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md](architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md) - System design
2. [architecture/HOMELAB-THREAT-MODEL.md](architecture/HOMELAB-THREAT-MODEL.md) - Security architecture
3. [architecture/DOCUMENTATION-ARCHITECTURE.md](architecture/DOCUMENTATION-ARCHITECTURE.md) - Documentation structure

---

## 📊 Project Status

**Current State:** Production Ready

**Recent Milestones:**
- ✅ 19 production-ready parsers (reverse proxy, auth, applications)
- ✅ 40+ detection rules implemented and tested
- ✅ Zero-configuration deployment with automatic seeding
- ✅ Comprehensive documentation reorganization

**Features:**
- Automatic parser and rule seeding on first startup
- Built-in parsers for common homelab applications
- Detection rules for authentication, proxy security, data exfiltration, and more
- Role-based access control and alert management

See [../DEPLOYMENT.md](../DEPLOYMENT.md) for quick start and [operations/TROUBLESHOOTING.md](operations/TROUBLESHOOTING.md) for support.

---

## 🔍 Documentation Index by Topic

### Authentication & Access Control
- [guides/USER-MANAGEMENT.md](guides/USER-MANAGEMENT.md) - User account and role management
- [parsers/AUTHENTICATION-PARSERS.md](parsers/AUTHENTICATION-PARSERS.md)
- [reference/RULES.md](reference/RULES.md) - AUTH-* and ACCESS-* rules
- [SECURITY.md](../SECURITY.md)

### Application Security
- [parsers/CRITICAL-APPLICATION-PARSERS.md](parsers/CRITICAL-APPLICATION-PARSERS.md)
- [architecture/VAULTWARDEN-PARSER-IMPLEMENTATION.md](architecture/VAULTWARDEN-PARSER-IMPLEMENTATION.md)
- [reference/RULES.md](reference/RULES.md) - APP-* and PWDMGR-* rules

### Network Security
- [parsers/REVERSE-PROXY-PARSERS.md](parsers/REVERSE-PROXY-PARSERS.md)
- [reference/RULES.md](reference/RULES.md) - PROXY-* and EXFIL-* rules
- [architecture/HOMELAB-THREAT-MODEL.md](architecture/HOMELAB-THREAT-MODEL.md)

### Infrastructure Security
- [reference/RULES.md](reference/RULES.md) - INFRA-* and IOT-* rules
- [DEPLOYMENT.md](../DEPLOYMENT.md)
- [SECURITY.md](../SECURITY.md)

---

## 🤝 Contributing to Documentation

When contributing to SIEMBox documentation:

1. **Technical Reference** → Add to `/reference` or `/parsers`
2. **Operational Guides** → Add to `/operations`
3. **Architecture/Design** → Add to `/architecture`
4. **Historical Materials** → Consult with maintainers before adding to `/archive`

Update this README.md when adding new documentation files. Each subdirectory has its own README.md to help with navigation.

---

## 📝 Documentation Standards

- **Format:** GitHub-flavored Markdown
- **Structure:** Clear headings, table of contents for long documents
- **Code Examples:** Use fenced code blocks with language identifiers
- **Cross-References:** Use relative links between documentation files
- **Versioning:** Track major changes in git commit messages
- **Maintenance:** Update documentation with code changes

---

## 📚 External Resources

- **GitHub Repository:** https://github.com/cladkins/SIEMBOX
- **Issues:** https://github.com/cladkins/SIEMBOX/issues
- **Discussions:** https://github.com/cladkins/SIEMBOX/discussions
- **License:** MIT (see root LICENSE file)

---

**Last Updated:** 2025-12-08
**Documentation Version:** 3.0 (Cleanup and reorganization)
