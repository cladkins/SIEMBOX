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

### `/phase-planning` - Project Phase Planning
High-level planning documents for multi-phase implementation.

- **[PHASE-4-IMPLEMENTATION-PLAN.md](phase-planning/PHASE-4-IMPLEMENTATION-PLAN.md)** - Phase 4 backend enhancements roadmap

### `/phase-implementation` - Phase Implementation Summaries
Detailed implementation summaries and quick reference guides for completed phases.

- **[AUTHENTICATION-RULES-PHASE-3A.md](phase-implementation/AUTHENTICATION-RULES-PHASE-3A.md)** - Phase 3A authentication rules
- **[PHASE-3B-IMPLEMENTATION-SUMMARY.md](phase-implementation/PHASE-3B-IMPLEMENTATION-SUMMARY.md)** - Phase 3B summary
- **[PHASE-3B-QUICK-REFERENCE.md](phase-implementation/PHASE-3B-QUICK-REFERENCE.md)** - Phase 3B quick reference
- **[PHASE-3C-IMPLEMENTATION-SUMMARY.md](phase-implementation/PHASE-3C-IMPLEMENTATION-SUMMARY.md)** - Phase 3C summary
- **[PHASE-3C-QUICK-REFERENCE.md](phase-implementation/PHASE-3C-QUICK-REFERENCE.md)** - Phase 3C quick reference

### `/archive` - Archive & Session History
Historical session handoffs, planning documents, and project evolution.

- **[SESSION-HANDOFF.md](archive/SESSION-HANDOFF.md)** - Session continuity tracking and project status
- **[DOCUMENTATION-MAP.md](archive/DOCUMENTATION-MAP.md)** - Historical documentation navigation
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

### For Architecture Review
1. [architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md](architecture/PARSER-RULE-IMPLEMENTATION-SPEC.md) - System design
2. [architecture/HOMELAB-THREAT-MODEL.md](architecture/HOMELAB-THREAT-MODEL.md) - Security architecture
3. [phase-planning/PHASE-4-IMPLEMENTATION-PLAN.md](phase-planning/PHASE-4-IMPLEMENTATION-PLAN.md) - Future enhancements

---

## 📊 Project Status

**Current Phase:** Phase 4 - Backend Enhancements (60% complete)

**Recent Milestones:**
- ✅ Phase 1: Parser infrastructure redesign
- ✅ Phase 2: 12 production-ready parsers
- ✅ Phase 3: 40 detection rules implemented
- 🚧 Phase 4: Advanced backend features (distinct count, IP whitelist, correlation)

**Deployment Status:**
- **38 of 40 rules** (95%) ready for production deployment
- **2 rules blocked** pending Phase 4D (event correlation) and Phase 4E (GeoIP enrichment)

See [archive/SESSION-HANDOFF.md](archive/SESSION-HANDOFF.md) for detailed project status and [operations/RULE-DEPLOYMENT-CHECKLIST.md](operations/RULE-DEPLOYMENT-CHECKLIST.md) for deployment roadmap.

---

## 🔍 Documentation Index by Topic

### Authentication & Access Control
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
4. **Planning Documents** → Add to `/phase-planning`
5. **Implementation Summaries** → Add to `/phase-implementation`
6. **Historical Materials** → Add to `/archive`

Update this README.md when adding new documentation files.

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

**Last Updated:** 2025-12-03
**Documentation Version:** 2.0 (Post-reorganization)
