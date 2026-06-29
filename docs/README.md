# SIEMBox Documentation

Welcome to the SIEMBox documentation. This directory contains technical documentation, architecture specifications, and operational guides.

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

### Feature guides
Deep-dives for specific shipped features (see also the friendlier **[GitHub Wiki](https://github.com/cladkins/SIEMBOX/wiki)**, which has pages for **AI Security Analyst** and **SIEMBOX Endpoint**).

- **[edr.md](edr.md)** - SIEMBOX Endpoint server API, agent enrollment, and YARA bundle delivery
- **[geoip.md](geoip.md)** - Offline GeoIP enrichment
- **[canonical-schema.md](canonical-schema.md)** - The normalized field schema parsers map to
- **[detection-normalization.md](detection-normalization.md)** - How detection rules match across sources
- **[detection-coverage.md](detection-coverage.md)** - Detection coverage notes

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

**Current State:** Production Ready (**v3**)

**Recent Milestones (v3):**
- ✅ **AI Security Analyst** — conversational, read-only, model-agnostic (local Ollama or cloud)
- ✅ **SIEMBOX Endpoint agents** — enrollment, inventory/detections/vulnerabilities, server-delivered YARA
- ✅ **Asset-360** — one asset view correlating vulns, alerts, agent, shipper, geo, and ports
- ✅ Threat Intel — blocklist feeds + BYO-key reputation (AbuseIPDB, AlienVault OTX) + dashboard country map

**v2 — the Parser Platform:**
- ✅ Declarative parser engine + portable, in-app community catalog (browse / install / export / **contribute**)
- ✅ AI builder for parsers and detections (Anthropic / OpenAI / Ollama, BYO key)
- ✅ Canonical normalization + offline GeoIP enrichment
- ✅ Catalog-only install — a fresh deployment starts empty, you install what you want

**Features:**
- Declarative, data-driven parsers — onboard a log source without engine code
- In-app catalog to browse, install, update, export, import, and **contribute** parsers/detections
- AI-assisted authoring with a generate → validate → auto-refine loop, plus a read-only **AI Security Analyst**
- SIEMBOX Endpoint agents, host (**Nuclei**) + container (**Trivy**) vulnerability scanning, and threat intelligence
- Role-based access control (**admin / analyst / operator / viewer**) and alert management

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

**Last Updated:** 2026-06-29
**Documentation Version:** 4.0 (v3 — AI Security Analyst + SIEMBOX Endpoint; internal planning docs kept local, out of the public repo)
