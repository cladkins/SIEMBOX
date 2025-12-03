# SIEMBox Documentation Map

This document provides an overview of all documentation and how it's organized.

## 📖 Documentation Structure

```
SIEMBox/
├── README.md                          # Main entry point
├── DOCUMENTATION-MAP.md               # This file - documentation overview
│
├── 🚀 Getting Started
│   ├── DEPLOYMENT.md                  # Complete installation & setup guide
│   └── log-shipper/README.md          # Log shipper setup & configuration
│
├── 📦 Log Shipper Documentation
│   ├── log-shipper/README.md          # Main log shipper guide
│   ├── log-shipper/VERIFICATION-GUIDE.md        # How to verify logs are flowing
│   ├── log-shipper/QUICK-REFERENCE.md           # Common commands & troubleshooting
│   ├── log-shipper/DEPLOYMENT-VERIFICATION.md   # Step-by-step deployment
│   └── log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md  # Technical details
│
├── 📚 Reference Documentation
│   ├── API.md                         # Complete REST API reference
│   ├── PARSERS.md                     # Pre-built parsers & how to create
│   └── RULES.md                       # Detection rules & examples
│
├── 🔒 Operations & Security
│   ├── SECURITY.md                    # Security hardening guide
│   └── TROUBLESHOOTING.md             # Common issues & solutions
│
├── 🔧 Development
│   ├── CONTRIBUTING.md                # How to contribute
│   ├── backend/README.md              # Backend development docs
│   └── frontend/README.md             # Frontend development docs
│
└── 📰 Recent Updates
    └── INCIDENT-RESOLUTION-SUMMARY.md # Recent critical bug fix (2025-12-03)
```

## 🎯 Quick Navigation by Task

### I want to deploy SIEMBox
1. Start with [DEPLOYMENT.md](./DEPLOYMENT.md)
2. Then set up [Log Shipper](./log-shipper/README.md)
3. Verify with [Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)

### I want to set up log forwarding
1. Read [Log Shipper README](./log-shipper/README.md)
2. Deploy using [Deployment Verification](./log-shipper/DEPLOYMENT-VERIFICATION.md)
3. Verify with [Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)
4. Troubleshoot with [Quick Reference](./log-shipper/QUICK-REFERENCE.md)

### I want to verify logs are being received
1. Follow [Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)
2. Use [Quick Reference](./log-shipper/QUICK-REFERENCE.md) for commands
3. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) if issues

### I want to create parsers or rules
1. Read [PARSERS.md](./PARSERS.md) for parser creation
2. Read [RULES.md](./RULES.md) for detection rules
3. Check [API.md](./API.md) for API endpoints

### I want to harden security
1. Follow [SECURITY.md](./SECURITY.md)
2. Review [DEPLOYMENT.md](./DEPLOYMENT.md) security sections

### I want to contribute
1. Read [CONTRIBUTING.md](./CONTRIBUTING.md)
2. Check [backend/README.md](./backend/README.md) for backend
3. Check [frontend/README.md](./frontend/README.md) for frontend

### I'm having issues
1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) first
2. For log shipper issues: [Quick Reference](./log-shipper/QUICK-REFERENCE.md)
3. For verification: [Verification Guide](./log-shipper/VERIFICATION-GUIDE.md)

## 📑 Documentation Details

### Core Documentation

#### [README.md](./README.md)
- **Purpose:** Project overview and quick start
- **Audience:** Everyone
- **Contains:** Features, quick start, architecture, links to all docs

#### [DEPLOYMENT.md](./DEPLOYMENT.md)
- **Purpose:** Complete installation and configuration guide
- **Audience:** Operators, system administrators
- **Contains:** Docker setup, environment variables, initial configuration

#### [API.md](./API.md)
- **Purpose:** Complete REST API reference
- **Audience:** Developers, integrators
- **Contains:** All endpoints, request/response examples, authentication

### Log Shipper Documentation

#### [log-shipper/README.md](./log-shipper/README.md)
- **Purpose:** Complete log shipper setup guide
- **Audience:** Operators, system administrators
- **Contains:** Managed & standalone modes, configuration, troubleshooting
- **Start here for:** Setting up log forwarding

#### [log-shipper/VERIFICATION-GUIDE.md](./log-shipper/VERIFICATION-GUIDE.md)
- **Purpose:** Step-by-step guide to verify logs are flowing
- **Audience:** Operators, troubleshooters
- **Contains:** Verification steps, database queries, troubleshooting
- **Start here for:** Confirming logs are being received

#### [log-shipper/QUICK-REFERENCE.md](./log-shipper/QUICK-REFERENCE.md)
- **Purpose:** Quick command reference and troubleshooting
- **Audience:** Operators who need quick answers
- **Contains:** Common commands, quick diagnostics, what was fixed
- **Start here for:** Fast troubleshooting

#### [log-shipper/DEPLOYMENT-VERIFICATION.md](./log-shipper/DEPLOYMENT-VERIFICATION.md)
- **Purpose:** Comprehensive deployment and testing procedures
- **Audience:** Operators deploying the fix
- **Contains:** Pre-deployment checklist, deployment steps, verification
- **Start here for:** Deploying recent updates

#### [log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md](./log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md)
- **Purpose:** Complete technical analysis of process management fix
- **Audience:** Engineers, developers
- **Contains:** Root cause, technical details, implementation
- **Start here for:** Understanding the technical details

### Reference Documentation

#### [PARSERS.md](./PARSERS.md)
- **Purpose:** Parser creation and community parsers
- **Audience:** Operators, contributors
- **Contains:** How to create parsers, pre-built parsers, examples

#### [RULES.md](./RULES.md)
- **Purpose:** Detection rule creation and examples
- **Audience:** Security analysts, operators
- **Contains:** Rule syntax, examples, best practices

#### [SECURITY.md](./SECURITY.md)
- **Purpose:** Security hardening and best practices
- **Audience:** Security engineers, operators
- **Contains:** Hardening checklist, TLS setup, access control

### Operations Documentation

#### [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
- **Purpose:** Common issues and solutions
- **Audience:** Operators, support
- **Contains:** Common problems, diagnostic steps, solutions

### Development Documentation

#### [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Purpose:** How to contribute to the project
- **Audience:** Contributors, developers
- **Contains:** Code style, PR process, development setup

#### [backend/README.md](./backend/README.md)
- **Purpose:** Backend development guide
- **Audience:** Backend developers
- **Contains:** Architecture, development setup, API structure

#### [frontend/README.md](./frontend/README.md)
- **Purpose:** Frontend development guide
- **Audience:** Frontend developers
- **Contains:** Component structure, development setup, build process

### Recent Updates

#### [INCIDENT-RESOLUTION-SUMMARY.md](./INCIDENT-RESOLUTION-SUMMARY.md)
- **Purpose:** Executive summary of recent critical bug fix
- **Audience:** Management, operators
- **Contains:** Impact, resolution, verification
- **Date:** 2025-12-03

## 🔗 Cross-References

All documentation files include:
- **Navigation breadcrumbs** - Shows where you are in the docs
- **Related documentation links** - Quick links to relevant docs
- **Context-specific guidance** - Tailored to the document's purpose

## 📝 Documentation Standards

All documentation follows these standards:
1. **Clear navigation** - Breadcrumbs at top of each doc
2. **Related links** - Cross-references to relevant docs
3. **Task-oriented** - Organized by what users want to do
4. **Examples included** - Code samples and command examples
5. **Troubleshooting** - Common issues and solutions
6. **Up-to-date** - Reflects current implementation

## 🆘 Getting Help

If you can't find what you need:

1. **Check this map** - Find the right document for your task
2. **Use the search** - GitHub has search functionality
3. **Check issues** - https://github.com/cladkins/SIEMBOX/issues
4. **Ask in discussions** - https://github.com/cladkins/SIEMBOX/discussions

## 📅 Last Updated

**Date:** 2025-12-03
**Reason:** Added comprehensive log shipper documentation and cross-linking
